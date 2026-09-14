package com.meshelf.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import com.meshelf.android.MainActivity
import com.meshelf.android.R
import com.meshelf.android.capture.CaptureActivity
import com.meshelf.android.capture.CaptureFiles
import com.meshelf.android.capture.CapturePresentationResult
import com.meshelf.android.capture.CaptureRegistry
import com.meshelf.android.capture.CapturedPhoto
import com.meshelf.android.capture.JpegSanitizer
import com.meshelf.android.capture.RequestText
import com.meshelf.android.nativebridge.MeshelfNative
import com.meshelf.android.nativebridge.NativeEventListener
import com.meshelf.android.pairing.PairingActivity
import com.meshelf.android.pairing.PairingEvent
import com.meshelf.android.state.AppStatePaths
import com.meshelf.android.tailscale.TailscaleRouteProvider
import java.io.File
import java.security.MessageDigest

class CaptureForegroundService : Service(), NativeEventListener, TailscaleRouteProvider.Listener {
    private val main = Handler(Looper.getMainLooper())
    private lateinit var notifications: NotificationManager
    private lateinit var routeProvider: TailscaleRouteProvider
    private lateinit var native: MeshelfNative
    private lateinit var paths: AppStatePaths
    private var enabled = false
    private var shelfBindCount = 0
    private var routeWatching = false
    private var nativeStarted = false
    private var deviceName = "Android phone"
    private var routeKey: Pair<Long, String>? = null
    private var lastRoute: TailscaleRouteProvider.Snapshot? = null
    private var expiryRunnable: Runnable? = null
    private var shelfListener: ShelfListener? = null
    private val binder = ShelfBinder()

    // The pairing screen that opened the current window, and when Rust ends that window by itself.
    private var pairingWindowToken: String? = null
    private var pairingWindowExpiresAtMs = 0L

    interface ShelfListener {
        fun onShelfChanged()
        fun onPlatformDispatchPrepared(dispatchId: String, text: String, gestureToken: String)
        fun onPlatformFileExportPrepared(
            dispatchId: String,
            absolutePath: String,
            displayName: String,
            mimeHint: String,
            gestureToken: String,
            exportKind: String,
        )
    }

    inner class ShelfBinder : Binder() {
        fun acquireShelfRef(name: String) {
            // Increment synchronously so an OpenDocument/picker transition cannot race a
            // posted acquire behind MainActivity.onStop's release and drop the resident.
            synchronized(this@CaptureForegroundService) {
                if (name.isNotBlank()) {
                    runCatching { RequestText.requireDeviceName(name) }
                        .onSuccess { deviceName = it }
                }
                shelfBindCount += 1
            }
            main.post {
                ensureRouteWatching()
                tryStartNativeFromLastRoute()
            }
        }

        fun releaseShelfRef() {
            val stopNow = synchronized(this@CaptureForegroundService) {
                shelfBindCount = (shelfBindCount - 1).coerceAtLeast(0)
                !wantsNative()
            }
            if (!stopNow) return
            main.post {
                if (!wantsNative()) {
                    stopNative()
                    if (!enabled) {
                        stopRouteWatching()
                        stopSelf()
                    }
                }
            }
        }

        fun nativeOrNull(): MeshelfNative? = if (nativeStarted) native else null

        fun setShelfListener(listener: ShelfListener?) {
            shelfListener = listener
        }
    }

    override fun onCreate() {
        super.onCreate()
        notifications = getSystemService(NotificationManager::class.java)
        createNotificationChannels()
        paths = AppStatePaths.from(this)
        native = MeshelfNative(applicationContext, this)
        routeProvider = TailscaleRouteProvider(applicationContext, this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> enable(intent.getStringExtra(EXTRA_DEVICE_NAME))
            ACTION_STOP -> disable("availability-disabled")
            ACTION_DECLINE -> decline(
                intent.getStringExtra(EXTRA_REQUEST_ID),
                intent.getStringExtra(EXTRA_REASON) ?: "user-declined",
            )
            ACTION_CAPTURED -> acceptCaptured(intent)
            ACTION_OPEN_PAIRING, ACTION_CLOSE_PAIRING, ACTION_CONFIRM_PAIRING, ACTION_REJECT_PAIRING -> {
                handlePairing(intent)
                if (!enabled && shelfBindCount == 0) stopSelf(startId)
            }
            ACTION_SHELF_BIND -> Unit
            else -> if (!enabled && shelfBindCount == 0) stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun wantsNative(): Boolean = enabled || shelfBindCount > 0

    private fun ensureRouteWatching() {
        if (routeWatching) return
        routeProvider.start()
        routeWatching = true
    }

    private fun stopRouteWatching() {
        if (!routeWatching) return
        routeProvider.stop()
        routeWatching = false
        lastRoute = null
    }

    private fun tryStartNativeFromLastRoute() {
        val snapshot = lastRoute ?: return
        if (!wantsNative()) return
        val nextKey = snapshot.networkHandle to snapshot.localAddress
        if (nativeStarted && routeKey == nextKey) return
        stopNative()
        val result = runCatching {
            val state = paths.ensureStateDirectory()
            native.start(
                stateDirectory = state,
                localAddress = snapshot.localAddress,
                networkHandle = snapshot.networkHandle,
                deviceName = deviceName,
            ).getOrThrow()
        }
        if (result.isSuccess) {
            nativeStarted = true
            routeKey = nextKey
            android.util.Log.i("MeshelfService", "Native resident started on ${snapshot.localAddress}: initial_status=${native.status().getOrNull()}")
            main.postDelayed({
                android.util.Log.i("MeshelfService", "Native status after 1s: ${native.status().getOrNull()}")
            }, 1000)
            if (enabled) updateAvailability("Available on ${snapshot.localAddress}.")
            // Shelf UI may have bound before the Tailscale route arrived; wake it so the
            // foreground open path can run one explicit catalog refresh.
            shelfListener?.onShelfChanged()
        } else {
            val errorMsg = result.exceptionOrNull()?.message ?: "native start failed"
            android.util.Log.e("MeshelfService", "Native resident start failed: $errorMsg", result.exceptionOrNull())
            if (enabled) {
                updateAvailability("Listener stopped: $errorMsg")
            }
            shelfListener?.onShelfChanged()
        }
    }

    private fun enable(candidateName: String?) {
        if (enabled) return
        val validatedName = runCatching { RequestText.requireDeviceName(candidateName.orEmpty()) }
            .getOrElse {
                stopSelf()
                return
            }
        deviceName = validatedName
        enabled = true
        setRunning(true)
        val starting = buildAvailabilityNotification("Resolving the active Tailscale VPN…")
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(
                FOREGROUND_NOTIFICATION_ID,
                starting,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(FOREGROUND_NOTIFICATION_ID, starting)
        }
        if (!notifications.areNotificationsEnabled()) {
            disable("notifications-disabled")
            return
        }
        CaptureFiles.cleanupRawCache(cacheDir)
        ensureRouteWatching()
        tryStartNativeFromLastRoute()
    }

    private fun disable(reason: String) {
        val captured = CaptureRegistry.active()?.requestId?.let { CaptureRegistry.captured(it) }
        val active = CaptureRegistry.clearAny()
        cancelExpiry()
        if (active != null) {
            native.captureDeclined(active.requestId, reason)
            // A photograph already handed to Rust may be Claimed; Rust owns deletion.
            if (captured == null) {
                CaptureFiles.cleanupRequest(paths.root, active.requestId)
            }
            CaptureActivity.finishRequest(active.requestId)
        }
        notifications.cancel(REQUEST_NOTIFICATION_ID)
        enabled = false
        setRunning(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (!wantsNative()) {
            stopRouteWatching()
            stopNative()
            stopSelf()
        }
    }

    override fun onDestroy() {
        cancelExpiry()
        val capturedId = CaptureRegistry.active()?.requestId?.let { id ->
            CaptureRegistry.captured(id)?.requestId
        }
        CaptureRegistry.clearAny()?.let { request ->
            if (nativeStarted) native.captureDeclined(request.requestId, "service-stopped")
            if (capturedId == null) {
                CaptureFiles.cleanupRequest(paths.root, request.requestId)
            }
            CaptureActivity.finishRequest(request.requestId)
        }
        stopRouteWatching()
        stopNative()
        enabled = false
        shelfBindCount = 0
        setRunning(false)
        super.onDestroy()
    }

    override fun onRouteAvailable(snapshot: TailscaleRouteProvider.Snapshot) {
        main.post {
            lastRoute = snapshot
            if (!wantsNative()) return@post
            tryStartNativeFromLastRoute()
        }
    }

    override fun onRouteUnavailable(reason: String) {
        main.post {
            lastRoute = null
            if (!wantsNative()) return@post
            // CaptureRegistry is UI state, not a durable source lease. A produced photo may
            // already be Claimed in Rust; UI state cannot authorize unlinking it.
            val capturedId = CaptureRegistry.active()?.requestId?.let { id ->
                CaptureRegistry.captured(id)?.requestId
            }
            CaptureRegistry.clearAny()?.let { request ->
                cancelExpiry()
                if (nativeStarted) native.captureDeclined(request.requestId, "route-unavailable")
                if (request.requestId != capturedId) {
                    CaptureFiles.cleanupRequest(paths.root, request.requestId)
                }
                CaptureActivity.finishRequest(request.requestId)
                notifications.cancel(REQUEST_NOTIFICATION_ID)
            }
            stopNative()
            if (enabled) updateAvailability(reason)
        }
    }

    override fun onShelfChanged() {
        main.post { shelfListener?.onShelfChanged() }
    }

    override fun onPlatformDispatchPrepared(dispatchId: String, text: String, gestureToken: String) {
        main.post {
            val listener = shelfListener
            if (listener == null) {
                // No foreground shelf to write the clipboard; fail closed so Rust does not
                // wait out the platform-outcome timeout as uncertain-no-replay.
                if (nativeStarted) {
                    native.reportPlatformOutcome(dispatchId, "FOREGROUND_LOST")
                }
                return@post
            }
            listener.onPlatformDispatchPrepared(dispatchId, text, gestureToken)
        }
    }

    override fun onPlatformFileExportPrepared(
        dispatchId: String,
        absolutePath: String,
        displayName: String,
        mimeHint: String,
        gestureToken: String,
        exportKind: String,
    ) {
        main.post {
            val listener = shelfListener
            if (listener == null) {
                if (nativeStarted) {
                    native.reportPlatformOutcome(dispatchId, "FOREGROUND_LOST")
                }
                return@post
            }
            listener.onPlatformFileExportPrepared(
                dispatchId,
                absolutePath,
                displayName,
                mimeHint,
                gestureToken,
                exportKind,
            )
        }
    }

    override fun onCaptureRequested(
        requestId: String,
        requesterName: String,
        purpose: String,
        expiresAtMs: Long,
    ) {
        main.post {
            if (!enabled || !nativeStarted) return@post
            when (
                CaptureRegistry.present(
                    requestId,
                    requesterName,
                    purpose,
                    expiresAtMs,
                    System.currentTimeMillis(),
                )
            ) {
                CapturePresentationResult.PRESENTED -> {
                    val request = requireNotNull(CaptureRegistry.active(requestId))
                    // O-027: open the camera immediately; shutter remains the consent act.
                    openCaptureCamera(request)
                    notifications.notify(REQUEST_NOTIFICATION_ID, buildRequestNotification(request))
                    updateAvailability("Photo requested — Take photo on the camera screen.")
                    scheduleExpiry(requestId, expiresAtMs)
                }
                CapturePresentationResult.DUPLICATE -> {
                    CaptureRegistry.active(requestId)?.let {
                        openCaptureCamera(it)
                        notifications.notify(REQUEST_NOTIFICATION_ID, buildRequestNotification(it))
                    }
                }
                CapturePresentationResult.BUSY -> native.captureDeclined(requestId, "busy")
                CapturePresentationResult.EXPIRED -> native.captureDeclined(requestId, "expired")
                CapturePresentationResult.INVALID -> native.captureDeclined(requestId, "refused")
            }
        }
    }

    override fun onCaptureWithdrawn(requestId: String, reason: String) {
        main.post {
            val active = CaptureRegistry.clear(requestId)
            cancelExpiry()
            CaptureFiles.cleanupRequest(paths.root, requestId)
            CaptureActivity.finishRequest(requestId)
            notifications.cancel(REQUEST_NOTIFICATION_ID)
            updateAvailability(
                active?.let { "The request from ${it.requesterName} was withdrawn." }
                    ?: "A capture request was withdrawn.",
            )
        }
    }

    override fun onCaptureDelivered(requestId: String) {
        main.post {
            CaptureRegistry.clear(requestId)
            cancelExpiry()
            val cleaned = CaptureFiles.cleanupRequest(paths.root, requestId)
            CaptureActivity.finishRequest(requestId)
            notifications.cancel(REQUEST_NOTIFICATION_ID)
            // O-021/O-027: delivery is reflected in the availability notice, never a separate
            // confirmation notification or an extra consent step.
            updateAvailability(
                if (cleaned) "Available for capture requests." else "Delivered, but temporary-file cleanup failed.",
            )
        }
    }

    override fun onPeerAdmitted(deviceName: String) {
        main.post {
            val peer = runCatching { RequestText.requireDeviceName(deviceName) }.getOrNull() ?: return@post
            updateAvailability("Peer admitted by Rust trust policy: $peer")
        }
    }

    override fun onPairingCandidate(
        pairingId: String,
        deviceName: String,
        sixDigitCode: String,
        transcriptHash: String,
        expiresAtMs: Long,
    ) {
        main.post {
            if (!nativeStarted) return@post
            val shown = pairingWindowToken != null && PairingActivity.deliver(
                PairingEvent.CandidateArrived(
                    pairingId,
                    deviceName,
                    sixDigitCode,
                    transcriptHash,
                    expiresAtMs,
                    System.currentTimeMillis(),
                ),
            )
            // A candidate only ever fills a pairing screen the person already has open.
            if (!shown && native.rejectPairing(pairingId).isFailure) {
                native.closePairingWindow()
                pairingWindowToken = null
                pairingWindowExpiresAtMs = 0L
            }
        }
    }

    override fun onPairingFinished(pairingId: String, result: String) {
        main.post {
            if (PairingActivity.deliver(PairingEvent.PairingFinished(pairingId, result))) return@post
            val shown = runCatching { RequestText.requirePairingResult(result) }.getOrDefault("unreadable result")
            updateAvailability("A pairing attempt ended: $shown")
        }
    }

    private fun handlePairing(intent: Intent) {
        val token = intent.getStringExtra(EXTRA_PAIRING_WINDOW_TOKEN)
        when (intent.action) {
            ACTION_OPEN_PAIRING -> openPairing(token)
            ACTION_CLOSE_PAIRING -> if (token != null && token == pairingWindowToken) closePairing()
            ACTION_CONFIRM_PAIRING -> native.confirmPairing(
                intent.getStringExtra(EXTRA_PAIRING_ID).orEmpty(),
                intent.getStringExtra(EXTRA_TRANSCRIPT_HASH).orEmpty(),
            ).onFailure {
                PairingActivity.deliver(PairingEvent.NativeCallFailed("Could not confirm the pairing: ${it.message}"))
            }
            ACTION_REJECT_PAIRING -> native.rejectPairing(intent.getStringExtra(EXTRA_PAIRING_ID).orEmpty())
                .onFailure {
                    PairingActivity.deliver(PairingEvent.NativeCallFailed("Could not reject the pairing: ${it.message}"))
                }
        }
    }

    private fun openPairing(token: String?) {
        val unavailable = when {
            token == null -> "The pairing screen sent no window token."
            !enabled -> PairingActivity.AVAILABILITY_OFF
            !nativeStarted -> "The listener is stopped because no Tailscale route is available."
            else -> null
        }
        if (unavailable != null) {
            PairingActivity.deliver(PairingEvent.Unavailable(unavailable))
            return
        }
        if (pairingWindowToken != null) closePairing()
        val expiresAtMs = System.currentTimeMillis() + MeshelfNative.PAIRING_WINDOW_MS
        native.openPairingWindow(expiresAtMs)
            .onSuccess {
                pairingWindowToken = token
                pairingWindowExpiresAtMs = expiresAtMs
                PairingActivity.deliver(PairingEvent.WindowOpened(expiresAtMs))
            }
            .onFailure {
                PairingActivity.deliver(PairingEvent.Unavailable("Could not open the pairing window: ${it.message}"))
            }
    }

    private fun closePairing() {
        val stillOpen = pairingWindowToken != null && System.currentTimeMillis() < pairingWindowExpiresAtMs
        pairingWindowToken = null
        pairingWindowExpiresAtMs = 0L
        if (stillOpen && nativeStarted) {
            native.closePairingWindow().onFailure {
                updateAvailability("Could not close the pairing window (${it.message}); Rust ends it within two minutes.")
            }
        }
    }

    private fun decline(requestId: String?, reason: String) {
        val id = requestId ?: return
        val active = CaptureRegistry.active(id)
        val alreadyCaptured = CaptureRegistry.captured(id) != null
        cancelExpiry()
        if (nativeStarted) native.captureDeclined(id, reason)
        // A photograph already handed to Rust may be Claimed: native decline is a no-op and the
        // transfer owns the file. Deleting here would unlink a live pull.
        if (!alreadyCaptured) {
            CaptureFiles.cleanupRequest(paths.root, id)
            CaptureRegistry.clear(id)
            CaptureActivity.finishRequest(id)
            notifications.cancel(REQUEST_NOTIFICATION_ID)
        }
        updateAvailability(
            active?.let { "The request from ${it.requesterName} was declined." }
                ?: "A capture request was declined.",
        )
    }

    private fun acceptCaptured(intent: Intent) {
        val photo = runCatching {
            CapturedPhoto(
                requestId = requireNotNull(intent.getStringExtra(EXTRA_REQUEST_ID)),
                absolutePath = requireNotNull(intent.getStringExtra(EXTRA_PATH)),
                sha256 = requireNotNull(intent.getStringExtra(EXTRA_SHA256)),
                width = intent.getIntExtra(EXTRA_WIDTH, 0),
                height = intent.getIntExtra(EXTRA_HEIGHT, 0),
            )
        }.getOrElse { return }
        val active = CaptureRegistry.active(photo.requestId) ?: run {
            CaptureFiles.cleanupRequest(paths.root, photo.requestId)
            return
        }
        val result = runCatching {
            require(CaptureRegistry.captured(photo.requestId) == photo) { "capture metadata was not registered" }
            val expected = CaptureFiles.finalFile(paths.root, photo.requestId).canonicalFile
            require(File(photo.absolutePath).canonicalFile == expected) { "capture path escaped request directory" }
            require(expected.isFile) { "sanitized capture is unavailable" }
            val inspected = JpegSanitizer.inspect(expected)
            require(!inspected.hasGpsExif && !inspected.hasXmp && !inspected.hasIptc && !inspected.hasComment) {
                "capture retained forbidden metadata"
            }
            require(inspected.width == photo.width && inspected.height == photo.height) {
                "capture dimensions changed"
            }
            require(sha256(expected) == photo.sha256) { "capture hash mismatch" }
            native.captureCaptured(
                photo.requestId,
                expected.absolutePath,
                photo.sha256,
                photo.width,
                photo.height,
            ).getOrThrow()
        }
        if (result.isSuccess) {
            cancelExpiry()
            notifications.cancel(REQUEST_NOTIFICATION_ID)
            updateAvailability("Photo captured for ${active.requesterName}; waiting for verified delivery receipt.")
        } else {
            updateAvailability("Capture could not be handed to Rust: ${result.exceptionOrNull()?.message}")
        }
    }

    private fun scheduleExpiry(requestId: String, expiresAtMs: Long) {
        cancelExpiry()
        val runnable = Runnable {
            val request = CaptureRegistry.active(requestId) ?: return@Runnable
            if (System.currentTimeMillis() < request.expiresAtMs) {
                scheduleExpiry(requestId, request.expiresAtMs)
                return@Runnable
            }
            decline(requestId, "expired")
        }
        expiryRunnable = runnable
        main.postDelayed(runnable, (expiresAtMs - System.currentTimeMillis()).coerceAtLeast(0L))
    }

    private fun cancelExpiry() {
        expiryRunnable?.let(main::removeCallbacks)
        expiryRunnable = null
    }

    private fun stopNative() {
        // nativeStop closes the Rust pairing window; tell the open pairing screen instead of leaving it waiting.
        if (pairingWindowToken != null) {
            pairingWindowToken = null
            pairingWindowExpiresAtMs = 0L
            PairingActivity.deliver(
                PairingEvent.Unavailable("The listener stopped, which closed the pairing window. Reopen this screen to try again."),
            )
        }
        if (nativeStarted) native.stop()
        nativeStarted = false
        routeKey = null
    }

    private fun createNotificationChannels() {
        notifications.createNotificationChannel(
            NotificationChannel(
                CHANNEL_AVAILABILITY,
                "Capture availability",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setDescription("Visible only while this phone is available for meshelf capture requests.")
                setShowBadge(false)
            },
        )
        notifications.createNotificationChannel(
            NotificationChannel(
                CHANNEL_REQUEST,
                "Capture requests",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                setDescription("User-visible photo requests that require opening the camera.")
            },
        )
    }

    private fun captureCameraIntent(requestId: String): Intent =
        Intent(this, CaptureActivity::class.java)
            .putExtra(CaptureActivity.EXTRA_REQUEST_ID, requestId)
            .addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP,
            )

    /** Best-effort auto-open (O-027). OEMs may still require the fallback notification tap. */
    private fun openCaptureCamera(request: com.meshelf.android.capture.CaptureRequest) {
        runCatching {
            startActivity(captureCameraIntent(request.requestId))
        }.onFailure {
            // Notification / full-screen intent remains the recovery path.
        }
    }

    private fun updateAvailability(detail: String) {
        if (!enabled) return
        notifications.notify(FOREGROUND_NOTIFICATION_ID, buildAvailabilityNotification(detail))
    }

    private fun buildAvailabilityNotification(detail: String): Notification {
        val content = NotificationContent.available(deviceName, detail)
        val openApp = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_AVAILABILITY)
            .setSmallIcon(R.drawable.ic_stat_meshelf)
            .setContentTitle(content.title)
            .setContentText(content.text)
            .setStyle(Notification.BigTextStyle().bigText(content.bigText))
            .setContentIntent(openApp)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setShowWhen(false)
            .build()
    }

    private fun buildRequestNotification(request: com.meshelf.android.capture.CaptureRequest): Notification {
        val content = NotificationContent.request(request)
        val openCamera = PendingIntent.getActivity(
            this,
            request.requestId.hashCode(),
            captureCameraIntent(request.requestId),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val decline = PendingIntent.getService(
            this,
            request.requestId.hashCode() xor 0x4d53,
            Intent(this, CaptureForegroundService::class.java)
                .setAction(ACTION_DECLINE)
                .putExtra(EXTRA_REQUEST_ID, request.requestId)
                .putExtra(EXTRA_REASON, "user-declined"),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = Notification.Builder(this, CHANNEL_REQUEST)
            .setSmallIcon(R.drawable.ic_stat_meshelf)
            .setContentTitle(content.title)
            .setContentText("Tap Take photo when the camera opens — or tap here.")
            .setStyle(
                Notification.BigTextStyle().bigText(
                    "${content.bigText}\n\nCamera should open automatically. Tap Take photo to shoot.",
                ),
            )
            .setContentIntent(openCamera)
            .setFullScreenIntent(openCamera, true)
            .addAction(
                Notification.Action.Builder(
                    R.drawable.ic_stat_meshelf,
                    "Decline",
                    decline,
                ).build(),
            )
            .setCategory(Notification.CATEGORY_CALL)
            .setPriority(Notification.PRIORITY_HIGH)
            .setOngoing(true)
            .setTimeoutAfter((request.expiresAtMs - System.currentTimeMillis()).coerceAtLeast(1_000L))
        return builder.build()
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    companion object {
        const val ACTION_START = "com.meshelf.android.action.START_CAPTURE_AVAILABILITY"
        const val ACTION_STOP = "com.meshelf.android.action.STOP_CAPTURE_AVAILABILITY"
        const val ACTION_SHELF_BIND = "com.meshelf.android.action.SHELF_BIND"
        const val ACTION_DECLINE = "com.meshelf.android.action.DECLINE_CAPTURE"
        const val ACTION_CAPTURED = "com.meshelf.android.action.CAPTURED"
        const val ACTION_OPEN_PAIRING = "com.meshelf.android.action.OPEN_PAIRING_WINDOW"
        const val ACTION_CLOSE_PAIRING = "com.meshelf.android.action.CLOSE_PAIRING_WINDOW"
        const val ACTION_CONFIRM_PAIRING = "com.meshelf.android.action.CONFIRM_PAIRING"
        const val ACTION_REJECT_PAIRING = "com.meshelf.android.action.REJECT_PAIRING"
        const val EXTRA_PAIRING_WINDOW_TOKEN = "pairingWindowToken"
        const val EXTRA_PAIRING_ID = "pairingId"
        const val EXTRA_TRANSCRIPT_HASH = "transcriptHash"
        const val EXTRA_DEVICE_NAME = "deviceName"
        const val EXTRA_REQUEST_ID = "requestId"
        const val EXTRA_REASON = "reason"
        const val EXTRA_PATH = "path"
        const val EXTRA_SHA256 = "sha256"
        const val EXTRA_WIDTH = "width"
        const val EXTRA_HEIGHT = "height"

        private const val CHANNEL_AVAILABILITY = "capture-availability-v1"
        private const val CHANNEL_REQUEST = "capture-requests-v1"
        private const val FOREGROUND_NOTIFICATION_ID = 4101
        private const val REQUEST_NOTIFICATION_ID = 4102
        @Volatile private var running = false
        @Volatile private var runningListener: (() -> Unit)? = null

        fun isRunning(): Boolean = running

        /** Settings observes availability on/off here; called on the main thread. */
        fun setRunningListener(listener: (() -> Unit)?) {
            runningListener = listener
        }

        private fun setRunning(value: Boolean) {
            running = value
            runningListener?.invoke()
        }
    }
}
