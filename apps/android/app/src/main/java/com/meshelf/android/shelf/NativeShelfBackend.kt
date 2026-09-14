package com.meshelf.android.shelf

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
import android.os.IBinder
import com.meshelf.android.capture.CaptureRegistry
import com.meshelf.android.nativebridge.MeshelfNative
import com.meshelf.android.service.CaptureForegroundService
import com.meshelf.android.state.DeviceDisplayName
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * ABI-8 shelf adapter against the single [CaptureForegroundService] resident. Foreground ownership
 * is reference-counted per in-app Activity ([ForegroundOwners]); the service binding and shelf ref
 * exist while any owner is started or an external-selection hold is taken. Native JSON is decoded
 * fail-closed by [ShelfDecoder]; callers receive typed results, never raw strings.
 */
class NativeShelfBackend(private val appContext: Context) : ShelfBackend {
    private class Owner(val platform: ShelfPlatformActions?, val onMetadataChanged: () -> Unit)

    private val owners = ForegroundOwners<Owner>()
    private val binderRef = AtomicReference<CaptureForegroundService.ShelfBinder?>(null)
    private val openEpoch = AtomicLong(0)

    // Main (foreground) binding: main thread only.
    private var bound = false
    private var boundRefAcquired = false

    // External selection hold binding.
    private val holdLock = Any()
    private var holds = 0
    private var holdBound = false
    private var holdRefAcquired = false
    @Volatile private var holdLatch: CountDownLatch? = null

    private val listener = object : CaptureForegroundService.ShelfListener {
        override fun onShelfChanged() {
            owners.current()?.onMetadataChanged?.invoke()
        }

        override fun onPlatformDispatchPrepared(dispatchId: String, text: String, gestureToken: String) {
            val report = reporter(dispatchId)
            val platform = owners.current()?.platform ?: return report(PlatformOutcome.FOREGROUND_LOST)
            val gesture = ForegroundGestureGate.parseToken(gestureToken) ?: return report(PlatformOutcome.FOREGROUND_LOST)
            platform.copyPreparedText(PreparedClipboardAction(dispatchId, gesture, text), report)
        }

        override fun onPlatformFileExportPrepared(
            dispatchId: String,
            absolutePath: String,
            displayName: String,
            mimeHint: String,
            gestureToken: String,
            exportKind: String,
        ) {
            val report = reporter(dispatchId)
            val platform = owners.current()?.platform ?: return report(PlatformOutcome.FOREGROUND_LOST)
            val gesture = ForegroundGestureGate.parseToken(gestureToken) ?: return report(PlatformOutcome.FOREGROUND_LOST)
            platform.exportPreparedFile(
                PreparedFileExportAction(dispatchId, gesture, absolutePath, displayName, mimeHint, exportKind),
                report,
            )
        }
    }

    private fun reporter(dispatchId: String): (PlatformOutcome) -> Unit = { outcome ->
        // A report that cannot be delivered leaves native's uncertain-no-replay recovery in charge.
        liveNative()?.reportPlatformOutcome(dispatchId, outcome.name)
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as? CaptureForegroundService.ShelfBinder ?: return
            if (!bound) return
            binderRef.set(binder)
            if (!boundRefAcquired) {
                binder.acquireShelfRef(DeviceDisplayName.load(appContext))
                boundRefAcquired = true
            }
            binder.setShelfListener(listener)
            // Native may start after bind (route lag); the owner reads state on this transition.
            owners.current()?.onMetadataChanged?.invoke()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            if (!holdBound) binderRef.set(null)
        }
    }

    private val holdConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as? CaptureForegroundService.ShelfBinder ?: return
            binderRef.set(binder)
            synchronized(holdLock) {
                if (holdBound && !holdRefAcquired) {
                    binder.acquireShelfRef(DeviceDisplayName.load(appContext))
                    holdRefAcquired = true
                }
            }
            holdLatch?.countDown()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            if (!bound) binderRef.set(null)
        }
    }

    override val connected: Boolean get() = liveNative() != null

    private fun liveNative(): MeshelfNative? = binderRef.get()?.nativeOrNull()?.takeIf { it.isStarted() }

    override fun openForeground(owner: Any, platform: ShelfPlatformActions?, onMetadataChanged: () -> Unit): Boolean {
        val opened = owners.start(owner, Owner(platform, onMetadataChanged))
        if (!bound) {
            val intent = Intent(appContext, CaptureForegroundService::class.java)
                .setAction(CaptureForegroundService.ACTION_SHELF_BIND)
            bound = appContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        } else {
            binderRef.get()?.setShelfListener(listener)
        }
        return opened
    }

    override fun resumeForeground(owner: Any) = owners.resume(owner)

    override fun pauseForeground(owner: Any) = owners.pause(owner)

    override fun deferForegroundClose(owner: Any) = owners.stopForRecreate(owner)

    override fun closeForeground(owner: Any) {
        if (!owners.stop(owner)) return
        val binder = binderRef.get()
        binder?.setShelfListener(null)
        if (boundRefAcquired) {
            binder?.releaseShelfRef()
            boundRefAcquired = false
        }
        if (bound) {
            runCatching { appContext.unbindService(connection) }
            bound = false
        }
        if (!holdBound) binderRef.set(null)
    }

    override fun snapshot(): ShelfResult<ShelfSnapshot> = call { native ->
        ShelfDecoder.snapshot(native.shelfSnapshot().getOrThrow())
    }

    override fun refreshCatalog(): ShelfResult<RefreshResult> = call { native ->
        ShelfDecoder.refresh(native.refreshOriginCatalogs(openEpoch.incrementAndGet()).getOrThrow())
    }

    override fun announceText(text: String): ShelfResult<AnnounceResult> = call { native ->
        ShelfDecoder.announce(native.announceText(text, UUID.randomUUID().toString()).getOrThrow())
    }

    override fun announcePickedPhoto(uri: Uri): ShelfResult<AnnounceResult> = call { native ->
        val outcome = native.acquireDocumentGrant(uri)
        val grant = outcome.grant
        val rootName = safeExportName(grant.displayName, fallback = "photo.jpg")
        try {
            ShelfDecoder.announce(
                native.announceDocument(grant.leaseId, rootName, grant.byteLength, UUID.randomUUID().toString()).getOrThrow(),
            )
        } catch (error: Throwable) {
            if (outcome.newlyAcquired) runCatching { native.releaseDocumentLease(grant.leaseId) }
            throw error
        }
    }

    override fun openShelfCamera(activity: Activity): ShelfResult<Unit> {
        if (CaptureRegistry.active() != null) {
            return ShelfResult.Error(ShelfErrorCode.CAMERA_BUSY, "an agent capture request owns the camera")
        }
        if (!connected) return ShelfResult.Error(ShelfErrorCode.NOT_READY, "resident not started")
        return runCatching { activity.startActivity(ShelfCameraActivity.intent(activity)) }.fold(
            onSuccess = { ShelfResult.Ok(Unit) },
            onFailure = { ShelfResult.Error(ShelfErrorCode.NATIVE_FAILED, it.message ?: it.toString()) },
        )
    }

    override fun activate(
        key: ShelfKey,
        action: ActivationAction,
        gesture: ForegroundGestureGate.Token,
    ): ShelfResult<ActivationResult> {
        val result = call { native ->
            ShelfDecoder.activation(
                native.activate(key.sourceDevice, key.offerId, action.name, ForegroundGestureGate.formatToken(gesture)).getOrThrow(),
            )
        }
        if (result is ShelfResult.Ok && (result.value.key != key || result.value.action != action)) {
            return ShelfResult.Error(ShelfErrorCode.RESULT_MISMATCH, "activation result names a different card or action")
        }
        return result
    }

    override fun invalidatePlatformActions() {
        liveNative()?.invalidatePlatformActions()
    }

    override fun beginExternalSelectionHold() {
        // Off the main thread only: the connection arrives on main, and the picker must not launch
        // until the hold owns a shelf ref, or the Activity's onStop could stop the resident.
        synchronized(holdLock) {
            if (holds == 0 && !holdBound) {
                val latch = CountDownLatch(1)
                holdLatch = latch
                val intent = Intent(appContext, CaptureForegroundService::class.java)
                    .setAction(CaptureForegroundService.ACTION_SHELF_BIND)
                holdBound = appContext.bindService(intent, holdConnection, Context.BIND_AUTO_CREATE)
                if (!holdBound) {
                    holdLatch = null
                    error("could not bind shelf resident for external selection")
                }
            }
        }
        holdLatch?.let { latch ->
            if (!latch.await(8, TimeUnit.SECONDS)) {
                synchronized(holdLock) {
                    if (holds == 0) {
                        runCatching { appContext.unbindService(holdConnection) }
                        holdBound = false
                    }
                    holdLatch = null
                }
                error("shelf resident did not connect for external selection")
            }
        }
        synchronized(holdLock) {
            holdLatch = null
            holds += 1
        }
    }

    override fun endExternalSelectionHold() {
        synchronized(holdLock) {
            if (holds == 0) return
            holds -= 1
            if (holds == 0 && holdBound) {
                if (holdRefAcquired) {
                    binderRef.get()?.releaseShelfRef()
                    holdRefAcquired = false
                }
                runCatching { appContext.unbindService(holdConnection) }
                holdBound = false
            }
        }
    }

    private inline fun <T> call(block: (MeshelfNative) -> Decoded<T>): ShelfResult<T> {
        val native = liveNative() ?: return ShelfResult.Error(ShelfErrorCode.NOT_READY, "resident not started")
        return try {
            when (val decoded = block(native)) {
                is Decoded.Ok -> ShelfResult.Ok(decoded.value)
                is Decoded.Rejected -> {
                    android.util.Log.w("MeshelfShelf", "native result rejected: ${decoded.failure.kind} ${decoded.failure.detail}")
                    ShelfResult.Rejected(decoded.failure)
                }
            }
        } catch (error: Exception) {
            ShelfResult.Error(ShelfErrorCode.NATIVE_FAILED, error.message ?: error.javaClass.simpleName)
        }
    }
}
