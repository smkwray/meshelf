package com.meshelf.android.nativebridge

import android.content.Context
import android.net.Uri
import com.meshelf.android.capture.RequestText
import com.meshelf.android.identity.KeystoreIdentityStore
import com.meshelf.android.shelf.DocumentGrantStore
import java.io.File

interface NativeEventListener {
    fun onCaptureRequested(
        requestId: String,
        requesterName: String,
        purpose: String,
        expiresAtMs: Long,
    )

    fun onCaptureWithdrawn(requestId: String, reason: String)
    fun onCaptureDelivered(requestId: String)
    fun onPeerAdmitted(deviceName: String)

    fun onPairingCandidate(
        pairingId: String,
        deviceName: String,
        sixDigitCode: String,
        transcriptHash: String,
        expiresAtMs: Long,
    )

    fun onPairingFinished(pairingId: String, result: String)

    fun onShelfChanged() {}

    fun onPlatformDispatchPrepared(dispatchId: String, text: String, gestureToken: String) {}

    fun onPlatformFileExportPrepared(
        dispatchId: String,
        absolutePath: String,
        displayName: String,
        mimeHint: String,
        gestureToken: String,
        exportKind: String,
    ) {}
}

/**
 * Kotlin half of JNI ABI-8. The method set is ABI-7's; the shelf JSON strings follow
 * schemaVersion 2 (handoffs/ANDROID_SHELF_ABI.md) and are decoded by ShelfDecoder.
 */
class MeshelfNative(
    context: Context,
    private val listener: NativeEventListener,
) {
    private val appContext = context.applicationContext
    private val identityStore = KeystoreIdentityStore(appContext)
    private val documentGrants = DocumentGrantStore(appContext).also { it.load() }
    private var started = false

    fun isStarted(): Boolean = started

    fun checkAbi(): Result<Int> = loadResult.mapCatching {
        val version = nativeAbiVersion()
        require(version == ABI_VERSION) { "unsupported native ABI $version (expected $ABI_VERSION)" }
        version
    }

    @Synchronized
    fun start(
        stateDirectory: File,
        localAddress: String,
        networkHandle: Long,
        deviceName: String,
    ): Result<Unit> = loadResult.mapCatching {
        checkAbi().getOrThrow()
        require(!started) { "native listener is already started" }
        require(stateDirectory.isDirectory) { "Rust state directory is unavailable" }
        require(stateDirectory.canonicalPath == stateDirectory.absoluteFile.canonicalPath) {
            "Rust state directory must resolve canonically"
        }
        require(networkHandle != 0L) { "network handle must be non-zero" }
        RequestText.requireDeviceName(deviceName)
        nativeStart(stateDirectory.absolutePath, localAddress, networkHandle, deviceName)
        started = true
    }

    @Synchronized
    fun stop(): Result<Unit> = loadResult.mapCatching {
        if (started) nativeStop()
        started = false
    }

    @Synchronized
    fun captureCaptured(
        requestId: String,
        path: String,
        sha256: String,
        width: Int,
        height: Int,
    ): Result<Unit> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        nativeCaptureCaptured(requestId, path, sha256, width, height)
    }

    @Synchronized
    fun captureDeclined(requestId: String, reason: String): Result<Unit> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        nativeCaptureDeclined(requestId, reason)
    }

    fun status(): Result<String> = loadResult.mapCatching { nativeStatus() }

    @Synchronized
    fun openPairingWindow(expiresAtMs: Long): Result<Unit> = loadResult.mapCatching {
        val now = System.currentTimeMillis()
        require(expiresAtMs > now && expiresAtMs - now <= PAIRING_WINDOW_MS) {
            "pairing window must end within ${PAIRING_WINDOW_MS / 1000} seconds"
        }
        require(started) { "native listener is not started" }
        nativeOpenPairingWindow(expiresAtMs)
    }

    @Synchronized
    fun closePairingWindow(): Result<Unit> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        nativeClosePairingWindow()
    }

    @Synchronized
    fun confirmPairing(pairingId: String, transcriptHash: String): Result<Unit> = loadResult.mapCatching {
        RequestText.requirePairingId(pairingId)
        RequestText.requireTranscriptHash(transcriptHash)
        require(started) { "native listener is not started" }
        nativeConfirmPairing(pairingId, transcriptHash)
    }

    @Synchronized
    fun rejectPairing(pairingId: String): Result<Unit> = loadResult.mapCatching {
        RequestText.requirePairingId(pairingId)
        require(started) { "native listener is not started" }
        nativeRejectPairing(pairingId)
    }

    @Synchronized
    fun shelfSnapshot(): Result<String> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        nativeShelfSnapshot()
    }

    @Synchronized
    fun refreshOriginCatalogs(openEpoch: Long): Result<String> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        nativeRefreshOriginCatalogs(openEpoch)
    }

    @Synchronized
    fun announceText(text: String, actionId: String): Result<String> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        require(actionId.isNotBlank()) { "action id is required" }
        nativeAnnounceText(text, actionId)
    }

    @Synchronized
    fun announceDocument(
        leaseId: String,
        rootName: String,
        byteLength: Long,
        actionId: String,
    ): Result<String> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        require(leaseId.isNotBlank()) { "lease id is required" }
        require(rootName.isNotBlank()) { "root name is required" }
        require(byteLength > 0L) { "byte length must be positive" }
        require(actionId.isNotBlank()) { "action id is required" }
        nativeAnnounceDocument(leaseId, rootName, byteLength, actionId)
    }

    fun acquireDocumentGrant(uri: Uri): DocumentGrantStore.AcquireOutcome =
        documentGrants.acquire(appContext.contentResolver, uri)

    /** JNI callback: detached FD (>=0) or DocumentGrantStore error codes. */
    @Suppress("unused")
    fun openDocumentSource(leaseId: String, expectedBytes: Long): Int {
        val code = documentGrants.openDetachedFd(leaseId, expectedBytes)
        android.util.Log.i(
            "meshelf-docs",
            "openDocumentSource lease=$leaseId expected=$expectedBytes -> $code held=${documentGrants.listLeaseIds()}",
        )
        return code
    }

    /** JNI callback: best-effort release when durable refcount hits zero. */
    @Suppress("unused")
    fun releaseDocumentLease(leaseId: String) {
        documentGrants.releaseIfUnreferenced(leaseId)
    }

    @Synchronized
    fun reserveOrdinaryPhoto(actionId: String): Result<String> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        require(actionId.isNotBlank()) { "action id is required" }
        nativeReserveOrdinaryPhoto(actionId)
    }

    /**
     * Must not hold the instance monitor across [nativeCommitOrdinaryPhoto]: fan-out can block
     * briefly on the caller thread while other shelf callbacks re-enter this object.
     */
    fun commitOrdinaryPhoto(
        leaseId: String,
        sha256: String,
        width: Int,
        height: Int,
    ): Result<String> = loadResult.mapCatching {
        synchronized(this) {
            require(started) { "native listener is not started" }
        }
        require(leaseId.isNotBlank()) { "lease id is required" }
        require(sha256.isNotBlank()) { "sha256 is required" }
        require(width > 0 && height > 0) { "dimensions must be positive" }
        nativeCommitOrdinaryPhoto(leaseId, sha256, width, height)
    }

    @Synchronized
    fun abandonPhoto(leaseId: String): Result<Unit> = loadResult.mapCatching {
        require(started) { "native listener is not started" }
        require(leaseId.isNotBlank()) { "lease id is required" }
        nativeAbandonPhoto(leaseId)
    }

    /**
     * Must not hold the instance monitor across [nativeActivate]: Rust waits for
     * [reportPlatformOutcome] / [invalidatePlatformActions] on another thread, and those
     * re-enter this object. Holding `@Synchronized` here deadlocks until the 30s clipboard
     * wait times out as `platform clipboard outcome was not reported`.
     */
    fun activate(
        sourceDevice: String,
        offerId: String,
        action: String,
        gestureToken: String,
    ): Result<String> = loadResult.mapCatching {
        synchronized(this) {
            require(started) { "native listener is not started" }
        }
        nativeActivate(sourceDevice, offerId, action, gestureToken)
    }

    fun invalidatePlatformActions(): Result<Unit> = loadResult.mapCatching {
        val live = synchronized(this) { started }
        if (live) nativeInvalidatePlatformActions()
    }

    fun reportPlatformOutcome(dispatchId: String, outcome: String): Result<Unit> = loadResult.mapCatching {
        synchronized(this) {
            require(started) { "native listener is not started" }
        }
        nativeReportPlatformOutcome(dispatchId, outcome)
    }

    @Suppress("unused")
    fun loadInstallationIdentity(): ByteArray? = identityStore.load().getOrThrow()

    @Suppress("unused")
    fun storeInstallationIdentity(record: ByteArray) {
        identityStore.storeNew(record).getOrThrow()
    }

    @Suppress("unused")
    fun onCaptureRequested(
        requestId: String,
        requesterName: String,
        purpose: String,
        expiresAtMs: Long,
    ) = listener.onCaptureRequested(requestId, requesterName, purpose, expiresAtMs)

    @Suppress("unused")
    fun onCaptureWithdrawn(requestId: String, reason: String) =
        listener.onCaptureWithdrawn(requestId, reason)

    @Suppress("unused")
    fun onCaptureDelivered(requestId: String) = listener.onCaptureDelivered(requestId)

    @Suppress("unused")
    fun onPeerAdmitted(deviceName: String) = listener.onPeerAdmitted(deviceName)

    @Suppress("unused")
    fun onPairingCandidate(
        pairingId: String,
        deviceName: String,
        sixDigitCode: String,
        transcriptHash: String,
        expiresAtMs: Long,
    ) = listener.onPairingCandidate(pairingId, deviceName, sixDigitCode, transcriptHash, expiresAtMs)

    @Suppress("unused")
    fun onPairingFinished(pairingId: String, result: String) =
        listener.onPairingFinished(pairingId, result)

    @Suppress("unused")
    fun onShelfChanged() = listener.onShelfChanged()

    @Suppress("unused")
    fun onPlatformDispatchPrepared(dispatchId: String, text: String, gestureToken: String) =
        listener.onPlatformDispatchPrepared(dispatchId, text, gestureToken)

    @Suppress("unused")
    fun onPlatformFileExportPrepared(
        dispatchId: String,
        absolutePath: String,
        displayName: String,
        mimeHint: String,
        gestureToken: String,
        exportKind: String,
    ) = listener.onPlatformFileExportPrepared(
        dispatchId,
        absolutePath,
        displayName,
        mimeHint,
        gestureToken,
        exportKind,
    )

    private external fun nativeAbiVersion(): Int
    private external fun nativeStart(
        stateDir: String,
        localAddress: String,
        networkHandle: Long,
        deviceName: String,
    )
    private external fun nativeStop()
    private external fun nativeCaptureCaptured(
        requestId: String,
        path: String,
        sha256: String,
        width: Int,
        height: Int,
    )
    private external fun nativeCaptureDeclined(requestId: String, reason: String)
    private external fun nativeStatus(): String
    private external fun nativeOpenPairingWindow(expiresAtMs: Long)
    private external fun nativeClosePairingWindow()
    private external fun nativeConfirmPairing(pairingId: String, transcriptHash: String)
    private external fun nativeRejectPairing(pairingId: String)
    private external fun nativeShelfSnapshot(): String
    private external fun nativeRefreshOriginCatalogs(openEpoch: Long): String
    private external fun nativeAnnounceText(text: String, actionId: String): String
    private external fun nativeAnnounceDocument(
        leaseId: String,
        rootName: String,
        byteLength: Long,
        actionId: String,
    ): String
    private external fun nativeReserveOrdinaryPhoto(actionId: String): String
    private external fun nativeCommitOrdinaryPhoto(
        leaseId: String,
        sha256: String,
        width: Int,
        height: Int,
    ): String
    private external fun nativeAbandonPhoto(leaseId: String)
    private external fun nativeActivate(
        sourceDevice: String,
        offerId: String,
        action: String,
        gestureToken: String,
    ): String
    private external fun nativeInvalidatePlatformActions()
    private external fun nativeReportPlatformOutcome(dispatchId: String, outcome: String)

    companion object {
        const val ABI_VERSION: Int = 8

        /** Work order 09 decision 12: the window lasts at most 120 seconds. */
        const val PAIRING_WINDOW_MS: Long = 120_000L

        private val loadResult: Result<Unit> = runCatching {
            System.loadLibrary("meshelf_android_bridge")
        }
    }
}
