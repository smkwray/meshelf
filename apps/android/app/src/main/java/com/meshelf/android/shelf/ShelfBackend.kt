package com.meshelf.android.shelf

import android.app.Activity
import android.content.Context
import android.net.Uri

/**
 * UI/native seam against the single resident owned by CaptureForegroundService. Shelf calls run
 * on worker threads; lifecycle calls on the main thread. No second host, JNI handle or state DB.
 */
interface ShelfBackend {
    val connected: Boolean

    /**
     * An in-app Activity's onStart. Returns true when it opened the app's foreground session
     * (no other Activity was started), which is the only time an open catalog round is due.
     */
    fun openForeground(owner: Any, platform: ShelfPlatformActions?, onMetadataChanged: () -> Unit): Boolean
    fun resumeForeground(owner: Any)
    fun pauseForeground(owner: Any)
    /** onStop. The resident is released only when the last in-app owner stops. */
    fun closeForeground(owner: Any)
    /** onStop during a configuration change; the replacement's openForeground releases [owner]. */
    fun deferForegroundClose(owner: Any)

    /** Local read only. A store invalidation must not launch a catalog query. */
    fun snapshot(): ShelfResult<ShelfSnapshot>
    /** One explicit bounded authenticated origin-catalog round; metadata, never payloads. */
    fun refreshCatalog(): ShelfResult<RefreshResult>
    fun announceText(text: String): ShelfResult<AnnounceResult>
    /** Backend owns persistable URI permission + durable refcount from acceptance onward. */
    fun announcePickedPhoto(uri: Uri): ShelfResult<AnnounceResult>
    /** Called on main thread from a live button. */
    fun openShelfCamera(activity: Activity): ShelfResult<Unit>
    /** Blocks until native reaches a terminal state; the platform step uses the gesture gate. */
    fun activate(key: ShelfKey, action: ActivationAction, gesture: ForegroundGestureGate.Token): ShelfResult<ActivationResult>
    fun invalidatePlatformActions()
    /** Keep the resident alive across an external picker Activity (OpenDocument, OpenDocumentTree). */
    fun beginExternalSelectionHold()
    fun endExternalSelectionHold()
}

/** Deliberately fails closed when no application context is available. */
object UnavailableShelfBackend : ShelfBackend {
    override val connected = false
    private fun unavailable() = ShelfResult.Error(ShelfErrorCode.NOT_READY, "native shelf adapter is not connected")
    override fun openForeground(owner: Any, platform: ShelfPlatformActions?, onMetadataChanged: () -> Unit) = false
    override fun resumeForeground(owner: Any) = Unit
    override fun pauseForeground(owner: Any) = Unit
    override fun closeForeground(owner: Any) = Unit
    override fun deferForegroundClose(owner: Any) = Unit
    override fun snapshot(): ShelfResult<ShelfSnapshot> = unavailable()
    override fun refreshCatalog(): ShelfResult<RefreshResult> = unavailable()
    override fun announceText(text: String): ShelfResult<AnnounceResult> = unavailable()
    override fun announcePickedPhoto(uri: Uri): ShelfResult<AnnounceResult> = unavailable()
    override fun openShelfCamera(activity: Activity): ShelfResult<Unit> = unavailable()
    override fun activate(key: ShelfKey, action: ActivationAction, gesture: ForegroundGestureGate.Token): ShelfResult<ActivationResult> = unavailable()
    override fun invalidatePlatformActions() = Unit
    override fun beginExternalSelectionHold() = Unit
    override fun endExternalSelectionHold() = Unit
}

object ShelfBackendProvider {
    @Volatile private var instance: ShelfBackend? = null

    fun obtain(context: Context? = null): ShelfBackend {
        instance?.let { return it }
        val app = context?.applicationContext ?: return UnavailableShelfBackend
        return synchronized(this) { instance ?: NativeShelfBackend(app).also { instance = it } }
    }
}
