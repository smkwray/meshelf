package com.meshelf.android.shelf

/** Final captured bytes are always owned by the native lease, not an Activity callback. */
object PhotoLeasePolicy {
    fun ordinaryExpiryMillis(): Long? = null // O-014: never inherit the capture timer.
    fun mayDeleteCaptureFromUi(hasBeenHandedToNative: Boolean): Boolean = !hasBeenHandedToNative
    fun needsGalleryWrite(operation: PhotoOperation): Boolean = false
}
