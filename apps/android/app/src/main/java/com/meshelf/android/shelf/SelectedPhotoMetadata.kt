package com.meshelf.android.shelf

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns

/** Worker-thread, selected-URI-only metadata helper. Never enumerate a library or copy bytes. */
data class SelectedPhotoMetadata(val uri: Uri, val displayName: String, val mimeType: String,
                                 val byteLength: Long) {
    companion object {
        fun inspect(resolver: ContentResolver, uri: Uri): SelectedPhotoMetadata {
            require(uri.scheme == ContentResolver.SCHEME_CONTENT) { "selected_photo_not_content_uri" }
            val mime = resolver.getType(uri) ?: error("selected_photo_type_unknown")
            require(mime.startsWith("image/")) { "selected_photo_not_image" }
            var name: String? = null
            var size: Long? = null
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val ni = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val si = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (ni >= 0 && !cursor.isNull(ni)) name = cursor.getString(ni)
                    if (si >= 0 && !cursor.isNull(si)) size = cursor.getLong(si)
                }
            }
            val length = size ?: error("selected_photo_size_unknown")
            require(length > 0) { "selected_photo_empty" }
            require(length <= 8L * 1024 * 1024 * 1024) { "selected_photo_protocol_limit" }
            // Display text only; never use a provider's name as a filesystem destination.
            val display = (name ?: "Photo").filterNot { it.isISOControl() }.take(160).ifBlank { "Photo" }
            return SelectedPhotoMetadata(uri, display, mime, length)
        }
    }
}
