package com.meshelf.android.shelf

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import java.io.File
import java.io.IOException

sealed class SaveTarget {
    object Downloads : SaveTarget()
    data class Folder(val uri: String, val label: String) : SaveTarget()
    data class Unavailable(val reason: SaveUnavailableReason) : SaveTarget()
}

enum class SaveUnavailableReason { NO_FOLDER_BEFORE_ANDROID_10, FOLDER_ACCESS_REVOKED }

/** What the Save platform step actually did, for the card wording. */
sealed class SaveReport {
    data class Saved(val target: SaveTarget) : SaveReport()
    data class Failed(val destinationUnavailable: Boolean) : SaveReport()
}

/**
 * O-011 destination: Downloads by default, or one persisted OpenDocumentTree grant. A configured
 * folder whose grant is gone, or no folder before API 29, is unavailable. Never a silent fallback.
 */
object SaveDestinationResolver {
    const val DOWNLOADS_MIN_SDK = 29

    fun resolve(sdkInt: Int, folderUri: String?, folderLabel: String?, writableGrants: Set<String>): SaveTarget = when {
        folderUri != null ->
            if (folderUri in writableGrants) SaveTarget.Folder(folderUri, folderLabel?.takeIf { it.isNotBlank() } ?: folderUri.substringAfterLast("%3A").ifBlank { "folder" })
            else SaveTarget.Unavailable(SaveUnavailableReason.FOLDER_ACCESS_REVOKED)
        sdkInt >= DOWNLOADS_MIN_SDK -> SaveTarget.Downloads
        else -> SaveTarget.Unavailable(SaveUnavailableReason.NO_FOLDER_BEFORE_ANDROID_10)
    }
}

/** App-private preference for the chosen folder. The grant itself lives in the ContentResolver. */
class SaveSettings(context: Context) {
    private val app = context.applicationContext
    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    val folderUri: String? get() = prefs.getString(KEY_URI, null)
    val folderLabel: String? get() = prefs.getString(KEY_LABEL, null)

    fun resolve(): SaveTarget {
        val grants = app.contentResolver.persistedUriPermissions
            .filter { it.isWritePermission }
            .map { it.uri.toString() }
            .toSet()
        return SaveDestinationResolver.resolve(Build.VERSION.SDK_INT, folderUri, folderLabel, grants)
    }

    /** Takes the persistable grant first; stores the folder only if Android kept it. */
    fun choose(tree: Uri): Boolean {
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        val kept = runCatching { app.contentResolver.takePersistableUriPermission(tree, flags) }.isSuccess
        if (!kept) return false
        val previous = folderUri
        prefs.edit().putString(KEY_URI, tree.toString()).putString(KEY_LABEL, labelOf(tree)).apply()
        if (previous != null && previous != tree.toString()) release(previous)
        return true
    }

    fun reset() {
        folderUri?.let(::release)
        prefs.edit().remove(KEY_URI).remove(KEY_LABEL).apply()
    }

    private fun release(uri: String) {
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        runCatching { app.contentResolver.releasePersistableUriPermission(Uri.parse(uri), flags) }
    }

    private fun labelOf(tree: Uri): String? = runCatching {
        val doc = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        app.contentResolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)
            ?.use { c -> if (c.moveToFirst() && !c.isNull(0)) c.getString(0) else null }
    }.getOrNull()?.filterNot { it.isISOControl() }?.take(80)

    companion object {
        private const val PREFS = "meshelf_save"
        private const val KEY_URI = "folder_tree_uri"
        private const val KEY_LABEL = "folder_label"
    }
}

/** Writes a verified file into a new document at the destination; partial output is removed. */
object SaveWriter {
    fun write(context: Context, target: SaveTarget, source: File, displayName: String, mimeHint: String): SaveReport {
        val name = safeExportName(displayName)
        val mime = mimeHint.ifBlank { "application/octet-stream" }
        return when (target) {
            is SaveTarget.Unavailable -> SaveReport.Failed(destinationUnavailable = true)
            SaveTarget.Downloads ->
                if (Build.VERSION.SDK_INT < SaveDestinationResolver.DOWNLOADS_MIN_SDK) SaveReport.Failed(true)
                else writeDownloads(context, source, name, mime)
            is SaveTarget.Folder -> writeTree(context, target, source, name, mime)
        }
    }

    @androidx.annotation.RequiresApi(SaveDestinationResolver.DOWNLOADS_MIN_SDK)
    private fun writeDownloads(context: Context, source: File, name: String, mime: String): SaveReport {
        val resolver = context.contentResolver
        val pending = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        // MediaStore assigns a unique name on collision; an existing Download is never opened.
        val uri = runCatching {
            resolver.insert(MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY), pending)
        }.getOrNull() ?: return SaveReport.Failed(false)
        return try {
            streamInto(context, uri, source)
            val published = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
            if (resolver.update(uri, published, null, null) != 1) throw IOException("could not publish download")
            SaveReport.Saved(SaveTarget.Downloads)
        } catch (e: Exception) {
            android.util.Log.w(TAG, "downloads save failed: ${e.javaClass.simpleName}")
            runCatching { resolver.delete(uri, null, null) }
            SaveReport.Failed(false)
        }
    }

    private fun writeTree(context: Context, target: SaveTarget.Folder, source: File, name: String, mime: String): SaveReport {
        val resolver = context.contentResolver
        val tree = Uri.parse(target.uri)
        val doc = try {
            val parent = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
            // The provider renames on collision; this never opens an existing document.
            DocumentsContract.createDocument(resolver, parent, mime, name)
        } catch (e: SecurityException) {
            return SaveReport.Failed(destinationUnavailable = true)
        } catch (e: java.io.FileNotFoundException) {
            return SaveReport.Failed(destinationUnavailable = true)
        } catch (e: RuntimeException) {
            android.util.Log.w(TAG, "tree create failed: ${e.javaClass.simpleName}")
            return SaveReport.Failed(false)
        } ?: return SaveReport.Failed(false)
        return try {
            streamInto(context, doc, source)
            SaveReport.Saved(target)
        } catch (e: Exception) {
            android.util.Log.w(TAG, "tree save failed: ${e.javaClass.simpleName}")
            runCatching { DocumentsContract.deleteDocument(resolver, doc) }
            SaveReport.Failed(e is SecurityException)
        }
    }

    private fun streamInto(context: Context, uri: Uri, source: File) {
        val expected = source.length()
        val output = context.contentResolver.openOutputStream(uri, "w") ?: throw IOException("no output stream")
        output.use { out -> source.inputStream().use { input -> ExportCopy.copyExact(input, out, expected) } }
    }

    private const val TAG = "MeshelfExport"
}
