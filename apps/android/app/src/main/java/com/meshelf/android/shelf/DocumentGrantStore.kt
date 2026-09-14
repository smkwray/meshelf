package com.meshelf.android.shelf

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Process + durable journal for selected-document leases.
 * Never copies gallery bytes into app storage. Persistable read grants only.
 */
class DocumentGrantStore(context: Context) {
    private val app = context.applicationContext
    private val journalFile = File(app.noBackupFilesDir, "meshelf/document-leases.json")
    private val held = ConcurrentHashMap<String, HeldGrant>()

    data class HeldGrant(
        val leaseId: String,
        val uri: String,
        val displayName: String,
        val mimeType: String,
        val byteLength: Long,
    )

    data class AcquireOutcome(
        val grant: HeldGrant,
        val newlyAcquired: Boolean,
    )

    @Synchronized
    fun acquire(resolver: ContentResolver, uri: Uri): AcquireOutcome {
        require(uri.scheme == ContentResolver.SCHEME_CONTENT) { "selected_photo_not_content_uri" }
        val meta = SelectedPhotoMetadata.inspect(resolver, uri)
        // Reuse an existing lease for the exact same URI string.
        held.values.firstOrNull { it.uri == uri.toString() }?.let {
            return AcquireOutcome(it, newlyAcquired = false)
        }
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
        try {
            app.contentResolver.takePersistableUriPermission(uri, flags)
        } catch (error: SecurityException) {
            error("persistable_grant_refused: ${error.message}")
        }
        val leaseId = UUID.randomUUID().toString()
        val grant = HeldGrant(
            leaseId = leaseId,
            uri = uri.toString(),
            displayName = meta.displayName,
            mimeType = meta.mimeType,
            byteLength = meta.byteLength,
        )
        held[leaseId] = grant
        persist()
        return AcquireOutcome(grant, newlyAcquired = true)
    }

    @Synchronized
    fun get(leaseId: String): HeldGrant? = held[leaseId]

    @Synchronized
    fun releaseIfUnreferenced(leaseId: String): Boolean {
        val grant = held.remove(leaseId) ?: return false
        runCatching {
            app.contentResolver.releasePersistableUriPermission(
                Uri.parse(grant.uri),
                Intent.FLAG_GRANT_READ_URI_PERMISSION,
            )
        }
        persist()
        return true
    }

    @Synchronized
    fun listLeaseIds(): List<String> = held.keys.toList()

    /** Open a read-only ParcelFileDescriptor and detach the FD for Rust ownership. */
    @Synchronized
    fun openDetachedFd(leaseId: String, expectedBytes: Long): Int {
        val grant = held[leaseId] ?: return CODE_UNAVAILABLE
        val uri = Uri.parse(grant.uri)
        val current = runCatching { SelectedPhotoMetadata.inspect(app.contentResolver, uri) }
            .getOrElse { return CODE_UNAVAILABLE }
        if (current.byteLength != expectedBytes || current.byteLength != grant.byteLength) {
            return CODE_CHANGED
        }
        if (current.mimeType != grant.mimeType) return CODE_CHANGED
        val pfd = runCatching {
            app.contentResolver.openFileDescriptor(uri, "r")
        }.getOrNull() ?: return CODE_UNAVAILABLE
        return try {
            pfd.detachFd()
        } catch (_: Exception) {
            runCatching { pfd.close() }
            CODE_UNSUPPORTED
        }
    }

    @Synchronized
    fun load() {
        held.clear()
        if (!journalFile.isFile) return
        val root = JSONObject(journalFile.readText())
        val leases = root.optJSONArray("leases") ?: return
        for (i in 0 until leases.length()) {
            val row = leases.getJSONObject(i)
            val grant = HeldGrant(
                leaseId = row.getString("leaseId"),
                uri = row.getString("uri"),
                displayName = row.getString("displayName"),
                mimeType = row.getString("mimeType"),
                byteLength = row.getLong("byteLength"),
            )
            held[grant.leaseId] = grant
        }
    }

    @Synchronized
    private fun persist() {
        journalFile.parentFile?.mkdirs()
        val leases = org.json.JSONArray()
        held.values.forEach { grant ->
            leases.put(
                JSONObject()
                    .put("leaseId", grant.leaseId)
                    .put("uri", grant.uri)
                    .put("displayName", grant.displayName)
                    .put("mimeType", grant.mimeType)
                    .put("byteLength", grant.byteLength),
            )
        }
        val tmp = File(journalFile.parentFile, ".${journalFile.name}.tmp")
        tmp.writeText(JSONObject().put("leases", leases).toString())
        if (!tmp.renameTo(journalFile)) {
            journalFile.writeText(tmp.readText())
            tmp.delete()
        }
    }

    companion object {
        const val CODE_UNAVAILABLE: Int = -1
        const val CODE_CHANGED: Int = -2
        const val CODE_UNSUPPORTED: Int = -3
    }
}
