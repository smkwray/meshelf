package com.meshelf.android.shelf

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Per-dispatch Share staging under `cacheDir/meshelf-share/<dispatchId>/`. A later Share never
 * deletes a chooser recipient's file that is still young, and never the current dispatch's.
 */
object ShareStaging {
    const val ROOT_NAME = "meshelf-share"
    const val MAX_AGE_MS = 10 * 60 * 1000L
    private val SAFE_DISPATCH_ID = Regex("^[A-Za-z0-9-]{1,64}$")

    data class PruneResult(val removed: Int, val retained: Int)

    fun isSafeDispatchId(dispatchId: String): Boolean = SAFE_DISPATCH_ID.matches(dispatchId)

    /** Prunes stale stages, then creates (or reuses) the current dispatch's own directory. */
    fun prepare(root: File, dispatchId: String, nowMs: Long): File {
        require(isSafeDispatchId(dispatchId)) { "unsafe dispatch id" }
        if (!root.isDirectory && !root.mkdirs()) throw IOException("share stage root unavailable")
        prune(root, nowMs, dispatchId)
        val dir = File(root, dispatchId)
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("share stage unavailable")
        dir.setLastModified(nowMs)
        return dir
    }

    /** Removes only entries whose modification time is more than [MAX_AGE_MS] before [nowMs]. */
    fun prune(root: File, nowMs: Long, currentDispatchId: String): PruneResult {
        var removed = 0
        var retained = 0
        root.listFiles()?.forEach { child ->
            val stale = child.name != currentDispatchId && nowMs - child.lastModified() > MAX_AGE_MS
            if (stale && child.deleteRecursively()) removed += 1 else retained += 1
        }
        return PruneResult(removed, retained)
    }
}

/** Display text only; never a path. Keeps a basename safe for a provider-created document. */
fun safeExportName(displayName: String, fallback: String = "meshelf-file"): String {
    val base = displayName.substringAfterLast('/').substringAfterLast('\\')
        .filterNot { it.isISOControl() || it == ':' || it == '*' || it == '?' || it == '"' || it == '<' || it == '>' || it == '|' }
        .trim()
        .take(160)
    return if (base.isBlank() || base == "." || base == "..") fallback else base
}

object ExportCopy {
    class LengthMismatch(val expected: Long, val written: Long) : IOException("wrote $written of $expected bytes")

    /** Streams exactly [expected] bytes; any other count is a failure the caller must clean up. */
    fun copyExact(input: InputStream, output: OutputStream, expected: Long): Long {
        val buffer = ByteArray(64 * 1024)
        var written = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            output.write(buffer, 0, n)
            written += n
            if (written > expected) throw LengthMismatch(expected, written)
        }
        output.flush()
        if (written != expected) throw LengthMismatch(expected, written)
        return written
    }
}
