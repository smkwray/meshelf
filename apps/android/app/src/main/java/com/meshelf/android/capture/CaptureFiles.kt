package com.meshelf.android.capture

import java.io.File
import java.nio.file.Files

object CaptureFiles {
    private const val ROOT_NAME = "agent-captures"

    /** Final photographs live under the app's no-backup root, never in evictable cache. */
    fun root(appPrivateRoot: File): File {
        val canonicalRoot = appPrivateRoot.canonicalFile
        val candidate = File(canonicalRoot, ROOT_NAME).canonicalFile
        require(candidate.parentFile == canonicalRoot) { "capture root escaped app-private storage" }
        return candidate
    }

    fun requestDirectory(appPrivateRoot: File, requestId: String): File {
        val safeId = RequestText.requireRequestId(requestId)
        val root = root(appPrivateRoot)
        val candidate = File(root, safeId).canonicalFile
        require(candidate.parentFile == root) { "request directory escaped capture root" }
        return candidate
    }

    fun prepareRequestDirectory(appPrivateRoot: File, requestId: String): File {
        val directory = requestDirectory(appPrivateRoot, requestId)
        require(directory.mkdirs() || directory.isDirectory) { "could not create capture directory" }
        return directory
    }

    /** Raw CameraX output is temporary and may use cache. It is deleted after sanitization. */
    fun rawFile(cacheDir: File, requestId: String): File =
        File(prepareRequestDirectory(cacheDir, requestId), "capture.raw.jpg")

    fun finalFile(appPrivateRoot: File, requestId: String): File =
        File(prepareRequestDirectory(appPrivateRoot, requestId), "capture.jpg")

    fun cleanupRequest(appPrivateRoot: File, requestId: String): Boolean {
        val directory = requestDirectory(appPrivateRoot, requestId)
        if (!directory.exists()) return true
        deleteTreeWithoutFollowingLinks(directory)
        return !directory.exists()
    }

    /**
     * Removes leftover raw CameraX trees under cache. Final photographs never live here; this is
     * the only backstop when the capture activity dies before sanitization deletes the raw file.
     */
    fun cleanupRawCache(cacheDir: File): Int {
        val root = root(cacheDir)
        if (!root.exists()) return 0
        require(root.isDirectory) { "raw capture root is not a directory" }
        var removed = 0
        root.listFiles()?.forEach { child ->
            deleteTreeWithoutFollowingLinks(child)
            if (!child.exists()) removed += 1
        }
        Files.deleteIfExists(root.toPath())
        return removed
    }

    private fun deleteTreeWithoutFollowingLinks(root: File) {
        if (Files.isSymbolicLink(root.toPath())) {
            Files.deleteIfExists(root.toPath())
            return
        }
        if (root.isDirectory) {
            root.listFiles()?.forEach { child -> deleteTreeWithoutFollowingLinks(child) }
        }
        Files.deleteIfExists(root.toPath())
    }
}
