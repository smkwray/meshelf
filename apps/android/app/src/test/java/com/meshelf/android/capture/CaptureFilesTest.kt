package com.meshelf.android.capture

import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class CaptureFilesTest {
    @Test fun finalPhotoUsesPrivateRootAndCleanupRemovesOnlyItsRequest() {
        val privateRoot = Files.createTempDirectory("meshelf-capture-test").toFile()
        try {
            val first = CaptureFiles.finalFile(privateRoot, "first-request")
            val second = CaptureFiles.finalFile(privateRoot, "second-request")
            first.writeText("first")
            second.writeText("second")

            assertTrue(first.canonicalPath.startsWith(privateRoot.canonicalPath))
            assertTrue(CaptureFiles.cleanupRequest(privateRoot, "first-request"))
            assertTrue(!first.exists())
            assertTrue(second.isFile)
        } finally {
            privateRoot.deleteRecursively()
        }
    }

    @Test fun rawCacheCleanupRemovesOrphanedCameraTemps() {
        val cache = Files.createTempDirectory("meshelf-raw-cache").toFile()
        try {
            val raw = CaptureFiles.rawFile(cache, "orphaned-request")
            raw.writeText("unsanitized")
            assertTrue(raw.isFile)
            assertTrue(CaptureFiles.cleanupRawCache(cache) >= 1)
            assertTrue(!CaptureFiles.root(cache).exists())
        } finally {
            cache.deleteRecursively()
        }
    }
}
