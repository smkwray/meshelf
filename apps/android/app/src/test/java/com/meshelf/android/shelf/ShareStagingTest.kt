package com.meshelf.android.shelf

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** A second Share must not delete a first chooser recipient's file, and stale stages must not pile up (O-008). */
class ShareStagingTest {
    private val root: File = Files.createTempDirectory("meshelf-share-test").toFile()
    private val now = 50_000_000L

    @After fun cleanup() {
        root.deleteRecursively()
    }

    private fun stage(name: String, ageMs: Long): File = File(root, name).apply {
        mkdirs()
        File(this, "payload.bin").writeText(name)
        setLastModified(now - ageMs)
    }

    @Test fun currentDispatchSurvivesEvenWhenItsDirectoryIsOld() {
        val current = stage("aaaaaaaa-0000-4000-8000-000000000001", ageMs = 60 * 60 * 1000L)
        val prepared = ShareStaging.prepare(root, current.name, now)
        assertEquals(current.canonicalFile, prepared.canonicalFile)
        assertTrue(File(prepared, "payload.bin").isFile)
    }

    @Test fun recentStagesSurviveAndOnlyStaleOnesAreRemoved() {
        val recent = stage("recent-1", ageMs = 5 * 60 * 1000L)
        val boundary = stage("boundary-1", ageMs = ShareStaging.MAX_AGE_MS)
        val stale = stage("stale-1", ageMs = ShareStaging.MAX_AGE_MS + 1)
        val legacyFlat = File(root, "old.jpg").apply { writeText("x"); setLastModified(now - 3_600_000L) }
        val result = ShareStaging.prune(root, now, currentDispatchId = "current-1")
        assertTrue(recent.isDirectory)
        assertTrue(boundary.isDirectory)
        assertFalse(stale.exists())
        assertFalse(legacyFlat.exists())
        assertEquals(ShareStaging.PruneResult(removed = 2, retained = 2), result)
    }

    @Test fun secondShareDoesNotDeleteTheFirstSharesFile() {
        val first = ShareStaging.prepare(root, "first-dispatch", now)
        val firstFile = File(first, "report.pdf").apply { writeText("first") }
        val second = ShareStaging.prepare(root, "second-dispatch", now + 60_000L)
        assertTrue(firstFile.isFile)
        assertTrue(second.isDirectory)
        assertTrue(first.canonicalPath != second.canonicalPath)
    }

    @Test fun unsafeDispatchIdsAreRefused() {
        for (bad in listOf("", "../escape", "a/b", "a\\b", ".", "x".repeat(65), "id:1")) {
            assertFalse(bad, ShareStaging.isSafeDispatchId(bad))
            try {
                ShareStaging.prepare(root, bad, now)
                fail("accepted $bad")
            } catch (_: IllegalArgumentException) {
            }
        }
        assertTrue(ShareStaging.isSafeDispatchId("c9b14a4c-1d2e-4f00-8a00-0123456789ab"))
    }

    @Test fun exactCopyRefusesShortAndLongStreams() {
        val bytes = ByteArray(200_000) { (it % 251).toByte() }
        val out = ByteArrayOutputStream()
        assertEquals(200_000L, ExportCopy.copyExact(ByteArrayInputStream(bytes), out, 200_000L))
        assertTrue(bytes.contentEquals(out.toByteArray()))
        for (expected in listOf(199_999L, 200_001L)) {
            try {
                ExportCopy.copyExact(ByteArrayInputStream(bytes), ByteArrayOutputStream(), expected)
                fail("accepted a partial or oversized write for $expected")
            } catch (e: ExportCopy.LengthMismatch) {
                assertEquals(expected, e.expected)
            }
        }
    }

    @Test fun exportNamesAreBasenamesNeverPaths() {
        assertEquals("report.pdf", safeExportName("../../docs/report.pdf"))
        assertEquals("shot.jpg", safeExportName("album\\sub\\shot.jpg"))
        assertEquals("meshelf-file", safeExportName(".."))
        assertEquals("meshelf-file", safeExportName("  "))
        assertEquals("ab.txt", safeExportName("a\u0000b.txt"))
    }
}
