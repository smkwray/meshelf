package com.meshelf.android.shelf

import com.meshelf.android.shelf.ShelfJsonFixtures.card
import com.meshelf.android.shelf.ShelfJsonFixtures.snapshot
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** G07/O-011 Save/Share policy through the production decoder, resolver and copy helpers. */
class FileExportPolicyTest {
    private fun decoded(vararg cards: String): ShelfSnapshot =
        (ShelfDecoder.snapshot(snapshot(cards = cards.toList())) as Decoded.Ok).value

    @Test fun folderCardsExposeNoFakeFileActions() {
        val folder = decoded(card(kind = "FOLDER", availability = "UNSUPPORTED", actions = emptyList())).cards.single()
        assertNull(folder.primaryAction())
        assertFalse(folder.supportsSave())
        val ready = ShelfDecoder.snapshot(snapshot(cards = listOf(card(kind = "FOLDER", actions = listOf("SHARE_FILE", "SAVE_FILE")))))
        assertTrue("a READY folder with file actions is refused", ready is Decoded.Rejected)
    }

    @Test fun photoCardsShareFirstAndSaveAsTheAlternate() {
        val photo = decoded(card(kind = "PHOTO", preview = "", actions = listOf("SHARE_FILE", "SAVE_FILE"))).cards.single()
        assertEquals(ActivationAction.SHARE_FILE, photo.primaryAction())
        assertTrue(photo.supportsSave())
        val shareOnly = decoded(card(kind = "PHOTO", preview = "", actions = listOf("SHARE_FILE"))).cards.single()
        assertFalse("no Save icon unless native lists SAVE_FILE", shareOnly.supportsSave())
    }

    @Test fun saveDefaultsToDownloadsFromAndroid10() {
        assertEquals(SaveTarget.Downloads, SaveDestinationResolver.resolve(29, null, null, emptySet()))
        assertEquals(SaveTarget.Downloads, SaveDestinationResolver.resolve(37, null, null, setOf("content://other")))
    }

    @Test fun noFolderBeforeAndroid10FailsExplicitly() {
        assertEquals(
            SaveTarget.Unavailable(SaveUnavailableReason.NO_FOLDER_BEFORE_ANDROID_10),
            SaveDestinationResolver.resolve(28, null, null, emptySet()),
        )
    }

    @Test fun revokedFolderNeverFallsBackToDownloads() {
        val tree = "content://com.android.externalstorage.documents/tree/primary%3ACamera"
        assertEquals(
            SaveTarget.Unavailable(SaveUnavailableReason.FOLDER_ACCESS_REVOKED),
            SaveDestinationResolver.resolve(34, tree, "Camera", setOf("content://another/tree")),
        )
        assertEquals(SaveTarget.Folder(tree, "Camera"), SaveDestinationResolver.resolve(26, tree, "Camera", setOf(tree)))
    }

    @Test fun partialWriteMustNotCountAsApplied() {
        try {
            ExportCopy.copyExact(ByteArrayInputStream(ByteArray(4)), ByteArrayOutputStream(), 10)
            fail("an interrupted write was accepted")
        } catch (e: ExportCopy.LengthMismatch) {
            assertEquals(4L, e.written)
        }
    }

    @Test fun destinationFailureWordingRoutesToSettings() {
        val failed = ShelfResult.Ok(
            ActivationResult(ShelfKey("s", "o"), ActivationAction.SAVE_FILE, ActivationStatus.FAILED, ActivationCode.PLATFORM_FAILED, 0, 0, null),
        )
        val revoked = ShelfWording.activation(failed, ActivationAction.SAVE_FILE, ShelfKind.FILE, SaveReport.Failed(destinationUnavailable = true))
        assertEquals(UiText.of(Msg.CHOOSE_SAVE_FOLDER), revoked.text)
        assertTrue(revoked.opensSettings)
        val ioFailure = ShelfWording.activation(failed, ActivationAction.SAVE_FILE, ShelfKind.FILE, SaveReport.Failed(destinationUnavailable = false))
        assertEquals(UiText.of(Msg.SAVE_FAILED), ioFailure.text)
    }
}
