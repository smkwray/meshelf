package com.meshelf.android.shelf

import com.meshelf.android.R
import java.io.File
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Renders production wording through the real res/values strings. The normal surface must speak the
 * redesign vocabulary and never leak a raw native code, exception string or offer UUID.
 */
class ShelfWordingTest {
    private val strings: Map<String, String> by lazy {
        val file = listOf("src/main/res/values/shelf_strings.xml", "app/src/main/res/values/shelf_strings.xml")
            .map(::File).first { it.isFile }
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val nodes = doc.getElementsByTagName("string")
        (0 until nodes.length).associate { i ->
            val node = nodes.item(i)
            node.attributes.getNamedItem("name").nodeValue to
                node.textContent.replace("\\n", "\n").replace("\\'", "'").replace("\\\"", "\"")
        }
    }
    private val names: Map<Int, String> by lazy {
        R.string::class.java.fields.associate { it.getInt(null) to it.name }
    }

    private fun render(text: UiText): String = text.render { msg, args ->
        val raw = strings[names[msg.res]] ?: error("no string resource for $msg")
        String.format(Locale.ROOT, raw, *args)
    }

    private fun render(feedback: Feedback?): String? = feedback?.let { render(it.text) }

    private val key = ShelfKey("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")

    private fun result(code: ActivationCode, action: ActivationAction) = ShelfResult.Ok(
        ActivationResult(
            key, action,
            when (code) {
                ActivationCode.COMPLETED -> ActivationStatus.COMPLETED
                ActivationCode.UNCERTAIN_NO_REPLAY -> ActivationStatus.UNCERTAIN
                else -> ActivationStatus.FAILED
            },
            code, 0, 12, "failed:${code.name.lowercase()}",
        ),
    )

    @Test fun everyMessageResolvesToAResourceString() {
        Msg.entries.forEach { msg ->
            val rendered = render(UiText.of(msg, 2, "x"))
            assertTrue(msg.name, rendered.isNotBlank())
        }
    }

    @Test fun everyActivationCodeHasHumanWording() {
        val expected = mapOf(
            ActivationCode.COMPLETED to listOf("Copied", "Share sheet opened", "Saved"),
            ActivationCode.SOURCE_UNAVAILABLE to List(3) { "Source unavailable" },
            ActivationCode.SOURCE_CHANGED to List(3) { "Source changed" },
            ActivationCode.BUSY to List(3) { "Busy — try again" },
            ActivationCode.CANCELLED to List(3) { "Canceled" },
            ActivationCode.CLIPBOARD_FAILED to List(3) { "Couldn’t copy" },
            ActivationCode.VERIFICATION_FAILED to List(3) { "Couldn’t verify the file" },
            ActivationCode.PLATFORM_FAILED to listOf("Couldn’t copy", "Couldn’t open the share sheet", "Couldn’t save the file"),
            ActivationCode.FOREGROUND_LOST to List(3) { "Action stopped before it could apply" },
            ActivationCode.UNCERTAIN_NO_REPLAY to List(3) { "Result unknown — not retried" },
            ActivationCode.UNSUPPORTED to List(3) { "This action isn’t available on this phone" },
            ActivationCode.INTERNAL to List(3) { "Meshelf couldn’t finish this action" },
        )
        assertEquals(ActivationCode.entries.toSet(), expected.keys)
        val actions = listOf(ActivationAction.COPY_TEXT, ActivationAction.SHARE_FILE, ActivationAction.SAVE_FILE)
        for ((code, words) in expected) {
            actions.forEachIndexed { i, action ->
                val feedback = ShelfWording.activation(result(code, action), action, ShelfKind.FILE, saveReport = null)
                val text = render(feedback)!!
                assertEquals("$code/$action", words[i], text)
                assertFalse(text.contains(code.name) || text.contains(key.offerId) || text.contains("failed:"))
                assertEquals("only completion fades", code == ActivationCode.COMPLETED, feedback.transient)
                assertTrue("technical detail stays in Details", feedback.detail!!.contains(code.name))
            }
        }
    }

    @Test fun saveWordingNamesTheDestinationAndRoutesRevocationToSettings() {
        val save = ActivationAction.SAVE_FILE
        assertEquals("Saved to Downloads", render(ShelfWording.activation(result(ActivationCode.COMPLETED, save), save, ShelfKind.PHOTO, SaveReport.Saved(SaveTarget.Downloads))))
        assertEquals("Saved to Camera", render(ShelfWording.activation(result(ActivationCode.COMPLETED, save), save, ShelfKind.PHOTO, SaveReport.Saved(SaveTarget.Folder("content://tree", "Camera")))))
        val revoked = ShelfWording.activation(result(ActivationCode.PLATFORM_FAILED, save), save, ShelfKind.FILE, SaveReport.Failed(destinationUnavailable = true))
        assertEquals("Choose a save folder in Settings", render(revoked))
        assertTrue(revoked.opensSettings)
        val writeFailed = ShelfWording.activation(result(ActivationCode.PLATFORM_FAILED, save), save, ShelfKind.FILE, SaveReport.Failed(destinationUnavailable = false))
        assertEquals("Couldn’t save the file", render(writeFailed))
        assertFalse(writeFailed.opensSettings)
        val pre = ShelfWording.saveDestinationUnavailable(SaveUnavailableReason.NO_FOLDER_BEFORE_ANDROID_10)
        assertEquals("Choose a save folder in Settings", render(pre))
        assertTrue(pre.opensSettings)
    }

    @Test fun folderUnsupportedUsesTheExactReason() {
        val a = ActivationAction.SHARE_FILE
        assertEquals("Folders can’t be saved here · zip it first", render(ShelfWording.activation(result(ActivationCode.UNSUPPORTED, a), a, ShelfKind.FOLDER, null)))
        val folder = ShelfCard(key, "CEDAR", ShelfOwnership.RECEIVED, ShelfKind.FOLDER, "bundle", "", 0, 1, ShelfAvailability.UNSUPPORTED, emptyList(), null)
        assertEquals("Folders can’t be saved here · zip it first", render(ShelfWording.availability(folder)))
        assertEquals("Source unavailable", render(ShelfWording.availability(folder.copy(kind = ShelfKind.FILE, availability = ShelfAvailability.SOURCE_OFFLINE))))
        assertEquals("Source changed", render(ShelfWording.availability(folder.copy(kind = ShelfKind.FILE, availability = ShelfAvailability.SOURCE_CHANGED))))
        assertNull(ShelfWording.availability(folder.copy(kind = ShelfKind.TEXT, availability = ShelfAvailability.READY, supportedActions = listOf(ActivationAction.COPY_TEXT))))
    }

    @Test fun inFlightAndNonResultWording() {
        assertEquals("Copying…", render(ShelfWording.inFlight(ActivationAction.COPY_TEXT)))
        assertEquals("Opening share sheet…", render(ShelfWording.inFlight(ActivationAction.SHARE_FILE)))
        assertEquals("Saving…", render(ShelfWording.inFlight(ActivationAction.SAVE_FILE)))
        val a = ActivationAction.COPY_TEXT
        val rejected = ShelfResult.Rejected(DecodeFailure(DecodeFailure.Kind.INVALID, 0, "bad"))
        assertEquals("Result unknown — not retried", render(ShelfWording.activation(rejected, a, ShelfKind.TEXT, null)))
        val thrown = ShelfResult.Error(ShelfErrorCode.NATIVE_FAILED, "native_shelf_failed: boom")
        assertEquals("Meshelf couldn’t finish this action", render(ShelfWording.activation(thrown, a, ShelfKind.TEXT, null)))
        assertEquals("Meshelf is getting ready…", render(ShelfWording.activation(ShelfResult.Error(ShelfErrorCode.NOT_READY, "x"), a, ShelfKind.TEXT, null)))
        assertEquals("Camera is already in use for a capture request", render(ShelfWording.error(ShelfResult.Error(ShelfErrorCode.CAMERA_BUSY, "x"))))
    }

    @Test fun lastAttemptKeepsFailuresVisibleAfterRecreation() {
        AttemptCode.entries.forEach { code ->
            val feedback = ShelfWording.lastAttempt(LastAttempt(code, 1, 0, 0, null))
            if (code == AttemptCode.COMPLETED) assertNull(feedback) else assertFalse(render(feedback)!!.contains(code.name))
        }
        assertEquals("Result unknown — not retried", render(ShelfWording.lastAttempt(LastAttempt(AttemptCode.UNCERTAIN_NO_REPLAY, 4, 0, 0, "cut"))))
    }

    private fun announce(added: Long, unavailable: Long, refused: Long, stored: Boolean = true) =
        ShelfResult.Ok(AnnounceResult("c9b14a4c-0000-4000-8000-000000000000", stored, added, unavailable, refused, emptyList()))

    @Test fun announceSentences() {
        val cases = listOf(
            Triple(announce(1, 0, 0), false, "Added to 1 device"),
            Triple(announce(2, 1, 0), false, "Added to 2 devices · 1 unavailable"),
            Triple(announce(1, 0, 1), false, "Added to 1 device · 1 refused"),
            Triple(announce(0, 2, 0), false, "Kept on this phone · no devices reached"),
            Triple(announce(0, 0, 0), false, "Kept on this phone · no devices reached"),
            Triple(announce(0, 1, 1), false, "Kept on this phone · 1 unavailable · 1 refused"),
            Triple(announce(1, 0, 0), true, "Photo added · sent to 1 device"),
            Triple(announce(3, 1, 0), true, "Photo added · sent to 3 devices · 1 unavailable"),
            Triple(announce(0, 1, 0), true, "Photo added · no devices reached"),
            Triple(announce(1, 0, 0, stored = false), false, "Meshelf couldn’t keep this item"),
        )
        for ((result, photo, expected) in cases) {
            val text = render(ShelfWording.announce(result, photo))!!
            assertEquals(expected, text)
            assertFalse(text.contains("c9b14a4c"))
        }
        val unreadable = ShelfResult.Rejected(DecodeFailure(DecodeFailure.Kind.INVALID, 0, "x"))
        assertEquals("Result couldn’t be read — check the shelf", render(ShelfWording.announce(unreadable, false)))
    }

    private fun refresh(newItems: Long, status: PeerStatus) =
        ShelfResult.Ok(RefreshResult(newItems, ShelfSnapshot(true, ShelfCompleteness.COMPLETE, "EMBER", emptyList(), status)))

    private fun observed(vararg reach: PeerReachability) = PeerStatus.Observed(
        PeerObservation(
            PeerTrigger.REFRESH,
            reach.mapIndexed { i, r ->
                PeerEntry("d$i", "P$i", r, if (r == PeerReachability.REACHABLE) PeerOutcome.CATALOG_APPLIED else PeerOutcome.TRANSPORT_FAILED)
            },
        ),
    )

    @Test fun refreshSentences() {
        val up = PeerReachability.REACHABLE
        val down = PeerReachability.UNAVAILABLE
        assertEquals("2 new items", render(ShelfWording.refresh(refresh(2, observed(up)))))
        assertEquals("1 new item · 1 device unavailable", render(ShelfWording.refresh(refresh(1, observed(up, down)))))
        assertEquals("Shelf is up to date", render(ShelfWording.refresh(refresh(0, observed(up, up)))))
        assertEquals("Updated · 1 device unavailable", render(ShelfWording.refresh(refresh(0, observed(up, down)))))
        assertEquals("Updated · 2 devices unavailable", render(ShelfWording.refresh(refresh(0, observed(up, down, down)))))
        assertEquals("No devices reached", render(ShelfWording.refresh(refresh(0, observed(down, down)))))
        assertEquals("No devices reached", render(ShelfWording.refresh(refresh(0, observed()))))
        fun failedStore(vararg outcomes: PeerOutcome) = PeerStatus.Observed(
            PeerObservation(PeerTrigger.REFRESH, outcomes.mapIndexed { i, o ->
                PeerEntry("d$i", "P$i", if (o == PeerOutcome.TRANSPORT_FAILED) down else up, o)
            }),
        )
        // A reached device whose catalog couldn't be stored must never read as "up to date".
        assertEquals("Items from 1 device couldn’t be stored",
            render(ShelfWording.refresh(refresh(0, failedStore(PeerOutcome.CATALOG_FAILED)))))
        assertEquals("Updated · Items from 1 device couldn’t be stored",
            render(ShelfWording.refresh(refresh(0, failedStore(PeerOutcome.CATALOG_APPLIED, PeerOutcome.CATALOG_FAILED)))))
        assertEquals("1 new item · 1 device unavailable · Items from 1 device couldn’t be stored",
            render(ShelfWording.refresh(refresh(1, failedStore(PeerOutcome.CATALOG_APPLIED, PeerOutcome.TRANSPORT_FAILED, PeerOutcome.CATALOG_FAILED)))))
        // Without a readable per-peer report the phone must not claim the shelf is up to date.
        assertEquals("Peer status couldn’t be read", render(ShelfWording.refresh(refresh(0, PeerStatus.Unreadable))))
        assertEquals("2 new items · Peer status couldn’t be read", render(ShelfWording.refresh(refresh(2, PeerStatus.Unreadable))))
    }

    @Test fun snapshotNoticesAndPeerDescriptions() {
        assertEquals("Shelf data couldn’t be read", render(ShelfWording.snapshotNotice(DecodeFailure(DecodeFailure.Kind.INVALID, 0, "x"))))
        assertEquals("Shelf data couldn’t be read · 2 invalid items", render(ShelfWording.snapshotNotice(DecodeFailure(DecodeFailure.Kind.INVALID, 2, "x"))))
        assertEquals("Shelf data couldn’t be read · 1 invalid item · Update meshelf to read this shelf",
            render(ShelfWording.snapshotNotice(DecodeFailure(DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA, 1, "x"))))
        val peer = PeerEntry("d", "CEDAR", PeerReachability.REACHABLE, PeerOutcome.REFUSED)
        assertEquals("CEDAR, reached", render(ShelfWording.peer(peer, pending = false)))
        assertEquals("CEDAR, pending", render(ShelfWording.peer(peer, pending = true)))
        assertEquals("CEDAR, unavailable", render(ShelfWording.peer(peer.copy(reachability = PeerReachability.UNAVAILABLE, outcome = PeerOutcome.NO_ADDRESS), pending = false)))
    }
}
