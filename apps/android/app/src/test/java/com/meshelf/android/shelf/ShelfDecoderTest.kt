package com.meshelf.android.shelf

import com.meshelf.android.shelf.ShelfJsonFixtures.attempt
import com.meshelf.android.shelf.ShelfJsonFixtures.card
import com.meshelf.android.shelf.ShelfJsonFixtures.observation
import com.meshelf.android.shelf.ShelfJsonFixtures.peer
import com.meshelf.android.shelf.ShelfJsonFixtures.snapshot
import com.meshelf.android.shelf.ShelfJsonFixtures.textCards
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The production decoder must fail closed: a contract violation keeps the last good shelf on screen
 * instead of silently rendering an empty or partial shelf as if it were complete (AGENTS.md rule).
 */
class ShelfDecoderTest {
    private fun ok(json: String): ShelfSnapshot = when (val d = ShelfDecoder.snapshot(json)) {
        is Decoded.Ok -> d.value
        is Decoded.Rejected -> fail("expected valid snapshot, got ${d.failure}") as Nothing
    }

    private fun rejected(json: String): DecodeFailure = when (val d = ShelfDecoder.snapshot(json)) {
        is Decoded.Ok -> fail("expected rejection, decoded $d") as Nothing
        is Decoded.Rejected -> d.failure
    }

    /** A READY card with nothing to do would look tappable, then claim the phone can't open it. */
    @Test fun readyCardWithoutActionsIsRejected() {
        val failure = rejected(snapshot(cards = listOf(card(actions = emptyList()))))
        assertEquals(DecodeFailure.Kind.INVALID, failure.kind)
        assertEquals(1, failure.invalidRecords)
    }

    /** A peer that answered but whose catalog this phone couldn't store was still reached. */
    @Test fun catalogFailedIsAReachableOutcome() {
        val s = ok(snapshot(peerObservation = observation("REFRESH", peer("a", "CEDAR", "REACHABLE", "CATALOG_FAILED"))))
        val observed = s.peerStatus as PeerStatus.Observed
        assertEquals(PeerOutcome.CATALOG_FAILED, observed.observation.peers.single().outcome)
        val contradictory = ok(snapshot(peerObservation = observation("REFRESH", peer("a", "CEDAR", "UNAVAILABLE", "CATALOG_FAILED"))))
        assertEquals(PeerStatus.Unreadable, contradictory.peerStatus)
    }

    @Test fun decodesOwnAndReceivedCardsOfEveryKind() {
        val s = ok(
            snapshot(
                cards = listOf(
                    card(offerId = "t", kind = "TEXT", preview = "ORIENT", shelfSequence = 9),
                    card(offerId = "f", ownership = "OWN", sourceDisplayName = "EMBER", kind = "FILE", displayName = "report.pdf",
                        preview = "", byteLength = 1400, shelfSequence = 8, actions = listOf("SHARE_FILE", "SAVE_FILE")),
                    card(offerId = "p", kind = "PHOTO", displayName = "IMG_1.jpg", preview = "", shelfSequence = 7,
                        actions = listOf("SHARE_FILE", "SAVE_FILE"), lastAttempt = attempt("UNCERTAIN_NO_REPLAY", detail = "\"cut\"")),
                    card(offerId = "p2", ownership = "OWN", kind = "PHOTO", displayName = "IMG_2.jpg", preview = "", shelfSequence = 6,
                        availability = "SOURCE_CHANGED", actions = emptyList()),
                    card(offerId = "d", kind = "FOLDER", displayName = "bundle", preview = "", shelfSequence = 5,
                        availability = "UNSUPPORTED", actions = emptyList()),
                    card(offerId = "o", ownership = "OWN", kind = "TEXT", shelfSequence = 4, availability = "SOURCE_OFFLINE", actions = emptyList()),
                ),
                peerObservation = observation(
                    "REFRESH",
                    peer("a", "CEDAR", "REACHABLE", "CATALOG_APPLIED"),
                    peer("b", "FERN", "UNAVAILABLE", "TRANSPORT_FAILED"),
                ),
            ),
        )
        assertEquals(true, s.ready)
        assertEquals("EMBER", s.localDisplayName)
        assertEquals(listOf("t", "f", "p", "p2", "d", "o"), s.cards.map { it.key.offerId })
        val text = s.cards[0]
        val file = s.cards[1]
        val photo = s.cards[2]
        val changed = s.cards[3]
        val folder = s.cards[4]
        val offline = s.cards[5]
        assertEquals(ActivationAction.COPY_TEXT, text.primaryAction())
        assertEquals(false, text.supportsSave())
        assertEquals(ShelfOwnership.OWN, file.ownership)
        assertEquals(ActivationAction.SHARE_FILE, file.primaryAction())
        assertTrue(file.supportsSave())
        assertEquals(ShelfKind.PHOTO, photo.kind)
        assertEquals(AttemptCode.UNCERTAIN_NO_REPLAY, photo.lastAttempt?.code)
        assertEquals("cut", photo.lastAttempt?.detail)
        assertNull(changed.primaryAction())
        assertNull(folder.primaryAction())
        assertEquals(ShelfAvailability.UNSUPPORTED, folder.availability)
        assertEquals(ShelfAvailability.SOURCE_OFFLINE, offline.availability)
        val peers = (s.peerStatus as PeerStatus.Observed).observation.peers
        assertEquals(listOf(PeerReachability.REACHABLE, PeerReachability.UNAVAILABLE), peers.map { it.reachability })
    }

    @Test fun emptyAndTenCardShelvesAreValid() {
        assertTrue(ok(snapshot()).cards.isEmpty())
        assertEquals(PeerStatus.None, ok(snapshot()).peerStatus)
        assertEquals(10, ok(snapshot(cards = textCards(10))).cards.size)
    }

    @Test fun elevenCardsRejectTheSnapshot() {
        assertEquals(DecodeFailure.Kind.INVALID, rejected(snapshot(cards = textCards(11))).kind)
    }

    @Test fun missingCardsIsNotAnEmptyShelf() {
        assertEquals(DecodeFailure.Kind.INVALID, rejected(snapshot(omit = "cards")).kind)
    }

    @Test fun everyMissingSnapshotFieldRejects() {
        for (field in listOf("schemaVersion", "ready", "completeness", "localDisplayName", "cards")) {
            assertEquals(field, DecodeFailure.Kind.INVALID, rejected(snapshot(cards = textCards(1), omit = field)).kind)
        }
    }

    @Test fun everyMissingCardFieldRejectsIncludingExplicitNullables() {
        val fields = listOf(
            "sourceDevice", "offerId", "sourceDisplayName", "ownership", "kind", "displayName", "preview",
            "byteLength", "shelfSequence", "availability", "supportedActions", "activeOperation", "lastAttempt",
        )
        for (field in fields) {
            val failure = rejected(snapshot(cards = listOf(card(omit = field))))
            assertEquals(field, DecodeFailure.Kind.INVALID, failure.kind)
            assertEquals(field, 1, failure.invalidRecords)
        }
    }

    @Test fun unknownEnumsRejectAsUnsupportedSchema() {
        val cases = listOf(
            snapshot(cards = listOf(card(kind = "VIDEO"))),
            snapshot(cards = listOf(card(availability = "MAYBE", actions = emptyList()))),
            snapshot(cards = listOf(card(ownership = "SHARED"))),
            snapshot(cards = listOf(card(actions = listOf("PRINT")))),
            snapshot(cards = listOf(card(lastAttempt = attempt("SOMETHING_NEW")))),
            snapshot(completeness = "\"PARTIAL\""),
        )
        cases.forEach { assertEquals(it, DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA, rejected(it).kind) }
    }

    @Test fun wrongSchemaVersionRejects() {
        assertEquals(DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA, rejected(snapshot(schemaVersion = "1")).kind)
        assertEquals(DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA, rejected(snapshot(schemaVersion = "3")).kind)
        assertEquals(DecodeFailure.Kind.INVALID, rejected(snapshot(schemaVersion = "\"2\"")).kind)
    }

    @Test fun duplicateCardKeyAndDuplicateMemberReject() {
        val twice = snapshot(cards = listOf(card(offerId = "x", shelfSequence = 2), card(offerId = "x", shelfSequence = 1)))
        assertEquals(DecodeFailure.Kind.INVALID, rejected(twice).kind)
        val duplicateMember = snapshot(cards = textCards(1)).replaceFirst("{", "{\"ready\":false,")
        assertEquals(DecodeFailure.Kind.INVALID, rejected(duplicateMember).kind)
    }

    @Test fun malformedPeerObservationKeepsTheCards() {
        val badEnum = observation("REFRESH", peer("a", "CEDAR", "SOMETIMES", "STORED"))
        val disagrees = observation("REFRESH", peer("a", "CEDAR", "REACHABLE", "NO_ADDRESS"))
        for (bad in listOf(badEnum, disagrees, "[]", "{\"trigger\":\"REFRESH\"}")) {
            val s = ok(snapshot(cards = textCards(2), peerObservation = bad))
            assertEquals(bad, 2, s.cards.size)
            assertEquals(bad, PeerStatus.Unreadable, s.peerStatus)
        }
        val missing = ok(snapshot(cards = textCards(2), omit = "peerObservation"))
        assertEquals(PeerStatus.Unreadable, missing.peerStatus)
    }

    @Test fun cardsMustFollowNativeCapabilityRules() {
        val invalid = listOf(
            card(kind = "FOLDER", availability = "READY", actions = emptyList()),
            card(kind = "FOLDER", availability = "UNSUPPORTED", actions = listOf("SAVE_FILE")),
            card(availability = "SOURCE_CHANGED", actions = listOf("COPY_TEXT")),
            card(kind = "FILE", actions = listOf("SAVE_FILE", "SHARE_FILE")),
            card(kind = "TEXT", actions = listOf("SHARE_FILE")),
            card(actions = listOf("COPY_TEXT", "COPY_TEXT")),
            card(sourceDisplayName = ""),
            card(preview = "é".repeat(129)),
            card(byteLength = -1),
        )
        invalid.forEach { assertEquals(it, DecodeFailure.Kind.INVALID, rejected(snapshot(cards = listOf(it))).kind) }
        assertEquals(
            DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA,
            rejected(snapshot(cards = listOf(card(activeOperation = "{\"phase\":\"TRANSFERRING\"}")))).kind,
        )
    }

    @Test fun invalidCardsAreCountedAndNeverDropped() {
        val failure = rejected(snapshot(cards = listOf(card(offerId = "a", kind = "X", shelfSequence = 3), card(offerId = "b", shelfSequence = 2), card(offerId = "c", omit = "kind"))))
        assertEquals(2, failure.invalidRecords)
    }

    @Test fun cardsMustBeNewestFirst() {
        val oldestFirst = snapshot(cards = listOf(card(offerId = "a", shelfSequence = 1), card(offerId = "b", shelfSequence = 2)))
        assertEquals(DecodeFailure.Kind.INVALID, rejected(oldestFirst).kind)
    }

    @Test fun malformedJsonRejects() {
        for (bad in listOf("", "null", "[]", snapshot().dropLast(1), snapshot() + "x", "{\"schemaVersion\":2,}")) {
            assertTrue(bad, ShelfDecoder.snapshot(bad) is Decoded.Rejected)
        }
    }

    @Test fun refreshCarriesItsOwnObservation() {
        val observed = observation("REFRESH", peer("a", "CEDAR", "REACHABLE", "REFUSED"))
        val refresh = ShelfDecoder.refresh("""{"schemaVersion":2,"newItems":2,"snapshot":${snapshot(cards = textCards(2), peerObservation = observed)}}""")
        refresh as Decoded.Ok
        assertEquals(2L, refresh.value.newItems)
        assertTrue(refresh.value.snapshot.peerStatus is PeerStatus.Observed)

        val announceTrigger = ShelfDecoder.refresh("""{"schemaVersion":2,"newItems":0,"snapshot":${snapshot(peerObservation = observation("ANNOUNCE"))}}""")
        assertEquals(PeerStatus.Unreadable, (announceTrigger as Decoded.Ok).value.snapshot.peerStatus)
        val absent = ShelfDecoder.refresh("""{"schemaVersion":2,"newItems":0,"snapshot":${snapshot()}}""")
        assertEquals(PeerStatus.Unreadable, (absent as Decoded.Ok).value.snapshot.peerStatus)

        assertTrue(ShelfDecoder.refresh("""{"schemaVersion":2,"newItems":0,"snapshot":${snapshot(cards = textCards(11))}}""") is Decoded.Rejected)
        assertTrue(ShelfDecoder.refresh("""{"schemaVersion":2,"snapshot":${snapshot()}}""") is Decoded.Rejected)
    }

    @Test fun announceCountsMustMatchPeers() {
        val peers = listOf(
            peer("a", "CEDAR", "REACHABLE", "STORED"),
            peer("b", "FERN", "UNAVAILABLE", "NO_ADDRESS"),
            peer("c", "BIRCH", "REACHABLE", "REFUSED"),
        ).joinToString(",", "[", "]")
        fun announce(added: Int, unavailable: Int, refused: Int, extra: String = "\"localStored\":true,") =
            """{"schemaVersion":2,"offerId":"o",$extra"addedCount":$added,"unavailableCount":$unavailable,"refusedCount":$refused,"peers":$peers}"""
        val good = ShelfDecoder.announce(announce(1, 1, 1)) as Decoded.Ok
        assertEquals(3, good.value.peers.size)
        assertTrue(ShelfDecoder.announce(announce(2, 1, 0)) is Decoded.Rejected)
        assertTrue(ShelfDecoder.announce(announce(1, 1, 1, extra = "")) is Decoded.Rejected)
        assertTrue(ShelfDecoder.announce("c9b14a4c-0000-4000-8000-000000000000") is Decoded.Rejected)
    }

    @Test fun activationResultIsStrict() {
        fun activation(status: String, code: String, detail: String = "null") =
            """{"schemaVersion":2,"sourceDevice":"s","offerId":"o","action":"COPY_TEXT","status":"$status","code":"$code","filesProcessed":0,"bytesProcessed":12,"detail":$detail}"""
        val ok = ShelfDecoder.activation(activation("COMPLETED", "COMPLETED")) as Decoded.Ok
        assertEquals(ShelfKey("s", "o"), ok.value.key)
        for (code in ActivationCode.entries.filter { it != ActivationCode.COMPLETED }) {
            assertTrue(code.name, ShelfDecoder.activation(activation("FAILED", code.name, "\"bounded\"")) is Decoded.Ok)
        }
        assertTrue(ShelfDecoder.activation(activation("COMPLETED", "BUSY")) is Decoded.Rejected)
        assertTrue(ShelfDecoder.activation(activation("FAILED", "COMPLETED")) is Decoded.Rejected)
        val unknown = ShelfDecoder.activation(activation("FAILED", "EXPLODED")) as Decoded.Rejected
        assertEquals(DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA, unknown.failure.kind)
        // ABI-7 free-form strings must never be read as an outcome.
        assertTrue(ShelfDecoder.activation("completed") is Decoded.Rejected)
        assertTrue(ShelfDecoder.activation("failed:uncertain") is Decoded.Rejected)
    }
}
