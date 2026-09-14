package com.meshelf.android.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingReducerTest {
    // Ids contain hex letters so that uppercasing one really produces a different, invalid id.
    private val id1 = "1a".repeat(16)
    private val hash1 = "a".repeat(64)
    private val id2 = "2b".repeat(16)
    private val hash2 = "b".repeat(64)

    private fun arrived(
        id: String,
        hash: String,
        name: String = "CEDAR",
        code: String = "012345",
        expiresAtMs: Long = 60_000L,
        nowMs: Long = 1_000L,
    ) = PairingEvent.CandidateArrived(id, name, code, hash, expiresAtMs, nowMs)

    private fun run(vararg events: PairingEvent): PairingTransition =
        events.fold(PairingTransition(PairingState.Opening)) { t, e -> PairingReducer.reduce(t.state, e) }

    private val candidate1 = PairingCandidate(id1, "CEDAR", "012345", hash1, 60_000L)

    @Test fun waitingThenCandidateThenConfirmedThenFinished() {
        val waiting = run(PairingEvent.WindowOpened(121_000L))
        assertEquals(PairingState.Waiting(121_000L), waiting.state)

        val showing = PairingReducer.reduce(waiting.state, arrived(id1, hash1))
        assertEquals(PairingState.Showing(candidate1), showing.state)
        assertNull("showing a code must not approve anything", showing.action)

        val confirmed = PairingReducer.reduce(showing.state, PairingEvent.ConfirmTapped(2_000L))
        assertEquals(PairingState.Confirmed(candidate1), confirmed.state)
        assertEquals(PairingAction.Confirm(id1, hash1), confirmed.action)

        val finished = PairingReducer.reduce(confirmed.state, PairingEvent.PairingFinished(id1, "paired"))
        assertEquals(PairingState.Finished(candidate1, "paired"), finished.state)
    }

    @Test fun rejectRejectsTheShownAttemptAndThenShowsItsOutcome() {
        val rejected = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1), PairingEvent.RejectTapped)
        assertEquals(PairingState.Rejected(candidate1), rejected.state)
        assertEquals(PairingAction.Reject(id1), rejected.action)

        val finished = PairingReducer.reduce(rejected.state, PairingEvent.PairingFinished(id1, "declined"))
        assertEquals(PairingState.Finished(candidate1, "declined"), finished.state)
    }

    // Approval must bind to the exchange the person compared. If a second attempt arrives while the first
    // is on screen, showing it would let a tap meant for one code approve another.
    @Test fun secondCandidateIsNeverDisplayedAndConfirmStillCarriesTheShownHash() {
        val showing = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1))
        val second = PairingReducer.reduce(showing.state, arrived(id2, hash2, name = "INTRUDER", code = "999999"))
        assertEquals(PairingState.Showing(candidate1), second.state)
        assertEquals(PairingAction.Reject(id2), second.action)

        val confirmed = PairingReducer.reduce(second.state, PairingEvent.ConfirmTapped(2_000L))
        assertEquals(PairingAction.Confirm(id1, hash1), confirmed.action)

        val secondWhileConfirming = PairingReducer.reduce(confirmed.state, arrived(id2, hash2))
        assertEquals(PairingState.Confirmed(candidate1), secondWhileConfirming.state)
        assertEquals(PairingAction.Reject(id2), secondWhileConfirming.action)
    }

    @Test fun repeatedDeliveryOfTheShownCandidateChangesNothing() {
        val showing = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1))
        assertEquals(showing.state, PairingReducer.reduce(showing.state, arrived(id1, hash1)).state)
        assertNull(PairingReducer.reduce(showing.state, arrived(id1, hash1)).action)
    }

    @Test fun confirmCanBeSentOnlyOnce() {
        val confirmed = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1), PairingEvent.ConfirmTapped(2_000L))
        val again = PairingReducer.reduce(confirmed.state, PairingEvent.ConfirmTapped(2_500L))
        assertEquals(confirmed.state, again.state)
        assertNull(again.action)
    }

    // The name arrives from the peer before any trust exists; the screen must say so every time it shows it.
    @Test fun deviceNameIsFlaggedUnverified() {
        val showing = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1)).state as PairingState.Showing
        assertFalse(showing.candidate.deviceNameVerified)
        val states = listOf(
            showing,
            PairingState.Confirmed(showing.candidate),
            PairingState.Rejected(showing.candidate),
            PairingState.Finished(showing.candidate, "paired"),
        )
        states.forEach { state ->
            val peer = PairingScreen.render(state) { "t" }.peer
            assertTrue(peer, peer.contains("unverified") && peer.contains("CEDAR"))
        }
        val screen = PairingScreen.render(showing) { "t" }
        assertEquals("012345", screen.code)
        assertTrue(screen.confirmEnabled)
        assertEquals("Reject", screen.secondaryLabel)
    }

    @Test fun onlyTheShownScreenEnablesCodesMatch() {
        listOf(
            PairingState.Opening,
            PairingState.Waiting(121_000L),
            PairingState.Confirmed(candidate1),
            PairingState.Rejected(candidate1),
            PairingState.Finished(candidate1, null),
            PairingState.Ended("off"),
        ).forEach { assertFalse(it.toString(), PairingScreen.render(it) { "t" }.confirmEnabled) }
    }

    @Test fun finishedForAnotherAttemptIsIgnored() {
        val showing = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1))
        val other = PairingReducer.reduce(showing.state, PairingEvent.PairingFinished(id2, "closed"))
        assertEquals(showing.state, other.state)
    }

    @Test fun unreadableResultIsReportedAsSuch() {
        val finished = run(
            PairingEvent.WindowOpened(121_000L),
            arrived(id1, hash1),
            PairingEvent.PairingFinished(id1, "paired\nextra"),
        )
        assertEquals(PairingState.Finished(candidate1, null), finished.state)
        assertTrue(PairingScreen.render(finished.state) { "t" }.status.contains("could not display"))
    }

    @Test fun expiredCandidateIsRejectedNotShown() {
        val waiting = run(PairingEvent.WindowOpened(121_000L))
        val late = PairingReducer.reduce(waiting.state, arrived(id1, hash1, expiresAtMs = 1_000L, nowMs = 1_000L))
        assertEquals(waiting.state, late.state)
        assertEquals(PairingAction.Reject(id1), late.action)
    }

    @Test fun confirmAfterTheCandidateExpiredRejectsInsteadOfConfirming() {
        val showing = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1, expiresAtMs = 5_000L))
        val late = PairingReducer.reduce(showing.state, PairingEvent.ConfirmTapped(5_000L))
        assertTrue(late.state is PairingState.Ended)
        assertEquals(PairingAction.Reject(id1), late.action)
    }

    @Test fun malformedCandidateClosesTheWindow() {
        val waiting = run(PairingEvent.WindowOpened(121_000L))
        listOf(
            arrived(id1, hash1.uppercase()),
            arrived(id1.uppercase(), hash1),
            arrived(id1, hash1, code = "12345"),
            arrived(id1, hash1, name = "bad\nname"),
        ).forEach { bad ->
            val t = PairingReducer.reduce(waiting.state, bad)
            assertTrue(t.state is PairingState.Ended)
            assertEquals(PairingAction.CloseWindow, t.action)
        }
    }

    @Test fun newAttemptAfterAFinishedOneIsShown() {
        val finished = run(
            PairingEvent.WindowOpened(121_000L),
            arrived(id1, hash1),
            PairingEvent.RejectTapped,
            PairingEvent.PairingFinished(id1, "declined"),
        )
        val next = PairingReducer.reduce(finished.state, arrived(id2, hash2))
        assertEquals(PairingAction.Confirm(id2, hash2), PairingReducer.reduce(next.state, PairingEvent.ConfirmTapped(2_000L)).action)
    }

    @Test fun candidateAfterTheScreenEndedIsRejected() {
        val ended = run(PairingEvent.Unavailable("availability is off"))
        val t = PairingReducer.reduce(ended.state, arrived(id1, hash1))
        assertEquals(ended.state, t.state)
        assertEquals(PairingAction.Reject(id1), t.action)
    }

    @Test fun listenerStopEndsAnAttemptButKeepsAFinishedOutcome() {
        val showing = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1))
        assertTrue(PairingReducer.reduce(showing.state, PairingEvent.Unavailable("stopped")).state is PairingState.Ended)
        val finished = PairingState.Finished(candidate1, "paired")
        assertEquals(finished, PairingReducer.reduce(finished, PairingEvent.Unavailable("stopped")).state)
    }

    @Test fun failedNativeCallEndsTheScreen() {
        val confirmed = run(PairingEvent.WindowOpened(121_000L), arrived(id1, hash1), PairingEvent.ConfirmTapped(2_000L))
        val failed = PairingReducer.reduce(confirmed.state, PairingEvent.NativeCallFailed("Could not confirm"))
        assertEquals(PairingState.Ended("Could not confirm"), failed.state)
    }
}
