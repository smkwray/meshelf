package com.meshelf.android.pairing

import com.meshelf.android.capture.RequestText

/** One pairing attempt as Rust reported it. The device name is the peer's claim, never verified. */
data class PairingCandidate(
    val pairingId: String,
    val claimedDeviceName: String,
    val sixDigitCode: String,
    val transcriptHash: String,
    val expiresAtMs: Long,
) {
    init {
        RequestText.requirePairingId(pairingId)
        RequestText.requireDeviceName(claimedDeviceName)
        RequestText.requirePairingCode(sixDigitCode)
        RequestText.requireTranscriptHash(transcriptHash)
    }

    val deviceNameVerified: Boolean get() = false
}

sealed interface PairingState {
    /** The screen asked the service to open the window and has no answer yet. */
    data object Opening : PairingState
    data class Waiting(val windowExpiresAtMs: Long) : PairingState
    data class Showing(val candidate: PairingCandidate) : PairingState
    data class Confirmed(val candidate: PairingCandidate) : PairingState
    data class Rejected(val candidate: PairingCandidate) : PairingState

    /** Rust's `onPairingFinished`; [result] is null when the text could not be shown safely. */
    data class Finished(val candidate: PairingCandidate, val result: String?) : PairingState

    /** Terminal without a Rust result: availability off, a native call failed, or bad input. */
    data class Ended(val message: String) : PairingState
}

sealed interface PairingEvent {
    data class WindowOpened(val expiresAtMs: Long) : PairingEvent
    data class Unavailable(val message: String) : PairingEvent
    data class CandidateArrived(
        val pairingId: String,
        val deviceName: String,
        val sixDigitCode: String,
        val transcriptHash: String,
        val expiresAtMs: Long,
        val nowMs: Long,
    ) : PairingEvent
    data class ConfirmTapped(val nowMs: Long) : PairingEvent
    data object RejectTapped : PairingEvent
    data class PairingFinished(val pairingId: String, val result: String) : PairingEvent
    data class NativeCallFailed(val message: String) : PairingEvent
}

/** What the screen must ask the service to do after a transition. */
sealed interface PairingAction {
    data class Confirm(val pairingId: String, val transcriptHash: String) : PairingAction
    data class Reject(val pairingId: String) : PairingAction
    data object CloseWindow : PairingAction
}

data class PairingTransition(val state: PairingState, val action: PairingAction? = null)

/**
 * Pure pairing-screen logic. One candidate is on screen at a time; approval is bound to the
 * transcript hash of the candidate on screen, never to whatever attempt is live when the tap lands.
 */
object PairingReducer {
    fun reduce(state: PairingState, event: PairingEvent): PairingTransition = when (event) {
        is PairingEvent.WindowOpened ->
            if (state == PairingState.Opening) PairingTransition(PairingState.Waiting(event.expiresAtMs))
            else PairingTransition(state)

        is PairingEvent.Unavailable ->
            if (state.isTerminal()) PairingTransition(state)
            else PairingTransition(PairingState.Ended(event.message))

        is PairingEvent.CandidateArrived -> candidateArrived(state, event)

        is PairingEvent.ConfirmTapped -> when {
            state !is PairingState.Showing -> PairingTransition(state)
            event.nowMs >= state.candidate.expiresAtMs -> PairingTransition(
                PairingState.Ended("This code expired before it was confirmed. Nothing was trusted."),
                PairingAction.Reject(state.candidate.pairingId),
            )
            else -> PairingTransition(
                PairingState.Confirmed(state.candidate),
                PairingAction.Confirm(state.candidate.pairingId, state.candidate.transcriptHash),
            )
        }

        PairingEvent.RejectTapped ->
            if (state is PairingState.Showing) {
                PairingTransition(PairingState.Rejected(state.candidate), PairingAction.Reject(state.candidate.pairingId))
            } else {
                PairingTransition(state)
            }

        is PairingEvent.PairingFinished -> {
            val candidate = state.liveCandidate()
            if (candidate == null || candidate.pairingId != event.pairingId) {
                PairingTransition(state)
            } else {
                val result = runCatching { RequestText.requirePairingResult(event.result) }.getOrNull()
                PairingTransition(PairingState.Finished(candidate, result))
            }
        }

        is PairingEvent.NativeCallFailed ->
            if (state is PairingState.Finished) PairingTransition(state)
            else PairingTransition(PairingState.Ended(event.message))
    }

    private fun candidateArrived(
        state: PairingState,
        event: PairingEvent.CandidateArrived,
    ): PairingTransition {
        val candidate = try {
            PairingCandidate(
                pairingId = event.pairingId,
                claimedDeviceName = event.deviceName,
                sixDigitCode = event.sixDigitCode,
                transcriptHash = event.transcriptHash,
                expiresAtMs = event.expiresAtMs,
            )
        } catch (_: IllegalArgumentException) {
            // Rust validated this already, so malformed input means a bridge defect: fail closed.
            return PairingTransition(
                PairingState.Ended("The pairing request was malformed, so the pairing window was closed."),
                PairingAction.CloseWindow,
            )
        }
        val shown = state.liveCandidate()
        return when {
            shown?.pairingId == candidate.pairingId -> PairingTransition(state)
            shown != null -> PairingTransition(state, PairingAction.Reject(candidate.pairingId))
            state is PairingState.Ended -> PairingTransition(state, PairingAction.Reject(candidate.pairingId))
            candidate.expiresAtMs <= event.nowMs ->
                PairingTransition(state, PairingAction.Reject(candidate.pairingId))
            else -> PairingTransition(PairingState.Showing(candidate))
        }
    }

    /** The candidate currently on screen, including one whose confirm or reject is in flight. */
    private fun PairingState.liveCandidate(): PairingCandidate? = when (this) {
        is PairingState.Showing -> candidate
        is PairingState.Confirmed -> candidate
        is PairingState.Rejected -> candidate
        else -> null
    }

    private fun PairingState.isTerminal(): Boolean =
        this is PairingState.Finished || this is PairingState.Ended
}

/** Plain strings for the pairing screen; no markup is interpreted. */
data class PairingScreen(
    val peer: String,
    val code: String,
    val status: String,
    val confirmEnabled: Boolean,
    val secondaryLabel: String,
) {
    companion object {
        private const val NO_CODE = "------"

        fun render(state: PairingState, formatTime: (Long) -> String): PairingScreen = when (state) {
            PairingState.Opening -> PairingScreen(
                peer = "Opening the pairing window…",
                code = NO_CODE,
                status = "",
                confirmEnabled = false,
                secondaryLabel = "Close",
            )
            is PairingState.Waiting -> PairingScreen(
                peer = "Waiting for a computer",
                code = NO_CODE,
                status = "Start pairing on the computer now. This phone accepts a pairing attempt " +
                    "until ${formatTime(state.windowExpiresAtMs)}, and only while this screen is open.",
                confirmEnabled = false,
                secondaryLabel = "Close",
            )
            is PairingState.Showing -> PairingScreen(
                peer = unverifiedPeer(state.candidate),
                code = state.candidate.sixDigitCode,
                status = "Compare this code with the one on the computer's screen. Tap Codes match only " +
                    "if they are identical; otherwise tap Reject.",
                confirmEnabled = true,
                secondaryLabel = "Reject",
            )
            is PairingState.Confirmed -> PairingScreen(
                peer = unverifiedPeer(state.candidate),
                code = state.candidate.sixDigitCode,
                status = "Codes confirmed. Finishing pairing with the computer…",
                confirmEnabled = false,
                secondaryLabel = "Close",
            )
            is PairingState.Rejected -> PairingScreen(
                peer = unverifiedPeer(state.candidate),
                code = state.candidate.sixDigitCode,
                status = "Rejected. Waiting for the computer to acknowledge.",
                confirmEnabled = false,
                secondaryLabel = "Close",
            )
            is PairingState.Finished -> PairingScreen(
                peer = unverifiedPeer(state.candidate),
                code = state.candidate.sixDigitCode,
                status = state.result?.let { "Pairing finished: $it" }
                    ?: "Pairing finished with a result this phone could not display.",
                confirmEnabled = false,
                secondaryLabel = "Close",
            )
            is PairingState.Ended -> PairingScreen(
                peer = "No computer",
                code = NO_CODE,
                status = state.message,
                confirmEnabled = false,
                secondaryLabel = "Close",
            )
        }

        private fun unverifiedPeer(candidate: PairingCandidate): String =
            "Computer (name claimed by the computer, unverified): ${candidate.claimedDeviceName}"
    }
}
