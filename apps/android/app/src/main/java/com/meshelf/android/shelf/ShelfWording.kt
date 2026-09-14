package com.meshelf.android.shelf

import com.meshelf.android.R

/** One user-facing phrase; resolved from res/values so wording lives in resources only. */
enum class Msg(val res: Int) {
    GETTING_READY(R.string.status_getting_ready),
    COPYING(R.string.progress_copying),
    OPENING_SHARE(R.string.progress_opening_share),
    SAVING(R.string.progress_saving),
    COPIED(R.string.result_copied),
    SHARE_OPENED(R.string.result_share_opened),
    SAVED_TO(R.string.result_saved_to),
    SAVED(R.string.result_saved),
    DOWNLOADS(R.string.downloads),
    SOURCE_UNAVAILABLE(R.string.state_source_unavailable),
    SOURCE_CHANGED(R.string.state_source_changed),
    FOLDER_UNSUPPORTED(R.string.state_folder_unsupported),
    ITEM_UNSUPPORTED(R.string.state_unsupported),
    BUSY(R.string.result_busy),
    CANCELED(R.string.result_canceled),
    COPY_FAILED(R.string.result_copy_failed),
    VERIFY_FAILED(R.string.result_verify_failed),
    SAVE_FAILED(R.string.result_save_failed),
    SHARE_FAILED(R.string.result_share_failed),
    FOREGROUND_LOST(R.string.result_foreground_lost),
    UNCERTAIN(R.string.result_uncertain),
    ACTION_UNSUPPORTED(R.string.result_action_unsupported),
    INTERNAL(R.string.result_internal),
    CHOOSE_SAVE_FOLDER(R.string.result_choose_save_folder),
    RESULT_UNREADABLE(R.string.result_unreadable),
    SHELF_UNREADABLE(R.string.notice_shelf_unreadable),
    INVALID_ITEM_ONE(R.string.notice_invalid_one),
    INVALID_ITEMS(R.string.notice_invalid_many),
    UPDATE_APP(R.string.notice_update_app),
    PEER_UNREADABLE(R.string.notice_peer_unreadable),
    ADDED_ONE(R.string.announce_added_one),
    ADDED_MANY(R.string.announce_added_many),
    UNAVAILABLE_COUNT(R.string.announce_unavailable),
    REFUSED_COUNT(R.string.announce_refused),
    KEPT_ON_PHONE(R.string.announce_kept),
    NO_DEVICES_REACHED_TAIL(R.string.announce_no_devices),
    PHOTO_ADDED(R.string.photo_added),
    SENT_TO_ONE(R.string.photo_sent_one),
    SENT_TO_MANY(R.string.photo_sent_many),
    NOT_STORED(R.string.announce_not_stored),
    NEW_ITEM_ONE(R.string.refresh_new_one),
    NEW_ITEMS(R.string.refresh_new_many),
    UP_TO_DATE(R.string.refresh_up_to_date),
    UPDATED(R.string.refresh_updated),
    DEVICE_UNAVAILABLE_ONE(R.string.refresh_device_unavailable_one),
    DEVICES_UNAVAILABLE(R.string.refresh_device_unavailable_many),
    NO_DEVICES_REACHED(R.string.refresh_no_devices),
    NOT_STORED_ONE(R.string.refresh_not_stored_one),
    NOT_STORED_MANY(R.string.refresh_not_stored_many),
    PEER_REACHED(R.string.peer_reached),
    PEER_PENDING(R.string.peer_pending),
    PEER_UNAVAILABLE(R.string.peer_unavailable),
    WAIT_CURRENT_ACTION(R.string.wait_current_action),
    TAP_AGAIN(R.string.tap_again),
    CAMERA_BUSY(R.string.camera_busy),
    CLIPBOARD_NO_TEXT(R.string.clipboard_no_text),
    ENTER_TEXT(R.string.put_enter_text),
    TEXT_TOO_LARGE(R.string.put_text_too_large),
    ADDING(R.string.put_adding),
}

data class UiPart(val msg: Msg, val args: List<Any> = emptyList())

/** A sentence of phrases joined by a middle dot, e.g. `Added to 2 devices · 1 unavailable`. */
data class UiText(val parts: List<UiPart>) {
    operator fun plus(other: UiText) = UiText(parts + other.parts)

    /** [lookup] formats one resource; a [UiPart] argument is itself resolved first. */
    fun render(lookup: (Msg, Array<Any>) -> String): String = parts.joinToString(SEPARATOR) { renderPart(it, lookup) }

    private fun renderPart(part: UiPart, lookup: (Msg, Array<Any>) -> String): String =
        lookup(part.msg, part.args.map { if (it is UiPart) renderPart(it, lookup) else it }.toTypedArray())

    companion object {
        const val SEPARATOR = " · "
        fun of(msg: Msg, vararg args: Any) = UiText(listOf(UiPart(msg, args.toList())))
    }
}

enum class FeedbackIcon { PROGRESS, SUCCESS, STOPPED, BUSY, SOURCE_UNAVAILABLE, WARNING, UNSUPPORTED, UNCERTAIN, ERROR }

/** Card or strip feedback. [detail] is technical text shown only inside Details. */
data class Feedback(
    val text: UiText,
    val icon: FeedbackIcon,
    val transient: Boolean,
    val opensSettings: Boolean = false,
    val detail: String? = null,
)

/** Maps typed native results to the redesign's vocabulary. Raw codes and IDs never pass through. */
object ShelfWording {
    fun inFlight(action: ActivationAction): Feedback = Feedback(
        UiText.of(
            when (action) {
                ActivationAction.COPY_TEXT -> Msg.COPYING
                ActivationAction.SHARE_FILE -> Msg.OPENING_SHARE
                ActivationAction.SAVE_FILE -> Msg.SAVING
            },
        ),
        FeedbackIcon.PROGRESS,
        transient = false,
    )

    fun saveDestinationUnavailable(reason: SaveUnavailableReason): Feedback =
        Feedback(UiText.of(Msg.CHOOSE_SAVE_FOLDER), FeedbackIcon.ERROR, transient = false, opensSettings = true, detail = reason.name)

    fun tapAgain(): Feedback = Feedback(UiText.of(Msg.TAP_AGAIN), FeedbackIcon.STOPPED, transient = false)

    fun activation(
        result: ShelfResult<ActivationResult>,
        action: ActivationAction,
        kind: ShelfKind,
        saveReport: SaveReport?,
    ): Feedback = when (result) {
        is ShelfResult.Rejected -> Feedback(UiText.of(Msg.UNCERTAIN), FeedbackIcon.UNCERTAIN, false, detail = result.failure.detail)
        is ShelfResult.Error -> when (result.code) {
            ShelfErrorCode.NOT_READY -> Feedback(UiText.of(Msg.GETTING_READY), FeedbackIcon.PROGRESS, true, detail = result.detail)
            ShelfErrorCode.RESULT_MISMATCH -> Feedback(UiText.of(Msg.UNCERTAIN), FeedbackIcon.UNCERTAIN, false, detail = result.detail)
            ShelfErrorCode.CAMERA_BUSY, ShelfErrorCode.NATIVE_FAILED ->
                Feedback(UiText.of(Msg.INTERNAL), FeedbackIcon.ERROR, false, detail = result.detail)
        }
        is ShelfResult.Ok -> code(result.value, action, kind, saveReport)
    }

    private fun code(r: ActivationResult, action: ActivationAction, kind: ShelfKind, saveReport: SaveReport?): Feedback {
        val detail = listOfNotNull("${r.status}/${r.code}", r.detail).joinToString(": ")
        fun fb(msg: Msg, icon: FeedbackIcon, transient: Boolean = false) = Feedback(UiText.of(msg), icon, transient, detail = detail)
        return when (r.code) {
            ActivationCode.COMPLETED -> when (action) {
                ActivationAction.COPY_TEXT -> fb(Msg.COPIED, FeedbackIcon.SUCCESS, true)
                ActivationAction.SHARE_FILE -> fb(Msg.SHARE_OPENED, FeedbackIcon.SUCCESS, true)
                ActivationAction.SAVE_FILE -> {
                    val target = (saveReport as? SaveReport.Saved)?.target
                    val text = when (target) {
                        SaveTarget.Downloads -> UiText(listOf(UiPart(Msg.SAVED_TO, listOf(UiPart(Msg.DOWNLOADS)))))
                        is SaveTarget.Folder -> UiText.of(Msg.SAVED_TO, target.label)
                        else -> UiText.of(Msg.SAVED)
                    }
                    Feedback(text, FeedbackIcon.SUCCESS, true, detail = detail)
                }
            }
            ActivationCode.SOURCE_UNAVAILABLE -> fb(Msg.SOURCE_UNAVAILABLE, FeedbackIcon.SOURCE_UNAVAILABLE)
            ActivationCode.SOURCE_CHANGED -> fb(Msg.SOURCE_CHANGED, FeedbackIcon.WARNING)
            ActivationCode.BUSY -> fb(Msg.BUSY, FeedbackIcon.BUSY)
            ActivationCode.CANCELLED -> fb(Msg.CANCELED, FeedbackIcon.STOPPED)
            ActivationCode.CLIPBOARD_FAILED -> fb(Msg.COPY_FAILED, FeedbackIcon.ERROR)
            ActivationCode.VERIFICATION_FAILED -> fb(Msg.VERIFY_FAILED, FeedbackIcon.ERROR)
            ActivationCode.PLATFORM_FAILED -> when (action) {
                ActivationAction.COPY_TEXT -> fb(Msg.COPY_FAILED, FeedbackIcon.ERROR)
                ActivationAction.SHARE_FILE -> fb(Msg.SHARE_FAILED, FeedbackIcon.ERROR)
                ActivationAction.SAVE_FILE -> {
                    val failed = saveReport as? SaveReport.Failed
                    if (failed?.destinationUnavailable == true) {
                        Feedback(UiText.of(Msg.CHOOSE_SAVE_FOLDER), FeedbackIcon.ERROR, false, opensSettings = true, detail = detail)
                    } else {
                        fb(Msg.SAVE_FAILED, FeedbackIcon.ERROR)
                    }
                }
            }
            ActivationCode.FOREGROUND_LOST -> fb(Msg.FOREGROUND_LOST, FeedbackIcon.STOPPED)
            ActivationCode.UNCERTAIN_NO_REPLAY -> fb(Msg.UNCERTAIN, FeedbackIcon.UNCERTAIN)
            ActivationCode.UNSUPPORTED ->
                if (kind == ShelfKind.FOLDER) fb(Msg.FOLDER_UNSUPPORTED, FeedbackIcon.UNSUPPORTED)
                else fb(Msg.ACTION_UNSUPPORTED, FeedbackIcon.UNSUPPORTED)
            ActivationCode.INTERNAL -> fb(Msg.INTERNAL, FeedbackIcon.ERROR)
        }
    }

    /** Stable (non-transient) card state from native availability; null means ready. */
    fun availability(card: ShelfCard): Feedback? = when (card.availability) {
        ShelfAvailability.READY -> null
        ShelfAvailability.SOURCE_OFFLINE -> Feedback(UiText.of(Msg.SOURCE_UNAVAILABLE), FeedbackIcon.SOURCE_UNAVAILABLE, false)
        ShelfAvailability.SOURCE_CHANGED -> Feedback(UiText.of(Msg.SOURCE_CHANGED), FeedbackIcon.WARNING, false)
        ShelfAvailability.UNSUPPORTED ->
            if (card.kind == ShelfKind.FOLDER) Feedback(UiText.of(Msg.FOLDER_UNSUPPORTED), FeedbackIcon.UNSUPPORTED, false)
            else Feedback(UiText.of(Msg.ITEM_UNSUPPORTED), FeedbackIcon.UNSUPPORTED, false)
    }

    /** A recreated Activity shows the durable last attempt unless it simply completed. */
    fun lastAttempt(attempt: LastAttempt?): Feedback? {
        attempt ?: return null
        val detail = listOfNotNull(attempt.code.name, attempt.detail).joinToString(": ")
        fun fb(msg: Msg, icon: FeedbackIcon) = Feedback(UiText.of(msg), icon, false, detail = detail)
        return when (attempt.code) {
            AttemptCode.COMPLETED -> null
            AttemptCode.SOURCE_UNAVAILABLE -> fb(Msg.SOURCE_UNAVAILABLE, FeedbackIcon.SOURCE_UNAVAILABLE)
            AttemptCode.SOURCE_CHANGED -> fb(Msg.SOURCE_CHANGED, FeedbackIcon.WARNING)
            AttemptCode.BUSY -> fb(Msg.BUSY, FeedbackIcon.BUSY)
            AttemptCode.CANCELLED -> fb(Msg.CANCELED, FeedbackIcon.STOPPED)
            AttemptCode.CLIPBOARD_FAILED -> fb(Msg.COPY_FAILED, FeedbackIcon.ERROR)
            AttemptCode.VERIFICATION_FAILED -> fb(Msg.VERIFY_FAILED, FeedbackIcon.ERROR)
            AttemptCode.UNCERTAIN_NO_REPLAY -> fb(Msg.UNCERTAIN, FeedbackIcon.UNCERTAIN)
            AttemptCode.FOREGROUND_LOST -> fb(Msg.FOREGROUND_LOST, FeedbackIcon.STOPPED)
            AttemptCode.UNSUPPORTED -> fb(Msg.ACTION_UNSUPPORTED, FeedbackIcon.UNSUPPORTED)
            AttemptCode.FAILED, AttemptCode.PLATFORM_FAILED, AttemptCode.INTERNAL -> fb(Msg.INTERNAL, FeedbackIcon.ERROR)
        }
    }

    fun announce(result: ShelfResult<AnnounceResult>, photo: Boolean): Feedback = when (result) {
        is ShelfResult.Rejected -> Feedback(UiText.of(Msg.RESULT_UNREADABLE), FeedbackIcon.UNCERTAIN, false, detail = result.failure.detail)
        is ShelfResult.Error -> error(result)
        is ShelfResult.Ok -> {
            val r = result.value
            if (!r.localStored) {
                Feedback(UiText.of(Msg.NOT_STORED), FeedbackIcon.ERROR, false, detail = "localStored=false")
            } else {
                val reached = r.addedCount > 0 || r.refusedCount > 0
                val head = when {
                    photo && r.addedCount > 0 -> UiText.of(Msg.PHOTO_ADDED) + count(r.addedCount, Msg.SENT_TO_ONE, Msg.SENT_TO_MANY)
                    photo -> UiText.of(Msg.PHOTO_ADDED)
                    r.addedCount > 0 -> count(r.addedCount, Msg.ADDED_ONE, Msg.ADDED_MANY)
                    else -> UiText.of(Msg.KEPT_ON_PHONE)
                }
                var text = if (reached) head else head + UiText.of(Msg.NO_DEVICES_REACHED_TAIL)
                if (reached && r.unavailableCount > 0) text += UiText.of(Msg.UNAVAILABLE_COUNT, r.unavailableCount)
                if (r.refusedCount > 0) text += UiText.of(Msg.REFUSED_COUNT, r.refusedCount)
                val icon = if (r.addedCount > 0 && r.unavailableCount == 0L && r.refusedCount == 0L) FeedbackIcon.SUCCESS else FeedbackIcon.WARNING
                Feedback(text, icon, transient = icon == FeedbackIcon.SUCCESS)
            }
        }
    }

    fun refresh(result: ShelfResult<RefreshResult>): Feedback = when (result) {
        is ShelfResult.Rejected -> Feedback(snapshotNotice(result.failure), FeedbackIcon.ERROR, false, detail = result.failure.detail)
        is ShelfResult.Error -> error(result)
        is ShelfResult.Ok -> {
            val newItems = result.value.newItems
            val items = if (newItems > 0) count(newItems, Msg.NEW_ITEM_ONE, Msg.NEW_ITEMS) else null
            when (val status = result.value.snapshot.peerStatus) {
                is PeerStatus.Observed -> {
                    val peers = status.observation.peers
                    val unavailable = peers.count { it.reachability == PeerReachability.UNAVAILABLE }.toLong()
                    val failed = peers.count { it.outcome == PeerOutcome.CATALOG_FAILED }.toLong()
                    val reached = peers.size - unavailable
                    var problems = UiText(emptyList())
                    if (unavailable > 0) problems += count(unavailable, Msg.DEVICE_UNAVAILABLE_ONE, Msg.DEVICES_UNAVAILABLE)
                    // A device that answered but whose items this phone couldn't store is never "up to date".
                    if (failed > 0) problems += count(failed, Msg.NOT_STORED_ONE, Msg.NOT_STORED_MANY)
                    when {
                        items != null && problems.parts.isNotEmpty() -> Feedback(items + problems, FeedbackIcon.WARNING, false)
                        items != null -> Feedback(items, FeedbackIcon.SUCCESS, true)
                        reached == 0L -> Feedback(UiText.of(Msg.NO_DEVICES_REACHED), FeedbackIcon.WARNING, false)
                        reached == failed -> Feedback(problems, FeedbackIcon.WARNING, false)
                        problems.parts.isNotEmpty() -> Feedback(UiText.of(Msg.UPDATED) + problems, FeedbackIcon.WARNING, false)
                        else -> Feedback(UiText.of(Msg.UP_TO_DATE), FeedbackIcon.SUCCESS, true)
                    }
                }
                // No trustworthy per-peer report: say only what native counted, never "up to date".
                PeerStatus.None, PeerStatus.Unreadable ->
                    Feedback((items ?: UiText(emptyList())) + UiText.of(Msg.PEER_UNREADABLE), FeedbackIcon.WARNING, false)
            }
        }
    }

    fun snapshotNotice(failure: DecodeFailure): UiText {
        var text = UiText.of(Msg.SHELF_UNREADABLE)
        if (failure.invalidRecords > 0) text += count(failure.invalidRecords.toLong(), Msg.INVALID_ITEM_ONE, Msg.INVALID_ITEMS)
        if (failure.kind == DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA) text += UiText.of(Msg.UPDATE_APP)
        return text
    }

    fun error(result: ShelfResult.Error): Feedback = when (result.code) {
        ShelfErrorCode.NOT_READY -> Feedback(UiText.of(Msg.GETTING_READY), FeedbackIcon.PROGRESS, false, detail = result.detail)
        ShelfErrorCode.CAMERA_BUSY -> Feedback(UiText.of(Msg.CAMERA_BUSY), FeedbackIcon.BUSY, false, detail = result.detail)
        ShelfErrorCode.NATIVE_FAILED, ShelfErrorCode.RESULT_MISMATCH ->
            Feedback(UiText.of(Msg.INTERNAL), FeedbackIcon.ERROR, false, detail = result.detail)
    }

    fun peer(entry: PeerEntry, pending: Boolean): UiText = UiText.of(
        when {
            pending -> Msg.PEER_PENDING
            entry.reachability == PeerReachability.REACHABLE -> Msg.PEER_REACHED
            else -> Msg.PEER_UNAVAILABLE
        },
        entry.displayName,
    )

    private fun count(n: Long, one: Msg, many: Msg): UiText = if (n == 1L) UiText.of(one) else UiText.of(many, n)
}
