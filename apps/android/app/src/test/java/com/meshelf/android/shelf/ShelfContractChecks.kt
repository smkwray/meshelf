package com.meshelf.android.shelf

/** Calls the shipped production helpers. Does not claim Activity/JNI/provider coverage. */
fun runShelfContractChecks(): List<String> {
    val passed = mutableListOf<String>()
    fun test(name: String, block: () -> Unit) { block(); passed += name }
    fun invalid(block: () -> Unit) {
        var thrown = false
        try { block() } catch (_: IllegalArgumentException) { thrown = true }
        check(thrown) { "expected refusal" }
    }
    fun ready() = ForegroundGestureGate().also { it.setResumed(true); it.setFocused(true) }
    fun card(
        id: String,
        kind: ShelfKind = ShelfKind.TEXT,
        state: ShelfAvailability = ShelfAvailability.READY,
        actions: List<ActivationAction> = if (state == ShelfAvailability.READY) listOf(ActivationAction.COPY_TEXT) else emptyList(),
        preview: String = "preview",
        size: Long = 10L,
    ) = ShelfCard(ShelfKey("origin", id), "CEDAR", ShelfOwnership.RECEIVED, kind, "name", preview, size, 1L, state, actions, null)
    fun shelf(cards: List<ShelfCard>) = ShelfSnapshot(true, ShelfCompleteness.COMPLETE, "EMBER", cards, PeerStatus.None)
    test("gate_requires_resumed") { val g=ForegroundGestureGate(); g.setFocused(true); check(g.issue()==null) }
    test("gate_requires_focus") { val g=ForegroundGestureGate(); g.setResumed(true); check(g.issue()==null) }
    test("one_use_only") { val g=ready(); val t=g.issue()!!; check(g.consume(t)); check(!g.consume(t)) }
    test("focus_loss_invalidates") { val g=ready(); val t=g.issue()!!; g.setFocused(false); g.setFocused(true); check(!g.consume(t)) }
    test("pause_invalidates") { val g=ready(); val t=g.issue()!!; g.setResumed(false); g.setResumed(true); check(!g.consume(t)) }
    test("later_action_supersedes") { val g=ready(); val a=g.issue()!!; val b=g.issue()!!; check(!g.consume(a)); check(g.consume(b)) }
    test("explicit_invalidate") { val g=ready(); val t=g.issue()!!; g.invalidate(); check(!g.consume(t)) }
    test("repeat_focus_event_does_not_rearm") { val g=ready(); val t=g.issue()!!; g.setFocused(true); check(g.consume(t)); g.setFocused(true); check(!g.consume(t)) }
    test("activity_session_tokens_cannot_alias") { val a=ready(); val b=ready(); val old=a.issue()!!; val fresh=b.issue()!!; check(!b.consume(old)); check(b.consume(fresh)) }
    test("token_round_trips_through_native") { val g=ready(); val t=g.issue()!!; check(g.consume(ForegroundGestureGate.parseToken(ForegroundGestureGate.formatToken(t))!!)) }
    test("empty_shelf_valid") { check(shelf(emptyList()).cards.isEmpty()) }
    test("ten_entries_valid") { check(shelf((1..10).map { card("$it") }).cards.size==10) }
    test("eleven_entries_refused") { invalid { shelf((1..11).map { card("$it") }) } }
    test("duplicate_key_refused") { invalid { shelf(listOf(card("x"), card("x"))) } }
    test("empty_key_refused") { invalid { ShelfKey("", "x") } }
    test("negative_size_refused") { invalid { card("x", size = -1) } }
    test("utf8_preview_bound") { invalid { card("x", preview = "😀".repeat(65)) } }
    test("text_copy_is_primary") { check(card("x").primaryAction()==ActivationAction.COPY_TEXT) }
    test("photo_share_primary_save_alternate") { val c=card("x",ShelfKind.PHOTO,actions=listOf(ActivationAction.SHARE_FILE,ActivationAction.SAVE_FILE)); check(c.primaryAction()==ActivationAction.SHARE_FILE && c.supportsSave()) }
    test("changed_source_has_no_action") { invalid { card("x",state=ShelfAvailability.SOURCE_CHANGED,actions=listOf(ActivationAction.COPY_TEXT)) }; check(card("x",state=ShelfAvailability.SOURCE_CHANGED).primaryAction()==null) }
    test("ordinary_fanout_retention") { check(PhotoOperation.PutOnShelf.isMeshWide()); check(PhotoOperation.PutOnShelf.retention()==PhotoRetention.UNTIL_SHELF_PURGE); check(PhotoLeasePolicy.ordinaryExpiryMillis()==null) }
    test("capture_is_scoped") { val p=PhotoOperation.FulfilRequest("r","d"); check(!p.isMeshWide()); check(p.retention()==PhotoRetention.UNTIL_CAPTURE_RECEIPT_OR_DEADLINE); check(!PhotoLeasePolicy.needsGalleryWrite(p)) }
    test("handoff_owns_cleanup") { check(!PhotoLeasePolicy.mayDeleteCaptureFromUi(true)); check(PhotoLeasePolicy.mayDeleteCaptureFromUi(false)) }
    return passed
}
