package com.meshelf.android.shelf

import android.app.AlertDialog
import android.content.Context
import android.content.res.ColorStateList
import android.text.format.Formatter
import android.util.TypedValue
import android.view.View
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat
import com.meshelf.android.R

/** Binds typed shelf state to plain Views. Renders only what native `supportedActions` allow. */
object ShelfViews {
    const val MAX_VISIBLE_PEERS = 3
    private const val MENU_DETAILS = 100

    interface CardCallbacks {
        fun onPrimary(card: ShelfCard)
        fun onAction(card: ShelfCard, action: ActivationAction)
        fun onDetails(card: ShelfCard)
        fun onOpenSettings()
    }

    fun text(context: Context, value: UiText): String = value.render { msg, args -> context.getString(msg.res, *args) }

    fun kindLabel(kind: ShelfKind): Int = when (kind) {
        ShelfKind.TEXT -> R.string.kind_text
        ShelfKind.FILE -> R.string.kind_file
        ShelfKind.PHOTO -> R.string.kind_photo
        ShelfKind.FOLDER -> R.string.kind_folder
    }

    private fun kindIcon(kind: ShelfKind): Int = when (kind) {
        ShelfKind.TEXT -> R.drawable.ic_kind_text
        ShelfKind.FILE -> R.drawable.ic_kind_file
        ShelfKind.PHOTO -> R.drawable.ic_kind_photo
        ShelfKind.FOLDER -> R.drawable.ic_kind_folder
    }

    fun actionLabel(action: ActivationAction): Int = when (action) {
        ActivationAction.COPY_TEXT -> R.string.action_copy
        ActivationAction.SHARE_FILE -> R.string.action_share
        ActivationAction.SAVE_FILE -> R.string.action_save
    }

    private fun stateIcon(icon: FeedbackIcon): Int? = when (icon) {
        FeedbackIcon.PROGRESS -> null
        FeedbackIcon.SUCCESS -> R.drawable.ic_state_success
        FeedbackIcon.STOPPED -> R.drawable.ic_state_stopped
        FeedbackIcon.BUSY -> R.drawable.ic_state_busy
        FeedbackIcon.SOURCE_UNAVAILABLE -> R.drawable.ic_state_source_unavailable
        FeedbackIcon.WARNING -> R.drawable.ic_state_warning
        FeedbackIcon.UNSUPPORTED -> R.drawable.ic_state_unsupported
        FeedbackIcon.UNCERTAIN -> R.drawable.ic_state_uncertain
        FeedbackIcon.ERROR -> R.drawable.ic_state_error
    }

    fun toneColor(context: Context, icon: FeedbackIcon): Int = context.getColor(
        when (icon) {
            FeedbackIcon.PROGRESS -> R.color.meshelf_state_info
            FeedbackIcon.SUCCESS -> R.color.meshelf_state_success
            FeedbackIcon.STOPPED, FeedbackIcon.BUSY, FeedbackIcon.WARNING, FeedbackIcon.UNCERTAIN -> R.color.meshelf_state_warning
            FeedbackIcon.SOURCE_UNAVAILABLE, FeedbackIcon.UNSUPPORTED -> R.color.meshelf_peer_unavailable
            FeedbackIcon.ERROR -> R.color.meshelf_state_error
        },
    )

    fun bindCard(view: View, card: ShelfCard, live: Feedback?, callbacks: CardCallbacks) {
        val ctx = view.context
        val kind = ctx.getString(kindLabel(card.kind))
        val own = card.ownership == ShelfOwnership.OWN
        val source = if (own) ctx.getString(R.string.source_this_phone) else card.sourceDisplayName
        val body = when (card.kind) {
            ShelfKind.TEXT -> card.preview.replace(Regex("\\s*\\n\\s*"), " ").trim()
            else -> safeExportName(card.displayName, fallback = "")
        }.ifBlank { ctx.getString(R.string.card_untitled) }
        val size = Formatter.formatShortFileSize(ctx, card.byteLength)

        view.findViewById<ImageView>(R.id.card_kind_icon).apply {
            setImageResource(kindIcon(card.kind))
            alpha = if (card.availability == ShelfAvailability.READY) 1f else 0.5f
        }
        view.findViewById<TextView>(R.id.card_title).text = ctx.getString(R.string.card_title, kind, source)
        view.findViewById<TextView>(R.id.card_body).text = body // Inert text only: no links, HTML or paths.
        view.findViewById<TextView>(R.id.card_meta).text = size

        val state = live ?: ShelfWording.availability(card) ?: ShelfWording.lastAttempt(card.lastAttempt)
        val stateText = bindFeedback(view.findViewById(R.id.card_status_row), state)
        view.findViewById<TextView>(R.id.card_status_text).apply {
            if (state?.opensSettings == true) setOnClickListener { callbacks.onOpenSettings() } else setOnClickListener(null)
            isClickable = state?.opensSettings == true
        }

        val save = view.findViewById<ImageButton>(R.id.card_save)
        save.visibility = if (card.supportsSave()) View.VISIBLE else View.GONE
        save.contentDescription = ctx.getString(R.string.card_save_description, body)
        save.setOnClickListener { callbacks.onAction(card, ActivationAction.SAVE_FILE) }
        val more = view.findViewById<ImageButton>(R.id.card_more)
        more.contentDescription = ctx.getString(R.string.card_more_description, body)
        more.setOnClickListener { showMenu(more, card, callbacks) }

        view.setOnClickListener { callbacks.onPrimary(card) }
        view.setOnLongClickListener { showMenu(more, card, callbacks); true }
        val who = ctx.getString(if (own) R.string.card_a11y_own else R.string.card_a11y_from, kind, source)
        view.contentDescription = listOfNotNull(who, body, size, stateText).joinToString(". ")
        val primary = card.primaryAction()
        ViewCompat.replaceAccessibilityAction(
            view, AccessibilityActionCompat.ACTION_CLICK,
            ctx.getString(primary?.let(::actionLabel) ?: R.string.action_explain), null,
        )
        @Suppress("UNCHECKED_CAST")
        (view.getTag(R.id.card_more) as? List<Int>)?.forEach { ViewCompat.removeAccessibilityAction(view, it) }
        val ids = card.supportedActions.filter { it != primary }.map { action ->
            ViewCompat.addAccessibilityAction(view, ctx.getString(actionLabel(action))) { _, _ -> callbacks.onAction(card, action); true }
        } + ViewCompat.addAccessibilityAction(view, ctx.getString(R.string.action_details)) { _, _ -> callbacks.onDetails(card); true }
        view.setTag(R.id.card_more, ids)
    }

    /** Shows feedback in a status row (spinner or icon + words); returns the words, if any. */
    fun bindFeedback(row: LinearLayout, feedback: Feedback?): String? {
        val ctx = row.context
        val progress = row.findViewById<ProgressBar>(R.id.card_status_progress)
        val icon = row.findViewById<ImageView>(R.id.card_status_icon)
        val label = row.findViewById<TextView>(R.id.card_status_text)
        if (feedback == null) {
            row.visibility = View.GONE
            return null
        }
        row.visibility = View.VISIBLE
        val color = toneColor(ctx, feedback.icon)
        progress.visibility = if (feedback.icon == FeedbackIcon.PROGRESS) View.VISIBLE else View.GONE
        val res = stateIcon(feedback.icon)
        if (res == null) icon.visibility = View.GONE else {
            icon.visibility = View.VISIBLE
            icon.setImageResource(res)
            icon.imageTintList = ColorStateList.valueOf(color)
        }
        return text(ctx, feedback.text).also { label.text = it }
    }

    private fun showMenu(anchor: View, card: ShelfCard, callbacks: CardCallbacks) {
        val menu = PopupMenu(anchor.context, anchor)
        card.supportedActions.forEachIndexed { index, action ->
            menu.menu.add(0, action.ordinal, index, actionLabel(action))
        }
        menu.menu.add(0, MENU_DETAILS, 50, R.string.action_details)
        menu.setOnMenuItemClickListener { item ->
            if (item.itemId == MENU_DETAILS) callbacks.onDetails(card)
            else ActivationAction.entries.getOrNull(item.itemId)?.let { callbacks.onAction(card, it) }
            true
        }
        menu.show()
    }

    /** Compact O-019 peer row: dot + name only, `+N` overflow. Hidden when nothing was observed. */
    fun bindPeers(row: View, chips: LinearLayout, more: TextView, status: PeerStatus?, pending: Boolean) {
        val peers = (status as? PeerStatus.Observed)?.observation?.peers.orEmpty()
        row.visibility = if (peers.isEmpty()) View.GONE else View.VISIBLE
        chips.removeAllViews()
        peers.take(MAX_VISIBLE_PEERS).forEach { chips.addView(peerChip(chips.context, it, pending)) }
        val extra = peers.size - MAX_VISIBLE_PEERS
        more.visibility = if (extra > 0) View.VISIBLE else View.GONE
        if (extra > 0) {
            more.text = more.context.getString(R.string.peer_more, extra)
            more.contentDescription = more.context.getString(R.string.peer_more_description, extra)
            more.setOnClickListener { showPeers(more.context, peers, pending) }
        }
    }

    private fun peerChip(ctx: Context, entry: PeerEntry, pending: Boolean): View {
        val dp = { v: Int -> TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), ctx.resources.displayMetrics).toInt() }
        return LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), dp(14), dp(4))
            contentDescription = text(ctx, ShelfWording.peer(entry, pending))
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_YES
            addView(ImageView(ctx).apply {
                setImageResource(
                    when {
                        pending -> R.drawable.peer_dot_pending
                        entry.reachability == PeerReachability.REACHABLE -> R.drawable.peer_dot_reached
                        else -> R.drawable.peer_dot_unavailable
                    },
                )
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }, LinearLayout.LayoutParams(dp(10), dp(10)).apply { marginEnd = dp(6) })
            addView(TextView(ctx).apply {
                text = entry.displayName
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                maxWidth = dp(140)
                setTextAppearance(R.style.TextAppearance_Meshelf_Secondary)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            })
        }
    }

    private fun showPeers(ctx: Context, peers: List<PeerEntry>, pending: Boolean) {
        val list = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (20 * ctx.resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, 0)
            peers.forEach { addView(peerChip(ctx, it, pending)) }
        }
        AlertDialog.Builder(ctx)
            .setView(ScrollView(ctx).apply { addView(list) })
            .setPositiveButton(R.string.details_close, null)
            .show()
    }

    fun showDetails(ctx: Context, body: String) {
        val pad = (20 * ctx.resources.displayMetrics.density).toInt()
        val view = TextView(ctx).apply {
            text = body
            setTextIsSelectable(true)
            setPadding(pad, pad, pad, 0)
            setTextAppearance(R.style.TextAppearance_Meshelf_Secondary)
        }
        AlertDialog.Builder(ctx)
            .setTitle(R.string.action_details)
            .setView(ScrollView(ctx).apply { addView(view) })
            .setPositiveButton(R.string.details_close, null)
            .show()
    }

    /** A transient or sticky one-line result; tapping it opens Settings or Details when offered. */
    fun bindStrip(strip: TextView, feedback: Feedback?, onSettings: () -> Unit) {
        if (feedback == null) {
            strip.visibility = View.GONE
            return
        }
        strip.visibility = View.VISIBLE
        strip.text = text(strip.context, feedback.text)
        strip.setTextColor(
            if (feedback.icon == FeedbackIcon.ERROR) toneColor(strip.context, feedback.icon)
            else strip.context.getColor(R.color.meshelf_text_primary),
        )
        val detail = feedback.detail
        when {
            feedback.opensSettings -> strip.setOnClickListener { onSettings() }
            detail != null -> strip.setOnClickListener { showDetails(strip.context, detail) }
            else -> strip.setOnClickListener(null)
        }
        strip.isClickable = feedback.opensSettings || detail != null
    }

    fun cardDetails(ctx: Context, card: ShelfCard, live: Feedback?): String = ctx.getString(
        R.string.details_card,
        card.key.offerId,
        card.key.sourceDevice,
        card.ownership.name,
        card.kind.name,
        card.availability.name,
        card.supportedActions.joinToString { it.name }.ifEmpty { "-" },
        card.byteLength,
        card.shelfSequence,
        card.lastAttempt?.let { a ->
            listOfNotNull("${a.code} #${a.attemptSequence} files=${a.filesProcessed} bytes=${a.bytesProcessed}", a.detail).joinToString(": ")
        } ?: "-",
        live?.detail ?: "-",
    )
}
