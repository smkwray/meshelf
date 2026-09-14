package com.meshelf.android

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import com.meshelf.android.shelf.ActivationAction
import com.meshelf.android.shelf.Feedback
import com.meshelf.android.shelf.FeedbackIcon
import com.meshelf.android.shelf.ForegroundFileExportPort
import com.meshelf.android.shelf.Msg
import com.meshelf.android.shelf.PeerStatus
import com.meshelf.android.shelf.SaveSettings
import com.meshelf.android.shelf.SaveTarget
import com.meshelf.android.shelf.ShelfAvailability
import com.meshelf.android.shelf.ShelfCard
import com.meshelf.android.shelf.ShelfKey
import com.meshelf.android.shelf.ShelfPlatformActions
import com.meshelf.android.shelf.ShelfResult
import com.meshelf.android.shelf.ShelfSnapshot
import com.meshelf.android.shelf.ShelfViews
import com.meshelf.android.shelf.ShelfWording
import com.meshelf.android.shelf.UiText
import java.util.concurrent.Executors

/**
 * Shelf surface. Compact cards render only native-supported actions; one activation runs at a
 * time and keeps its own in-flight state, while navigation and Refresh stay usable. The last good
 * shelf stays visible under a notice when native data is refused.
 */
class MainActivity : ShelfForegroundActivity(), ShelfViews.CardCallbacks {
    private lateinit var port: ForegroundFileExportPort
    override val platformActions: ShelfPlatformActions? get() = if (::port.isInitialized) port else null

    /** Activation blocks until terminal; it must not queue Refresh or snapshot reads behind it. */
    private val activationIo = Executors.newSingleThreadExecutor()

    private lateinit var refreshProgress: ProgressBar
    private lateinit var peerRow: View
    private lateinit var peerChips: LinearLayout
    private lateinit var peerMore: TextView
    private lateinit var notice: TextView
    private lateinit var strip: TextView
    private lateinit var cards: LinearLayout
    private lateinit var empty: View

    private var lastGood: ShelfSnapshot? = null
    private var snapshotNotice: Feedback? = null
    private var stripFeedback: Feedback? = null
    private val live = HashMap<ShelfKey, Feedback>()
    private val cardViews = LinkedHashMap<ShelfKey, View>()
    private var activeKey: ShelfKey? = null
    private var refreshInFlight = false
    private var localReadInFlight = false
    private var localReadAgain = false
    private var catalogRoundDue = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        applySystemBarInsets(findViewById(R.id.shelf_root))
        port = ForegroundFileExportPort(this, gate)
        refreshProgress = findViewById(R.id.refresh_progress)
        peerRow = findViewById(R.id.peer_row)
        peerChips = findViewById(R.id.peer_chips)
        peerMore = findViewById(R.id.peer_more)
        notice = findViewById(R.id.shelf_notice)
        strip = findViewById(R.id.result_strip)
        cards = findViewById(R.id.shelf_cards)
        empty = findViewById(R.id.empty_state)
        findViewById<ImageButton>(R.id.app_bar_refresh).setOnClickListener { requestRefresh() }
        findViewById<ImageButton>(R.id.app_bar_put).setOnClickListener { openPutOnShelf() }
        findViewById<ImageButton>(R.id.app_bar_settings).setOnClickListener { onOpenSettings() }
        findViewById<View>(R.id.empty_put_button).setOnClickListener { openPutOnShelf() }
        if (savedInstanceState == null) forwardAutoEnable(intent)
        render()
    }

    override fun onStart() {
        super.onStart()
        // O-026: one metadata round when the shelf opens from outside the app, never on in-app
        // navigation, focus, resume or a metadata invalidation.
        if (openedSession) catalogRoundDue = true
        onShelfStateChanged()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        forwardAutoEnable(intent)
    }

    override fun onDestroy() {
        activationIo.shutdown()
        super.onDestroy()
    }

    override fun onShelfStateChanged() {
        if (!backend.connected) {
            snapshotNotice = Feedback(UiText.of(Msg.GETTING_READY), FeedbackIcon.PROGRESS, false)
            render()
            return
        }
        if (catalogRoundDue) requestRefresh() else readLocal()
    }

    private fun requestRefresh() {
        if (refreshInFlight) return
        if (!backend.connected) {
            showStrip(Feedback(UiText.of(Msg.GETTING_READY), FeedbackIcon.PROGRESS, true))
            return
        }
        catalogRoundDue = false
        refreshInFlight = true
        render()
        background({ backend.refreshCatalog() }) { result ->
            refreshInFlight = false
            when (result) {
                is ShelfResult.Ok -> applySnapshot(ShelfResult.Ok(result.value.snapshot))
                is ShelfResult.Rejected -> applySnapshot(result)
                is ShelfResult.Error -> Unit
            }
            if (result !is ShelfResult.Rejected) showStrip(ShelfWording.refresh(result)) else render()
        }
    }

    private fun readLocal() {
        if (refreshInFlight) return // The refresh result carries a fresh snapshot.
        if (localReadInFlight) {
            localReadAgain = true
            return
        }
        localReadInFlight = true
        background({ backend.snapshot() }) { result ->
            localReadInFlight = false
            applySnapshot(result)
            render()
            if (localReadAgain) {
                localReadAgain = false
                readLocal()
            }
        }
    }

    private fun applySnapshot(result: ShelfResult<ShelfSnapshot>) {
        when (result) {
            is ShelfResult.Ok -> {
                val snapshot = result.value
                lastGood = snapshot
                val keys = snapshot.cards.map { it.key }.toSet()
                live.keys.retainAll { it in keys || it == activeKey }
                snapshotNotice = when {
                    !snapshot.ready -> Feedback(UiText.of(Msg.GETTING_READY), FeedbackIcon.PROGRESS, false)
                    snapshot.peerStatus is PeerStatus.Unreadable -> Feedback(UiText.of(Msg.PEER_UNREADABLE), FeedbackIcon.WARNING, false)
                    else -> null
                }
            }
            is ShelfResult.Rejected -> snapshotNotice = Feedback(
                ShelfWording.snapshotNotice(result.failure), FeedbackIcon.ERROR, false, detail = result.failure.detail,
            )
            is ShelfResult.Error -> snapshotNotice = ShelfWording.error(result)
        }
    }

    private fun render() {
        refreshProgress.visibility = if (refreshInFlight) View.VISIBLE else View.GONE
        ShelfViews.bindPeers(peerRow, peerChips, peerMore, lastGood?.peerStatus, pending = refreshInFlight)
        ShelfViews.bindStrip(notice, snapshotNotice) { onOpenSettings() }
        ShelfViews.bindStrip(strip, stripFeedback) { onOpenSettings() }
        val snapshot = lastGood
        empty.visibility = if (snapshot != null && snapshot.cards.isEmpty()) View.VISIBLE else View.GONE
        val shown = snapshot?.cards.orEmpty()
        if (shown.map { it.key } != cardViews.keys.toList()) {
            cards.removeAllViews()
            cardViews.clear()
            val inflater = LayoutInflater.from(this)
            shown.forEach { card ->
                val view = inflater.inflate(R.layout.view_shelf_card, cards, false)
                cards.addView(view)
                cardViews[card.key] = view
            }
        }
        shown.forEach { card -> cardViews[card.key]?.let { ShelfViews.bindCard(it, card, live[card.key], this) } }
    }

    override fun onPrimary(card: ShelfCard) {
        val action = card.primaryAction()
        if (action == null) explain(card) else activate(card, action)
    }

    override fun onAction(card: ShelfCard, action: ActivationAction) = activate(card, action)

    override fun onDetails(card: ShelfCard) = ShelfViews.showDetails(this, ShelfViews.cardDetails(this, card, live[card.key]))

    override fun onOpenSettings() {
        startActivity(Intent(this, SettingsActivity::class.java))
    }

    private fun openPutOnShelf() {
        startActivity(Intent(this, PutOnShelfActivity::class.java))
    }

    private fun activate(card: ShelfCard, action: ActivationAction) {
        if (action !in card.supportedActions) return
        if (activeKey != null) {
            showStrip(Feedback(UiText.of(Msg.WAIT_CURRENT_ACTION), FeedbackIcon.BUSY, true))
            return
        }
        if (!backend.connected) {
            showStrip(Feedback(UiText.of(Msg.GETTING_READY), FeedbackIcon.PROGRESS, true))
            return
        }
        if (action == ActivationAction.SAVE_FILE) {
            // O-011: an unusable destination fails before any pull; never a silent fallback.
            val target = SaveSettings(this).resolve()
            if (target is SaveTarget.Unavailable) {
                setLive(card.key, ShelfWording.saveDestinationUnavailable(target.reason))
                return
            }
        }
        val gesture = gate.issue() ?: run {
            setLive(card.key, ShelfWording.tapAgain())
            return
        }
        activeKey = card.key
        setLive(card.key, ShelfWording.inFlight(action))
        activationIo.execute {
            val result = backend.activate(card.key, action, gesture)
            runOnUiThread {
                activeKey = null
                if (isDestroyed) return@runOnUiThread
                val report = if (action == ActivationAction.SAVE_FILE) port.takeSaveReport(gesture) else null
                setLive(card.key, ShelfWording.activation(result, action, card.kind, report))
                readLocal()
            }
        }
    }

    private fun explain(card: ShelfCard) {
        val state = ShelfWording.availability(card)?.let { text(it.text) }
        val reason = getString(
            when (card.availability) {
                ShelfAvailability.SOURCE_OFFLINE -> R.string.explain_source_unavailable
                ShelfAvailability.SOURCE_CHANGED -> R.string.explain_source_changed
                ShelfAvailability.UNSUPPORTED, ShelfAvailability.READY -> R.string.explain_unsupported
            },
        )
        AlertDialog.Builder(this)
            .setTitle(state)
            .setMessage(reason)
            .setPositiveButton(android.R.string.ok, null)
            .setNeutralButton(R.string.action_details) { _, _ -> onDetails(card) }
            .show()
    }

    private fun setLive(key: ShelfKey, feedback: Feedback) {
        live[key] = feedback
        render()
        if (feedback.transient) {
            // UI-only fade back to the card's stable state; triggers no network or clipboard work.
            cards.postDelayed({ if (!isDestroyed && live[key] === feedback) { live.remove(key); render() } }, FADE_MS)
        }
    }

    private fun showStrip(feedback: Feedback) {
        stripFeedback = feedback
        render()
        if (feedback.transient) {
            strip.postDelayed({ if (!isDestroyed && stripFeedback === feedback) { stripFeedback = null; render() } }, FADE_MS)
        }
    }

    private fun forwardAutoEnable(intent: Intent) {
        if (!intent.getBooleanExtra(EXTRA_AUTO_ENABLE, false)) return
        startActivity(Intent(this, SettingsActivity::class.java).putExtras(intent))
        intent.removeExtra(EXTRA_AUTO_ENABLE)
    }

    companion object {
        const val EXTRA_AUTO_ENABLE = "auto_enable"
        const val EXTRA_DEVICE_NAME = "device_name"
        private const val FADE_MS = 4_000L
    }
}
