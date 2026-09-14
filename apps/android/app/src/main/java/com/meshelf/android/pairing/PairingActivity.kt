package com.meshelf.android.pairing

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.format.DateFormat
import android.widget.Button
import android.widget.TextView
import com.meshelf.android.R
import com.meshelf.android.service.CaptureForegroundService
import java.lang.ref.WeakReference
import java.util.Date
import java.util.UUID

/**
 * The only place pairing happens. The window is open exactly while this screen is visible: it opens
 * in onStart and closes in onStop. Nothing launches this activity except the person's own tap.
 * The service owns the native listener; this screen sends it intents and receives events through
 * [deliver], the same shape CaptureActivity uses for capture requests.
 */
class PairingActivity : Activity() {
    private lateinit var peerView: TextView
    private lateinit var codeView: TextView
    private lateinit var statusView: TextView
    private lateinit var confirm: Button
    private lateinit var secondary: Button
    private var state: PairingState = PairingState.Opening
    private var windowToken: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing)
        peerView = findViewById(R.id.pairing_peer)
        codeView = findViewById(R.id.pairing_code)
        statusView = findViewById(R.id.pairing_status)
        confirm = findViewById(R.id.pairing_confirm)
        secondary = findViewById(R.id.pairing_decline)

        confirm.setOnClickListener { dispatch(PairingEvent.ConfirmTapped(System.currentTimeMillis())) }
        secondary.setOnClickListener {
            if (state is PairingState.Showing) dispatch(PairingEvent.RejectTapped) else finish()
        }
    }

    override fun onStart() {
        super.onStart()
        visible = WeakReference(this)
        state = PairingState.Opening
        render()
        if (!CaptureForegroundService.isRunning()) {
            dispatch(PairingEvent.Unavailable(AVAILABILITY_OFF))
            return
        }
        val token = UUID.randomUUID().toString()
        windowToken = token
        sendToService(CaptureForegroundService.ACTION_OPEN_PAIRING) {
            putExtra(CaptureForegroundService.EXTRA_PAIRING_WINDOW_TOKEN, token)
        }
    }

    override fun onStop() {
        if (visible?.get() === this) visible = null
        val token = windowToken
        windowToken = null
        if (token != null && CaptureForegroundService.isRunning()) {
            sendToService(CaptureForegroundService.ACTION_CLOSE_PAIRING) {
                putExtra(CaptureForegroundService.EXTRA_PAIRING_WINDOW_TOKEN, token)
            }
        }
        super.onStop()
    }

    private fun dispatch(event: PairingEvent) {
        val transition = PairingReducer.reduce(state, event)
        state = transition.state
        render()
        when (val action = transition.action) {
            is PairingAction.Confirm -> sendToService(CaptureForegroundService.ACTION_CONFIRM_PAIRING) {
                putExtra(CaptureForegroundService.EXTRA_PAIRING_ID, action.pairingId)
                putExtra(CaptureForegroundService.EXTRA_TRANSCRIPT_HASH, action.transcriptHash)
            }
            is PairingAction.Reject -> sendToService(CaptureForegroundService.ACTION_REJECT_PAIRING) {
                putExtra(CaptureForegroundService.EXTRA_PAIRING_ID, action.pairingId)
            }
            PairingAction.CloseWindow -> {
                val token = windowToken ?: return
                windowToken = null
                sendToService(CaptureForegroundService.ACTION_CLOSE_PAIRING) {
                    putExtra(CaptureForegroundService.EXTRA_PAIRING_WINDOW_TOKEN, token)
                }
            }
            null -> Unit
        }
    }

    private fun render() {
        val screen = PairingScreen.render(state) { DateFormat.getTimeFormat(this).format(Date(it)) }
        peerView.text = screen.peer
        codeView.text = screen.code
        statusView.text = screen.status
        confirm.isEnabled = screen.confirmEnabled
        secondary.text = screen.secondaryLabel
    }

    private fun sendToService(action: String, extras: Intent.() -> Unit) {
        val intent = Intent(this, CaptureForegroundService::class.java).setAction(action).apply(extras)
        runCatching { startService(intent) }.onFailure { error ->
            if (action != CaptureForegroundService.ACTION_CLOSE_PAIRING) {
                dispatch(PairingEvent.NativeCallFailed("The capture service is unreachable: ${error.message}"))
            }
        }
    }

    companion object {
        const val AVAILABILITY_OFF =
            "Turn on \"Available for capture requests\" first. Pairing uses the same listener."

        @Volatile private var visible: WeakReference<PairingActivity>? = null

        /** Called by the service on the main thread. Returns false when no pairing screen is visible. */
        fun deliver(event: PairingEvent): Boolean {
            val activity = visible?.get() ?: return false
            activity.dispatch(event)
            return true
        }
    }
}
