package com.meshelf.android

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.TypedValue
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import com.meshelf.android.shelf.Feedback
import com.meshelf.android.shelf.FeedbackIcon
import com.meshelf.android.shelf.Msg
import com.meshelf.android.shelf.ShelfResult
import com.meshelf.android.shelf.ShelfViews
import com.meshelf.android.shelf.ShelfWording
import com.meshelf.android.shelf.UiText

/**
 * Put on shelf: typed text, Paste and add, camera, gallery. `Paste and add` is the only clipboard
 * read in the app, and it happens directly in its click handler. There is no recipient picker.
 */
class PutOnShelfActivity : ShelfForegroundActivity() {
    private lateinit var draft: EditText
    private lateinit var strip: TextView
    private lateinit var sendButtons: List<Button>
    private var announcing = false
    private var selectionPending = false

    private val pickPhoto = registerForActivityResult(
        object : ActivityResultContracts.OpenDocument() {
            override fun createIntent(context: Context, input: Array<String>): Intent =
                super.createIntent(context, input).addFlags(
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
                )
        },
    ) { uri ->
        selectionPending = false
        // The selection hold keeps the resident alive until the announce ends or the picker cancels.
        if (uri == null) {
            backend.endExternalSelectionHold()
            return@registerForActivityResult
        }
        announce(photo = true, clearDraft = false) {
            try {
                backend.announcePickedPhoto(uri)
            } finally {
                backend.endExternalSelectionHold()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_put_on_shelf)
        applySystemBarInsets(findViewById(R.id.put_root))
        findViewById<TextView>(R.id.screen_title).setText(R.string.put_title)
        findViewById<View>(R.id.screen_back).setOnClickListener { finish() }
        draft = findViewById(R.id.put_text)
        strip = findViewById(R.id.result_strip)
        val addText = findViewById<Button>(R.id.put_add_text)
        val paste = findViewById<Button>(R.id.put_paste_add)
        val takePhoto = findViewById<Button>(R.id.put_take_photo)
        val choosePhoto = findViewById<Button>(R.id.put_choose_photo)
        sendButtons = listOf(addText, paste, takePhoto, choosePhoto)
        stackIfCramped(findViewById(R.id.put_text_row), findViewById(R.id.put_photo_row))

        addText.setOnClickListener { addText(draft.text.toString(), clearDraft = true) }
        paste.setOnClickListener {
            // The only clipboard READ in the app: directly within this explicit button handler.
            // Never on resume, focus, a timer, an Intent, or as a retry.
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = clipboard.primaryClip
            val text = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null
            if (text.isNullOrEmpty()) showStrip(Feedback(UiText.of(Msg.CLIPBOARD_NO_TEXT), FeedbackIcon.WARNING, false))
            else addText(text, clearDraft = false)
        }
        takePhoto.setOnClickListener {
            val opened = backend.openShelfCamera(this)
            if (opened is ShelfResult.Error) showStrip(ShelfWording.error(opened))
        }
        choosePhoto.setOnClickListener { choosePhoto() }
    }

    private fun addText(text: String, clearDraft: Boolean) {
        if (text.isEmpty()) {
            showStrip(Feedback(UiText.of(Msg.ENTER_TEXT), FeedbackIcon.WARNING, false))
            return
        }
        if (text.toByteArray(Charsets.UTF_8).size > MAX_TEXT_BYTES) {
            showStrip(Feedback(UiText.of(Msg.TEXT_TOO_LARGE), FeedbackIcon.ERROR, false))
            return
        }
        announce(photo = false, clearDraft = clearDraft) { backend.announceText(text) }
    }

    private fun choosePhoto() {
        if (announcing || selectionPending) return
        selectionPending = true
        io.execute {
            val held = runCatching { backend.beginExternalSelectionHold() }
            runOnUiThread {
                if (isDestroyed) {
                    if (held.isSuccess) backend.endExternalSelectionHold()
                    return@runOnUiThread
                }
                held.onFailure { error ->
                    selectionPending = false
                    showStrip(Feedback(UiText.of(Msg.INTERNAL), FeedbackIcon.ERROR, false, detail = error.message))
                }.onSuccess {
                    runCatching { pickPhoto.launch(arrayOf("image/*")) }.onFailure { error ->
                        selectionPending = false
                        backend.endExternalSelectionHold()
                        showStrip(Feedback(UiText.of(Msg.INTERNAL), FeedbackIcon.ERROR, false, detail = error.message))
                    }
                }
            }
        }
    }

    private fun announce(photo: Boolean, clearDraft: Boolean, work: () -> ShelfResult<com.meshelf.android.shelf.AnnounceResult>) {
        if (announcing) return
        announcing = true
        sendButtons.forEach { it.isEnabled = false }
        showStrip(Feedback(UiText.of(Msg.ADDING), FeedbackIcon.PROGRESS, false))
        background(work) { result ->
            announcing = false
            sendButtons.forEach { it.isEnabled = true }
            showStrip(ShelfWording.announce(result, photo))
            if (clearDraft && result is ShelfResult.Ok && result.value.localStored) draft.text.clear()
        }
    }

    private fun showStrip(feedback: Feedback) {
        ShelfViews.bindStrip(strip, feedback) { startActivity(Intent(this, SettingsActivity::class.java)) }
    }

    /** Paired buttons stack at large font scale or on a narrow window. */
    private fun stackIfCramped(vararg rows: LinearLayout) {
        val config = resources.configuration
        if (config.fontScale < 1.3f && config.screenWidthDp >= 360) return
        val gap = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 8f, resources.displayMetrics).toInt()
        rows.forEach { row ->
            row.orientation = LinearLayout.VERTICAL
            for (i in 0 until row.childCount) {
                val child = row.getChildAt(i)
                child.layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                    .apply { if (i > 0) topMargin = gap }
            }
        }
    }

    private companion object {
        const val MAX_TEXT_BYTES = 1024 * 1024
    }
}
