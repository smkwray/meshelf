package com.meshelf.android

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.meshelf.android.clipboard.ExplicitTextClipboard
import com.meshelf.android.clipboard.TextClipboardWriteResult
import com.meshelf.android.nativebridge.MeshelfNative

class MainActivity : Activity() {
    private lateinit var editor: EditText
    private lateinit var status: TextView
    private lateinit var clipboard: ExplicitTextClipboard

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        editor = findViewById(R.id.editor)
        status = findViewById(R.id.status)
        clipboard = ExplicitTextClipboard(this)

        findViewById<Button>(R.id.check_native).setOnClickListener {
            status.text = MeshelfNative.abiVersion()
                .fold(
                    onSuccess = { version -> "Native ABI: $version" },
                    onFailure = { error -> "Native library unavailable: ${error.message}" },
                )
        }

        findViewById<Button>(R.id.read_clipboard).setOnClickListener {
            clipboard.readPlainTextOnce()
                .onSuccess { text ->
                    editor.setText(text)
                    status.text = "Clipboard text read once (${text.toByteArray().size} UTF-8 bytes)."
                }
                .onFailure { error -> status.text = "Clipboard read refused: ${error.message}" }
        }

        findViewById<Button>(R.id.write_clipboard).setOnClickListener {
            status.text = when (val result = clipboard.writePlainTextAndVerify(editor.text.toString())) {
                TextClipboardWriteResult.Verified -> "Clipboard write verified."
                is TextClipboardWriteResult.DefiniteFailure ->
                    "Clipboard unchanged by a definite pre-write failure: ${result.reason}"
                is TextClipboardWriteResult.UncertainNoReplay ->
                    "Clipboard result uncertain; do not replay: ${result.reason}"
            }
        }
    }
}
