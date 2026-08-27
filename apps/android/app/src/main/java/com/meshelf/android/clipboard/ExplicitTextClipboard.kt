package com.meshelf.android.clipboard

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle

private const val MAX_TEXT_BYTES: Int = 1024 * 1024
private const val LEGACY_SENSITIVE_EXTRA: String = "android.content.extra.IS_SENSITIVE"

sealed interface TextClipboardWriteResult {
    data object Verified : TextClipboardWriteResult
    data class DefiniteFailure(val reason: String) : TextClipboardWriteResult
    data class UncertainNoReplay(val reason: String) : TextClipboardWriteResult
}

/**
 * Explicit foreground text clipboard operations only.
 *
 * This class never registers a clipboard listener and never converts a URI or
 * Intent clip into text or a filesystem path. The real Rust activation callback
 * must add an atomic QUEUED/RUNNING/COMPLETED state machine before using this
 * across threads; this seed is a synchronous main-thread demonstrator.
 */
class ExplicitTextClipboard(context: Context) {
    private val clipboard = context.getSystemService(ClipboardManager::class.java)

    fun readPlainTextOnce(): Result<String> = runCatching {
        val clip = clipboard.primaryClip ?: error("clipboard has no readable primary clip")
        require(clip.itemCount == 1) { "Android text v1 accepts exactly one clipboard item" }
        val text = clip.getItemAt(0).text?.toString()
            ?: error("clipboard item is not direct text; URI and Intent clips are unsupported")
        val bytes = text.toByteArray(Charsets.UTF_8)
        require(bytes.isNotEmpty()) { "text must not be empty" }
        require(bytes.size <= MAX_TEXT_BYTES) { "text exceeds the 1 MiB Meshelf bound" }
        text
    }

    fun writePlainTextAndVerify(text: String): TextClipboardWriteResult {
        val size = text.toByteArray(Charsets.UTF_8).size
        if (size == 0) {
            return TextClipboardWriteResult.DefiniteFailure("text must not be empty")
        }
        if (size > MAX_TEXT_BYTES) {
            return TextClipboardWriteResult.DefiniteFailure("text exceeds the 1 MiB Meshelf bound")
        }

        val clip = ClipData.newPlainText("meshelf text", text).apply {
            description.extras = PersistableBundle().apply {
                val key = if (Build.VERSION.SDK_INT >= 33) {
                    ClipDescription.EXTRA_IS_SENSITIVE
                } else {
                    LEGACY_SENSITIVE_EXTRA
                }
                putBoolean(key, true)
            }
        }

        return try {
            // From this point onward an exception is conservatively uncertain:
            // Android may already have changed the global clipboard.
            clipboard.setPrimaryClip(clip)
            val observed = clipboard.primaryClip
                ?.takeIf { it.itemCount == 1 }
                ?.getItemAt(0)
                ?.text
                ?.toString()
            if (observed == text) {
                TextClipboardWriteResult.Verified
            } else {
                TextClipboardWriteResult.UncertainNoReplay("exact readback failed or differed")
            }
        } catch (error: Throwable) {
            TextClipboardWriteResult.UncertainNoReplay(
                error.message ?: error::class.java.simpleName,
            )
        }
    }
}
