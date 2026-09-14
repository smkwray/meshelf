package com.meshelf.android.shelf

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper

/** A dispatch ID exists only after native's durable side-effect-intent transaction. */
data class PreparedClipboardAction(
    val dispatchId: String,
    val gesture: ForegroundGestureGate.Token,
    val text: String,
)

enum class PlatformOutcome { APPLIED, FOREGROUND_LOST, PLATFORM_FAILED }

/** No reads, retries, URI coercion, or silent app-resume replay. Main-thread-only final write. */
class ForegroundClipboardPort(context: Context, private val gate: ForegroundGestureGate) {
    private val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val main = Handler(Looper.getMainLooper())

    fun copyPreparedText(action: PreparedClipboardAction, completion: (PlatformOutcome) -> Unit) {
        main.post {
            if (action.dispatchId.isBlank() || action.text.toByteArray(Charsets.UTF_8).size > 1024 * 1024) {
                completion(PlatformOutcome.PLATFORM_FAILED)
            } else if (!gate.consume(action.gesture)) {
                completion(PlatformOutcome.FOREGROUND_LOST)
            } else {
                val outcome = try {
                    clipboard.setPrimaryClip(ClipData.newPlainText("meshelf", action.text))
                    PlatformOutcome.APPLIED
                } catch (_: RuntimeException) {
                    // Do not retry after a platform call: side effects might have happened.
                    PlatformOutcome.PLATFORM_FAILED
                }
                // Backend persists outcome on its worker. Loss of this callback is uncertain,
                // not "applied", not "not applied", and never permission to replay.
                completion(outcome)
            }
        }
    }
}
