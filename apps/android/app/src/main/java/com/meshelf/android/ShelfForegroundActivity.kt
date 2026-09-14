package com.meshelf.android

import android.content.Intent
import android.view.View
import androidx.activity.ComponentActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.meshelf.android.shelf.ForegroundGestureGate
import com.meshelf.android.shelf.ShelfBackend
import com.meshelf.android.shelf.ShelfBackendProvider
import com.meshelf.android.shelf.ShelfPlatformActions
import com.meshelf.android.shelf.UiText
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Shared foreground ownership for in-app shelf Activities. Each registers as a reference-counted
 * owner of the single resident (onStart/onStop), and any later gesture, pause or focus loss
 * invalidates a pending platform dispatch. Nothing here reads the clipboard or schedules work.
 */
abstract class ShelfForegroundActivity : ComponentActivity() {
    protected val backend: ShelfBackend by lazy { ShelfBackendProvider.obtain(applicationContext) }
    protected val gate = ForegroundGestureGate()
    protected val io: ExecutorService = Executors.newSingleThreadExecutor()

    /** Platform actions for dispatches this Activity's gestures authorise; null means none. */
    protected open val platformActions: ShelfPlatformActions? get() = null

    /** True when this onStart opened the app's foreground session (not an in-app transition). */
    protected var openedSession = false
        private set

    override fun onStart() {
        super.onStart()
        openedSession = backend.openForeground(this, platformActions) {
            runOnUiThread { if (!isDestroyed) onShelfStateChanged() }
        }
    }

    override fun onResume() {
        super.onResume()
        gate.setResumed(true)
        backend.resumeForeground(this)
    }

    override fun onPause() {
        gate.setResumed(false)
        backend.pauseForeground(this)
        backend.invalidatePlatformActions()
        super.onPause()
    }

    override fun onStop() {
        // A configuration change stops this instance before its replacement starts; releasing here
        // would stop the resident in that gap and make the replacement look like a fresh open.
        if (isChangingConfigurations) backend.deferForegroundClose(this) else backend.closeForeground(this)
        super.onStop()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        gate.setFocused(hasFocus)
        if (!hasFocus) backend.invalidatePlatformActions()
    }

    override fun onUserInteraction() {
        // A later gesture supersedes any pending platform action without observing copies.
        gate.invalidate()
        backend.invalidatePlatformActions()
        super.onUserInteraction()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        gate.invalidate()
    }

    override fun onDestroy() {
        gate.invalidate()
        io.shutdown() // Never interrupt an already durable native operation.
        super.onDestroy()
    }

    /** Resident connected or shelf metadata invalidated while this Activity owns the foreground. */
    protected open fun onShelfStateChanged() {}

    protected fun text(value: UiText): String = value.render { msg, args -> getString(msg.res, *args) }

    /** Runs [work] on [io] and delivers its value on the main thread if still alive. */
    protected fun <T> background(work: () -> T, done: (T) -> Unit) {
        io.execute {
            val value = work()
            runOnUiThread { if (!isDestroyed) done(value) }
        }
    }

    protected fun applySystemBarInsets(root: View) {
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime(),
            )
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
    }
}
