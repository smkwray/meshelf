package com.meshelf.android.shelf

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import androidx.core.content.FileProvider
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/** A dispatch ID exists only after native's durable side-effect-intent transaction. */
data class PreparedFileExportAction(
    val dispatchId: String,
    val gesture: ForegroundGestureGate.Token,
    val absolutePath: String,
    val displayName: String,
    val mimeHint: String,
    val exportKind: String,
)

interface ShelfPlatformActions {
    /** Backend has already verified payload/hash and committed the no-replay dispatch journal. */
    fun copyPreparedText(action: PreparedClipboardAction, completion: (PlatformOutcome) -> Unit)

    fun exportPreparedFile(action: PreparedFileExportAction, completion: (PlatformOutcome) -> Unit)
}

/**
 * Save: stream verified bytes into a new document at the O-011 configured destination (Downloads
 * or a persisted folder grant). Share: stage per dispatch under the FileProvider cache path and
 * present ACTION_SEND; success means the chooser opened, never that a recipient stored it.
 * The gesture token is consumed on the main thread immediately before the side effect starts.
 */
class ForegroundFileExportPort(
    context: Context,
    private val gate: ForegroundGestureGate,
    private val saveTarget: () -> SaveTarget = { SaveSettings(context).resolve() },
) : ShelfPlatformActions {
    private val app = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val clipboard = ForegroundClipboardPort(app, gate)
    private val lastSave = AtomicReference<Pair<String, SaveReport>?>(null)

    override fun copyPreparedText(action: PreparedClipboardAction, completion: (PlatformOutcome) -> Unit) =
        clipboard.copyPreparedText(action, completion)

    /** What the Save step for [gesture] did; read once by the Activity that minted the token. */
    fun takeSaveReport(gesture: ForegroundGestureGate.Token): SaveReport? {
        val key = ForegroundGestureGate.formatToken(gesture)
        val current = lastSave.get() ?: return null
        return if (current.first == key && lastSave.compareAndSet(current, null)) current.second else null
    }

    override fun exportPreparedFile(action: PreparedFileExportAction, completion: (PlatformOutcome) -> Unit) {
        main.post {
            val source = File(action.absolutePath)
            if (action.dispatchId.isBlank() || action.absolutePath.isBlank() || !source.isFile) {
                completion(PlatformOutcome.PLATFORM_FAILED)
                return@post
            }
            when (action.exportKind) {
                "SAVE" -> save(action, source, completion)
                "SHARE" -> share(action, source, completion)
                else -> completion(PlatformOutcome.PLATFORM_FAILED)
            }
        }
    }

    private fun save(action: PreparedFileExportAction, source: File, completion: (PlatformOutcome) -> Unit) {
        if (!gate.consume(action.gesture)) {
            completion(PlatformOutcome.FOREGROUND_LOST)
            return
        }
        val target = saveTarget()
        val key = ForegroundGestureGate.formatToken(action.gesture)
        if (target is SaveTarget.Unavailable) {
            lastSave.set(key to SaveReport.Failed(destinationUnavailable = true))
            completion(PlatformOutcome.PLATFORM_FAILED)
            return
        }
        worker.execute {
            val report = try {
                SaveWriter.write(app, target, source, action.displayName, action.mimeHint)
            } catch (e: RuntimeException) {
                android.util.Log.w(TAG, "save failed: ${e.javaClass.simpleName}")
                SaveReport.Failed(destinationUnavailable = false)
            }
            lastSave.set(key to report)
            completion(if (report is SaveReport.Saved) PlatformOutcome.APPLIED else PlatformOutcome.PLATFORM_FAILED)
        }
    }

    private fun share(action: PreparedFileExportAction, source: File, completion: (PlatformOutcome) -> Unit) {
        if (!gate.isCurrent(action.gesture)) {
            completion(PlatformOutcome.FOREGROUND_LOST)
            return
        }
        worker.execute {
            val staged = try {
                stage(action, source)
            } catch (e: Exception) {
                android.util.Log.w(TAG, "share staging failed: ${e.javaClass.simpleName}")
                null
            }
            main.post {
                if (staged == null) {
                    completion(PlatformOutcome.PLATFORM_FAILED)
                } else if (!gate.consume(action.gesture)) {
                    staged.parentFile?.deleteRecursively()
                    completion(PlatformOutcome.FOREGROUND_LOST)
                } else {
                    completion(openChooser(staged, action.mimeHint))
                }
            }
        }
    }

    private fun stage(action: PreparedFileExportAction, source: File): File {
        val root = File(app.cacheDir, ShareStaging.ROOT_NAME)
        val dir = ShareStaging.prepare(root, action.dispatchId, System.currentTimeMillis())
        val staged = File(dir, safeExportName(action.displayName))
        staged.outputStream().use { out -> source.inputStream().use { ExportCopy.copyExact(it, out, source.length()) } }
        val uri = FileProvider.getUriForFile(app, "${app.packageName}.fileprovider", staged)
        // Prove the grant path is readable with the exact byte count before claiming share-ready.
        val readable = app.contentResolver.openInputStream(uri)?.use { input ->
            ExportCopy.copyExact(input, DiscardingOutput, source.length())
        }
        if (readable == null) {
            dir.deleteRecursively()
            error("staged share is not readable")
        }
        return staged
    }

    private fun openChooser(staged: File, mimeHint: String): PlatformOutcome = try {
        val uri = FileProvider.getUriForFile(app, "${app.packageName}.fileprovider", staged)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = mimeHint.ifBlank { "application/octet-stream" }
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(send, null).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
        app.startActivity(chooser)
        PlatformOutcome.APPLIED
    } catch (e: RuntimeException) {
        android.util.Log.w(TAG, "share chooser failed: ${e.javaClass.simpleName}")
        PlatformOutcome.PLATFORM_FAILED
    }

    /** Counts readable bytes without keeping them (OutputStream.nullOutputStream needs API 33). */
    private object DiscardingOutput : java.io.OutputStream() {
        override fun write(b: Int) = Unit
        override fun write(b: ByteArray, off: Int, len: Int) = Unit
    }

    companion object {
        private const val TAG = "MeshelfExport"

        /** Process-lifetime worker: a committed Save finishes even if its Activity is destroyed. */
        private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    }
}
