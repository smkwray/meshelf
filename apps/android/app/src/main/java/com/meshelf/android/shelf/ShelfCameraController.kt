package com.meshelf.android.shelf

import android.content.Context
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import java.io.File
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Implementable foreground camera component, not registered as a second capture product.
 * Caller must obtain CAMERA permission and a durable ordinary-source reservation first.
 * A native-issued app-private raw path is required; never accept a remote-supplied path.
 * Caller sanitizes on a worker via existing JpegSanitizer, then commits the same lease.
 */
class ShelfCameraController(private val context: Context, private val owner: LifecycleOwner) {
    private var provider: ProcessCameraProvider? = null
    private var imageCapture: ImageCapture? = null
    private var previewUseCase: Preview? = null
    private var generation = 0L
    private val taking = AtomicBoolean(false)

    fun open(view: PreviewView, ready: (Result<Unit>) -> Unit) {
        close()
        val ticket = generation
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            if (ticket != generation) return@addListener
            val result = runCatching {
                val p = future.get()
                val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
                val image = ImageCapture.Builder().setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY).build()
                p.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, image)
                provider = p
                previewUseCase = preview
                imageCapture = image
            }
            ready(result)
        }, ContextCompat.getMainExecutor(context))
    }
    fun take(raw: File, callbackExecutor: Executor, done: (Result<File>) -> Unit) {
        val image = imageCapture ?: return done(Result.failure(IllegalStateException("camera_not_ready")))
        if (taking.get()) return done(Result.failure(IllegalStateException("camera_busy")))
        if (raw.exists() || raw.parentFile?.isDirectory != true) {
            return done(Result.failure(IllegalStateException("camera_raw_reservation_invalid")))
        }
        if (!taking.compareAndSet(false, true)) return done(Result.failure(IllegalStateException("camera_busy")))
        image.takePicture(ImageCapture.OutputFileOptions.Builder(raw).build(), callbackExecutor,
            object : ImageCapture.OnImageSavedCallback {
                override fun onImageSaved(result: ImageCapture.OutputFileResults) {
                    // Always return completion to the lease owner, even after close().
                    // The owner must suppress publication after foreground invalidation.
                    taking.set(false)
                    done(Result.success(raw))
                }
                override fun onError(error: ImageCaptureException) {
                    taking.set(false)
                    done(Result.failure(error))
                }
            })
    }
    fun close() {
        generation += 1
        val p = provider
        // Never unbindAll(): do not steal an agent-request camera's use case.
        previewUseCase?.let { p?.unbind(it) }
        imageCapture?.let { p?.unbind(it) }
        provider = null
        previewUseCase = null
        imageCapture = null
    }
}
