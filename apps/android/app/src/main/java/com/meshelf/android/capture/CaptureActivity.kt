package com.meshelf.android.capture

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.KeyEvent
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import com.meshelf.android.R
import com.meshelf.android.service.CaptureForegroundService
import com.meshelf.android.state.AppStatePaths
import java.lang.ref.WeakReference
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class CaptureActivity : ComponentActivity() {
    private val mainExecutor = Executor { command -> Handler(Looper.getMainLooper()).post(command) }
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private val terminalAction = AtomicBoolean(false)
    private lateinit var previewView: PreviewView
    private lateinit var shutter: Button
    private lateinit var flash: Button
    private lateinit var lens: Button
    private var imageCapture: ImageCapture? = null
    private var provider: ProcessCameraProvider? = null
    private var request: CaptureRequest? = null
    private var useFrontLens = false
    private var flashIndex = 0
    private val flashModes = intArrayOf(ImageCapture.FLASH_MODE_OFF, ImageCapture.FLASH_MODE_AUTO, ImageCapture.FLASH_MODE_ON)

    override fun onCreate(savedInstanceState: Bundle?) {
        if (Build.VERSION.SDK_INT >= 27) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON,
            )
        }
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_capture)
        applySystemBarInsets()

        val requestId = intent.getStringExtra(EXTRA_REQUEST_ID)
        val active = requestId?.let(CaptureRegistry::active)
        if (active == null || active.expiresAtMs <= System.currentTimeMillis()) {
            finish()
            return
        }
        request = active
        activeActivity = WeakReference(this)

        findViewById<TextView>(R.id.requester).text = "Requested by ${active.requesterName}"
        findViewById<TextView>(R.id.purpose).text = "Purpose: ${active.purpose}"
        previewView = findViewById(R.id.preview_view)
        shutter = findViewById(R.id.shutter)
        flash = findViewById(R.id.flash)
        lens = findViewById(R.id.switch_lens)

        shutter.setOnClickListener { takePhoto() }
        flash.setOnClickListener {
            flashIndex = (flashIndex + 1) % flashModes.size
            imageCapture?.flashMode = flashModes[flashIndex]
            flash.text = when (flashModes[flashIndex]) {
                ImageCapture.FLASH_MODE_AUTO -> getString(R.string.flash_auto)
                ImageCapture.FLASH_MODE_ON -> getString(R.string.flash_on)
                else -> getString(R.string.flash_off)
            }
        }
        lens.setOnClickListener {
            useFrontLens = !useFrontLens
            bindCamera()
        }
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() = decline("user-declined")
            },
        )

        val keyguard = getSystemService(KeyguardManager::class.java)
        if (keyguard.isKeyguardLocked) keyguard.requestDismissKeyguard(this, null)

        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQUEST_CAMERA) return
        if (grantResults.singleOrNull() == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            decline("camera-permission-denied")
        }
    }

    private fun applySystemBarInsets() {
        val header = findViewById<LinearLayout>(R.id.capture_header)
        val controls = findViewById<LinearLayout>(R.id.capture_controls)
        val headerPadL = header.paddingLeft
        val headerPadT = header.paddingTop
        val headerPadR = header.paddingRight
        val headerPadB = header.paddingBottom
        val controlPadL = controls.paddingLeft
        val controlPadT = controls.paddingTop
        val controlPadR = controls.paddingRight
        val controlPadB = controls.paddingBottom
        fun pad(left: Int, top: Int, right: Int, bottom: Int) {
            header.setPadding(headerPadL + left, headerPadT + top, headerPadR + right, headerPadB)
            controls.setPadding(
                controlPadL + left,
                controlPadT,
                controlPadR + right,
                controlPadB + bottom,
            )
        }
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false)
            findViewById<View>(R.id.capture_root).setOnApplyWindowInsetsListener { _, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars())
                pad(bars.left, bars.top, bars.right, bars.bottom)
                insets
            }
            findViewById<View>(R.id.capture_root).requestApplyInsets()
        } else {
            @Suppress("DEPRECATION")
            window.decorView.setOnApplyWindowInsetsListener { _, insets ->
                pad(
                    insets.systemWindowInsetLeft,
                    insets.systemWindowInsetTop,
                    insets.systemWindowInsetRight,
                    insets.systemWindowInsetBottom,
                )
                @Suppress("DEPRECATION")
                insets.consumeSystemWindowInsets()
            }
        }
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener(
            {
                runCatching {
                    provider = future.get()
                    bindCamera()
                }.onFailure { error ->
                    Toast.makeText(this, "Camera unavailable: ${error.message}", Toast.LENGTH_LONG).show()
                    shutter.isEnabled = false
                }
            },
            mainExecutor,
        )
    }

    private fun bindCamera() {
        val cameraProvider = provider ?: return
        val preferred = if (useFrontLens) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA
        val selector = when {
            runCatching { cameraProvider.hasCamera(preferred) }.getOrDefault(false) -> preferred
            runCatching { cameraProvider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) }.getOrDefault(false) -> {
                useFrontLens = false
                CameraSelector.DEFAULT_BACK_CAMERA
            }
            else -> {
                shutter.isEnabled = false
                return
            }
        }
        val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
        imageCapture = ImageCapture.Builder()
            .setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
            .setFlashMode(flashModes[flashIndex])
            .build()
        cameraProvider.unbindAll()
        cameraProvider.bindToLifecycle(this, selector, preview, imageCapture)
    }

    private fun takePhoto() {
        val active = request ?: return
        if (terminalAction.get() || !shutter.isEnabled) return
        if (CaptureRegistry.active(active.requestId) == null || active.expiresAtMs <= System.currentTimeMillis()) {
            finishRequest(active.requestId)
            return
        }
        val capture = imageCapture ?: return
        shutter.isEnabled = false
        val raw = CaptureFiles.rawFile(cacheDir, active.requestId)
        val destination = CaptureFiles.finalFile(AppStatePaths.from(this).root, active.requestId)
        raw.delete()
        destination.delete()

        capture.takePicture(
            ImageCapture.OutputFileOptions.Builder(raw).build(),
            ioExecutor,
            object : ImageCapture.OnImageSavedCallback {
                override fun onImageSaved(output: ImageCapture.OutputFileResults) {
                    runCatching {
                        val result = JpegSanitizer.sanitize(raw, destination)
                        check(raw.delete() || !raw.exists()) { "could not remove raw camera file" }
                        val photo = CapturedPhoto(
                            requestId = active.requestId,
                            absolutePath = destination.canonicalPath,
                            sha256 = result.sha256,
                            width = result.width,
                            height = result.height,
                        )
                        check(CaptureRegistry.markCaptured(photo)) { "capture request is no longer active" }
                        startService(
                            Intent(this@CaptureActivity, CaptureForegroundService::class.java)
                                .setAction(CaptureForegroundService.ACTION_CAPTURED)
                                .putExtra(CaptureForegroundService.EXTRA_REQUEST_ID, photo.requestId)
                                .putExtra(CaptureForegroundService.EXTRA_PATH, photo.absolutePath)
                                .putExtra(CaptureForegroundService.EXTRA_SHA256, photo.sha256)
                                .putExtra(CaptureForegroundService.EXTRA_WIDTH, photo.width)
                                .putExtra(CaptureForegroundService.EXTRA_HEIGHT, photo.height),
                        )
                    }.onFailure { error ->
                        raw.delete()
                        destination.delete()
                        runOnUiThread {
                            Toast.makeText(this@CaptureActivity, "Capture failed: ${error.message}", Toast.LENGTH_LONG).show()
                            shutter.isEnabled = true
                        }
                        return
                    }
                    terminalAction.set(true)
                    runOnUiThread { finish() }
                }

                override fun onError(exception: ImageCaptureException) {
                    raw.delete()
                    runOnUiThread {
                        Toast.makeText(this@CaptureActivity, "Capture failed: ${exception.message}", Toast.LENGTH_LONG).show()
                        shutter.isEnabled = true
                    }
                }
            },
        )
    }

    private fun decline(reason: String) {
        val requestId = request?.requestId ?: return finish()
        if (!terminalAction.compareAndSet(false, true)) return
        startService(
            Intent(this, CaptureForegroundService::class.java)
                .setAction(CaptureForegroundService.ACTION_DECLINE)
                .putExtra(CaptureForegroundService.EXTRA_REQUEST_ID, requestId)
                .putExtra(CaptureForegroundService.EXTRA_REASON, reason),
        )
        finish()
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        if ((keyCode == KeyEvent.KEYCODE_VOLUME_UP || keyCode == KeyEvent.KEYCODE_VOLUME_DOWN) && event.repeatCount == 0) {
            takePhoto()
            return true
        }
        return super.onKeyDown(keyCode, event)
    }

    override fun onDestroy() {
        provider?.unbindAll()
        if (activeActivity?.get() === this) activeActivity = null
        ioExecutor.shutdown()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_REQUEST_ID = "requestId"
        private const val REQUEST_CAMERA = 2002
        @Volatile private var activeActivity: WeakReference<CaptureActivity>? = null

        fun finishRequest(requestId: String) {
            val activity = activeActivity?.get() ?: return
            if (activity.request?.requestId == requestId) {
                activity.terminalAction.set(true)
                activity.runOnUiThread { activity.finish() }
            }
        }
    }
}
