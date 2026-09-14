package com.meshelf.android.shelf

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.widget.Button
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.camera.view.PreviewView
import com.meshelf.android.R
import com.meshelf.android.capture.CaptureRegistry
import com.meshelf.android.capture.JpegSanitizer
import com.meshelf.android.nativebridge.MeshelfNative
import com.meshelf.android.service.CaptureForegroundService
import com.meshelf.android.state.DeviceDisplayName
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Ordinary shelf camera: open (from shelf) + shutter. Paths come only from a native lease.
 * Does not use the capture-request timer or CaptureActivity.
 */
class ShelfCameraActivity : ComponentActivity() {
    private val mainExecutor = Executor { command -> Handler(Looper.getMainLooper()).post(command) }
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private val finished = AtomicBoolean(false)
    private val reserved = AtomicBoolean(false)
    private val nativeRef = AtomicReference<MeshelfNative?>(null)
    private var leaseId: String? = null
    private var rawPath: File? = null
    private var finalPath: File? = null
    private var controller: ShelfCameraController? = null
    private var bound = false
    private lateinit var previewView: PreviewView
    private lateinit var shutter: Button

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as? CaptureForegroundService.ShelfBinder ?: return
            binder.acquireShelfRef(DeviceDisplayName.load(this@ShelfCameraActivity))
            shelfBinder = binder
            val native = binder.nativeOrNull()
            if (native == null || !native.isStarted()) {
                // Route may still be attaching; poll briefly on main.
                mainExecutor.execute { waitForNative(binder, attempts = 20) }
                return
            }
            nativeRef.set(native)
            reserveAndOpen(native)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            nativeRef.set(null)
            shelfBinder = null
        }
    }

    private var shelfBinder: CaptureForegroundService.ShelfBinder? = null

    private fun waitForNative(binder: CaptureForegroundService.ShelfBinder, attempts: Int) {
        if (finished.get()) return
        val native = binder.nativeOrNull()
        if (native != null && native.isStarted()) {
            nativeRef.set(native)
            reserveAndOpen(native)
            return
        }
        if (attempts <= 0) {
            toastAndFinish(getString(R.string.shelf_not_connected))
            return
        }
        Handler(Looper.getMainLooper()).postDelayed(
            { waitForNative(binder, attempts - 1) },
            250L,
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (CaptureRegistry.active() != null) {
            Toast.makeText(this, R.string.shelf_camera_busy, Toast.LENGTH_LONG).show()
            finish()
            return
        }
        setContentView(R.layout.view_shelf_camera)
        previewView = findViewById(R.id.shelf_camera_preview)
        shutter = findViewById(R.id.shelf_camera_shutter)
        shutter.isEnabled = false
        findViewById<Button>(R.id.shelf_camera_cancel).setOnClickListener { cancelAndFinish() }
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() = cancelAndFinish()
            },
        )
        controller = ShelfCameraController(this, this)
        val intent = Intent(this, CaptureForegroundService::class.java)
            .setAction(CaptureForegroundService.ACTION_SHELF_BIND)
        bound = bindService(intent, connection, Context.BIND_AUTO_CREATE)
        if (!bound) {
            toastAndFinish(getString(R.string.shelf_not_connected))
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
            openCamera()
        } else {
            toastAndFinish(getString(R.string.camera_permission_denied))
        }
    }

    private fun reserveAndOpen(native: MeshelfNative) {
        if (!reserved.compareAndSet(false, true)) return
        if (CaptureRegistry.active() != null) {
            toastAndFinish(getString(R.string.shelf_camera_busy))
            return
        }
        val result = native.reserveOrdinaryPhoto(UUID.randomUUID().toString())
        if (result.isFailure) {
            android.util.Log.w(TAG, "reserve failed: ${result.exceptionOrNull()?.javaClass?.simpleName}")
            toastAndFinish(getString(R.string.camera_open_failed))
            return
        }
        val json = JSONObject(result.getOrThrow())
        leaseId = json.getString("leaseId")
        rawPath = File(json.getString("rawPath"))
        finalPath = File(json.getString("finalPath"))
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            openCamera()
        } else {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
        }
    }

    private fun openCamera() {
        val camera = controller ?: return
        camera.open(previewView) { result ->
            result.onSuccess {
                shutter.isEnabled = true
                shutter.setOnClickListener { takeAndAnnounce() }
            }.onFailure { error ->
                android.util.Log.w(TAG, "camera open failed: ${error.javaClass.simpleName}")
                toastAndFinish(getString(R.string.camera_open_failed))
            }
        }
    }

    private fun takeAndAnnounce() {
        if (!finished.compareAndSet(false, true)) return
        shutter.isEnabled = false
        val lease = leaseId
        val raw = rawPath
        val final = finalPath
        val native = nativeRef.get()
        if (lease == null || raw == null || final == null || native == null) {
            finish()
            return
        }
        controller?.take(raw, ioExecutor) { takeResult ->
            takeResult.fold(
                onSuccess = {
                    ioExecutor.execute {
                        val commit = runCatching {
                            val sanitized = JpegSanitizer.sanitize(raw, final)
                            native.commitOrdinaryPhoto(
                                lease,
                                sanitized.sha256,
                                sanitized.width,
                                sanitized.height,
                            ).getOrThrow()
                        }
                        mainExecutor.execute {
                            commit.fold(
                                onSuccess = { json ->
                                    // The photo is committed; only the sentence depends on decoding.
                                    val decoded = when (val d = ShelfDecoder.announce(json)) {
                                        is Decoded.Ok -> ShelfResult.Ok(d.value)
                                        is Decoded.Rejected -> ShelfResult.Rejected(d.failure)
                                    }
                                    val sentence = ShelfViews.text(this, ShelfWording.announce(decoded, photo = true).text)
                                    Toast.makeText(this, sentence, Toast.LENGTH_LONG).show()
                                    finish()
                                },
                                onFailure = { error ->
                                    native.abandonPhoto(lease)
                                    android.util.Log.w(TAG, "photo commit failed: ${error.javaClass.simpleName}")
                                    toastAndFinish(getString(R.string.camera_add_failed))
                                },
                            )
                        }
                    }
                },
                onFailure = { error ->
                    native.abandonPhoto(lease)
                    android.util.Log.w(TAG, "capture failed: ${error.javaClass.simpleName}")
                    toastAndFinish(getString(R.string.camera_capture_failed))
                },
            )
        }
    }

    private fun cancelAndFinish() {
        if (!finished.compareAndSet(false, true)) return
        abandonLease()
        finish()
    }

    private fun toastAndFinish(message: String) {
        if (!finished.compareAndSet(false, true)) {
            Toast.makeText(this, message, Toast.LENGTH_LONG).show()
            return
        }
        abandonLease()
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    private fun abandonLease() {
        leaseId?.let { id -> nativeRef.get()?.abandonPhoto(id) }
        leaseId = null
    }

    override fun onDestroy() {
        controller?.close()
        controller = null
        if (!isFinishing && !finished.get()) {
            abandonLease()
        }
        shelfBinder?.releaseShelfRef()
        shelfBinder = null
        if (bound) {
            runCatching { unbindService(connection) }
            bound = false
        }
        ioExecutor.shutdown()
        super.onDestroy()
    }

    companion object {
        private const val REQUEST_CAMERA = 71
        private const val TAG = "MeshelfShelfCamera"

        fun intent(context: Context): Intent = Intent(context, ShelfCameraActivity::class.java)
    }
}
