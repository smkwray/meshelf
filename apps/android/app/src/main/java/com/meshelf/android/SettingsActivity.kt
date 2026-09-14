package com.meshelf.android

import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import com.meshelf.android.service.CaptureForegroundService
import com.meshelf.android.shelf.SaveSettings
import com.meshelf.android.shelf.SaveTarget
import com.meshelf.android.shelf.SaveUnavailableReason
import com.meshelf.android.state.DeviceDisplayName

/** Settings: device name, O-011 save location, and optional background capture availability. */
class SettingsActivity : ShelfForegroundActivity() {
    private lateinit var saveSettings: SaveSettings
    private lateinit var deviceName: TextView
    private lateinit var deviceNote: TextView
    private lateinit var saveLabel: TextView
    private lateinit var saveNote: TextView
    private lateinit var saveReset: Button
    private lateinit var toggle: Switch
    private lateinit var availabilityStatus: TextView
    private var suppressToggle = false
    private var pendingDeviceName: String? = null
    private var folderSelectionPending = false
    private var folderHoldTaken = false

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        val name = pendingDeviceName
        pendingDeviceName = null
        if (granted && name != null) enableAvailability(name) else {
            availabilityStatus.setText(R.string.availability_needs_notifications)
            setToggle(false)
        }
    }

    private val chooseFolder = registerForActivityResult(
        object : ActivityResultContracts.OpenDocumentTree() {
            override fun createIntent(context: Context, input: Uri?): Intent =
                super.createIntent(context, input).addFlags(
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
                )
        },
    ) { tree ->
        folderSelectionPending = false
        try {
            if (tree != null && !saveSettings.choose(tree)) saveNote.setText(R.string.settings_folder_grant_failed)
        } finally {
            endFolderHold()
        }
        renderSave(keepNote = tree != null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        applySystemBarInsets(findViewById(R.id.settings_root))
        findViewById<TextView>(R.id.screen_title).setText(R.string.settings_title)
        findViewById<View>(R.id.screen_back).setOnClickListener { finish() }
        saveSettings = SaveSettings(this)
        deviceName = findViewById(R.id.settings_device_name)
        deviceNote = findViewById(R.id.settings_device_note)
        saveLabel = findViewById(R.id.settings_save_label)
        saveNote = findViewById(R.id.settings_save_note)
        saveReset = findViewById(R.id.settings_save_reset)
        toggle = findViewById(R.id.settings_availability_switch)
        availabilityStatus = findViewById(R.id.settings_availability_status)

        findViewById<Button>(R.id.settings_rename).setOnClickListener { rename() }
        findViewById<Button>(R.id.settings_save_change).setOnClickListener { changeFolder() }
        saveReset.setOnClickListener {
            saveSettings.reset()
            renderSave(keepNote = false)
        }
        toggle.setOnCheckedChangeListener { _, enabled ->
            if (!suppressToggle) { if (enabled) requestEnable() else disableAvailability() }
        }
        if (savedInstanceState == null) maybeAutoEnable(intent)
    }

    override fun onStart() {
        super.onStart()
        // The service reports on/off after onStartCommand; reading it right after startService
        // showed Off and snapped the switch back while the service was in fact starting.
        CaptureForegroundService.setRunningListener { if (!isDestroyed) refreshAvailabilityUi() }
    }

    override fun onStop() {
        CaptureForegroundService.setRunningListener(null)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        deviceName.text = DeviceDisplayName.load(this)
        renderSave(keepNote = false)
        refreshAvailabilityUi()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        maybeAutoEnable(intent)
    }

    private fun rename() {
        val field = EditText(this).apply {
            setText(DeviceDisplayName.load(this@SettingsActivity))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
            setSingleLine()
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.settings_rename_title)
            .setView(field)
            .setPositiveButton(R.string.settings_rename) { _, _ ->
                val saved = runCatching { DeviceDisplayName.save(this, field.text.toString().trim()) }.isSuccess
                deviceName.text = DeviceDisplayName.load(this)
                deviceNote.setText(if (saved) R.string.settings_rename_note else R.string.settings_name_invalid)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun changeFolder() {
        if (folderSelectionPending) return
        folderSelectionPending = true
        io.execute {
            val held = runCatching { backend.beginExternalSelectionHold() }
            runOnUiThread {
                if (isDestroyed) {
                    if (held.isSuccess) backend.endExternalSelectionHold()
                    return@runOnUiThread
                }
                // Choosing a folder does not need the resident, so a failed hold does not block it;
                // only a hold this screen actually took is ended.
                folderHoldTaken = held.isSuccess
                val launched = runCatching { chooseFolder.launch(null) }.isSuccess
                if (!launched) {
                    folderSelectionPending = false
                    endFolderHold()
                    saveNote.setText(R.string.settings_folder_grant_failed)
                    saveNote.visibility = View.VISIBLE
                }
            }
        }
    }

    private fun endFolderHold() {
        if (!folderHoldTaken) return
        folderHoldTaken = false
        backend.endExternalSelectionHold()
    }

    private fun renderSave(keepNote: Boolean) {
        val target = saveSettings.resolve()
        saveReset.visibility = if (saveSettings.folderUri != null) View.VISIBLE else View.GONE
        saveLabel.text = when (target) {
            SaveTarget.Downloads -> getString(R.string.downloads)
            is SaveTarget.Folder -> target.label
            is SaveTarget.Unavailable -> saveSettings.folderLabel ?: getString(R.string.settings_save_not_set)
        }
        val note = when ((target as? SaveTarget.Unavailable)?.reason) {
            SaveUnavailableReason.NO_FOLDER_BEFORE_ANDROID_10 -> getString(R.string.settings_save_pre10)
            SaveUnavailableReason.FOLDER_ACCESS_REVOKED -> getString(R.string.settings_folder_revoked)
            null -> null
        }
        if (note != null) saveNote.text = note
        saveNote.visibility = if (note != null || (keepNote && saveNote.text.isNotEmpty())) View.VISIBLE else View.GONE
        if (note == null && !keepNote) saveNote.text = ""
    }

    private fun maybeAutoEnable(intent: Intent) {
        if (!intent.getBooleanExtra(MainActivity.EXTRA_AUTO_ENABLE, false)) return
        val name = intent.getStringExtra(MainActivity.EXTRA_DEVICE_NAME)?.trim().orEmpty()
        if (name.isNotEmpty()) runCatching { DeviceDisplayName.save(this, name) }
        requestEnable()
    }

    private fun refreshAvailabilityUi() {
        val running = CaptureForegroundService.isRunning()
        setToggle(running)
        availabilityStatus.setText(if (running) R.string.availability_on else R.string.availability_off)
    }

    private fun requestEnable() {
        val name = DeviceDisplayName.load(this)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            pendingDeviceName = name
            setToggle(false)
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else enableAvailability(name)
    }

    private fun enableAvailability(name: String) {
        try {
            startForegroundService(
                Intent(this, CaptureForegroundService::class.java)
                    .setAction(CaptureForegroundService.ACTION_START)
                    .putExtra(CaptureForegroundService.EXTRA_DEVICE_NAME, name),
            )
            availabilityStatus.setText(R.string.availability_starting)
        } catch (e: RuntimeException) {
            android.util.Log.w("MeshelfSettings", "availability start failed: ${e.javaClass.simpleName}")
            setToggle(false)
            availabilityStatus.setText(R.string.availability_failed)
        }
    }

    private fun disableAvailability() {
        pendingDeviceName = null
        startService(Intent(this, CaptureForegroundService::class.java).setAction(CaptureForegroundService.ACTION_STOP))
        availabilityStatus.setText(R.string.availability_stopping)
    }

    private fun setToggle(value: Boolean) {
        suppressToggle = true
        toggle.isChecked = value
        suppressToggle = false
    }
}
