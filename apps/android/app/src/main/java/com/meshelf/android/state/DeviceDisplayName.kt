package com.meshelf.android.state

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.meshelf.android.capture.RequestText

/** Device display name for hello / pairing: prefs, then system Settings name, then model. */
object DeviceDisplayName {
    private const val PREFS = "meshelf_ui"
    private const val KEY = "device_name"

    fun load(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val saved = prefs.getString(KEY, null)?.trim().orEmpty()
        if (saved.isNotEmpty()) {
            return runCatching { RequestText.requireDeviceName(saved) }.getOrElse { fallback(context) }
        }
        return fallback(context)
    }

    fun save(context: Context, name: String) {
        val validated = RequestText.requireDeviceName(name)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY, validated)
            .apply()
    }

    fun fallback(context: Context): String {
        // Settings.Secure.bluetooth_name is blocked for targetSdk > 31 (SecurityException).
        val fromSettings = runCatching {
            Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
        }.getOrNull()?.trim()?.takeIf(String::isNotEmpty)
        val raw = fromSettings ?: Build.MODEL.ifBlank { "Android phone" }
        val cleaned = raw
            .filterNot { Character.isISOControl(it) || Character.getType(it) == Character.FORMAT.toInt() }
            .ifBlank { "Android phone" }
        return cleaned.toByteArray(Charsets.UTF_8)
            .take(RequestText.MAX_DEVICE_NAME_UTF8_BYTES)
            .toByteArray()
            .toString(Charsets.UTF_8)
            .trimEnd('\uFFFD')
            .ifBlank { "Android phone" }
            .let { runCatching { RequestText.requireDeviceName(it) }.getOrDefault("Android phone") }
    }
}
