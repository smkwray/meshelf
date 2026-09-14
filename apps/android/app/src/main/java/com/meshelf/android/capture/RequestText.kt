package com.meshelf.android.capture

import java.nio.charset.StandardCharsets

/** Defensive display and path validation. Rust remains authoritative for wire validation. */
object RequestText {
    const val MAX_PURPOSE_UTF8_BYTES: Int = 160
    const val MAX_REQUESTER_UTF8_BYTES: Int = 128
    const val MAX_DEVICE_NAME_UTF8_BYTES: Int = 80

    const val MAX_PAIRING_RESULT_UTF8_BYTES: Int = 64

    private val requestIdPattern = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    private val pairingCodePattern = Regex("[0-9]{6}")
    private val pairingIdPattern = Regex("[0-9a-f]{32}")
    private val transcriptHashPattern = Regex("[0-9a-f]{64}")

    fun requirePurpose(value: String): String = requirePlainText(
        label = "purpose",
        value = value,
        maxUtf8Bytes = MAX_PURPOSE_UTF8_BYTES,
        allowEmpty = false,
    )

    fun requireRequesterName(value: String): String = requirePlainText(
        label = "requester name",
        value = value,
        maxUtf8Bytes = MAX_REQUESTER_UTF8_BYTES,
        allowEmpty = false,
    )

    fun requireDeviceName(value: String): String = requirePlainText(
        label = "device name",
        value = value,
        maxUtf8Bytes = MAX_DEVICE_NAME_UTF8_BYTES,
        allowEmpty = false,
    )

    fun requireRequestId(value: String): String {
        require(requestIdPattern.matches(value)) { "invalid request id" }
        return value
    }

    /** Exactly six ASCII digits; `[0-9]` deliberately excludes other scripts' decimal digits. */
    fun requirePairingCode(value: String): String {
        require(pairingCodePattern.matches(value)) { "pairing code must contain exactly six digits" }
        return value
    }

    fun requirePairingId(value: String): String {
        require(pairingIdPattern.matches(value)) { "pairing id must be 32 lowercase hexadecimal characters" }
        return value
    }

    fun requireTranscriptHash(value: String): String {
        require(transcriptHashPattern.matches(value)) {
            "transcript hash must be 64 lowercase hexadecimal characters"
        }
        return value
    }

    /** The ABI-3 result vocabulary is Rust's; Kotlin only makes sure it is safe to show literally. */
    fun requirePairingResult(value: String): String = requirePlainText(
        label = "pairing result",
        value = value,
        maxUtf8Bytes = MAX_PAIRING_RESULT_UTF8_BYTES,
        allowEmpty = false,
    )

    private fun requirePlainText(
        label: String,
        value: String,
        maxUtf8Bytes: Int,
        allowEmpty: Boolean,
    ): String {
        if (!allowEmpty) require(value.isNotEmpty()) { "$label must not be empty" }
        require(value.toByteArray(StandardCharsets.UTF_8).size <= maxUtf8Bytes) {
            "$label exceeds $maxUtf8Bytes UTF-8 bytes"
        }
        require(value.none { Character.isISOControl(it) }) { "$label contains a control character" }
        require(value.none { Character.getType(it) == Character.FORMAT.toInt() }) {
            "$label contains a formatting control character"
        }
        return value
    }
}
