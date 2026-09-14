package com.meshelf.android.capture

data class CaptureRequest(
    val requestId: String,
    val requesterName: String,
    val purpose: String,
    val expiresAtMs: Long,
) {
    init {
        RequestText.requireRequestId(requestId)
        RequestText.requireRequesterName(requesterName)
        RequestText.requirePurpose(purpose)
        require(expiresAtMs > 0L) { "expiry must be positive" }
    }
}

enum class CapturePresentationResult {
    PRESENTED,
    DUPLICATE,
    BUSY,
    EXPIRED,
    INVALID,
}

data class CapturedPhoto(
    val requestId: String,
    val absolutePath: String,
    val sha256: String,
    val width: Int,
    val height: Int,
) {
    init {
        RequestText.requireRequestId(requestId)
        require(Regex("[0-9a-f]{64}").matches(sha256)) { "sha256 must be 64 lowercase hexadecimal characters" }
        require(width in 1..100_000 && height in 1..100_000) { "invalid image dimensions" }
        require(absolutePath.startsWith("/")) { "capture path must be absolute" }
    }
}
