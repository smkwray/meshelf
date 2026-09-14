package com.meshelf.android.capture

/**
 * One process-local request slot. Rust owns durable protocol state and duplicate handling.
 * Kotlin deliberately does not persist requester/purpose text across process death.
 */
object CaptureRegistry {
    private const val MAX_FUTURE_EXPIRY_MS = 3 * 60 * 1000L + 5_000L

    private data class Slot(
        val request: CaptureRequest,
        var captured: CapturedPhoto? = null,
    )

    private var slot: Slot? = null

    @Synchronized
    fun present(
        requestId: String,
        requesterName: String,
        purpose: String,
        expiresAtMs: Long,
        nowMs: Long,
    ): CapturePresentationResult {
        val request = try {
            CaptureRequest(
                requestId = RequestText.requireRequestId(requestId),
                requesterName = RequestText.requireRequesterName(requesterName),
                purpose = RequestText.requirePurpose(purpose),
                expiresAtMs = expiresAtMs,
            )
        } catch (_: IllegalArgumentException) {
            return CapturePresentationResult.INVALID
        }

        if (expiresAtMs <= nowMs) return CapturePresentationResult.EXPIRED
        if (expiresAtMs - nowMs > MAX_FUTURE_EXPIRY_MS) return CapturePresentationResult.INVALID

        val existing = slot
        if (existing != null) {
            return if (existing.request.requestId == requestId) {
                CapturePresentationResult.DUPLICATE
            } else {
                CapturePresentationResult.BUSY
            }
        }

        slot = Slot(request)
        return CapturePresentationResult.PRESENTED
    }

    @Synchronized
    fun active(requestId: String? = null): CaptureRequest? {
        val current = slot?.request ?: return null
        return if (requestId == null || current.requestId == requestId) current else null
    }

    @Synchronized
    fun markCaptured(photo: CapturedPhoto): Boolean {
        val current = slot ?: return false
        if (current.request.requestId != photo.requestId || current.captured != null) return false
        current.captured = photo
        return true
    }

    @Synchronized
    fun captured(requestId: String): CapturedPhoto? =
        slot?.takeIf { it.request.requestId == requestId }?.captured

    @Synchronized
    fun clear(requestId: String): CaptureRequest? {
        val current = slot ?: return null
        if (current.request.requestId != requestId) return null
        slot = null
        return current.request
    }

    @Synchronized
    fun clearAny(): CaptureRequest? {
        val current = slot ?: return null
        slot = null
        return current.request
    }
}
