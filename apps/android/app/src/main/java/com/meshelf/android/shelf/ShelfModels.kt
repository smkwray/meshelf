package com.meshelf.android.shelf

/**
 * ABI-8 shelf models (handoffs/ANDROID_SHELF_ABI.md, schemaVersion 2). Rust derives every field;
 * Kotlin only validates and renders them. Metadata only: no body, thumbnail, clipboard text or path.
 */
data class ShelfKey(val sourceDevice: String, val offerId: String) {
    init {
        require(sourceDevice.isNotBlank())
        require(offerId.isNotBlank())
    }
}

enum class ShelfKind { TEXT, FILE, PHOTO, FOLDER }
enum class ShelfOwnership { OWN, RECEIVED }
enum class ShelfAvailability { READY, SOURCE_OFFLINE, SOURCE_CHANGED, UNSUPPORTED }
enum class ShelfCompleteness { COMPLETE }

/** Declared in contract order: Share is the file/photo primary action, Save the O-011 alternate. */
enum class ActivationAction { COPY_TEXT, SHARE_FILE, SAVE_FILE }

/**
 * `lastAttempt.code`: `OfferAttemptCode` in SCREAMING_SNAKE_CASE. Also accepts the ActivationResult
 * codes so a stored platform-stage code is not misread as an unknown schema.
 */
enum class AttemptCode {
    COMPLETED, SOURCE_UNAVAILABLE, SOURCE_CHANGED, BUSY, CANCELLED, CLIPBOARD_FAILED,
    VERIFICATION_FAILED, UNCERTAIN_NO_REPLAY, FAILED,
    PLATFORM_FAILED, FOREGROUND_LOST, UNSUPPORTED, INTERNAL,
}

data class LastAttempt(
    val code: AttemptCode,
    val attemptSequence: Long,
    val filesProcessed: Long,
    val bytesProcessed: Long,
    val detail: String?,
)

data class ShelfCard(
    val key: ShelfKey,
    val sourceDisplayName: String,
    val ownership: ShelfOwnership,
    val kind: ShelfKind,
    val displayName: String,
    val preview: String,
    val byteLength: Long,
    val shelfSequence: Long,
    val availability: ShelfAvailability,
    val supportedActions: List<ActivationAction>,
    val lastAttempt: LastAttempt?,
) {
    init {
        require(byteLength >= 0 && shelfSequence >= 0)
        require(preview.toByteArray(Charsets.UTF_8).size <= MAX_PREVIEW_UTF8_BYTES) { "preview exceeds O-015" }
        require(supportedActions.isEmpty() || availability == ShelfAvailability.READY)
    }

    /** The whole-card action: first native-supported action, never reconstructed from kind. */
    fun primaryAction(): ActivationAction? = supportedActions.firstOrNull()

    fun supportsSave(): Boolean = ActivationAction.SAVE_FILE in supportedActions

    companion object {
        const val MAX_PREVIEW_UTF8_BYTES = 256
    }
}

enum class PeerTrigger { REFRESH, ANNOUNCE }
enum class PeerReachability { REACHABLE, UNAVAILABLE }
enum class PeerOutcome { CATALOG_APPLIED, CATALOG_UNSUPPORTED, CATALOG_FAILED, REFUSED, STORED, TRANSPORT_FAILED, NO_ADDRESS }

data class PeerEntry(
    val deviceId: String,
    val displayName: String,
    val reachability: PeerReachability,
    val outcome: PeerOutcome,
)

data class PeerObservation(val trigger: PeerTrigger, val peers: List<PeerEntry>)

/** `peerObservation` is null (no explicit operation yet), valid, or unreadable (cards still kept). */
sealed class PeerStatus {
    object None : PeerStatus()
    data class Observed(val observation: PeerObservation) : PeerStatus()
    object Unreadable : PeerStatus()
}

data class ShelfSnapshot(
    val ready: Boolean,
    val completeness: ShelfCompleteness,
    val localDisplayName: String,
    val cards: List<ShelfCard>,
    val peerStatus: PeerStatus,
) {
    init {
        require(cards.size <= MAX_CARDS) { "ordinary shelf exceeds O-014" }
        require(cards.map { it.key }.distinct().size == cards.size) { "duplicate shelf keys" }
    }

    companion object {
        const val MAX_CARDS = 10
    }
}

data class RefreshResult(val newItems: Long, val snapshot: ShelfSnapshot)

data class AnnounceResult(
    val offerId: String,
    val localStored: Boolean,
    val addedCount: Long,
    val unavailableCount: Long,
    val refusedCount: Long,
    val peers: List<PeerEntry>,
)

enum class ActivationStatus { COMPLETED, FAILED, UNCERTAIN }

enum class ActivationCode {
    COMPLETED, SOURCE_UNAVAILABLE, SOURCE_CHANGED, BUSY, CANCELLED, CLIPBOARD_FAILED,
    VERIFICATION_FAILED, PLATFORM_FAILED, FOREGROUND_LOST, UNCERTAIN_NO_REPLAY, UNSUPPORTED, INTERNAL,
}

data class ActivationResult(
    val key: ShelfKey,
    val action: ActivationAction,
    val status: ActivationStatus,
    val code: ActivationCode,
    val filesProcessed: Long,
    val bytesProcessed: Long,
    val detail: String?,
)

enum class ShelfErrorCode { NOT_READY, CAMERA_BUSY, NATIVE_FAILED, RESULT_MISMATCH }

sealed class ShelfResult<out T> {
    data class Ok<T>(val value: T) : ShelfResult<T>()
    /** Native returned JSON that violates the contract. The caller keeps its last good render. */
    data class Rejected(val failure: DecodeFailure) : ShelfResult<Nothing>()
    /** Resident not ready, or a thrown JNI contract exception. Detail is technical (Details only). */
    data class Error(val code: ShelfErrorCode, val detail: String) : ShelfResult<Nothing>()
}

/** Ordinary fanout and request-scoped grants must not be represented by a nullable target. */
sealed class PhotoOperation {
    object PutOnShelf : PhotoOperation()
    data class FulfilRequest(val requestId: String, val requesterDevice: String) : PhotoOperation() {
        init { require(requestId.isNotBlank()); require(requesterDevice.isNotBlank()) }
    }
}
enum class PhotoRetention { UNTIL_SHELF_PURGE, UNTIL_CAPTURE_RECEIPT_OR_DEADLINE }
fun PhotoOperation.retention(): PhotoRetention = when (this) {
    PhotoOperation.PutOnShelf -> PhotoRetention.UNTIL_SHELF_PURGE
    is PhotoOperation.FulfilRequest -> PhotoRetention.UNTIL_CAPTURE_RECEIPT_OR_DEADLINE
}
fun PhotoOperation.isMeshWide(): Boolean = this is PhotoOperation.PutOnShelf
