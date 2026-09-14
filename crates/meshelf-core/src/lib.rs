//! Domain semantics for meshelf.
//!
//! This crate deliberately has no socket, Tailscale, UI, database, or operating-system
//! dependencies. The most important contract implemented here is at-most-once clipboard
//! application across duplicate delivery and an uncertain crash boundary.

mod activation;
mod capture;
mod destination;
mod model;
mod offer;
mod receiver;
mod settings;
mod store;

pub use activation::{
    ActivationId, ActivationJournalEntry, ActivationMode, ActivationState, ClipboardCacheRecord,
    ClipboardCacheState, ClipboardFence,
};
pub use capture::{
    CaptureCorrelation, CaptureKind, CaptureLens, CaptureNotStarted, CaptureOutcome,
    CapturePullGrant, CaptureReceipt, CaptureRequestId, CaptureRequestPhase, CaptureRequestRecord,
    CaptureSourcePhase, CaptureSourceRecord, CaptureSourceTerminalCode, CaptureTerminalCode,
    CaptureTextError, CapturedPhoto, MAX_CAPTURE_DETAIL_BYTES, MAX_CAPTURE_LABEL_BYTES,
    MAX_CAPTURE_LIFETIME_MS, MAX_CAPTURE_PURPOSE_BYTES, validate_capture_detail,
    validate_capture_label, validate_capture_lifetime, validate_capture_purpose,
};
pub use destination::{
    DestinationPolicy, relative_path, validate_component, validate_relative_path,
};
pub use model::{
    ContentKind, DeviceId, MAX_CONTROL_REQUEST_BYTES, MAX_TEXT_BYTES, MessageId, PROTOCOL_VERSION,
};
pub use offer::{
    CardAvailability, DocumentLeaseId, FileContentClass, MAX_OFFER_ATTEMPT_DETAIL_BYTES,
    MAX_OFFER_FILE_BYTES, MAX_OFFER_MANIFEST_ENTRIES, MAX_OFFER_PORTABLE_COMPONENT_BYTES,
    MAX_OFFER_PREVIEW_BYTES, MAX_OFFER_TRANSFER_BYTES, OfferDescriptor, OfferDescriptorError,
    OfferId, OfferSource, OfferSourceError, V2_MAX_LIVE_ENTRIES,
};
pub use receiver::{ClipboardError, ClipboardSink};
pub use settings::{SaveDestination, UserSettings};
pub use store::{
    CatalogFrontier, CleanupReport, MigrationReport, OfferAnnouncedRecipientUpdate,
    OfferAttemptCode, OfferAttemptStatus, OfferCardInput, OfferCardInsert, OfferCardRecord,
    OfferEligibilityUpdate, OfferSourceInput, OfferSourceInsert, OfferSourceRecord,
    OfferSourceStore, OwnedOrdinaryInsert, StoreError,
};
