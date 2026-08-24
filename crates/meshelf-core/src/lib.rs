//! Domain semantics for meshelf.
//!
//! This crate deliberately has no socket, Tailscale, UI, database, or operating-system
//! dependencies. The most important contract implemented here is at-most-once clipboard
//! application across duplicate delivery and an uncertain crash boundary.

mod activation;
mod memory_store;
mod model;
mod offer;
mod receiver;
mod store;

pub use activation::{
    ActivationId, ActivationJournalEntry, ActivationState, ClipboardCacheRecord,
    ClipboardCacheState,
};
pub use memory_store::MemoryReceiveStore;
pub use model::{
    ContentKind, DeliveryMode, DeviceId, EnvelopeValidationError, MAX_TEXT_BYTES, MessageId,
    PROTOCOL_VERSION, Receipt, ReceiptCode, TextEnvelope,
};
pub use offer::{
    CardAvailability, MAX_OFFER_ATTEMPT_DETAIL_BYTES, MAX_OFFER_FILE_BYTES,
    MAX_OFFER_MANIFEST_ENTRIES, MAX_OFFER_PORTABLE_COMPONENT_BYTES, MAX_OFFER_PREVIEW_BYTES,
    MAX_OFFER_TRANSFER_BYTES, OfferDescriptor, OfferDescriptorError, OfferId, OfferSource,
    OfferSourceError, V2_MAX_LIVE_ENTRIES,
};
pub use receiver::{ClipboardError, ClipboardSink, ReceiverService};
pub use store::{
    CleanupReport, MigrationReport, OfferAttemptCode, OfferAttemptStatus, OfferCardInput,
    OfferCardInsert, OfferCardRecord, OfferSourceInput, OfferSourceInsert, OfferSourceRecord,
    ReceivePhase, ReceiveRecord, ReceiveState, ReceiveStore, StoreError, TransitionOutcome,
};
