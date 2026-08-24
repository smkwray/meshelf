//! Domain semantics for meshelf.
//!
//! This crate deliberately has no socket, Tailscale, UI, database, or operating-system
//! dependencies. The most important contract implemented here is at-most-once clipboard
//! application across duplicate delivery and an uncertain crash boundary.

mod memory_store;
mod model;
mod receiver;
mod store;

pub use memory_store::MemoryReceiveStore;
pub use model::{
    ContentKind, DeliveryMode, DeviceId, EnvelopeValidationError, MAX_TEXT_BYTES, MessageId,
    PROTOCOL_VERSION, Receipt, ReceiptCode, TextEnvelope,
};
pub use receiver::{ClipboardError, ClipboardSink, ReceiverService};
pub use store::{
    ReceivePhase, ReceiveRecord, ReceiveState, ReceiveStore, StoreError, TransitionOutcome,
};
