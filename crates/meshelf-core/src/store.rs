use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CardAvailability, DeviceId, MAX_OFFER_ATTEMPT_DETAIL_BYTES, MessageId, OfferDescriptor,
    OfferId, OfferSource, TextEnvelope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceivePhase {
    Recorded,
    Applying,
    Applied,
    ClipboardFailed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveState {
    pub phase: ReceivePhase,
    pub detail: Option<String>,
}

impl ReceiveState {
    #[must_use]
    pub const fn recorded() -> Self {
        Self {
            phase: ReceivePhase::Recorded,
            detail: None,
        }
    }

    #[must_use]
    pub const fn applying() -> Self {
        Self {
            phase: ReceivePhase::Applying,
            detail: None,
        }
    }

    #[must_use]
    pub const fn applied() -> Self {
        Self {
            phase: ReceivePhase::Applied,
            detail: None,
        }
    }

    #[must_use]
    pub fn clipboard_failed(detail: impl Into<String>) -> Self {
        Self {
            phase: ReceivePhase::ClipboardFailed,
            detail: Some(detail.into()),
        }
    }

    #[must_use]
    pub fn rejected(detail: impl Into<String>) -> Self {
        Self {
            phase: ReceivePhase::Rejected,
            detail: Some(detail.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveRecord {
    pub envelope: TextEnvelope,
    pub state: ReceiveState,
    pub first_seen_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionOutcome {
    Changed(ReceiveRecord),
    Mismatch(ReceiveRecord),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("receive store error: {message}")]
pub struct StoreError {
    message: String,
}

impl StoreError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

pub trait ReceiveStore: Send + Sync + 'static {
    /// Inserts the message in `Recorded` if absent and returns the current record.
    /// Implementations must perform the check-and-insert atomically.
    fn record_if_absent(
        &self,
        envelope: &TextEnvelope,
        now_unix_ms: u64,
    ) -> Result<ReceiveRecord, StoreError>;

    fn get(&self, message_id: MessageId) -> Result<Option<ReceiveRecord>, StoreError>;

    /// Atomically changes the state only when the current phase equals `expected`.
    fn transition(
        &self,
        message_id: MessageId,
        expected: ReceivePhase,
        next: ReceiveState,
        now_unix_ms: u64,
    ) -> Result<TransitionOutcome, StoreError>;
}

/// The sender-side durable source record. Text is intentionally the only
/// payload retained here; file and folder sources remain references to the
/// user's existing objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferSourceRecord {
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub creation_sequence: u64,
    pub announced_to: HashSet<DeviceId>,
    pub source: OfferSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferSourceInput {
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub announced_to: HashSet<DeviceId>,
    pub source: OfferSource,
}

impl OfferSourceInput {
    #[must_use]
    pub fn new(
        offer_id: OfferId,
        descriptor: OfferDescriptor,
        announced_to: HashSet<DeviceId>,
        source: OfferSource,
    ) -> Self {
        Self {
            offer_id,
            descriptor,
            announced_to,
            source,
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        self.descriptor
            .validate()
            .map_err(|error| StoreError::new(error.to_string()))?;
        self.source
            .validate_for(&self.descriptor)
            .map_err(|error| StoreError::new(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferSourceInsert {
    pub record: OfferSourceRecord,
    pub inserted: bool,
    pub purged: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferEligibilityUpdate {
    pub recipient_was_eligible: bool,
    pub offer_deleted: bool,
    pub remaining_recipients: u32,
}

/// The sender-side durable source authority. Implementations must make each
/// mutation durable and atomic; callers never maintain a parallel registry.
pub trait OfferSourceStore: Send + Sync + 'static {
    fn insert_offer_source(&self, input: OfferSourceInput)
    -> Result<OfferSourceInsert, StoreError>;

    fn remove_explicit_refusal(
        &self,
        offer_id: OfferId,
        recipient: DeviceId,
    ) -> Result<OfferEligibilityUpdate, StoreError>;

    fn get_offer_source(&self, offer_id: OfferId) -> Result<Option<OfferSourceRecord>, StoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferCardRecord {
    pub source_device: DeviceId,
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub received_sequence: u64,
    pub availability: CardAvailability,
    pub last_attempt: Option<OfferAttemptStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferCardInput {
    pub source_device: DeviceId,
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub availability: CardAvailability,
}

impl OfferCardInput {
    #[must_use]
    pub fn new(
        source_device: DeviceId,
        offer_id: OfferId,
        descriptor: OfferDescriptor,
        availability: CardAvailability,
    ) -> Self {
        Self {
            source_device,
            offer_id,
            descriptor,
            availability,
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        self.descriptor
            .validate()
            .map_err(|error| StoreError::new(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferCardInsert {
    pub record: OfferCardRecord,
    pub inserted: bool,
    pub purged: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferAttemptCode {
    Completed,
    SourceUnavailable,
    SourceChanged,
    Busy,
    Cancelled,
    ClipboardFailed,
    VerificationFailed,
    UncertainNoReplay,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferAttemptStatus {
    pub code: OfferAttemptCode,
    pub attempt_sequence: u64,
    pub files_processed: u32,
    pub bytes_processed: u64,
    pub detail: Option<String>,
}

impl OfferAttemptStatus {
    pub fn new(
        code: OfferAttemptCode,
        attempt_sequence: u64,
        files_processed: u32,
        bytes_processed: u64,
        detail: Option<String>,
    ) -> Result<Self, StoreError> {
        if detail
            .as_ref()
            .is_some_and(|value| value.len() > MAX_OFFER_ATTEMPT_DETAIL_BYTES)
        {
            return Err(StoreError::new("offer attempt detail is too large"));
        }
        Ok(Self {
            code,
            attempt_sequence,
            files_processed,
            bytes_processed,
            detail,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupReport {
    pub journaled_entries: u32,
    pub removed_entries: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MigrationReport {
    pub v1_body_records_removed: u64,
}
