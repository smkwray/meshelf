use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CardAvailability, DeviceId, MAX_OFFER_ATTEMPT_DETAIL_BYTES, OfferDescriptor, OfferId,
    OfferSource,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("store error: {message}")]
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
    pub partials_directory_removed: bool,
    pub completion_markers_removed: u64,
}
