use std::{collections::HashSet, path::PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CardAvailability, DeviceId, DocumentLeaseId, MAX_OFFER_ATTEMPT_DETAIL_BYTES, OfferDescriptor,
    OfferId, OfferSource,
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
    /// Durable origin ordinal for shelf catalog.
    ///
    /// Assigned once at insert by the store's `next_source_sequence` counter and never
    /// rewritten. Catalog deltas and receiver frontiers treat this field as the
    /// **origin_ordinal**; do not add a parallel ordinal column.
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
    /// Document leases whose durable refcount reached zero because of this mutation.
    pub releasable_document_leases: Vec<crate::DocumentLeaseId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferEligibilityUpdate {
    pub recipient_was_eligible: bool,
    pub offer_deleted: bool,
    pub remaining_recipients: u32,
    /// Set when `offer_deleted` removed a document source whose refcount reached zero.
    pub releasable_document_lease: Option<crate::DocumentLeaseId>,
}

/// Result of granting ordinary fetch eligibility to one announced recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferAnnouncedRecipientUpdate {
    /// `true` when the recipient was newly inserted into `announced_to`.
    pub newly_granted: bool,
    pub remaining_recipients: u32,
}

/// Receiver-side accepted catalog frontier for one origin.
///
/// A complete catalog snapshot from a different `origin_epoch` replaces the stored
/// frontier entirely (new epoch + ordinal). Same-epoch advances only move
/// `accepted_through_ordinal` forward; regressions are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogFrontier {
    pub origin_epoch: u64,
    pub accepted_through_ordinal: u64,
}

pub trait OfferSourceStore: Send + Sync + 'static {
    fn insert_offer_source(&self, input: OfferSourceInput)
    -> Result<OfferSourceInsert, StoreError>;
    fn remove_explicit_refusal(
        &self,
        offer_id: OfferId,
        recipient: DeviceId,
    ) -> Result<OfferEligibilityUpdate, StoreError>;
    /// Atomically grant ordinary fetch eligibility to `recipient` for an existing source.
    /// Idempotent when the recipient is already present. Errors if the source is missing.
    fn add_announced_recipient(
        &self,
        offer_id: OfferId,
        recipient: DeviceId,
    ) -> Result<OfferAnnouncedRecipientUpdate, StoreError>;
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
    /// Document leases released because an owned ordinary entry was purged from the index.
    pub releasable_document_leases: Vec<DocumentLeaseId>,
    /// Absolute paths of owned File/Folder sources removed with a purged ordinary card.
    /// Callers decide which trees are safe to unlink (e.g. app-private ordinary photos).
    pub purged_owned_file_paths: Vec<PathBuf>,
}

/// Result of admitting one owned ordinary source together with its local shelf card.
///
/// Phone/Android O-014 uses this so own and received entries share one ten-entry index:
/// the card table is the product shelf, and purging an owned card also removes its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedOrdinaryInsert {
    pub source: OfferSourceRecord,
    pub card: OfferCardRecord,
    pub inserted: bool,
    pub purged: u32,
    pub releasable_document_leases: Vec<DocumentLeaseId>,
    pub purged_owned_file_paths: Vec<PathBuf>,
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
    /// Uncertain clipboard rows retired because their card left the shelf (O-028).
    pub retired_entries: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MigrationReport {
    pub v1_body_records_removed: u64,
    pub partials_directory_removed: bool,
    pub completion_markers_removed: u64,
}
