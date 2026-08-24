use std::{fmt, path::PathBuf, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActivationId(Uuid);

impl ActivationId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ActivationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ActivationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ActivationId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationState {
    Requested,
    Planning,
    Staging,
    Transferring,
    Verified,
    Publishing,
    ApplyingClipboard,
    Completed,
    Failed,
    Cancelled,
    UncertainNoReplay,
}

/// Cleanup ownership only. The journal deliberately has no payload or
/// transfer-resume fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationJournalEntry {
    pub activation_id: ActivationId,
    pub staging_root: PathBuf,
    pub state: ActivationState,
    pub reserved_entries: u32,
    pub reserved_bytes: u64,
}

impl ActivationJournalEntry {
    pub fn validate(&self) -> Result<(), StoreError> {
        if !self.staging_root.is_absolute() {
            return Err(StoreError::new("staging root must be absolute"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardCacheState {
    InFlight,
    Completed,
}

/// An index entry, not a payload. The payload itself is owned by the
/// app-owned path and is bounded to one completed item plus one in-flight item
/// by the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardCacheRecord {
    pub activation_id: ActivationId,
    pub state: ClipboardCacheState,
    pub payload_path: PathBuf,
}

impl ClipboardCacheRecord {
    pub fn validate(&self) -> Result<(), StoreError> {
        if !self.payload_path.is_absolute() {
            return Err(StoreError::new("clipboard cache path must be absolute"));
        }
        Ok(())
    }
}
