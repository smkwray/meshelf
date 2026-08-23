use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{MessageId, TextEnvelope};

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
