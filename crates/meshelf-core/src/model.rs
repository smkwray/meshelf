use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Six bytes per JSON-escaped control character is the worst-case encoding
/// expansion for a valid UTF-8 text body, plus a bounded request envelope.
pub const MAX_CONTROL_REQUEST_BYTES: usize = MAX_TEXT_BYTES * 6 + 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(Uuid);

impl DeviceId {
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

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for DeviceId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(Uuid);

impl MessageId {
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

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for MessageId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    ClipboardPush,
    ShelfItem,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    #[default]
    Text,
    Path,
    File,
    Folder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEnvelope {
    pub protocol_version: u16,
    pub message_id: MessageId,
    pub source_device: DeviceId,
    pub target_device: DeviceId,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: Option<u64>,
    pub delivery_mode: DeliveryMode,
    #[serde(default)]
    pub content_kind: ContentKind,
    pub text: String,
}

impl TextEnvelope {
    #[must_use]
    pub fn clipboard_push(
        source_device: DeviceId,
        target_device: DeviceId,
        created_at_unix_ms: u64,
        expires_at_unix_ms: Option<u64>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId::new(),
            source_device,
            target_device,
            created_at_unix_ms,
            expires_at_unix_ms,
            delivery_mode: DeliveryMode::ClipboardPush,
            content_kind: ContentKind::Text,
            text: text.into(),
        }
    }

    #[must_use]
    pub fn shelf_item(
        source_device: DeviceId,
        target_device: DeviceId,
        created_at_unix_ms: u64,
        expires_at_unix_ms: Option<u64>,
        content_kind: ContentKind,
        text: impl Into<String>,
    ) -> Self {
        Self::shelf_item_with_id(
            MessageId::new(),
            source_device,
            target_device,
            created_at_unix_ms,
            expires_at_unix_ms,
            content_kind,
            text,
        )
    }

    #[must_use]
    pub fn shelf_item_with_id(
        message_id: MessageId,
        source_device: DeviceId,
        target_device: DeviceId,
        created_at_unix_ms: u64,
        expires_at_unix_ms: Option<u64>,
        content_kind: ContentKind,
        text: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            message_id,
            source_device,
            target_device,
            created_at_unix_ms,
            expires_at_unix_ms,
            delivery_mode: DeliveryMode::ShelfItem,
            content_kind,
            text: text.into(),
        }
    }

    pub fn validate(&self, now_unix_ms: u64) -> Result<(), EnvelopeValidationError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(EnvelopeValidationError::UnsupportedProtocolVersion {
                received: self.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }
        if self.text.is_empty() {
            return Err(EnvelopeValidationError::EmptyText);
        }
        let text_bytes = self.text.len();
        if text_bytes > MAX_TEXT_BYTES {
            return Err(EnvelopeValidationError::TextTooLarge {
                bytes: text_bytes,
                maximum: MAX_TEXT_BYTES,
            });
        }
        if let Some(expires_at) = self.expires_at_unix_ms {
            if expires_at < self.created_at_unix_ms {
                return Err(EnvelopeValidationError::ExpiryBeforeCreation);
            }
            if now_unix_ms > expires_at {
                return Err(EnvelopeValidationError::Expired {
                    expires_at_unix_ms: expires_at,
                    now_unix_ms,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnvelopeValidationError {
    #[error("unsupported protocol version {received}; supported version is {supported}")]
    UnsupportedProtocolVersion { received: u16, supported: u16 },
    #[error("text is empty")]
    EmptyText,
    #[error("text is {bytes} bytes; maximum is {maximum}")]
    TextTooLarge { bytes: usize, maximum: usize },
    #[error("expiration precedes creation")]
    ExpiryBeforeCreation,
    #[error("message expired at {expires_at_unix_ms}; now is {now_unix_ms}")]
    Expired {
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptCode {
    Stored,
    Applied,
    DuplicateApplied,
    ClipboardFailed,
    RejectedInvalid,
    RejectedWrongTarget,
    RejectedUnsupportedMode,
    RejectedMessageIdConflict,
    RejectedUnauthorized,
    UncertainNoReplay,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub protocol_version: u16,
    pub message_id: MessageId,
    pub code: ReceiptCode,
    pub detail: Option<String>,
}

impl Receipt {
    #[must_use]
    pub fn new(message_id: MessageId, code: ReceiptCode, detail: Option<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            message_id,
            code,
            detail,
        }
    }

    #[must_use]
    pub fn applied(message_id: MessageId) -> Self {
        Self::new(message_id, ReceiptCode::Applied, None)
    }

    #[must_use]
    pub fn duplicate_applied(message_id: MessageId) -> Self {
        Self::new(message_id, ReceiptCode::DuplicateApplied, None)
    }

    #[must_use]
    pub fn rejected(message_id: MessageId, code: ReceiptCode, detail: impl Into<String>) -> Self {
        Self::new(message_id, code, Some(detail.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unicode_and_newlines() {
        let source = DeviceId::new();
        let target = DeviceId::new();
        let envelope =
            TextEnvelope::clipboard_push(source, target, 1_000, Some(2_000), "alpha\nβeta\n🙂");
        assert_eq!(envelope.text, "alpha\nβeta\n🙂");
        assert_eq!(envelope.validate(1_500), Ok(()));
    }

    #[test]
    fn rejects_oversized_text_by_utf8_byte_count() {
        let source = DeviceId::new();
        let target = DeviceId::new();
        let text = "é".repeat(MAX_TEXT_BYTES / 2 + 1);
        let envelope = TextEnvelope::clipboard_push(source, target, 1, None, text);
        assert!(matches!(
            envelope.validate(1),
            Err(EnvelopeValidationError::TextTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_expired_message() {
        let envelope =
            TextEnvelope::clipboard_push(DeviceId::new(), DeviceId::new(), 100, Some(200), "text");
        assert!(matches!(
            envelope.validate(201),
            Err(EnvelopeValidationError::Expired { .. })
        ));
    }
}
