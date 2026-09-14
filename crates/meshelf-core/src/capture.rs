//! Durable domain types for agent-requested, user-mediated capture.
//!
//! Capture control messages never carry media bytes. A completed photo is correlated to a normal
//! protocol-2 file offer and is transferred only by the existing receiver-initiated pull lane.
//! Capture rows live in their own bounded records on each side and never occupy the ten-entry
//! offer shelf.

use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{ActivationId, DeviceId, OfferDescriptor, OfferId, StoreError};

pub const MAX_CAPTURE_PURPOSE_BYTES: usize = 160;
/// Matches `RequestText.MAX_REQUESTER_UTF8_BYTES` in the Android client.
pub const MAX_CAPTURE_LABEL_BYTES: usize = 128;
pub const MAX_CAPTURE_DETAIL_BYTES: usize = 512;
pub const MAX_CAPTURE_LIFETIME_MS: u64 = 3 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CaptureRequestId(Uuid);

impl CaptureRequestId {
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

impl Default for CaptureRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CaptureRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for CaptureRequestId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureKind {
    Photo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLens {
    Front,
    Rear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureCorrelation {
    pub request_id: CaptureRequestId,
}

/// Why a capture text field was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CaptureTextError {
    #[error("text is empty")]
    Empty,
    #[error("text is {bytes} UTF-8 bytes; maximum is {maximum}")]
    TooLong { bytes: usize, maximum: usize },
    #[error("text contains control character U+{code_point:04X}")]
    Control { code_point: u32 },
    #[error("text contains format character U+{code_point:04X}")]
    Format { code_point: u32 },
}

/// The one purpose validator for protocol, store, and CLI.
///
/// The purpose is shown to the person holding the phone as the reason for a photograph, so it
/// must read exactly as it is: non-empty, at most [`MAX_CAPTURE_PURPOSE_BYTES`] UTF-8 bytes, and
/// free of control (Cc) and format (Cf) characters. Format characters include the bidirectional
/// overrides and zero-width characters that make displayed text differ from its content.
pub fn validate_capture_purpose(purpose: &str) -> Result<(), CaptureTextError> {
    validate_plain_text(purpose, MAX_CAPTURE_PURPOSE_BYTES)
}

/// Validates a device label shown with a capture (the requester name on the phone, the peer name
/// on the requester) under the same plain-text rule as the purpose.
pub fn validate_capture_label(label: &str) -> Result<(), CaptureTextError> {
    validate_plain_text(label, MAX_CAPTURE_LABEL_BYTES)
}

fn validate_plain_text(value: &str, maximum_bytes: usize) -> Result<(), CaptureTextError> {
    if value.is_empty() {
        return Err(CaptureTextError::Empty);
    }
    if value.len() > maximum_bytes {
        return Err(CaptureTextError::TooLong {
            bytes: value.len(),
            maximum: maximum_bytes,
        });
    }
    for character in value.chars() {
        let code_point = u32::from(character);
        if character.is_control() {
            return Err(CaptureTextError::Control { code_point });
        }
        if is_format_character(character) {
            return Err(CaptureTextError::Format { code_point });
        }
    }
    Ok(())
}

/// Unicode General_Category=Cf (Format), transcribed from `DerivedGeneralCategory.txt` of
/// Unicode 16.0.0: 170 code points in 21 ranges. The standard library tests Cc
/// (`char::is_control`) but has no Cf test. Regenerate this table if a later Unicode version
/// assigns new Cf code points.
///
/// The Android client (`RequestText.requirePlainText`) rejects `Character.isISOControl`, which is
/// exactly Cc, and `Character.getType == FORMAT`, evaluated per UTF-16 unit. That per-unit check
/// never sees a supplementary-plane Cf character, because each half of its surrogate pair reports
/// SURROGATE, so the last seven ranges are refused here but not by the phone. Rust is the wire
/// authority, and refusing a superset keeps the property that matters: the phone never refuses
/// a purpose Rust accepted, provided its Unicode data assigns no Cf code point that 16.0.0 lacks.
const FORMAT_RANGES: [(u32, u32); 21] = [
    (0x00AD, 0x00AD),   // SOFT HYPHEN
    (0x0600, 0x0605),   // ARABIC NUMBER SIGN..ARABIC NUMBER MARK ABOVE
    (0x061C, 0x061C),   // ARABIC LETTER MARK
    (0x06DD, 0x06DD),   // ARABIC END OF AYAH
    (0x070F, 0x070F),   // SYRIAC ABBREVIATION MARK
    (0x0890, 0x0891),   // ARABIC POUND MARK ABOVE..ARABIC PIASTRE MARK ABOVE
    (0x08E2, 0x08E2),   // ARABIC DISPUTED END OF AYAH
    (0x180E, 0x180E),   // MONGOLIAN VOWEL SEPARATOR
    (0x200B, 0x200F),   // ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),   // LEFT-TO-RIGHT EMBEDDING..RIGHT-TO-LEFT OVERRIDE
    (0x2060, 0x2064),   // WORD JOINER..INVISIBLE PLUS
    (0x2066, 0x206F),   // LEFT-TO-RIGHT ISOLATE..NOMINAL DIGIT SHAPES
    (0xFEFF, 0xFEFF),   // ZERO WIDTH NO-BREAK SPACE
    (0xFFF9, 0xFFFB),   // INTERLINEAR ANNOTATION ANCHOR..INTERLINEAR ANNOTATION TERMINATOR
    (0x110BD, 0x110BD), // KAITHI NUMBER SIGN
    (0x110CD, 0x110CD), // KAITHI NUMBER SIGN ABOVE
    (0x13430, 0x1343F), // EGYPTIAN HIEROGLYPH VERTICAL JOINER..END WALLED ENCLOSURE
    (0x1BCA0, 0x1BCA3), // SHORTHAND FORMAT LETTER OVERLAP..SHORTHAND FORMAT UP STEP
    (0x1D173, 0x1D17A), // MUSICAL SYMBOL BEGIN BEAM..MUSICAL SYMBOL END PHRASE
    (0xE0001, 0xE0001), // LANGUAGE TAG
    (0xE0020, 0xE007F), // TAG SPACE..CANCEL TAG
];

fn is_format_character(character: char) -> bool {
    let code_point = u32::from(character);
    FORMAT_RANGES
        .iter()
        .any(|&(first, last)| (first..=last).contains(&code_point))
}

/// Validates a capture's lifetime: expiry strictly after creation and within
/// [`MAX_CAPTURE_LIFETIME_MS`] of it.
pub fn validate_capture_lifetime(
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<(), StoreError> {
    if expires_at_unix_ms <= created_at_unix_ms {
        return Err(StoreError::new(
            "capture expiry must be after creation time",
        ));
    }
    if expires_at_unix_ms - created_at_unix_ms > MAX_CAPTURE_LIFETIME_MS {
        return Err(StoreError::new(
            "capture expiry exceeds the three-minute lifetime",
        ));
    }
    Ok(())
}

pub fn validate_capture_detail(detail: &Option<String>) -> Result<(), StoreError> {
    if detail
        .as_ref()
        .is_some_and(|value| value.len() > MAX_CAPTURE_DETAIL_BYTES)
    {
        return Err(StoreError::new("capture detail is too large"));
    }
    Ok(())
}

fn text_error(field: &str, error: CaptureTextError) -> StoreError {
    StoreError::new(format!("capture {field} is invalid: {error}"))
}

fn validate_absolute_file_path(path: &Path, field: &str) -> Result<(), StoreError> {
    if path.is_absolute() && path.file_name().is_some() {
        Ok(())
    } else {
        Err(StoreError::new(format!(
            "capture {field} must be an absolute path naming a file"
        )))
    }
}

/// A capture result is exactly one non-empty file offer.
fn validate_photo_descriptor(descriptor: &OfferDescriptor) -> Result<(), StoreError> {
    descriptor.validate().map_err(|error| {
        StoreError::new(format!("capture photo descriptor is invalid: {error}"))
    })?;
    match descriptor {
        OfferDescriptor::File { total_bytes, .. } if *total_bytes > 0 => Ok(()),
        OfferDescriptor::File { .. } => Err(StoreError::new("capture photo must not be empty")),
        OfferDescriptor::Text { .. } | OfferDescriptor::Folder { .. } => {
            Err(StoreError::new("capture photo must be a single file offer"))
        }
    }
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), StoreError> {
    if width == 0 || height == 0 {
        return Err(StoreError::new(
            "capture photo width and height must be positive",
        ));
    }
    Ok(())
}

/// How a finished capture is reported: the JSON `type`, its `reason`, and the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureOutcome {
    pub json_type: &'static str,
    pub reason: &'static str,
    pub exit_code: u8,
}

impl CaptureOutcome {
    pub const COMPLETED: Self = Self {
        json_type: "capture_completed",
        reason: "completed",
        exit_code: 0,
    };
}

const CAPTURE_NOT_STARTED: &str = "capture_not_started";
const CAPTURE_FAILED: &str = "capture_failed";
const CAPTURE_UNCERTAIN: &str = "capture_uncertain";

/// Why a requester-side capture ended without a published photograph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureTerminalCode {
    /// The person holding the phone declined.
    Declined,
    Expired,
    /// The phone was already presenting another request.
    Busy,
    /// Both activation permits on the requester were in use, so the automatic pull was refused
    /// rather than queued.
    RequesterBusy,
    Unsupported,
    Refused,
    PeerOffline,
    RemoteFailed,
    Cancelled,
    TransferFailed,
    VerificationFailed,
    /// Another process created the exact output after preflight; nothing was renamed.
    OutputExists,
    PublicationFailed,
    InsufficientSpace,
    ResidentRestarted,
    ResidentDisconnected,
    UncertainNoReplay,
}

impl CaptureTerminalCode {
    /// The reported reason, identical to the serde wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Busy => "busy",
            Self::RequesterBusy => "requester_busy",
            Self::Unsupported => "unsupported",
            Self::Refused => "refused",
            Self::PeerOffline => "peer_offline",
            Self::RemoteFailed => "remote_failed",
            Self::Cancelled => "cancelled",
            Self::TransferFailed => "transfer_failed",
            Self::VerificationFailed => "verification_failed",
            Self::OutputExists => "output_exists",
            Self::PublicationFailed => "publication_failed",
            Self::InsufficientSpace => "insufficient_space",
            Self::ResidentRestarted => "resident_restarted",
            Self::ResidentDisconnected => "resident_disconnected",
            Self::UncertainNoReplay => "uncertain_no_replay",
        }
    }

    /// The exit-code table: 3 for a remote or refused result, 4 for a local transfer,
    /// verification, or publication failure, 5 when the outcome is uncertain.
    #[must_use]
    pub const fn outcome(self) -> CaptureOutcome {
        let (json_type, exit_code) = match self {
            Self::Declined
            | Self::Expired
            | Self::Busy
            | Self::RequesterBusy
            | Self::Cancelled
            | Self::Unsupported
            | Self::Refused
            | Self::PeerOffline
            | Self::RemoteFailed => (CAPTURE_FAILED, 3),
            Self::TransferFailed
            | Self::VerificationFailed
            | Self::OutputExists
            | Self::PublicationFailed
            | Self::InsufficientSpace => (CAPTURE_FAILED, 4),
            Self::ResidentRestarted | Self::ResidentDisconnected | Self::UncertainNoReplay => {
                (CAPTURE_UNCERTAIN, 5)
            }
        };
        CaptureOutcome {
            json_type,
            reason: self.as_str(),
            exit_code,
        }
    }
}

/// Why a capture was refused by preflight before any request record existed (exit 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureNotStarted {
    OutputExists,
    OutputIsDirectory,
    OutputParentMissing,
    OutputParentNotDirectory,
    OutputParentIsLink,
    OutputNameInvalid,
    InvalidArguments,
    PeerNotPaired,
    ResidentUnavailable,
    Capacity,
}

impl CaptureNotStarted {
    /// The reported reason, identical to the serde wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutputExists => "output_exists",
            Self::OutputIsDirectory => "output_is_directory",
            Self::OutputParentMissing => "output_parent_missing",
            Self::OutputParentNotDirectory => "output_parent_not_directory",
            Self::OutputParentIsLink => "output_parent_is_link",
            Self::OutputNameInvalid => "output_name_invalid",
            Self::InvalidArguments => "invalid_arguments",
            Self::PeerNotPaired => "peer_not_paired",
            Self::ResidentUnavailable => "resident_unavailable",
            Self::Capacity => "capacity",
        }
    }

    #[must_use]
    pub const fn outcome(self) -> CaptureOutcome {
        CaptureOutcome {
            json_type: CAPTURE_NOT_STARTED,
            reason: self.as_str(),
            exit_code: 2,
        }
    }
}

/// Authority for one automatic pull, created only by an explicit local capture start and scoped
/// to one request. Correlation alone never authorizes a pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePullGrant {
    pub expected_source: DeviceId,
    pub kind: CaptureKind,
    /// The one file the photograph is published to; never renamed or rewritten.
    pub exact_output_path: PathBuf,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureReceipt {
    pub output_path: PathBuf,
    #[serde(with = "sha256_hex")]
    pub sha256: [u8; 32],
    pub bytes: u64,
    pub width: u32,
    pub height: u32,
}

impl CaptureReceipt {
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_absolute_file_path(&self.output_path, "receipt output path")?;
        if self.bytes == 0 {
            return Err(StoreError::new(
                "capture receipt must record a non-empty photo",
            ));
        }
        validate_dimensions(self.width, self.height)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureRequestPhase {
    AwaitingPresentation,
    Armed {
        presented_at_unix_ms: u64,
    },
    Claimed {
        offer_id: OfferId,
        activation_id: ActivationId,
        descriptor: OfferDescriptor,
    },
    Completed {
        receipt: CaptureReceipt,
    },
    Terminal {
        code: CaptureTerminalCode,
        detail: Option<String>,
    },
}

/// The requester's durable record of one capture request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRequestRecord {
    pub request_id: CaptureRequestId,
    pub peer: DeviceId,
    pub peer_label: String,
    pub purpose: String,
    pub lens: Option<CaptureLens>,
    pub created_at_unix_ms: u64,
    pub grant: CapturePullGrant,
    pub phase: CaptureRequestPhase,
    pub terminal_reported: bool,
}

impl CaptureRequestRecord {
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_capture_purpose(&self.purpose).map_err(|error| text_error("purpose", error))?;
        validate_capture_label(&self.peer_label)
            .map_err(|error| text_error("peer label", error))?;
        validate_capture_lifetime(self.created_at_unix_ms, self.grant.expires_at_unix_ms)?;
        if self.grant.expected_source != self.peer {
            return Err(StoreError::new(
                "capture pull grant must expect the requested peer as its source",
            ));
        }
        validate_absolute_file_path(&self.grant.exact_output_path, "output path")?;
        match &self.phase {
            CaptureRequestPhase::AwaitingPresentation | CaptureRequestPhase::Armed { .. } => {}
            CaptureRequestPhase::Claimed { descriptor, .. } => {
                validate_photo_descriptor(descriptor)?;
            }
            CaptureRequestPhase::Completed { receipt } => {
                receipt.validate()?;
                if receipt.output_path != self.grant.exact_output_path {
                    return Err(StoreError::new(
                        "capture receipt must name the grant's exact output path",
                    ));
                }
            }
            CaptureRequestPhase::Terminal { detail, .. } => validate_capture_detail(detail)?,
        }
        if self.terminal_reported && self.outcome().is_none() {
            return Err(StoreError::new(
                "a live capture request cannot already be reported",
            ));
        }
        Ok(())
    }

    /// The single authority for how a finished request is reported; `None` while it is live.
    #[must_use]
    pub fn outcome(&self) -> Option<CaptureOutcome> {
        match &self.phase {
            CaptureRequestPhase::AwaitingPresentation
            | CaptureRequestPhase::Armed { .. }
            | CaptureRequestPhase::Claimed { .. } => None,
            CaptureRequestPhase::Completed { .. } => Some(CaptureOutcome::COMPLETED),
            CaptureRequestPhase::Terminal { code, .. } => Some(code.outcome()),
        }
    }
}

/// The photograph the phone holds for one request, shared by every phase that still has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedPhoto {
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub path: PathBuf,
    #[serde(with = "sha256_hex")]
    pub sha256: [u8; 32],
    pub width: u32,
    pub height: u32,
    pub delete_deadline_unix_ms: u64,
}

impl CapturedPhoto {
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_photo_descriptor(&self.descriptor)?;
        validate_absolute_file_path(&self.path, "photo path")?;
        validate_dimensions(self.width, self.height)?;
        if self.delete_deadline_unix_ms == 0 {
            return Err(StoreError::new("capture photo delete deadline must be set"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSourceTerminalCode {
    Declined,
    Expired,
    Cancelled,
    Failed,
    /// The receipt never arrived, so the photo was deleted at its deadline without a recorded
    /// delivery.
    ExpiredUnconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSourcePhase {
    Presented,
    Captured {
        photo: CapturedPhoto,
    },
    Announced {
        photo: CapturedPhoto,
    },
    /// A fetch began; the photo is never served again. `activation_id` is the requester's fetch
    /// request id.
    Claimed {
        photo: CapturedPhoto,
        activation_id: ActivationId,
    },
    /// Tombstone after a verified receipt; it keeps no path, so nothing can serve the photo again.
    Delivered,
    /// The receipt was lost after serving; never re-served or re-announced. `path` is retained only
    /// so the phone can delete the bytes at `deadline_unix_ms`; fetch must refuse this phase.
    UncertainNoReplay {
        deadline_unix_ms: u64,
        path: PathBuf,
    },
    Terminal {
        code: CaptureSourceTerminalCode,
    },
}

/// The phone's durable record of one capture request it received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSourceRecord {
    pub request_id: CaptureRequestId,
    pub requester: DeviceId,
    pub requester_label: String,
    pub purpose: String,
    pub lens: Option<CaptureLens>,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub phase: CaptureSourcePhase,
}

impl CaptureSourceRecord {
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_capture_purpose(&self.purpose).map_err(|error| text_error("purpose", error))?;
        validate_capture_label(&self.requester_label)
            .map_err(|error| text_error("requester label", error))?;
        validate_capture_lifetime(self.created_at_unix_ms, self.expires_at_unix_ms)?;
        match &self.phase {
            CaptureSourcePhase::Presented
            | CaptureSourcePhase::Delivered
            | CaptureSourcePhase::Terminal { .. } => Ok(()),
            CaptureSourcePhase::Captured { photo }
            | CaptureSourcePhase::Announced { photo }
            | CaptureSourcePhase::Claimed { photo, .. } => photo.validate(),
            CaptureSourcePhase::UncertainNoReplay {
                deadline_unix_ms,
                path,
            } => {
                if *deadline_unix_ms == 0 {
                    return Err(StoreError::new(
                        "uncertain capture source must record its delete deadline",
                    ));
                }
                validate_absolute_file_path(path, "uncertain photo path")
            }
        }
    }
}

mod sha256_hex {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            value.push(HEX[usize::from(byte >> 4)] as char);
            value.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        serializer.serialize_str(&value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64 {
            return Err(D::Error::custom(
                "SHA-256 must be a 64-character hexadecimal string",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let high = hex_digit(pair[0]).ok_or_else(|| D::Error::custom("invalid SHA-256"))?;
            let low = hex_digit(pair[1]).ok_or_else(|| D::Error::custom("invalid SHA-256"))?;
            *slot = (high << 4) | low;
        }
        Ok(bytes)
    }

    fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATED: u64 = 1_000;
    const EXPIRES: u64 = CREATED + MAX_CAPTURE_LIFETIME_MS;

    fn output_path() -> PathBuf {
        std::env::temp_dir().join("router-label.jpg")
    }

    fn photo_descriptor() -> OfferDescriptor {
        OfferDescriptor::File {
            root_name: "router-label.jpg".to_owned(),
            total_bytes: 48_213,
            content_class: crate::FileContentClass::File,
        }
    }

    fn receipt() -> CaptureReceipt {
        CaptureReceipt {
            output_path: output_path(),
            sha256: [0xab; 32],
            bytes: 48_213,
            width: 4032,
            height: 3024,
        }
    }

    fn requester_record(phase: CaptureRequestPhase) -> CaptureRequestRecord {
        let peer = DeviceId::new();
        CaptureRequestRecord {
            request_id: CaptureRequestId::new(),
            peer,
            peer_label: "amber".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: Some(CaptureLens::Rear),
            created_at_unix_ms: CREATED,
            grant: CapturePullGrant {
                expected_source: peer,
                kind: CaptureKind::Photo,
                exact_output_path: output_path(),
                expires_at_unix_ms: EXPIRES,
            },
            phase,
            terminal_reported: false,
        }
    }

    fn requester_phases() -> Vec<CaptureRequestPhase> {
        vec![
            CaptureRequestPhase::AwaitingPresentation,
            CaptureRequestPhase::Armed {
                presented_at_unix_ms: CREATED + 10,
            },
            CaptureRequestPhase::Claimed {
                offer_id: OfferId::new(),
                activation_id: ActivationId::new(),
                descriptor: photo_descriptor(),
            },
            CaptureRequestPhase::Completed { receipt: receipt() },
            CaptureRequestPhase::Terminal {
                code: CaptureTerminalCode::Declined,
                detail: Some("user-declined".to_owned()),
            },
        ]
    }

    fn photo() -> CapturedPhoto {
        CapturedPhoto {
            offer_id: OfferId::new(),
            descriptor: photo_descriptor(),
            path: std::env::temp_dir()
                .join("agent-captures")
                .join("router-label.jpg"),
            sha256: [0x5c; 32],
            width: 4032,
            height: 3024,
            delete_deadline_unix_ms: CREATED + 600_000,
        }
    }

    fn source_record(phase: CaptureSourcePhase) -> CaptureSourceRecord {
        CaptureSourceRecord {
            request_id: CaptureRequestId::new(),
            requester: DeviceId::new(),
            requester_label: "CEDAR".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: None,
            created_at_unix_ms: CREATED,
            expires_at_unix_ms: EXPIRES,
            phase,
        }
    }

    fn source_phases() -> Vec<CaptureSourcePhase> {
        vec![
            CaptureSourcePhase::Presented,
            CaptureSourcePhase::Captured { photo: photo() },
            CaptureSourcePhase::Announced { photo: photo() },
            CaptureSourcePhase::Claimed {
                photo: photo(),
                activation_id: ActivationId::new(),
            },
            CaptureSourcePhase::Delivered,
            CaptureSourcePhase::UncertainNoReplay {
                deadline_unix_ms: CREATED + 600_000,
                path: photo().path,
            },
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::ExpiredUnconfirmed,
            },
        ]
    }

    // Every terminal code. The exhaustive match in `documented` refuses to compile when a code is
    // added without a row, and this list must name each code once.
    const ALL_TERMINAL_CODES: [CaptureTerminalCode; 17] = [
        CaptureTerminalCode::Declined,
        CaptureTerminalCode::Expired,
        CaptureTerminalCode::Busy,
        CaptureTerminalCode::RequesterBusy,
        CaptureTerminalCode::Unsupported,
        CaptureTerminalCode::Refused,
        CaptureTerminalCode::PeerOffline,
        CaptureTerminalCode::RemoteFailed,
        CaptureTerminalCode::Cancelled,
        CaptureTerminalCode::TransferFailed,
        CaptureTerminalCode::VerificationFailed,
        CaptureTerminalCode::OutputExists,
        CaptureTerminalCode::PublicationFailed,
        CaptureTerminalCode::InsufficientSpace,
        CaptureTerminalCode::ResidentRestarted,
        CaptureTerminalCode::ResidentDisconnected,
        CaptureTerminalCode::UncertainNoReplay,
    ];

    /// The documented exit-code table, written independently of the implementation so that a
    /// drifted mapping fails here rather than in an agent's shell script.
    fn documented(code: CaptureTerminalCode) -> (&'static str, &'static str, u8) {
        use CaptureTerminalCode as C;
        match code {
            C::Declined => ("capture_failed", "declined", 3),
            C::Expired => ("capture_failed", "expired", 3),
            C::Busy => ("capture_failed", "busy", 3),
            C::RequesterBusy => ("capture_failed", "requester_busy", 3),
            C::Cancelled => ("capture_failed", "cancelled", 3),
            C::Unsupported => ("capture_failed", "unsupported", 3),
            C::Refused => ("capture_failed", "refused", 3),
            C::PeerOffline => ("capture_failed", "peer_offline", 3),
            C::RemoteFailed => ("capture_failed", "remote_failed", 3),
            C::TransferFailed => ("capture_failed", "transfer_failed", 4),
            C::VerificationFailed => ("capture_failed", "verification_failed", 4),
            C::OutputExists => ("capture_failed", "output_exists", 4),
            C::PublicationFailed => ("capture_failed", "publication_failed", 4),
            C::InsufficientSpace => ("capture_failed", "insufficient_space", 4),
            C::ResidentRestarted => ("capture_uncertain", "resident_restarted", 5),
            C::ResidentDisconnected => ("capture_uncertain", "resident_disconnected", 5),
            C::UncertainNoReplay => ("capture_uncertain", "uncertain_no_replay", 5),
        }
    }

    #[test]
    fn every_finished_request_maps_to_its_documented_json_type_reason_and_exit_code() {
        for code in ALL_TERMINAL_CODES {
            let record = requester_record(CaptureRequestPhase::Terminal { code, detail: None });
            let outcome = record.outcome().expect("a terminal request has an outcome");
            assert_eq!(
                (outcome.json_type, outcome.reason, outcome.exit_code),
                documented(code),
                "{code:?}"
            );
            // The reason an agent reads and the stored wire name are one string.
            assert_eq!(
                serde_json::to_value(code).expect("encode code"),
                serde_json::Value::String(outcome.reason.to_owned())
            );
        }
        let completed = requester_record(CaptureRequestPhase::Completed { receipt: receipt() });
        assert_eq!(
            completed.outcome(),
            Some(CaptureOutcome {
                json_type: "capture_completed",
                reason: "completed",
                exit_code: 0,
            })
        );
    }

    #[test]
    fn a_live_request_has_no_outcome_so_a_waiter_cannot_report_it_finished() {
        for phase in requester_phases().into_iter().take(3) {
            assert_eq!(requester_record(phase.clone()).outcome(), None, "{phase:?}");
        }
    }

    #[test]
    fn every_preflight_refusal_exits_two_as_capture_not_started() {
        use CaptureNotStarted as N;
        let documented = [
            (N::OutputExists, "output_exists"),
            (N::OutputIsDirectory, "output_is_directory"),
            (N::OutputParentMissing, "output_parent_missing"),
            (N::OutputParentNotDirectory, "output_parent_not_directory"),
            (N::OutputParentIsLink, "output_parent_is_link"),
            (N::OutputNameInvalid, "output_name_invalid"),
            (N::InvalidArguments, "invalid_arguments"),
            (N::PeerNotPaired, "peer_not_paired"),
            (N::ResidentUnavailable, "resident_unavailable"),
            (N::Capacity, "capacity"),
        ];
        for (reason, name) in documented {
            // Exhaustive: a new preflight reason does not compile until it is listed above.
            match reason {
                N::OutputExists
                | N::OutputIsDirectory
                | N::OutputParentMissing
                | N::OutputParentNotDirectory
                | N::OutputParentIsLink
                | N::OutputNameInvalid
                | N::InvalidArguments
                | N::PeerNotPaired
                | N::ResidentUnavailable
                | N::Capacity => {}
            }
            assert_eq!(
                reason.outcome(),
                CaptureOutcome {
                    json_type: "capture_not_started",
                    reason: name,
                    exit_code: 2,
                }
            );
            assert_eq!(
                serde_json::to_value(reason).expect("encode reason"),
                serde_json::Value::String(name.to_owned())
            );
        }
    }

    #[test]
    fn purpose_accepts_plain_text_up_to_160_utf8_bytes_including_multibyte() {
        assert_eq!(
            validate_capture_purpose("Photograph the router label"),
            Ok(())
        );
        assert_eq!(validate_capture_purpose(&"a".repeat(160)), Ok(()));
        assert_eq!(validate_capture_purpose(&"é".repeat(80)), Ok(()));
        assert_eq!(validate_capture_purpose(&"📷".repeat(40)), Ok(()));
        assert_eq!(
            validate_capture_purpose("Étiquette du routeur, côté gauche"),
            Ok(())
        );
    }

    #[test]
    fn purpose_rejects_empty_and_161_bytes() {
        assert_eq!(validate_capture_purpose(""), Err(CaptureTextError::Empty));
        assert_eq!(
            validate_capture_purpose(&"a".repeat(161)),
            Err(CaptureTextError::TooLong {
                bytes: 161,
                maximum: 160
            })
        );
        assert_eq!(
            validate_capture_purpose(&format!("{}a", "é".repeat(80))),
            Err(CaptureTextError::TooLong {
                bytes: 161,
                maximum: 160
            })
        );
    }

    #[test]
    fn purpose_rejects_a_newline_control_character() {
        assert_eq!(
            validate_capture_purpose("line\nbreak"),
            Err(CaptureTextError::Control { code_point: 0x0A })
        );
        assert_eq!(
            validate_capture_purpose("C1 \u{85} next line"),
            Err(CaptureTextError::Control { code_point: 0x85 })
        );
    }

    #[test]
    fn purpose_with_right_to_left_override_is_refused_so_it_cannot_read_differently_than_it_is() {
        // Rendered, this reads "Photograph the router label"; its content asks for something
        // else. The phone shows the purpose as the reason to take a photograph.
        let spoofed = "Photograph the \u{202E}lebal retuor";
        assert_eq!(
            validate_capture_purpose(spoofed),
            Err(CaptureTextError::Format { code_point: 0x202E })
        );
    }

    #[test]
    fn purpose_rejects_invisible_zero_width_space_and_byte_order_mark() {
        assert_eq!(
            validate_capture_purpose("router\u{200B}label"),
            Err(CaptureTextError::Format { code_point: 0x200B })
        );
        assert_eq!(
            validate_capture_purpose("\u{FEFF}router label"),
            Err(CaptureTextError::Format { code_point: 0xFEFF })
        );
    }

    #[test]
    fn purpose_rejects_supplementary_plane_tag_characters_that_hide_text() {
        // Tag characters render as nothing and can smuggle a hidden instruction. The phone's
        // per-UTF-16-unit check misses them; the authoritative Rust check must not.
        assert_eq!(
            validate_capture_purpose("router label\u{E0041}\u{E0042}"),
            Err(CaptureTextError::Format {
                code_point: 0xE0041
            })
        );
    }

    #[test]
    fn neighbors_of_format_ranges_are_ordinary_text_the_phone_accepts() {
        // Overbroad ranges would refuse text the phone would show. U+00AC NOT SIGN, U+200A HAIR
        // SPACE, U+2010 HYPHEN, and U+FFFC OBJECT REPLACEMENT CHARACTER sit beside Cf ranges.
        for text in ["a\u{AC}b", "a\u{200A}b", "a\u{2010}b", "a\u{FFFC}b"] {
            assert_eq!(validate_capture_purpose(text), Ok(()), "{text:?}");
        }
    }

    #[test]
    fn format_table_holds_the_whole_unicode_16_cf_population_in_order() {
        let mut total = 0_u32;
        let mut previous_end = None;
        for (first, last) in FORMAT_RANGES {
            assert!(first <= last);
            if let Some(end) = previous_end {
                assert!(first > end + 1, "ranges must be sorted and not adjacent");
            }
            previous_end = Some(last);
            total += last - first + 1;
        }
        assert_eq!(total, 170, "Unicode 16.0.0 assigns 170 Cf code points");
    }

    #[test]
    fn labels_follow_the_phones_128_byte_plain_text_rule() {
        assert_eq!(validate_capture_label(&"b".repeat(128)), Ok(()));
        assert!(validate_capture_label(&"b".repeat(129)).is_err());
        assert!(validate_capture_label("CEDAR\u{202E}").is_err());
        assert_eq!(validate_capture_label(""), Err(CaptureTextError::Empty));
    }

    #[test]
    fn lifetime_must_be_positive_and_at_most_three_minutes() {
        assert!(validate_capture_lifetime(CREATED, EXPIRES).is_ok());
        assert!(validate_capture_lifetime(CREATED, CREATED).is_err());
        assert!(validate_capture_lifetime(CREATED, CREATED - 1).is_err());
        assert!(validate_capture_lifetime(CREATED, EXPIRES + 1).is_err());
    }

    #[test]
    fn every_requester_phase_validates_and_round_trips() {
        for phase in requester_phases() {
            let record = requester_record(phase);
            assert_eq!(record.validate(), Ok(()), "{:?}", record.phase);
            let json = serde_json::to_string(&record).expect("encode record");
            let decoded: CaptureRequestRecord = serde_json::from_str(&json).expect("decode record");
            assert_eq!(decoded, record);
        }
        let mut reported = requester_record(CaptureRequestPhase::Completed { receipt: receipt() });
        reported.terminal_reported = true;
        assert_eq!(reported.validate(), Ok(()));
    }

    #[test]
    fn receipt_sha256_is_lowercase_hex_on_the_wire_and_exactly_32_bytes() {
        let json = serde_json::to_value(receipt()).expect("encode receipt");
        assert_eq!(json["sha256"], serde_json::Value::String("ab".repeat(32)));
        for wrong in [
            "ab".repeat(31),
            "ab".repeat(33),
            format!("{}zz", "ab".repeat(31)),
        ] {
            let mut altered = json.clone();
            altered["sha256"] = serde_json::Value::String(wrong.clone());
            assert!(
                serde_json::from_value::<CaptureReceipt>(altered).is_err(),
                "{wrong}"
            );
        }
    }

    #[test]
    fn requester_record_rejects_impossible_shapes() {
        let mut relative = requester_record(CaptureRequestPhase::AwaitingPresentation);
        relative.grant.exact_output_path = PathBuf::from("router-label.jpg");
        assert!(relative.validate().is_err(), "output path must be absolute");

        let mut no_name = requester_record(CaptureRequestPhase::AwaitingPresentation);
        no_name.grant.exact_output_path = std::env::temp_dir().join("..");
        assert!(no_name.validate().is_err(), "output path must name a file");

        let mut other_source = requester_record(CaptureRequestPhase::AwaitingPresentation);
        other_source.grant.expected_source = DeviceId::new();
        assert!(
            other_source.validate().is_err(),
            "a grant must not authorize a pull from a device other than the requested peer"
        );

        let mut spoofed = requester_record(CaptureRequestPhase::AwaitingPresentation);
        spoofed.purpose = "Photograph the \u{202E}lebal retuor".to_owned();
        assert!(spoofed.validate().is_err());

        let mut too_long = requester_record(CaptureRequestPhase::AwaitingPresentation);
        too_long.grant.expires_at_unix_ms = EXPIRES + 1;
        assert!(too_long.validate().is_err());

        let folder = requester_record(CaptureRequestPhase::Claimed {
            offer_id: OfferId::new(),
            activation_id: ActivationId::new(),
            descriptor: OfferDescriptor::Folder {
                root_name: "photos".to_owned(),
                total_bytes: 10,
                entry_count: 1,
                file_count: 1,
                directory_count: 0,
            },
        });
        assert!(folder.validate().is_err(), "a claim is for one file only");

        let mut elsewhere = receipt();
        elsewhere.output_path = std::env::temp_dir().join("other.jpg");
        let moved = requester_record(CaptureRequestPhase::Completed { receipt: elsewhere });
        assert!(
            moved.validate().is_err(),
            "a completed photo must be at the exact output, never renamed"
        );

        let mut unmeasured = receipt();
        unmeasured.width = 0;
        unmeasured.height = 0;
        let unmeasured = requester_record(CaptureRequestPhase::Completed {
            receipt: unmeasured,
        });
        assert!(
            unmeasured.validate().is_err(),
            "dimensions must be measured"
        );

        let mut empty = receipt();
        empty.bytes = 0;
        assert!(
            requester_record(CaptureRequestPhase::Completed { receipt: empty })
                .validate()
                .is_err()
        );

        let mut live_reported = requester_record(CaptureRequestPhase::Armed {
            presented_at_unix_ms: CREATED + 10,
        });
        live_reported.terminal_reported = true;
        assert!(live_reported.validate().is_err());

        let oversized_detail = requester_record(CaptureRequestPhase::Terminal {
            code: CaptureTerminalCode::RemoteFailed,
            detail: Some("x".repeat(MAX_CAPTURE_DETAIL_BYTES + 1)),
        });
        assert!(oversized_detail.validate().is_err());
    }

    #[test]
    fn completed_without_a_receipt_does_not_decode() {
        let json = serde_json::to_value(requester_record(CaptureRequestPhase::Completed {
            receipt: receipt(),
        }))
        .expect("encode");
        let mut stripped = json.clone();
        stripped["phase"]["completed"]
            .as_object_mut()
            .expect("completed body")
            .remove("receipt");
        assert!(serde_json::from_value::<CaptureRequestRecord>(stripped).is_err());
    }

    #[test]
    fn every_source_phase_validates_and_round_trips() {
        for phase in source_phases() {
            let record = source_record(phase);
            assert_eq!(record.validate(), Ok(()), "{:?}", record.phase);
            let json = serde_json::to_string(&record).expect("encode record");
            let decoded: CaptureSourceRecord = serde_json::from_str(&json).expect("decode record");
            assert_eq!(decoded, record);
        }
    }

    #[test]
    fn delivered_tombstone_keeps_no_path_to_serve_again() {
        let json = serde_json::to_value(source_record(CaptureSourcePhase::Delivered))
            .expect("encode tombstone");
        assert_eq!(
            json["phase"],
            serde_json::Value::String("delivered".to_owned())
        );
        assert!(!json.to_string().contains("agent-captures"));
    }

    #[test]
    fn source_record_rejects_impossible_shapes() {
        let mut relative = photo();
        relative.path = PathBuf::from("router-label.jpg");
        assert!(
            source_record(CaptureSourcePhase::Captured { photo: relative })
                .validate()
                .is_err()
        );

        let mut unmeasured = photo();
        unmeasured.height = 0;
        assert!(
            source_record(CaptureSourcePhase::Announced { photo: unmeasured })
                .validate()
                .is_err()
        );

        let mut text = photo();
        text.descriptor = OfferDescriptor::text("not a photo").expect("text descriptor");
        assert!(
            source_record(CaptureSourcePhase::Claimed {
                photo: text,
                activation_id: ActivationId::new(),
            })
            .validate()
            .is_err()
        );

        let mut no_deadline = photo();
        no_deadline.delete_deadline_unix_ms = 0;
        assert!(
            source_record(CaptureSourcePhase::Captured { photo: no_deadline })
                .validate()
                .is_err()
        );

        assert!(
            source_record(CaptureSourcePhase::UncertainNoReplay {
                deadline_unix_ms: 0,
                path: photo().path,
            })
            .validate()
            .is_err()
        );

        let mut spoofed_label = source_record(CaptureSourcePhase::Presented);
        spoofed_label.requester_label = "CEDAR\u{200F}".to_owned();
        assert!(spoofed_label.validate().is_err());

        let mut expired_window = source_record(CaptureSourcePhase::Presented);
        expired_window.expires_at_unix_ms = expired_window.created_at_unix_ms;
        assert!(expired_window.validate().is_err());
    }
}
