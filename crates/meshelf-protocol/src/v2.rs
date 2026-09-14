//! Protocol-v2 offer and receiver-initiated fetch types.
//!
//! Hello frames still use [`super::WireMessage`]. Offer, fetch, and payload
//! frames use [`V2Message`] on the production protocol-2 connection after a
//! version-2 hello is accepted.

use std::io::{Read, Write};

use meshelf_core::{
    ActivationId, CaptureCorrelation, CaptureKind, CaptureLens, CaptureRequestId, DeviceId,
    MAX_OFFER_FILE_BYTES, MAX_OFFER_MANIFEST_ENTRIES, MAX_OFFER_PORTABLE_COMPONENT_BYTES,
    MAX_OFFER_PREVIEW_BYTES, MAX_OFFER_TRANSFER_BYTES, MAX_TEXT_BYTES, OfferDescriptor,
    OfferDescriptorError, OfferId, validate_capture_lifetime, validate_capture_purpose,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{FileEntryKind, ProtocolError, check_frame_len, read_length_prefixed_async};
use crate::pairing::{PAIRING_MAX_FRAME_BYTES, SignedPairingFrame};

pub const V2_PROTOCOL_VERSION: u16 = 2;
pub const CAP_OFFER_PULL_V2: &str = "offer-pull-v2";
pub const CAP_CAPTURE_REQUEST_V1: &str = "capture-request-v1";
pub const CAP_CAPTURE_PHOTO_V1: &str = "capture-photo-v1";
pub const CAP_PAIRING_V1: &str = "pairing-v1";
pub const CAP_SHELF_CATALOG_V1: &str = "shelf-catalog-v1";

// Hello frames keep MAX_FRAME_BYTES. Offer and fetch frames use these v2 bounds.
pub const V2_MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
pub const V2_MAX_CATALOG_ENTRIES: usize = 10;
pub const V2_MAX_TEXT_PAYLOAD_BYTES: usize = MAX_TEXT_BYTES;
pub const V2_MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const V2_MAX_MANIFEST_ENTRIES: u32 = MAX_OFFER_MANIFEST_ENTRIES;
pub const V2_MAX_RELATIVE_PATH_BYTES: usize = 4096;
pub const V2_MAX_PORTABLE_COMPONENT_BYTES: usize = MAX_OFFER_PORTABLE_COMPONENT_BYTES;
pub const V2_MAX_FILE_BYTES: u64 = MAX_OFFER_FILE_BYTES;
pub const V2_MAX_TRANSFER_BYTES: u64 = MAX_OFFER_TRANSFER_BYTES;
pub use meshelf_core::V2_MAX_LIVE_ENTRIES;
pub const V2_MAX_ACTIVE_PAYLOAD_STREAMS: u32 = 2;
pub const V2_MAX_ACTIVE_CLIPBOARD_PULLS: u32 = 1;
pub const V2_MAX_INBOUND_HANDLERS: u32 = 16;
pub const V2_STREAM_BUFFER_BYTES: usize = 64 * 1024;
pub const V2_PAYLOAD_INACTIVITY_SECS: u64 = 60;
pub const V2_ADMISSION_TIMEOUT_SECS: u64 = 5 * 60;
pub const V2_MAX_STATUS_DETAIL_BYTES: usize = 512;
pub const V2_MAX_PREVIEW_BYTES: usize = MAX_OFFER_PREVIEW_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferAckCode {
    Stored,
    Duplicate,
    RefusedInvalid,
    RefusedCapacity,
    RefusedConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferAnnouncement {
    pub protocol_version: u16,
    pub offer_id: OfferId,
    pub source_device: DeviceId,
    pub target_device: DeviceId,
    pub created_at_unix_ms: u64,
    pub descriptor: OfferDescriptor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureCorrelation>,
}

impl OfferAnnouncement {
    #[must_use]
    pub fn new(
        offer_id: OfferId,
        source_device: DeviceId,
        target_device: DeviceId,
        created_at_unix_ms: u64,
        descriptor: OfferDescriptor,
    ) -> Self {
        Self {
            protocol_version: V2_PROTOCOL_VERSION,
            offer_id,
            source_device,
            target_device,
            created_at_unix_ms,
            descriptor,
            capture: None,
        }
    }

    #[must_use]
    pub fn with_capture(mut self, capture: CaptureCorrelation) -> Self {
        self.capture = Some(capture);
        self
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != V2_PROTOCOL_VERSION {
            return Err(v2_validation(format!(
                "unsupported v2 protocol version {}; expected {V2_PROTOCOL_VERSION}",
                self.protocol_version
            )));
        }
        self.descriptor
            .validate()
            .map_err(descriptor_validation_error)
    }

    /// Returns whether one offer ID is being reused with different immutable
    /// announcement metadata. The target is intentionally excluded because
    /// the same offer is announced separately to each eligible peer.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.offer_id == other.offer_id
            && (self.source_device != other.source_device
                || self.created_at_unix_ms != other.created_at_unix_ms
                || self.descriptor != other.descriptor
                || self.capture != other.capture)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRequest {
    pub request_id: CaptureRequestId,
    pub requester: DeviceId,
    pub target: DeviceId,
    pub kind: CaptureKind,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens: Option<CaptureLens>,
}

impl CaptureRequest {
    #[must_use]
    pub fn photo(
        request_id: CaptureRequestId,
        requester: DeviceId,
        target: DeviceId,
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            request_id,
            requester,
            target,
            kind: CaptureKind::Photo,
            created_at_unix_ms,
            expires_at_unix_ms,
            purpose: purpose.into(),
            lens: None,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_capture_purpose(&self.purpose)
            .map_err(|error| v2_validation(format!("capture purpose is invalid: {error}")))?;
        if self.requester == self.target {
            return Err(v2_validation(
                "capture requester and target must be different devices",
            ));
        }
        validate_capture_lifetime(self.created_at_unix_ms, self.expires_at_unix_ms)
            .map_err(|error| v2_validation(error.message()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureAckCode {
    Presented,
    Busy,
    Unsupported,
    Expired,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureAck {
    pub request_id: CaptureRequestId,
    pub code: CaptureAckCode,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatusCode {
    Declined,
    Expired,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub request_id: CaptureRequestId,
    pub code: CaptureStatusCode,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferAck {
    pub offer_id: OfferId,
    pub code: OfferAckCode,
    pub live_entries: u32,
    pub max_live_entries: u32,
    pub pruned_entries: u32,
    pub detail: Option<String>,
}

/// Explicit origin catalog read. `request_id` reuses [`ActivationId`] as the
/// existing request/response correlation newtype (same role as [`FetchRequest`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRequest {
    pub protocol_version: u16,
    pub request_id: ActivationId,
    pub origin_device: DeviceId,
    pub requester_device: DeviceId,
    pub after_ordinal: u64,
    pub origin_epoch: u64,
}

impl CatalogRequest {
    #[must_use]
    pub fn new(
        origin_device: DeviceId,
        requester_device: DeviceId,
        after_ordinal: u64,
        origin_epoch: u64,
    ) -> Self {
        Self {
            protocol_version: V2_PROTOCOL_VERSION,
            request_id: ActivationId::new(),
            origin_device,
            requester_device,
            after_ordinal,
            origin_epoch,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)
    }
}

/// One retained ordinary offer in a catalog snapshot. No capture correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub offer_id: OfferId,
    pub origin_ordinal: u64,
    pub created_at_unix_ms: u64,
    pub descriptor: OfferDescriptor,
}

impl CatalogEntry {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.descriptor
            .validate()
            .map_err(descriptor_validation_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub protocol_version: u16,
    pub request_id: ActivationId,
    pub origin_device: DeviceId,
    pub requester_device: DeviceId,
    pub origin_epoch: u64,
    pub highest_issued_ordinal: u64,
    pub entries: Vec<CatalogEntry>,
}

impl CatalogSnapshot {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)?;
        if self.entries.len() > V2_MAX_CATALOG_ENTRIES {
            return Err(v2_validation(format!(
                "catalog snapshot has {} entries; maximum is {V2_MAX_CATALOG_ENTRIES}",
                self.entries.len()
            )));
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogRefusalCode {
    Unsupported,
    RefusedInvalid,
    RefusedTooLarge,
    OriginUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRefusal {
    pub protocol_version: u16,
    pub request_id: ActivationId,
    pub code: CatalogRefusalCode,
    pub detail: Option<String>,
}

impl CatalogRefusal {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)?;
        validate_detail(&self.detail)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRequest {
    pub request_id: ActivationId,
    pub offer_id: OfferId,
    pub source_device: DeviceId,
    pub requester_device: DeviceId,
}

impl FetchRequest {
    #[must_use]
    pub fn new(offer_id: OfferId, source_device: DeviceId, requester_device: DeviceId) -> Self {
        Self {
            request_id: ActivationId::new(),
            offer_id,
            source_device,
            requester_device,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchRefusalCode {
    UnknownOffer,
    NotAnnouncedToRequester,
    SourceUnavailable,
    SourceChanged,
    Busy,
    Malformed,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRefusal {
    pub request_id: ActivationId,
    pub offer_id: OfferId,
    pub code: FetchRefusalCode,
    pub active_streams: u32,
    pub max_active_streams: u32,
    pub detail: Option<String>,
}

impl FetchRefusal {
    pub fn validate_for(&self, descriptor: &OfferDescriptor) -> Result<(), ProtocolError> {
        validate_detail(&self.detail)?;
        if descriptor.is_text() && self.code == FetchRefusalCode::SourceChanged {
            return Err(v2_validation(
                "source_changed is not a valid refusal for a text descriptor",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchHeader {
    pub request_id: ActivationId,
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub manifest_entries: u32,
    pub manifest_encoded_bytes: u64,
    pub text_sha256: Option<Vec<u8>>,
    pub manifest_sha256: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub relative_path: String,
    pub kind: FileEntryKind,
    pub byte_len: u64,
}

impl ManifestEntry {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.relative_path.len() > V2_MAX_RELATIVE_PATH_BYTES {
            return Err(v2_validation(format!(
                "relative path is {} bytes; maximum is {V2_MAX_RELATIVE_PATH_BYTES}",
                self.relative_path.len()
            )));
        }
        if self.relative_path.is_empty() {
            if self.kind != FileEntryKind::File {
                return Err(v2_validation("only a file may use an empty relative path"));
            }
        } else {
            validate_relative_path(&self.relative_path)?;
        }
        match self.kind {
            FileEntryKind::File if self.byte_len > V2_MAX_FILE_BYTES => {
                Err(v2_validation(format!(
                    "file is {} bytes; maximum is {V2_MAX_FILE_BYTES}",
                    self.byte_len
                )))
            }
            FileEntryKind::Directory if self.byte_len != 0 => {
                Err(v2_validation("directory entries must have zero bytes"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestChunk {
    pub request_id: ActivationId,
    pub first_index: u32,
    pub entries: Vec<ManifestEntry>,
}

impl ManifestChunk {
    pub fn new(
        request_id: ActivationId,
        first_index: u32,
        entries: Vec<ManifestEntry>,
    ) -> Result<Self, ProtocolError> {
        let chunk = Self {
            request_id,
            first_index,
            entries,
        };
        validate_manifest_chunk(&chunk)?;
        let payload_len = serde_json::to_vec(&V2Message::ManifestChunk(chunk.clone()))?.len();
        validate_v2_payload_len(payload_len)?;
        Ok(chunk)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_manifest_chunk(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEnd {
    pub request_id: ActivationId,
    pub entry_count: u32,
    pub file_count: u32,
    pub total_bytes: u64,
    pub manifest_sha256: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchAdmissionCode {
    Accepted,
    RefusedBusy,
    InvalidManifest,
    TooLarge,
    InsufficientSpace,
    DestinationUnavailable,
    AllocationFailed,
    UnsupportedMode,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchAdmission {
    pub request_id: ActivationId,
    pub code: FetchAdmissionCode,
    pub entries_reserved: u32,
    pub bytes_reserved: u64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStart {
    pub request_id: ActivationId,
    pub entry_index: u32,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEnd {
    pub request_id: ActivationId,
    pub entry_index: u32,
    pub sha256: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEnd {
    pub request_id: ActivationId,
    pub sha256: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchComplete {
    pub request_id: ActivationId,
    pub files_sent: u32,
    pub bytes_sent: u64,
    pub content_set_sha256: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchAbortCode {
    SourceUnavailable,
    SourceChanged,
    Cancelled,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchAbort {
    pub request_id: ActivationId,
    pub code: FetchAbortCode,
    pub files_sent: u32,
    pub bytes_sent: u64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchReceiptCode {
    Completed,
    ConnectionLost,
    Cancelled,
    VerificationFailed,
    ClipboardFailed,
    UncertainNoReplay,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchReceipt {
    pub request_id: ActivationId,
    pub offer_id: OfferId,
    pub code: FetchReceiptCode,
    pub files_received: u32,
    pub bytes_received: u64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum V2Message {
    CaptureRequest(CaptureRequest),
    CaptureAck(CaptureAck),
    CaptureStatus(CaptureStatus),
    OfferAnnouncement(OfferAnnouncement),
    OfferAck(OfferAck),
    CatalogRequest(CatalogRequest),
    CatalogSnapshot(CatalogSnapshot),
    CatalogRefusal(CatalogRefusal),
    FetchRequest(FetchRequest),
    FetchRefusal(FetchRefusal),
    FetchHeader(FetchHeader),
    ManifestChunk(ManifestChunk),
    ManifestEnd(ManifestEnd),
    FetchAdmission(FetchAdmission),
    FileStart(FileStart),
    FileEnd(FileEnd),
    TextEnd(TextEnd),
    FetchComplete(FetchComplete),
    FetchAbort(FetchAbort),
    FetchReceipt(FetchReceipt),
    /// One signed pairing subframe (work order 09 decision 12). Only a pairing-only connection
    /// carries it, and its encoded form is bounded by [`PAIRING_MAX_FRAME_BYTES`].
    Pair(SignedPairingFrame),
}

/// Encodes one v2 message using the existing four-byte length prefix and a
/// 64 KiB v2 control-frame payload limit.
pub fn encode_v2_frame(message: &V2Message) -> Result<Vec<u8>, ProtocolError> {
    validate_v2_message(message)?;
    let payload = serde_json::to_vec(message)?;
    validate_v2_payload_len(payload.len())?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| ProtocolError::LengthOverflow)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_v2_payload(payload: &[u8]) -> Result<V2Message, ProtocolError> {
    validate_v2_payload_len(payload.len())?;
    Ok(serde_json::from_slice(payload)?)
}

pub fn write_v2_frame<W: Write>(writer: &mut W, message: &V2Message) -> Result<(), ProtocolError> {
    writer.write_all(&encode_v2_frame(message)?)?;
    writer.flush()?;
    Ok(())
}

pub fn read_v2_frame<R: Read>(reader: &mut R) -> Result<V2Message, ProtocolError> {
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    validate_v2_payload_len(length)?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    decode_v2_payload(&payload)
}

pub async fn write_v2_frame_async<W>(
    writer: &mut W,
    message: &V2Message,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_v2_frame(message)?).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_v2_frame_async<R>(reader: &mut R) -> Result<V2Message, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    read_v2_frame_async_limited(reader, V2_MAX_CONTROL_FRAME_BYTES).await
}

/// Same as [`read_v2_frame_async`] with a caller bound on the payload, never above
/// [`V2_MAX_CONTROL_FRAME_BYTES`]. The declared length is refused before any payload buffer is
/// allocated. A pairing connection reads with [`PAIRING_MAX_FRAME_BYTES`], the same bound
/// [`validate_v2_message`] applies to an encoded [`V2Message::Pair`]. Like the unlimited reader,
/// this does not validate the decoded message.
pub async fn read_v2_frame_async_limited<R>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<V2Message, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let payload =
        read_length_prefixed_async(reader, max_bytes.min(V2_MAX_CONTROL_FRAME_BYTES)).await?;
    decode_v2_payload(&payload)
}

/// Splits a manifest into control-frame-safe chunks and enforces the
/// aggregate encoded-manifest bound.
pub fn chunk_manifest(
    request_id: ActivationId,
    entries: Vec<ManifestEntry>,
) -> Result<Vec<ManifestChunk>, ProtocolError> {
    validate_manifest_entries(&entries)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut first_index = 0_u32;

    for entry in entries {
        let mut candidate = current.clone();
        candidate.push(entry.clone());
        let candidate_chunk = ManifestChunk {
            request_id,
            first_index,
            entries: candidate,
        };
        let candidate_len = serde_json::to_vec(&V2Message::ManifestChunk(candidate_chunk))?.len();
        if candidate_len <= V2_MAX_CONTROL_FRAME_BYTES {
            current.push(entry);
            continue;
        }

        if current.is_empty() {
            return Err(ProtocolError::FrameTooLarge {
                bytes: candidate_len,
                maximum: V2_MAX_CONTROL_FRAME_BYTES,
            });
        }
        chunks.push(ManifestChunk::new(
            request_id,
            first_index,
            std::mem::take(&mut current),
        )?);
        first_index = chunks
            .last()
            .and_then(|chunk| chunk.first_index.checked_add(chunk.entries.len() as u32))
            .ok_or_else(|| v2_validation("manifest index overflow"))?;
        current.push(entry);
    }

    if !current.is_empty() {
        chunks.push(ManifestChunk::new(request_id, first_index, current)?);
    }

    let encoded_bytes = encoded_manifest_bytes(&chunks)?;
    if encoded_bytes > V2_MAX_MANIFEST_BYTES {
        return Err(v2_validation(format!(
            "encoded manifest is {encoded_bytes} bytes; maximum is {V2_MAX_MANIFEST_BYTES}"
        )));
    }
    Ok(chunks)
}

pub fn encode_manifest_chunks(
    request_id: ActivationId,
    entries: Vec<ManifestEntry>,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    chunk_manifest(request_id, entries)?
        .into_iter()
        .map(|chunk| encode_v2_frame(&V2Message::ManifestChunk(chunk)))
        .collect()
}

pub fn encoded_manifest_bytes(chunks: &[ManifestChunk]) -> Result<usize, ProtocolError> {
    let mut total = 0_usize;
    for chunk in chunks {
        chunk.validate()?;
        let encoded = serde_json::to_vec(&V2Message::ManifestChunk(chunk.clone()))?;
        validate_v2_payload_len(encoded.len())?;
        total = total
            .checked_add(encoded.len())
            .ok_or_else(|| v2_validation("encoded manifest size overflow"))?;
    }
    if total > V2_MAX_MANIFEST_BYTES {
        return Err(v2_validation(format!(
            "encoded manifest is {total} bytes; maximum is {V2_MAX_MANIFEST_BYTES}"
        )));
    }
    Ok(total)
}

pub fn validate_v2_message(message: &V2Message) -> Result<(), ProtocolError> {
    match message {
        V2Message::CaptureRequest(value) => value.validate(),
        V2Message::CaptureAck(value) => validate_detail(&value.detail),
        V2Message::CaptureStatus(value) => validate_detail(&value.detail),
        V2Message::OfferAnnouncement(value) => value.validate(),
        V2Message::OfferAck(value) => {
            if value.live_entries > value.max_live_entries
                || value.max_live_entries != V2_MAX_LIVE_ENTRIES
            {
                return Err(v2_validation("offer card capacity is not the v2 bound"));
            }
            validate_detail(&value.detail)
        }
        V2Message::CatalogRequest(value) => value.validate(),
        V2Message::CatalogSnapshot(value) => value.validate(),
        V2Message::CatalogRefusal(value) => value.validate(),
        V2Message::FetchRequest(_) => Ok(()),
        V2Message::FetchRefusal(value) => {
            if value.active_streams > value.max_active_streams
                || value.max_active_streams != V2_MAX_ACTIVE_PAYLOAD_STREAMS
            {
                return Err(v2_validation("payload stream capacity is not the v2 bound"));
            }
            validate_detail(&value.detail)?;
            Ok(())
        }
        V2Message::FetchHeader(value) => {
            value
                .descriptor
                .validate()
                .map_err(descriptor_validation_error)?;
            if value.manifest_entries > V2_MAX_MANIFEST_ENTRIES {
                return Err(v2_validation("manifest entry count exceeds the v2 bound"));
            }
            if value.manifest_encoded_bytes > V2_MAX_MANIFEST_BYTES as u64 {
                return Err(v2_validation("encoded manifest exceeds the v2 bound"));
            }
            Ok(())
        }
        V2Message::ManifestChunk(value) => value.validate(),
        V2Message::ManifestEnd(value) => {
            if value.entry_count > V2_MAX_MANIFEST_ENTRIES {
                return Err(v2_validation("manifest entry count exceeds the v2 bound"));
            }
            if value.total_bytes > V2_MAX_TRANSFER_BYTES {
                return Err(v2_validation("manifest transfer size exceeds the v2 bound"));
            }
            Ok(())
        }
        V2Message::FetchAdmission(value) => {
            if value.entries_reserved > V2_MAX_MANIFEST_ENTRIES {
                return Err(v2_validation("reserved entry count exceeds the v2 bound"));
            }
            if value.bytes_reserved > V2_MAX_TRANSFER_BYTES {
                return Err(v2_validation("reserved transfer size exceeds the v2 bound"));
            }
            validate_detail(&value.detail)
        }
        V2Message::FileStart(value) => {
            if value.entry_index >= V2_MAX_MANIFEST_ENTRIES {
                return Err(v2_validation("file entry index exceeds the v2 bound"));
            }
            if value.byte_len > V2_MAX_FILE_BYTES {
                return Err(v2_validation("file size exceeds the v2 bound"));
            }
            Ok(())
        }
        V2Message::FileEnd(_) | V2Message::TextEnd(_) => Ok(()),
        V2Message::FetchComplete(value) => {
            if value.files_sent > V2_MAX_MANIFEST_ENTRIES {
                return Err(v2_validation("sent file count exceeds the v2 bound"));
            }
            if value.bytes_sent > V2_MAX_TRANSFER_BYTES {
                return Err(v2_validation("sent transfer size exceeds the v2 bound"));
            }
            Ok(())
        }
        V2Message::FetchAbort(value) => validate_detail(&value.detail),
        V2Message::FetchReceipt(value) => {
            if value.files_received > V2_MAX_MANIFEST_ENTRIES {
                return Err(v2_validation("received file count exceeds the v2 bound"));
            }
            if value.bytes_received > V2_MAX_TRANSFER_BYTES {
                return Err(v2_validation("received transfer size exceeds the v2 bound"));
            }
            validate_detail(&value.detail)
        }
        V2Message::Pair(signed) => {
            signed.frame.validate()?;
            // A2: the bound applies to the frame as it travels, wrapped in its V2Message tag, which
            // is also what a pairing reader's length prefix counts.
            check_frame_len(serde_json::to_vec(message)?.len(), PAIRING_MAX_FRAME_BYTES)
        }
    }
}

fn validate_manifest_chunk(chunk: &ManifestChunk) -> Result<(), ProtocolError> {
    let end_index = chunk
        .first_index
        .checked_add(chunk.entries.len() as u32)
        .ok_or_else(|| v2_validation("manifest index overflow"))?;
    if end_index > V2_MAX_MANIFEST_ENTRIES {
        return Err(v2_validation("manifest entry count exceeds the v2 bound"));
    }
    for entry in &chunk.entries {
        entry.validate()?;
    }
    let total_bytes = chunk
        .entries
        .iter()
        .filter(|entry| entry.kind == FileEntryKind::File)
        .try_fold(0_u64, |total, entry| total.checked_add(entry.byte_len))
        .ok_or_else(|| v2_validation("manifest transfer size overflow"))?;
    if total_bytes > V2_MAX_TRANSFER_BYTES {
        return Err(v2_validation("manifest transfer size exceeds the v2 bound"));
    }
    Ok(())
}

fn validate_manifest_entries(entries: &[ManifestEntry]) -> Result<(), ProtocolError> {
    let count = u32::try_from(entries.len())
        .map_err(|_| v2_validation("manifest entry count cannot be represented as u32"))?;
    if count > V2_MAX_MANIFEST_ENTRIES {
        return Err(v2_validation("manifest entry count exceeds the v2 bound"));
    }
    let mut total_bytes = 0_u64;
    for entry in entries {
        entry.validate()?;
        if entry.kind == FileEntryKind::File {
            total_bytes = total_bytes
                .checked_add(entry.byte_len)
                .ok_or_else(|| v2_validation("manifest transfer size overflow"))?;
        }
    }
    if total_bytes > V2_MAX_TRANSFER_BYTES {
        return Err(v2_validation("manifest transfer size exceeds the v2 bound"));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), ProtocolError> {
    if path.starts_with('/') || path.contains('\\') {
        return Err(v2_validation("relative path is not portable"));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(v2_validation("relative path contains an invalid component"));
        }
        if component.len() > V2_MAX_PORTABLE_COMPONENT_BYTES {
            return Err(v2_validation(format!(
                "path component is {} bytes; maximum is {V2_MAX_PORTABLE_COMPONENT_BYTES}",
                component.len()
            )));
        }
        if component.chars().any(char::is_control) {
            return Err(v2_validation("relative path contains a control character"));
        }
    }
    Ok(())
}

fn validate_detail(detail: &Option<String>) -> Result<(), ProtocolError> {
    if let Some(detail) = detail
        && detail.len() > V2_MAX_STATUS_DETAIL_BYTES
    {
        return Err(v2_validation(format!(
            "status detail is {} bytes; maximum is {V2_MAX_STATUS_DETAIL_BYTES}",
            detail.len()
        )));
    }
    Ok(())
}

fn validate_protocol_version(protocol_version: u16) -> Result<(), ProtocolError> {
    if protocol_version != V2_PROTOCOL_VERSION {
        return Err(v2_validation(format!(
            "unsupported v2 protocol version {protocol_version}; expected {V2_PROTOCOL_VERSION}"
        )));
    }
    Ok(())
}

fn validate_v2_payload_len(length: usize) -> Result<(), ProtocolError> {
    check_frame_len(length, V2_MAX_CONTROL_FRAME_BYTES)
}

fn descriptor_validation_error(error: OfferDescriptorError) -> ProtocolError {
    v2_validation(error.to_string())
}

fn v2_validation(detail: impl Into<String>) -> ProtocolError {
    ProtocolError::V2Validation {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use meshelf_core::{ActivationState, OfferDescriptor, OfferId};

    use super::*;

    fn text_descriptor() -> OfferDescriptor {
        OfferDescriptor::text("alpha\nβeta\n🙂").expect("text descriptor")
    }

    fn announcement(descriptor: OfferDescriptor) -> OfferAnnouncement {
        OfferAnnouncement::new(
            OfferId::new(),
            DeviceId::new(),
            DeviceId::new(),
            1_000,
            descriptor,
        )
    }

    #[test]
    fn offer_announcement_round_trip_contains_no_payload_fields() {
        let message = V2Message::OfferAnnouncement(announcement(text_descriptor()));
        let json = serde_json::to_string(&message).expect("serialize");
        for forbidden in [
            "text_body",
            "content",
            "payload",
            "sender_path",
            "manifest",
            "sha256",
            "clipboard_generation",
            "lease_ms",
            "expires_at",
        ] {
            assert!(
                !json.contains(forbidden),
                "unexpected field {forbidden}: {json}"
            );
        }
        let frame = encode_v2_frame(&message).expect("encode");
        assert_eq!(
            read_v2_frame(&mut Cursor::new(frame)).expect("decode"),
            message
        );
    }

    #[test]
    fn manifest_chunks_fit_control_frame_and_aggregate_limit() {
        let entries = (0..V2_MAX_MANIFEST_ENTRIES)
            .map(|index| ManifestEntry {
                relative_path: format!("dir/{index}/file.txt"),
                kind: FileEntryKind::File,
                byte_len: 0,
            })
            .collect();
        let chunks = chunk_manifest(ActivationId::new(), entries).expect("chunk manifest");
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            let frame = encode_v2_frame(&V2Message::ManifestChunk(chunk.clone())).expect("frame");
            assert!(frame.len() <= V2_MAX_CONTROL_FRAME_BYTES + 4);
        }
        assert!(encoded_manifest_bytes(&chunks).expect("size") <= V2_MAX_MANIFEST_BYTES);

        let component = "a".repeat(V2_MAX_PORTABLE_COMPONENT_BYTES);
        let long_path = (0..16)
            .map(|_| component.as_str())
            .collect::<Vec<_>>()
            .join("/");
        let oversized_entries = (0..V2_MAX_MANIFEST_ENTRIES)
            .map(|_| ManifestEntry {
                relative_path: long_path.clone(),
                kind: FileEntryKind::File,
                byte_len: 0,
            })
            .collect();
        assert!(chunk_manifest(ActivationId::new(), oversized_entries).is_err());
    }

    #[test]
    fn fetch_request_cannot_encode_destination_or_activation_mode() {
        let request = FetchRequest::new(OfferId::new(), DeviceId::new(), DeviceId::new());
        let json = serde_json::to_string(&V2Message::FetchRequest(request)).expect("serialize");
        for forbidden in [
            "destination",
            "save_folder",
            "activation_mode",
            "clipboard_mode",
        ] {
            assert!(
                !json.contains(forbidden),
                "unexpected field {forbidden}: {json}"
            );
        }
    }

    #[test]
    fn same_offer_id_with_changed_descriptor_is_conflict() {
        let offer_id = OfferId::new();
        let source = DeviceId::new();
        let first = OfferAnnouncement::new(
            offer_id,
            source,
            DeviceId::new(),
            1_000,
            OfferDescriptor::File {
                root_name: "a.txt".to_owned(),
                total_bytes: 1,
                content_class: meshelf_core::FileContentClass::File,
            },
        );
        let changed = OfferAnnouncement::new(
            offer_id,
            source,
            DeviceId::new(),
            1_000,
            OfferDescriptor::File {
                root_name: "a.txt".to_owned(),
                total_bytes: 2,
                content_class: meshelf_core::FileContentClass::File,
            },
        );
        assert!(first.conflicts_with(&changed));
    }

    #[test]
    fn amendments_have_no_clipboard_stamp_text_source_change_or_expiry_fields() {
        let announcement_json =
            serde_json::to_string(&announcement(text_descriptor())).expect("json");
        assert!(!announcement_json.contains("clipboard_generation"));
        assert!(!announcement_json.contains("expires"));
        assert!(!announcement_json.contains("lease"));

        let refusal = FetchRefusal {
            request_id: ActivationId::new(),
            offer_id: OfferId::new(),
            code: FetchRefusalCode::SourceChanged,
            active_streams: 0,
            max_active_streams: V2_MAX_ACTIVE_PAYLOAD_STREAMS,
            detail: None,
        };
        assert!(refusal.validate_for(&text_descriptor()).is_err());
        assert!(
            !serde_json::to_string(&ActivationState::Completed)
                .expect("state json")
                .contains("expired")
        );
        assert!(!format!("{:?}", OfferAckCode::Stored).contains("Expired"));
        assert!(!format!("{:?}", FetchRefusalCode::UnknownOffer).contains("Expired"));
        assert!(!format!("{:?}", FetchAdmissionCode::Accepted).contains("Expired"));
        assert!(!format!("{:?}", FetchReceiptCode::Completed).contains("Expired"));
    }

    #[test]
    fn zero_byte_file_is_valid_not_missing_input() {
        let entry = ManifestEntry {
            relative_path: String::new(),
            kind: FileEntryKind::File,
            byte_len: 0,
        };
        assert!(entry.validate().is_ok());
        let descriptor = OfferDescriptor::File {
            root_name: "empty.txt".to_owned(),
            total_bytes: 0,
            content_class: meshelf_core::FileContentClass::File,
        };
        assert_eq!(descriptor.validate(), Ok(()));
    }
    #[test]
    fn capture_request_round_trip_and_bounds_are_exhaustive() {
        let requester = DeviceId::new();
        let target = DeviceId::new();
        let request = CaptureRequest::photo(
            CaptureRequestId::new(),
            requester,
            target,
            1_000,
            181_000,
            "Photograph the serial label",
        );
        let message = V2Message::CaptureRequest(request.clone());
        let frame = encode_v2_frame(&message).expect("bounded capture request");
        assert!(frame.len() <= V2_MAX_CONTROL_FRAME_BYTES + 4);
        assert_eq!(
            read_v2_frame(&mut Cursor::new(frame)).expect("decode"),
            message
        );

        let mut oversized = request.clone();
        oversized.purpose = "é".repeat(81);
        assert!(validate_v2_message(&V2Message::CaptureRequest(oversized)).is_err());

        let mut control = request.clone();
        control.purpose = "line\nbreak".to_owned();
        assert!(validate_v2_message(&V2Message::CaptureRequest(control)).is_err());

        let mut overlong = request;
        overlong.expires_at_unix_ms += 1;
        assert!(validate_v2_message(&V2Message::CaptureRequest(overlong)).is_err());
    }

    #[test]
    fn capture_request_addressed_to_its_own_requester_is_refused() {
        // A capture pulls a photograph from a second, pinned device. A device asking itself
        // would make the requester the expected photo source, which no grant may name.
        let device = DeviceId::new();
        let request = CaptureRequest::photo(
            CaptureRequestId::new(),
            device,
            device,
            1_000,
            181_000,
            "Photograph the serial label",
        );
        assert!(request.validate().is_err());
        assert!(validate_v2_message(&V2Message::CaptureRequest(request)).is_err());
    }

    #[test]
    fn capture_request_purpose_goes_through_the_core_validator_the_phone_agrees_with() {
        let mut request = CaptureRequest::photo(
            CaptureRequestId::new(),
            DeviceId::new(),
            DeviceId::new(),
            1_000,
            181_000,
            "Photograph the serial label",
        );
        assert!(request.validate().is_ok());
        for refused in [
            "",
            "Photograph the \u{202E}lebal laires",
            "serial\u{200B}label",
        ] {
            request.purpose = refused.to_owned();
            assert!(
                validate_v2_message(&V2Message::CaptureRequest(request.clone())).is_err(),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn ordinary_offer_omits_capture_but_correlated_offer_carries_only_request_id() {
        let ordinary = announcement(text_descriptor());
        let ordinary_json = serde_json::to_string(&ordinary).expect("ordinary json");
        assert!(!ordinary_json.contains("capture"));

        let request_id = CaptureRequestId::new();
        let correlated = ordinary.with_capture(CaptureCorrelation { request_id });
        let json = serde_json::to_string(&correlated).expect("correlated json");
        assert!(json.contains("capture"));
        assert!(json.contains(&request_id.to_string()));
        for forbidden in ["photo_bytes", "jpeg", "content", "payload"] {
            assert!(!json.contains(forbidden), "unexpected {forbidden}: {json}");
        }
    }

    #[test]
    fn shelf_catalog_cap_constant_exists() {
        assert_eq!(CAP_SHELF_CATALOG_V1, "shelf-catalog-v1");
    }

    #[test]
    fn catalog_snapshot_round_trip_with_one_text_descriptor() {
        let request_id = ActivationId::new();
        let origin = DeviceId::new();
        let requester = DeviceId::new();
        let snapshot = CatalogSnapshot {
            protocol_version: V2_PROTOCOL_VERSION,
            request_id,
            origin_device: origin,
            requester_device: requester,
            origin_epoch: 1,
            highest_issued_ordinal: 7,
            entries: vec![CatalogEntry {
                offer_id: OfferId::new(),
                origin_ordinal: 7,
                created_at_unix_ms: 1_000,
                descriptor: text_descriptor(),
            }],
        };
        let message = V2Message::CatalogSnapshot(snapshot);
        let json = serde_json::to_string(&message).expect("serialize");
        for forbidden in [
            "capture",
            "text_body",
            "content",
            "payload",
            "photo_bytes",
            "grant",
        ] {
            assert!(
                !json.contains(forbidden),
                "unexpected field {forbidden}: {json}"
            );
        }
        let frame = encode_v2_frame(&message).expect("encode under control bound");
        assert!(frame.len() <= V2_MAX_CONTROL_FRAME_BYTES + 4);
        assert_eq!(
            read_v2_frame(&mut Cursor::new(frame)).expect("decode"),
            message
        );
    }

    #[test]
    fn catalog_snapshot_refuses_more_than_ten_entries() {
        let entries = (0..=V2_MAX_CATALOG_ENTRIES)
            .map(|index| CatalogEntry {
                offer_id: OfferId::new(),
                origin_ordinal: index as u64,
                created_at_unix_ms: 1_000 + index as u64,
                descriptor: text_descriptor(),
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), V2_MAX_CATALOG_ENTRIES + 1);
        let snapshot = CatalogSnapshot {
            protocol_version: V2_PROTOCOL_VERSION,
            request_id: ActivationId::new(),
            origin_device: DeviceId::new(),
            requester_device: DeviceId::new(),
            origin_epoch: 1,
            highest_issued_ordinal: V2_MAX_CATALOG_ENTRIES as u64,
            entries,
        };
        assert!(validate_v2_message(&V2Message::CatalogSnapshot(snapshot)).is_err());
    }
}
