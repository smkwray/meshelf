//! Versioned and size-bounded meshelf wire protocol.

use std::io::{Read, Write};

use meshelf_core::{DeviceId, MAX_TEXT_BYTES};
use meshelf_identity::InstallationIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_BYTES: usize = MAX_TEXT_BYTES + 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub device_name: String,
    pub nonce: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl ClientHello {
    #[must_use]
    pub fn new(
        device_id: DeviceId,
        device_name: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self::v2(device_id, device_name, nonce)
    }

    #[must_use]
    pub fn signed(
        device_id: DeviceId,
        device_name: impl Into<String>,
        nonce: impl Into<String>,
        identity: &InstallationIdentity,
    ) -> Self {
        Self::signed_v2(device_id, device_name, nonce, identity)
    }

    #[must_use]
    pub fn v2(
        device_id: DeviceId,
        device_name: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: V2_PROTOCOL_VERSION,
            device_id,
            device_name: device_name.into(),
            nonce: nonce.into(),
            capabilities: vec![CAP_OFFER_PULL_V2.to_owned()],
            public_key: Vec::new(),
            signature: Vec::new(),
        }
    }

    #[must_use]
    pub fn signed_v2(
        device_id: DeviceId,
        device_name: impl Into<String>,
        nonce: impl Into<String>,
        identity: &InstallationIdentity,
    ) -> Self {
        let mut hello = Self::v2(device_id, device_name, nonce);
        hello.public_key = identity.public_key().to_vec();
        hello.signature = identity.sign(&hello.signing_bytes());
        hello
    }

    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned).expect("client hello is serializable")
    }

    #[must_use]
    pub fn has_valid_signature(&self) -> bool {
        InstallationIdentity::verify(&self.public_key, &self.signing_bytes(), &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    pub protocol_version: u16,
    pub device_id: DeviceId,
    pub device_name: String,
    pub accepted: bool,
    pub reason: Option<String>,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEntryKind {
    File,
    Directory,
}

impl ServerHello {
    #[must_use]
    pub fn signed(
        protocol_version: u16,
        device_id: DeviceId,
        device_name: String,
        accepted: bool,
        reason: Option<String>,
        capabilities: Vec<String>,
        identity: &InstallationIdentity,
    ) -> Self {
        let mut hello = Self {
            protocol_version,
            device_id,
            device_name,
            accepted,
            reason,
            capabilities,
            public_key: identity.public_key().to_vec(),
            signature: Vec::new(),
        };
        hello.signature = identity.sign(&hello.signing_bytes());
        hello
    }

    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned).expect("server hello is serializable")
    }

    #[must_use]
    pub fn has_valid_signature(&self) -> bool {
        InstallationIdentity::verify(&self.public_key, &self.signing_bytes(), &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum WireMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame is empty")]
    EmptyFrame,
    #[error("frame length {bytes} exceeds maximum {maximum}")]
    FrameTooLarge { bytes: usize, maximum: usize },
    #[error("frame length cannot be represented as u32")]
    LengthOverflow,
    #[error("v2 message validation failed: {detail}")]
    V2Validation { detail: String },
}

pub mod v2;

pub use v2::{
    CAP_OFFER_PULL_V2, FetchAbort, FetchAbortCode, FetchAdmission, FetchAdmissionCode,
    FetchComplete, FetchHeader, FetchReceipt, FetchReceiptCode, FetchRefusal, FetchRefusalCode,
    FetchRequest, FileEnd, FileStart, ManifestChunk, ManifestEnd, ManifestEntry, OfferAck,
    OfferAckCode, OfferAnnouncement, TextEnd, V2_ADMISSION_TIMEOUT_SECS,
    V2_MAX_ACTIVE_CLIPBOARD_PULLS, V2_MAX_ACTIVE_PAYLOAD_STREAMS, V2_MAX_CONTROL_FRAME_BYTES,
    V2_MAX_FILE_BYTES, V2_MAX_INBOUND_HANDLERS, V2_MAX_LIVE_ENTRIES, V2_MAX_MANIFEST_BYTES,
    V2_MAX_MANIFEST_ENTRIES, V2_MAX_PORTABLE_COMPONENT_BYTES, V2_MAX_PREVIEW_BYTES,
    V2_MAX_RELATIVE_PATH_BYTES, V2_MAX_STATUS_DETAIL_BYTES, V2_MAX_TEXT_PAYLOAD_BYTES,
    V2_MAX_TRANSFER_BYTES, V2_PAYLOAD_INACTIVITY_SECS, V2_PROTOCOL_VERSION, V2_STREAM_BUFFER_BYTES,
    V2Message, chunk_manifest, decode_v2_payload, encode_manifest_chunks, encode_v2_frame,
    encoded_manifest_bytes, read_v2_frame, read_v2_frame_async, validate_v2_message,
    write_v2_frame, write_v2_frame_async,
};

pub fn encode_frame(message: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(message)?;
    validate_payload_len(payload.len())?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| ProtocolError::LengthOverflow)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn write_frame<W: Write>(writer: &mut W, message: &WireMessage) -> Result<(), ProtocolError> {
    writer.write_all(&encode_frame(message)?)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<WireMessage, ProtocolError> {
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    validate_payload_len(length)?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

pub async fn write_frame_async<W>(
    writer: &mut W,
    message: &WireMessage,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_frame(message)?).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame_async<R>(reader: &mut R) -> Result<WireMessage, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    validate_payload_len(length)?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

/// Read one bounded handshake frame and accept only a ClientHello.
pub async fn read_client_hello_async<R>(reader: &mut R) -> Result<ClientHello, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    validate_payload_len(length)?;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    match serde_json::from_slice::<WireMessage>(&payload)? {
        WireMessage::ClientHello(hello) => Ok(hello),
        WireMessage::ServerHello(_) => Err(ProtocolError::V2Validation {
            detail: "expected client_hello as the first frame".to_owned(),
        }),
    }
}

fn validate_payload_len(length: usize) -> Result<(), ProtocolError> {
    if length == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            bytes: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod restored_handshake_tests {
    use std::io::Cursor;

    use meshelf_core::DeviceId;
    use meshelf_identity::InstallationIdentity;

    use super::*;

    #[test]
    fn synchronous_round_trip_preserves_unicode() {
        let message = WireMessage::ClientHello(ClientHello::v2(
            DeviceId::new(),
            "BMST δ🙂",
            "line one\nδelta\n🙂",
        ));
        let frame = encode_frame(&message).expect("encode");
        let decoded = read_frame(&mut Cursor::new(frame)).expect("decode");
        assert_eq!(decoded, message);
    }

    #[test]
    fn rejects_declared_oversized_frame_without_allocating_payload() {
        let length = (MAX_FRAME_BYTES as u32).saturating_add(1);
        let frame = length.to_be_bytes();
        let error = read_frame(&mut Cursor::new(frame)).expect_err("oversized frame");
        assert!(matches!(error, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut frame = Vec::from(10_u32.to_be_bytes());
        frame.extend_from_slice(b"tiny");
        let error = read_frame(&mut Cursor::new(frame)).expect_err("truncated frame");
        assert!(matches!(error, ProtocolError::Io(_)));
    }

    #[tokio::test]
    async fn asynchronous_round_trip() {
        let hello =
            WireMessage::ClientHello(ClientHello::v2(DeviceId::new(), "BMST", "test-nonce"));
        let (mut left, mut right) = tokio::io::duplex(MAX_FRAME_BYTES + 4);
        let expected = hello.clone();
        let sender = tokio::spawn(async move {
            write_frame_async(&mut left, &hello).await.expect("write");
        });
        let decoded = read_frame_async(&mut right).await.expect("read");
        sender.await.expect("sender task");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn signed_hello_rejects_field_and_signature_mutations() {
        let identity = InstallationIdentity::generate();
        let mut hello = ClientHello::signed_v2(identity.device_id, "BMST", "nonce", &identity);
        assert!(hello.has_valid_signature());

        hello.device_name.push('x');
        assert!(!hello.has_valid_signature());
        hello.device_name.pop();
        assert!(hello.has_valid_signature());

        hello.signature[0] ^= 1;
        assert!(!hello.has_valid_signature());
    }
}
