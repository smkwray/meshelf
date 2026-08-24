//! Versioned and size-bounded meshelf wire protocol.

use std::io::{Read, Write};

use meshelf_core::{
    ContentKind, DeviceId, MAX_TEXT_BYTES, MessageId, PROTOCOL_VERSION, Receipt, TextEnvelope,
};
use meshelf_identity::InstallationIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_BYTES: usize = MAX_TEXT_BYTES + 64 * 1024;
pub const CAP_TEXT_CLIPBOARD_PUSH_V1: &str = "text-clipboard-push-v1";
pub const CAP_TEXT_SHELF_V1: &str = "text-shelf-v1";
pub const CAP_FILE_STREAM_V1: &str = "file-stream-v1";
pub const MAX_FILE_ENTRIES: usize = 4096;
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_TRANSFER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_RELATIVE_PATH_BYTES: usize = 4096;

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
        Self {
            protocol_version: PROTOCOL_VERSION,
            device_id,
            device_name: device_name.into(),
            nonce: nonce.into(),
            capabilities: vec![CAP_TEXT_SHELF_V1.to_owned(), CAP_FILE_STREAM_V1.to_owned()],
            public_key: Vec::new(),
            signature: Vec::new(),
        }
    }

    #[must_use]
    pub fn signed(
        device_id: DeviceId,
        device_name: impl Into<String>,
        nonce: impl Into<String>,
        identity: &InstallationIdentity,
    ) -> Self {
        let mut hello = Self::new(device_id, device_name, nonce);
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTransferEntry {
    pub relative_path: String,
    pub kind: FileEntryKind,
    pub byte_len: u64,
    #[serde(default)]
    pub sha256: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTransferOffer {
    pub protocol_version: u16,
    pub transfer_id: MessageId,
    pub source_device: DeviceId,
    pub target_device: DeviceId,
    pub content_kind: ContentKind,
    pub root_name: String,
    pub total_bytes: u64,
    pub entries: Vec<FileTransferEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAdmission {
    pub transfer_id: MessageId,
    pub accepted: bool,
    pub already_complete: bool,
    pub detail: Option<String>,
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
    PushEnvelope(TextEnvelope),
    FileOffer(FileTransferOffer),
    FileAdmission(FileAdmission),
    Receipt(Receipt),
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
}

pub fn encode_frame(message: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(message)?;
    validate_payload_len(payload.len())?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| ProtocolError::LengthOverflow)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_payload(payload: &[u8]) -> Result<WireMessage, ProtocolError> {
    validate_payload_len(payload.len())?;
    Ok(serde_json::from_slice(payload)?)
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
    decode_payload(&payload)
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
    decode_payload(&payload)
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
mod tests {
    use std::io::Cursor;

    use meshelf_core::{DeviceId, TextEnvelope};

    use super::*;

    #[test]
    fn synchronous_round_trip_preserves_unicode() {
        let source = DeviceId::new();
        let target = DeviceId::new();
        let message = WireMessage::PushEnvelope(TextEnvelope::clipboard_push(
            source,
            target,
            10,
            Some(100),
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

    #[test]
    fn signed_hello_rejects_field_and_signature_mutations() {
        let identity = InstallationIdentity::generate();
        let mut hello = ClientHello::signed(identity.device_id, "BMST", "nonce", &identity);
        assert!(hello.has_valid_signature());
        hello.device_name = "forged".to_owned();
        assert!(!hello.has_valid_signature());
        hello.device_name = "BMST".to_owned();
        hello.signature[0] ^= 1;
        assert!(!hello.has_valid_signature());
    }

    #[tokio::test]
    async fn asynchronous_round_trip() {
        let hello =
            WireMessage::ClientHello(ClientHello::new(DeviceId::new(), "BMST", "test-nonce"));
        let (mut left, mut right) = tokio::io::duplex(MAX_FRAME_BYTES + 4);
        let expected = hello.clone();
        let sender = tokio::spawn(async move {
            write_frame_async(&mut left, &hello).await.expect("write");
        });
        let decoded = read_frame_async(&mut right).await.expect("read");
        sender.await.expect("sender task");
        assert_eq!(decoded, expected);
    }
}
