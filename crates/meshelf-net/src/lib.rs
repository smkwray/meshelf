//! Direct, one-message meshelf peer transport.
//!
//! This crate does not contain a permissive production trust policy. `DenyAll` is the safe
//! default; `ExactDeviceAllowList` exists only for loopback simulation and bounded development.

mod destination;
mod fetch_receiver;
mod fetch_sender;
pub use fetch_receiver::{
    FetchActivation, FetchClipboard, FetchReceiver, OfferFetchReceiver, ReservationError,
    ReservationLedger, ReservationPermit, V2FetchReceiver,
};
pub use fetch_sender::{OfferFetchHandler, V2FetchSender};

#[cfg(test)]
use meshelf_core::MAX_OFFER_PORTABLE_COMPONENT_BYTES as MAX_PORTABLE_COMPONENT_BYTES;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr, TcpListener as StdTcpListener},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use meshelf_core::{
    CardAvailability, ClipboardSink, ContentKind, DeviceId, OfferCardInput, OfferCardInsert,
    OfferCardRecord, OfferId, Receipt, ReceiptCode, ReceiveStore, ReceiverService, StoreError,
    TextEnvelope, V2_MAX_LIVE_ENTRIES, validate_component, validate_relative_path,
};
use meshelf_protocol::{
    CAP_FILE_STREAM_V1, CAP_TEXT_SHELF_V1, ClientHello, FileAdmission, FileEntryKind,
    FileTransferOffer, MAX_FILE_BYTES, MAX_FILE_ENTRIES, MAX_FRAME_BYTES, MAX_TRANSFER_BYTES,
    OfferAck, OfferAckCode, OfferAnnouncement, ProtocolError, ServerHello, V2_MAX_INBOUND_HANDLERS,
    V2Message, WireMessage, decode_payload, read_frame_async, read_v2_frame_async,
    validate_v2_message, write_frame_async, write_v2_frame_async,
};
use meshelf_store::RedbV2Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, TryAcquireError, watch},
    time::timeout,
};

#[derive(Debug, Clone)]
pub struct ServerIdentity {
    pub signing_identity: meshelf_identity::InstallationIdentity,
    pub device_name: String,
}

impl ServerIdentity {
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.signing_identity.device_id
    }

    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_identity.public_key().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    Allow,
    Deny(String),
}

pub trait TrustGate: Send + Sync + 'static {
    fn authorize(&self, remote: SocketAddr, hello: &ClientHello) -> TrustDecision;
}

#[derive(Debug, Default)]
pub struct DenyAll;

impl TrustGate for DenyAll {
    fn authorize(&self, _remote: SocketAddr, _hello: &ClientHello) -> TrustDecision {
        TrustDecision::Deny("secure pairing is not configured".to_owned())
    }
}

/// Development/test gate. It validates only the claimed device ID and is not secure pairing.
#[derive(Debug, Clone)]
pub struct ExactDeviceAllowList {
    allowed: HashSet<DeviceId>,
}

impl ExactDeviceAllowList {
    #[must_use]
    pub fn new(allowed: impl IntoIterator<Item = DeviceId>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }
}

impl TrustGate for ExactDeviceAllowList {
    fn authorize(&self, _remote: SocketAddr, hello: &ClientHello) -> TrustDecision {
        if self.allowed.contains(&hello.device_id) {
            TrustDecision::Allow
        } else {
            TrustDecision::Deny("claimed device ID is not in the development allowlist".to_owned())
        }
    }
}

/// Development-only address gate for test scaffolding.
///
/// This is not application authorization: it verifies only a claimed device ID and source
/// address. Production composition must use signed pairing and remains `DenyAll` until then.
#[derive(Debug, Clone, Default)]
pub struct TailnetPeerAllowList {
    allowed: Arc<RwLock<HashMap<DeviceId, HashSet<IpAddr>>>>,
}

impl TailnetPeerAllowList {
    #[must_use]
    pub fn new(
        peers: impl IntoIterator<Item = (DeviceId, impl IntoIterator<Item = IpAddr>)>,
    ) -> Self {
        Self {
            allowed: Arc::new(RwLock::new(
                peers
                    .into_iter()
                    .map(|(device_id, addresses)| (device_id, addresses.into_iter().collect()))
                    .collect(),
            )),
        }
    }

    pub fn replace(
        &self,
        peers: impl IntoIterator<Item = (DeviceId, impl IntoIterator<Item = IpAddr>)>,
    ) {
        let replacement = peers
            .into_iter()
            .map(|(device_id, addresses)| (device_id, addresses.into_iter().collect()))
            .collect();
        if let Ok(mut allowed) = self.allowed.write() {
            *allowed = replacement;
        }
    }
}

impl TrustGate for TailnetPeerAllowList {
    fn authorize(&self, remote: SocketAddr, hello: &ClientHello) -> TrustDecision {
        let Ok(allowed) = self.allowed.read() else {
            return TrustDecision::Deny("tailnet peer registry is unavailable".to_owned());
        };
        match allowed.get(&hello.device_id) {
            Some(addresses) if addresses.contains(&remote.ip()) => TrustDecision::Allow,
            Some(_) => TrustDecision::Deny(
                "accepted meshelf identity arrived from an unrecognized Tailscale address"
                    .to_owned(),
            ),
            None => TrustDecision::Deny("meshelf device has not been accepted".to_owned()),
        }
    }
}

#[async_trait]
pub trait EnvelopeHandler: Send + Sync + 'static {
    async fn handle(&self, envelope: TextEnvelope, now_unix_ms: u64) -> Receipt;
}

#[derive(Debug)]
pub struct CoreEnvelopeHandler<S, C> {
    service: Arc<ReceiverService<S, C>>,
}

impl<S, C> CoreEnvelopeHandler<S, C> {
    #[must_use]
    pub fn new(service: Arc<ReceiverService<S, C>>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl<S, C> EnvelopeHandler for CoreEnvelopeHandler<S, C>
where
    S: ReceiveStore,
    C: ClipboardSink,
{
    async fn handle(&self, envelope: TextEnvelope, now_unix_ms: u64) -> Receipt {
        let service = self.service.clone();
        let message_id = envelope.message_id;
        match tokio::task::spawn_blocking(move || service.receive(envelope, now_unix_ms)).await {
            Ok(receipt) => receipt,
            Err(error) => Receipt::new(
                message_id,
                ReceiptCode::InternalError,
                Some(format!("receiver task failed: {error}")),
            ),
        }
    }
}

/// The receiver-side v2 card operations used by the announcement boundary.
///
/// This small transport-facing trait keeps the network layer on the Step 2 API while leaving
/// redb as the sole persisted card authority. It intentionally exposes no payload or staging
/// operation.
pub trait OfferCardStore: Send + Sync + 'static {
    fn get_offer_card(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
    ) -> Result<Option<OfferCardRecord>, StoreError>;

    fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError>;

    fn insert_offer_card(&self, input: OfferCardInput) -> Result<OfferCardInsert, StoreError>;
}

impl OfferCardStore for RedbV2Store {
    fn get_offer_card(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
    ) -> Result<Option<OfferCardRecord>, StoreError> {
        RedbV2Store::get_offer_card(self, source_device, offer_id)
    }

    fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError> {
        RedbV2Store::read_offer_shelf(self)
    }

    fn insert_offer_card(&self, input: OfferCardInput) -> Result<OfferCardInsert, StoreError> {
        RedbV2Store::insert_offer_card(self, input)
    }
}

/// A v2 announcement receiver. It stores bounded card metadata only; it never opens a source,
/// creates staging, writes a cache, or creates a payload file.
pub struct OfferAnnouncementHandler {
    store: Arc<dyn OfferCardStore>,
    mutation_lock: std::sync::Mutex<()>,
}

impl OfferAnnouncementHandler {
    #[must_use]
    pub fn new(store: Arc<dyn OfferCardStore>) -> Self {
        Self {
            store,
            mutation_lock: std::sync::Mutex::new(()),
        }
    }

    fn live_counts(&self) -> Result<(u32, u32), NetError> {
        let live = self
            .store
            .read_offer_shelf()
            .map_err(|error| NetError::OfferStorage(error.to_string()))?
            .len();
        let live = u32::try_from(live)
            .map_err(|_| NetError::OfferStorage("offer card count exceeds u32".to_owned()))?;
        Ok((live, V2_MAX_LIVE_ENTRIES))
    }

    fn ack(
        offer_id: OfferId,
        code: OfferAckCode,
        live_entries: u32,
        pruned_entries: u32,
        detail: Option<String>,
    ) -> OfferAck {
        OfferAck {
            offer_id,
            code,
            live_entries,
            max_live_entries: V2_MAX_LIVE_ENTRIES,
            pruned_entries,
            detail,
        }
    }

    pub fn handle_sync(
        &self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError> {
        let offer_id = announcement.offer_id;
        let (live_entries, _max_live_entries) = self.live_counts()?;

        if announcement.source_device != authenticated_source {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedInvalid,
                live_entries,
                0,
                Some("source device does not match authenticated client".to_owned()),
            ));
        }
        if announcement.target_device != listener_device {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedInvalid,
                live_entries,
                0,
                Some("target device does not match listener".to_owned()),
            ));
        }
        if let Err(error) = announcement.validate() {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedInvalid,
                live_entries,
                0,
                Some(format!("invalid offer announcement: {error}")),
            ));
        }

        // The count and insert must be one local critical section. The Step 2 store API still
        // supports sender-side oldest-first pruning for its independent source table; receiver
        // announcements must refuse at ten instead of invoking that pruning path.
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| NetError::OfferStorage("offer card lock is poisoned".to_owned()))?;
        let (live_entries, _) = self.live_counts()?;
        if let Some(existing) = self
            .store
            .get_offer_card(authenticated_source, offer_id)
            .map_err(|error| NetError::OfferStorage(error.to_string()))?
        {
            let (code, detail) = if existing.descriptor == announcement.descriptor {
                (OfferAckCode::Duplicate, None)
            } else {
                (
                    OfferAckCode::RefusedConflict,
                    Some("offer ID is already stored with a different descriptor".to_owned()),
                )
            };
            return Ok(Self::ack(offer_id, code, live_entries, 0, detail));
        }
        if live_entries >= V2_MAX_LIVE_ENTRIES {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedCapacity,
                live_entries,
                0,
                Some("receiver offer-card capacity is full".to_owned()),
            ));
        }

        let inserted = self
            .store
            .insert_offer_card(OfferCardInput::new(
                authenticated_source,
                offer_id,
                announcement.descriptor,
                CardAvailability::Available,
            ))
            .map_err(|error| NetError::OfferStorage(error.to_string()))?;
        let live_entries = self.live_counts()?.0;
        let code = if inserted.inserted {
            OfferAckCode::Stored
        } else {
            OfferAckCode::Duplicate
        };
        Ok(Self::ack(
            offer_id,
            code,
            live_entries,
            inserted.purged,
            None,
        ))
    }
}

#[async_trait]
pub trait V2AnnouncementReceiver: Send + Sync + 'static {
    async fn handle_announcement(
        &self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError>;
}

#[async_trait]
impl V2AnnouncementReceiver for OfferAnnouncementHandler {
    async fn handle_announcement(
        &self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError> {
        self.handle_sync(authenticated_source, listener_device, announcement)
    }
}

#[derive(Debug, Clone)]
pub struct PeerClient {
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl Default for PeerClient {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
        }
    }
}

impl PeerClient {
    #[must_use]
    pub const fn with_timeouts(connect_timeout: Duration, io_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            io_timeout,
        }
    }

    /// Discover whether a meshelf listener is present without sending clipboard content.
    ///
    /// A probe intentionally receives the peer's normal server hello even when the peer
    /// rejects the probe under its current trust policy. The caller can therefore display a
    /// pending device for the one-time acceptance flow while the receiver remains deny-by-default.
    pub async fn probe(&self, address: SocketAddr) -> Result<ServerHello, NetError> {
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| NetError::Timeout("probe connect"))??;
        stream.set_nodelay(true)?;

        let probe_device = DeviceId::new();
        let hello = ClientHello::new(probe_device, "meshelf-discovery", probe_device.to_string());
        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write probe hello",
        )
        .await?;

        let response = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read probe response",
        )
        .await?;
        let WireMessage::ServerHello(server_hello) = response else {
            return Err(NetError::UnexpectedMessage("expected server_hello"));
        };
        Ok(server_hello)
    }

    pub async fn push(
        &self,
        address: SocketAddr,
        hello: ClientHello,
        envelope: TextEnvelope,
        expected_server_public_key: &[u8],
    ) -> Result<Receipt, NetError> {
        if hello.device_id != envelope.source_device {
            return Err(NetError::IdentityMismatch(
                "client hello and envelope source differ".to_owned(),
            ));
        }

        let mut stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| NetError::Timeout("connect"))??;
        stream.set_nodelay(true)?;

        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write client hello",
        )
        .await?;

        let server_hello = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read server hello",
        )
        .await?;
        let WireMessage::ServerHello(server_hello) = server_hello else {
            return Err(NetError::UnexpectedMessage("expected server_hello"));
        };
        if !server_hello.has_valid_signature()
            || (!expected_server_public_key.is_empty()
                && server_hello.public_key != expected_server_public_key)
        {
            return Err(NetError::IdentityMismatch(
                "server hello signature or public key is invalid".to_owned(),
            ));
        }
        if server_hello.device_id != envelope.target_device {
            return Err(NetError::IdentityMismatch(
                "server hello does not match envelope target".to_owned(),
            ));
        }
        if !server_hello.accepted {
            return Err(NetError::Rejected(
                server_hello
                    .reason
                    .unwrap_or_else(|| "receiver rejected connection".to_owned()),
            ));
        }
        if !server_hello
            .capabilities
            .iter()
            .any(|capability| capability == CAP_TEXT_SHELF_V1)
        {
            return Err(NetError::Rejected(
                "receiver does not advertise text shelf v1".to_owned(),
            ));
        }

        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::PushEnvelope(envelope.clone())),
            "write envelope",
        )
        .await?;
        let response = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read receipt",
        )
        .await?;
        let WireMessage::Receipt(receipt) = response else {
            return Err(NetError::UnexpectedMessage("expected receipt"));
        };
        if receipt.message_id != envelope.message_id {
            return Err(NetError::IdentityMismatch(
                "receipt message ID does not match request".to_owned(),
            ));
        }
        Ok(receipt)
    }

    /// Announce one metadata-only offer over one authenticated connection.
    ///
    /// This deliberately has no retry or queue path. A connect or I/O failure is returned to the
    /// caller immediately, and the connection is never reused for another operation.
    pub async fn announce_offer(
        &self,
        address: SocketAddr,
        hello: ClientHello,
        announcement: OfferAnnouncement,
        expected_server_public_key: &[u8],
    ) -> Result<OfferAck, NetError> {
        announcement.validate()?;
        if hello.device_id != announcement.source_device {
            return Err(NetError::IdentityMismatch(
                "client hello and offer announcement source differ".to_owned(),
            ));
        }

        let mut stream = match timeout(self.connect_timeout, TcpStream::connect(address)).await {
            Err(_) => {
                return Err(NetError::Unavailable(
                    "announce connect timed out".to_owned(),
                ));
            }
            Ok(Err(error)) => return Err(NetError::Unavailable(error.to_string())),
            Ok(Ok(stream)) => stream,
        };
        stream.set_nodelay(true)?;

        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write announce client hello",
        )
        .await
        .map_err(|error| match error {
            NetError::Io(error) => NetError::Unavailable(error.to_string()),
            NetError::Timeout(operation) => NetError::Unavailable(operation.to_owned()),
            other => other,
        })?;
        let response = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read announce server hello",
        )
        .await
        .map_err(|error| match error {
            NetError::Io(error) => NetError::Unavailable(error.to_string()),
            NetError::Timeout(operation) => NetError::Unavailable(operation.to_owned()),
            other => other,
        })?;
        let WireMessage::ServerHello(server_hello) = response else {
            return Err(NetError::UnexpectedMessage("expected server_hello"));
        };
        if !server_hello.has_valid_signature()
            || (!expected_server_public_key.is_empty()
                && server_hello.public_key != expected_server_public_key)
        {
            return Err(NetError::IdentityMismatch(
                "announcement receiver signature or public key is invalid".to_owned(),
            ));
        }
        if server_hello.device_id != announcement.target_device {
            return Err(NetError::IdentityMismatch(
                "announcement receiver does not match target".to_owned(),
            ));
        }
        if server_hello.protocol_version != meshelf_core::PROTOCOL_VERSION {
            return Err(NetError::Rejected(
                "announcement receiver uses an unsupported protocol version".to_owned(),
            ));
        }
        if !server_hello.accepted {
            return Err(NetError::Rejected(server_hello.reason.unwrap_or_else(
                || "announcement receiver rejected connection".to_owned(),
            )));
        }

        io_timeout(
            self.io_timeout,
            write_v2_frame_async(
                &mut stream,
                &V2Message::OfferAnnouncement(announcement.clone()),
            ),
            "write offer announcement",
        )
        .await?;
        let response = io_timeout(
            self.io_timeout,
            read_v2_frame_async(&mut stream),
            "read offer acknowledgement",
        )
        .await?;
        validate_v2_message(&response)?;
        let V2Message::OfferAck(ack) = response else {
            return Err(NetError::UnexpectedMessage("expected offer_ack"));
        };
        if ack.offer_id != announcement.offer_id {
            return Err(NetError::IdentityMismatch(
                "offer acknowledgement ID does not match announcement".to_owned(),
            ));
        }
        Ok(ack)
    }

    pub async fn push_file_transfer(
        &self,
        address: SocketAddr,
        hello: ClientHello,
        offer: FileTransferOffer,
        source_files: Vec<PathBuf>,
        expected_server_public_key: &[u8],
    ) -> Result<Receipt, NetError> {
        if hello.device_id != offer.source_device {
            return Err(NetError::IdentityMismatch(
                "client hello and file offer source differ".to_owned(),
            ));
        }
        validate_file_offer(&offer).map_err(NetError::FileTransfer)?;
        let expected_files = offer
            .entries
            .iter()
            .filter(|entry| entry.kind == FileEntryKind::File)
            .count();
        if expected_files != source_files.len() {
            return Err(NetError::FileTransfer(
                "file offer and local source count differ".to_owned(),
            ));
        }

        let mut stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| NetError::Timeout("file connect"))??;
        stream.set_nodelay(true)?;
        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write file client hello",
        )
        .await?;
        let response = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read file server hello",
        )
        .await?;
        let WireMessage::ServerHello(server_hello) = response else {
            return Err(NetError::UnexpectedMessage("expected server_hello"));
        };
        if !server_hello.has_valid_signature()
            || (!expected_server_public_key.is_empty()
                && server_hello.public_key != expected_server_public_key)
        {
            return Err(NetError::IdentityMismatch(
                "file receiver signature or public key is invalid".to_owned(),
            ));
        }
        if server_hello.device_id != offer.target_device {
            return Err(NetError::IdentityMismatch(
                "file receiver does not match offer target".to_owned(),
            ));
        }
        if !server_hello.accepted {
            return Err(NetError::Rejected(
                server_hello
                    .reason
                    .unwrap_or_else(|| "file receiver rejected connection".to_owned()),
            ));
        }
        if !server_hello
            .capabilities
            .iter()
            .any(|capability| capability == CAP_FILE_STREAM_V1)
        {
            return Err(NetError::Rejected(
                "receiver does not advertise file stream v1".to_owned(),
            ));
        }

        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::FileOffer(offer.clone())),
            "write file offer",
        )
        .await?;
        let admission = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read file admission",
        )
        .await?;
        let WireMessage::FileAdmission(admission) = admission else {
            return Err(NetError::UnexpectedMessage("expected file_admission"));
        };
        if admission.transfer_id != offer.transfer_id {
            return Err(NetError::IdentityMismatch(
                "file admission transfer ID differs".to_owned(),
            ));
        }
        if !admission.accepted {
            return Err(NetError::Rejected(
                admission
                    .detail
                    .unwrap_or_else(|| "file offer was refused".to_owned()),
            ));
        }

        if !admission.already_complete {
            let mut sources = source_files.into_iter();
            for entry in offer
                .entries
                .iter()
                .filter(|entry| entry.kind == FileEntryKind::File)
            {
                let path = sources
                    .next()
                    .ok_or_else(|| NetError::FileTransfer("missing local source".to_owned()))?;
                send_file_bytes(&mut stream, &path, entry, self.io_timeout).await?;
            }
        }

        let response = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read file receipt",
        )
        .await?;
        let WireMessage::Receipt(receipt) = response else {
            return Err(NetError::UnexpectedMessage("expected file receipt"));
        };
        if receipt.message_id != offer.transfer_id {
            return Err(NetError::IdentityMismatch(
                "file receipt transfer ID differs".to_owned(),
            ));
        }
        Ok(receipt)
    }

    /// Open one authenticated receiver-initiated pull. The receiver-side activation is supplied
    /// by the caller before this method is called; announcements never invoke it.
    pub async fn fetch<C>(
        &self,
        address: SocketAddr,
        hello: ClientHello,
        request: meshelf_protocol::FetchRequest,
        activation: FetchActivation,
        expected_server_public_key: &[u8],
        receiver: &FetchReceiver<C>,
    ) -> Result<(), NetError>
    where
        C: FetchClipboard,
    {
        let requester_device = hello.device_id;
        if hello.device_id != request.requester_device
            || activation.request_id != request.request_id
            || activation.source_device != request.source_device
            || activation.offer_id != request.offer_id
        {
            return Err(NetError::IdentityMismatch(
                "fetch request, activation, and client identity differ".to_owned(),
            ));
        }
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| NetError::Timeout("fetch connect"))??;
        stream.set_nodelay(true)?;
        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write fetch client hello",
        )
        .await?;
        let response = io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read fetch server hello",
        )
        .await?;
        let WireMessage::ServerHello(server_hello) = response else {
            return Err(NetError::UnexpectedMessage("expected server_hello"));
        };
        if !server_hello.has_valid_signature()
            || (!expected_server_public_key.is_empty()
                && server_hello.public_key != expected_server_public_key)
        {
            return Err(NetError::IdentityMismatch(
                "fetch server hello signature or public key is invalid".to_owned(),
            ));
        }
        if server_hello.device_id != request.source_device {
            return Err(NetError::IdentityMismatch(
                "fetch server hello does not match source device".to_owned(),
            ));
        }
        if !server_hello.accepted {
            return Err(NetError::Rejected(
                server_hello
                    .reason
                    .unwrap_or_else(|| "fetch server rejected connection".to_owned()),
            ));
        }
        io_timeout(
            self.io_timeout,
            write_v2_frame_async(&mut stream, &V2Message::FetchRequest(request)),
            "write fetch request",
        )
        .await?;
        receiver
            .receive(requester_device, activation, &mut stream, self.io_timeout)
            .await
    }
}

async fn send_file_bytes(
    stream: &mut TcpStream,
    path: &Path,
    entry: &meshelf_protocol::FileTransferEntry,
    io_timeout_duration: Duration,
) -> Result<(), NetError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut remaining = entry.byte_len;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = file.read(&mut buffer[..wanted]).await?;
        if read == 0 {
            return Err(NetError::FileTransfer(format!(
                "{} changed or ended during transfer",
                path.display()
            )));
        }
        hasher.update(&buffer[..read]);
        timeout(io_timeout_duration, stream.write_all(&buffer[..read]))
            .await
            .map_err(|_| NetError::Timeout("write file bytes"))??;
        remaining = remaining.saturating_sub(read as u64);
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra).await? != 0 {
        return Err(NetError::FileTransfer(format!(
            "{} grew during transfer",
            path.display()
        )));
    }
    if hasher.finalize().as_slice() != entry.sha256.as_slice() {
        return Err(NetError::FileTransfer(format!(
            "{} changed after its manifest was prepared",
            path.display()
        )));
    }
    Ok(())
}

pub fn validate_file_offer(offer: &FileTransferOffer) -> Result<(), String> {
    if offer.protocol_version != meshelf_core::PROTOCOL_VERSION {
        return Err("unsupported file-transfer protocol version".to_owned());
    }
    if !matches!(offer.content_kind, ContentKind::File | ContentKind::Folder) {
        return Err("file offer kind must be file or folder".to_owned());
    }
    validate_component(&offer.root_name)?;
    if offer.entries.len() > MAX_FILE_ENTRIES {
        return Err(format!(
            "file offer contains {} entries; maximum is {MAX_FILE_ENTRIES}",
            offer.entries.len()
        ));
    }
    if offer.content_kind == ContentKind::File && offer.entries.len() != 1 {
        return Err("a file offer must contain exactly one entry".to_owned());
    }
    if offer.content_kind == ContentKind::File && offer.entries[0].relative_path != offer.root_name
    {
        return Err("a file offer entry must match its root name".to_owned());
    }
    let mut total = 0_u64;
    let mut seen = HashSet::new();
    for entry in &offer.entries {
        validate_relative_path(&entry.relative_path)?;
        if !seen.insert(entry.relative_path.to_ascii_lowercase()) {
            return Err(format!("duplicate file path: {}", entry.relative_path));
        }
        match entry.kind {
            FileEntryKind::Directory => {
                if entry.byte_len != 0 || !entry.sha256.is_empty() {
                    return Err("directory entries cannot contain bytes or a hash".to_owned());
                }
            }
            FileEntryKind::File => {
                if entry.byte_len > MAX_FILE_BYTES {
                    return Err(format!(
                        "{} is {} bytes; per-file maximum is {MAX_FILE_BYTES}",
                        entry.relative_path, entry.byte_len
                    ));
                }
                if entry.sha256.len() != 32 {
                    return Err(format!(
                        "{} does not contain a SHA-256 hash",
                        entry.relative_path
                    ));
                }
                total = total
                    .checked_add(entry.byte_len)
                    .ok_or_else(|| "file-transfer size overflow".to_owned())?;
            }
        }
    }
    if total != offer.total_bytes {
        return Err("file offer total does not match its entries".to_owned());
    }
    if total > MAX_TRANSFER_BYTES {
        return Err(format!(
            "transfer is {total} bytes; maximum is {MAX_TRANSFER_BYTES}"
        ));
    }
    Ok(())
}

pub async fn serve<G, H>(
    listener: TcpListener,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
    io_timeout_duration: Duration,
    shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
    serve_inner(
        listener,
        ServerContext {
            identity,
            gate,
            handler,
            incoming_directory: None,
            offer_receiver: None,
            fetch_sender: None,
            io_timeout_duration,
        },
        shutdown,
    )
    .await
}

pub async fn serve_with_files<G, H>(
    listener: TcpListener,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
    incoming_directory: PathBuf,
    io_timeout_duration: Duration,
    shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
    serve_inner(
        listener,
        ServerContext {
            identity,
            gate,
            handler,
            incoming_directory: Some(incoming_directory),
            offer_receiver: None,
            fetch_sender: None,
            io_timeout_duration,
        },
        shutdown,
    )
    .await
}

/// Serve the existing v1 operations and the additive, unadvertised v2 announcement operation.
///
/// The v2 receiver is deliberately opt-in at the composition boundary. It does not alter the
/// v1 capability list or select v2 for existing clients.
pub async fn serve_with_offers<G, H>(
    listener: TcpListener,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
    offer_receiver: Arc<dyn V2AnnouncementReceiver>,
    io_timeout_duration: Duration,
    shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
    serve_inner(
        listener,
        ServerContext {
            identity,
            gate,
            handler,
            incoming_directory: None,
            offer_receiver: Some(offer_receiver),
            fetch_sender: None,
            io_timeout_duration,
        },
        shutdown,
    )
    .await
}

/// Serve the existing v1 operations, the additive announcement operation, and the origin half of
/// the v2 fetch operation. The v2 capability remains intentionally absent from the hello.
pub struct V2OfferServices {
    pub announcement_receiver: Arc<dyn V2AnnouncementReceiver>,
    pub fetch_sender: Arc<dyn V2FetchSender>,
}

pub async fn serve_with_offers_and_fetch<G, H>(
    listener: TcpListener,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
    services: V2OfferServices,
    io_timeout_duration: Duration,
    shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
    serve_inner(
        listener,
        ServerContext {
            identity,
            gate,
            handler,
            incoming_directory: None,
            offer_receiver: Some(services.announcement_receiver),
            fetch_sender: Some(services.fetch_sender),
            io_timeout_duration,
        },
        shutdown,
    )
    .await
}

struct ServerContext<G, H> {
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
    incoming_directory: Option<PathBuf>,
    offer_receiver: Option<Arc<dyn V2AnnouncementReceiver>>,
    fetch_sender: Option<Arc<dyn V2FetchSender>>,
    io_timeout_duration: Duration,
}

impl<G, H> Clone for ServerContext<G, H> {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            gate: self.gate.clone(),
            handler: self.handler.clone(),
            incoming_directory: self.incoming_directory.clone(),
            offer_receiver: self.offer_receiver.clone(),
            fetch_sender: self.fetch_sender.clone(),
            io_timeout_duration: self.io_timeout_duration,
        }
    }
}

async fn serve_inner<G, H>(
    listener: TcpListener,
    context: ServerContext<G, H>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
    let handler_limit = Arc::new(Semaphore::new(
        usize::try_from(V2_MAX_INBOUND_HANDLERS).expect("handler limit fits usize"),
    ));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            accepted = listener.accept() => {
                let (stream, remote) = accepted?;
                let permit = match handler_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(TryAcquireError::NoPermits) => {
                        let active = V2_MAX_INBOUND_HANDLERS.saturating_sub(
                            u32::try_from(handler_limit.available_permits()).unwrap_or(0),
                        );
                        refuse_excess_connection(
                            stream,
                            context.identity.clone(),
                            context.incoming_directory.is_some(),
                            active,
                            context.io_timeout_duration,
                        ).await?;
                        continue;
                    }
                    Err(TryAcquireError::Closed) => {
                        return Err(NetError::HandlerLimitClosed);
                    }
                };
                let context = context.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_connection(stream, remote, context).await {
                        tracing::warn!(remote = %remote, error = %error, "meshelf peer connection failed");
                    }
                });
            }
        }
    }
}

pub async fn bind_discovered_tailscale_address(
    address: SocketAddr,
    discovered_local_addresses: &[IpAddr],
) -> Result<TcpListener, NetError> {
    let listener = bind_discovered_tailscale_std_listener(address, discovered_local_addresses)?;
    Ok(TcpListener::from_std(listener)?)
}

/// Bind a nonblocking production listener without attaching it to a Tokio runtime.
///
/// Desktop composition creates the socket before its network thread starts, then converts it to
/// a Tokio listener inside the long-lived server runtime. A Tokio listener must not be created in
/// a temporary runtime and moved after that runtime is dropped.
pub fn bind_discovered_tailscale_std_listener(
    address: SocketAddr,
    discovered_local_addresses: &[IpAddr],
) -> Result<StdTcpListener, NetError> {
    if address.ip().is_unspecified() {
        return Err(NetError::UnsafeBind(
            "unspecified listener addresses are forbidden".to_owned(),
        ));
    }
    if !discovered_local_addresses.contains(&address.ip()) {
        return Err(NetError::UnsafeBind(
            "listener address is not one of the currently discovered local Tailscale addresses"
                .to_owned(),
        ));
    }
    let listener = StdTcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

async fn refuse_excess_connection(
    mut stream: TcpStream,
    identity: ServerIdentity,
    has_file_receiver: bool,
    active: u32,
    io_timeout_duration: Duration,
) -> Result<(), NetError> {
    stream.set_nodelay(true)?;
    let mut capabilities = vec![CAP_TEXT_SHELF_V1.to_owned()];
    if has_file_receiver {
        capabilities.push(CAP_FILE_STREAM_V1.to_owned());
    }
    let reason = format!(
        "inbound handler capacity exhausted: active={active}, maximum={V2_MAX_INBOUND_HANDLERS}"
    );
    let server_hello = WireMessage::ServerHello(ServerHello::signed(
        meshelf_core::PROTOCOL_VERSION,
        identity.device_id(),
        identity.device_name,
        false,
        Some(reason),
        capabilities,
        &identity.signing_identity,
    ));
    io_timeout(
        io_timeout_duration,
        write_frame_async(&mut stream, &server_hello),
        "write handler-capacity refusal",
    )
    .await
}

async fn handle_connection<G, H>(
    mut stream: TcpStream,
    remote: SocketAddr,
    context: ServerContext<G, H>,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
    stream.set_nodelay(true)?;
    let first = io_timeout(
        context.io_timeout_duration,
        read_frame_async(&mut stream),
        "read client hello",
    )
    .await?;
    let WireMessage::ClientHello(hello) = first else {
        return Err(NetError::UnexpectedMessage("expected client_hello"));
    };

    let protocol_ok = hello.protocol_version == meshelf_core::PROTOCOL_VERSION;
    let trust = if protocol_ok && hello.has_valid_signature() {
        context.gate.authorize(remote, &hello)
    } else if protocol_ok {
        TrustDecision::Deny("client hello signature is invalid".to_owned())
    } else {
        TrustDecision::Deny(format!(
            "unsupported protocol version {}",
            hello.protocol_version
        ))
    };
    let (accepted, reason) = match trust {
        TrustDecision::Allow => (true, None),
        TrustDecision::Deny(reason) => (false, Some(reason)),
    };
    let mut capabilities = vec![CAP_TEXT_SHELF_V1.to_owned()];
    if context.incoming_directory.is_some() {
        capabilities.push(CAP_FILE_STREAM_V1.to_owned());
    }
    let server_hello = WireMessage::ServerHello(ServerHello::signed(
        meshelf_core::PROTOCOL_VERSION,
        context.identity.device_id(),
        context.identity.device_name.clone(),
        accepted,
        reason,
        capabilities,
        &context.identity.signing_identity,
    ));
    io_timeout(
        context.io_timeout_duration,
        write_frame_async(&mut stream, &server_hello),
        "write server hello",
    )
    .await?;
    if !accepted {
        return Ok(());
    }

    let payload = io_timeout(
        context.io_timeout_duration,
        read_raw_frame_async(&mut stream),
        "read envelope",
    )
    .await?;
    if let Ok(v2_message) = serde_json::from_slice::<V2Message>(&payload) {
        match v2_message {
            V2Message::OfferAnnouncement(announcement) => {
                let Some(offer_receiver) = context.offer_receiver.as_ref() else {
                    return Err(NetError::UnexpectedMessage(
                        "v2 offer announcements are not configured",
                    ));
                };
                let ack = offer_receiver
                    .handle_announcement(
                        hello.device_id,
                        context.identity.device_id(),
                        announcement,
                    )
                    .await?;
                io_timeout(
                    context.io_timeout_duration,
                    write_v2_frame_async(&mut stream, &V2Message::OfferAck(ack)),
                    "write offer acknowledgement",
                )
                .await?;
                return Ok(());
            }
            V2Message::FetchRequest(request) => {
                let Some(fetch_sender) = context.fetch_sender.as_ref() else {
                    return Err(NetError::UnexpectedMessage(
                        "v2 fetch serving is not configured",
                    ));
                };
                fetch_sender
                    .handle_fetch(
                        hello.device_id,
                        request,
                        &mut stream,
                        context.io_timeout_duration,
                    )
                    .await?;
                return Ok(());
            }
            _ => {
                return Err(NetError::UnexpectedMessage(
                    "unsupported v2 operation; announcement and fetch request are enabled",
                ));
            }
        }
    }
    let message = decode_payload(&payload)?;
    let WireMessage::PushEnvelope(envelope) = message else {
        if let WireMessage::FileOffer(offer) = message {
            let Some(incoming_directory) = context.incoming_directory else {
                return Err(NetError::FileTransfer(
                    "file receiving is not configured".to_owned(),
                ));
            };
            return handle_file_offer(
                &mut stream,
                &hello,
                context.identity.device_id(),
                offer,
                &incoming_directory,
                context.handler,
                context.io_timeout_duration,
            )
            .await;
        }
        return Err(NetError::UnexpectedMessage(
            "expected push_envelope or file_offer",
        ));
    };
    if envelope.source_device != hello.device_id {
        let receipt = Receipt::rejected(
            envelope.message_id,
            ReceiptCode::RejectedUnauthorized,
            "authenticated hello identity and envelope source differ",
        );
        io_timeout(
            context.io_timeout_duration,
            write_frame_async(&mut stream, &WireMessage::Receipt(receipt)),
            "write rejection receipt",
        )
        .await?;
        return Ok(());
    }
    if envelope.target_device != context.identity.device_id() {
        let receipt = Receipt::rejected(
            envelope.message_id,
            ReceiptCode::RejectedWrongTarget,
            "message target does not match listener device",
        );
        io_timeout(
            context.io_timeout_duration,
            write_frame_async(&mut stream, &WireMessage::Receipt(receipt)),
            "write wrong-target receipt",
        )
        .await?;
        return Ok(());
    }

    let receipt = context.handler.handle(envelope, now_unix_ms()).await;
    io_timeout(
        context.io_timeout_duration,
        write_frame_async(&mut stream, &WireMessage::Receipt(receipt)),
        "write receipt",
    )
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompletedTransfer {
    final_path: String,
    content_kind: ContentKind,
}

async fn handle_file_offer<H>(
    stream: &mut TcpStream,
    hello: &ClientHello,
    local_device: DeviceId,
    offer: FileTransferOffer,
    incoming_directory: &Path,
    handler: Arc<H>,
    io_timeout_duration: Duration,
) -> Result<(), NetError>
where
    H: EnvelopeHandler,
{
    let transfer_id = offer.transfer_id;
    if offer.source_device != hello.device_id || offer.target_device != local_device {
        return send_file_admission(
            stream,
            transfer_id,
            false,
            false,
            Some("authenticated source or target does not match the file offer".to_owned()),
            io_timeout_duration,
        )
        .await;
    }
    if let Err(error) = validate_file_offer(&offer) {
        return send_file_admission(
            stream,
            transfer_id,
            false,
            false,
            Some(error),
            io_timeout_duration,
        )
        .await;
    }

    tokio::fs::create_dir_all(incoming_directory).await?;
    let completed_directory = incoming_directory.join(".meshelf-completed");
    tokio::fs::create_dir_all(&completed_directory).await?;
    let completed_path = completed_directory.join(format!("{transfer_id}.json"));
    if let Ok(bytes) = tokio::fs::read(&completed_path).await
        && let Ok(completed) = serde_json::from_slice::<CompletedTransfer>(&bytes)
        && Path::new(&completed.final_path).starts_with(incoming_directory)
        && tokio::fs::try_exists(&completed.final_path)
            .await
            .unwrap_or(false)
    {
        send_file_admission(
            stream,
            transfer_id,
            true,
            true,
            Some(completed.final_path.clone()),
            io_timeout_duration,
        )
        .await?;
        let receipt = Receipt::new(transfer_id, ReceiptCode::Stored, Some(completed.final_path));
        io_timeout(
            io_timeout_duration,
            write_frame_async(stream, &WireMessage::Receipt(receipt)),
            "write completed file receipt",
        )
        .await?;
        return Ok(());
    }

    let available = fs2::available_space(incoming_directory)?;
    let required = offer.total_bytes.saturating_add(64 * 1024 * 1024);
    if available < required {
        return send_file_admission(
            stream,
            transfer_id,
            false,
            false,
            Some(format!(
                "receiver has {available} bytes free; transfer requires {required}"
            )),
            io_timeout_duration,
        )
        .await;
    }

    let partials_directory = incoming_directory.join(".meshelf-partials");
    tokio::fs::create_dir_all(&partials_directory).await?;
    let partial_directory = partials_directory.join(transfer_id.to_string());
    if tokio::fs::try_exists(&partial_directory)
        .await
        .unwrap_or(false)
    {
        tokio::fs::remove_dir_all(&partial_directory).await?;
    }
    tokio::fs::create_dir(&partial_directory).await?;

    send_file_admission(stream, transfer_id, true, false, None, io_timeout_duration).await?;

    let payload = partial_directory.join("payload");
    if offer.content_kind == ContentKind::Folder {
        tokio::fs::create_dir(&payload).await?;
    }
    let receive_result = receive_file_bytes(
        stream,
        &offer,
        &payload,
        io_timeout_duration.max(Duration::from_secs(30)),
    )
    .await;
    if let Err(error) = receive_result {
        let _ = tokio::fs::remove_dir_all(&partial_directory).await;
        let receipt = Receipt::rejected(
            transfer_id,
            ReceiptCode::RejectedInvalid,
            format!("file transfer failed: {error}"),
        );
        io_timeout(
            io_timeout_duration,
            write_frame_async(stream, &WireMessage::Receipt(receipt)),
            "write failed file receipt",
        )
        .await?;
        return Ok(());
    }

    let final_path = match finalize_payload_without_overwrite(
        &payload,
        incoming_directory,
        &offer.root_name,
        offer.content_kind,
    )
    .await
    {
        Ok(path) => path,
        Err(error) => {
            let _ = tokio::fs::remove_dir_all(&partial_directory).await;
            return Err(error);
        }
    };
    let _ = tokio::fs::remove_dir_all(&partial_directory).await;

    let now = now_unix_ms();
    let envelope = TextEnvelope::shelf_item_with_id(
        transfer_id,
        offer.source_device,
        offer.target_device,
        now,
        None,
        offer.content_kind,
        final_path.to_string_lossy(),
    );
    let receipt = handler.handle(envelope, now).await;
    if receipt.code == ReceiptCode::Stored {
        let completed = serde_json::to_vec(&CompletedTransfer {
            final_path: final_path.to_string_lossy().into_owned(),
            content_kind: offer.content_kind,
        })
        .map_err(|error| NetError::FileTransfer(error.to_string()))?;
        tokio::fs::write(&completed_path, completed).await?;
    }
    io_timeout(
        io_timeout_duration,
        write_frame_async(stream, &WireMessage::Receipt(receipt)),
        "write file receipt",
    )
    .await?;
    Ok(())
}

async fn send_file_admission(
    stream: &mut TcpStream,
    transfer_id: meshelf_core::MessageId,
    accepted: bool,
    already_complete: bool,
    detail: Option<String>,
    io_timeout_duration: Duration,
) -> Result<(), NetError> {
    let admission = FileAdmission {
        transfer_id,
        accepted,
        already_complete,
        detail,
    };
    io_timeout(
        io_timeout_duration,
        write_frame_async(stream, &WireMessage::FileAdmission(admission)),
        "write file admission",
    )
    .await
}

async fn receive_file_bytes(
    stream: &mut TcpStream,
    offer: &FileTransferOffer,
    payload: &Path,
    io_timeout_duration: Duration,
) -> Result<(), String> {
    let mut buffer = vec![0_u8; 64 * 1024];
    for entry in &offer.entries {
        let destination = if offer.content_kind == ContentKind::File {
            payload.to_path_buf()
        } else {
            payload.join(relative_path(&entry.relative_path))
        };
        match entry.kind {
            FileEntryKind::Directory => {
                tokio::fs::create_dir_all(&destination)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            FileEntryKind::File => {
                if let Some(parent) = destination.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .await
                    .map_err(|error| error.to_string())?;
                let mut remaining = entry.byte_len;
                let mut hasher = Sha256::new();
                while remaining > 0 {
                    let wanted =
                        usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                    let read = timeout(io_timeout_duration, stream.read(&mut buffer[..wanted]))
                        .await
                        .map_err(|_| "timed out reading file bytes".to_owned())?
                        .map_err(|error| error.to_string())?;
                    if read == 0 {
                        return Err("sender disconnected before the file completed".to_owned());
                    }
                    hasher.update(&buffer[..read]);
                    file.write_all(&buffer[..read])
                        .await
                        .map_err(|error| error.to_string())?;
                    remaining = remaining.saturating_sub(read as u64);
                }
                file.sync_all().await.map_err(|error| error.to_string())?;
                if hasher.finalize().as_slice() != entry.sha256.as_slice() {
                    return Err(format!("hash mismatch for {}", entry.relative_path));
                }
            }
        }
    }
    Ok(())
}

async fn finalize_payload_without_overwrite(
    payload: &Path,
    directory: &Path,
    root_name: &str,
    content_kind: ContentKind,
) -> Result<PathBuf, NetError> {
    destination::finalize_payload_without_overwrite(payload, directory, root_name, content_kind)
        .await
}

#[cfg(test)]
fn collision_candidate(
    directory: &Path,
    root_name: &str,
    content_kind: ContentKind,
    index: usize,
) -> Result<PathBuf, NetError> {
    destination::collision_candidate(directory, root_name, content_kind, index)
}

#[cfg(test)]
fn component_with_suffix(component: &str, suffix: &str) -> Result<String, NetError> {
    destination::component_with_suffix(component, suffix)
}

#[cfg(test)]
fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    destination::truncate_utf8(value, max_bytes)
}

fn relative_path(value: &str) -> PathBuf {
    destination::relative_path(value)
}

async fn io_timeout<T>(
    duration: Duration,
    future: impl std::future::Future<Output = Result<T, ProtocolError>>,
    operation: &'static str,
) -> Result<T, NetError> {
    timeout(duration, future)
        .await
        .map_err(|_| NetError::Timeout(operation))?
        .map_err(NetError::Protocol)
}

/// Read one existing-protocol frame without choosing a wire enum first. The post-handshake
/// server path uses this to distinguish an additive v2 announcement from an existing v1 message;
/// it keeps the v1 frame ceiling and never allocates based on an unchecked length.
async fn read_raw_frame_async<R>(reader: &mut R) -> Result<Vec<u8>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            bytes: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

fn now_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[derive(Debug, Error)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("operation timed out during {0}")]
    Timeout(&'static str),
    #[error("peer rejected connection: {0}")]
    Rejected(String),
    #[error("peer unavailable: {0}")]
    Unavailable(String),
    #[error("unexpected wire message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("identity mismatch: {0}")]
    IdentityMismatch(String),
    #[error("unsafe bind refused: {0}")]
    UnsafeBind(String),
    #[error("file transfer failed: {0}")]
    FileTransfer(String),
    #[error("offer card storage failed: {0}")]
    OfferStorage(String),
    #[error("fetch service failed: {0}")]
    FetchService(&'static str),
    #[error("fetch service failed: {0}")]
    FetchServiceOwned(String),
    #[error("inbound handler limit was closed")]
    HandlerLimitClosed,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fs,
        path::{Path, PathBuf},
        sync::{Arc, Barrier, Mutex},
    };

    use meshelf_core::{
        ActivationId, ClipboardError, ClipboardSink, MemoryReceiveStore, OfferDescriptor,
        OfferSource, OfferSourceInput, ReceiptCode, ReceiveStore, ReceiverService,
    };
    use meshelf_protocol::{
        ClientHello, FetchAbortCode, FetchReceipt, FetchRefusal, FetchRefusalCode, FetchRequest,
        ManifestEntry, V2_MAX_MANIFEST_BYTES,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;

    use super::*;

    /// Loopback tests assert data preservation, not latency. Two seconds was tight enough that
    /// the folder-stream test timed out only when the whole workspace suite ran in parallel on a
    /// loaded machine, which turns a real failure into something easy to dismiss as flake.
    const TEST_IO_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Debug, Default)]
    struct TestClipboard(Mutex<Vec<String>>);

    impl ClipboardSink for TestClipboard {
        fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
            self.0
                .lock()
                .expect("clipboard mutex")
                .push(text.to_owned());
            Ok(())
        }
    }

    async fn start_offer_server(
        allowed_devices: impl IntoIterator<Item = DeviceId>,
    ) -> (
        tempfile::TempDir,
        SocketAddr,
        meshelf_identity::InstallationIdentity,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), NetError>>,
        Arc<RedbV2Store>,
    ) {
        let directory = tempfile::tempdir().expect("temporary offer directory");
        let store = Arc::new(
            RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
        );
        let target_identity = meshelf_identity::InstallationIdentity::generate();
        let target = target_identity.device_id;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let receiver = Arc::new(ReceiverService::new(
            target,
            Arc::new(MemoryReceiveStore::new()),
            Arc::new(TestClipboard::default()),
        ));
        let handler = Arc::new(CoreEnvelopeHandler::new(receiver));
        let offer_receiver: Arc<dyn V2AnnouncementReceiver> =
            Arc::new(OfferAnnouncementHandler::new(store.clone()));
        let server = tokio::spawn(serve_with_offers(
            listener,
            ServerIdentity {
                signing_identity: target_identity.clone(),
                device_name: "BZOT".to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new(allowed_devices)),
            handler,
            offer_receiver,
            TEST_IO_TIMEOUT,
            shutdown_rx,
        ));
        (
            directory,
            address,
            target_identity,
            shutdown_tx,
            server,
            store,
        )
    }

    async fn stop_offer_server(
        shutdown_tx: watch::Sender<bool>,
        server: tokio::task::JoinHandle<Result<(), NetError>>,
    ) {
        shutdown_tx.send(true).expect("request shutdown");
        server.await.expect("server task").expect("clean server");
    }

    async fn start_fetch_server(
        allowed_devices: impl IntoIterator<Item = DeviceId>,
    ) -> (
        tempfile::TempDir,
        SocketAddr,
        meshelf_identity::InstallationIdentity,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), NetError>>,
        Arc<RedbV2Store>,
    ) {
        let directory = tempfile::tempdir().expect("temporary fetch directory");
        let store = Arc::new(
            RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
        );
        let origin_identity = meshelf_identity::InstallationIdentity::generate();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let receiver = Arc::new(ReceiverService::new(
            origin_identity.device_id,
            Arc::new(MemoryReceiveStore::new()),
            Arc::new(TestClipboard::default()),
        ));
        let handler = Arc::new(CoreEnvelopeHandler::new(receiver));
        let offer_receiver: Arc<dyn V2AnnouncementReceiver> =
            Arc::new(OfferAnnouncementHandler::new(store.clone()));
        let fetch_sender: Arc<dyn V2FetchSender> = Arc::new(OfferFetchHandler::new(
            origin_identity.device_id,
            store.clone(),
        ));
        let server = tokio::spawn(serve_with_offers_and_fetch(
            listener,
            ServerIdentity {
                signing_identity: origin_identity.clone(),
                device_name: "BMST".to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new(allowed_devices)),
            handler,
            V2OfferServices {
                announcement_receiver: offer_receiver,
                fetch_sender,
            },
            TEST_IO_TIMEOUT,
            shutdown_rx,
        ));
        (
            directory,
            address,
            origin_identity,
            shutdown_tx,
            server,
            store,
        )
    }

    fn insert_text_source(
        store: &RedbV2Store,
        requester: DeviceId,
        offer_id: OfferId,
        text: &str,
    ) -> OfferDescriptor {
        let descriptor = OfferDescriptor::text(text).expect("text descriptor");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor.clone(),
                HashSet::from([requester]),
                OfferSource::Text {
                    text: text.to_owned(),
                },
            ))
            .expect("insert text source");
        descriptor
    }

    fn insert_file_source(
        store: &RedbV2Store,
        requester: DeviceId,
        offer_id: OfferId,
        path: &Path,
    ) -> OfferDescriptor {
        let root_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("file root name")
            .to_owned();
        let total_bytes = fs::metadata(path).expect("file metadata").len();
        let descriptor = OfferDescriptor::File {
            root_name: root_name.clone(),
            total_bytes,
        };
        let commitment =
            fetch_sender::metadata_commitment_for_test(path, &descriptor).expect("file commitment");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor.clone(),
                HashSet::from([requester]),
                OfferSource::File {
                    canonical_path: fs::canonicalize(path).expect("canonical file"),
                    metadata_commitment: commitment,
                },
            ))
            .expect("insert file source");
        descriptor
    }

    fn insert_folder_source(
        store: &RedbV2Store,
        requester: DeviceId,
        offer_id: OfferId,
        path: &Path,
    ) -> OfferDescriptor {
        let root_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("folder root name")
            .to_owned();
        let mut total_bytes = 0_u64;
        let mut entry_count = 0_u32;
        let mut file_count = 0_u32;
        let mut directory_count = 0_u32;
        let mut pending = vec![path.to_owned()];
        while let Some(directory) = pending.pop() {
            for child in fs::read_dir(directory).expect("read folder") {
                let child = child.expect("folder entry");
                let metadata = child.metadata().expect("folder metadata");
                entry_count = entry_count.saturating_add(1);
                if metadata.is_dir() {
                    directory_count = directory_count.saturating_add(1);
                    pending.push(child.path());
                } else {
                    file_count = file_count.saturating_add(1);
                    total_bytes = total_bytes.saturating_add(metadata.len());
                }
            }
        }
        let descriptor = OfferDescriptor::Folder {
            root_name: root_name.clone(),
            total_bytes,
            entry_count,
            file_count,
            directory_count,
        };
        let commitment = fetch_sender::metadata_commitment_for_test(path, &descriptor)
            .expect("folder commitment");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor.clone(),
                HashSet::from([requester]),
                OfferSource::Folder {
                    canonical_path: fs::canonicalize(path).expect("canonical folder"),
                    metadata_commitment: commitment,
                },
            ))
            .expect("insert folder source");
        descriptor
    }

    async fn connect_fetch(
        address: SocketAddr,
        requester_identity: &meshelf_identity::InstallationIdentity,
        origin_identity: &meshelf_identity::InstallationIdentity,
        request: FetchRequest,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.expect("connect fetch");
        stream.set_nodelay(true).expect("nodelay");
        let hello = ClientHello::signed(
            requester_identity.device_id,
            "BZOT",
            DeviceId::new().to_string(),
            requester_identity,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write fetch hello",
        )
        .await
        .expect("write fetch hello");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read fetch server hello",
        )
        .await
        .expect("read fetch server hello");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected fetch server hello");
        };
        assert!(server_hello.accepted);
        assert_eq!(server_hello.device_id, origin_identity.device_id);
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(&mut stream, &V2Message::FetchRequest(request)),
            "write fetch request",
        )
        .await
        .expect("write fetch request");
        stream
    }

    async fn read_fetch_header_and_manifest(
        stream: &mut TcpStream,
    ) -> (meshelf_protocol::FetchHeader, Vec<ManifestEntry>, usize) {
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_v2_frame_async(stream),
            "read fetch header",
        )
        .await
        .expect("read fetch header");
        let V2Message::FetchHeader(header) = response else {
            panic!("expected fetch header");
        };
        let mut entries = Vec::new();
        let mut chunk_count = 0;
        while entries.len() < usize::try_from(header.manifest_entries).expect("entry count") {
            let response = io_timeout(
                TEST_IO_TIMEOUT,
                read_v2_frame_async(stream),
                "read manifest frame",
            )
            .await
            .expect("read manifest frame");
            match response {
                V2Message::ManifestChunk(chunk) => {
                    chunk_count += 1;
                    entries.extend(chunk.entries);
                }
                V2Message::ManifestEnd(end) => {
                    assert_eq!(end.entry_count, header.manifest_entries);
                }
                other => panic!("unexpected manifest response: {other:?}"),
            }
        }
        if header.manifest_entries > 0 {
            let response = io_timeout(
                TEST_IO_TIMEOUT,
                read_v2_frame_async(stream),
                "read manifest end",
            )
            .await
            .expect("read manifest end");
            assert!(matches!(response, V2Message::ManifestEnd(_)));
        }
        (header, entries, chunk_count)
    }

    async fn admit_fetch(stream: &mut TcpStream, request_id: meshelf_core::ActivationId) {
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(
                stream,
                &V2Message::FetchAdmission(meshelf_protocol::FetchAdmission {
                    request_id,
                    code: meshelf_protocol::FetchAdmissionCode::Accepted,
                    entries_reserved: 0,
                    bytes_reserved: 0,
                    detail: None,
                }),
            ),
            "write fetch admission",
        )
        .await
        .expect("write fetch admission");
    }

    async fn read_v2_test(stream: &mut TcpStream, operation: &'static str) -> V2Message {
        io_timeout(TEST_IO_TIMEOUT, read_v2_frame_async(stream), operation)
            .await
            .expect("read v2 frame")
    }

    async fn write_fetch_receipt(
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
        offer_id: OfferId,
    ) {
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(
                stream,
                &V2Message::FetchReceipt(meshelf_protocol::FetchReceipt {
                    request_id,
                    offer_id,
                    code: meshelf_protocol::FetchReceiptCode::Completed,
                    files_received: 0,
                    bytes_received: 0,
                    detail: None,
                }),
            ),
            "write fetch receipt",
        )
        .await
        .expect("write fetch receipt");
    }

    async fn read_exact_test(stream: &mut TcpStream, bytes: &mut [u8], operation: &'static str) {
        timeout(TEST_IO_TIMEOUT, stream.read_exact(bytes))
            .await
            .expect("read payload timeout")
            .expect(operation);
    }

    fn text_announcement(
        source: DeviceId,
        target: DeviceId,
        offer_id: OfferId,
        text: &str,
    ) -> OfferAnnouncement {
        OfferAnnouncement::new(
            offer_id,
            source,
            target,
            now_unix_ms(),
            meshelf_core::OfferDescriptor::text(text).expect("text descriptor"),
        )
    }

    async fn send_announcement(
        address: SocketAddr,
        source_identity: &meshelf_identity::InstallationIdentity,
        target_identity: &meshelf_identity::InstallationIdentity,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError> {
        PeerClient::with_timeouts(TEST_IO_TIMEOUT, TEST_IO_TIMEOUT)
            .announce_offer(
                address,
                ClientHello::signed(
                    source_identity.device_id,
                    "BMST",
                    DeviceId::new().to_string(),
                    source_identity,
                ),
                announcement,
                &target_identity.public_key(),
            )
            .await
    }

    async fn send_raw_announcement(
        address: SocketAddr,
        source_identity: &meshelf_identity::InstallationIdentity,
        target_identity: &meshelf_identity::InstallationIdentity,
        announcement: OfferAnnouncement,
    ) -> OfferAck {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect announcement");
        stream.set_nodelay(true).expect("nodelay");
        let hello = ClientHello::signed(
            source_identity.device_id,
            "BMST",
            DeviceId::new().to_string(),
            source_identity,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write raw client hello",
        )
        .await
        .expect("write hello");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read raw server hello",
        )
        .await
        .expect("read hello");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected server hello");
        };
        assert!(server_hello.accepted);
        assert_eq!(server_hello.device_id, target_identity.device_id);

        let payload = serde_json::to_vec(&V2Message::OfferAnnouncement(announcement))
            .expect("serialize raw announcement");
        let payload_len = u32::try_from(payload.len()).expect("raw announcement length");
        stream
            .write_all(&payload_len.to_be_bytes())
            .await
            .expect("write raw announcement length");
        stream
            .write_all(&payload)
            .await
            .expect("write raw announcement");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_v2_frame_async(&mut stream),
            "read raw acknowledgement",
        )
        .await
        .expect("read raw acknowledgement");
        let V2Message::OfferAck(ack) = response else {
            panic!("expected offer ack");
        };
        ack
    }

    fn filesystem_entries(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut entries = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).expect("read test directory") {
                let entry = entry.expect("read directory entry");
                let path = entry.path();
                let metadata = entry.metadata().expect("read entry metadata");
                if metadata.is_dir() {
                    pending.push(path);
                } else {
                    entries.push((path, metadata.len()));
                }
            }
        }
        entries
    }

    fn assert_no_payload_artifacts(root: &Path) {
        let entries = filesystem_entries(root);
        let forbidden = entries
            .iter()
            .filter(|(path, _)| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.contains("staging")
                            || name.contains("cache")
                            || name.contains("payload")
                    })
            })
            .collect::<Vec<_>>();
        assert!(
            forbidden.is_empty(),
            "unexpected payload artifacts: {forbidden:?}"
        );
        assert!(
            entries
                .iter()
                .any(|(path, _)| path.ends_with("offers.redb")),
            "metadata store was not created"
        );
        let non_store_bytes: u64 = entries
            .iter()
            .filter(|(path, _)| !path.ends_with("offers.redb"))
            .map(|(_, bytes)| *bytes)
            .sum();
        assert_eq!(non_store_bytes, 0, "non-store payload bytes were written");
    }

    #[tokio::test]
    async fn v1_push_still_works_unchanged() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let target_identity = meshelf_identity::InstallationIdentity::generate();
        let source = source_identity.device_id;
        let target = target_identity.device_id;
        let clipboard = Arc::new(TestClipboard::default());
        let receiver = Arc::new(ReceiverService::new(
            target,
            Arc::new(MemoryReceiveStore::new()),
            clipboard.clone(),
        ));
        let handler = Arc::new(CoreEnvelopeHandler::new(receiver));
        let gate = Arc::new(ExactDeviceAllowList::new([source]));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve(
            listener,
            ServerIdentity {
                signing_identity: target_identity.clone(),
                device_name: "BZOT".to_owned(),
            },
            gate,
            handler,
            TEST_IO_TIMEOUT,
            shutdown_rx,
        ));

        let message = TextEnvelope::clipboard_push(source, target, now_unix_ms(), None, "hello");
        let client = PeerClient::with_timeouts(TEST_IO_TIMEOUT, TEST_IO_TIMEOUT);
        let first = client
            .push(
                address,
                ClientHello::signed(source, "BMST", "nonce-1", &source_identity),
                message.clone(),
                &target_identity.public_key(),
            )
            .await
            .expect("first push");
        let duplicate = client
            .push(
                address,
                ClientHello::signed(source, "BMST", "nonce-2", &source_identity),
                message,
                &target_identity.public_key(),
            )
            .await
            .expect("duplicate push");

        assert_eq!(first.code, ReceiptCode::Applied);
        assert_eq!(duplicate.code, ReceiptCode::DuplicateApplied);
        assert_eq!(
            clipboard.0.lock().expect("clipboard mutex").as_slice(),
            ["hello".to_owned()]
        );

        shutdown_tx.send(true).expect("request shutdown");
        server.await.expect("server task").expect("clean server");
    }

    #[tokio::test]
    async fn loopback_file_stream_hashes_finalizes_and_adds_shelf_card() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let target_identity = meshelf_identity::InstallationIdentity::generate();
        let source = source_identity.device_id;
        let target = target_identity.device_id;
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = directory.path().join("example.txt");
        let bytes = b"meshelf file transfer\n";
        std::fs::write(&source_path, bytes).expect("write source");
        let incoming = directory.path().join("incoming");
        let store = Arc::new(MemoryReceiveStore::new());
        let receiver = Arc::new(ReceiverService::new(
            target,
            store.clone(),
            Arc::new(TestClipboard::default()),
        ));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_with_files(
            listener,
            ServerIdentity {
                signing_identity: target_identity.clone(),
                device_name: "BZOT".to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new([source])),
            Arc::new(CoreEnvelopeHandler::new(receiver)),
            incoming.clone(),
            TEST_IO_TIMEOUT,
            shutdown_rx,
        ));
        let transfer_id = meshelf_core::MessageId::new();
        let offer = FileTransferOffer {
            protocol_version: meshelf_core::PROTOCOL_VERSION,
            transfer_id,
            source_device: source,
            target_device: target,
            content_kind: ContentKind::File,
            root_name: "example.txt".to_owned(),
            total_bytes: bytes.len() as u64,
            entries: vec![meshelf_protocol::FileTransferEntry {
                relative_path: "example.txt".to_owned(),
                kind: FileEntryKind::File,
                byte_len: bytes.len() as u64,
                sha256: Sha256::digest(bytes).to_vec(),
            }],
        };
        let client = PeerClient::with_timeouts(TEST_IO_TIMEOUT, TEST_IO_TIMEOUT);
        let receipt = client
            .push_file_transfer(
                address,
                ClientHello::signed(source, "BMST", "file-nonce", &source_identity),
                offer.clone(),
                vec![source_path.clone()],
                &target_identity.public_key(),
            )
            .await
            .expect("file transfer");
        let duplicate = client
            .push_file_transfer(
                address,
                ClientHello::signed(source, "BMST", "file-retry", &source_identity),
                offer,
                vec![source_path],
                &target_identity.public_key(),
            )
            .await
            .expect("duplicate file receipt");

        assert_eq!(receipt.code, ReceiptCode::Stored);
        assert_eq!(duplicate.code, ReceiptCode::Stored);
        assert_eq!(
            std::fs::read(incoming.join("example.txt")).expect("received file"),
            bytes
        );
        let record = store
            .get(transfer_id)
            .expect("read shelf record")
            .expect("shelf record exists");
        assert_eq!(record.envelope.content_kind, ContentKind::File);
        assert_eq!(
            record.envelope.text,
            incoming.join("example.txt").to_string_lossy()
        );
        assert!(!incoming.join("example (2).txt").exists());

        shutdown_tx.send(true).expect("request shutdown");
        server.await.expect("server task").expect("clean server");
    }

    #[test]
    fn file_offer_rejects_traversal_reserved_names_and_size_mismatch() {
        let base = FileTransferOffer {
            protocol_version: meshelf_core::PROTOCOL_VERSION,
            transfer_id: meshelf_core::MessageId::new(),
            source_device: DeviceId::new(),
            target_device: DeviceId::new(),
            content_kind: ContentKind::File,
            root_name: "safe.txt".to_owned(),
            total_bytes: 1,
            entries: vec![meshelf_protocol::FileTransferEntry {
                relative_path: "safe.txt".to_owned(),
                kind: FileEntryKind::File,
                byte_len: 1,
                sha256: vec![0; 32],
            }],
        };
        assert!(validate_file_offer(&base).is_ok());
        let mut traversal = base.clone();
        traversal.entries[0].relative_path = "../escape.txt".to_owned();
        assert!(validate_file_offer(&traversal).is_err());
        let mut reserved = base.clone();
        reserved.root_name = "CON.txt".to_owned();
        assert!(validate_file_offer(&reserved).is_err());
        let mut mismatch = base;
        mismatch.total_bytes = 2;
        assert!(validate_file_offer(&mismatch).is_err());

        for root_name in [
            r"..\escape",
            r"\escape",
            r"C:\escape",
            "/escape",
            "bad?.folder",
            "COM¹.log",
            "LPT³",
            "line\nfeed",
        ] {
            let folder = FileTransferOffer {
                protocol_version: meshelf_core::PROTOCOL_VERSION,
                transfer_id: meshelf_core::MessageId::new(),
                source_device: DeviceId::new(),
                target_device: DeviceId::new(),
                content_kind: ContentKind::Folder,
                root_name: root_name.to_owned(),
                total_bytes: 0,
                entries: Vec::new(),
            };
            assert!(
                validate_file_offer(&folder).is_err(),
                "unsafe folder root was accepted: {root_name:?}"
            );
        }
    }

    #[test]
    fn collision_candidates_stay_within_portable_component_limit() {
        let directory = Path::new("incoming");
        let folder_root = "a".repeat(MAX_PORTABLE_COMPONENT_BYTES);
        let folder_candidate = collision_candidate(directory, &folder_root, ContentKind::Folder, 2)
            .expect("folder collision candidate");
        let folder_name = folder_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("folder collision name");
        assert_eq!(folder_name.len(), MAX_PORTABLE_COMPONENT_BYTES);
        assert!(folder_name.ends_with(" (2)"));
        validate_component(folder_name).expect("portable folder collision name");

        let file_root = format!("{}.txt", "b".repeat(MAX_PORTABLE_COMPONENT_BYTES - 4));
        let file_candidate = collision_candidate(directory, &file_root, ContentKind::File, 9999)
            .expect("file collision candidate");
        let file_name = file_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("file collision name");
        assert_eq!(file_name.len(), MAX_PORTABLE_COMPONENT_BYTES);
        assert!(file_name.ends_with(" (9999).txt"));
        validate_component(file_name).expect("portable file collision name");

        let unicode_root = format!("{}a", "é".repeat(127));
        let unicode_candidate =
            collision_candidate(directory, &unicode_root, ContentKind::Folder, 2)
                .expect("UTF-8 collision candidate");
        let unicode_name = unicode_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("UTF-8 collision name");
        assert!(unicode_name.len() <= MAX_PORTABLE_COMPONENT_BYTES);
        assert!(unicode_name.ends_with(" (2)"));
        validate_component(unicode_name).expect("portable UTF-8 collision name");

        let fallback_suffix = format!(".{}", meshelf_core::MessageId::new());
        let fallback_name = component_with_suffix(&folder_root, &fallback_suffix)
            .expect("portable UUID fallback name");
        assert!(fallback_name.len() <= MAX_PORTABLE_COMPONENT_BYTES);
        validate_component(&fallback_name).expect("portable UUID fallback name");
    }

    #[test]
    fn generated_collision_names_reject_degenerate_suffix_budgets() {
        let at_ceiling = "x".repeat(MAX_PORTABLE_COMPONENT_BYTES);
        let over_ceiling = "x".repeat(MAX_PORTABLE_COMPONENT_BYTES + 1);
        assert!(component_with_suffix("stem", &at_ceiling).is_err());
        assert!(component_with_suffix("stem", &over_ceiling).is_err());

        let almost_ceiling = "x".repeat(MAX_PORTABLE_COMPONENT_BYTES - 1);
        assert!(component_with_suffix("é", &almost_ceiling).is_err());
        assert_eq!(truncate_utf8("é", 1), "");

        let directory = Path::new("incoming");
        let dotfile = collision_candidate(directory, ".bashrc", ContentKind::File, 2)
            .expect("dotfile collision candidate");
        assert_eq!(dotfile, directory.join(".bashrc (2)"));

        let long_extension = format!("a.{}", "x".repeat(250));
        let long_extension_candidate =
            collision_candidate(directory, &long_extension, ContentKind::File, 2)
                .expect("long-extension collision candidate");
        let long_extension_name = long_extension_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("long-extension collision name");
        assert!(long_extension_name.len() <= MAX_PORTABLE_COMPONENT_BYTES);
        assert!(long_extension_name.ends_with(" (2)"));
        validate_component(long_extension_name).expect("portable long-extension collision name");
    }

    #[tokio::test]
    async fn max_length_folder_collision_finalizes_on_the_real_filesystem() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let incoming = directory.path().join("incoming");
        std::fs::create_dir(&incoming).expect("incoming directory");
        let root_name = "a".repeat(MAX_PORTABLE_COMPONENT_BYTES);
        let existing = incoming.join(&root_name);
        std::fs::create_dir(&existing).expect("existing maximum-length destination");

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            assert!(existing.as_os_str().encode_wide().count() >= 260);
        }

        let payload = directory.path().join("payload");
        std::fs::create_dir(&payload).expect("payload directory");
        std::fs::write(payload.join("item.txt"), b"payload").expect("payload file");

        let final_path = finalize_payload_without_overwrite(
            &payload,
            &incoming,
            &root_name,
            ContentKind::Folder,
        )
        .await
        .expect("maximum-length exclusive folder finalization");
        let final_name = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .expect("maximum-length final name");

        assert_eq!(final_name.len(), MAX_PORTABLE_COMPONENT_BYTES);
        assert!(final_name.ends_with(" (2)"));
        validate_component(final_name).expect("portable maximum-length final name");
        assert!(existing.is_dir());
        assert_eq!(
            std::fs::read(final_path.join("item.txt")).expect("published payload"),
            b"payload"
        );
    }

    #[tokio::test]
    async fn folder_finalization_uses_atomic_no_replace_and_next_collision_name() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let incoming = directory.path().join("incoming");
        std::fs::create_dir(&incoming).expect("incoming directory");
        let existing = incoming.join("bundle");
        std::fs::create_dir(&existing).expect("existing empty destination");
        let payload = directory.path().join("payload");
        std::fs::create_dir(&payload).expect("payload directory");
        std::fs::write(payload.join("item.txt"), b"payload").expect("payload file");

        let final_path =
            finalize_payload_without_overwrite(&payload, &incoming, "bundle", ContentKind::Folder)
                .await
                .expect("exclusive folder finalization");

        assert_eq!(final_path, incoming.join("bundle (2)"));
        assert!(existing.is_dir());
        assert!(
            std::fs::read_dir(&existing)
                .expect("read original destination")
                .next()
                .is_none()
        );
        assert_eq!(
            std::fs::read(final_path.join("item.txt")).expect("published payload"),
            b"payload"
        );
    }

    #[test]
    fn concurrent_folder_finalization_never_overwrites() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let incoming = directory.path().join("incoming");
        std::fs::create_dir(&incoming).expect("incoming directory");
        let first_payload = directory.path().join("first-payload");
        let second_payload = directory.path().join("second-payload");
        std::fs::create_dir(&first_payload).expect("first payload directory");
        std::fs::create_dir(&second_payload).expect("second payload directory");
        std::fs::write(first_payload.join("first.txt"), b"first").expect("first payload");
        std::fs::write(second_payload.join("second.txt"), b"second").expect("second payload");

        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for payload in [first_payload, second_payload] {
            let incoming = incoming.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                barrier.wait();
                runtime.block_on(finalize_payload_without_overwrite(
                    &payload,
                    &incoming,
                    "bundle",
                    ContentKind::Folder,
                ))
            }));
        }

        barrier.wait();
        let mut final_paths = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .expect("finalization worker")
                    .expect("exclusive finalization")
            })
            .collect::<Vec<_>>();
        final_paths.sort();

        assert_eq!(
            final_paths,
            vec![incoming.join("bundle"), incoming.join("bundle (2)")]
        );
        let published_names = final_paths
            .iter()
            .flat_map(|path| {
                std::fs::read_dir(path)
                    .expect("published directory")
                    .map(|entry| {
                        entry
                            .expect("published entry")
                            .file_name()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            published_names,
            std::collections::BTreeSet::from(["first.txt".to_owned(), "second.txt".to_owned()])
        );
    }

    #[tokio::test]
    async fn loopback_folder_stream_preserves_nested_and_empty_directories() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let target_identity = meshelf_identity::InstallationIdentity::generate();
        let source = source_identity.device_id;
        let target = target_identity.device_id;
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_root = directory.path().join("bundle");
        std::fs::create_dir_all(source_root.join("empty")).expect("empty directory");
        std::fs::create_dir_all(source_root.join("nested")).expect("nested directory");
        let source_path = source_root.join("nested").join("item.txt");
        let bytes = b"nested meshelf file";
        std::fs::write(&source_path, bytes).expect("write nested file");
        let incoming = directory.path().join("incoming");
        let store = Arc::new(MemoryReceiveStore::new());
        let receiver = Arc::new(ReceiverService::new(
            target,
            store,
            Arc::new(TestClipboard::default()),
        ));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_with_files(
            listener,
            ServerIdentity {
                signing_identity: target_identity.clone(),
                device_name: "BZOT".to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new([source])),
            Arc::new(CoreEnvelopeHandler::new(receiver)),
            incoming.clone(),
            TEST_IO_TIMEOUT,
            shutdown_rx,
        ));
        let transfer_id = meshelf_core::MessageId::new();
        let offer = FileTransferOffer {
            protocol_version: meshelf_core::PROTOCOL_VERSION,
            transfer_id,
            source_device: source,
            target_device: target,
            content_kind: ContentKind::Folder,
            root_name: "bundle".to_owned(),
            total_bytes: bytes.len() as u64,
            entries: vec![
                meshelf_protocol::FileTransferEntry {
                    relative_path: "empty".to_owned(),
                    kind: FileEntryKind::Directory,
                    byte_len: 0,
                    sha256: Vec::new(),
                },
                meshelf_protocol::FileTransferEntry {
                    relative_path: "nested".to_owned(),
                    kind: FileEntryKind::Directory,
                    byte_len: 0,
                    sha256: Vec::new(),
                },
                meshelf_protocol::FileTransferEntry {
                    relative_path: "nested/item.txt".to_owned(),
                    kind: FileEntryKind::File,
                    byte_len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).to_vec(),
                },
            ],
        };
        let receipt = PeerClient::with_timeouts(TEST_IO_TIMEOUT, TEST_IO_TIMEOUT)
            .push_file_transfer(
                address,
                ClientHello::signed(source, "BMST", "folder-nonce", &source_identity),
                offer,
                vec![source_path],
                &target_identity.public_key(),
            )
            .await
            .expect("folder transfer");

        assert_eq!(receipt.code, ReceiptCode::Stored);
        assert!(incoming.join("bundle").join("empty").is_dir());
        assert_eq!(
            std::fs::read(incoming.join("bundle").join("nested").join("item.txt"))
                .expect("received nested file"),
            bytes
        );
        assert!(
            !incoming
                .join(".meshelf-partials")
                .join(transfer_id.to_string())
                .exists()
        );

        shutdown_tx.send(true).expect("request shutdown");
        server.await.expect("server task").expect("clean server");
    }

    #[tokio::test]
    async fn deny_all_rejects_before_payload() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let target_identity = meshelf_identity::InstallationIdentity::generate();
        let source = source_identity.device_id;
        let target = target_identity.device_id;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let receiver = Arc::new(ReceiverService::new(
            target,
            Arc::new(MemoryReceiveStore::new()),
            Arc::new(TestClipboard::default()),
        ));
        let server = tokio::spawn(serve(
            listener,
            ServerIdentity {
                signing_identity: target_identity.clone(),
                device_name: "BZOT".to_owned(),
            },
            Arc::new(DenyAll),
            Arc::new(CoreEnvelopeHandler::new(receiver)),
            TEST_IO_TIMEOUT,
            shutdown_rx,
        ));

        let advertisement = PeerClient::default()
            .probe(address)
            .await
            .expect("probe discovers deny-all listener");
        assert_eq!(advertisement.device_id, target);
        assert_eq!(advertisement.device_name, "BZOT");
        assert!(!advertisement.accepted);
        assert!(
            advertisement
                .capabilities
                .iter()
                .any(|capability| capability == CAP_TEXT_SHELF_V1)
        );

        let error = PeerClient::default()
            .push(
                address,
                ClientHello::signed(source, "BMST", "nonce", &source_identity),
                TextEnvelope::clipboard_push(source, target, now_unix_ms(), None, "secret"),
                &target_identity.public_key(),
            )
            .await
            .expect_err("deny all");
        assert!(matches!(error, NetError::Rejected(_)));

        shutdown_tx.send(true).expect("request shutdown");
        server.await.expect("server task").expect("clean server");
    }

    #[test]
    fn tailnet_gate_requires_both_device_and_current_address() {
        let device = DeviceId::new();
        let gate = TailnetPeerAllowList::new([(device, ["100.77.0.2".parse().expect("address")])]);
        let hello = ClientHello::new(device, "BZOT", "probe");

        assert_eq!(
            gate.authorize("100.77.0.2:45832".parse().expect("socket"), &hello),
            TrustDecision::Allow
        );
        assert!(matches!(
            gate.authorize("100.77.0.3:45832".parse().expect("socket"), &hello),
            TrustDecision::Deny(_)
        ));
        assert!(matches!(
            gate.authorize(
                "100.77.0.2:45832".parse().expect("socket"),
                &ClientHello::new(DeviceId::new(), "other", "probe")
            ),
            TrustDecision::Deny(_)
        ));
    }

    #[tokio::test]
    async fn refuses_unspecified_or_non_discovered_bind() {
        let unspecified = SocketAddr::from(([0, 0, 0, 0], 32179));
        assert!(matches!(
            bind_discovered_tailscale_address(unspecified, &[]).await,
            Err(NetError::UnsafeBind(_))
        ));
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        assert!(matches!(
            bind_discovered_tailscale_address(loopback, &[]).await,
            Err(NetError::UnsafeBind(_))
        ));
    }

    #[test]
    fn production_listener_attaches_to_its_long_lived_runtime() {
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = bind_discovered_tailscale_std_listener(
            address,
            &[std::net::Ipv4Addr::LOCALHOST.into()],
        )
        .expect("bind validated standard listener");
        let bound_address = listener.local_addr().expect("bound address");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("server runtime");
            let listener = runtime
                .block_on(async move { TcpListener::from_std(listener) })
                .expect("attach listener to runtime");
            ready_tx.send(()).expect("signal listener ready");
            runtime
                .block_on(async { timeout(TEST_IO_TIMEOUT, listener.accept()).await })
                .expect("listener accepted before timeout")
                .expect("accept connection");
        });

        ready_rx.recv().expect("listener attached");
        std::net::TcpStream::connect(bound_address).expect("connect to moved listener");
        worker.join().expect("server worker");
    }

    #[tokio::test]
    async fn announcement_persists_only_metadata() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "metadata must be bounded",
        );
        let ack = send_announcement(
            address,
            &source_identity,
            &target_identity,
            announcement.clone(),
        )
        .await
        .expect("metadata announcement");
        assert_eq!(ack.code, OfferAckCode::Stored);
        let card = store
            .get_offer_card(source_identity.device_id, announcement.offer_id)
            .expect("read card")
            .expect("stored card");
        assert_eq!(card.descriptor, announcement.descriptor);
        assert_eq!(card.availability, CardAvailability::Available);
        assert!(card.last_attempt.is_none());
        assert!(
            store
                .read_offer_sources()
                .expect("read source table")
                .is_empty()
        );
        stop_offer_server(shutdown_tx, server).await;
        assert_no_payload_artifacts(directory.path());
    }

    #[tokio::test]
    async fn announcement_creates_no_staging_cache_or_payload_file_on_disk() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (directory, address, target_identity, shutdown_tx, server, _store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "metadata only",
        );
        let ack = send_announcement(address, &source_identity, &target_identity, announcement)
            .await
            .expect("announce");
        assert_eq!(ack.code, OfferAckCode::Stored);
        stop_offer_server(shutdown_tx, server).await;
        assert_no_payload_artifacts(directory.path());
    }

    #[tokio::test]
    async fn announcement_without_activation_writes_zero_payload_bytes() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let source_directory = tempfile::tempdir().expect("source directory");
        let source_file = source_directory.path().join("secret.txt");
        fs::write(&source_file, b"payload remains on the source").expect("write source file");
        let (receiver_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            source_identity.device_id,
            target_identity.device_id,
            now_unix_ms(),
            meshelf_core::OfferDescriptor::File {
                root_name: "secret.txt".to_owned(),
                total_bytes: 31,
            },
        );
        let ack = send_announcement(address, &source_identity, &target_identity, announcement)
            .await
            .expect("announce file metadata");
        assert_eq!(ack.code, OfferAckCode::Stored);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
        assert_no_payload_artifacts(receiver_directory.path());
        assert_eq!(
            fs::read(&source_file).expect("source remains"),
            b"payload remains on the source"
        );
    }

    #[tokio::test]
    async fn announcement_from_unpaired_peer_is_refused_before_storage() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let unpaired_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([unpaired_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "must not store",
        );
        let error = send_announcement(address, &source_identity, &target_identity, announcement)
            .await
            .expect_err("unpaired announcement");
        assert!(matches!(error, NetError::Rejected(_)));
        assert!(store.read_offer_shelf().expect("read shelf").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn announcement_with_wrong_target_device_is_refused() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            DeviceId::new(),
            OfferId::new(),
            "wrong target",
        );
        let ack =
            send_raw_announcement(address, &source_identity, &target_identity, announcement).await;
        assert_eq!(ack.code, OfferAckCode::RefusedInvalid);
        assert_eq!(ack.live_entries, 0);
        assert_eq!(ack.max_live_entries, V2_MAX_LIVE_ENTRIES);
        assert!(store.read_offer_shelf().expect("read shelf").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn announcement_with_oversized_preview_is_refused_invalid() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            source_identity.device_id,
            target_identity.device_id,
            now_unix_ms(),
            meshelf_core::OfferDescriptor::Text {
                utf8_bytes: 1,
                line_count: 1,
                preview: "x".repeat(meshelf_core::MAX_OFFER_PREVIEW_BYTES + 1),
            },
        );
        let ack =
            send_raw_announcement(address, &source_identity, &target_identity, announcement).await;
        assert_eq!(ack.code, OfferAckCode::RefusedInvalid);
        assert_eq!(ack.live_entries, 0);
        assert_eq!(ack.max_live_entries, V2_MAX_LIVE_ENTRIES);
        assert!(store.read_offer_shelf().expect("read shelf").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn identical_reannouncement_returns_duplicate_and_does_not_duplicate_the_card() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "same descriptor",
        );
        let first = send_announcement(
            address,
            &source_identity,
            &target_identity,
            announcement.clone(),
        )
        .await
        .expect("first announcement");
        let duplicate =
            send_announcement(address, &source_identity, &target_identity, announcement)
                .await
                .expect("duplicate announcement");
        assert_eq!(first.code, OfferAckCode::Stored);
        assert_eq!(duplicate.code, OfferAckCode::Duplicate);
        assert_eq!(duplicate.live_entries, 1);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn same_offer_id_with_different_descriptor_returns_conflict() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let offer_id = OfferId::new();
        let first = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            offer_id,
            "first",
        );
        let second = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            offer_id,
            "different",
        );
        assert_eq!(
            send_announcement(address, &source_identity, &target_identity, first)
                .await
                .expect("first announcement")
                .code,
            OfferAckCode::Stored
        );
        let conflict = send_announcement(address, &source_identity, &target_identity, second)
            .await
            .expect("conflicting announcement");
        assert_eq!(conflict.code, OfferAckCode::RefusedConflict);
        assert_eq!(conflict.live_entries, 1);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn eleventh_card_returns_capacity_with_ten_of_ten_counts() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        for index in 0..V2_MAX_LIVE_ENTRIES {
            let ack = send_announcement(
                address,
                &source_identity,
                &target_identity,
                text_announcement(
                    source_identity.device_id,
                    target_identity.device_id,
                    OfferId::new(),
                    &format!("card {index}"),
                ),
            )
            .await
            .expect("announcement within capacity");
            assert_eq!(ack.code, OfferAckCode::Stored);
        }
        let eleventh = send_announcement(
            address,
            &source_identity,
            &target_identity,
            text_announcement(
                source_identity.device_id,
                target_identity.device_id,
                OfferId::new(),
                "eleventh",
            ),
        )
        .await
        .expect("capacity acknowledgement");
        assert_eq!(eleventh.code, OfferAckCode::RefusedCapacity);
        assert_eq!(eleventh.live_entries, V2_MAX_LIVE_ENTRIES);
        assert_eq!(eleventh.max_live_entries, V2_MAX_LIVE_ENTRIES);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 10);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn offline_announcement_is_reported_and_not_retried() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let target_identity = meshelf_identity::InstallationIdentity::generate();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        drop(listener);
        let started = std::time::Instant::now();
        let error = send_announcement(
            address,
            &source_identity,
            &target_identity,
            text_announcement(
                source_identity.device_id,
                target_identity.device_id,
                OfferId::new(),
                "offline",
            ),
        )
        .await
        .expect_err("offline peer");
        assert!(matches!(error, NetError::Unavailable(_) | NetError::Io(_)));
        assert!(started.elapsed() < TEST_IO_TIMEOUT);
    }

    #[tokio::test]
    async fn one_connection_cannot_announce_twice() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect announcement");
        stream.set_nodelay(true).expect("nodelay");
        let hello = ClientHello::signed(
            source_identity.device_id,
            "BMST",
            "single-operation",
            &source_identity,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write client hello",
        )
        .await
        .expect("write hello");
        let _ = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read server hello",
        )
        .await
        .expect("read hello");
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "one operation",
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(
                &mut stream,
                &V2Message::OfferAnnouncement(announcement.clone()),
            ),
            "write first announcement",
        )
        .await
        .expect("write first announcement");
        let first = io_timeout(
            TEST_IO_TIMEOUT,
            read_v2_frame_async(&mut stream),
            "read first acknowledgement",
        )
        .await
        .expect("read first acknowledgement");
        assert!(matches!(first, V2Message::OfferAck(_)));

        let second_write = io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(&mut stream, &V2Message::OfferAnnouncement(announcement)),
            "write second announcement",
        )
        .await;
        if second_write.is_ok() {
            let second_read = io_timeout(
                TEST_IO_TIMEOUT,
                read_v2_frame_async(&mut stream),
                "read second acknowledgement",
            )
            .await;
            assert!(
                second_read.is_err(),
                "one connection returned two acknowledgements"
            );
        }
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn handler_limit_refuses_excess_connections_without_unbounded_task_growth() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, _target_identity, shutdown_tx, server, _store) =
            start_offer_server([source_identity.device_id]).await;
        let mut held = Vec::new();
        for index in 0..V2_MAX_INBOUND_HANDLERS {
            let mut stream = TcpStream::connect(address)
                .await
                .expect("connect held handler");
            stream.set_nodelay(true).expect("nodelay");
            let hello = ClientHello::signed(
                source_identity.device_id,
                "BMST",
                format!("held-{index}"),
                &source_identity,
            );
            io_timeout(
                TEST_IO_TIMEOUT,
                write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
                "write held hello",
            )
            .await
            .expect("write held hello");
            let response = io_timeout(
                TEST_IO_TIMEOUT,
                read_frame_async(&mut stream),
                "read held server hello",
            )
            .await
            .expect("read held server hello");
            let WireMessage::ServerHello(server_hello) = response else {
                panic!("expected held server hello");
            };
            assert!(server_hello.accepted);
            held.push(stream);
        }

        let mut excess = TcpStream::connect(address)
            .await
            .expect("connect excess handler");
        excess.set_nodelay(true).expect("nodelay");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut excess),
            "read capacity refusal",
        )
        .await
        .expect("read capacity refusal");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected capacity refusal server hello");
        };
        let reason = server_hello.reason.expect("capacity refusal detail");
        assert!(!server_hello.accepted);
        assert!(reason.contains("active=16"));
        assert!(reason.contains("maximum=16"));
        drop(excess);
        drop(held);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn unannounced_peer_cannot_fetch_known_offer_id() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let other = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        let descriptor = OfferDescriptor::text("known but not announced").expect("descriptor");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor,
                HashSet::from([other.device_id]),
                OfferSource::Text {
                    text: "known but not announced".to_owned(),
                },
            ))
            .expect("insert source");
        let mut stream = connect_fetch(
            address,
            &requester,
            &origin,
            FetchRequest::new(offer_id, origin.device_id, requester.device_id),
        )
        .await;
        let response = read_v2_test(&mut stream, "read refusal").await;
        let V2Message::FetchRefusal(refusal) = response else {
            panic!("expected fetch refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::NotAnnouncedToRequester);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn unpaired_peer_cannot_fetch_even_if_announced() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([]).await;
        let offer_id = OfferId::new();
        let descriptor =
            OfferDescriptor::text("announced to an unpaired peer").expect("descriptor");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor,
                HashSet::from([requester.device_id]),
                OfferSource::Text {
                    text: "announced to an unpaired peer".to_owned(),
                },
            ))
            .expect("insert source");
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect unpaired peer");
        let hello = ClientHello::signed(
            requester.device_id,
            "BZOT",
            DeviceId::new().to_string(),
            &requester,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write unpaired hello",
        )
        .await
        .expect("write hello");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read unpaired hello",
        )
        .await
        .expect("read hello");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected server hello");
        };
        assert!(!server_hello.accepted);
        assert!(
            store
                .get_offer_source(offer_id)
                .expect("read source")
                .is_some()
        );
        assert_eq!(origin.device_id, server_hello.device_id);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn wrong_source_device_in_request_is_refused() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        insert_text_source(&store, requester.device_id, offer_id, "wrong source");
        let mut stream = connect_fetch(
            address,
            &requester,
            &origin,
            FetchRequest::new(offer_id, DeviceId::new(), requester.device_id),
        )
        .await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::Malformed);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn unknown_offer_id_is_refused_without_touching_the_source() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let unknown = OfferId::new();
        let mut stream = connect_fetch(
            address,
            &requester,
            &origin,
            FetchRequest::new(unknown, origin.device_id, requester.device_id),
        )
        .await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::UnknownOffer);
        assert!(store.read_offer_sources().expect("read sources").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn text_fetch_serves_the_stored_body_exactly() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let body = "stored text\nwith unicode: β🙂";
        let offer_id = OfferId::new();
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (header, entries, chunks) = read_fetch_header_and_manifest(&mut stream).await;
        assert_eq!(header.manifest_entries, 0);
        assert_eq!(entries.len(), 0);
        assert_eq!(chunks, 0);
        assert_eq!(
            header.text_sha256,
            Some(Sha256::digest(body.as_bytes()).to_vec())
        );
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read text body").await;
        assert_eq!(received, body.as_bytes());
        assert!(matches!(
            read_v2_test(&mut stream, "read text end").await,
            V2Message::TextEnd(_)
        ));
        assert!(matches!(
            read_v2_test(&mut stream, "read fetch complete").await,
            V2Message::FetchComplete(_)
        ));
        write_fetch_receipt(&mut stream, request_id, offer_id).await;
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn origin_waits_for_and_validates_fetch_receipt() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let directory = tempfile::tempdir().expect("temporary fetch directory");
        let store = Arc::new(
            RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
        );
        let origin = meshelf_identity::InstallationIdentity::generate();
        let body = "receipt-gated text";
        let offer_id = OfferId::new();
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let sender = Arc::new(OfferFetchHandler::new(origin.device_id, store));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fetch");
            sender
                .handle_fetch(requester.device_id, request, &mut stream, TEST_IO_TIMEOUT)
                .await
        });
        let mut stream = TcpStream::connect(address).await.expect("connect fetch");
        let _ = read_fetch_header_and_manifest(&mut stream).await;
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read text body").await;
        assert_eq!(received, body.as_bytes());
        let _ = read_v2_test(&mut stream, "read text end").await;
        let _ = read_v2_test(&mut stream, "read fetch complete").await;

        let mut probe = [0_u8; 1];
        assert!(
            timeout(TEST_IO_TIMEOUT / 10, stream.read(&mut probe))
                .await
                .is_err(),
            "origin returned before the receiver supplied a receipt"
        );
        write_v2_frame_async(
            &mut stream,
            &V2Message::FetchReceipt(FetchReceipt {
                request_id: ActivationId::new(),
                offer_id,
                code: meshelf_protocol::FetchReceiptCode::Completed,
                files_received: 0,
                bytes_received: body.len() as u64,
                detail: None,
            }),
        )
        .await
        .expect("write mismatched receipt");
        assert_eq!(
            timeout(TEST_IO_TIMEOUT, stream.read(&mut probe))
                .await
                .expect("read close timeout")
                .expect("read close"),
            0
        );
        let result = server.await.expect("sender task");
        assert!(matches!(result, Err(NetError::IdentityMismatch(_))));
    }

    #[tokio::test]
    async fn text_fetch_cannot_return_source_changed() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        let body = "text is durable";
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (header, _, _) = read_fetch_header_and_manifest(&mut stream).await;
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read text body").await;
        assert_eq!(received, body.as_bytes());
        assert_eq!(header.manifest_entries, 0);
        let response = read_v2_test(&mut stream, "read text end").await;
        assert!(!matches!(
            response,
            V2Message::FetchRefusal(FetchRefusal {
                code: FetchRefusalCode::SourceChanged,
                ..
            })
        ));
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn deleted_file_source_returns_source_unavailable_and_sends_no_payload() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let path = source_directory.path().join("deleted.txt");
        fs::write(&path, b"body").expect("write source");
        let offer_id = OfferId::new();
        insert_file_source(&store, requester.device_id, offer_id, &path);
        fs::remove_file(&path).expect("delete source");
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected source refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::SourceUnavailable);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn modified_file_source_returns_source_changed_and_sends_no_payload() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let path = source_directory.path().join("modified.txt");
        fs::write(&path, b"body").expect("write source");
        let offer_id = OfferId::new();
        insert_file_source(&store, requester.device_id, offer_id, &path);
        fs::write(&path, b"changed body").expect("modify source");
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected source refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::SourceChanged);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn folder_manifest_is_chunked_within_the_control_frame() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let root = source_directory.path().join("many-files");
        fs::create_dir(&root).expect("create root");
        for index in 0..1500 {
            fs::write(root.join(format!("file-{index:04}.txt")), []).expect("write file");
        }
        let offer_id = OfferId::new();
        insert_folder_source(&store, requester.device_id, offer_id, &root);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (header, entries, chunk_count) = read_fetch_header_and_manifest(&mut stream).await;
        assert_eq!(header.manifest_entries, 1500);
        assert_eq!(entries.len(), 1500);
        assert!(chunk_count > 1);
        assert!(header.manifest_encoded_bytes <= V2_MAX_MANIFEST_BYTES as u64);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn manifest_contains_no_sender_absolute_path() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let root = source_directory.path().join("folder");
        fs::create_dir(&root).expect("create root");
        fs::write(root.join("item.txt"), b"body").expect("write file");
        let offer_id = OfferId::new();
        insert_folder_source(&store, requester.device_id, offer_id, &root);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (_, entries, _) = read_fetch_header_and_manifest(&mut stream).await;
        let encoded = serde_json::to_string(&entries).expect("encode manifest");
        assert!(!encoded.contains(source_directory.path().to_str().expect("temp path")));
        assert!(
            entries
                .iter()
                .all(|entry| !Path::new(&entry.relative_path).is_absolute())
        );
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn two_peers_can_fetch_the_same_offer_concurrently() {
        let first = meshelf_identity::InstallationIdentity::generate();
        let second = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([first.device_id, second.device_id]).await;
        let offer_id = OfferId::new();
        let body = "same offer twice";
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                OfferDescriptor::text(body).expect("descriptor"),
                HashSet::from([first.device_id, second.device_id]),
                OfferSource::Text {
                    text: body.to_owned(),
                },
            ))
            .expect("insert source");
        let request_one = FetchRequest::new(offer_id, origin.device_id, first.device_id);
        let request_two = FetchRequest::new(offer_id, origin.device_id, second.device_id);
        let request_one_id = request_one.request_id;
        let request_two_id = request_two.request_id;
        let mut stream_one = connect_fetch(address, &first, &origin, request_one).await;
        let mut stream_two = connect_fetch(address, &second, &origin, request_two).await;
        let (_, _, _) = read_fetch_header_and_manifest(&mut stream_one).await;
        let (_, _, _) = read_fetch_header_and_manifest(&mut stream_two).await;
        admit_fetch(&mut stream_one, request_one_id).await;
        admit_fetch(&mut stream_two, request_two_id).await;
        let mut one = vec![0_u8; body.len()];
        let mut two = vec![0_u8; body.len()];
        read_exact_test(&mut stream_one, &mut one, "read first body").await;
        read_exact_test(&mut stream_two, &mut two, "read second body").await;
        assert_eq!(one, body.as_bytes());
        assert_eq!(two, body.as_bytes());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn third_concurrent_fetch_is_refused_busy_with_two_of_two_and_no_queue() {
        let first = meshelf_identity::InstallationIdentity::generate();
        let second = meshelf_identity::InstallationIdentity::generate();
        let third = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([first.device_id, second.device_id, third.device_id]).await;
        let offer_id = OfferId::new();
        let body = "held until admission";
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                OfferDescriptor::text(body).expect("descriptor"),
                HashSet::from([first.device_id, second.device_id, third.device_id]),
                OfferSource::Text {
                    text: body.to_owned(),
                },
            ))
            .expect("insert source");
        let request_one = FetchRequest::new(offer_id, origin.device_id, first.device_id);
        let request_two = FetchRequest::new(offer_id, origin.device_id, second.device_id);
        let mut one = connect_fetch(address, &first, &origin, request_one).await;
        let mut two = connect_fetch(address, &second, &origin, request_two).await;
        let _ = read_fetch_header_and_manifest(&mut one).await;
        let _ = read_fetch_header_and_manifest(&mut two).await;
        let request_three = FetchRequest::new(offer_id, origin.device_id, third.device_id);
        let mut three = connect_fetch(address, &third, &origin, request_three).await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut three, "read busy refusal").await
        else {
            panic!("expected busy refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::Busy);
        assert_eq!((refusal.active_streams, refusal.max_active_streams), (2, 2));
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn successful_fetch_does_not_consume_the_offer() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        let body = "still available";
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let _ = read_fetch_header_and_manifest(&mut stream).await;
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read body").await;
        assert!(
            store
                .get_offer_source(offer_id)
                .expect("read source")
                .is_some()
        );
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn source_change_mid_transfer_aborts_and_sends_no_further_bytes() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let root = source_directory.path().join("changing-folder");
        fs::create_dir(&root).expect("create root");
        fs::write(root.join("one.txt"), b"one").expect("write first file");
        fs::write(root.join("two.txt"), b"two").expect("write second file");
        let offer_id = OfferId::new();
        insert_folder_source(&store, requester.device_id, offer_id, &root);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let _ = read_fetch_header_and_manifest(&mut stream).await;
        fs::write(root.join("two.txt"), b"changed after manifest").expect("change source");
        admit_fetch(&mut stream, request_id).await;
        let response = read_v2_test(&mut stream, "read abort").await;
        let V2Message::FetchAbort(abort) = response else {
            panic!("expected fetch abort");
        };
        assert_eq!(abort.code, FetchAbortCode::SourceChanged);
        assert_eq!(abort.files_sent, 0);
        assert_eq!(abort.bytes_sent, 0);
        write_fetch_receipt(&mut stream, request_id, offer_id).await;
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn refusal_never_contains_an_absolute_source_path() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let path = source_directory.path().join("private.txt");
        fs::write(&path, b"body").expect("write source");
        let offer_id = OfferId::new();
        insert_file_source(&store, requester.device_id, offer_id, &path);
        fs::write(&path, b"changed").expect("change source");
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let response = read_v2_test(&mut stream, "read refusal").await;
        let V2Message::FetchRefusal(refusal) = response else {
            panic!("expected refusal");
        };
        let encoded = serde_json::to_string(&refusal).expect("encode refusal");
        assert!(!encoded.contains(source_directory.path().to_str().expect("temp path")));
        assert!(refusal.detail.is_none());
        stop_offer_server(shutdown_tx, server).await;
    }
}
