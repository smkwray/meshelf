//! Direct, one-message meshelf peer transport.
//!
//! This crate does not contain a permissive production trust policy. `DenyAll` is the safe
//! default; `ExactDeviceAllowList` exists only for loopback simulation and bounded development.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr, TcpListener as StdTcpListener},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use meshelf_core::{
    ClipboardSink, ContentKind, DeviceId, Receipt, ReceiptCode, ReceiveStore, ReceiverService,
    TextEnvelope,
};
use meshelf_protocol::{
    CAP_FILE_STREAM_V1, CAP_TEXT_SHELF_V1, ClientHello, FileAdmission, FileEntryKind,
    FileTransferOffer, MAX_FILE_BYTES, MAX_FILE_ENTRIES, MAX_RELATIVE_PATH_BYTES,
    MAX_TRANSFER_BYTES, ProtocolError, ServerHello, WireMessage, read_frame_async,
    write_frame_async,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

const MAX_PORTABLE_COMPONENT_BYTES: usize = 255;

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

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_RELATIVE_PATH_BYTES {
        return Err("file path is empty or too long".to_owned());
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') || path.contains(':')
    {
        return Err(format!("unsafe file path: {path}"));
    }
    for component in path.split('/') {
        validate_component(component)?;
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), String> {
    let contains_platform_forbidden_character = component.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    });
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > MAX_PORTABLE_COMPONENT_BYTES
        || contains_platform_forbidden_character
    {
        return Err(format!("unsafe file name component: {component:?}"));
    }
    let device_stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let numbered_device_suffix = device_stem
        .strip_prefix("COM")
        .or_else(|| device_stem.strip_prefix("LPT"));
    let reserved = matches!(device_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || numbered_device_suffix.is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if reserved || component.ends_with(' ') || component.ends_with('.') {
        return Err(format!("platform-reserved file name: {component}"));
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
        identity,
        gate,
        handler,
        None,
        io_timeout_duration,
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
        identity,
        gate,
        handler,
        Some(incoming_directory),
        io_timeout_duration,
        shutdown,
    )
    .await
}

async fn serve_inner<G, H>(
    listener: TcpListener,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
    incoming_directory: Option<PathBuf>,
    io_timeout_duration: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
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
                let identity = identity.clone();
                let gate = gate.clone();
                let handler = handler.clone();
                let incoming_directory = incoming_directory.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(
                        stream,
                        remote,
                        identity,
                        gate,
                        handler,
                        incoming_directory,
                        io_timeout_duration,
                    ).await {
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

async fn handle_connection<G, H>(
    mut stream: TcpStream,
    remote: SocketAddr,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
    incoming_directory: Option<PathBuf>,
    io_timeout_duration: Duration,
) -> Result<(), NetError>
where
    G: TrustGate,
    H: EnvelopeHandler,
{
    stream.set_nodelay(true)?;
    let first = io_timeout(
        io_timeout_duration,
        read_frame_async(&mut stream),
        "read client hello",
    )
    .await?;
    let WireMessage::ClientHello(hello) = first else {
        return Err(NetError::UnexpectedMessage("expected client_hello"));
    };

    let protocol_ok = hello.protocol_version == meshelf_core::PROTOCOL_VERSION;
    let trust = if protocol_ok && hello.has_valid_signature() {
        gate.authorize(remote, &hello)
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
    if incoming_directory.is_some() {
        capabilities.push(CAP_FILE_STREAM_V1.to_owned());
    }
    let server_hello = WireMessage::ServerHello(ServerHello::signed(
        meshelf_core::PROTOCOL_VERSION,
        identity.device_id(),
        identity.device_name.clone(),
        accepted,
        reason,
        capabilities,
        &identity.signing_identity,
    ));
    io_timeout(
        io_timeout_duration,
        write_frame_async(&mut stream, &server_hello),
        "write server hello",
    )
    .await?;
    if !accepted {
        return Ok(());
    }

    let message = io_timeout(
        io_timeout_duration,
        read_frame_async(&mut stream),
        "read envelope",
    )
    .await?;
    let WireMessage::PushEnvelope(envelope) = message else {
        if let WireMessage::FileOffer(offer) = message {
            let Some(incoming_directory) = incoming_directory else {
                return Err(NetError::FileTransfer(
                    "file receiving is not configured".to_owned(),
                ));
            };
            return handle_file_offer(
                &mut stream,
                &hello,
                identity.device_id(),
                offer,
                &incoming_directory,
                handler,
                io_timeout_duration,
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
            io_timeout_duration,
            write_frame_async(&mut stream, &WireMessage::Receipt(receipt)),
            "write rejection receipt",
        )
        .await?;
        return Ok(());
    }
    if envelope.target_device != identity.device_id() {
        let receipt = Receipt::rejected(
            envelope.message_id,
            ReceiptCode::RejectedWrongTarget,
            "message target does not match listener device",
        );
        io_timeout(
            io_timeout_duration,
            write_frame_async(&mut stream, &WireMessage::Receipt(receipt)),
            "write wrong-target receipt",
        )
        .await?;
        return Ok(());
    }

    let receipt = handler.handle(envelope, now_unix_ms()).await;
    io_timeout(
        io_timeout_duration,
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
    for index in 1..=9999 {
        let final_path = collision_candidate(directory, root_name, content_kind, index)?;
        match finalize_payload(payload, &final_path, content_kind).await {
            Ok(()) => return Ok(final_path),
            Err(NetError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    let suffix = format!(".{}", meshelf_core::MessageId::new());
    let final_path = directory.join(component_with_suffix(root_name, &suffix)?);
    finalize_payload(payload, &final_path, content_kind).await?;
    Ok(final_path)
}

async fn finalize_payload(
    payload: &Path,
    final_path: &Path,
    content_kind: ContentKind,
) -> Result<(), NetError> {
    if content_kind == ContentKind::File {
        std::fs::hard_link(payload, final_path)?;
        // Once the no-replace link exists, staging cleanup must not turn a valid publication into
        // a failed transfer. The caller removes the whole transfer staging directory as well.
        let _ = tokio::fs::remove_file(payload).await;
    } else {
        rename_exclusive_portable(payload, final_path)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn rename_exclusive_portable(payload: &Path, final_path: &Path) -> std::io::Result<()> {
    renamore::rename_exclusive(payload, final_path)
}

#[cfg(windows)]
fn rename_exclusive_portable(payload: &Path, final_path: &Path) -> std::io::Result<()> {
    let payload = windows_verbatim_path(payload)?;
    let final_path = windows_verbatim_path(final_path)?;
    renamore::rename_exclusive(&payload, &final_path)
}

#[cfg(windows)]
fn windows_verbatim_path(path: &Path) -> std::io::Result<PathBuf> {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
    };

    const SEP: u16 = b'\\' as u16;
    const DOT: u16 = b'.' as u16;
    const QUERY: u16 = b'?' as u16;
    const U: u16 = b'U' as u16;
    const N: u16 = b'N' as u16;
    const C: u16 = b'C' as u16;
    const VERBATIM_PREFIX: &[u16] = &[SEP, SEP, QUERY, SEP];
    const NT_PREFIX: &[u16] = &[SEP, QUERY, QUERY, SEP];
    const DEVICE_PREFIX: &[u16] = &[SEP, SEP, DOT, SEP];
    const UNC_PREFIX: &[u16] = &[SEP, SEP, QUERY, SEP, U, N, C, SEP];

    let absolute = std::path::absolute(path)?;
    let wide = absolute.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.starts_with(VERBATIM_PREFIX) || wide.starts_with(NT_PREFIX) {
        return Ok(absolute);
    }

    let (prefix, body) = if wide.starts_with(DEVICE_PREFIX) {
        (VERBATIM_PREFIX, &wide[DEVICE_PREFIX.len()..])
    } else if wide.starts_with(&[SEP, SEP]) {
        (UNC_PREFIX, &wide[2..])
    } else {
        (VERBATIM_PREFIX, wide.as_slice())
    };
    let mut verbatim = Vec::with_capacity(prefix.len() + body.len());
    verbatim.extend_from_slice(prefix);
    verbatim.extend_from_slice(body);
    Ok(PathBuf::from(OsString::from_wide(&verbatim)))
}

fn collision_candidate(
    directory: &Path,
    root_name: &str,
    content_kind: ContentKind,
    index: usize,
) -> Result<PathBuf, NetError> {
    if index == 1 {
        validate_component(root_name).map_err(generated_component_error)?;
        return Ok(directory.join(root_name));
    }

    let suffix = format!(" ({index})");
    let source = Path::new(root_name);
    let extension = (content_kind == ContentKind::File)
        .then(|| source.extension().and_then(|value| value.to_str()))
        .flatten();
    if let Some(extension) = extension {
        let stem = source
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or(root_name);
        let fixed_bytes = suffix
            .len()
            .checked_add(1)
            .and_then(|value| value.checked_add(extension.len()))
            .ok_or_else(|| {
                NetError::FileTransfer("generated destination name length overflow".to_owned())
            })?;
        if let Some(max_stem_bytes) = MAX_PORTABLE_COMPONENT_BYTES.checked_sub(fixed_bytes) {
            let stem = truncate_utf8(stem, max_stem_bytes);
            if !stem.is_empty() {
                let name = format!("{stem}{suffix}.{extension}");
                validate_component(&name).map_err(generated_component_error)?;
                return Ok(directory.join(name));
            }
        }
    }

    Ok(directory.join(component_with_suffix(root_name, &suffix)?))
}

fn component_with_suffix(component: &str, suffix: &str) -> Result<String, NetError> {
    let max_component_bytes = MAX_PORTABLE_COMPONENT_BYTES
        .checked_sub(suffix.len())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            NetError::FileTransfer(format!(
                "generated destination suffix is {} bytes; maximum component is {MAX_PORTABLE_COMPONENT_BYTES}",
                suffix.len()
            ))
        })?;
    let component = truncate_utf8(component, max_component_bytes);
    if component.is_empty() {
        return Err(NetError::FileTransfer(
            "generated destination suffix leaves no complete UTF-8 character for the name"
                .to_owned(),
        ));
    }
    let name = format!("{component}{suffix}");
    validate_component(&name).map_err(generated_component_error)?;
    Ok(name)
}

fn generated_component_error(error: String) -> NetError {
    NetError::FileTransfer(format!("generated destination name is invalid: {error}"))
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn relative_path(value: &str) -> PathBuf {
    value.split('/').collect()
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
    #[error("unexpected wire message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("identity mismatch: {0}")]
    IdentityMismatch(String),
    #[error("unsafe bind refused: {0}")]
    UnsafeBind(String),
    #[error("file transfer failed: {0}")]
    FileTransfer(String),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, Mutex};

    use meshelf_core::{
        ClipboardError, ClipboardSink, MemoryReceiveStore, ReceiptCode, ReceiveStore,
        ReceiverService,
    };
    use meshelf_protocol::ClientHello;
    use tokio::sync::watch;

    use super::*;

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

    #[tokio::test]
    async fn loopback_delivery_is_duplicate_safe() {
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
            Duration::from_secs(2),
            shutdown_rx,
        ));

        let message = TextEnvelope::clipboard_push(source, target, now_unix_ms(), None, "hello");
        let client = PeerClient::with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
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
            Duration::from_secs(2),
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
        let client = PeerClient::with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
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
            Duration::from_secs(2),
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
        let receipt = PeerClient::with_timeouts(Duration::from_secs(2), Duration::from_secs(2))
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
            Duration::from_secs(2),
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
                .block_on(async { timeout(Duration::from_secs(2), listener.accept()).await })
                .expect("listener accepted before timeout")
                .expect("accept connection");
        });

        ready_rx.recv().expect("listener attached");
        std::net::TcpStream::connect(bound_address).expect("connect to moved listener");
        worker.join().expect("server worker");
    }
}
