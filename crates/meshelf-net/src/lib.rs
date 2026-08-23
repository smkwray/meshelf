//! Direct, one-message meshelf peer transport.
//!
//! This crate does not contain a permissive production trust policy. `DenyAll` is the safe
//! default; `ExactDeviceAllowList` exists only for loopback simulation and bounded development.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use meshelf_core::{
    ClipboardSink, DeviceId, Receipt, ReceiptCode, ReceiveStore, ReceiverService, TextEnvelope,
};
use meshelf_protocol::{
    CAP_TEXT_CLIPBOARD_PUSH_V1, ClientHello, ProtocolError, ServerHello, WireMessage,
    read_frame_async, write_frame_async,
};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

#[derive(Debug, Clone)]
pub struct ServerIdentity {
    pub device_id: DeviceId,
    pub device_name: String,
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

    pub async fn push(
        &self,
        address: SocketAddr,
        hello: ClientHello,
        envelope: TextEnvelope,
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
            .any(|capability| capability == CAP_TEXT_CLIPBOARD_PUSH_V1)
        {
            return Err(NetError::Rejected(
                "receiver does not advertise text clipboard push v1".to_owned(),
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
}

pub async fn serve<G, H>(
    listener: TcpListener,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
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
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(
                        stream,
                        remote,
                        identity,
                        gate,
                        handler,
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
    Ok(TcpListener::bind(address).await?)
}

async fn handle_connection<G, H>(
    mut stream: TcpStream,
    remote: SocketAddr,
    identity: ServerIdentity,
    gate: Arc<G>,
    handler: Arc<H>,
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
    let trust = if protocol_ok {
        gate.authorize(remote, &hello)
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
    let server_hello = WireMessage::ServerHello(ServerHello {
        protocol_version: meshelf_core::PROTOCOL_VERSION,
        device_id: identity.device_id,
        device_name: identity.device_name,
        accepted,
        reason,
        capabilities: vec![CAP_TEXT_CLIPBOARD_PUSH_V1.to_owned()],
    });
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
        return Err(NetError::UnexpectedMessage("expected push_envelope"));
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
    if envelope.target_device != identity.device_id {
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
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use meshelf_core::{
        ClipboardError, ClipboardSink, MemoryReceiveStore, ReceiptCode, ReceiverService,
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
        let source = DeviceId::new();
        let target = DeviceId::new();
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
                device_id: target,
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
                ClientHello::new(source, "BMST", "nonce-1"),
                message.clone(),
            )
            .await
            .expect("first push");
        let duplicate = client
            .push(
                address,
                ClientHello::new(source, "BMST", "nonce-2"),
                message,
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
    async fn deny_all_rejects_before_payload() {
        let source = DeviceId::new();
        let target = DeviceId::new();
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
                device_id: target,
                device_name: "BZOT".to_owned(),
            },
            Arc::new(DenyAll),
            Arc::new(CoreEnvelopeHandler::new(receiver)),
            Duration::from_secs(2),
            shutdown_rx,
        ));

        let error = PeerClient::default()
            .push(
                address,
                ClientHello::new(source, "BMST", "nonce"),
                TextEnvelope::clipboard_push(source, target, now_unix_ms(), None, "secret"),
            )
            .await
            .expect_err("deny all");
        assert!(matches!(error, NetError::Rejected(_)));

        shutdown_tx.send(true).expect("request shutdown");
        server.await.expect("server task").expect("clean server");
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
}
