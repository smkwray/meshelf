#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use meshelf_core::{DeviceId, Receipt, TextEnvelope};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    CoreEnvelopeHandler, PeerClient, ServerIdentity, TrustDecision, TrustGate,
    bind_discovered_tailscale_address, serve,
};
use meshelf_platform::{ClipboardSource, ClipboardWorker};
use meshelf_protocol::{CAP_TEXT_CLIPBOARD_PUSH_V1, ClientHello, ServerHello};
use meshelf_store::RedbReceiveStore;
use meshelf_tailscale::{
    CliPeerDiscovery, InstallationState, PeerDiscovery, SshBootstrap, SshBootstrapRequest,
    SshBootstrapResponse, TailNode, TailStatus,
};
use slint::ComponentHandle;
use tokio::{runtime::Runtime, sync::watch};
use tracing_subscriber::EnvFilter;

slint::include_modules!();

const MESHELF_PORT: u16 = 45_832;

#[derive(Debug, Clone)]
struct PendingPeer {
    node: TailNode,
    server: ServerHello,
}

#[derive(Debug, Clone)]
struct PeerView {
    name: String,
    online: bool,
    approval_available: bool,
    status: String,
}

struct DiscoveryState {
    state_path: PathBuf,
    identity: InstallationIdentity,
    installation: InstallationState,
    device_name: String,
    discovery: Option<CliPeerDiscovery>,
    last_status: Option<TailStatus>,
    pending: Option<PendingPeer>,
    selected_device: Option<DeviceId>,
}

impl DiscoveryState {
    fn load(state_path: PathBuf, device_name: String) -> Result<Self, String> {
        let identity = InstallationIdentity::load_or_create()
            .map_err(|error| format!("could not load meshelf installation identity: {error}"))?;
        let loaded = InstallationState::load(&state_path)
            .map_err(|error| format!("could not load meshelf state: {error}"))?;
        let installation = if loaded.device_id == identity.device_id {
            loaded
        } else {
            // A state file from another installation must never retain trust after a new
            // credential-store identity is created or restored.
            InstallationState {
                device_id: identity.device_id,
                peers: Default::default(),
            }
        };
        Ok(Self {
            state_path,
            identity,
            installation,
            device_name,
            discovery: CliPeerDiscovery::discover().ok(),
            last_status: None,
            pending: None,
            selected_device: None,
        })
    }

    fn refresh(&mut self) -> Result<PeerView, String> {
        let discovery = self
            .discovery
            .as_ref()
            .ok_or_else(|| "Tailscale was not found; install Tailscale and retry".to_owned())?;
        let status = discovery
            .refresh()
            .map_err(|error| format!("Tailscale discovery failed: {error}"))?;
        self.installation.peers.refresh_addresses(&status);
        self.installation
            .save(&self.state_path)
            .map_err(|error| format!("could not save meshelf state: {error}"))?;
        self.last_status = Some(status.clone());
        self.pending = None;
        self.selected_device = None;

        let runtime =
            Runtime::new().map_err(|error| format!("probe runtime unavailable: {error}"))?;
        let client = PeerClient::with_timeouts(Duration::from_secs(1), Duration::from_secs(2));
        for node in status.online_peers() {
            for address in &node.addresses {
                let socket = SocketAddr::new(*address, MESHELF_PORT);
                let Ok(server) = runtime.block_on(client.probe(socket)) else {
                    continue;
                };
                if !server
                    .capabilities
                    .iter()
                    .any(|capability| capability == CAP_TEXT_CLIPBOARD_PUSH_V1)
                {
                    continue;
                }
                if !server.has_valid_signature() {
                    continue;
                }
                self.pending = Some(PendingPeer {
                    node: node.clone(),
                    server,
                });
                return Ok(self.view());
            }
        }
        Ok(self.view())
    }

    fn send_text(&self, text: &str) -> Result<Receipt, String> {
        let device_id = self.selected_device.ok_or_else(|| {
            "this device is discovered but unpaired; use Trust both ways using SSH first".to_owned()
        })?;
        let peer = self
            .installation
            .peers
            .by_device_id(device_id)
            .ok_or_else(|| "selected meshelf device is no longer trusted".to_owned())?;
        let address = peer
            .addresses
            .first()
            .copied()
            .ok_or_else(|| "trusted device has no current Tailscale address".to_owned())?;
        let now = now_unix_ms();
        let envelope = TextEnvelope::clipboard_push(
            self.identity.device_id,
            peer.device_id,
            now,
            Some(now.saturating_add(30_000)),
            text,
        );
        let hello = ClientHello::signed(
            self.identity.device_id,
            self.device_name.clone(),
            DeviceId::new().to_string(),
            &self.identity,
        );
        let runtime =
            Runtime::new().map_err(|error| format!("send runtime unavailable: {error}"))?;
        runtime
            .block_on(PeerClient::default().push(
                SocketAddr::new(address, MESHELF_PORT),
                hello,
                envelope,
                &peer.public_key,
            ))
            .map_err(|error| format!("send failed: {error}"))
    }

    fn approve_pending(&mut self) -> Result<PeerView, String> {
        let pending = self
            .pending
            .clone()
            .ok_or_else(|| "no discovered meshelf device is waiting for approval".to_owned())?;
        let local_status = self
            .last_status
            .as_ref()
            .ok_or_else(|| "local Tailscale identity is unavailable".to_owned())?;
        let node_id = local_status
            .self_node
            .node_id
            .clone()
            .ok_or_else(|| "local Tailscale node has no stable node ID".to_owned())?;
        let bootstrap = SshBootstrap::discover(&pending.node).ok_or_else(|| {
            "no configured SSH route was found for this Tailscale peer".to_owned()
        })?;
        let response = bootstrap
            .authorize(&SshBootstrapRequest::signed(
                self.identity.device_id,
                node_id,
                local_status.self_node.hostname.clone(),
                local_status.self_node.addresses.clone(),
                &self.identity,
            ))
            .map_err(|error| format!("one-side SSH bootstrap failed: {error}"))?;
        if response.device_id != pending.server.device_id
            || response.node_id != pending.node.node_id.clone().unwrap_or_default()
            || response.public_key != pending.server.public_key
            || !response.has_valid_signature()
        {
            return Err("SSH bootstrap answered with a different meshelf identity".to_owned());
        }
        self.installation
            .peers
            .accept_signed(
                &response_to_tail_node(&response),
                pending.server.device_id,
                response.public_key.clone(),
            )
            .map_err(|error| format!("could not record reciprocal peer approval: {error}"))?;
        self.installation
            .save(&self.state_path)
            .map_err(|error| format!("could not save reciprocal peer approval: {error}"))?;
        self.selected_device = Some(pending.server.device_id);
        self.pending = None;
        Ok(self.view())
    }

    fn view(&self) -> PeerView {
        if let Some(pending) = &self.pending {
            return PeerView {
                name: pending.server.device_name.clone(),
                online: false,
                approval_available: SshBootstrap::discover(&pending.node).is_some(),
                status: format!(
                    "{} discovered on Tailscale; approve once via existing SSH",
                    pending.server.device_name
                ),
            };
        }
        if let Some(device_id) = self.selected_device
            && let Some(peer) = self.installation.peers.by_device_id(device_id)
        {
            return PeerView {
                name: peer.hostname.clone(),
                online: true,
                approval_available: false,
                status: format!("{} is ready for explicit text sends", peer.hostname),
            };
        }
        PeerView {
            name: "Not configured".to_owned(),
            online: false,
            approval_available: false,
            status: "No meshelf peer discovered on Tailscale".to_owned(),
        }
    }
}

fn response_to_tail_node(response: &SshBootstrapResponse) -> TailNode {
    TailNode {
        node_id: Some(response.node_id.clone()),
        hostname: response.hostname.clone(),
        dns_name: None,
        addresses: response.addresses.clone(),
        online: true,
        active: true,
    }
}

#[derive(Debug, Clone)]
struct FileBackedTrustGate {
    state_path: PathBuf,
}

impl TrustGate for FileBackedTrustGate {
    fn authorize(
        &self,
        remote: SocketAddr,
        hello: &meshelf_protocol::ClientHello,
    ) -> TrustDecision {
        let Ok(state) = InstallationState::load(&self.state_path) else {
            return TrustDecision::Deny("local meshelf state is unavailable".to_owned());
        };
        match state.peers.by_device_id(hello.device_id) {
            Some(peer)
                if peer.addresses.contains(&remote.ip())
                    && peer.public_key == hello.public_key
                    && hello.has_valid_signature() =>
            {
                TrustDecision::Allow
            }
            Some(_) if hello.public_key.len() != 32 => {
                TrustDecision::Deny("peer hello has no valid installation key".to_owned())
            }
            Some(_) => TrustDecision::Deny(
                "approved peer key or Tailscale address does not match".to_owned(),
            ),
            None => TrustDecision::Deny("meshelf installation has not been approved".to_owned()),
        }
    }
}

struct ServerHandle {
    shutdown: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn start_listener(
    state: &DiscoveryState,
    clipboard: &ClipboardWorker,
    data_dir: &Path,
) -> Result<ServerHandle, String> {
    let status = state
        .last_status
        .as_ref()
        .ok_or_else(|| "Tailscale status is unavailable".to_owned())?;
    let address = status
        .self_node
        .addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4())
        .or_else(|| status.self_node.addresses.first().copied())
        .ok_or_else(|| "Tailscale supplied no local address".to_owned())?;
    let runtime =
        Runtime::new().map_err(|error| format!("listener runtime unavailable: {error}"))?;
    let listener = runtime
        .block_on(bind_discovered_tailscale_address(
            SocketAddr::new(address, MESHELF_PORT),
            &status.self_node.addresses,
        ))
        .map_err(|error| format!("could not bind Tailscale listener: {error}"))?;
    let store = RedbReceiveStore::open(data_dir.join("meshelf.redb"))
        .map_err(|error| format!("could not open receive ledger: {error}"))?;
    let receiver = Arc::new(meshelf_core::ReceiverService::new(
        state.installation.device_id,
        Arc::new(store),
        Arc::new(clipboard.clone()),
    ));
    let handler = Arc::new(CoreEnvelopeHandler::new(receiver));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let identity = ServerIdentity {
        signing_identity: state.identity.clone(),
        device_name: state.device_name.clone(),
    };
    let gate = Arc::new(FileBackedTrustGate {
        state_path: state.state_path.clone(),
    });
    let worker = thread::Builder::new()
        .name("meshelf-network".to_owned())
        .spawn(move || {
            let Ok(runtime) = Runtime::new() else {
                return;
            };
            let _ = runtime.block_on(serve(
                listener,
                identity,
                gate,
                handler,
                Duration::from_secs(5),
                shutdown_rx,
            ));
        })
        .map_err(|error| format!("could not start Tailscale listener: {error}"))?;
    Ok(ServerHandle {
        shutdown,
        worker: Some(worker),
    })
}

fn apply_peer_view(window: &MainWindow, view: PeerView) {
    window.set_default_peer(view.name.into());
    window.set_default_peer_online(view.online);
    window.set_default_peer_approval_available(view.approval_available);
    window.set_status_text(view.status.into());
}

fn now_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn main() -> Result<()> {
    if std::env::args()
        .any(|argument| argument == "pair-stdio" || argument == "--ssh-bootstrap-stdin")
    {
        return meshelf_bootstrap::run_stdio();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .without_time()
        .init();

    let window = MainWindow::new()?;
    let tray = MeshelfTray::new()?;
    let device_name = std::env::var("MESHELF_DEVICE_NAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".to_owned());
    window.set_device_name(device_name.clone().into());
    tray.set_tooltip_text(format!("meshelf — {device_name}").into());

    let data_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("meshelf");
    fs::create_dir_all(&data_dir)?;
    let state_path = data_dir.join("state.json");
    let app_state = Arc::new(Mutex::new(
        DiscoveryState::load(state_path, device_name.clone())
            .map_err(|error| anyhow::anyhow!(error))?,
    ));
    let initial_view = {
        let mut state = app_state.lock().expect("app state mutex");
        match state.refresh() {
            Ok(view) => view,
            Err(error) => PeerView {
                name: "Not configured".to_owned(),
                online: false,
                approval_available: false,
                status: error,
            },
        }
    };
    apply_peer_view(&window, initial_view);

    let clipboard = match ClipboardWorker::new() {
        Ok(clipboard) => Some(clipboard),
        Err(error) => {
            window.set_status_text(format!("Clipboard unavailable: {error}").into());
            None
        }
    };
    let _server = clipboard.as_ref().and_then(|clipboard| {
        let state = app_state.lock().ok()?;
        match start_listener(&state, clipboard, &data_dir) {
            Ok(server) => Some(server),
            Err(error) => {
                window.set_status_text(error.into());
                None
            }
        }
    });

    {
        let window_weak = window.as_weak();
        let clipboard = clipboard.clone();
        window.on_paste_clipboard(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let Some(clipboard) = clipboard.as_ref() else {
                window.set_status_text("Clipboard adapter is unavailable".into());
                return;
            };
            match clipboard.read_text() {
                Ok(text) => {
                    window.set_draft_text(text.into());
                    window
                        .set_status_text("Clipboard loaded locally; nothing has been sent".into());
                }
                Err(error) => {
                    window.set_status_text(format!("Could not read clipboard: {error}").into());
                }
            }
        });
    }

    {
        let window_weak = window.as_weak();
        let app_state = app_state.clone();
        window.on_send_default(move |draft| {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            if draft.trim().is_empty() {
                window.set_status_text("Nothing to send".into());
                return;
            }
            let result = app_state
                .lock()
                .map_err(|_| "app state is unavailable".to_owned())
                .and_then(|state| {
                    state
                        .send_text(&draft)
                        .map(|receipt| format!("Send result: {:?}", receipt.code))
                });
            window.set_status_text(result.unwrap_or_else(|error| error).into());
        });
    }

    {
        let window_weak = window.as_weak();
        let app_state = app_state.clone();
        window.on_refresh_peers(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let result = app_state
                .lock()
                .map_err(|_| "app state is unavailable".to_owned())
                .and_then(|mut state| state.refresh());
            match result {
                Ok(view) => apply_peer_view(&window, view),
                Err(error) => window.set_status_text(error.into()),
            }
        });
    }

    {
        let window_weak = window.as_weak();
        let app_state = app_state.clone();
        window.on_approve_default(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let result = app_state
                .lock()
                .map_err(|_| "app state is unavailable".to_owned())
                .and_then(|mut state| state.approve_pending());
            match result {
                Ok(view) => apply_peer_view(&window, view),
                Err(error) => window.set_status_text(error.into()),
            }
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_open_window(move || {
            if let Some(window) = window_weak.upgrade() {
                let _ = window.show();
            }
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_send_default(move || {
            if let Some(window) = window_weak.upgrade() {
                window.set_status_text("Open meshelf to review the explicit send".into());
                let _ = window.show();
            }
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_choose_target(move || {
            if let Some(window) = window_weak.upgrade() {
                window
                    .set_status_text("Refresh peers to discover a Tailscale meshelf device".into());
                let _ = window.show();
            }
        });
    }

    tray.on_quit(|| {
        let _ = slint::quit_event_loop();
    });

    window.show()?;
    tray.show()?;
    slint::run_event_loop()?;
    Ok(())
}
