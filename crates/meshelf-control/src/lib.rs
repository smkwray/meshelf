//! Shared application controller used by the desktop UI and `meshelfctl`.
//!
//! Every user-facing operation remains explicit. Discovery does not read the clipboard or
//! create trust; SSH trust is a one-time local action; sends use the direct signed protocol.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use meshelf_core::{DeviceId, Receipt, TextEnvelope};
use meshelf_identity::InstallationIdentity;
use meshelf_net::PeerClient;
use meshelf_protocol::{CAP_TEXT_CLIPBOARD_PUSH_V1, ClientHello, ServerHello};
use meshelf_tailscale::{
    CliPeerDiscovery, InstallationState, PeerDiscovery, SshBootstrap, SshBootstrapRequest,
    SshBootstrapResponse, TailNode, TailStatus,
};
use tokio::runtime::Runtime;

pub const MESHELF_PORT: u16 = 45_832;

#[derive(Debug, Clone)]
pub struct PendingPeer {
    pub node: TailNode,
    pub server: ServerHello,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerView {
    pub name: String,
    pub online: bool,
    pub approval_available: bool,
    pub status: String,
}

pub struct Controller {
    pub state_path: PathBuf,
    pub identity: InstallationIdentity,
    pub installation: InstallationState,
    pub device_name: String,
    discovery: Option<CliPeerDiscovery>,
    pub last_status: Option<TailStatus>,
    pub pending: Option<PendingPeer>,
    pub selected_device: Option<DeviceId>,
}

impl Controller {
    pub fn load(state_path: PathBuf, device_name: String) -> Result<Self, String> {
        let identity = InstallationIdentity::load_or_create()
            .map_err(|error| format!("could not load meshelf installation identity: {error}"))?;
        let loaded = InstallationState::load(&state_path)
            .map_err(|error| format!("could not load meshelf state: {error}"))?;
        let installation = if loaded.device_id == identity.device_id {
            loaded
        } else {
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

    pub fn refresh(&mut self) -> Result<PeerView, String> {
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
                    || !server.has_valid_signature()
                {
                    continue;
                }
                let already_trusted = node
                    .node_id
                    .as_deref()
                    .and_then(|node_id| self.installation.peers.by_node_id(node_id))
                    .is_some_and(|peer| {
                        peer.device_id == server.device_id && peer.public_key == server.public_key
                    });
                if already_trusted {
                    self.selected_device = Some(server.device_id);
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

    pub fn approve_pending(&mut self) -> Result<PeerView, String> {
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
                response.public_key,
            )
            .map_err(|error| format!("could not record reciprocal peer approval: {error}"))?;
        self.installation
            .save(&self.state_path)
            .map_err(|error| format!("could not save reciprocal peer approval: {error}"))?;
        self.selected_device = Some(pending.server.device_id);
        self.pending = None;
        Ok(self.view())
    }

    pub fn select_peer(&mut self, selector: Option<&str>) -> Result<(), String> {
        if let Some(selector) = selector {
            if let Ok(device_id) = selector.parse::<DeviceId>()
                && self.installation.peers.by_device_id(device_id).is_some()
            {
                self.selected_device = Some(device_id);
                return Ok(());
            }
            let needle = selector.to_ascii_lowercase();
            if let Some(peer) = self
                .installation
                .peers
                .peers()
                .iter()
                .find(|peer| peer.hostname.to_ascii_lowercase() == needle)
            {
                self.selected_device = Some(peer.device_id);
                return Ok(());
            }
            return Err(format!("trusted meshelf peer not found: {selector}"));
        }
        if self.selected_device.is_none() {
            self.selected_device = self
                .installation
                .peers
                .peers()
                .first()
                .map(|peer| peer.device_id);
        }
        self.selected_device
            .map(|_| ())
            .ok_or_else(|| "no trusted meshelf peer is configured".to_owned())
    }

    pub fn send_text(&self, text: &str) -> Result<Receipt, String> {
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

    #[must_use]
    pub fn view(&self) -> PeerView {
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

#[must_use]
pub fn response_to_tail_node(response: &SshBootstrapResponse) -> TailNode {
    TailNode {
        node_id: Some(response.node_id.clone()),
        hostname: response.hostname.clone(),
        dns_name: None,
        addresses: response.addresses.clone(),
        online: true,
        active: true,
    }
}

fn now_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

pub fn state_path(config_dir: &Path) -> PathBuf {
    config_dir.join("state.json")
}
