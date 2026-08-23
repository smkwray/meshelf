//! Local, on-demand Tailscale peer discovery.
//!
//! The user never needs to run a terminal command. This adapter invokes the already-installed
//! Tailscale CLI internally only on explicit refresh/send paths. It never polls in the background.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
};

use meshelf_core::DeviceId;
use serde::Deserialize;
use thiserror::Error;

const MAX_STATUS_JSON_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailNode {
    pub node_id: Option<String>,
    pub hostname: String,
    pub dns_name: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub online: bool,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailStatus {
    pub backend_state: String,
    pub self_node: TailNode,
    pub peers: Vec<TailNode>,
}

impl TailStatus {
    /// Return peers that are currently usable candidates for a bounded meshelf probe.
    ///
    /// Tailscale tells us which nodes exist and which are online; the meshelf network probe
    /// decides whether the application is actually present. This deliberately does not scan
    /// SSH or treat tailnet membership as application trust.
    pub fn online_peers(&self) -> impl Iterator<Item = &TailNode> {
        self.peers.iter().filter(|peer| peer.online && peer.active)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedPeer {
    pub node_id: String,
    pub device_id: DeviceId,
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerRegistry {
    peers: Vec<TrustedPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstallationState {
    pub device_id: DeviceId,
    pub peers: PeerRegistry,
}

impl Default for InstallationState {
    fn default() -> Self {
        Self {
            device_id: DeviceId::new(),
            peers: PeerRegistry::default(),
        }
    }
}

impl InstallationState {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let path = path.as_ref();
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(RegistryError::Io(error)),
        };
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(RegistryError::TooLarge {
                bytes: bytes.len(),
                maximum: MAX_REGISTRY_BYTES,
            });
        }
        serde_json::from_slice(&bytes).map_err(RegistryError::Json)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), RegistryError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(RegistryError::Json)?;
        fs::write(path, bytes).map_err(RegistryError::Io)
    }
}

impl PeerRegistry {
    #[must_use]
    pub fn peers(&self) -> &[TrustedPeer] {
        &self.peers
    }

    #[must_use]
    pub fn by_device_id(&self, device_id: DeviceId) -> Option<&TrustedPeer> {
        self.peers.iter().find(|peer| peer.device_id == device_id)
    }

    #[must_use]
    pub fn by_node_id(&self, node_id: &str) -> Option<&TrustedPeer> {
        self.peers.iter().find(|peer| peer.node_id == node_id)
    }

    /// Record one explicit acceptance, preserving the original device identity for that
    /// Tailscale node. Re-accepting the same node with a different meshelf identity is refused.
    pub fn accept(&mut self, node: &TailNode, device_id: DeviceId) -> Result<(), RegistryError> {
        let node_id = node
            .node_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(RegistryError::MissingNodeId)?;
        if let Some(existing) = self.peers.iter_mut().find(|peer| peer.node_id == node_id) {
            if existing.device_id != device_id {
                return Err(RegistryError::IdentityConflict {
                    node_id: node_id.to_owned(),
                });
            }
            existing.hostname = node.hostname.clone();
            existing.addresses = node.addresses.clone();
            return Ok(());
        }
        self.peers.push(TrustedPeer {
            node_id: node_id.to_owned(),
            device_id,
            hostname: node.hostname.clone(),
            addresses: node.addresses.clone(),
        });
        self.peers.sort_by(|left, right| {
            left.hostname
                .to_ascii_lowercase()
                .cmp(&right.hostname.to_ascii_lowercase())
        });
        Ok(())
    }

    /// Refresh accepted peers' display names and current Tailscale addresses without changing
    /// the one-time acceptance decision.
    pub fn refresh_addresses(&mut self, status: &TailStatus) {
        for trusted in &mut self.peers {
            let Some(node) = status
                .peers
                .iter()
                .find(|node| node.node_id.as_deref() == Some(trusted.node_id.as_str()))
            else {
                continue;
            };
            trusted.hostname = node.hostname.clone();
            trusted.addresses = node.addresses.clone();
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let path = path.as_ref();
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(RegistryError::Io(error)),
        };
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(RegistryError::TooLarge {
                bytes: bytes.len(),
                maximum: MAX_REGISTRY_BYTES,
            });
        }
        serde_json::from_slice(&bytes).map_err(RegistryError::Json)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), RegistryError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(RegistryError::Json)?;
        fs::write(path, bytes).map_err(RegistryError::Io)
    }
}

const MAX_REGISTRY_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("accepted Tailscale node has no stable node ID")]
    MissingNodeId,
    #[error("Tailscale node {node_id} is already bound to another meshelf identity")]
    IdentityConflict { node_id: String },
    #[error("peer registry I/O error: {0}")]
    Io(#[source] std::io::Error),
    #[error("peer registry JSON error: {0}")]
    Json(#[source] serde_json::Error),
    #[error("peer registry is {bytes} bytes; maximum is {maximum}")]
    TooLarge { bytes: usize, maximum: usize },
}

pub trait PeerDiscovery: Send + Sync + 'static {
    fn refresh(&self) -> Result<TailStatus, DiscoveryError>;
}

#[derive(Debug, Clone)]
pub struct CliPeerDiscovery {
    binary: PathBuf,
}

impl CliPeerDiscovery {
    pub fn discover() -> Result<Self, DiscoveryError> {
        locate_tailscale_binary()
            .map(|binary| Self { binary })
            .ok_or(DiscoveryError::BinaryNotFound)
    }

    #[must_use]
    pub fn from_binary(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }
}

impl PeerDiscovery for CliPeerDiscovery {
    fn refresh(&self) -> Result<TailStatus, DiscoveryError> {
        let output = Command::new(&self.binary)
            .args(["status", "--json"])
            .output()
            .map_err(DiscoveryError::Launch)?;
        if !output.status.success() {
            return Err(DiscoveryError::NonZeroExit {
                code: output.status.code(),
                stderr: bounded_lossy(&output.stderr, 4096),
            });
        }
        if output.stdout.len() > MAX_STATUS_JSON_BYTES {
            return Err(DiscoveryError::OutputTooLarge {
                bytes: output.stdout.len(),
                maximum: MAX_STATUS_JSON_BYTES,
            });
        }
        parse_status_json(&output.stdout)
    }
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Tailscale CLI was not found; set MESHELF_TAILSCALE_BIN or install Tailscale")]
    BinaryNotFound,
    #[error("failed to launch Tailscale CLI: {0}")]
    Launch(#[source] std::io::Error),
    #[error("Tailscale status failed with exit code {code:?}: {stderr}")]
    NonZeroExit { code: Option<i32>, stderr: String },
    #[error("Tailscale status output is {bytes} bytes; maximum is {maximum}")]
    OutputTooLarge { bytes: usize, maximum: usize },
    #[error("invalid Tailscale status JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("Tailscale status did not contain a local Self node")]
    MissingSelf,
    #[error("Tailscale status contained no valid IP address for {node}")]
    MissingAddress { node: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawStatus {
    #[serde(default)]
    backend_state: String,
    #[serde(rename = "Self")]
    self_node: Option<RawNode>,
    #[serde(default)]
    peer: BTreeMap<String, RawNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawNode {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_i_ps: Vec<String>,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    active: bool,
}

pub fn parse_status_json(bytes: &[u8]) -> Result<TailStatus, DiscoveryError> {
    let raw: RawStatus = serde_json::from_slice(bytes)?;
    let self_raw = raw.self_node.ok_or(DiscoveryError::MissingSelf)?;
    let self_node = convert_node(self_raw)?;
    let mut peers = raw
        .peer
        .into_values()
        .map(convert_node)
        .collect::<Result<Vec<_>, _>>()?;
    peers.sort_by(|left, right| {
        left.hostname
            .to_ascii_lowercase()
            .cmp(&right.hostname.to_ascii_lowercase())
    });
    Ok(TailStatus {
        backend_state: raw.backend_state,
        self_node,
        peers,
    })
}

fn convert_node(raw: RawNode) -> Result<TailNode, DiscoveryError> {
    let hostname = if raw.host_name.trim().is_empty() {
        raw.dns_name
            .as_deref()
            .unwrap_or("unknown-tailnet-device")
            .trim_end_matches('.')
            .split('.')
            .next()
            .unwrap_or("unknown-tailnet-device")
            .to_owned()
    } else {
        raw.host_name
    };
    let addresses = raw
        .tailscale_i_ps
        .iter()
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(DiscoveryError::MissingAddress { node: hostname });
    }
    Ok(TailNode {
        node_id: raw.id,
        hostname,
        dns_name: raw
            .dns_name
            .map(|value| value.trim_end_matches('.').to_owned()),
        addresses,
        online: raw.online,
        active: raw.active,
    })
}

#[must_use]
pub fn locate_tailscale_binary() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("MESHELF_TAILSCALE_BIN") {
        let path = PathBuf::from(explicit);
        if is_file(&path) {
            return Some(path);
        }
    }

    let executable = if cfg!(windows) {
        OsString::from("tailscale.exe")
    } else {
        OsString::from("tailscale")
    };
    if let Some(path) = find_on_path(&executable) {
        return Some(path);
    }

    known_binary_locations()
        .into_iter()
        .find(|path| is_file(path))
}

fn find_on_path(executable: &OsString) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(executable))
            .find(|candidate| is_file(candidate))
    })
}

fn known_binary_locations() -> Vec<PathBuf> {
    let mut locations = vec![
        PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale"),
        PathBuf::from("/usr/bin/tailscale"),
        PathBuf::from("/usr/local/bin/tailscale"),
    ];
    if let Some(program_files) = env::var_os("ProgramFiles") {
        locations.push(
            PathBuf::from(program_files)
                .join("Tailscale")
                .join("tailscale.exe"),
        );
    }
    locations
}

fn is_file(path: &Path) -> bool {
    path.metadata()
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn bounded_lossy(bytes: &[u8], maximum: usize) -> String {
    let slice = if bytes.len() > maximum {
        &bytes[..maximum]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture_and_sorts_peers() {
        let status = parse_status_json(include_bytes!("../fixtures/tailscale-status.json"))
            .expect("parse fixture");
        assert_eq!(status.backend_state, "Running");
        assert_eq!(status.self_node.hostname, "BMST");
        assert_eq!(status.peers.len(), 2);
        assert_eq!(status.peers[0].hostname, "BZOT");
        assert_eq!(status.peers[1].hostname, "SPARK");
        assert_eq!(status.peers[0].addresses[0].to_string(), "100.77.0.2");
        assert_eq!(
            status
                .online_peers()
                .map(|peer| peer.hostname.as_str())
                .collect::<Vec<_>>(),
            ["BZOT"]
        );
    }

    #[test]
    fn rejects_node_without_parseable_address() {
        let input = br#"{
            "BackendState":"Running",
            "Self":{"HostName":"BMST","TailscaleIPs":["not-an-ip"]},
            "Peer":{}
        }"#;
        assert!(matches!(
            parse_status_json(input),
            Err(DiscoveryError::MissingAddress { .. })
        ));
    }

    #[test]
    fn one_time_acceptance_persists_and_refreshes_addresses() {
        let mut registry = PeerRegistry::default();
        let device_id = DeviceId::new();
        let node = TailNode {
            node_id: Some("bzot-node".to_owned()),
            hostname: "BZOT".to_owned(),
            dns_name: Some("bzot.example.ts.net".to_owned()),
            addresses: vec!["100.77.0.2".parse().expect("address")],
            online: true,
            active: true,
        };
        registry.accept(&node, device_id).expect("accept peer");

        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("peers.json");
        registry.save(&path).expect("save registry");
        let mut reopened = PeerRegistry::load(&path).expect("load registry");
        assert_eq!(reopened.peers(), registry.peers());

        let status = TailStatus {
            backend_state: "Running".to_owned(),
            self_node: node.clone(),
            peers: vec![TailNode {
                addresses: vec!["100.77.0.22".parse().expect("updated address")],
                ..node
            }],
        };
        reopened.refresh_addresses(&status);
        assert_eq!(reopened.peers()[0].addresses[0].to_string(), "100.77.0.22");
    }

    #[test]
    fn refuses_identity_replacement_for_accepted_node() {
        let mut registry = PeerRegistry::default();
        let node = TailNode {
            node_id: Some("bzot-node".to_owned()),
            hostname: "BZOT".to_owned(),
            dns_name: None,
            addresses: vec!["100.77.0.2".parse().expect("address")],
            online: true,
            active: true,
        };
        registry
            .accept(&node, DeviceId::new())
            .expect("first accept");
        assert!(matches!(
            registry.accept(&node, DeviceId::new()),
            Err(RegistryError::IdentityConflict { .. })
        ));
    }
}
