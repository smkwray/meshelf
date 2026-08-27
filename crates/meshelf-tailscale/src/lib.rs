//! Local, on-demand Tailscale peer discovery.
//!
//! The user never needs to run a terminal command. This adapter invokes the already-installed
//! Tailscale CLI internally only on explicit refresh/send paths. It never polls in the background.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use atomic_write_file::AtomicWriteFile;
use meshelf_core::{DeviceId, UserSettings};
use serde::Deserialize;
use thiserror::Error;

const MAX_STATUS_JSON_BYTES: usize = 8 * 1024 * 1024;
const STATUS_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

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
        self.peers.iter().filter(|peer| peer.online)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedPeer {
    pub node_id: String,
    pub device_id: DeviceId,
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    /// The peer's Ed25519 installation key. An absent key is legacy state and is not trusted by
    /// the production network gate.
    #[serde(default)]
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerRegistry {
    peers: Vec<TrustedPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstallationState {
    pub device_id: DeviceId,
    pub peers: PeerRegistry,
    #[serde(default)]
    pub settings: UserSettings,
}

/// Cross-process transaction boundary for the shared per-user installation state.
///
/// The desktop and other meshelf processes share this store. Every production read and
/// mutation goes through the same sidecar lock, and every mutation atomically replaces the state
/// file while that lock remains held.
#[derive(Debug, Clone)]
pub struct InstallationStore {
    state_path: PathBuf,
    lock_path: PathBuf,
}

impl Default for InstallationState {
    fn default() -> Self {
        Self {
            device_id: DeviceId::new(),
            peers: PeerRegistry::default(),
            settings: UserSettings::default(),
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
        let mut file = AtomicWriteFile::open(path).map_err(RegistryError::Io)?;
        file.write_all(&bytes).map_err(RegistryError::Io)?;
        file.sync_all().map_err(RegistryError::Io)?;
        file.commit().map_err(RegistryError::Io)
    }
}

impl InstallationStore {
    #[must_use]
    pub fn new(state_path: impl Into<PathBuf>) -> Self {
        let state_path = state_path.into();
        let mut lock_name = OsString::from(state_path.as_os_str());
        lock_name.push(".lock");
        Self {
            state_path,
            lock_path: PathBuf::from(lock_name),
        }
    }

    pub fn load_for_identity(
        &self,
        identity: DeviceId,
    ) -> Result<InstallationState, RegistryError> {
        self.with_exclusive_lock(|| self.load_reconciled(identity))
    }

    pub fn update<F>(
        &self,
        identity: DeviceId,
        update: F,
    ) -> Result<InstallationState, RegistryError>
    where
        F: FnOnce(&mut InstallationState) -> Result<(), RegistryError>,
    {
        self.with_exclusive_lock(|| {
            let mut latest = self.load_reconciled(identity)?;
            update(&mut latest)?;
            latest.save(&self.state_path)?;
            Ok(latest)
        })
    }

    fn load_reconciled(&self, identity: DeviceId) -> Result<InstallationState, RegistryError> {
        let loaded = InstallationState::load(&self.state_path)?;
        if loaded.device_id == identity {
            Ok(loaded)
        } else {
            Ok(InstallationState {
                device_id: identity,
                peers: PeerRegistry::default(),
                settings: loaded.settings,
            })
        }
    }

    fn with_exclusive_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        if let Some(parent) = self
            .state_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(RegistryError::Io)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(RegistryError::Io)?;
        File::lock(&lock).map_err(RegistryError::Io)?;
        let result = operation();
        let unlock = File::unlock(&lock).map_err(RegistryError::Io);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
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
            public_key: Vec::new(),
        });
        self.peers.sort_by(|left, right| {
            left.hostname
                .to_ascii_lowercase()
                .cmp(&right.hostname.to_ascii_lowercase())
        });
        Ok(())
    }

    /// Record a signed Meshelf installation discovered on a Tailscale node. During private
    /// functional testing, reinstalling Meshelf on the same Tailscale node replaces its prior app
    /// identity automatically. A hardened release must add explicit revocation/rotation policy.
    pub fn accept_signed(
        &mut self,
        node: &TailNode,
        device_id: DeviceId,
        public_key: Vec<u8>,
    ) -> Result<(), RegistryError> {
        if public_key.len() != 32 {
            return Err(RegistryError::InvalidPublicKey);
        }
        let node_id = node
            .node_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(RegistryError::MissingNodeId)?;
        if let Some(existing) = self.peers.iter_mut().find(|peer| peer.node_id == node_id) {
            existing.device_id = device_id;
            existing.public_key = public_key;
            existing.hostname = node.hostname.clone();
            existing.addresses = node.addresses.clone();
            return Ok(());
        }
        self.peers.push(TrustedPeer {
            node_id: node_id.to_owned(),
            device_id,
            hostname: node.hostname.clone(),
            addresses: node.addresses.clone(),
            public_key,
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
    #[error("accepted meshelf identity does not contain a 32-byte public key")]
    InvalidPublicKey,
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
        let mut command = Command::new(&self.binary);
        hide_console(&mut command);
        command.args(["status", "--json"]);
        let output = output_with_timeout(command, STATUS_COMMAND_TIMEOUT)?;
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

fn output_with_timeout(mut command: Command, timeout: Duration) -> Result<Output, DiscoveryError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(DiscoveryError::Launch)?;
    let stdout = child.stdout.take().ok_or_else(|| {
        DiscoveryError::Launch(io::Error::other("Tailscale stdout was not piped"))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        DiscoveryError::Launch(io::Error::other("Tailscale stderr was not piped"))
    })?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_STATUS_JSON_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(4097).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(DiscoveryError::Timeout {
                    milliseconds: timeout.as_millis() as u64,
                });
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(DiscoveryError::Launch(error));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| DiscoveryError::Launch(io::Error::other("Tailscale stdout reader panicked")))?
        .map_err(DiscoveryError::Launch)?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| DiscoveryError::Launch(io::Error::other("Tailscale stderr reader panicked")))?
        .map_err(DiscoveryError::Launch)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(windows)]
fn hide_console(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    command.creation_flags(0x0800_0000);
}

#[cfg(not(windows))]
fn hide_console(_command: &mut Command) {}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Tailscale CLI was not found; set MESHELF_TAILSCALE_BIN or install Tailscale")]
    BinaryNotFound,
    #[error("failed to launch Tailscale CLI: {0}")]
    Launch(#[source] std::io::Error),
    #[error("Tailscale status failed with exit code {code:?}: {stderr}")]
    NonZeroExit { code: Option<i32>, stderr: String },
    #[error("Tailscale status did not finish within {milliseconds} ms")]
    Timeout { milliseconds: u64 },
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
        PathBuf::from("/opt/homebrew/bin/tailscale"),
    ];
    if let Some(program_files) = env::var_os("ProgramFiles") {
        locations.push(
            PathBuf::from(program_files)
                .join("Tailscale")
                .join("tailscale.exe"),
        );
    }
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        locations.push(
            PathBuf::from(local_app_data)
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

    use meshelf_core::{SaveDestination, UserSettings};

    #[test]
    fn old_state_without_settings_loads_downloads_default() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let identity = DeviceId::new();
        let path = directory.path().join("state.json");
        let old_state = serde_json::json!({
            "device_id": identity,
            "peers": {"peers": []}
        });
        fs::write(&path, serde_json::to_vec(&old_state).expect("encode")).expect("write state");
        let loaded = InstallationState::load(path).expect("load old state");
        assert_eq!(loaded.settings, UserSettings::default());
        assert_eq!(loaded.settings.save_destination, SaveDestination::Downloads);
    }

    fn test_peer() -> (TailNode, meshelf_identity::InstallationIdentity) {
        let peer = meshelf_identity::InstallationIdentity::generate();
        (
            TailNode {
                node_id: Some("settings-peer-node".to_owned()),
                hostname: "settings-peer".to_owned(),
                dns_name: None,
                addresses: vec!["100.64.0.2".parse().expect("peer address")],
                online: true,
                active: true,
            },
            peer,
        )
    }

    #[test]
    fn settings_update_preserves_peers() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = InstallationStore::new(directory.path().join("state.json"));
        let identity = DeviceId::new();
        let (node, peer) = test_peer();
        store
            .update(identity, |state| {
                state
                    .peers
                    .accept_signed(&node, peer.device_id, peer.public_key().to_vec())
            })
            .expect("peer");
        let custom = std::env::temp_dir().join("meshelf-settings-test");
        store
            .update(identity, |state| {
                state.settings.save_destination = SaveDestination::Custom {
                    path: custom.clone(),
                };
                Ok(())
            })
            .expect("settings");
        let loaded = store.load_for_identity(identity).expect("load");
        assert!(loaded.peers.by_device_id(peer.device_id).is_some());
        assert_eq!(
            loaded.settings.save_destination,
            SaveDestination::Custom { path: custom }
        );
    }

    #[test]
    fn peer_update_preserves_settings() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = InstallationStore::new(directory.path().join("state.json"));
        let identity = DeviceId::new();
        let custom = std::env::temp_dir().join("meshelf-peer-settings-test");
        store
            .update(identity, |state| {
                state.settings.save_destination = SaveDestination::Custom {
                    path: custom.clone(),
                };
                Ok(())
            })
            .expect("settings");
        let (node, peer) = test_peer();
        store
            .update(identity, |state| {
                state
                    .peers
                    .accept_signed(&node, peer.device_id, peer.public_key().to_vec())
            })
            .expect("peer");
        assert_eq!(
            store
                .load_for_identity(identity)
                .expect("load")
                .settings
                .save_destination,
            SaveDestination::Custom { path: custom }
        );
    }

    #[test]
    fn native_gui_launch_locations_include_apple_silicon_homebrew() {
        assert!(known_binary_locations().contains(&PathBuf::from("/opt/homebrew/bin/tailscale")));
    }

    #[cfg(unix)]
    #[test]
    fn status_command_has_a_finite_deadline() {
        let mut command = Command::new("sh");
        command.args(["-c", "exec sleep 2"]);
        let started = Instant::now();
        let error = output_with_timeout(command, Duration::from_millis(50))
            .expect_err("a hung status command must time out");
        assert!(matches!(
            error,
            DiscoveryError::Timeout { milliseconds: 50 }
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(windows)]
    #[test]
    fn status_command_has_a_finite_deadline() {
        let mut command = Command::new("powershell.exe");
        command.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 2"]);
        let started = Instant::now();
        let error = output_with_timeout(command, Duration::from_millis(50))
            .expect_err("a hung status command must time out");
        assert!(matches!(
            error,
            DiscoveryError::Timeout { milliseconds: 50 }
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

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
    fn online_but_idle_peer_remains_probe_candidate() {
        let status = TailStatus {
            backend_state: "Running".to_owned(),
            self_node: TailNode {
                node_id: Some("node-local".to_owned()),
                hostname: "BMST".to_owned(),
                dns_name: None,
                addresses: vec!["100.71.19.72".parse().expect("local address")],
                online: true,
                active: true,
            },
            peers: vec![TailNode {
                node_id: Some("node-idle".to_owned()),
                hostname: "BZOT".to_owned(),
                dns_name: None,
                addresses: vec!["100.90.118.120".parse().expect("peer address")],
                online: true,
                active: false,
            }],
        };

        assert_eq!(
            status
                .online_peers()
                .map(|peer| peer.hostname.as_str())
                .collect::<Vec<_>>(),
            ["BZOT"]
        );
    }

    #[test]
    fn concurrent_refresh_and_bootstrap_do_not_lose_peer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state_path = directory.path().join("state.json");
        let local_device = DeviceId::new();
        let peer_device = DeviceId::new();
        let peer = TailNode {
            node_id: Some("node-bzot".to_owned()),
            hostname: "BZOT".to_owned(),
            dns_name: None,
            addresses: vec!["100.90.118.120".parse().expect("peer address")],
            online: true,
            active: false,
        };
        InstallationStore::new(state_path.clone())
            .update(local_device, |_| Ok(()))
            .expect("initialize state");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let refresh_store = InstallationStore::new(state_path.clone());
        let refresh_barrier = barrier.clone();
        let refresh_peer = peer.clone();
        let refresh = std::thread::spawn(move || {
            refresh_barrier.wait();
            refresh_store
                .update(local_device, |latest| {
                    latest.peers.refresh_addresses(&TailStatus {
                        backend_state: "Running".to_owned(),
                        self_node: TailNode {
                            node_id: Some("node-bmst".to_owned()),
                            hostname: "BMST".to_owned(),
                            dns_name: None,
                            addresses: vec!["100.71.19.72".parse().expect("local address")],
                            online: true,
                            active: true,
                        },
                        peers: vec![refresh_peer],
                    });
                    std::thread::sleep(std::time::Duration::from_millis(40));
                    Ok(())
                })
                .expect("refresh transaction");
        });
        let bootstrap_store = InstallationStore::new(state_path.clone());
        let bootstrap_barrier = barrier.clone();
        let bootstrap = std::thread::spawn(move || {
            bootstrap_barrier.wait();
            bootstrap_store
                .update(local_device, |latest| {
                    latest
                        .peers
                        .accept_signed(&peer, peer_device, vec![7; 32])?;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    Ok(())
                })
                .expect("bootstrap transaction");
        });
        barrier.wait();
        refresh.join().expect("refresh thread");
        bootstrap.join().expect("bootstrap thread");

        let committed = InstallationStore::new(state_path)
            .load_for_identity(local_device)
            .expect("load committed state");
        assert_eq!(
            committed
                .peers
                .by_device_id(peer_device)
                .expect("bootstrap peer preserved")
                .public_key,
            vec![7; 32]
        );
    }

    #[test]
    fn identity_change_is_reconciled_inside_locked_transaction() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = InstallationStore::new(directory.path().join("state.json"));
        let old_device = DeviceId::new();
        let new_device = DeviceId::new();
        let peer_device = DeviceId::new();
        store
            .update(old_device, |latest| {
                latest.settings.save_destination = SaveDestination::Custom {
                    path: std::env::temp_dir().join("identity-reconciliation-settings"),
                };
                latest.peers.accept_signed(
                    &TailNode {
                        node_id: Some("node-peer".to_owned()),
                        hostname: "peer".to_owned(),
                        dns_name: None,
                        addresses: vec!["100.64.0.2".parse().expect("peer address")],
                        online: true,
                        active: true,
                    },
                    peer_device,
                    vec![9; 32],
                )
            })
            .expect("save old identity state");

        let reconciled = store
            .update(new_device, |_| Ok(()))
            .expect("reconcile new identity");
        assert_eq!(reconciled.device_id, new_device);
        assert!(reconciled.peers.peers().is_empty());
        assert_eq!(
            reconciled.settings.save_destination,
            SaveDestination::Custom {
                path: std::env::temp_dir().join("identity-reconciliation-settings")
            }
        );
    }

    #[test]
    fn identity_reconciliation_preserves_settings_but_clears_peers() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = InstallationStore::new(directory.path().join("state.json"));
        let old_device = DeviceId::new();
        let new_device = DeviceId::new();
        let custom = std::env::temp_dir().join("identity-settings");
        let (node, peer) = test_peer();
        store
            .update(old_device, |state| {
                state.settings.save_destination = SaveDestination::Custom {
                    path: custom.clone(),
                };
                state
                    .peers
                    .accept_signed(&node, peer.device_id, peer.public_key().to_vec())
            })
            .expect("old state");
        let reconciled = store
            .load_for_identity(new_device)
            .expect("reconcile identity");
        assert!(reconciled.peers.peers().is_empty());
        assert_eq!(
            reconciled.settings.save_destination,
            SaveDestination::Custom { path: custom }
        );
    }

    #[test]
    fn concurrent_peer_and_settings_updates_do_not_lose_either() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.json");
        let store = InstallationStore::new(path.clone());
        let identity = DeviceId::new();
        store
            .update(identity, |_| Ok(()))
            .expect("initialize state");
        let (node, peer) = test_peer();
        let peer_device_id = peer.device_id;
        let peer_public_key = peer.public_key();
        let custom = std::env::temp_dir().join("concurrent-settings");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

        let peer_store = InstallationStore::new(path.clone());
        let peer_barrier = barrier.clone();
        let peer_thread = std::thread::spawn(move || {
            peer_barrier.wait();
            peer_store
                .update(identity, |state| {
                    state
                        .peers
                        .accept_signed(&node, peer_device_id, peer_public_key.to_vec())
                })
                .expect("peer update");
        });
        let settings_store = InstallationStore::new(path);
        let settings_barrier = barrier.clone();
        let settings_thread = std::thread::spawn(move || {
            settings_barrier.wait();
            settings_store
                .update(identity, |state| {
                    state.settings.save_destination = SaveDestination::Custom { path: custom };
                    Ok(())
                })
                .expect("settings update");
        });
        barrier.wait();
        peer_thread.join().expect("peer thread");
        settings_thread.join().expect("settings thread");

        let committed = store_for_test(&directory)
            .load_for_identity(identity)
            .expect("load");
        assert!(committed.peers.by_device_id(peer_device_id).is_some());
        assert!(matches!(
            committed.settings.save_destination,
            SaveDestination::Custom { .. }
        ));
    }

    fn store_for_test(directory: &tempfile::TempDir) -> InstallationStore {
        InstallationStore::new(directory.path().join("state.json"))
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

    #[test]
    fn signed_acceptance_binds_public_key() {
        let mut registry = PeerRegistry::default();
        let identity = meshelf_identity::InstallationIdentity::generate();
        let node = TailNode {
            node_id: Some("bzot-node".to_owned()),
            hostname: "BZOT".to_owned(),
            dns_name: None,
            addresses: vec!["100.77.0.2".parse().expect("address")],
            online: true,
            active: true,
        };
        registry
            .accept_signed(&node, identity.device_id, identity.public_key().to_vec())
            .expect("signed accept");
        assert_eq!(registry.peers()[0].public_key, identity.public_key());
        let replacement = meshelf_identity::InstallationIdentity::generate();
        registry
            .accept_signed(
                &node,
                replacement.device_id,
                replacement.public_key().to_vec(),
            )
            .expect("same Tailscale node rotates its Meshelf installation automatically");
        assert_eq!(registry.peers()[0].device_id, replacement.device_id);
        assert_eq!(registry.peers()[0].public_key, replacement.public_key());
    }
}
