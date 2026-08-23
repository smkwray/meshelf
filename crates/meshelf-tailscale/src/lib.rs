//! Local, on-demand Tailscale peer discovery.
//!
//! The user never needs to run a terminal command. This adapter invokes the already-installed
//! Tailscale CLI internally only on explicit refresh/send paths. It never polls in the background.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
};

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
}
