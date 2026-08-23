//! The fixed, non-interactive command used by one-sided SSH enrollment.
//!
//! This crate intentionally has no clipboard or arbitrary-command surface. It accepts one
//! bounded signed enrollment request on stdin, verifies that the SSH source is the requested
//! Tailscale node, records the reciprocal signed peer binding, and emits one response.

use std::{
    io::{self, Read},
    net::IpAddr,
    path::PathBuf,
};

use anyhow::Result;
use meshelf_identity::InstallationIdentity;
use meshelf_tailscale::{
    CliPeerDiscovery, InstallationState, PeerDiscovery, SshBootstrapRequest, SshBootstrapResponse,
    TailNode,
};

const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;

pub fn run_stdio() -> Result<()> {
    let mut payload = Vec::new();
    io::stdin()
        .take(MAX_BOOTSTRAP_BYTES as u64 + 1)
        .read_to_end(&mut payload)?;
    if payload.len() > MAX_BOOTSTRAP_BYTES {
        anyhow::bail!("SSH bootstrap request is too large");
    }
    let request: SshBootstrapRequest = serde_json::from_slice(&payload)?;
    if request.node_id.trim().is_empty()
        || request.addresses.is_empty()
        || request.public_key.len() != 32
        || !request.has_valid_signature()
    {
        anyhow::bail!("SSH bootstrap request lacks a valid signed installation identity");
    }

    let discovery = CliPeerDiscovery::discover()
        .map_err(|error| anyhow::anyhow!("could not read remote Tailscale identity: {error}"))?;
    let status = discovery
        .refresh()
        .map_err(|error| anyhow::anyhow!("could not refresh remote Tailscale identity: {error}"))?;
    let ssh_source = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .and_then(|value| value.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("SSH_CONNECTION did not expose a source address"))?;
    if !request.addresses.contains(&ssh_source) {
        anyhow::bail!("SSH source is not one of the requesting device's Tailscale addresses");
    }
    let source_peer = status
        .peers
        .iter()
        .find(|peer| peer.addresses.contains(&ssh_source))
        .ok_or_else(|| anyhow::anyhow!("SSH source is not a discovered remote Tailscale peer"))?;
    if source_peer.node_id.as_deref() != Some(request.node_id.as_str()) {
        anyhow::bail!("SSH source Tailscale identity does not match the bootstrap request");
    }

    let data_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("meshelf");
    std::fs::create_dir_all(&data_dir)?;
    let state_path = data_dir.join("state.json");
    let identity = InstallationIdentity::load_or_create()
        .map_err(|error| anyhow::anyhow!("could not load remote meshelf identity: {error}"))?;
    let loaded = InstallationState::load(&state_path)
        .map_err(|error| anyhow::anyhow!("could not load remote meshelf state: {error}"))?;
    let mut installation = if loaded.device_id == identity.device_id {
        loaded
    } else {
        InstallationState {
            device_id: identity.device_id,
            peers: Default::default(),
        }
    };
    installation
        .peers
        .accept_signed(
            &TailNode {
                node_id: Some(request.node_id),
                hostname: request.hostname,
                dns_name: None,
                addresses: request.addresses,
                online: true,
                active: true,
            },
            request.device_id,
            request.public_key,
        )
        .map_err(|error| anyhow::anyhow!("could not record SSH-approved peer: {error}"))?;
    installation
        .save(&state_path)
        .map_err(|error| anyhow::anyhow!("could not save remote meshelf state: {error}"))?;

    let node_id = status
        .self_node
        .node_id
        .ok_or_else(|| anyhow::anyhow!("remote Tailscale node has no stable node ID"))?;
    let response = SshBootstrapResponse::signed(
        identity.device_id,
        node_id,
        status.self_node.hostname,
        status.self_node.addresses,
        &identity,
    );
    serde_json::to_writer(io::stdout().lock(), &response)?;
    Ok(())
}
