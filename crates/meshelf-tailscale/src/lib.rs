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
use meshelf_protocol::pairing::{self, PairingId, TranscriptHash};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_STATUS_JSON_BYTES: usize = 8 * 1024 * 1024;
const STATUS_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// Tailscale userspace IPv4 (CGNAT `100.64.0.0/10`). Used by O-025 phone interim auto-trust.
#[must_use]
pub fn is_tailscale_cgnat_v4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(_) => false,
    }
}

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

/// How a trusted peer is located, and the source addresses it is admitted from.
///
/// Desktops learn peers from Tailscale discovery, which names a stable node and refreshes its
/// addresses. A phone cannot run discovery, so it binds a paired computer to the address it was
/// observed at during pairing. A Tailscale node id is never fabricated where none was reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerNetworkBinding {
    /// A node reported by Tailscale discovery; `refresh_addresses` keeps `addresses` current.
    TailscaleNode {
        node_id: String,
        addresses: Vec<IpAddr>,
    },
    /// The one address a paired peer was observed at. Nothing refreshes it: a connection from any
    /// other address is a changed network identity and requires pairing again.
    ObservedTailscaleAddress { address: IpAddr },
}

impl PeerNetworkBinding {
    /// Whether two bindings name the same network endpoint, so that recording one must replace
    /// the other rather than sit beside it.
    fn same_endpoint(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::TailscaleNode { node_id: left, .. },
                Self::TailscaleNode { node_id: right, .. },
            ) => left == right,
            (
                Self::ObservedTailscaleAddress { address: left },
                Self::ObservedTailscaleAddress { address: right },
            ) => left == right,
            _ => false,
        }
    }
}

/// Which operation created a trust record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOrigin {
    /// Recorded automatically from a signed discovery probe (owner decision O-003). A record
    /// written before origins existed decodes as this.
    #[default]
    Discovery,
    /// Recorded by a completed pairing whose code a person confirmed. Only `record_paired`
    /// creates or replaces such a record; discovery can never overwrite it.
    Paired,
}

impl TrustOrigin {
    fn is_discovery(&self) -> bool {
        *self == Self::Discovery
    }
}

/// The completed pairing transcript that justifies a `Paired` record. Both ids are lowercase hex
/// on disk, encoded by the protocol's own types. `expires_at_unix_ms` is that pairing's expiry:
/// an initiator whose final `Complete` was lost resumes the same transcript until that expiry
/// plus the reconciliation allowance (A12), so it must survive with the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingEvidence {
    pub pairing_id: PairingId,
    pub transcript_hash: TranscriptHash,
    pub paired_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// One trusted peer. The binding, origin, and pairing evidence are readable but can be set only
/// by `PeerRegistry` operations, so a `Paired` record always carries its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TrustedPeerRepr", into = "TrustedPeerRepr")]
pub struct TrustedPeer {
    pub device_id: DeviceId,
    pub hostname: String,
    /// The peer's Ed25519 installation key. An absent key is legacy state and is never admitted.
    pub public_key: Vec<u8>,
    binding: PeerNetworkBinding,
    origin: TrustOrigin,
    pairing: Option<PairingEvidence>,
}

impl TrustedPeer {
    #[must_use]
    pub fn binding(&self) -> &PeerNetworkBinding {
        &self.binding
    }

    #[must_use]
    pub fn origin(&self) -> TrustOrigin {
        self.origin
    }

    #[must_use]
    pub fn pairing(&self) -> Option<&PairingEvidence> {
        self.pairing.as_ref()
    }

    /// The Tailscale node id, which exists only for a discovery-refreshed binding.
    #[must_use]
    pub fn node_id(&self) -> Option<&str> {
        match &self.binding {
            PeerNetworkBinding::TailscaleNode { node_id, .. } => Some(node_id),
            PeerNetworkBinding::ObservedTailscaleAddress { .. } => None,
        }
    }

    /// Addresses to connect to, in the order the binding lists them.
    #[must_use]
    pub fn dial_addresses(&self) -> &[IpAddr] {
        match &self.binding {
            PeerNetworkBinding::TailscaleNode { addresses, .. } => addresses,
            PeerNetworkBinding::ObservedTailscaleAddress { address } => {
                std::slice::from_ref(address)
            }
        }
    }

    /// Whether an inbound connection from `ip` comes from this peer's bound network identity.
    #[must_use]
    pub fn admits(&self, ip: IpAddr) -> bool {
        self.dial_addresses().contains(&ip)
    }

    /// The pairing this record came from, in the form `record_paired` took it, or `None` for a
    /// discovery record. A desktop resumes an interrupted pairing from this (A12).
    #[must_use]
    pub fn paired(&self) -> Option<PairedPeer> {
        let evidence = self.pairing.as_ref()?;
        let public_key = <[u8; 32]>::try_from(self.public_key.as_slice()).ok()?;
        Some(PairedPeer {
            peer: pairing::PairedPeer {
                device_id: self.device_id,
                public_key,
                device_name: self.hostname.clone(),
                pairing_id: evidence.pairing_id,
                transcript_hash: evidence.transcript_hash,
            },
            binding: self.binding.clone(),
            expires_at_unix_ms: evidence.expires_at_unix_ms,
        })
    }

    fn is_installation(&self, device_id: DeviceId, public_key: &[u8]) -> bool {
        self.device_id == device_id && self.public_key == public_key
    }

    /// Whether a pairing of this identity and binding may replace this record: the same network
    /// endpoint (a reinstall on the same node), or the same installation, device id and key, whose
    /// signature proves it, re-paired after its address or node changed.
    fn replaced_by(
        &self,
        device_id: DeviceId,
        public_key: &[u8],
        binding: &PeerNetworkBinding,
    ) -> bool {
        self.binding.same_endpoint(binding) || self.is_installation(device_id, public_key)
    }

    /// Whether this record claims the same device id under another key at another endpoint. A
    /// device id is an unauthenticated label, so a pairing may never use it to displace this.
    fn conflicts_with(
        &self,
        device_id: DeviceId,
        public_key: &[u8],
        binding: &PeerNetworkBinding,
    ) -> bool {
        self.device_id == device_id
            && self.public_key != public_key
            && !self.binding.same_endpoint(binding)
    }
}

/// The on-disk form of `TrustedPeer`. A `TailscaleNode` record keeps the legacy flat `node_id`
/// and `addresses` fields, so an older build reading the same `state.json` still parses it; every
/// newer field is optional and omitted at its legacy default.
#[derive(Serialize, Deserialize)]
struct TrustedPeerRepr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    device_id: DeviceId,
    hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    addresses: Option<Vec<IpAddr>>,
    #[serde(default)]
    public_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "TrustOrigin::is_discovery")]
    origin: TrustOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pairing: Option<PairingEvidence>,
}

impl TryFrom<TrustedPeerRepr> for TrustedPeer {
    type Error = String;

    fn try_from(repr: TrustedPeerRepr) -> Result<Self, Self::Error> {
        let binding = match (repr.node_id, repr.addresses, repr.observed_address) {
            (Some(node_id), Some(addresses), None) => {
                PeerNetworkBinding::TailscaleNode { node_id, addresses }
            }
            (None, None, Some(address)) => PeerNetworkBinding::ObservedTailscaleAddress { address },
            _ => {
                return Err(
                    "trusted peer needs exactly one network binding: node_id with \
                            addresses, or observed_address"
                        .to_owned(),
                );
            }
        };
        let consistent = matches!(
            (repr.origin, &repr.pairing, &binding),
            (TrustOrigin::Paired, Some(_), _)
                | (
                    TrustOrigin::Discovery,
                    None,
                    PeerNetworkBinding::TailscaleNode { .. }
                        | PeerNetworkBinding::ObservedTailscaleAddress { .. }
                )
        );
        if !consistent {
            return Err(
                "trusted peer origin disagrees with its pairing evidence or binding: a \
                        paired record needs evidence, and only a paired or discovery-observed \
                        record may bind an observed address"
                    .to_owned(),
            );
        }
        Ok(Self {
            device_id: repr.device_id,
            hostname: repr.hostname,
            public_key: repr.public_key,
            binding,
            origin: repr.origin,
            pairing: repr.pairing,
        })
    }
}

impl From<TrustedPeer> for TrustedPeerRepr {
    fn from(peer: TrustedPeer) -> Self {
        let (node_id, addresses, observed_address) = match peer.binding {
            PeerNetworkBinding::TailscaleNode { node_id, addresses } => {
                (Some(node_id), Some(addresses), None)
            }
            PeerNetworkBinding::ObservedTailscaleAddress { address } => (None, None, Some(address)),
        };
        Self {
            node_id,
            device_id: peer.device_id,
            hostname: peer.hostname,
            addresses,
            public_key: peer.public_key,
            observed_address,
            origin: peer.origin,
            pairing: peer.pairing,
        }
    }
}

/// What a completed pairing establishes, the input to `record_paired`: the protocol's record of the
/// peer and transcript a person confirmed, the network binding it is admitted from, and that
/// pairing's expiry. `into_trusted` is the one conversion to a stored record, and
/// `TrustedPeer::paired` its inverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedPeer {
    pub peer: pairing::PairedPeer,
    pub binding: PeerNetworkBinding,
    pub expires_at_unix_ms: u64,
}

impl PairedPeer {
    fn into_trusted(self, paired_at_unix_ms: u64) -> TrustedPeer {
        TrustedPeer {
            device_id: self.peer.device_id,
            hostname: self.peer.device_name,
            public_key: self.peer.public_key.to_vec(),
            binding: self.binding,
            origin: TrustOrigin::Paired,
            pairing: Some(PairingEvidence {
                pairing_id: self.peer.pairing_id,
                transcript_hash: self.peer.transcript_hash,
                paired_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
            }),
        }
    }
}

/// The one admission predicate every trust gate shares. Computing it never changes a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAdmission {
    Trusted,
    UnknownDevice,
    /// The device is known but presented a different key, or the stored record is keyless legacy
    /// state. Only a new pairing may replace the key.
    KeyChanged,
    /// The device and key match but the connection comes from outside the bound network identity.
    NetworkIdentityChanged,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRegistry {
    peers: Vec<TrustedPeer>,
}

/// A pairing the local person approved, stored durably before the approval is sent, whose trust
/// record is not yet written: the protocol's approval of one exact transcript plus the address the
/// peer was observed at on that connection, which a resume must also come from. It may be promoted
/// while `approval.completion_deadline_unix_ms()` is in the future.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ApprovedPendingRepr", into = "ApprovedPendingRepr")]
pub struct ApprovedPending {
    pub approval: pairing::ApprovedPending,
    pub observed_address: IpAddr,
}

impl ApprovedPending {
    /// The trust record promotion writes: the approved peer bound to its observed address.
    #[must_use]
    pub fn paired_peer(&self) -> PairedPeer {
        let approval = &self.approval;
        PairedPeer {
            peer: pairing::PairedPeer {
                device_id: approval.peer_device_id,
                public_key: approval.peer_public_key,
                device_name: approval.peer_device_name.clone(),
                pairing_id: approval.pairing_id,
                transcript_hash: approval.transcript_hash,
            },
            binding: PeerNetworkBinding::ObservedTailscaleAddress {
                address: self.observed_address,
            },
            expires_at_unix_ms: approval.expires_at_unix_ms,
        }
    }
}

/// The on-disk form of `ApprovedPending`; `expires_at_unix_ms` is the pairing expiry.
#[derive(Serialize, Deserialize)]
struct ApprovedPendingRepr {
    pairing_id: PairingId,
    transcript_hash: TranscriptHash,
    peer_device_id: DeviceId,
    peer_public_key: Vec<u8>,
    peer_name: String,
    observed_address: IpAddr,
    approved_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl TryFrom<ApprovedPendingRepr> for ApprovedPending {
    type Error = String;

    fn try_from(repr: ApprovedPendingRepr) -> Result<Self, Self::Error> {
        let peer_public_key = <[u8; 32]>::try_from(repr.peer_public_key.as_slice())
            .map_err(|_| "approved pairing peer key is not 32 bytes".to_owned())?;
        Ok(Self {
            approval: pairing::ApprovedPending {
                pairing_id: repr.pairing_id,
                transcript_hash: repr.transcript_hash,
                peer_device_id: repr.peer_device_id,
                peer_public_key,
                peer_device_name: repr.peer_name,
                approved_at_unix_ms: repr.approved_at_unix_ms,
                expires_at_unix_ms: repr.expires_at_unix_ms,
            },
            observed_address: repr.observed_address,
        })
    }
}

impl From<ApprovedPending> for ApprovedPendingRepr {
    fn from(pending: ApprovedPending) -> Self {
        let approval = pending.approval;
        Self {
            pairing_id: approval.pairing_id,
            transcript_hash: approval.transcript_hash,
            peer_device_id: approval.peer_device_id,
            peer_public_key: approval.peer_public_key.to_vec(),
            peer_name: approval.peer_device_name,
            observed_address: pending.observed_address,
            approved_at_unix_ms: approval.approved_at_unix_ms,
            expires_at_unix_ms: approval.expires_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationState {
    pub device_id: DeviceId,
    pub peers: PeerRegistry,
    #[serde(default)]
    pub settings: UserSettings,
    /// Promoted and cleared together by `InstallationStore::promote_pending_pairing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_pairing: Option<ApprovedPending>,
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
            pending_pairing: None,
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

    /// Turn the stored approval for exactly this transcript into a `Paired` trust record bound to
    /// the observed address, and clear the approval, in one locked atomic file replace. A crash
    /// leaves either the pending approval or the completed trust, never half of each; any refusal
    /// leaves the file untouched.
    pub fn promote_pending_pairing(
        &self,
        identity: DeviceId,
        pairing_id: &PairingId,
        transcript_hash: &TranscriptHash,
        now_unix_ms: u64,
        expected_prior: Option<(DeviceId, Vec<u8>)>,
    ) -> Result<InstallationState, RegistryError> {
        self.update(identity, |state| {
            let pending = state
                .pending_pairing
                .as_ref()
                .ok_or(RegistryError::NoPendingPairing)?;
            if pending.approval.pairing_id != *pairing_id
                || pending.approval.transcript_hash != *transcript_hash
            {
                return Err(RegistryError::PendingPairingMismatch);
            }
            if now_unix_ms >= pending.approval.completion_deadline_unix_ms() {
                return Err(RegistryError::PendingPairingExpired);
            }
            let paired = pending.paired_peer();
            state
                .peers
                .record_paired(paired, now_unix_ms, expected_prior)?;
            state.pending_pairing = None;
            Ok(())
        })
    }

    fn load_reconciled(&self, identity: DeviceId) -> Result<InstallationState, RegistryError> {
        let loaded = InstallationState::load(&self.state_path)?;
        if loaded.device_id == identity {
            Ok(loaded)
        } else {
            // A pending approval covered a transcript signed by the previous identity, so it
            // cannot survive the identity change any more than the peers it would have joined.
            Ok(InstallationState {
                device_id: identity,
                peers: PeerRegistry::default(),
                settings: loaded.settings,
                pending_pairing: None,
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
        let held = match File::lock(&lock) {
            Ok(()) => true,
            // Android app-private storage rejects advisory locks (ENOTSUP). The phone has one
            // meshelf process; in-process call serialization still covers mutations here.
            Err(error)
                if cfg!(target_os = "android")
                    && (error.kind() == io::ErrorKind::Unsupported
                        || error.raw_os_error() == Some(95)
                        || error.raw_os_error() == Some(45)) =>
            {
                false
            }
            Err(error) => return Err(RegistryError::Io(error)),
        };
        let result = operation();
        if held {
            let unlock = File::unlock(&lock).map_err(RegistryError::Io);
            match (result, unlock) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), _) => Err(error),
                (Ok(_), Err(error)) => Err(error),
            }
        } else {
            result
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
        self.peers
            .iter()
            .find(|peer| peer.node_id() == Some(node_id))
    }

    /// Decide whether an authenticated installation may use the ordinary protocol. The caller
    /// still verifies the hello signature; this checks the stored device, key, and network
    /// binding. A 32-byte key match is required, so keyless legacy records are never trusted.
    #[must_use]
    pub fn admit(
        &self,
        device_id: DeviceId,
        public_key: &[u8],
        remote_ip: IpAddr,
    ) -> PeerAdmission {
        let Some(peer) = self.by_device_id(device_id) else {
            return PeerAdmission::UnknownDevice;
        };
        if public_key.len() != 32 || peer.public_key != public_key {
            PeerAdmission::KeyChanged
        } else if !peer.admits(remote_ip) {
            PeerAdmission::NetworkIdentityChanged
        } else {
            PeerAdmission::Trusted
        }
    }

    /// Record the peer a completed pairing confirmed. This is the only operation that creates or
    /// replaces a `Paired` record.
    ///
    /// A record at the same network endpoint, or of the same installation (device id and key),
    /// is replaced. A record claiming the same device id under another key at another endpoint is
    /// a conflict: the pairing is refused with `DeviceIdentityConflict` and nothing changes, since
    /// a device id alone proves nothing. When a replaced record holds a different device or key,
    /// the caller must name its `(device_id, public_key)` exactly in `expected_prior`; naming an
    /// identity that is not there is also refused.
    pub fn record_paired(
        &mut self,
        paired: PairedPeer,
        paired_at_unix_ms: u64,
        expected_prior: Option<(DeviceId, Vec<u8>)>,
    ) -> Result<(), RegistryError> {
        if let PeerNetworkBinding::TailscaleNode { node_id, .. } = &paired.binding
            && node_id.trim().is_empty()
        {
            return Err(RegistryError::MissingNodeId);
        }
        let record = paired.into_trusted(paired_at_unix_ms);
        self.refuse_conflict(record.device_id, &record.public_key, &record.binding)?;
        let replaced = |existing: &TrustedPeer| {
            existing.replaced_by(record.device_id, &record.public_key, &record.binding)
        };
        let mut prior_named = false;
        for existing in self.peers.iter().filter(|existing| replaced(existing)) {
            if existing.is_installation(record.device_id, &record.public_key) {
                continue;
            }
            match &expected_prior {
                Some((device_id, public_key))
                    if *device_id == existing.device_id && *public_key == existing.public_key =>
                {
                    prior_named = true;
                }
                _ => return Err(RegistryError::PriorIdentityMismatch),
            }
        }
        if expected_prior.is_some() && !prior_named {
            return Err(RegistryError::PriorIdentityMismatch);
        }
        self.peers.retain(|existing| !replaced(existing));
        self.peers.push(record);
        self.sort_by_hostname();
        Ok(())
    }

    /// What recording a paired peer with this device, key, and binding would do, under the same
    /// rule as `record_paired`: `Err(DeviceIdentityConflict)` when it would be refused, otherwise
    /// the identity it would displace (the record at the same endpoint holding a different device
    /// or key), if any. A pairing driver reads this when its session begins, refusing before any
    /// code is shown, and passes the displaced identity to `record_paired` as `expected_prior`, so
    /// a record that changes while the person compares codes is refused rather than replaced.
    pub fn displaced_identity(
        &self,
        device_id: DeviceId,
        public_key: &[u8],
        binding: &PeerNetworkBinding,
    ) -> Result<Option<(DeviceId, Vec<u8>)>, RegistryError> {
        self.refuse_conflict(device_id, public_key, binding)?;
        Ok(self
            .peers
            .iter()
            .find(|existing| {
                existing.replaced_by(device_id, public_key, binding)
                    && !existing.is_installation(device_id, public_key)
            })
            .map(|existing| (existing.device_id, existing.public_key.clone())))
    }

    fn refuse_conflict(
        &self,
        device_id: DeviceId,
        public_key: &[u8],
        binding: &PeerNetworkBinding,
    ) -> Result<(), RegistryError> {
        match self
            .peers
            .iter()
            .find(|existing| existing.conflicts_with(device_id, public_key, binding))
        {
            Some(conflict) => Err(RegistryError::DeviceIdentityConflict {
                device_id: conflict.device_id,
            }),
            None => Ok(()),
        }
    }

    fn sort_by_hostname(&mut self) {
        self.peers.sort_by(|left, right| {
            left.hostname
                .to_ascii_lowercase()
                .cmp(&right.hostname.to_ascii_lowercase())
        });
    }

    /// Record one explicit acceptance, preserving the original device identity for that
    /// Tailscale node. Re-accepting the same node with a different meshelf identity is refused.
    pub fn accept(&mut self, node: &TailNode, device_id: DeviceId) -> Result<(), RegistryError> {
        let node_id = node
            .node_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(RegistryError::MissingNodeId)?;
        let binding = PeerNetworkBinding::TailscaleNode {
            node_id: node_id.to_owned(),
            addresses: node.addresses.clone(),
        };
        if let Some(existing) = self
            .peers
            .iter_mut()
            .find(|peer| peer.node_id() == Some(node_id))
        {
            if existing.device_id != device_id {
                return Err(RegistryError::IdentityConflict {
                    node_id: node_id.to_owned(),
                });
            }
            existing.hostname = node.hostname.clone();
            existing.binding = binding;
            return Ok(());
        }
        self.peers.push(TrustedPeer {
            device_id,
            hostname: node.hostname.clone(),
            public_key: Vec::new(),
            binding,
            origin: TrustOrigin::Discovery,
            pairing: None,
        });
        self.sort_by_hostname();
        Ok(())
    }

    /// Record a signed Meshelf installation discovered on a Tailscale node. During private
    /// functional testing, reinstalling Meshelf on the same Tailscale node replaces its prior app
    /// identity automatically (O-003). A hardened release must add explicit revocation/rotation
    /// policy. A record created by pairing is never touched here: if the device or the node
    /// already has a `Paired` record, this refuses and changes nothing.
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
        if let Some(protected) = self.peers.iter().find(|existing| {
            existing.origin == TrustOrigin::Paired
                && (existing.device_id == device_id || existing.node_id() == Some(node_id))
        }) {
            return Err(RegistryError::PairedIdentityProtected {
                device_id: protected.device_id,
            });
        }
        let binding = PeerNetworkBinding::TailscaleNode {
            node_id: node_id.to_owned(),
            addresses: node.addresses.clone(),
        };
        if let Some(existing) = self
            .peers
            .iter_mut()
            .find(|peer| peer.node_id() == Some(node_id))
        {
            existing.device_id = device_id;
            existing.public_key = public_key;
            existing.hostname = node.hostname.clone();
            existing.binding = binding;
            return Ok(());
        }
        self.peers.push(TrustedPeer {
            device_id,
            hostname: node.hostname.clone(),
            public_key,
            binding,
            origin: TrustOrigin::Discovery,
            pairing: None,
        });
        self.sort_by_hostname();
        Ok(())
    }

    /// Record a signed installation observed at one Tailscale CGNAT address (O-025 phone interim).
    ///
    /// Phones have no discovery CLI, so they bind the peer to the address of the connection that
    /// presented a valid hello. A `Paired` record for the same device is never overwritten.
    pub fn accept_observed_signed(
        &mut self,
        hostname: impl Into<String>,
        address: IpAddr,
        device_id: DeviceId,
        public_key: Vec<u8>,
    ) -> Result<(), RegistryError> {
        if public_key.len() != 32 {
            return Err(RegistryError::InvalidPublicKey);
        }
        if !is_tailscale_cgnat_v4(address) {
            return Err(RegistryError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "observed address is not Tailscale CGNAT IPv4",
            )));
        }
        if let Some(protected) = self.peers.iter().find(|existing| {
            existing.origin == TrustOrigin::Paired && existing.device_id == device_id
        }) {
            return Err(RegistryError::PairedIdentityProtected {
                device_id: protected.device_id,
            });
        }
        let hostname = hostname.into();
        let binding = PeerNetworkBinding::ObservedTailscaleAddress { address };
        if let Some(existing) = self
            .peers
            .iter_mut()
            .find(|peer| peer.device_id == device_id)
        {
            existing.public_key = public_key;
            existing.hostname = hostname;
            existing.binding = binding;
            existing.origin = TrustOrigin::Discovery;
            existing.pairing = None;
            return Ok(());
        }
        self.peers.push(TrustedPeer {
            device_id,
            hostname,
            public_key,
            binding,
            origin: TrustOrigin::Discovery,
            pairing: None,
        });
        self.sort_by_hostname();
        Ok(())
    }

    /// Refresh accepted peers' display names and current Tailscale addresses without changing
    /// the one-time acceptance decision. Only discovery-refreshed `TailscaleNode` bindings move;
    /// an observed-address binding is fixed until the peer pairs again.
    pub fn refresh_addresses(&mut self, status: &TailStatus) {
        for trusted in &mut self.peers {
            let PeerNetworkBinding::TailscaleNode { node_id, addresses } = &mut trusted.binding
            else {
                continue;
            };
            let Some(node) = status
                .peers
                .iter()
                .find(|node| node.node_id.as_deref() == Some(node_id.as_str()))
            else {
                continue;
            };
            trusted.hostname = node.hostname.clone();
            *addresses = node.addresses.clone();
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
    #[error("meshelf peer {device_id} was trusted by pairing; only a new pairing may change it")]
    PairedIdentityProtected { device_id: DeviceId },
    #[error("replacing a trusted peer identity requires naming the prior identity exactly")]
    PriorIdentityMismatch,
    #[error(
        "meshelf peer {device_id} is trusted under another key at another address; a pairing \
         may not replace it"
    )]
    DeviceIdentityConflict { device_id: DeviceId },
    #[error("no approved pairing is waiting to be promoted")]
    NoPendingPairing,
    #[error("the approved pairing is for a different pairing id or transcript")]
    PendingPairingMismatch,
    #[error("the approved pairing expired before it was promoted")]
    PendingPairingExpired,
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
    use meshelf_identity::InstallationIdentity;

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
        assert_eq!(status.self_node.hostname, "CEDAR");
        assert_eq!(status.peers.len(), 2);
        assert_eq!(status.peers[0].hostname, "FERN");
        assert_eq!(status.peers[1].hostname, "GROVE");
        assert_eq!(status.peers[0].addresses[0].to_string(), "100.64.1.30");
        assert_eq!(
            status
                .online_peers()
                .map(|peer| peer.hostname.as_str())
                .collect::<Vec<_>>(),
            ["FERN"]
        );
    }

    #[test]
    fn online_but_idle_peer_remains_probe_candidate() {
        let status = TailStatus {
            backend_state: "Running".to_owned(),
            self_node: TailNode {
                node_id: Some("node-local".to_owned()),
                hostname: "CEDAR".to_owned(),
                dns_name: None,
                addresses: vec!["100.64.1.10".parse().expect("local address")],
                online: true,
                active: true,
            },
            peers: vec![TailNode {
                node_id: Some("node-idle".to_owned()),
                hostname: "FERN".to_owned(),
                dns_name: None,
                addresses: vec!["100.64.1.30".parse().expect("peer address")],
                online: true,
                active: false,
            }],
        };

        assert_eq!(
            status
                .online_peers()
                .map(|peer| peer.hostname.as_str())
                .collect::<Vec<_>>(),
            ["FERN"]
        );
    }

    #[test]
    fn concurrent_refresh_and_bootstrap_do_not_lose_peer() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state_path = directory.path().join("state.json");
        let local_device = DeviceId::new();
        let peer_device = DeviceId::new();
        let peer = TailNode {
            node_id: Some("node-fern".to_owned()),
            hostname: "FERN".to_owned(),
            dns_name: None,
            addresses: vec!["100.64.1.30".parse().expect("peer address")],
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
                            node_id: Some("node-cedar".to_owned()),
                            hostname: "CEDAR".to_owned(),
                            dns_name: None,
                            addresses: vec!["100.64.1.10".parse().expect("local address")],
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
            "Self":{"HostName":"CEDAR","TailscaleIPs":["not-an-ip"]},
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
            node_id: Some("fern-node".to_owned()),
            hostname: "FERN".to_owned(),
            dns_name: Some("fern.example.invalid".to_owned()),
            addresses: vec!["100.64.1.30".parse().expect("address")],
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
                addresses: vec!["100.64.1.31".parse().expect("updated address")],
                ..node
            }],
        };
        reopened.refresh_addresses(&status);
        assert_eq!(
            reopened.peers()[0].dial_addresses()[0].to_string(),
            "100.64.1.31"
        );
    }

    #[test]
    fn refuses_identity_replacement_for_accepted_node() {
        let mut registry = PeerRegistry::default();
        let node = TailNode {
            node_id: Some("fern-node".to_owned()),
            hostname: "FERN".to_owned(),
            dns_name: None,
            addresses: vec!["100.64.1.30".parse().expect("address")],
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
            node_id: Some("fern-node".to_owned()),
            hostname: "FERN".to_owned(),
            dns_name: None,
            addresses: vec!["100.64.1.30".parse().expect("address")],
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
        // O-003 rotation keeps producing an ordinary discovery record, never a paired one.
        assert_eq!(registry.peers()[0].origin(), TrustOrigin::Discovery);
        assert_eq!(registry.peers()[0].pairing(), None);
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    const PAIRED_AT: u64 = 1_000;
    const PAIRING_EXPIRES: u64 = 9_000;

    fn evidence(seed: u8) -> PairingEvidence {
        PairingEvidence {
            pairing_id: PairingId::from_bytes([seed; 16]),
            transcript_hash: TranscriptHash::from_bytes([seed; 32]),
            paired_at_unix_ms: PAIRED_AT,
            expires_at_unix_ms: PAIRING_EXPIRES,
        }
    }

    fn paired(
        identity: &InstallationIdentity,
        hostname: &str,
        binding: PeerNetworkBinding,
        seed: u8,
    ) -> PairedPeer {
        PairedPeer {
            peer: pairing::PairedPeer {
                device_id: identity.device_id,
                public_key: identity.public_key(),
                device_name: hostname.to_owned(),
                pairing_id: PairingId::from_bytes([seed; 16]),
                transcript_hash: TranscriptHash::from_bytes([seed; 32]),
            },
            binding,
            expires_at_unix_ms: PAIRING_EXPIRES,
        }
    }

    fn observed(
        identity: &InstallationIdentity,
        hostname: &str,
        address: &str,
        seed: u8,
    ) -> PairedPeer {
        paired(
            identity,
            hostname,
            PeerNetworkBinding::ObservedTailscaleAddress {
                address: ip(address),
            },
            seed,
        )
    }

    fn identity_of(identity: &InstallationIdentity) -> (DeviceId, Vec<u8>) {
        (identity.device_id, identity.public_key().to_vec())
    }

    fn tail_node(node_id: &str, hostname: &str, addresses: &[&str]) -> TailNode {
        TailNode {
            node_id: Some(node_id.to_owned()),
            hostname: hostname.to_owned(),
            dns_name: None,
            addresses: addresses.iter().map(|address| ip(address)).collect(),
            online: true,
            active: true,
        }
    }

    fn approved(peer: &InstallationIdentity, seed: u8, address: &str) -> ApprovedPending {
        ApprovedPending {
            approval: pairing::ApprovedPending {
                pairing_id: PairingId::from_bytes([seed; 16]),
                transcript_hash: TranscriptHash::from_bytes([seed; 32]),
                peer_device_id: peer.device_id,
                peer_public_key: peer.public_key(),
                peer_device_name: "CEDAR".to_owned(),
                approved_at_unix_ms: 1_000,
                expires_at_unix_ms: 10_000,
            },
            observed_address: ip(address),
        }
    }

    #[test]
    fn admission_requires_the_exact_paired_device_key_and_address() {
        // A copied installation key used from another tailnet node, or a reinstalled peer with a
        // new key, must be refused, and refusing must never move the record toward the caller.
        let mut registry = PeerRegistry::default();
        let desktop = InstallationIdentity::generate();
        registry
            .record_paired(
                observed(&desktop, "CEDAR", "100.64.0.7", 1),
                PAIRED_AT,
                None,
            )
            .expect("pair");
        let snapshot = registry.clone();
        let key = desktop.public_key();

        assert_eq!(
            registry.admit(desktop.device_id, &key, ip("100.64.0.7")),
            PeerAdmission::Trusted
        );
        assert_eq!(
            registry.admit(DeviceId::new(), &key, ip("100.64.0.7")),
            PeerAdmission::UnknownDevice
        );
        let other_key = InstallationIdentity::generate().public_key();
        assert_eq!(
            registry.admit(desktop.device_id, &other_key, ip("100.64.0.7")),
            PeerAdmission::KeyChanged
        );
        assert_eq!(registry, snapshot);
        assert_eq!(
            registry.admit(desktop.device_id, &key, ip("100.64.0.8")),
            PeerAdmission::NetworkIdentityChanged
        );
        assert_eq!(registry, snapshot);

        // A discovery-refreshed desktop binding admits exactly its current Tailscale addresses.
        let peer = InstallationIdentity::generate();
        registry
            .accept_signed(
                &tail_node("node-fern", "FERN", &["100.64.1.30", "fd7a:115c:a1e0::9"]),
                peer.device_id,
                peer.public_key().to_vec(),
            )
            .expect("discover");
        assert_eq!(
            registry.admit(peer.device_id, &peer.public_key(), ip("fd7a:115c:a1e0::9")),
            PeerAdmission::Trusted
        );
        assert_eq!(
            registry.admit(peer.device_id, &peer.public_key(), ip("100.64.1.40")),
            PeerAdmission::NetworkIdentityChanged
        );
    }

    #[test]
    fn keyless_legacy_record_is_never_admitted() {
        // A record written before keys existed has an empty key; a hello presenting an empty key
        // must not match it, or admission would reduce to "comes from the right address".
        let mut registry = PeerRegistry::default();
        let device_id = DeviceId::new();
        registry
            .accept(&tail_node("node-old", "OLD", &["100.64.1.32"]), device_id)
            .expect("legacy accept");
        assert_eq!(
            registry.admit(device_id, &[], ip("100.64.1.32")),
            PeerAdmission::KeyChanged
        );
    }

    #[test]
    fn discovery_cannot_overwrite_or_rebind_a_paired_identity() {
        // Discovery trusts whatever signed hello answers a probe (O-003). If it could replace a
        // paired record, anyone answering on that node could undo the code a person compared.
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.json");
        let store = InstallationStore::new(path.clone());
        let local = DeviceId::new();
        let phone = InstallationIdentity::generate();
        let node = tail_node("node-pixel", "Pixel", &["100.64.1.50"]);
        store
            .update(local, |state| {
                state.peers.record_paired(
                    paired(
                        &phone,
                        "Pixel",
                        PeerNetworkBinding::TailscaleNode {
                            node_id: "node-pixel".to_owned(),
                            addresses: node.addresses.clone(),
                        },
                        3,
                    ),
                    PAIRED_AT,
                    None,
                )
            })
            .expect("pair phone");
        let before = fs::read(&path).expect("read state");
        let impostor = InstallationIdentity::generate();

        let same_node = store
            .update(local, |state| {
                state
                    .peers
                    .accept_signed(&node, impostor.device_id, impostor.public_key().to_vec())
            })
            .expect_err("a paired node cannot be re-identified by discovery");
        assert!(matches!(
            same_node,
            RegistryError::PairedIdentityProtected { device_id } if device_id == phone.device_id
        ));
        assert_eq!(fs::read(&path).expect("read state"), before);

        let same_device = store
            .update(local, |state| {
                state.peers.accept_signed(
                    &tail_node("node-elsewhere", "Pixel", &["100.64.1.51"]),
                    phone.device_id,
                    impostor.public_key().to_vec(),
                )
            })
            .expect_err("a paired device cannot be re-keyed by discovery");
        assert!(matches!(
            same_device,
            RegistryError::PairedIdentityProtected { device_id } if device_id == phone.device_id
        ));
        assert_eq!(fs::read(&path).expect("read state"), before);
    }

    #[test]
    fn refresh_never_moves_an_observed_address_binding() {
        // The phone's record of a computer is the address pairing saw. Discovery data must never
        // move it: another address is a changed network identity that needs a new pairing.
        let mut registry = PeerRegistry::default();
        let desktop = InstallationIdentity::generate();
        registry
            .record_paired(
                observed(&desktop, "CEDAR", "100.64.0.7", 1),
                PAIRED_AT,
                None,
            )
            .expect("pair");
        let discovered = InstallationIdentity::generate();
        let fern = tail_node("node-fern", "FERN", &["100.64.1.30"]);
        registry
            .accept_signed(
                &fern,
                discovered.device_id,
                discovered.public_key().to_vec(),
            )
            .expect("discover");
        let paired_before = registry
            .by_device_id(desktop.device_id)
            .cloned()
            .expect("paired record");

        registry.refresh_addresses(&TailStatus {
            backend_state: "Running".to_owned(),
            self_node: fern.clone(),
            peers: vec![
                // Same hostname and the observed address among others, as a stale or hostile
                // status could report; nothing may match it to the observed binding.
                tail_node("node-cedar", "CEDAR", &["100.64.0.9", "100.64.0.7"]),
                tail_node("node-fern", "FERN", &["100.64.1.31"]),
            ],
        });

        assert_eq!(
            registry.by_device_id(desktop.device_id),
            Some(&paired_before)
        );
        assert_eq!(
            registry
                .by_device_id(discovered.device_id)
                .expect("discovered record")
                .dial_addresses()
                .to_vec(),
            vec![ip("100.64.1.31")]
        );
    }

    #[test]
    fn pairing_replaces_a_trusted_key_only_when_the_prior_identity_is_named() {
        // A key change always needs explicit re-pairing, and that pairing must name the identity
        // it displaces, so a stale or racing caller can never silently swap a trusted key.
        let mut registry = PeerRegistry::default();
        let desktop = InstallationIdentity::generate();
        registry
            .record_paired(
                observed(&desktop, "CEDAR", "100.64.0.7", 1),
                PAIRED_AT,
                None,
            )
            .expect("first pairing creates the record");
        let record = registry.by_device_id(desktop.device_id).expect("record");
        assert_eq!(record.origin(), TrustOrigin::Paired);
        assert_eq!(record.pairing(), Some(&evidence(1)));
        assert_eq!(record.node_id(), None);

        // The same identity re-paired after a Tailscale identity reset moves its binding.
        registry
            .record_paired(
                observed(&desktop, "CEDAR", "100.64.0.8", 2),
                PAIRED_AT,
                None,
            )
            .expect("same identity re-pairs without naming itself");
        assert_eq!(registry.peers().len(), 1);
        assert_eq!(
            registry.admit(desktop.device_id, &desktop.public_key(), ip("100.64.0.7")),
            PeerAdmission::NetworkIdentityChanged
        );

        // A new identity at the paired address, as after desktop identity-store loss.
        let replacement = InstallationIdentity::generate();
        let snapshot = registry.clone();
        for wrong_prior in [
            None,
            Some(identity_of(&replacement)),
            Some((desktop.device_id, replacement.public_key().to_vec())),
        ] {
            assert!(matches!(
                registry.record_paired(
                    observed(&replacement, "CEDAR", "100.64.0.8", 3),
                    PAIRED_AT,
                    wrong_prior
                ),
                Err(RegistryError::PriorIdentityMismatch)
            ));
            assert_eq!(registry, snapshot);
        }
        // The same device presenting a rotated key is a key replacement too.
        let mut rotated = observed(&desktop, "CEDAR", "100.64.0.8", 4);
        rotated.peer.public_key = replacement.public_key();
        assert!(matches!(
            registry.record_paired(rotated, PAIRED_AT, None),
            Err(RegistryError::PriorIdentityMismatch)
        ));
        assert_eq!(registry, snapshot);

        registry
            .record_paired(
                observed(&replacement, "CEDAR", "100.64.0.8", 3),
                PAIRED_AT,
                Some(identity_of(&desktop)),
            )
            .expect("naming the prior identity replaces it");
        assert_eq!(registry.peers().len(), 1);
        assert_eq!(
            registry.admit(
                replacement.device_id,
                &replacement.public_key(),
                ip("100.64.0.8")
            ),
            PeerAdmission::Trusted
        );
        assert_eq!(
            registry.admit(desktop.device_id, &desktop.public_key(), ip("100.64.0.8")),
            PeerAdmission::UnknownDevice
        );

        // Naming a prior identity that is not there means the caller's view is stale.
        let newcomer = InstallationIdentity::generate();
        let snapshot = registry.clone();
        assert!(matches!(
            registry.record_paired(
                observed(&newcomer, "BIRCH", "100.64.0.9", 5),
                PAIRED_AT,
                Some(identity_of(&desktop))
            ),
            Err(RegistryError::PriorIdentityMismatch)
        ));
        assert_eq!(registry, snapshot);
    }

    #[test]
    fn pending_pairing_promotion_is_all_or_nothing() {
        // The phone stores its approval before telling the desktop. Promotion must turn exactly
        // that approval into trust in one atomic replace, so neither a crash nor a refusal can
        // leave the approval consumed without trust, or trust recorded beside a live approval.
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.json");
        let store = InstallationStore::new(path.clone());
        let local = DeviceId::new();
        let desktop = InstallationIdentity::generate();
        let pending = approved(&desktop, 7, "100.64.0.7");
        store
            .update(local, |state| {
                state.pending_pairing = Some(pending.clone());
                Ok(())
            })
            .expect("store approval");
        let before = fs::read(&path).expect("read state");

        let other_transcript = TranscriptHash::from_bytes([8; 32]);
        assert!(matches!(
            store.promote_pending_pairing(
                local,
                &pending.approval.pairing_id,
                &other_transcript,
                5_000,
                None
            ),
            Err(RegistryError::PendingPairingMismatch)
        ));
        assert_eq!(fs::read(&path).expect("read state"), before);
        assert!(matches!(
            store.promote_pending_pairing(
                local,
                &pending.approval.pairing_id,
                &pending.approval.transcript_hash,
                10_000 + pairing::PAIRING_RECONCILE_ALLOWANCE_MS,
                None
            ),
            Err(RegistryError::PendingPairingExpired)
        ));
        assert_eq!(fs::read(&path).expect("read state"), before);

        let promoted = store
            .promote_pending_pairing(
                local,
                &pending.approval.pairing_id,
                &pending.approval.transcript_hash,
                5_000,
                None,
            )
            .expect("promote");
        let reopened = store.load_for_identity(local).expect("load");
        assert_eq!(reopened, promoted);
        assert_eq!(reopened.pending_pairing, None);
        let record = reopened
            .peers
            .by_device_id(desktop.device_id)
            .expect("trusted");
        assert_eq!(record.origin(), TrustOrigin::Paired);
        assert_eq!(
            record.pairing(),
            Some(&PairingEvidence {
                pairing_id: pending.approval.pairing_id,
                transcript_hash: pending.approval.transcript_hash,
                paired_at_unix_ms: 5_000,
                expires_at_unix_ms: pending.approval.expires_at_unix_ms,
            })
        );
        assert_eq!(
            reopened
                .peers
                .admit(desktop.device_id, &desktop.public_key(), ip("100.64.0.7")),
            PeerAdmission::Trusted
        );
        assert!(matches!(
            store.promote_pending_pairing(
                local,
                &pending.approval.pairing_id,
                &pending.approval.transcript_hash,
                5_000,
                None
            ),
            Err(RegistryError::NoPendingPairing)
        ));

        // A refusal raised by the trust write itself, inside the same update, also leaves the
        // file as it was: another identity approved at the paired address without naming it.
        let replacement = InstallationIdentity::generate();
        let second = approved(&replacement, 9, "100.64.0.7");
        store
            .update(local, |state| {
                state.pending_pairing = Some(second.clone());
                Ok(())
            })
            .expect("store second approval");
        let before = fs::read(&path).expect("read state");
        assert!(matches!(
            store.promote_pending_pairing(
                local,
                &second.approval.pairing_id,
                &second.approval.transcript_hash,
                5_000,
                None
            ),
            Err(RegistryError::PriorIdentityMismatch)
        ));
        assert_eq!(fs::read(&path).expect("read state"), before);
        assert_eq!(
            store
                .load_for_identity(local)
                .expect("load")
                .pending_pairing,
            Some(second)
        );
    }

    /// `state.json` exactly as the build before trust origins wrote it: produced by running that
    /// build's `InstallationStore::update` with `accept_signed`, then stripped of whitespace.
    const LEGACY_STATE_JSON: &str = r#"{"device_id":"6f1c2a4e-8b0d-4c3a-9e57-1d2b3c4d5e6f","peers":{"peers":[{"node_id":"nFERN1CNTRL","device_id":"0a9b8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d","hostname":"FERN","addresses":["100.64.1.30","fd7a:115c:a1e0::9"],"public_key":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7]}]},"settings":{"schema_version":1,"save_destination":{"kind":"downloads"}}}"#;

    #[test]
    fn legacy_state_file_decodes_and_reencodes_byte_for_byte() {
        // Desktops upgrade in place: a file an older build wrote must keep its trust, and writing
        // it back must not change its shape for an older build still reading the same file.
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.json");
        fs::write(&path, LEGACY_STATE_JSON).expect("write legacy state");
        let state = InstallationState::load(&path).expect("legacy state decodes");
        let peer = &state.peers.peers()[0];
        assert_eq!(
            peer.binding(),
            &PeerNetworkBinding::TailscaleNode {
                node_id: "nFERN1CNTRL".to_owned(),
                addresses: vec![ip("100.64.1.30"), ip("fd7a:115c:a1e0::9")],
            }
        );
        assert_eq!(peer.origin(), TrustOrigin::Discovery);
        assert_eq!(peer.pairing(), None);
        assert_eq!(state.pending_pairing, None);
        assert_eq!(
            serde_json::to_string(&state).expect("encode"),
            LEGACY_STATE_JSON
        );
    }

    #[test]
    fn older_build_still_reads_state_with_paired_records_and_a_pending_approval() {
        // These are the definitions an older desktop build parses state.json with. Everything a
        // newer build adds to a TailscaleNode record must be an extra field it ignores.
        #[derive(Deserialize)]
        struct OldTrustedPeer {
            node_id: String,
            device_id: DeviceId,
            hostname: String,
            addresses: Vec<IpAddr>,
            #[serde(default)]
            public_key: Vec<u8>,
        }
        #[derive(Deserialize)]
        struct OldPeerRegistry {
            peers: Vec<OldTrustedPeer>,
        }
        #[derive(Deserialize)]
        struct OldInstallationState {
            device_id: DeviceId,
            peers: OldPeerRegistry,
            #[serde(default)]
            settings: UserSettings,
        }

        let phone = InstallationIdentity::generate();
        let mut state = InstallationState::default();
        state
            .peers
            .record_paired(
                paired(
                    &phone,
                    "Pixel",
                    PeerNetworkBinding::TailscaleNode {
                        node_id: "node-pixel".to_owned(),
                        addresses: vec![ip("100.64.1.50")],
                    },
                    0xab,
                ),
                PAIRED_AT,
                None,
            )
            .expect("pair");
        state.pending_pairing = Some(approved(&phone, 5, "100.64.1.50"));
        let bytes = serde_json::to_vec_pretty(&state).expect("encode");

        let old: OldInstallationState = serde_json::from_slice(&bytes).expect("older build parses");
        assert_eq!(old.device_id, state.device_id);
        assert_eq!(old.settings, state.settings);
        let old_peer = &old.peers.peers[0];
        assert_eq!(old_peer.node_id, "node-pixel");
        assert_eq!(old_peer.device_id, phone.device_id);
        assert_eq!(old_peer.hostname, "Pixel");
        assert_eq!(old_peer.addresses, vec![ip("100.64.1.50")]);
        assert_eq!(old_peer.public_key, phone.public_key().to_vec());

        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let pairing = &value["peers"]["peers"][0]["pairing"];
        assert_eq!(pairing["pairing_id"], "ab".repeat(16));
        assert_eq!(pairing["transcript_hash"], "ab".repeat(32));
        assert_eq!(
            serde_json::from_slice::<InstallationState>(&bytes).expect("current build decodes"),
            state
        );
    }

    #[test]
    fn ambiguous_or_inconsistent_trust_records_fail_closed() {
        // A record that could be read two ways is refused rather than guessed at: a guess could
        // admit a peer from an address nobody paired, or strip a paired record's protection.
        let device = DeviceId::new();
        let evidence = serde_json::to_value(evidence(1)).expect("evidence");
        for record in [
            serde_json::json!({"node_id": "n", "device_id": device, "hostname": "h",
                "addresses": ["100.64.0.1"], "observed_address": "100.64.0.1"}),
            serde_json::json!({"device_id": device, "hostname": "h"}),
            serde_json::json!({"node_id": "n", "device_id": device, "hostname": "h"}),
            serde_json::json!({"node_id": "n", "device_id": device, "hostname": "h",
                "addresses": [], "origin": "paired"}),
            serde_json::json!({"device_id": device, "hostname": "h",
                "observed_address": "100.64.0.1", "origin": "paired"}),
            serde_json::json!({"node_id": "n", "device_id": device, "hostname": "h",
                "addresses": [], "pairing": evidence}),
        ] {
            assert!(
                serde_json::from_value::<TrustedPeer>(record.clone()).is_err(),
                "accepted {record}"
            );
        }
    }

    #[test]
    fn observed_signed_discovery_peer_round_trips_through_state_json() {
        let mut registry = PeerRegistry::default();
        let peer_id = DeviceId::new();
        let peer_key = [42u8; 32];
        registry
            .accept_observed_signed("CEDAR", ip("100.64.1.10"), peer_id, peer_key.to_vec())
            .expect("accept observed signed peer");
        let encoded = serde_json::to_vec(&registry).expect("encode");
        let decoded: PeerRegistry = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.peers().len(), 1);
        let peer = &decoded.peers()[0];
        assert_eq!(peer.device_id, peer_id);
        assert_eq!(peer.hostname, "CEDAR");
        assert_eq!(peer.origin(), TrustOrigin::Discovery);
        assert_eq!(peer.pairing(), None);
        assert_eq!(
            peer.binding,
            PeerNetworkBinding::ObservedTailscaleAddress {
                address: ip("100.64.1.10")
            }
        );
    }

    #[test]
    fn stored_pairing_records_are_the_protocol_records_with_one_conversion() {
        // A18: the approval the phone persists is exactly the protocol's ApprovedPending plus the
        // observed address, and promotion is bounded by the protocol's own completion deadline,
        // so no second definition of either fact can drift. A desktop resumes from its record.
        let desktop = InstallationIdentity::generate();
        let pending = approved(&desktop, 7, "100.64.0.7");
        let decoded: ApprovedPending =
            serde_json::from_slice(&serde_json::to_vec(&pending).expect("encode")).expect("decode");
        assert_eq!(decoded, pending);
        let mut short_key = serde_json::to_value(&pending).expect("value");
        short_key["peer_public_key"] = serde_json::json!([1, 2, 3]);
        assert!(serde_json::from_value::<ApprovedPending>(short_key).is_err());

        // Past the pairing expiry but inside the reconciliation allowance the approval still
        // promotes (A12); the record then yields the same protocol peer it was written from.
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = InstallationStore::new(directory.path().join("state.json"));
        let local = DeviceId::new();
        store
            .update(local, |state| {
                state.pending_pairing = Some(pending.clone());
                Ok(())
            })
            .expect("store approval");
        let late = pending.approval.expires_at_unix_ms + 1;
        let state = store
            .promote_pending_pairing(
                local,
                &pending.approval.pairing_id,
                &pending.approval.transcript_hash,
                late,
                None,
            )
            .expect("promote inside the allowance");
        let record = state.peers.by_device_id(desktop.device_id).expect("record");
        assert_eq!(record.paired(), Some(pending.paired_peer()));
        assert_eq!(record.pairing().expect("evidence").paired_at_unix_ms, late);

        // The identity a re-pairing displaces is named from the record, never guessed.
        let replacement = InstallationIdentity::generate();
        let binding = PeerNetworkBinding::ObservedTailscaleAddress {
            address: ip("100.64.0.7"),
        };
        assert_eq!(
            state
                .peers
                .displaced_identity(replacement.device_id, &replacement.public_key(), &binding)
                .expect("a reinstall on the same endpoint is not a conflict"),
            Some(identity_of(&desktop))
        );
        assert_eq!(
            state
                .peers
                .displaced_identity(desktop.device_id, &desktop.public_key(), &binding)
                .expect("the same installation is not a conflict"),
            None
        );
    }

    #[test]
    fn a_device_id_claimed_under_another_key_elsewhere_never_replaces_a_trusted_record() {
        // A device id is an unauthenticated label. If a pairing could replace a record by device
        // id alone, anyone who learned CEDAR's id could pair from their own node with their own
        // key and silently take CEDAR's place, even while naming CEDAR as the prior identity.
        let desktop = InstallationIdentity::generate();
        let attacker = InstallationIdentity::generate();
        let mut registry = PeerRegistry::default();
        registry
            .record_paired(
                observed(&desktop, "CEDAR", "100.64.0.7", 1),
                PAIRED_AT,
                None,
            )
            .expect("pair CEDAR");
        let before = serde_json::to_vec(&registry).expect("encode");
        let mut claim = observed(&attacker, "CEDAR", "100.64.0.9", 2);
        claim.peer.device_id = desktop.device_id;
        for prior in [None, Some(identity_of(&desktop))] {
            assert!(matches!(
                registry.record_paired(claim.clone(), PAIRED_AT, prior),
                Err(RegistryError::DeviceIdentityConflict { device_id }) if device_id == desktop.device_id
            ));
            assert_eq!(serde_json::to_vec(&registry).expect("encode"), before);
        }
        assert!(matches!(
            registry.displaced_identity(desktop.device_id, &attacker.public_key(), &claim.binding),
            Err(RegistryError::DeviceIdentityConflict { .. })
        ));

        // The same for a desktop trusted by discovery and a hostile node claiming its id.
        let fern = InstallationIdentity::generate();
        registry
            .accept_signed(
                &tail_node("node-fern", "FERN", &["100.64.1.30"]),
                fern.device_id,
                fern.public_key().to_vec(),
            )
            .expect("discover FERN");
        let before = serde_json::to_vec(&registry).expect("encode");
        let mut hostile = paired(
            &attacker,
            "FERN",
            PeerNetworkBinding::TailscaleNode {
                node_id: "node-hostile".to_owned(),
                addresses: vec![ip("100.64.1.41")],
            },
            3,
        );
        hostile.peer.device_id = fern.device_id;
        assert!(matches!(
            registry.record_paired(hostile, PAIRED_AT, None),
            Err(RegistryError::DeviceIdentityConflict { device_id }) if device_id == fern.device_id
        ));
        assert_eq!(serde_json::to_vec(&registry).expect("encode"), before);

        // Rule (b): the same installation, id and key, re-paired from a new address replaces it.
        registry
            .record_paired(
                observed(&desktop, "CEDAR", "100.64.0.8", 4),
                PAIRED_AT,
                None,
            )
            .expect("the same installation moves");
        assert_eq!(
            registry.admit(desktop.device_id, &desktop.public_key(), ip("100.64.0.8")),
            PeerAdmission::Trusted
        );
        assert_eq!(
            registry
                .peers()
                .iter()
                .filter(|peer| peer.device_id == desktop.device_id)
                .count(),
            1
        );

        // Rule (a): a new installation on the same endpoint (a reinstall) replaces it, named.
        let reinstall = InstallationIdentity::generate();
        let same_endpoint = observed(&reinstall, "CEDAR", "100.64.0.8", 5);
        assert_eq!(
            registry
                .displaced_identity(
                    reinstall.device_id,
                    &reinstall.public_key(),
                    &same_endpoint.binding
                )
                .expect("a reinstall on the same endpoint is not a conflict"),
            Some(identity_of(&desktop))
        );
        registry
            .record_paired(same_endpoint, PAIRED_AT, Some(identity_of(&desktop)))
            .expect("reinstall on the same endpoint");
        assert_eq!(
            registry.admit(desktop.device_id, &desktop.public_key(), ip("100.64.0.8")),
            PeerAdmission::UnknownDevice
        );
        assert_eq!(
            registry.admit(
                reinstall.device_id,
                &reinstall.public_key(),
                ip("100.64.0.8")
            ),
            PeerAdmission::Trusted
        );
    }
}
