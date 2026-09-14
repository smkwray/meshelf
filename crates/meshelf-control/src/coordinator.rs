//! The resident, durable paste-to-offer coordinator.

#[cfg(not(target_os = "android"))]
use std::path::PathBuf;
use std::{
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex, mpsc},
    time::SystemTime,
};

use meshelf_core::{
    ActivationId, ActivationMode, DeviceId, OfferCardInput, OfferCardInsert, OfferCardRecord,
    OfferDescriptor, OfferId, OfferSourceInput, OfferSourceStore, SaveDestination, StoreError,
};
#[cfg(not(target_os = "android"))]
use meshelf_identity::InstallationIdentity;
use meshelf_net::OfferCardStore;
use meshelf_protocol::OfferAnnouncement;
#[cfg(not(target_os = "android"))]
use meshelf_store::RedbV2Store;
use meshelf_tailscale::{InstallationStore, TrustOrigin, TrustedPeer};

use crate::offer_source::{OfferInput, PreparedOfferSource, prepare_source};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerAnnouncement {
    pub device_id: DeviceId,
    pub hostname: String,
    pub announcement: OfferAnnouncement,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OfferPlan {
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub announcements: Vec<PeerAnnouncement>,
}

/// In-process notification for the resident shelf. It carries no card data; consumers reread the
/// v2 store after receiving it, so the store remains the sole shelf authority.
#[derive(Clone, Default)]
pub struct ShelfChangeNotifier {
    subscribers: Arc<Mutex<Vec<mpsc::Sender<()>>>>,
}

impl ShelfChangeNotifier {
    pub fn subscribe(&self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        if let Ok(mut subscribers) = self.subscribers.lock() {
            subscribers.push(sender);
        }
        receiver
    }

    pub fn notify(&self) {
        if let Ok(mut subscribers) = self.subscribers.lock() {
            subscribers.retain(|sender| sender.send(()).is_ok());
        }
    }
}

/// Card-store composition for the resident shelf. Announcement handlers use this wrapper so a
/// durable card insertion wakes the desktop's metadata-only shelf without carrying card data in
/// the notification.
pub struct NotifyingOfferCardStore {
    inner: Arc<dyn OfferCardStore>,
    shelf_changes: ShelfChangeNotifier,
}

impl NotifyingOfferCardStore {
    #[must_use]
    pub fn new(inner: Arc<dyn OfferCardStore>, shelf_changes: ShelfChangeNotifier) -> Self {
        Self {
            inner,
            shelf_changes,
        }
    }
}

impl OfferCardStore for NotifyingOfferCardStore {
    fn get_offer_card(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
    ) -> Result<Option<OfferCardRecord>, StoreError> {
        self.inner.get_offer_card(source_device, offer_id)
    }

    fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError> {
        self.inner.read_offer_shelf()
    }

    fn insert_offer_card(&self, input: OfferCardInput) -> Result<OfferCardInsert, StoreError> {
        let result = self.inner.insert_offer_card(input)?;
        if result.inserted {
            self.shelf_changes.notify();
        }
        Ok(result)
    }
}

/// One peer a capture request may be sent to.
///
/// A capture needs the peer's pinned installation key and at least one dial address, so a trust
/// record missing either cannot authorize one. There is no fallback to an unauthenticated address
/// or an unpinned key: tailnet membership alone is not application authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePeer {
    pub device_id: DeviceId,
    /// The peer's own name, as the trust record holds it. A phone paired before the first
    /// discovery refresh is stored under the name the phone gave.
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub public_key: Vec<u8>,
}

/// Why a capture peer selector named no single usable trust record.
///
/// These are separate because they are different answers to the agent: nothing of that name is
/// paired, several paired records answer to that name, or the one that does cannot be dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturePeerError {
    /// No *paired* trust record matches. A discovery record is not one: O-003 records any signed
    /// tailnet node automatically, under the name that node chose for itself, and tailnet
    /// membership is not application authorization (invariant 7).
    NotPaired(String),
    /// More than one paired record matches, so the selector named no one device. Refused rather
    /// than resolved: Tailscale does not deduplicate hostnames, and a phone is stored under its
    /// own self-reported name until a discovery refresh renames it, so the name an agent typed
    /// can genuinely belong to two records.
    Ambiguous(String),
    /// Exactly one paired record matches and cannot be used for a capture.
    Unusable(String),
}

impl fmt::Display for CapturePeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPaired(detail) | Self::Ambiguous(detail) | Self::Unusable(detail) => {
                formatter.write_str(detail)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationPlan {
    pub activation_id: ActivationId,
    pub source_device: DeviceId,
    pub offer_id: OfferId,
    pub descriptor: OfferDescriptor,
    pub mode: ActivationMode,
    /// A save activation snapshots the controller setting here. The platform resolves Downloads
    /// only when the pull starts; a later settings edit therefore affects future activations only.
    pub destination: Option<SaveDestination>,
}

pub struct Coordinator {
    identity: DeviceId,
    installation_store: InstallationStore,
    offer_store: Arc<dyn OfferSourceStore>,
    card_store: Option<Arc<dyn OfferCardStore>>,
    shelf_changes: ShelfChangeNotifier,
}

impl Coordinator {
    #[must_use]
    pub fn new(
        identity: DeviceId,
        installation_store: InstallationStore,
        offer_store: Arc<dyn OfferSourceStore>,
    ) -> Self {
        Self {
            identity,
            installation_store,
            offer_store,
            card_store: None,
            shelf_changes: ShelfChangeNotifier::default(),
        }
    }

    #[must_use]
    pub fn with_card_store(mut self, card_store: Arc<dyn OfferCardStore>) -> Self {
        self.card_store = Some(Arc::new(NotifyingOfferCardStore::new(
            card_store,
            self.shelf_changes.clone(),
        )));
        self
    }

    pub fn card_store(&self) -> Option<Arc<dyn OfferCardStore>> {
        self.card_store.clone()
    }

    #[must_use]
    pub fn shelf_changes(&self) -> ShelfChangeNotifier {
        self.shelf_changes.clone()
    }

    pub fn read_shelf(&self) -> Result<Vec<OfferCardRecord>, String> {
        self.card_store
            .as_ref()
            .ok_or_else(|| "v2 offer-card store is not configured".to_owned())?
            .read_offer_shelf()
            .map_err(|error| format!("could not read offer shelf: {error}"))
    }

    pub fn plan_activation(
        &self,
        offer_id: OfferId,
        mode: ActivationMode,
    ) -> Result<ActivationPlan, String> {
        let card = self
            .card_store
            .as_ref()
            .ok_or_else(|| "v2 offer-card store is not configured".to_owned())?
            .read_offer_shelf()
            .map_err(|error| format!("could not read offer shelf: {error}"))?
            .into_iter()
            .find(|card| card.offer_id == offer_id)
            .ok_or_else(|| format!("offer {offer_id} is not on this shelf"))?;
        if mode == ActivationMode::Save && card.descriptor.is_text() {
            return Err("text offers cannot use save activation".to_owned());
        }
        if matches!(
            card.availability,
            meshelf_core::CardAvailability::SourceChanged
        ) {
            return Err("the offer source changed; activation is disabled".to_owned());
        }
        let destination = if mode == ActivationMode::Save {
            Some(self.settings()?.save_destination)
        } else {
            None
        };
        Ok(ActivationPlan {
            activation_id: ActivationId::new(),
            source_device: card.source_device,
            offer_id: card.offer_id,
            descriptor: card.descriptor,
            mode,
            destination,
        })
    }

    #[cfg(not(target_os = "android"))]
    pub fn open(
        state_path: PathBuf,
        offer_path: PathBuf,
    ) -> Result<(Self, InstallationIdentity), String> {
        let identity = InstallationIdentity::load_or_create()
            .map_err(|error| format!("could not load meshelf installation identity: {error}"))?;
        let store = Arc::new(
            RedbV2Store::open(offer_path)
                .map_err(|error| format!("could not open v2 offer store: {error}"))?,
        );
        let coordinator = Self::new(
            identity.device_id,
            InstallationStore::new(state_path),
            store.clone(),
        )
        .with_card_store(store);
        Ok((coordinator, identity))
    }

    /// Persist the source and complete current peer eligibility before making
    /// any announcement plan visible to a caller.
    pub fn create_offer(&self, input: OfferInput) -> Result<Option<OfferPlan>, String> {
        self.create_offer_with_id(OfferId::new(), input)
    }

    pub fn create_offer_with_id(
        &self,
        offer_id: OfferId,
        input: OfferInput,
    ) -> Result<Option<OfferPlan>, String> {
        let state = self
            .installation_store
            .load_for_identity(self.identity)
            .map_err(|error| format!("could not load meshelf state: {error}"))?;
        let peers = state.peers.peers().to_vec();
        if peers.is_empty() {
            return Ok(None);
        }

        let PreparedOfferSource { descriptor, source } =
            prepare_source(input).map_err(|error| error.to_string())?;
        let announced_to = peers.iter().map(|peer| peer.device_id).collect();
        self.offer_store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor.clone(),
                announced_to,
                source,
            ))
            .map_err(|error| format!("could not durably store offer: {error}"))?;
        self.shelf_changes.notify();

        let created_at_unix_ms = now_unix_ms();
        let announcements = peers
            .into_iter()
            .map(|peer| PeerAnnouncement {
                device_id: peer.device_id,
                hostname: peer.hostname,
                announcement: OfferAnnouncement::new(
                    offer_id,
                    self.identity,
                    peer.device_id,
                    created_at_unix_ms,
                    descriptor.clone(),
                ),
            })
            .collect();
        Ok(Some(OfferPlan {
            offer_id,
            descriptor,
            announcements,
        }))
    }

    /// Resolves the peer an agent named on the command line: its device id, its Tailscale
    /// hostname, or its Tailscale node id, case-folded for the two names.
    ///
    /// A phone is stored under the name it gave until a discovery refresh renames it, so the
    /// hostname an agent expects may not match on the first run after pairing — and, for the same
    /// reason, a name can match more than one record. A selector that does is refused
    /// ([`CapturePeerError::Ambiguous`]); nothing here picks one for the agent.
    pub fn resolve_capture_peer(&self, selector: &str) -> Result<CapturePeer, CapturePeerError> {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err(CapturePeerError::NotPaired(
                "capture peer selector is empty".to_owned(),
            ));
        }
        let folded = selector.to_ascii_lowercase();
        self.find_capture_peer(
            |peer| {
                peer.device_id.to_string() == selector
                    || peer.hostname.to_ascii_lowercase() == folded
                    || peer
                        .node_id()
                        .is_some_and(|node_id| node_id.to_ascii_lowercase() == folded)
            },
            &format!("capture peer {selector:?}"),
        )
    }

    /// Resolves the peer a claimed pull names, so the automatic pull dials the same trust record
    /// the grant expects rather than anything the announcement carried.
    pub fn capture_peer_by_device(
        &self,
        device_id: DeviceId,
    ) -> Result<CapturePeer, CapturePeerError> {
        self.find_capture_peer(
            |peer| peer.device_id == device_id,
            &format!("capture peer {device_id}"),
        )
    }

    /// The one trust record `matches` selects, or why there is not exactly one.
    ///
    /// Only a `Paired` record authorizes a capture; a `Discovery` record of the same name is
    /// skipped, so a tailnet node that names itself after the phone is never sent a request. A
    /// selector that matches several paired records refuses rather than guessing.
    fn find_capture_peer(
        &self,
        matches: impl Fn(&TrustedPeer) -> bool,
        subject: &str,
    ) -> Result<CapturePeer, CapturePeerError> {
        let state = self
            .installation_store
            .load_for_identity(self.identity)
            .map_err(|error| {
                CapturePeerError::Unusable(format!("could not load meshelf state: {error}"))
            })?;
        let candidates: Vec<&TrustedPeer> = state
            .peers
            .peers()
            .iter()
            .filter(|peer| matches(peer) && peer.origin() == TrustOrigin::Paired)
            .collect();
        let [peer] = candidates.as_slice() else {
            if candidates.is_empty() {
                return Err(CapturePeerError::NotPaired(format!(
                    "{subject} is not paired"
                )));
            }
            let devices: Vec<String> = candidates
                .iter()
                .map(|peer| format!("{} ({})", peer.hostname, peer.device_id))
                .collect();
            return Err(CapturePeerError::Ambiguous(format!(
                "{subject} matches {} trust records: {}",
                candidates.len(),
                devices.join(", ")
            )));
        };
        // An Ed25519 installation key is 32 bytes. Anything else — a keyless legacy record, or a
        // record an older build rewrote — is refused here, because `meshelf-net` pins a key only
        // when one is present: an empty expected key means the dialled peer is never checked.
        if peer.public_key.len() != 32 {
            return Err(CapturePeerError::Unusable(format!(
                "capture peer {} has no authenticated installation key",
                peer.hostname
            )));
        }
        let addresses = peer.dial_addresses().to_vec();
        if addresses.is_empty() {
            return Err(CapturePeerError::Unusable(format!(
                "capture peer {} has no Tailscale address",
                peer.hostname
            )));
        }
        Ok(CapturePeer {
            device_id: peer.device_id,
            hostname: peer.hostname.clone(),
            addresses,
            public_key: peer.public_key.clone(),
        })
    }

    pub fn record_explicit_refusal(
        &self,
        offer_id: OfferId,
        recipient: DeviceId,
    ) -> Result<(), String> {
        self.offer_store
            .remove_explicit_refusal(offer_id, recipient)
            .map(|_| ())
            .map_err(|error| format!("could not record explicit refusal: {error}"))
    }

    pub fn settings(&self) -> Result<meshelf_core::UserSettings, String> {
        self.installation_store
            .load_for_identity(self.identity)
            .map(|state| state.settings)
            .map_err(|error| format!("could not load meshelf settings: {error}"))
    }

    pub fn update_settings(
        &self,
        settings: meshelf_core::UserSettings,
    ) -> Result<meshelf_core::UserSettings, String> {
        self.installation_store
            .update(self.identity, |state| {
                state.settings = settings;
                Ok(())
            })
            .map(|state| state.settings)
            .map_err(|error| format!("could not save meshelf settings: {error}"))
    }
}

fn now_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use meshelf_core::{OfferEligibilityUpdate, OfferSourceInsert, OfferSourceRecord, StoreError};
    use meshelf_tailscale::{InstallationStore, PeerNetworkBinding, TailNode};
    use tempfile::tempdir;

    use super::*;

    fn setup() -> (tempfile::TempDir, Coordinator, Arc<RedbV2Store>, DeviceId) {
        let directory = tempdir().expect("temporary directory");
        let state_path = directory.path().join("state.json");
        let offer_path = directory.path().join("offers.redb");
        let identity = InstallationIdentity::generate();
        let peer = InstallationIdentity::generate();
        let peer_id = peer.device_id;
        let node = TailNode {
            node_id: Some("peer-node".to_owned()),
            hostname: "peer".to_owned(),
            dns_name: None,
            addresses: vec!["100.64.0.2".parse().expect("address")],
            online: true,
            active: true,
        };
        let installation_store = InstallationStore::new(state_path);
        installation_store
            .update(identity.device_id, |state| {
                state
                    .peers
                    .accept_signed(&node, peer_id, peer.public_key().to_vec())
            })
            .expect("pair peer");
        let store = Arc::new(RedbV2Store::open(offer_path).expect("open store"));
        let coordinator = Coordinator::new(identity.device_id, installation_store, store.clone());
        (directory, coordinator, store, peer_id)
    }

    #[test]
    fn announcement_card_insert_wakes_the_shelf_subscriber() {
        let directory = tempdir().expect("temporary directory");
        let source = InstallationIdentity::generate();
        let target = InstallationIdentity::generate();
        let store = Arc::new(
            RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
        );
        let coordinator = Coordinator::new(
            target.device_id,
            InstallationStore::new(directory.path().join("state.json")),
            store.clone(),
        )
        .with_card_store(store);
        let subscriber = coordinator.shelf_changes().subscribe();
        let handler = meshelf_net::OfferAnnouncementHandler::new(
            coordinator.card_store().expect("card store"),
        );
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            source.device_id,
            target.device_id,
            1,
            OfferDescriptor::text("announced metadata").expect("descriptor"),
        );

        let ack = handler
            .handle_sync(source.device_id, target.device_id, announcement)
            .expect("announcement");

        assert_eq!(ack.code, meshelf_protocol::OfferAckCode::Stored);
        assert!(
            subscriber
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_ok()
        );
    }

    #[test]
    fn store_commit_precedes_first_announcement_plan() {
        let (_directory, coordinator, store, peer_id) = setup();
        let plan = coordinator
            .create_offer(OfferInput::Text("durable first".to_owned()))
            .expect("create")
            .expect("plan");
        assert!(
            store
                .get_offer_source(plan.offer_id)
                .expect("read source")
                .is_some()
        );
        assert_eq!(plan.announcements[0].device_id, peer_id);
    }

    struct FailingStore;

    impl OfferSourceStore for FailingStore {
        fn insert_offer_source(
            &self,
            _input: meshelf_core::OfferSourceInput,
        ) -> Result<OfferSourceInsert, StoreError> {
            Err(StoreError::new("injected commit failure"))
        }

        fn remove_explicit_refusal(
            &self,
            _offer_id: OfferId,
            _recipient: DeviceId,
        ) -> Result<OfferEligibilityUpdate, StoreError> {
            unreachable!("not used")
        }

        fn add_announced_recipient(
            &self,
            _offer_id: OfferId,
            _recipient: DeviceId,
        ) -> Result<meshelf_core::OfferAnnouncedRecipientUpdate, StoreError> {
            unreachable!("not used")
        }

        fn get_offer_source(
            &self,
            _offer_id: OfferId,
        ) -> Result<Option<OfferSourceRecord>, StoreError> {
            unreachable!("not used")
        }
    }

    #[test]
    fn store_failure_produces_zero_attempts() {
        let (_directory, _unused, _store, _peer_id) = setup();
        let directory = tempdir().expect("temporary directory");
        let identity = InstallationIdentity::generate();
        let state_path = directory.path().join("state.json");
        let peer_identity = InstallationIdentity::generate();
        let node = TailNode {
            node_id: Some("peer-node".to_owned()),
            hostname: "peer".to_owned(),
            dns_name: None,
            addresses: vec!["100.64.0.2".parse().expect("address")],
            online: true,
            active: true,
        };
        let state_store = InstallationStore::new(state_path);
        state_store
            .update(identity.device_id, |state| {
                state.peers.accept_signed(
                    &node,
                    peer_identity.device_id,
                    peer_identity.public_key().to_vec(),
                )
            })
            .expect("pair peer");
        let coordinator = Coordinator::new(identity.device_id, state_store, Arc::new(FailingStore));
        assert!(
            coordinator
                .create_offer(OfferInput::Text("will fail".to_owned()))
                .is_err()
        );
    }

    #[test]
    fn no_peers_creates_no_offer() {
        let directory = tempdir().expect("temporary directory");
        let identity = InstallationIdentity::generate();
        let state_store = InstallationStore::new(directory.path().join("state.json"));
        state_store
            .update(identity.device_id, |_| Ok(()))
            .expect("initialize state");
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("offers.redb")).expect("open store"));
        let coordinator = Coordinator::new(identity.device_id, state_store, store.clone());
        assert!(
            coordinator
                .create_offer(OfferInput::Text("no recipient".to_owned()))
                .expect("create")
                .is_none()
        );
        assert!(store.read_offer_sources().expect("read").is_empty());
    }

    #[test]
    fn duplicate_creation_is_idempotent_or_conflict() {
        let (_directory, coordinator, store, _peer_id) = setup();
        let id = OfferId::new();
        let first = coordinator
            .create_offer_with_id(id, OfferInput::Text("same".to_owned()))
            .expect("first")
            .expect("plan");
        let second = coordinator
            .create_offer_with_id(id, OfferInput::Text("same".to_owned()))
            .expect("duplicate")
            .expect("plan");
        assert_eq!(first.offer_id, second.offer_id);
        assert_eq!(store.read_offer_sources().expect("one source").len(), 1);
        assert!(
            coordinator
                .create_offer_with_id(id, OfferInput::Text("different".to_owned()))
                .is_err()
        );
    }

    // -- capture peer resolution ---------------------------------------------------------------

    /// A trust store holding whatever records a test needs, and the coordinator that reads it.
    struct Peers {
        _directory: tempfile::TempDir,
        state_path: PathBuf,
        identity: DeviceId,
        store: InstallationStore,
        coordinator: Coordinator,
    }

    impl Peers {
        fn new() -> Self {
            let directory = tempdir().expect("temporary directory");
            let state_path = directory.path().join("state.json");
            let identity = InstallationIdentity::generate().device_id;
            let store = InstallationStore::new(state_path.clone());
            let offers = Arc::new(
                RedbV2Store::open(directory.path().join("offers.redb")).expect("open store"),
            );
            let coordinator = Coordinator::new(identity, store.clone(), offers);
            Self {
                _directory: directory,
                state_path,
                identity,
                store,
                coordinator,
            }
        }

        /// A record exactly as a completed pairing writes one.
        fn pair(&self, hostname: &str, node_id: &str, address: &str) -> DeviceId {
            self.pair_bound(
                hostname,
                PeerNetworkBinding::TailscaleNode {
                    node_id: node_id.to_owned(),
                    addresses: vec![address.parse().expect("address")],
                },
            )
        }

        fn pair_bound(&self, hostname: &str, binding: PeerNetworkBinding) -> DeviceId {
            let peer = InstallationIdentity::generate();
            let device_id = peer.device_id;
            self.store
                .update(self.identity, |state| {
                    state.peers.record_paired(
                        meshelf_tailscale::PairedPeer {
                            peer: meshelf_protocol::pairing::PairedPeer {
                                device_id,
                                public_key: peer.public_key(),
                                device_name: hostname.to_owned(),
                                pairing_id: meshelf_protocol::pairing::PairingId::generate(),
                                transcript_hash:
                                    meshelf_protocol::pairing::TranscriptHash::from_bytes([7; 32]),
                            },
                            binding: binding.clone(),
                            expires_at_unix_ms: now_unix_ms() + 120_000,
                        },
                        now_unix_ms(),
                        None,
                    )
                })
                .expect("record the paired peer");
            device_id
        }

        /// A record the O-003 discovery rule writes by itself, with no person in the loop.
        fn discover(&self, hostname: &str, node_id: &str, address: &str) -> DeviceId {
            let peer = InstallationIdentity::generate();
            let device_id = peer.device_id;
            self.store
                .update(self.identity, |state| {
                    state.peers.accept_signed(
                        &TailNode {
                            node_id: Some(node_id.to_owned()),
                            hostname: hostname.to_owned(),
                            dns_name: None,
                            addresses: vec![address.parse().expect("address")],
                            online: true,
                            active: true,
                        },
                        device_id,
                        peer.public_key().to_vec(),
                    )
                })
                .expect("record the discovered peer");
            device_id
        }

        /// Rewrites one stored record's key, the way a build that does not know the field, or a
        /// hand-edited state file, leaves it.
        fn strip_key(&self, device_id: DeviceId) {
            let text = std::fs::read_to_string(&self.state_path).expect("read state");
            let mut state: serde_json::Value = serde_json::from_str(&text).expect("parse state");
            let peers = state["peers"]["peers"].as_array_mut().expect("peer array");
            let peer = peers
                .iter_mut()
                .find(|peer| peer["device_id"] == serde_json::json!(device_id.to_string()))
                .expect("the stored peer");
            peer["public_key"] = serde_json::json!([]);
            std::fs::write(&self.state_path, state.to_string()).expect("write state");
        }
    }

    #[test]
    fn a_capture_peer_needs_a_pairing_and_a_discovery_record_of_the_same_name_is_not_one() {
        // The attack this refuses: any tailnet node may name itself `amber` and is recorded
        // automatically by O-003. Resolving it would send it the agent's purpose text and let it
        // publish bytes at the agent's output path under a grant meant for the phone.
        let peers = Peers::new();
        let impostor = peers.discover("amber", "impostor-node", "100.64.0.9");

        let error = peers
            .coordinator
            .resolve_capture_peer("amber")
            .expect_err("a discovery record is not a capture peer");
        assert!(
            matches!(error, CapturePeerError::NotPaired(_)),
            "a discovered node must be refused as not paired, got {error:?}"
        );
        assert!(
            matches!(
                peers.coordinator.capture_peer_by_device(impostor),
                Err(CapturePeerError::NotPaired(_))
            ),
            "the pull resolves its source under the same rule as the request"
        );

        // The same name, now genuinely paired, resolves to the paired device and never to the
        // discovered one, whichever way the registry happens to sort them.
        let phone = peers.pair("amber", "phone-node", "100.64.0.4");
        assert_eq!(
            peers
                .coordinator
                .resolve_capture_peer("amber")
                .expect("the paired phone resolves")
                .device_id,
            phone
        );
    }

    #[test]
    fn a_selector_matching_two_paired_records_is_refused_rather_than_resolved_to_one() {
        let peers = Peers::new();
        let first = peers.pair("amber", "phone-node", "100.64.0.4");
        let second = peers.pair("amber", "other-node", "100.64.0.5");

        let error = peers
            .coordinator
            .resolve_capture_peer("amber")
            .expect_err("two paired records of one name name no device");
        let CapturePeerError::Ambiguous(detail) = &error else {
            panic!("expected an ambiguous selector, got {error:?}");
        };
        assert!(
            detail.contains(&first.to_string()) && detail.contains(&second.to_string()),
            "the refusal must name both records it could have meant: {detail}"
        );

        // Each device id still names exactly one of them, which is how an agent proceeds.
        for device_id in [first, second] {
            assert_eq!(
                peers
                    .coordinator
                    .resolve_capture_peer(&device_id.to_string())
                    .expect("a device id names one record")
                    .device_id,
                device_id
            );
        }
    }

    #[test]
    fn a_device_id_held_by_two_paired_records_is_refused_as_well() {
        // The ambiguity rule has no exemption for device ids. A registry holding one device id
        // twice is precisely where picking the first record silently would dial the wrong key.
        let peers = Peers::new();
        let phone = peers.pair("amber", "phone-node", "100.64.0.4");
        let text = std::fs::read_to_string(&peers.state_path).expect("read state");
        let mut state: serde_json::Value = serde_json::from_str(&text).expect("parse state");
        let records = state["peers"]["peers"].as_array_mut().expect("peer array");
        let mut twin = records[0].clone();
        twin["node_id"] = serde_json::json!("twin-node");
        twin["hostname"] = serde_json::json!("twin");
        records.push(twin);
        std::fs::write(&peers.state_path, state.to_string()).expect("write state");

        assert!(matches!(
            peers.coordinator.capture_peer_by_device(phone),
            Err(CapturePeerError::Ambiguous(_))
        ));
        assert!(matches!(
            peers.coordinator.resolve_capture_peer(&phone.to_string()),
            Err(CapturePeerError::Ambiguous(_))
        ));
    }

    #[test]
    fn a_paired_record_without_a_pinned_key_or_an_address_is_never_dialled() {
        // `CapturePeer` is what decides the pinned key and the address the capture dials, and
        // `meshelf-net` pins a key only when one is present, so a record with no key would be
        // dialled with no pinning at all rather than refused.
        let keyless = Peers::new();
        let phone = keyless.pair("amber", "phone-node", "100.64.0.4");
        keyless.strip_key(phone);
        let error = keyless
            .coordinator
            .resolve_capture_peer("amber")
            .expect_err("a record with no key cannot authenticate anyone");
        let CapturePeerError::Unusable(detail) = &error else {
            panic!("expected an unusable record, got {error:?}");
        };
        assert!(detail.contains("installation key"), "{detail}");

        let unbound = Peers::new();
        unbound.pair_bound(
            "amber",
            PeerNetworkBinding::TailscaleNode {
                node_id: "phone-node".to_owned(),
                addresses: Vec::new(),
            },
        );
        let error = unbound
            .coordinator
            .resolve_capture_peer("amber")
            .expect_err("a record with no address cannot be dialled");
        let CapturePeerError::Unusable(detail) = &error else {
            panic!("expected an unusable record, got {error:?}");
        };
        assert!(detail.contains("Tailscale address"), "{detail}");
    }

    #[test]
    fn coordinator_restart_reads_the_same_offer_authority() {
        let (directory, coordinator, store, _peer_id) = setup();
        let plan = coordinator
            .create_offer(OfferInput::Text("survives resident restart".to_owned()))
            .expect("create")
            .expect("plan");
        drop(coordinator);
        drop(store);
        let reopened = RedbV2Store::open(directory.path().join("offers.redb")).expect("reopen");
        assert_eq!(
            reopened
                .get_offer_source(plan.offer_id)
                .expect("read")
                .expect("source")
                .announced_to
                .len(),
            1
        );
    }
}
