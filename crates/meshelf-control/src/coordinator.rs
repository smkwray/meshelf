//! The resident, durable paste-to-offer coordinator.

use std::{path::PathBuf, sync::Arc, time::SystemTime};

use meshelf_core::{DeviceId, OfferDescriptor, OfferId, OfferSourceInput, OfferSourceStore};
use meshelf_identity::InstallationIdentity;
use meshelf_protocol::OfferAnnouncement;
use meshelf_store::RedbV2Store;
use meshelf_tailscale::InstallationStore;

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

pub struct Coordinator {
    identity: DeviceId,
    installation_store: InstallationStore,
    offer_store: Arc<dyn OfferSourceStore>,
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
        }
    }

    pub fn open(
        state_path: PathBuf,
        offer_path: PathBuf,
    ) -> Result<(Self, InstallationIdentity), String> {
        let identity = InstallationIdentity::load_or_create()
            .map_err(|error| format!("could not load meshelf installation identity: {error}"))?;
        let store = RedbV2Store::open(offer_path)
            .map_err(|error| format!("could not open v2 offer store: {error}"))?;
        let coordinator = Self::new(
            identity.device_id,
            InstallationStore::new(state_path),
            Arc::new(store),
        );
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
    use meshelf_tailscale::{InstallationStore, TailNode};
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
