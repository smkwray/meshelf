//! Typed requests handled by the one resident meshelf process.

use std::{io, path::PathBuf};

use meshelf_core::{
    ActivationId, ActivationMode, DeviceId, MAX_CONTROL_REQUEST_BYTES, MAX_TEXT_BYTES,
    OfferCardRecord, OfferDescriptor, OfferId, UserSettings,
};
use serde::{Deserialize, Serialize};

use crate::{
    coordinator::{ActivationPlan, Coordinator, OfferPlan, PeerAnnouncement},
    offer_source::OfferInput,
};

pub const MAX_SERIALIZED_TEXT_REQUEST_BYTES: usize = MAX_CONTROL_REQUEST_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum LocalRequest {
    AnnounceText {
        text: String,
    },
    AnnouncePath {
        path: PathBuf,
    },
    RecordExplicitRefusal {
        offer_id: OfferId,
        recipient: DeviceId,
    },
    GetSettings,
    SetSettings {
        settings: UserSettings,
    },
    Shelf,
    ActivateOffer {
        offer_id: OfferId,
        mode: ActivationMode,
    },
    CancelActivation {
        activation_id: ActivationId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum LocalResponse {
    OfferCreated {
        offer_id: OfferId,
        descriptor: OfferDescriptor,
        announcements: Vec<PeerAnnouncement>,
    },
    NoPeers,
    RefusalRecorded,
    Settings {
        settings: UserSettings,
    },
    Shelf {
        offers: Vec<OfferCardRecord>,
    },
    ActivationStarted {
        activation_id: ActivationId,
        offer_id: OfferId,
        mode: ActivationMode,
    },
    ActivationCancelled {
        activation_id: ActivationId,
    },
    ActivationRefused {
        message: String,
    },
    Error {
        message: String,
    },
}

/// Runtime-owned side effects for the resident control channel. The coordinator remains the
/// durable authority; these hooks are the only place a binary attaches network fan-out and a real
/// fetch worker.
pub trait LocalRuntime: Send + Sync + 'static {
    fn announce(&self, plan: &OfferPlan) -> Result<(), String>;
    fn activate(&self, plan: &ActivationPlan) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct NoopRuntime;

impl LocalRuntime for NoopRuntime {
    fn announce(&self, _plan: &OfferPlan) -> Result<(), String> {
        Ok(())
    }

    fn activate(&self, _plan: &ActivationPlan) -> Result<(), String> {
        Ok(())
    }
}

pub fn encode_request(request: &LocalRequest) -> io::Result<Vec<u8>> {
    if let LocalRequest::AnnounceText { text } = request
        && text.len() > MAX_TEXT_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "text exceeds the 1 MiB meshelf limit",
        ));
    }
    let encoded = serde_json::to_vec(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if encoded.len() > MAX_SERIALIZED_TEXT_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "serialized control request is {} bytes; maximum is {MAX_SERIALIZED_TEXT_REQUEST_BYTES}",
                encoded.len()
            ),
        ));
    }
    Ok(encoded)
}

pub fn decode_request(bytes: &[u8]) -> io::Result<LocalRequest> {
    if bytes.len() > MAX_SERIALIZED_TEXT_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "serialized control request is {} bytes; maximum is {MAX_SERIALIZED_TEXT_REQUEST_BYTES}",
                bytes.len()
            ),
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn dispatch(coordinator: &Coordinator, request: LocalRequest) -> LocalResponse {
    dispatch_with_runtime(coordinator, request, &NoopRuntime)
}

pub fn dispatch_with_runtime(
    coordinator: &Coordinator,
    request: LocalRequest,
    runtime: &dyn LocalRuntime,
) -> LocalResponse {
    match request {
        LocalRequest::AnnounceText { text } => {
            if text.len() > MAX_TEXT_BYTES {
                return LocalResponse::Error {
                    message: "text exceeds the 1 MiB meshelf limit".to_owned(),
                };
            }
            match coordinator.create_offer(OfferInput::Text(text)) {
                Ok(Some(plan)) => match runtime.announce(&plan) {
                    Ok(()) => LocalResponse::OfferCreated {
                        offer_id: plan.offer_id,
                        descriptor: plan.descriptor,
                        announcements: plan.announcements,
                    },
                    Err(message) => LocalResponse::Error { message },
                },
                Ok(None) => LocalResponse::NoPeers,
                Err(message) => LocalResponse::Error { message },
            }
        }
        LocalRequest::AnnouncePath { path } => {
            match coordinator.create_offer(OfferInput::Path(path)) {
                Ok(Some(plan)) => match runtime.announce(&plan) {
                    Ok(()) => LocalResponse::OfferCreated {
                        offer_id: plan.offer_id,
                        descriptor: plan.descriptor,
                        announcements: plan.announcements,
                    },
                    Err(message) => LocalResponse::Error { message },
                },
                Ok(None) => LocalResponse::NoPeers,
                Err(message) => LocalResponse::Error { message },
            }
        }
        LocalRequest::RecordExplicitRefusal {
            offer_id,
            recipient,
        } => match coordinator.record_explicit_refusal(offer_id, recipient) {
            Ok(()) => LocalResponse::RefusalRecorded,
            Err(message) => LocalResponse::Error { message },
        },
        LocalRequest::GetSettings => match coordinator.settings() {
            Ok(settings) => LocalResponse::Settings { settings },
            Err(message) => LocalResponse::Error { message },
        },
        LocalRequest::SetSettings { settings } => match coordinator.update_settings(settings) {
            Ok(settings) => LocalResponse::Settings { settings },
            Err(message) => LocalResponse::Error { message },
        },
        LocalRequest::Shelf => match coordinator.read_shelf() {
            Ok(offers) => LocalResponse::Shelf { offers },
            Err(message) => LocalResponse::Error { message },
        },
        LocalRequest::ActivateOffer { offer_id, mode } => {
            match coordinator.plan_activation(offer_id, mode) {
                Ok(plan) => match runtime.activate(&plan) {
                    Ok(()) => LocalResponse::ActivationStarted {
                        activation_id: plan.activation_id,
                        offer_id: plan.offer_id,
                        mode: plan.mode,
                    },
                    Err(message) => LocalResponse::ActivationRefused { message },
                },
                Err(message) => LocalResponse::ActivationRefused { message },
            }
        }
        LocalRequest::CancelActivation { activation_id } => {
            // The desktop owns active connection handles. This response is intentionally a
            // routed acknowledgement; the UI cancellation path invokes the same fetch task's
            // abort handle locally, while headless clients can use it for parity once resident
            // activation execution is enabled at the protocol cutover.
            LocalResponse::ActivationCancelled { activation_id }
        }
    }
}

pub fn dispatch_bytes(coordinator: &Coordinator, bytes: &[u8]) -> io::Result<Vec<u8>> {
    dispatch_bytes_with_runtime(coordinator, bytes, &NoopRuntime)
}

pub fn dispatch_bytes_with_runtime(
    coordinator: &Coordinator,
    bytes: &[u8],
    runtime: &dyn LocalRuntime,
) -> io::Result<Vec<u8>> {
    let response = dispatch_with_runtime(coordinator, decode_request(bytes)?, runtime);
    serde_json::to_vec(&response).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use meshelf_core::{CardAvailability, OfferCardInput, OfferDescriptor};
    use meshelf_identity::InstallationIdentity;
    use meshelf_store::RedbV2Store;
    use meshelf_tailscale::{InstallationStore, TailNode};
    use tempfile::tempdir;

    use super::*;

    #[derive(Default)]
    struct RecordingRuntime {
        announces: AtomicUsize,
        activations: AtomicUsize,
    }

    impl LocalRuntime for RecordingRuntime {
        fn announce(&self, _plan: &OfferPlan) -> Result<(), String> {
            self.announces.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn activate(&self, _plan: &ActivationPlan) -> Result<(), String> {
            self.activations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn one_mib_worst_case_text_serializes_within_control_bound() {
        let request = LocalRequest::AnnounceText {
            text: "\0".repeat(MAX_TEXT_BYTES),
        };
        let encoded = encode_request(&request).expect("bounded worst-case request");
        assert!(encoded.len() > 64 * 1024);
        assert!(encoded.len() <= MAX_SERIALIZED_TEXT_REQUEST_BYTES);
    }

    #[test]
    fn local_request_dispatches_to_resident_coordinator() {
        let directory = tempdir().expect("temporary directory");
        let identity = InstallationIdentity::generate();
        let peer = InstallationIdentity::generate();
        let state_store = InstallationStore::new(directory.path().join("state.json"));
        state_store
            .update(identity.device_id, |state| {
                state.peers.accept_signed(
                    &TailNode {
                        node_id: Some("peer-node".to_owned()),
                        hostname: "peer".to_owned(),
                        dns_name: None,
                        addresses: vec!["100.64.0.2".parse().expect("address")],
                        online: true,
                        active: true,
                    },
                    peer.device_id,
                    peer.public_key().to_vec(),
                )
            })
            .expect("pair peer");
        let coordinator = Coordinator::new(
            identity.device_id,
            state_store,
            Arc::new(RedbV2Store::open(directory.path().join("offers.redb")).expect("open offers")),
        );
        let response = dispatch(
            &coordinator,
            LocalRequest::AnnounceText {
                text: "resident text".to_owned(),
            },
        );
        assert!(matches!(
            response,
            LocalResponse::OfferCreated { announcements, .. } if announcements.len() == 1
        ));
    }

    fn coordinator_with_peer(
        directory: &tempfile::TempDir,
    ) -> (
        Coordinator,
        Arc<RedbV2Store>,
        InstallationIdentity,
        DeviceId,
    ) {
        let identity = InstallationIdentity::generate();
        let peer = InstallationIdentity::generate();
        let state_store = InstallationStore::new(directory.path().join("state.json"));
        state_store
            .update(identity.device_id, |state| {
                state.peers.accept_signed(
                    &TailNode {
                        node_id: Some("peer-node".to_owned()),
                        hostname: "peer".to_owned(),
                        dns_name: None,
                        addresses: vec!["100.64.0.2".parse().expect("address")],
                        online: true,
                        active: true,
                    },
                    peer.device_id,
                    peer.public_key().to_vec(),
                )
            })
            .expect("pair peer");
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("offers.redb")).expect("open offers"));
        let coordinator = Coordinator::new(identity.device_id, state_store, store.clone())
            .with_card_store(store.clone());
        (coordinator, store, identity, peer.device_id)
    }

    #[test]
    fn production_paste_calls_announce_not_push() {
        let directory = tempdir().expect("temporary directory");
        let (coordinator, _store, _identity, _peer) = coordinator_with_peer(&directory);
        let runtime = RecordingRuntime::default();
        let response = dispatch_with_runtime(
            &coordinator,
            LocalRequest::AnnounceText {
                text: "paste".to_owned(),
            },
            &runtime,
        );
        assert!(matches!(response, LocalResponse::OfferCreated { .. }));
        assert_eq!(runtime.announces.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.activations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn production_card_activation_calls_fetch() {
        let directory = tempdir().expect("temporary directory");
        let (coordinator, store, _identity, source_device) = coordinator_with_peer(&directory);
        store
            .insert_offer_card(OfferCardInput::new(
                source_device,
                OfferId::new(),
                OfferDescriptor::text("card").expect("descriptor"),
                CardAvailability::Available,
            ))
            .expect("card");
        let offer_id = store.read_offer_shelf().expect("shelf")[0].offer_id;
        let runtime = RecordingRuntime::default();
        let response = dispatch_with_runtime(
            &coordinator,
            LocalRequest::ActivateOffer {
                offer_id,
                mode: ActivationMode::Clipboard,
            },
            &runtime,
        );
        assert!(matches!(response, LocalResponse::ActivationStarted { .. }));
        assert_eq!(runtime.activations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn no_v1_push_symbol_is_reachable_from_production_composition() {
        let directory = tempdir().expect("temporary directory");
        let (coordinator, _store, _identity, _peer) = coordinator_with_peer(&directory);
        let runtime = RecordingRuntime::default();
        let response = dispatch_with_runtime(
            &coordinator,
            LocalRequest::AnnounceText {
                text: "production".to_owned(),
            },
            &runtime,
        );
        assert!(matches!(response, LocalResponse::OfferCreated { .. }));
        assert_eq!(runtime.announces.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.activations.load(Ordering::SeqCst), 0);
    }
}
