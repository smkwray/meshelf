//! Typed requests handled by the one resident meshelf process.

use std::{io, path::PathBuf};

use meshelf_core::{
    ActivationId, ActivationMode, DeviceId, MAX_CONTROL_REQUEST_BYTES, MAX_TEXT_BYTES,
    OfferCardRecord, OfferDescriptor, OfferId, UserSettings,
};
use serde::{Deserialize, Serialize};

use crate::{
    coordinator::{Coordinator, PeerAnnouncement},
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
    match request {
        LocalRequest::AnnounceText { text } => {
            if text.len() > MAX_TEXT_BYTES {
                return LocalResponse::Error {
                    message: "text exceeds the 1 MiB meshelf limit".to_owned(),
                };
            }
            match coordinator.create_offer(OfferInput::Text(text)) {
                Ok(Some(plan)) => LocalResponse::OfferCreated {
                    offer_id: plan.offer_id,
                    descriptor: plan.descriptor,
                    announcements: plan.announcements,
                },
                Ok(None) => LocalResponse::NoPeers,
                Err(message) => LocalResponse::Error { message },
            }
        }
        LocalRequest::AnnouncePath { path } => {
            match coordinator.create_offer(OfferInput::Path(path)) {
                Ok(Some(plan)) => LocalResponse::OfferCreated {
                    offer_id: plan.offer_id,
                    descriptor: plan.descriptor,
                    announcements: plan.announcements,
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
                Ok(plan) => LocalResponse::ActivationStarted {
                    activation_id: plan.activation_id,
                    offer_id: plan.offer_id,
                    mode: plan.mode,
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
    let response = dispatch(coordinator, decode_request(bytes)?);
    serde_json::to_vec(&response).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use meshelf_identity::InstallationIdentity;
    use meshelf_store::RedbV2Store;
    use meshelf_tailscale::{InstallationStore, TailNode};
    use tempfile::tempdir;

    use super::*;

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
}
