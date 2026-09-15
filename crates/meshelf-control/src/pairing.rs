//! `meshelfctl pair --peer X`: the standalone desktop side of one pairing.
//!
//! Pairing runs without a resident and without the local-control channel. A person has to compare
//! a six-digit code on two screens, which can take longer than the control client's five-second
//! read timeout, and the desktop must be free to record trust and finish the exchange while they
//! do. So this opens its own connection to the phone and drives the exchange to its end.
//!
//! Discovery is only how the phone's address is found; it is never authorization. The phone is not
//! trusted yet, so it is not in the trust records, and Tailscale membership alone admits nothing:
//! the code the person compares is what authenticates both keys.
//!
//! A rerun resumes rather than re-pairing. If this desktop already holds a paired record for the
//! peer, the only thing that can be missing is the phone's confirmation that it recorded this
//! desktop, so the desktop resends its commitment instead of showing a new code (A12). A phone
//! that already finished refuses that resume; the desktop's own trust is unaffected, and the
//! pairing is complete on both sides regardless.

use std::time::Duration;

use meshelf_identity::InstallationIdentity;
use meshelf_net::{DesktopPairingFailure, DesktopPairingRequest, PeerClient};
use meshelf_protocol::pairing::{PairingCandidate, PairingResult};
use meshelf_tailscale::{
    CliPeerDiscovery, InstallationStore, PeerDiscovery, PeerNetworkBinding, TailNode,
};

use crate::MESHELF_PORT;

/// A pairing exchange is bounded by the protocol's own window; these bound one connection's I/O.
const PAIR_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Long enough for a person to read two screens and decide, short enough that a dead peer is not
/// waited on forever. The protocol's inactivity bound applies within it.
const PAIR_IO_TIMEOUT: Duration = Duration::from_secs(150);

/// Everything one `pair` invocation needs. The caller supplies the discovery source so a test can
/// pair against a local listener without a `tailscale` binary.
pub struct PairInput<'a> {
    /// Device id, Tailscale hostname, or Tailscale node id.
    pub peer: &'a str,
    pub identity: InstallationIdentity,
    pub device_name: String,
    pub store: InstallationStore,
    pub discovery: &'a dyn PeerDiscovery,
    /// Shown to the person so they can compare it with the phone's screen.
    pub on_candidate: &'a (dyn Fn(&PairingCandidate) + Send + Sync),
}

/// How one pairing ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairOutcome {
    Paired {
        hostname: String,
        device_id: meshelf_core::DeviceId,
    },
    /// The peer could not be found or could not be dialled; nothing was attempted.
    Unresolved { detail: String },
    Failed {
        result: PairingResult,
        /// This desktop recorded the phone, but the phone never confirmed it recorded this
        /// desktop. Trust is one-sided until a resume completes it; a capture cannot use it.
        trust_recorded: bool,
        detail: String,
    },
}

impl PairOutcome {
    /// The process exit code. This is the only place pairing's codes are decided.
    ///
    /// `2` an invalid or unknown peer, `3` a refusal by the phone or its window, `4` a protocol or
    /// local failure, `5` one-sided trust: the desktop committed and never heard back, which a
    /// rerun inside the reconciliation allowance completes without a new code.
    ///
    /// `timeout` is a refusal rather than a protocol failure: nobody picked the phone up, which is
    /// the same class of answer as a decline. `identity_changed` is also a refusal, not a bad
    /// argument: the peer named is real and known, and it is being refused on purpose.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Paired { .. } => 0,
            Self::Unresolved { .. } => 2,
            Self::Failed {
                trust_recorded: true,
                ..
            } => 5,
            Self::Failed { result, .. } => match result {
                PairingResult::Declined
                | PairingResult::WindowClosed
                | PairingResult::Timeout
                | PairingResult::Busy
                | PairingResult::RateLimited
                | PairingResult::IdentityChanged => 3,
                PairingResult::Invalid => 2,
                // `Paired` cannot reach here; a failure never carries it.
                PairingResult::Failed | PairingResult::Paired => 4,
            },
        }
    }

    /// The reported word: an A11 pairing result, or `unknown_peer` when nothing was attempted.
    #[must_use]
    pub fn result_word(&self) -> &'static str {
        match self {
            Self::Paired { .. } => PairingResult::Paired.as_str(),
            Self::Unresolved { .. } => "unknown_peer",
            Self::Failed { result, .. } => result.as_str(),
        }
    }
}

/// Runs one pairing to its end, blocking the calling thread.
pub fn pair_with_peer(input: PairInput<'_>) -> PairOutcome {
    let node = match resolve_pairing_node(input.discovery, input.peer) {
        Ok(node) => node,
        Err(detail) => return PairOutcome::Unresolved { detail },
    };
    let Some(address) = meshelf_net::select_discovered_socket(&node.addresses, MESHELF_PORT) else {
        return PairOutcome::Unresolved {
            detail: format!("peer {:?} has no usable Tailscale address", node.hostname),
        };
    };
    let binding = PeerNetworkBinding::TailscaleNode {
        node_id: node.node_id.clone().unwrap_or_default(),
        addresses: node.addresses.clone(),
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return PairOutcome::Failed {
                result: PairingResult::Failed,
                trust_recorded: false,
                detail: format!("pairing runtime unavailable: {error}"),
            };
        }
    };
    let client = PeerClient::with_timeouts(PAIR_CONNECT_TIMEOUT, PAIR_IO_TIMEOUT);

    // A record this desktop already holds can only be missing the phone's confirmation, so the
    // commitment is resent rather than a second code being shown for a transcript already approved.
    let existing = this_peer_already_paired(&input.store, &input.identity, &node);
    if let Some(paired) = existing {
        let hostname = node.hostname.clone();
        let device_id = paired.peer.device_id;
        return match runtime.block_on(client.pair_resume(
            address,
            &input.identity,
            &input.device_name,
            &paired,
        )) {
            Ok(()) => PairOutcome::Paired {
                hostname,
                device_id,
            },
            Err(failure) => failed(failure),
        };
    }

    let request = DesktopPairingRequest {
        identity: input.identity.clone(),
        device_name: input.device_name.clone(),
        store: input.store,
        phone_binding: binding,
    };
    match runtime.block_on(client.pair_initiate(address, &request, input.on_candidate)) {
        Ok(peer) => PairOutcome::Paired {
            hostname: node.hostname,
            device_id: peer.device_id,
        },
        Err(failure) => failed(failure),
    }
}

fn failed(failure: DesktopPairingFailure) -> PairOutcome {
    PairOutcome::Failed {
        result: failure.result,
        trust_recorded: failure.trust_recorded,
        detail: failure.detail,
    }
}

/// The paired record this desktop already holds for `node`, if the same endpoint is bound.
///
/// Matching on the endpoint, not on the name, is deliberate: a resume must reach the same node the
/// approval was given at.
fn this_peer_already_paired(
    store: &InstallationStore,
    identity: &InstallationIdentity,
    node: &TailNode,
) -> Option<meshelf_tailscale::PairedPeer> {
    let state = store.load_for_identity(identity.device_id).ok()?;
    state
        .peers
        .peers()
        .iter()
        .find(|peer| {
            peer.node_id() == node.node_id.as_deref()
                || node.addresses.iter().any(|address| peer.admits(*address))
        })
        .and_then(meshelf_tailscale::TrustedPeer::paired)
}

/// Finds the phone through discovery by device-independent name. Only a node with a node id can be
/// paired, because a paired record's binding must name one.
fn resolve_pairing_node(discovery: &dyn PeerDiscovery, selector: &str) -> Result<TailNode, String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err("pair peer selector is empty".to_owned());
    }
    let folded = selector.to_ascii_lowercase();
    let status = discovery
        .refresh()
        .map_err(|error| format!("could not read Tailscale status: {error}"))?;
    let node = status
        .peers
        .into_iter()
        .find(|node| {
            node.hostname.to_ascii_lowercase() == folded
                || node
                    .dns_name
                    .as_deref()
                    .is_some_and(|name| name.to_ascii_lowercase().trim_end_matches('.') == folded)
                || node
                    .node_id
                    .as_deref()
                    .is_some_and(|node_id| node_id.to_ascii_lowercase() == folded)
                || node
                    .addresses
                    .iter()
                    .any(|address| address.to_string() == selector)
        })
        .ok_or_else(|| format!("Tailscale knows no peer {selector:?}"))?;
    if node
        .node_id
        .as_deref()
        .is_none_or(|id| id.trim().is_empty())
    {
        return Err(format!(
            "peer {:?} has no Tailscale node id, so it cannot be paired",
            node.hostname
        ));
    }
    Ok(node)
}

/// The Tailscale CLI, when one is installed. Pairing needs discovery to find the phone's address.
pub fn cli_discovery() -> Result<CliPeerDiscovery, String> {
    CliPeerDiscovery::discover().map_err(|error| format!("Tailscale is unavailable: {error}"))
}

#[cfg(test)]
mod tests {
    use meshelf_tailscale::{DiscoveryError, TailStatus};
    use tempfile::tempdir;

    use super::*;

    struct StubDiscovery {
        peers: Vec<TailNode>,
    }

    impl PeerDiscovery for StubDiscovery {
        fn refresh(&self) -> Result<TailStatus, DiscoveryError> {
            Ok(TailStatus {
                backend_state: "Running".to_owned(),
                self_node: node("cedar", Some("desktop-node"), "100.64.0.1"),
                peers: self.peers.clone(),
            })
        }
    }

    fn node(hostname: &str, node_id: Option<&str>, address: &str) -> TailNode {
        TailNode {
            node_id: node_id.map(ToOwned::to_owned),
            hostname: hostname.to_owned(),
            dns_name: Some(format!("{hostname}.example.invalid.")),
            addresses: vec![address.parse().expect("address")],
            online: true,
            active: true,
        }
    }

    fn failure(result: PairingResult, trust_recorded: bool) -> PairOutcome {
        PairOutcome::Failed {
            result,
            trust_recorded,
            detail: String::new(),
        }
    }

    #[test]
    fn every_pairing_result_has_exactly_one_exit_code() {
        assert_eq!(
            PairOutcome::Paired {
                hostname: "amber".to_owned(),
                device_id: meshelf_core::DeviceId::new(),
            }
            .exit_code(),
            0
        );
        assert_eq!(
            PairOutcome::Unresolved {
                detail: String::new()
            }
            .exit_code(),
            2
        );
        assert_eq!(failure(PairingResult::Invalid, false).exit_code(), 2);
        for refusal in [
            PairingResult::Declined,
            PairingResult::WindowClosed,
            PairingResult::Timeout,
            PairingResult::Busy,
            PairingResult::RateLimited,
            PairingResult::IdentityChanged,
        ] {
            assert_eq!(
                failure(refusal, false).exit_code(),
                3,
                "{refusal} is a refusal, not a bad argument and not a protocol failure"
            );
        }
        assert_eq!(failure(PairingResult::Failed, false).exit_code(), 4);

        // One-sided trust outranks the reason: the desktop committed and never heard back, so a
        // rerun inside the allowance is what finishes it.
        for result in PairingResult::ALL {
            assert_eq!(
                failure(result, true).exit_code(),
                5,
                "{result} with trust recorded must report one-sided trust"
            );
        }
    }

    #[test]
    fn a_peer_tailscale_does_not_know_is_refused_before_anything_is_dialled() {
        let directory = tempdir().expect("temporary directory");
        let identity = InstallationIdentity::generate();
        let store = InstallationStore::new(directory.path().join("state.json"));
        let discovery = StubDiscovery {
            peers: vec![node("other", Some("other-node"), "100.64.0.9")],
        };
        let outcome = pair_with_peer(PairInput {
            peer: "amber",
            identity: identity.clone(),
            device_name: "CEDAR".to_owned(),
            store: store.clone(),
            discovery: &discovery,
            on_candidate: &|candidate| panic!("no code may be shown: {candidate:?}"),
        });
        assert!(matches!(outcome, PairOutcome::Unresolved { .. }));
        assert_eq!(outcome.exit_code(), 2);
        assert_eq!(outcome.result_word(), "unknown_peer");
        assert!(
            store
                .load_for_identity(identity.device_id)
                .expect("state")
                .peers
                .peers()
                .is_empty(),
            "a refused pairing records no trust"
        );
    }

    #[test]
    fn a_node_without_a_node_id_cannot_be_paired() {
        // A paired record's binding must name the node it was approved at, so a node Tailscale
        // reports without an id cannot be bound and must not be paired instead of guessing.
        let directory = tempdir().expect("temporary directory");
        let discovery = StubDiscovery {
            peers: vec![node("amber", None, "100.64.0.9")],
        };
        let outcome = pair_with_peer(PairInput {
            peer: "amber",
            identity: InstallationIdentity::generate(),
            device_name: "CEDAR".to_owned(),
            store: InstallationStore::new(directory.path().join("state.json")),
            discovery: &discovery,
            on_candidate: &|candidate| panic!("no code may be shown: {candidate:?}"),
        });
        assert!(matches!(outcome, PairOutcome::Unresolved { .. }));
        assert_eq!(outcome.exit_code(), 2);
    }

    #[test]
    fn a_phone_that_does_not_answer_records_no_trust_and_shows_no_code() {
        // Loopback with nothing listening: the desktop's own listener binds a Tailscale address,
        // so this is a peer that is simply not there.
        let directory = tempdir().expect("temporary directory");
        let identity = InstallationIdentity::generate();
        let store = InstallationStore::new(directory.path().join("state.json"));
        let discovery = StubDiscovery {
            peers: vec![node("amber", Some("phone-node"), "127.0.0.1")],
        };
        let outcome = pair_with_peer(PairInput {
            peer: "amber",
            identity: identity.clone(),
            device_name: "CEDAR".to_owned(),
            store: store.clone(),
            discovery: &discovery,
            on_candidate: &|candidate| panic!("no code may be shown: {candidate:?}"),
        });
        assert_eq!(
            outcome,
            PairOutcome::Failed {
                result: PairingResult::Failed,
                trust_recorded: false,
                detail: match &outcome {
                    PairOutcome::Failed { detail, .. } => detail.clone(),
                    other => panic!("expected a failure, got {other:?}"),
                },
            }
        );
        assert_eq!(outcome.exit_code(), 4);
        assert!(
            store
                .load_for_identity(identity.device_id)
                .expect("state")
                .peers
                .peers()
                .is_empty(),
            "a pairing that never completed records no trust"
        );
    }

    #[test]
    fn a_peer_is_found_by_hostname_dns_name_node_id_or_address() {
        let discovery = StubDiscovery {
            peers: vec![node("amber", Some("phone-node"), "100.64.0.9")],
        };
        for selector in [
            "amber",
            "AMBER",
            "amber.example.invalid",
            "phone-node",
            "100.64.0.9",
        ] {
            let node = resolve_pairing_node(&discovery, selector)
                .unwrap_or_else(|error| panic!("selector {selector:?} did not resolve: {error}"));
            assert_eq!(node.hostname, "amber");
        }
        assert!(resolve_pairing_node(&discovery, "  ").is_err());
        assert!(resolve_pairing_node(&discovery, "cedar").is_err());
    }
}
