//! Shared discovery, pairing, offer planning, and resident control for meshelf.

pub mod coordinator;
pub mod local_control;
pub mod offer_source;

pub use coordinator::{
    ActivationPlan, Coordinator, NotifyingOfferCardStore, OfferPlan, PeerAnnouncement,
    ShelfChangeNotifier,
};
pub use offer_source::{OfferInput, PreparedOfferSource, SourcePreparationError};

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use meshelf_identity::InstallationIdentity;
use meshelf_net::PeerClient;
use meshelf_protocol::{
    CAP_OFFER_PULL_V2, ClientHello, OfferAckCode, ServerHello, V2_PROTOCOL_VERSION,
};
use meshelf_tailscale::{
    CliPeerDiscovery, InstallationState, InstallationStore, PeerDiscovery, SshBootstrap,
    SshBootstrapRequest, TailNode, TailStatus,
};
use tokio::{runtime::Builder, task::JoinSet};

pub const MESHELF_PORT: u16 = 45_832;

type ProbeFuture = Pin<Box<dyn Future<Output = Result<ServerHello, ()>> + Send>>;

trait PeerProbe: Send + Sync + 'static {
    fn probe(&self, address: SocketAddr) -> ProbeFuture;
}

impl PeerProbe for PeerClient {
    fn probe(&self, address: SocketAddr) -> ProbeFuture {
        let client = self.clone();
        Box::pin(async move { client.probe(address).await.map_err(|_| ()) })
    }
}

fn operation_runtime(label: &str) -> Result<tokio::runtime::Runtime, String> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("{label} runtime unavailable: {error}"))
}

#[derive(Debug, Clone)]
pub struct PendingPeer {
    pub node: TailNode,
    pub server: ServerHello,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerView {
    pub name: String,
    pub online: bool,
    pub approval_available: bool,
    pub status: String,
    pub reachable_names: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSendReport {
    pub stored_on: Vec<String>,
    pub unavailable: Vec<String>,
}

impl MeshSendReport {
    #[must_use]
    pub fn status(&self) -> String {
        match (self.stored_on.len(), self.unavailable.len()) {
            (0, 0) => "No paired devices accepted the offer".to_owned(),
            (stored, 0) => format!(
                "Added to {stored} device{}",
                if stored == 1 { "" } else { "s" }
            ),
            (stored, _) => format!(
                "Added to {stored} device{}; unavailable: {}",
                if stored == 1 { "" } else { "s" },
                self.unavailable.join(", ")
            ),
        }
    }
}

/// Fan out one durable v2 offer plan. A failed direct connection is reported immediately; it is
/// never queued for a later clipboard application.
pub fn announce_offer_plan(
    state_path: &Path,
    identity: &InstallationIdentity,
    device_name: &str,
    plan: &OfferPlan,
) -> Result<MeshSendReport, String> {
    let state = InstallationStore::new(state_path.to_owned())
        .load_for_identity(identity.device_id)
        .map_err(|error| format!("could not load meshelf state: {error}"))?;
    let peers = state.peers.peers().to_vec();
    let identity = identity.clone();
    let device_name = device_name.to_owned();
    let announcements = plan.announcements.clone();
    let runtime = operation_runtime("announce")?;
    runtime.block_on(async move {
        let mut tasks = JoinSet::new();
        for item in announcements {
            let identity = identity.clone();
            let device_name = device_name.clone();
            let peer = peers
                .iter()
                .find(|peer| peer.device_id == item.device_id)
                .cloned();
            tasks.spawn(async move {
                let hostname = item.hostname;
                let Some(peer) = peer else {
                    return (hostname, false);
                };
                let Some(address) = peer
                    .addresses
                    .iter()
                    .copied()
                    .find(|address| address.is_ipv4())
                    .or_else(|| peer.addresses.first().copied())
                else {
                    return (hostname, false);
                };
                let hello = ClientHello::signed_v2(
                    identity.device_id,
                    device_name,
                    item.announcement.offer_id.to_string(),
                    &identity,
                );
                let stored = PeerClient::default()
                    .announce_offer_v2(
                        SocketAddr::new(address, MESHELF_PORT),
                        hello,
                        item.announcement,
                        &peer.public_key,
                    )
                    .await
                    .is_ok_and(|ack| {
                        matches!(ack.code, OfferAckCode::Stored | OfferAckCode::Duplicate)
                    });
                (hostname, stored)
            });
        }
        let mut report = MeshSendReport {
            stored_on: Vec::new(),
            unavailable: Vec::new(),
        };
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((hostname, true)) => report.stored_on.push(hostname),
                Ok((hostname, false)) => report.unavailable.push(hostname),
                Err(error) => report.unavailable.push(format!("worker ({error})")),
            }
        }
        report.stored_on.sort();
        report.unavailable.sort();
        Ok(report)
    })
}

pub struct Controller {
    pub state_path: PathBuf,
    pub identity: InstallationIdentity,
    pub installation: InstallationState,
    pub device_name: String,
    discovery: Option<Arc<dyn PeerDiscovery>>,
    probe: Arc<dyn PeerProbe>,
    pub last_status: Option<TailStatus>,
    pub reachable_peers: HashMap<meshelf_core::DeviceId, String>,
    pub pending: Option<PendingPeer>,
    pub selected_device: Option<meshelf_core::DeviceId>,
}

impl Controller {
    pub fn load(state_path: PathBuf, device_name: String) -> Result<Self, String> {
        let identity = InstallationIdentity::load_or_create()
            .map_err(|error| format!("could not load meshelf installation identity: {error}"))?;
        let installation = InstallationStore::new(state_path.clone())
            .load_for_identity(identity.device_id)
            .map_err(|error| format!("could not load meshelf state: {error}"))?;
        Ok(Self {
            state_path,
            identity,
            installation,
            device_name,
            discovery: CliPeerDiscovery::discover()
                .ok()
                .map(|discovery| Arc::new(discovery) as Arc<dyn PeerDiscovery>),
            probe: Arc::new(PeerClient::with_timeouts(
                Duration::from_secs(1),
                Duration::from_secs(2),
            )),
            last_status: None,
            reachable_peers: HashMap::new(),
            pending: None,
            selected_device: None,
        })
    }

    pub fn refresh(&mut self) -> Result<PeerView, String> {
        self.reachable_peers.clear();
        let discovery = self
            .discovery
            .as_ref()
            .ok_or_else(|| "Tailscale was not found; install Tailscale and retry".to_owned())?;
        let status = discovery
            .refresh()
            .map_err(|error| format!("Tailscale discovery failed: {error}"))?;
        self.device_name.clone_from(&status.self_node.hostname);
        self.installation = InstallationStore::new(self.state_path.clone())
            .update(self.identity.device_id, |state| {
                state.peers.refresh_addresses(&status);
                Ok(())
            })
            .map_err(|error| format!("could not save meshelf state: {error}"))?;
        self.pending = None;
        self.selected_device = None;

        let runtime = operation_runtime("probe")?;
        let probe = self.probe.clone();
        let candidates = runtime.block_on(async {
            let mut tasks = JoinSet::new();
            for node in status.online_peers().cloned() {
                for address in node.addresses.iter().copied() {
                    let probe = probe.clone();
                    let node = node.clone();
                    tasks.spawn(async move {
                        probe
                            .probe(SocketAddr::new(address, MESHELF_PORT))
                            .await
                            .ok()
                            .map(|server| (node, server))
                    });
                }
            }
            let mut candidates = Vec::new();
            while let Some(result) = tasks.join_next().await {
                if let Ok(Some(candidate)) = result {
                    candidates.push(candidate);
                }
            }
            candidates
        });
        let paired = self
            .installation
            .peers
            .peers()
            .iter()
            .map(|peer| peer.device_id)
            .collect::<HashSet<_>>();
        self.reachable_peers = candidates
            .iter()
            .filter(|(_, server)| paired.contains(&server.device_id))
            .map(|(node, server)| (server.device_id, node.hostname.clone()))
            .collect();
        for (node, server) in candidates {
            self.accept_discovered(node, server)?;
        }
        self.last_status = Some(status);
        Ok(self.view())
    }

    fn accept_discovered(&mut self, node: TailNode, server: ServerHello) -> Result<(), String> {
        if server.protocol_version != V2_PROTOCOL_VERSION
            || !server
                .capabilities
                .iter()
                .any(|capability| capability == CAP_OFFER_PULL_V2)
            || !server.has_valid_signature()
        {
            return Ok(());
        }
        self.installation = InstallationStore::new(self.state_path.clone())
            .update(self.identity.device_id, |state| {
                state
                    .peers
                    .accept_signed(&node, server.device_id, server.public_key.clone())
            })
            .map_err(|error| format!("could not pair discovered meshelf device: {error}"))?;
        self.selected_device = Some(server.device_id);
        Ok(())
    }

    pub fn approve_pending(&mut self) -> Result<PeerView, String> {
        let pending = self
            .pending
            .clone()
            .ok_or_else(|| "no discovered meshelf device is waiting for approval".to_owned())?;
        let local_status = self
            .last_status
            .as_ref()
            .ok_or_else(|| "local Tailscale identity is unavailable".to_owned())?;
        let node_id = local_status
            .self_node
            .node_id
            .clone()
            .ok_or_else(|| "local Tailscale node has no stable node ID".to_owned())?;
        let bootstrap = SshBootstrap::discover(&pending.node).ok_or_else(|| {
            "no configured SSH route was found for this Tailscale peer".to_owned()
        })?;
        let response = bootstrap
            .authorize(&SshBootstrapRequest::signed(
                self.identity.device_id,
                node_id,
                local_status.self_node.hostname.clone(),
                local_status.self_node.addresses.clone(),
                &self.identity,
            ))
            .map_err(|error| format!("one-side SSH bootstrap failed: {error}"))?;
        if response.device_id != pending.server.device_id
            || response.node_id != pending.node.node_id.clone().unwrap_or_default()
            || response.public_key != pending.server.public_key
            || !response.has_valid_signature()
        {
            return Err("SSH bootstrap identity mismatch".to_owned());
        }
        let device_id = pending.server.device_id;
        let response_node = response_to_tail_node(&response);
        let key = response.public_key.clone();
        self.installation = InstallationStore::new(self.state_path.clone())
            .update(self.identity.device_id, |state| {
                state.peers.accept_signed(&response_node, device_id, key)
            })
            .map_err(|error| format!("could not save reciprocal peer approval: {error}"))?;
        self.selected_device = Some(device_id);
        self.pending = None;
        Ok(self.view())
    }

    pub fn select_peer(&mut self, selector: Option<&str>) -> Result<(), String> {
        if let Some(selector) = selector {
            if let Ok(device_id) = selector.parse::<meshelf_core::DeviceId>()
                && self.installation.peers.by_device_id(device_id).is_some()
            {
                self.selected_device = Some(device_id);
                return Ok(());
            }
            if let Some(peer) = self
                .installation
                .peers
                .peers()
                .iter()
                .find(|peer| peer.hostname.eq_ignore_ascii_case(selector))
            {
                self.selected_device = Some(peer.device_id);
                return Ok(());
            }
            return Err(format!("trusted meshelf peer not found: {selector}"));
        }
        if self.selected_device.is_none() {
            self.selected_device = self
                .installation
                .peers
                .peers()
                .first()
                .map(|peer| peer.device_id);
        }
        Ok(())
    }

    #[must_use]
    pub fn view(&self) -> PeerView {
        let names = self.reachable_paired_names();
        let checked = self.last_status.is_some();
        let status = if !checked {
            "Reachability not checked yet · refresh to find meshelf devices".to_owned()
        } else if names.is_empty() && self.installation.peers.peers().is_empty() {
            "No paired meshelf devices · refresh to discover devices".to_owned()
        } else if names.is_empty() {
            "No paired meshelf devices are reachable · refresh to retry".to_owned()
        } else if names.len() == 1 {
            "1 device reachable · paste text or copied files".to_owned()
        } else {
            format!(
                "{} devices reachable · paste text or copied files",
                names.len()
            )
        };
        let selected_name = self
            .selected_device
            .and_then(|id| self.reachable_peers.get(&id).cloned())
            .or_else(|| names.first().cloned());
        let reachable_names = if names.is_empty() {
            if checked {
                "No meshelf devices are reachable".to_owned()
            } else {
                "Reachability not checked yet".to_owned()
            }
        } else {
            names.join("\n")
        };
        PeerView {
            name: selected_name.unwrap_or_else(|| "Not configured".to_owned()),
            online: !names.is_empty(),
            approval_available: self.pending.is_some(),
            status,
            reachable_names,
        }
    }

    fn reachable_paired_names(&self) -> Vec<String> {
        let mut names = self
            .installation
            .peers
            .peers()
            .iter()
            .filter_map(|peer| self.reachable_peers.get(&peer.device_id).cloned())
            .collect::<Vec<_>>();
        names.sort_unstable_by_key(|name| name.to_ascii_lowercase());
        names
    }
}

#[must_use]
pub fn response_to_tail_node(response: &meshelf_tailscale::SshBootstrapResponse) -> TailNode {
    TailNode {
        node_id: Some(response.node_id.clone()),
        hostname: response.hostname.clone(),
        dns_name: None,
        addresses: response.addresses.clone(),
        online: true,
        active: true,
    }
}

pub fn state_path(config_dir: &Path) -> PathBuf {
    config_dir.join("state.json")
}

#[cfg(test)]
mod restored_control_tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use meshelf_core::DeviceId;
    use meshelf_identity::InstallationIdentity;
    use meshelf_protocol::{CAP_OFFER_PULL_V2, V2_PROTOCOL_VERSION};
    use meshelf_tailscale::DiscoveryError;
    use tempfile::tempdir;

    use super::*;

    #[derive(Debug, Clone)]
    struct FakeDiscovery {
        status: TailStatus,
    }

    impl PeerDiscovery for FakeDiscovery {
        fn refresh(&self) -> Result<TailStatus, DiscoveryError> {
            Ok(self.status.clone())
        }
    }

    #[derive(Debug, Clone, Default)]
    struct FakeProbe {
        answers: HashMap<SocketAddr, ServerHello>,
    }

    impl PeerProbe for FakeProbe {
        fn probe(&self, address: SocketAddr) -> ProbeFuture {
            let answer = self.answers.get(&address).cloned();
            Box::pin(async move { answer.ok_or(()) })
        }
    }

    fn test_controller() -> (tempfile::TempDir, Controller) {
        let directory = tempdir().expect("temporary directory");
        let identity = InstallationIdentity::generate();
        let installation = InstallationState {
            device_id: identity.device_id,
            peers: Default::default(),
            settings: Default::default(),
        };
        let controller = Controller {
            state_path: directory.path().join("state.json"),
            identity,
            installation,
            device_name: "BMST".to_owned(),
            discovery: None,
            probe: Arc::new(FakeProbe::default()),
            last_status: None,
            reachable_peers: HashMap::new(),
            pending: None,
            selected_device: None,
        };
        (directory, controller)
    }

    fn pair_test_peer(controller: &mut Controller, hostname: &str) -> DeviceId {
        let identity = InstallationIdentity::generate();
        pair_test_peer_with_identity(
            controller,
            hostname,
            &format!("node-{hostname}"),
            None,
            &identity,
        )
    }

    fn pair_test_peer_with_identity(
        controller: &mut Controller,
        hostname: &str,
        node_id: &str,
        address: Option<IpAddr>,
        identity: &InstallationIdentity,
    ) -> DeviceId {
        let device_id = identity.device_id;
        controller
            .installation
            .peers
            .accept_signed(
                &TailNode {
                    node_id: Some(node_id.to_owned()),
                    hostname: hostname.to_owned(),
                    dns_name: None,
                    addresses: address.into_iter().collect(),
                    online: true,
                    active: true,
                },
                device_id,
                identity.public_key().to_vec(),
            )
            .expect("pair test peer");
        device_id
    }

    fn test_tail_node(node_id: &str, hostname: &str, address: IpAddr) -> TailNode {
        TailNode {
            node_id: Some(node_id.to_owned()),
            hostname: hostname.to_owned(),
            dns_name: None,
            addresses: vec![address],
            online: true,
            active: true,
        }
    }

    fn test_tail_status(peers: Vec<TailNode>) -> TailStatus {
        TailStatus {
            backend_state: "Running".to_owned(),
            self_node: TailNode {
                node_id: Some("node-bmst".to_owned()),
                hostname: "BMST".to_owned(),
                dns_name: None,
                addresses: Vec::new(),
                online: true,
                active: true,
            },
            peers,
        }
    }

    fn signed_probe_answer(identity: &InstallationIdentity, hostname: &str) -> ServerHello {
        ServerHello::signed(
            V2_PROTOCOL_VERSION,
            identity.device_id,
            hostname.to_owned(),
            false,
            None,
            vec![CAP_OFFER_PULL_V2.to_owned()],
            identity,
        )
    }

    fn configure_fake_refresh(
        controller: &mut Controller,
        status: TailStatus,
        answers: HashMap<SocketAddr, ServerHello>,
    ) {
        controller
            .installation
            .save(&controller.state_path)
            .expect("save test state");
        controller.discovery = Some(Arc::new(FakeDiscovery { status }));
        controller.probe = Arc::new(FakeProbe { answers });
    }

    fn mark_refresh_complete(controller: &mut Controller) {
        controller.last_status = Some(test_tail_status(Vec::new()));
    }

    #[test]
    fn valid_signed_tailscale_discovery_pairs_without_ssh() {
        let (_directory, mut controller) = test_controller();
        let peer_identity = InstallationIdentity::generate();
        let peer_id = peer_identity.device_id;
        let node = TailNode {
            node_id: Some("node-bzot".to_owned()),
            hostname: "BZOT".to_owned(),
            dns_name: None,
            addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 90, 118, 120))],
            online: true,
            active: false,
        };
        let hello = ServerHello::signed(
            V2_PROTOCOL_VERSION,
            peer_id,
            "BZOT".to_owned(),
            false,
            Some("not paired yet".to_owned()),
            vec![CAP_OFFER_PULL_V2.to_owned()],
            &peer_identity,
        );

        controller
            .accept_discovered(node, hello)
            .expect("signed discovery auto-pairs");

        let paired = controller
            .installation
            .peers
            .by_device_id(peer_id)
            .expect("peer stored automatically");
        assert_eq!(paired.hostname, "BZOT");
        assert_eq!(paired.public_key, peer_identity.public_key());
        assert_eq!(controller.selected_device, Some(peer_id));
    }

    #[test]
    fn stale_resident_controller_preserves_ssh_bootstrap() {
        let (_directory, mut controller) = test_controller();
        let peer_identity = InstallationIdentity::generate();
        let peer_id = pair_test_peer_with_identity(
            &mut controller,
            "BZOT",
            "node-bzot",
            Some(IpAddr::V4(Ipv4Addr::new(100, 90, 118, 120))),
            &peer_identity,
        );
        let status = test_tail_status(vec![TailNode {
            node_id: Some("node-bzot".to_owned()),
            hostname: "BZOT".to_owned(),
            dns_name: None,
            addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 90, 118, 120))],
            online: true,
            active: false,
        }]);
        configure_fake_refresh(&mut controller, status, HashMap::new());

        controller.refresh().expect("resident refresh");

        let paired = controller
            .installation
            .peers
            .by_device_id(peer_id)
            .expect("external peer remains paired");
        assert_eq!(paired.hostname, "BZOT");
        assert_eq!(paired.public_key, peer_identity.public_key());
    }

    #[test]
    fn status_counts_only_reachable_peers_not_paired_ones() {
        let (_directory, mut controller) = test_controller();
        let reachable = pair_test_peer(&mut controller, "BZOT");
        pair_test_peer(&mut controller, "BMBA");
        controller
            .reachable_peers
            .insert(reachable, "BZOT".to_owned());
        controller.selected_device = Some(reachable);
        mark_refresh_complete(&mut controller);

        let view = controller.view();

        assert_eq!(
            view.status,
            "1 device reachable · paste text or copied files"
        );
        assert_eq!(view.reachable_names, "BZOT");
    }

    #[test]
    fn status_before_first_refresh_does_not_claim_readiness() {
        let (_directory, mut controller) = test_controller();
        pair_test_peer(&mut controller, "BZOT");

        let view = controller.view();

        assert_eq!(
            view.status,
            "Reachability not checked yet · refresh to find meshelf devices"
        );
        assert_eq!(view.reachable_names, "Reachability not checked yet");
        assert!(!view.status.contains("ready"));
    }

    #[test]
    fn status_with_paired_but_unreachable_peers_says_none_are_reachable() {
        let (_directory, mut controller) = test_controller();
        pair_test_peer(&mut controller, "BMBA");
        mark_refresh_complete(&mut controller);

        let view = controller.view();

        assert_eq!(
            view.status,
            "No paired meshelf devices are reachable · refresh to retry"
        );
        assert_eq!(view.reachable_names, "No meshelf devices are reachable");
    }

    #[test]
    fn status_singular_and_plural_and_zero_all_read_correctly() {
        let (_zero_directory, mut zero) = test_controller();
        mark_refresh_complete(&mut zero);
        assert_eq!(
            zero.view().status,
            "No paired meshelf devices · refresh to discover devices"
        );

        let (_one_directory, mut one) = test_controller();
        let one_id = pair_test_peer(&mut one, "BZOT");
        one.reachable_peers.insert(one_id, "BZOT".to_owned());
        mark_refresh_complete(&mut one);
        assert_eq!(
            one.view().status,
            "1 device reachable · paste text or copied files"
        );

        let (_many_directory, mut many) = test_controller();
        let first = pair_test_peer(&mut many, "BMBA");
        let second = pair_test_peer(&mut many, "BZOT");
        many.reachable_peers.insert(first, "BMBA".to_owned());
        many.reachable_peers.insert(second, "BZOT".to_owned());
        mark_refresh_complete(&mut many);
        assert_eq!(
            many.view().status,
            "2 devices reachable · paste text or copied files"
        );
    }

    #[test]
    fn reachable_list_names_only_peers_that_answered_the_probe() {
        let (_directory, mut controller) = test_controller();
        let bmba = pair_test_peer(&mut controller, "BMBA");
        let bzot = pair_test_peer(&mut controller, "BZOT");
        pair_test_peer(&mut controller, "BZDROPPED");
        controller.reachable_peers.insert(bmba, "BMBA".to_owned());
        controller.reachable_peers.insert(bzot, "BZOT".to_owned());
        mark_refresh_complete(&mut controller);

        let view = controller.view();

        assert_eq!(view.reachable_names, "BMBA\nBZOT");
        assert!(!view.reachable_names.contains("BZDROPPED"));
    }

    #[test]
    fn refresh_inserts_only_peers_that_answered_the_probe() {
        let (_directory, mut controller) = test_controller();
        let bzot_identity = InstallationIdentity::generate();
        let bmba_identity = InstallationIdentity::generate();
        let bzot_address = IpAddr::V4(Ipv4Addr::new(100, 90, 118, 120));
        let bmba_address = IpAddr::V4(Ipv4Addr::new(100, 90, 118, 121));
        let bzot = pair_test_peer_with_identity(
            &mut controller,
            "BZOT",
            "node-bzot",
            Some(bzot_address),
            &bzot_identity,
        );
        let bmba = pair_test_peer_with_identity(
            &mut controller,
            "BMBA",
            "node-bmba",
            Some(bmba_address),
            &bmba_identity,
        );
        configure_fake_refresh(
            &mut controller,
            test_tail_status(vec![
                test_tail_node("node-bzot", "BZOT", bzot_address),
                test_tail_node("node-bmba", "BMBA", bmba_address),
            ]),
            HashMap::from([(
                SocketAddr::new(bzot_address, MESHELF_PORT),
                signed_probe_answer(&bzot_identity, "BZOT"),
            )]),
        );

        controller.refresh().expect("fake refresh");

        assert_eq!(controller.reachable_peers.len(), 1);
        assert_eq!(
            controller.reachable_peers.get(&bzot),
            Some(&"BZOT".to_owned())
        );
        assert!(!controller.reachable_peers.contains_key(&bmba));
    }

    #[test]
    fn refresh_clears_the_previous_reachable_set_before_repopulating() {
        let (_directory, mut controller) = test_controller();
        let bzot_identity = InstallationIdentity::generate();
        let bmba_identity = InstallationIdentity::generate();
        let bzot_address = IpAddr::V4(Ipv4Addr::new(100, 90, 118, 122));
        let bmba_address = IpAddr::V4(Ipv4Addr::new(100, 90, 118, 123));
        let bzot = pair_test_peer_with_identity(
            &mut controller,
            "BZOT",
            "node-bzot",
            Some(bzot_address),
            &bzot_identity,
        );
        let bmba = pair_test_peer_with_identity(
            &mut controller,
            "BMBA",
            "node-bmba",
            Some(bmba_address),
            &bmba_identity,
        );
        controller.reachable_peers.insert(bzot, "BZOT".to_owned());
        configure_fake_refresh(
            &mut controller,
            test_tail_status(vec![
                test_tail_node("node-bzot", "BZOT", bzot_address),
                test_tail_node("node-bmba", "BMBA", bmba_address),
            ]),
            HashMap::from([(
                SocketAddr::new(bmba_address, MESHELF_PORT),
                signed_probe_answer(&bmba_identity, "BMBA"),
            )]),
        );

        controller.refresh().expect("fake refresh");

        assert_eq!(controller.reachable_peers.len(), 1);
        assert!(!controller.reachable_peers.contains_key(&bzot));
        assert_eq!(
            controller.reachable_peers.get(&bmba),
            Some(&"BMBA".to_owned())
        );
    }

    #[test]
    fn refresh_that_answers_for_an_unpaired_device_does_not_make_it_reachable() {
        let (_directory, mut controller) = test_controller();
        let unpaired_identity = InstallationIdentity::generate();
        let address = IpAddr::V4(Ipv4Addr::new(100, 90, 118, 124));
        configure_fake_refresh(
            &mut controller,
            test_tail_status(vec![test_tail_node("node-unpaired", "UNPAIRED", address)]),
            HashMap::from([(
                SocketAddr::new(address, MESHELF_PORT),
                signed_probe_answer(&unpaired_identity, "UNPAIRED"),
            )]),
        );

        let view = controller.refresh().expect("fake refresh");

        assert!(controller.reachable_peers.is_empty());
        assert_eq!(view.reachable_names, "No meshelf devices are reachable");
        assert!(
            controller
                .installation
                .peers
                .by_device_id(unpaired_identity.device_id)
                .is_some()
        );
    }
}
