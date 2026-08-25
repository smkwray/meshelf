//! Shared application controller used by the desktop UI and `meshelfctl`.
//!
//! Clipboard operations remain explicit. Signed meshelf installations on the owner's Tailscale
//! network pair automatically; sends use the direct signed protocol.

pub mod coordinator;
pub mod local_control;
pub mod offer_source;

pub use coordinator::{Coordinator, OfferPlan, PeerAnnouncement};
pub use offer_source::{OfferInput, PreparedOfferSource, SourcePreparationError};

use std::{
    collections::HashMap,
    fs,
    future::Future,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use meshelf_core::{ContentKind, DeviceId, MessageId, ReceiptCode, TextEnvelope};
use meshelf_identity::InstallationIdentity;
use meshelf_net::PeerClient;
use meshelf_protocol::{
    CAP_TEXT_SHELF_V1, ClientHello, FileEntryKind, FileTransferEntry, FileTransferOffer,
    MAX_FILE_BYTES, MAX_FILE_ENTRIES, MAX_TRANSFER_BYTES, ServerHello,
};
use meshelf_tailscale::{
    CliPeerDiscovery, InstallationState, InstallationStore, PeerDiscovery, SshBootstrap,
    SshBootstrapRequest, SshBootstrapResponse, TailNode, TailStatus,
};
use sha2::{Digest, Sha256};
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

#[derive(Debug, Clone)]
struct PreparedPathTransfer {
    transfer_id: MessageId,
    content_kind: ContentKind,
    root_name: String,
    total_bytes: u64,
    entries: Vec<FileTransferEntry>,
    source_files: Vec<PathBuf>,
}

impl MeshSendReport {
    #[must_use]
    pub fn status(&self) -> String {
        let stored = self.stored_on.len();
        let unavailable = self.unavailable.len();
        match (stored, unavailable) {
            (0, 0) => "No other meshelf devices are paired".to_owned(),
            (0, _) => format!(
                "Mesh send failed; unavailable: {}",
                self.unavailable.join(", ")
            ),
            (_, 0) => format!(
                "Added to {}",
                if stored == 1 {
                    "1 other device's shelf".to_owned()
                } else {
                    format!("{stored} other devices' shelves")
                }
            ),
            _ => format!(
                "Added to {}; unavailable: {}",
                if stored == 1 {
                    "1 shelf".to_owned()
                } else {
                    format!("{stored} shelves")
                },
                self.unavailable.join(", ")
            ),
        }
    }
}

pub struct Controller {
    pub state_path: PathBuf,
    pub identity: InstallationIdentity,
    pub installation: InstallationState,
    pub device_name: String,
    discovery: Option<Arc<dyn PeerDiscovery>>,
    probe: Arc<dyn PeerProbe>,
    pub last_status: Option<TailStatus>,
    pub reachable_peers: HashMap<DeviceId, String>,
    pub pending: Option<PendingPeer>,
    pub selected_device: Option<DeviceId>,
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
        self.merge_refreshed_status(&status)?;
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
        let paired_device_ids = self
            .installation
            .peers
            .peers()
            .iter()
            .map(|peer| peer.device_id)
            .collect::<std::collections::HashSet<_>>();
        self.reachable_peers = candidates
            .iter()
            .filter(|(_, server)| paired_device_ids.contains(&server.device_id))
            .map(|(node, server)| (server.device_id, node.hostname.clone()))
            .collect();
        for (node, server) in candidates {
            self.accept_discovered(node, server)?;
        }
        self.last_status = Some(status);
        Ok(self.view())
    }

    fn accept_discovered(&mut self, node: TailNode, server: ServerHello) -> Result<(), String> {
        if !server
            .capabilities
            .iter()
            .any(|capability| capability == CAP_TEXT_SHELF_V1)
            || !server.has_valid_signature()
        {
            return Ok(());
        }
        self.installation = InstallationStore::new(self.state_path.clone())
            .update(self.identity.device_id, |latest| {
                latest
                    .peers
                    .accept_signed(&node, server.device_id, server.public_key.clone())
            })
            .map_err(|error| format!("could not pair discovered meshelf device: {error}"))?;
        self.selected_device = Some(server.device_id);
        Ok(())
    }

    fn merge_refreshed_status(&mut self, status: &TailStatus) -> Result<(), String> {
        self.installation = InstallationStore::new(self.state_path.clone())
            .update(self.identity.device_id, |latest| {
                latest.peers.refresh_addresses(status);
                Ok(())
            })
            .map_err(|error| format!("could not save meshelf state: {error}"))?;
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
        let device_id_matches = response.device_id == pending.server.device_id;
        let node_id_matches = response.node_id == pending.node.node_id.clone().unwrap_or_default();
        let public_key_matches = response.public_key == pending.server.public_key;
        let signature_valid = response.has_valid_signature();
        if !device_id_matches || !node_id_matches || !public_key_matches || !signature_valid {
            return Err(format!(
                "SSH bootstrap identity mismatch (device_id={device_id_matches}, tailscale_node={node_id_matches}, public_key={public_key_matches}, signature={signature_valid})"
            ));
        }
        let response_node = response_to_tail_node(&response);
        let response_key = response.public_key;
        self.installation = InstallationStore::new(self.state_path.clone())
            .update(self.identity.device_id, |latest| {
                latest
                    .peers
                    .accept_signed(&response_node, pending.server.device_id, response_key)
            })
            .map_err(|error| format!("could not save reciprocal peer approval: {error}"))?;
        self.selected_device = Some(pending.server.device_id);
        self.pending = None;
        Ok(self.view())
    }

    pub fn select_peer(&mut self, selector: Option<&str>) -> Result<(), String> {
        if let Some(selector) = selector {
            if let Ok(device_id) = selector.parse::<DeviceId>()
                && self.installation.peers.by_device_id(device_id).is_some()
            {
                self.selected_device = Some(device_id);
                return Ok(());
            }
            let needle = selector.to_ascii_lowercase();
            if let Some(peer) = self
                .installation
                .peers
                .peers()
                .iter()
                .find(|peer| peer.hostname.to_ascii_lowercase() == needle)
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
        self.selected_device
            .map(|_| ())
            .ok_or_else(|| "no trusted meshelf peer is configured".to_owned())
    }

    pub fn send_to_mesh(&self, text: &str) -> Result<MeshSendReport, String> {
        let trimmed = text.trim();
        let path = Path::new(trimmed);
        if trimmed.lines().count() == 1 && (path.is_file() || path.is_dir()) {
            return self.send_path_to_mesh(path);
        }
        self.send_text_to_mesh(text)
    }

    pub fn send_paths_to_mesh(&self, paths: &[PathBuf]) -> Result<String, String> {
        if paths.is_empty() {
            return Err("clipboard contains no files or folders".to_owned());
        }
        let mut sent_items = 0_usize;
        let mut failures = Vec::new();
        for path in paths {
            match self.send_path_to_mesh(path) {
                Ok(report) if !report.stored_on.is_empty() => {
                    sent_items += 1;
                    failures.extend(report.unavailable);
                }
                Ok(report) => failures.extend(report.unavailable),
                Err(error) => failures.push(format!("{} ({error})", path.display())),
            }
        }
        match (sent_items, failures.is_empty()) {
            (0, _) => Err(format!("File send failed: {}", failures.join("; "))),
            (count, true) => Ok(format!(
                "Added {count} file{} to the mesh",
                if count == 1 { "" } else { "s" }
            )),
            (count, false) => Ok(format!(
                "Added {count} file{}; unavailable: {}",
                if count == 1 { "" } else { "s" },
                failures.join("; ")
            )),
        }
    }

    fn send_text_to_mesh(&self, text: &str) -> Result<MeshSendReport, String> {
        // Deliberate: sends attempt every paired peer; status reports only peers that answered the
        // latest reachability probe.
        let peers = self.installation.peers.peers().to_vec();
        if peers.is_empty() {
            return Err(
                "no other meshelf device is available yet; keep meshelf open on both devices"
                    .to_owned(),
            );
        }
        let now = now_unix_ms();
        let content_kind = classify_content(text);
        let source = self.identity.device_id;
        let identity = self.identity.clone();
        let device_name = self.device_name.clone();
        let text = text.to_owned();
        let runtime = operation_runtime("send")?;
        runtime.block_on(async move {
            let mut tasks = JoinSet::new();
            for peer in peers {
                let identity = identity.clone();
                let device_name = device_name.clone();
                let text = text.clone();
                tasks.spawn(async move {
                    let hostname = peer.hostname.clone();
                    let Some(address) = peer
                        .addresses
                        .iter()
                        .copied()
                        .find(|address| address.is_ipv4())
                        .or_else(|| peer.addresses.first().copied())
                    else {
                        return (hostname, false);
                    };
                    let envelope = TextEnvelope::shelf_item(
                        source,
                        peer.device_id,
                        now,
                        Some(now.saturating_add(30_000)),
                        content_kind,
                        text,
                    );
                    let hello = ClientHello::signed(
                        source,
                        device_name,
                        DeviceId::new().to_string(),
                        &identity,
                    );
                    let stored = PeerClient::default()
                        .push(
                            SocketAddr::new(address, MESHELF_PORT),
                            hello,
                            envelope,
                            &peer.public_key,
                        )
                        .await
                        .is_ok_and(|receipt| receipt.code == ReceiptCode::Stored);
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

    fn send_path_to_mesh(&self, path: &Path) -> Result<MeshSendReport, String> {
        let peers = self.installation.peers.peers().to_vec();
        if peers.is_empty() {
            return Err(
                "no other meshelf device is available yet; keep meshelf open on both devices"
                    .to_owned(),
            );
        }
        let prepared = prepare_path_transfer(path)?;
        let source = self.identity.device_id;
        let identity = self.identity.clone();
        let device_name = self.device_name.clone();
        let runtime = operation_runtime("file send")?;
        runtime.block_on(async move {
            let mut tasks = JoinSet::new();
            for peer in peers {
                let prepared = prepared.clone();
                let identity = identity.clone();
                let device_name = device_name.clone();
                tasks.spawn(async move {
                    let hostname = peer.hostname.clone();
                    let Some(address) = peer
                        .addresses
                        .iter()
                        .copied()
                        .find(|address| address.is_ipv4())
                        .or_else(|| peer.addresses.first().copied())
                    else {
                        return (hostname, Err("peer has no Tailscale address".to_owned()));
                    };
                    let offer = FileTransferOffer {
                        protocol_version: meshelf_core::PROTOCOL_VERSION,
                        transfer_id: prepared.transfer_id,
                        source_device: source,
                        target_device: peer.device_id,
                        content_kind: prepared.content_kind,
                        root_name: prepared.root_name,
                        total_bytes: prepared.total_bytes,
                        entries: prepared.entries,
                    };
                    let hello = ClientHello::signed(
                        source,
                        device_name,
                        DeviceId::new().to_string(),
                        &identity,
                    );
                    let outcome = PeerClient::default()
                        .push_file_transfer(
                            SocketAddr::new(address, MESHELF_PORT),
                            hello,
                            offer,
                            prepared.source_files,
                            &peer.public_key,
                        )
                        .await
                        .map_err(|error| error.to_string())
                        .and_then(|receipt| {
                            (receipt.code == ReceiptCode::Stored)
                                .then_some(())
                                .ok_or_else(|| {
                                    receipt.detail.unwrap_or_else(|| {
                                        format!("receiver returned {:?}", receipt.code)
                                    })
                                })
                        });
                    (hostname, outcome)
                });
            }

            let mut report = MeshSendReport {
                stored_on: Vec::new(),
                unavailable: Vec::new(),
            };
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok((hostname, Ok(()))) => report.stored_on.push(hostname),
                    Ok((hostname, Err(error))) => {
                        report.unavailable.push(format!("{hostname} ({error})"));
                    }
                    Err(error) => report.unavailable.push(format!("worker ({error})")),
                }
            }
            report.stored_on.sort();
            report.unavailable.sort();
            Ok(report)
        })
    }

    #[must_use]
    pub fn view(&self) -> PeerView {
        let reachable_names = self.reachable_paired_names();
        let reachable_count = reachable_names.len();
        let reachability_checked = self.last_status.is_some();
        let status = if !reachability_checked {
            "Reachability not checked yet · refresh to find meshelf devices".to_owned()
        } else if reachable_count == 0 && self.installation.peers.peers().is_empty() {
            "No paired meshelf devices · refresh to discover devices".to_owned()
        } else if reachable_count == 0 {
            "No paired meshelf devices are reachable · refresh to retry".to_owned()
        } else if reachable_count == 1 {
            "1 device reachable · paste text or copied files".to_owned()
        } else {
            format!("{reachable_count} devices reachable · paste text or copied files")
        };
        let selected_name = self
            .selected_device
            .and_then(|device_id| self.reachable_peers.get(&device_id))
            .cloned()
            .or_else(|| reachable_names.first().cloned());
        let reachable_names = if reachable_names.is_empty() {
            if reachability_checked {
                "No meshelf devices are reachable".to_owned()
            } else {
                "Reachability not checked yet".to_owned()
            }
        } else {
            reachable_names.join("\n")
        };
        PeerView {
            name: selected_name.unwrap_or_else(|| "Not configured".to_owned()),
            online: reachable_count > 0,
            approval_available: false,
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
pub fn response_to_tail_node(response: &SshBootstrapResponse) -> TailNode {
    TailNode {
        node_id: Some(response.node_id.clone()),
        hostname: response.hostname.clone(),
        dns_name: None,
        addresses: response.addresses.clone(),
        online: true,
        active: true,
    }
}

fn now_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn prepare_path_transfer(path: &Path) -> Result<PreparedPathTransfer, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err("symbolic links are not transferred".to_owned());
    }
    let root_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "file or folder name is not valid UTF-8".to_owned())?
        .to_owned();
    let content_kind = if metadata.is_file() {
        ContentKind::File
    } else if metadata.is_dir() {
        ContentKind::Folder
    } else {
        return Err("only regular files and folders can be transferred".to_owned());
    };
    let mut entries = Vec::new();
    let mut source_files = Vec::new();
    let mut total_bytes = 0_u64;
    if content_kind == ContentKind::File {
        add_file_entry(
            path,
            root_name.clone(),
            &mut entries,
            &mut source_files,
            &mut total_bytes,
        )?;
    } else {
        collect_folder_entries(
            path,
            Path::new(""),
            &mut entries,
            &mut source_files,
            &mut total_bytes,
        )?;
    }
    let prepared = PreparedPathTransfer {
        transfer_id: MessageId::new(),
        content_kind,
        root_name,
        total_bytes,
        entries,
        source_files,
    };
    let validation_offer = FileTransferOffer {
        protocol_version: meshelf_core::PROTOCOL_VERSION,
        transfer_id: prepared.transfer_id,
        source_device: DeviceId::new(),
        target_device: DeviceId::new(),
        content_kind: prepared.content_kind,
        root_name: prepared.root_name.clone(),
        total_bytes: prepared.total_bytes,
        entries: prepared.entries.clone(),
    };
    meshelf_net::validate_file_offer(&validation_offer)?;
    Ok(prepared)
}

fn collect_folder_entries(
    directory: &Path,
    relative_directory: &Path,
    entries: &mut Vec<FileTransferEntry>,
    source_files: &mut Vec<PathBuf>,
    total_bytes: &mut u64,
) -> Result<(), String> {
    let mut children = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if entries.len() >= MAX_FILE_ENTRIES {
            return Err(format!(
                "folder contains more than {MAX_FILE_ENTRIES} entries"
            ));
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("symbolic link refused: {}", path.display()));
        }
        let relative = relative_directory.join(child.file_name());
        let relative_text = portable_relative_path(&relative)?;
        if metadata.is_dir() {
            entries.push(FileTransferEntry {
                relative_path: relative_text,
                kind: FileEntryKind::Directory,
                byte_len: 0,
                sha256: Vec::new(),
            });
            collect_folder_entries(&path, &relative, entries, source_files, total_bytes)?;
        } else if metadata.is_file() {
            add_file_entry(&path, relative_text, entries, source_files, total_bytes)?;
        } else {
            return Err(format!("non-regular file refused: {}", path.display()));
        }
    }
    Ok(())
}

fn add_file_entry(
    path: &Path,
    relative_path: String,
    entries: &mut Vec<FileTransferEntry>,
    source_files: &mut Vec<PathBuf>,
    total_bytes: &mut u64,
) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
    let byte_len = metadata.len();
    if byte_len > MAX_FILE_BYTES {
        return Err(format!(
            "{} is {byte_len} bytes; per-file maximum is {MAX_FILE_BYTES}",
            path.display()
        ));
    }
    *total_bytes = total_bytes
        .checked_add(byte_len)
        .ok_or_else(|| "file-transfer size overflow".to_owned())?;
    if *total_bytes > MAX_TRANSFER_BYTES {
        return Err(format!(
            "transfer exceeds the {MAX_TRANSFER_BYTES}-byte maximum"
        ));
    }
    let mut file = fs::File::open(path)
        .map_err(|error| format!("could not open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    entries.push(FileTransferEntry {
        relative_path,
        kind: FileEntryKind::File,
        byte_len,
        sha256: hasher.finalize().to_vec(),
    });
    source_files.push(path.to_path_buf());
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String, String> {
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "folder contains a non-UTF-8 file name".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn classify_content(text: &str) -> ContentKind {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.lines().count() != 1 {
        return ContentKind::Text;
    }
    let path = Path::new(trimmed);
    if path.is_file() {
        ContentKind::File
    } else if path.is_dir() {
        ContentKind::Folder
    } else if path.is_absolute()
        || trimmed.starts_with("~/")
        || trimmed.starts_with("\\\\")
        || trimmed.as_bytes().get(1) == Some(&b':')
    {
        ContentKind::Path
    } else {
        ContentKind::Text
    }
}

pub fn state_path(config_dir: &Path) -> PathBuf {
    config_dir.join("state.json")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use tempfile::tempdir;

    use meshelf_tailscale::DiscoveryError;

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

    #[test]
    fn classifies_text_and_future_file_items() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("example.txt");
        std::fs::write(&file, "example").expect("write example file");

        assert_eq!(classify_content("ordinary text"), ContentKind::Text);
        assert_eq!(classify_content("two\nlines"), ContentKind::Text);
        assert_eq!(classify_content(&file.to_string_lossy()), ContentKind::File);
        assert_eq!(
            classify_content(&directory.path().to_string_lossy()),
            ContentKind::Folder
        );
        assert_eq!(classify_content("C:\\future\\item.txt"), ContentKind::Path);
    }

    #[test]
    fn prepares_nested_folder_manifest_in_stable_order() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("package");
        std::fs::create_dir_all(root.join("empty")).expect("create empty folder");
        std::fs::create_dir_all(root.join("nested")).expect("create nested folder");
        std::fs::write(root.join("b.txt"), "bravo").expect("write b");
        std::fs::write(root.join("nested").join("a.txt"), "alpha").expect("write a");

        let prepared = prepare_path_transfer(&root).expect("prepare folder");

        assert_eq!(prepared.content_kind, ContentKind::Folder);
        assert_eq!(prepared.root_name, "package");
        assert_eq!(prepared.total_bytes, 10);
        assert_eq!(prepared.source_files.len(), 2);
        assert_eq!(
            prepared
                .entries
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["b.txt", "empty", "nested", "nested/a.txt"]
        );
    }

    #[test]
    fn valid_signed_tailscale_discovery_pairs_without_ssh() {
        let directory = tempdir().expect("temporary directory");
        let state_path = directory.path().join("state.json");
        let identity = InstallationIdentity::generate();
        let local_device_id = identity.device_id;
        let installation = InstallationState {
            device_id: local_device_id,
            peers: Default::default(),
            settings: Default::default(),
        };
        installation.save(&state_path).expect("save initial state");
        let mut controller = Controller {
            state_path,
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
            meshelf_core::PROTOCOL_VERSION,
            peer_id,
            "BZOT".to_owned(),
            false,
            Some("not paired yet".to_owned()),
            vec![CAP_TEXT_SHELF_V1.to_owned()],
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
        let directory = tempdir().expect("temporary directory");
        let state_path = directory.path().join("state.json");
        let identity = InstallationIdentity::generate();
        let local_device_id = identity.device_id;
        let initial = InstallationState {
            device_id: local_device_id,
            peers: Default::default(),
            settings: Default::default(),
        };
        initial.save(&state_path).expect("save initial state");
        let mut controller = Controller {
            state_path: state_path.clone(),
            identity,
            installation: initial.clone(),
            device_name: "BMST".to_owned(),
            discovery: None,
            probe: Arc::new(FakeProbe::default()),
            last_status: None,
            reachable_peers: HashMap::new(),
            pending: None,
            selected_device: None,
        };

        let peer_identity = InstallationIdentity::generate();
        InstallationStore::new(state_path.clone())
            .update(local_device_id, |latest| {
                latest.peers.accept_signed(
                    &TailNode {
                        node_id: Some("node-bzot".to_owned()),
                        hostname: "BZOT".to_owned(),
                        dns_name: None,
                        addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 90, 118, 120))],
                        online: true,
                        active: true,
                    },
                    peer_identity.device_id,
                    peer_identity.public_key().to_vec(),
                )
            })
            .expect("record external pairing");

        controller
            .merge_refreshed_status(&TailStatus {
                backend_state: "Running".to_owned(),
                self_node: TailNode {
                    node_id: Some("node-bmst".to_owned()),
                    hostname: "BMST".to_owned(),
                    dns_name: None,
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 71, 19, 72))],
                    online: true,
                    active: true,
                },
                peers: vec![TailNode {
                    node_id: Some("node-bzot".to_owned()),
                    hostname: "BZOT".to_owned(),
                    dns_name: None,
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 90, 118, 120))],
                    online: true,
                    active: false,
                }],
            })
            .expect("resident refresh merges the latest state");
        assert_eq!(
            controller
                .installation
                .peers
                .by_device_id(peer_identity.device_id)
                .expect("external peer reloaded")
                .hostname,
            "BZOT"
        );
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
        let node_id = format!("node-{hostname}");
        pair_test_peer_with_identity(controller, hostname, &node_id, None, &identity)
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
            meshelf_core::PROTOCOL_VERSION,
            identity.device_id,
            hostname.to_owned(),
            false,
            None,
            vec![CAP_TEXT_SHELF_V1.to_owned()],
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
        controller.last_status = Some(TailStatus {
            backend_state: "Running".to_owned(),
            self_node: TailNode {
                node_id: Some("node-bmst".to_owned()),
                hostname: "BMST".to_owned(),
                dns_name: None,
                addresses: Vec::new(),
                online: true,
                active: true,
            },
            peers: Vec::new(),
        });
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
        let (_zero_directory, zero) = test_controller();
        let mut zero = zero;
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
