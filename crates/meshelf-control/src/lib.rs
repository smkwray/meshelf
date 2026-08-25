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
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
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
    discovery: Option<CliPeerDiscovery>,
    pub last_status: Option<TailStatus>,
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
            discovery: CliPeerDiscovery::discover().ok(),
            last_status: None,
            pending: None,
            selected_device: None,
        })
    }

    pub fn refresh(&mut self) -> Result<PeerView, String> {
        let discovery = self
            .discovery
            .as_ref()
            .ok_or_else(|| "Tailscale was not found; install Tailscale and retry".to_owned())?;
        let status = discovery
            .refresh()
            .map_err(|error| format!("Tailscale discovery failed: {error}"))?;
        self.device_name.clone_from(&status.self_node.hostname);
        self.merge_refreshed_status(&status)?;
        self.last_status = Some(status.clone());
        self.pending = None;
        self.selected_device = None;

        let runtime = operation_runtime("probe")?;
        let client = PeerClient::with_timeouts(Duration::from_secs(1), Duration::from_secs(2));
        let candidates = runtime.block_on(async {
            let mut tasks = JoinSet::new();
            for node in status.online_peers().cloned() {
                for address in node.addresses.iter().copied() {
                    let client = client.clone();
                    let node = node.clone();
                    tasks.spawn(async move {
                        client
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
        for (node, server) in candidates {
            self.accept_discovered(node, server)?;
        }
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
        let paired_count = self.installation.peers.peers().len();
        if let Some(device_id) = self.selected_device
            && let Some(peer) = self.installation.peers.by_device_id(device_id)
        {
            return PeerView {
                name: peer.hostname.clone(),
                online: true,
                approval_available: false,
                status: if paired_count == 1 {
                    format!("{} ready · paste text or copied files", peer.hostname)
                } else {
                    format!("{paired_count} devices ready · paste text or copied files")
                },
            };
        }
        PeerView {
            name: "Not configured".to_owned(),
            online: false,
            approval_available: false,
            status: "Keep meshelf open on another Tailscale device to pair automatically"
                .to_owned(),
        }
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
    use std::net::{IpAddr, Ipv4Addr};

    use tempfile::tempdir;

    use super::*;

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
            last_status: None,
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
            last_status: None,
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
}
