#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(target_os = "macos")]
use std::process::Command;

use anyhow::Result;
use meshelf_control::{
    ActivationPlan, Controller, MESHELF_PORT, PeerView, announce_offer_plan,
    coordinator::{Coordinator, OfferPlan},
    local_control::{self, LocalRuntime},
    offer_source::OfferInput,
    report_announce_outcome,
};
use meshelf_core::{
    ActivationMode, CardAvailability, ClipboardError, ClipboardSink, DeviceId, OfferCardRecord,
    OfferDescriptor, OfferId, SaveDestination,
};
use meshelf_net::{
    ActivationOutcome, ActivationService, FetchActivation, FetchClipboard,
    OfferAnnouncementHandler, OfferCardStore, OfferFetchHandler, PeerClient, ServerIdentity,
    TrustDecision, TrustGate, V2OfferServices, bind_discovered_tailscale_std_listener,
    select_discovered_ip, select_discovered_socket, serve_v2_with_offers_and_fetch,
};
use meshelf_platform::{
    ClipboardItem, ClipboardSource, ClipboardWorker, acquire_resident_lock, choose_folder,
    listen_with_control, resolve_save_destination, signal,
};
#[cfg(test)]
use meshelf_protocol::OfferAnnouncement;
use meshelf_protocol::{ClientHello, FetchRequest};
use meshelf_store::RedbV2Store;
use meshelf_tailscale::InstallationStore;
use slint::{ComponentHandle, ModelRc, VecModel};
use tokio::{
    runtime::{Builder, Runtime},
    sync::watch,
};
use tracing_subscriber::EnvFilter;

slint::include_modules!();

#[derive(Debug, Clone)]
struct FileBackedTrustGate {
    store: InstallationStore,
    identity: meshelf_core::DeviceId,
}

impl TrustGate for FileBackedTrustGate {
    fn authorize(
        &self,
        remote: SocketAddr,
        hello: &meshelf_protocol::ClientHello,
    ) -> TrustDecision {
        let Ok(state) = self.store.load_for_identity(self.identity) else {
            return TrustDecision::Deny("local meshelf state is unavailable".to_owned());
        };
        match state.peers.by_device_id(hello.device_id) {
            Some(peer)
                if peer.addresses.contains(&remote.ip())
                    && peer.public_key == hello.public_key
                    && hello.has_valid_signature() =>
            {
                TrustDecision::Allow
            }
            Some(_) if hello.public_key.len() != 32 => {
                TrustDecision::Deny("peer hello has no valid installation key".to_owned())
            }
            Some(_) => TrustDecision::Deny(
                "approved peer key or Tailscale address does not match".to_owned(),
            ),
            None => TrustDecision::Deny("meshelf installation has not been approved".to_owned()),
        }
    }
}

struct ServerHandle {
    shutdown: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

struct ActivationCleanup(PathBuf);

impl Drop for ActivationCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Debug, Clone, Default)]
struct OperationGate {
    busy: Arc<AtomicBool>,
}

impl OperationGate {
    fn try_enter(&self) -> Option<OperationPermit> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| OperationPermit {
                busy: self.busy.clone(),
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryRefreshTrigger {
    Launch,
    Explicit,
    BeforeUserOperation,
}

#[derive(Debug, Clone, Copy, Default)]
struct DiscoveryEventLoop;

impl DiscoveryEventLoop {
    fn dispatch(self, _trigger: DiscoveryRefreshTrigger, refresh: impl FnOnce() -> bool) -> bool {
        refresh()
    }
}

#[derive(Debug)]
struct OperationPermit {
    busy: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Default)]
struct ActivationGate {
    active: Arc<AtomicUsize>,
}

impl ActivationGate {
    fn try_enter(&self) -> Option<ActivationPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= 2 {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ActivationPermit(self.active.clone())),
                Err(updated) => current = updated,
            }
        }
    }
}

#[derive(Debug)]
struct ActivationPermit(Arc<AtomicUsize>);

impl Drop for ActivationPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
struct ShelfSnapshot {
    records: Vec<OfferCardRecord>,
    peer_names: HashMap<DeviceId, String>,
    active: HashMap<OfferId, String>,
}

#[derive(Debug)]
struct ActiveActivation {
    cancel: watch::Sender<bool>,
    progress: String,
}

type ActiveActivations = Arc<Mutex<HashMap<OfferId, ActiveActivation>>>;

struct DesktopLocalRuntime {
    app_state: Arc<Mutex<Controller>>,
    state_path: PathBuf,
    identity: meshelf_identity::InstallationIdentity,
    device_name: String,
    clipboard: Option<ClipboardWorker>,
    activations: Arc<ActivationService<ActivationClipboard>>,
}

impl LocalRuntime for DesktopLocalRuntime {
    fn announce(&self, plan: &OfferPlan) -> Result<String, String> {
        report_announce_outcome(announce_offer_plan(
            &self.state_path,
            &self.identity,
            &self.device_name,
            plan,
        )?)
    }

    fn activate(&self, plan: &ActivationPlan) -> Result<ActivationOutcome, String> {
        let input = self
            .app_state
            .lock()
            .map_err(|_| "app state is unavailable".to_owned())
            .and_then(|state| build_activation_input(plan, &state))?;
        clipboard_for_activation(plan.mode, self.clipboard.clone())?;
        let (_cancel, cancel) = watch::channel(false);
        run_activation(input, self.activations.clone(), cancel)
    }
}

fn register_active_activation(
    active: &ActiveActivations,
    offer_id: OfferId,
    activation: ActiveActivation,
) -> bool {
    let Ok(mut active) = active.lock() else {
        return false;
    };
    if active.contains_key(&offer_id) {
        return false;
    }
    active.insert(offer_id, activation);
    true
}

fn remove_active_activation(active: &ActiveActivations, offer_id: OfferId) {
    if let Ok(mut active) = active.lock() {
        active.remove(&offer_id);
    }
}

#[derive(Debug)]
enum ActivationClipboard {
    Worker(Arc<ClipboardWorker>),
    Unavailable,
}

impl ClipboardSink for ActivationClipboard {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        match self {
            Self::Worker(worker) => worker.set_text(text),
            Self::Unavailable => Err(ClipboardError::new(
                "clipboard adapter is unavailable for this activation",
            )),
        }
    }
}

impl FetchClipboard for ActivationClipboard {
    fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
        match self {
            Self::Worker(worker) => worker.set_files(paths).map_err(ClipboardError::from),
            Self::Unavailable => Err(ClipboardError::new(
                "clipboard adapter is unavailable for this activation",
            )),
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn start_v2_listener(
    state: &Controller,
    offer_store: Arc<RedbV2Store>,
    card_store: Arc<dyn OfferCardStore>,
) -> Result<ServerHandle, String> {
    let status = state
        .last_status
        .as_ref()
        .ok_or_else(|| "Tailscale status is unavailable".to_owned())?;
    let address = select_discovered_ip(&status.self_node.addresses)
        .ok_or_else(|| "Tailscale supplied no local address".to_owned())?;
    let listener = bind_discovered_tailscale_std_listener(
        SocketAddr::new(address, MESHELF_PORT),
        &status.self_node.addresses,
    )
    .map_err(|error| format!("could not bind Tailscale listener: {error}"))?;
    let offer_receiver = Arc::new(OfferAnnouncementHandler::new(card_store));
    let fetch_sender = Arc::new(OfferFetchHandler::new(
        state.installation.device_id,
        offer_store,
    ));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let identity = ServerIdentity {
        signing_identity: state.identity.clone(),
        device_name: state.device_name.clone(),
    };
    let gate = Arc::new(FileBackedTrustGate {
        store: InstallationStore::new(state.state_path.clone()),
        identity: state.identity.device_id,
    });
    let worker = thread::Builder::new()
        .name("meshelf-network-v2".to_owned())
        .spawn(move || {
            let Ok(runtime) = Runtime::new() else {
                tracing::error!("meshelf v2 listener runtime could not be created");
                return;
            };
            let Ok(listener) =
                runtime.block_on(async move { tokio::net::TcpListener::from_std(listener) })
            else {
                tracing::error!("meshelf v2 listener could not attach to its server runtime");
                return;
            };
            if let Err(error) = runtime.block_on(serve_v2_with_offers_and_fetch(
                listener,
                identity,
                gate,
                V2OfferServices {
                    announcement_receiver: offer_receiver,
                    fetch_sender,
                },
                Duration::from_secs(5),
                shutdown_rx,
            )) {
                tracing::error!(%error, "meshelf v2 listener stopped unexpectedly");
            }
        })
        .map_err(|error| format!("could not start Tailscale v2 listener: {error}"))?;
    Ok(ServerHandle {
        shutdown,
        worker: Some(worker),
    })
}

fn apply_peer_view(window: &MainWindow, view: PeerView) {
    window.set_default_peer(view.name.into());
    window.set_default_peer_online(view.online);
    window.set_status_text(view.status.into());
    window.set_reachable_names(view.reachable_names.into());
}

fn apply_refresh_error(window: &MainWindow, error: String) {
    window.set_reachable_names("Reachability unavailable".into());
    window.set_status_text(error.into());
}

fn create_and_announce(
    coordinator: &Coordinator,
    runtime: &dyn LocalRuntime,
    input: OfferInput,
) -> Result<String, String> {
    let Some(plan) = coordinator.create_offer(input)? else {
        return Err("no other meshelf device is paired".to_owned());
    };
    runtime.announce(&plan)
}

fn load_shelf_snapshot(
    offer_store: &RedbV2Store,
    peer_names: &Mutex<HashMap<DeviceId, String>>,
    active: &ActiveActivations,
) -> Result<ShelfSnapshot, String> {
    let records = offer_store
        .read_offer_shelf()
        .map_err(|error| format!("Could not read local offer shelf: {error}"))?;
    let peer_names = peer_names
        .lock()
        .map_err(|_| "peer names are unavailable".to_owned())?
        .clone();
    let active = active
        .lock()
        .map_err(|_| "activation state is unavailable".to_owned())?
        .iter()
        .map(|(offer_id, activation)| (*offer_id, activation.progress.clone()))
        .collect();
    Ok(ShelfSnapshot {
        records,
        peer_names,
        active,
    })
}

fn apply_shelf_snapshot(window: &MainWindow, snapshot: ShelfSnapshot) {
    let rows = snapshot
        .records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let progress = snapshot.active.get(&record.offer_id).cloned();
            shelf_row(&snapshot.peer_names, index, record, progress)
        })
        .collect::<Vec<_>>();
    window.set_shelf_items(ModelRc::new(VecModel::from(rows)));
}

fn refresh_shelf_in_background(
    window_weak: slint::Weak<MainWindow>,
    offer_store: Arc<RedbV2Store>,
    peer_names: Arc<Mutex<HashMap<DeviceId, String>>>,
    active: ActiveActivations,
) {
    thread::spawn(move || {
        let result = load_shelf_snapshot(&offer_store, &peer_names, &active);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = window_weak.upgrade() {
                match result {
                    Ok(snapshot) => apply_shelf_snapshot(&window, snapshot),
                    Err(error) => window.set_status_text(error.into()),
                }
            }
        });
    });
}

fn shelf_row(
    peer_names: &HashMap<DeviceId, String>,
    index: usize,
    record: OfferCardRecord,
    progress: Option<String>,
) -> ShelfRow {
    let source = peer_names
        .get(&record.source_device)
        .cloned()
        .unwrap_or_else(|| record.source_device.to_string());
    let (kind, name, size, preview, counts) = match &record.descriptor {
        OfferDescriptor::Text {
            utf8_bytes,
            preview,
            ..
        } => (
            "Text",
            String::new(),
            format!("{utf8_bytes} bytes"),
            preview.clone(),
            String::new(),
        ),
        OfferDescriptor::File {
            root_name,
            total_bytes,
        } => (
            "File",
            root_name.clone(),
            format!("{total_bytes} bytes"),
            String::new(),
            String::new(),
        ),
        OfferDescriptor::Folder {
            root_name,
            total_bytes,
            entry_count,
            file_count,
            directory_count,
        } => (
            "Folder",
            root_name.clone(),
            format!("{total_bytes} bytes"),
            String::new(),
            format!("{entry_count} entries · {file_count} files · {directory_count} folders"),
        ),
    };
    let availability = match record.availability {
        CardAvailability::Available => "available",
        CardAvailability::SourceUnavailable => "source unavailable",
        CardAvailability::SourceChanged => "source changed",
    };
    let active = progress.is_some();
    let can_activate = !active && !matches!(record.availability, CardAvailability::SourceChanged);
    let can_save = !record.descriptor.is_text();
    ShelfRow {
        icon: match &record.descriptor {
            OfferDescriptor::Text { .. } => "📝",
            OfferDescriptor::File { .. } => "📄",
            OfferDescriptor::Folder { .. } => "📁",
        }
        .into(),
        offer_id: record.offer_id.to_string().into(),
        kind: kind.into(),
        origin_device: source.clone().into(),
        name: name.into(),
        size: size.into(),
        preview: if record.descriptor.is_text() {
            preview.into()
        } else {
            String::new().into()
        },
        counts: counts.into(),
        availability: availability.into(),
        progress: progress.unwrap_or_default().into(),
        active,
        can_activate,
        can_save,
        detail: format!("From {source}").into(),
        shortcut: if index < 5 {
            item_shortcut(index + 1).into()
        } else {
            "click".into()
        },
        save_shortcut: if index < 5 {
            save_shortcut(index + 1).into()
        } else {
            "save".into()
        },
    }
}

#[cfg(target_os = "macos")]
fn paste_shortcut() -> &'static str {
    "⌘V"
}

#[cfg(not(target_os = "macos"))]
fn paste_shortcut() -> &'static str {
    "Ctrl+V"
}

#[cfg(target_os = "macos")]
fn refresh_shortcut() -> &'static str {
    "⌘R"
}

#[cfg(not(target_os = "macos"))]
fn refresh_shortcut() -> &'static str {
    "Ctrl+R"
}

#[cfg(target_os = "macos")]
fn shelf_shortcut_help() -> &'static str {
    "click or ⌘1–5 to pull · ⌥1–5 to save files"
}

#[cfg(not(target_os = "macos"))]
fn shelf_shortcut_help() -> &'static str {
    "click or Ctrl+1–5 to pull · Alt+1–5 to save files"
}

#[cfg(target_os = "macos")]
fn item_shortcut(index: usize) -> String {
    format!("⌘{index}")
}

#[cfg(not(target_os = "macos"))]
fn item_shortcut(index: usize) -> String {
    format!("Ctrl+{index}")
}

#[cfg(target_os = "macos")]
fn save_shortcut(index: usize) -> String {
    format!("⌥{index}")
}

#[cfg(not(target_os = "macos"))]
fn save_shortcut(index: usize) -> String {
    format!("Alt+{index}")
}

fn capture_peer_names(state: &Controller) -> HashMap<DeviceId, String> {
    state
        .installation
        .peers
        .peers()
        .iter()
        .map(|peer| (peer.device_id, peer.hostname.clone()))
        .collect()
}

fn raise_window(window: &MainWindow) {
    window.window().set_minimized(false);
    let _ = window.show();
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("/usr/bin/open")
            .args(["-a", "meshelf"])
            .spawn();
    }
}

fn refresh_in_background(
    app_state: Arc<Mutex<Controller>>,
    peer_names: Arc<Mutex<HashMap<DeviceId, String>>>,
    server: Arc<Mutex<Option<ServerHandle>>>,
    offer_store: Arc<RedbV2Store>,
    card_store: Arc<dyn OfferCardStore>,
    gate: OperationGate,
    on_complete: impl FnOnce(Result<PeerView, String>) + Send + 'static,
) -> bool {
    let Some(permit) = gate.try_enter() else {
        return false;
    };
    thread::spawn(move || {
        let result = app_state
            .lock()
            .map_err(|_| "app state is unavailable".to_owned())
            .and_then(|mut state| {
                state.refresh_discovery()?;
                if let Ok(mut names) = peer_names.lock() {
                    *names = capture_peer_names(&state);
                }
                let needs_server = server.lock().map(|slot| slot.is_none()).unwrap_or(false);
                if needs_server {
                    let listener =
                        start_v2_listener(&state, offer_store.clone(), card_store.clone())?;
                    if let Ok(mut slot) = server.lock()
                        && slot.is_none()
                    {
                        *slot = Some(listener);
                    }
                }
                state.refresh_reachability()
            });
        drop(permit);
        let _ = slint::invoke_from_event_loop(move || on_complete(result));
    });
    true
}

fn destination_label(destination: &SaveDestination) -> String {
    match destination {
        SaveDestination::Downloads => "Downloads".to_owned(),
        SaveDestination::Custom { path } => path.display().to_string(),
    }
}

fn settings_for_surface(coordinator: &Coordinator) -> Result<meshelf_core::UserSettings, String> {
    coordinator.settings()
}

#[cfg(test)]
struct TestDirectory(PathBuf);

#[cfg(test)]
impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("meshelf-step8-{}", OfferId::new()));
        fs::create_dir_all(&path).expect("test directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn update_settings_from_surface(
    coordinator: &Coordinator,
    settings: meshelf_core::UserSettings,
) -> Result<meshelf_core::UserSettings, String> {
    coordinator.update_settings(settings)
}

#[derive(Debug)]
struct ActivationInput {
    address: SocketAddr,
    hello: ClientHello,
    request: FetchRequest,
    activation: FetchActivation,
    expected_server_public_key: Vec<u8>,
}

fn build_activation_input(
    plan: &ActivationPlan,
    state: &Controller,
) -> Result<ActivationInput, String> {
    let peer = state
        .installation
        .peers
        .by_device_id(plan.source_device)
        .ok_or_else(|| "the offer's source device is not paired".to_owned())?;
    let address = select_discovered_socket(&peer.addresses, MESHELF_PORT)
        .ok_or_else(|| "the offer's source device has no address".to_owned())?;
    let destination = match plan.mode {
        ActivationMode::Clipboard => None,
        ActivationMode::Save => Some(resolve_save_destination(
            plan.destination
                .as_ref()
                .ok_or_else(|| "save activation has no destination setting".to_owned())?,
        )?),
    };
    let hello = ClientHello::signed_v2(
        state.identity.device_id,
        state.device_name.clone(),
        plan.activation_id.to_string(),
        &state.identity,
    );
    let request = FetchRequest {
        request_id: plan.activation_id,
        offer_id: plan.offer_id,
        source_device: plan.source_device,
        requester_device: state.identity.device_id,
    };
    let activation = FetchActivation::new(
        request.request_id,
        plan.source_device,
        plan.offer_id,
        plan.mode,
        destination,
    );
    Ok(ActivationInput {
        address,
        hello,
        request,
        activation,
        expected_server_public_key: peer.public_key.clone(),
    })
}

fn clipboard_for_activation(
    mode: ActivationMode,
    clipboard: Option<ClipboardWorker>,
) -> Result<Option<ClipboardWorker>, String> {
    if mode == ActivationMode::Save {
        Ok(None)
    } else {
        clipboard
            .map(Some)
            .ok_or_else(|| "Clipboard adapter is unavailable".to_owned())
    }
}

fn run_activation(
    input: ActivationInput,
    service: Arc<ActivationService<ActivationClipboard>>,
    cancel: watch::Receiver<bool>,
) -> Result<ActivationOutcome, String> {
    let client = PeerClient::with_timeouts(Duration::from_secs(3), Duration::from_secs(5));
    let ActivationInput {
        address,
        hello,
        request,
        activation,
        expected_server_public_key,
    } = input;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("activation runtime unavailable: {error}"))?;
    runtime.block_on(async move {
        service
            .activate(
                &client,
                address,
                hello,
                request,
                activation,
                &expected_server_public_key,
                cancel,
            )
            .await
            .map_err(|error| error.to_string())
    })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .without_time()
        .init();

    let window = MainWindow::new()?;
    let tray = MeshelfTray::new()?;
    window.set_paste_shortcut(paste_shortcut().into());
    window.set_refresh_shortcut(refresh_shortcut().into());
    window.set_shelf_shortcut_help(shelf_shortcut_help().into());
    let device_name = std::env::var("MESHELF_DEVICE_NAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".to_owned());
    let data_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("meshelf");
    fs::create_dir_all(&data_dir)?;
    let Some(_resident_lock) = acquire_resident_lock(&data_dir)? else {
        let signalled = signal(&data_dir);
        tracing::info!(signalled, "meshelf desktop is already running");
        return Ok(());
    };
    let _activation_cleanup = ActivationCleanup(data_dir.join("activation"));
    let state_path = data_dir.join("state.json");
    let app_state = Arc::new(Mutex::new(
        Controller::load(state_path.clone(), device_name)
            .map_err(|error| anyhow::anyhow!(error))?,
    ));
    let offer_store = Arc::new(
        meshelf_store::RedbV2Store::open(data_dir.join("meshelf.redb"))
            .map_err(|error| anyhow::anyhow!("could not open v2 offer store: {error}"))?,
    );
    let incoming_directory = dirs::download_dir()
        .unwrap_or_else(|| data_dir.clone())
        .join("Meshelf Incoming");
    let migration = offer_store
        .migrate_legacy_state(&incoming_directory)
        .map_err(|error| anyhow::anyhow!("legacy startup migration failed: {error}"))?;
    tracing::info!(
        v1_body_records_removed = migration.v1_body_records_removed,
        partials_directory_removed = migration.partials_directory_removed,
        completion_markers_removed = migration.completion_markers_removed,
        "legacy meshelf state migration completed before network binding"
    );
    let coordinator = {
        let state = app_state.lock().expect("app state mutex");
        Arc::new(
            Coordinator::new(
                state.identity.device_id,
                InstallationStore::new(state_path),
                offer_store.clone(),
            )
            .with_card_store(offer_store.clone()),
        )
    };
    let card_store = coordinator
        .card_store()
        .ok_or_else(|| anyhow::anyhow!("v2 offer-card store is not configured"))?;
    let (device_name, initial_peer_names) = {
        let state = app_state.lock().expect("app state mutex");
        (state.device_name.clone(), capture_peer_names(&state))
    };
    let peer_names = Arc::new(Mutex::new(initial_peer_names));
    window.set_device_name(device_name.clone().into());
    tray.set_tooltip_text(format!("meshelf — {device_name}").into());
    window.set_status_text("Finding meshelf devices on Tailscale…".into());

    let clipboard = match ClipboardWorker::new() {
        Ok(clipboard) => Some(clipboard),
        Err(error) => {
            window.set_status_text(format!("Clipboard unavailable: {error}").into());
            None
        }
    };
    let activation_clipboard = match clipboard.clone() {
        Some(worker) => ActivationClipboard::Worker(Arc::new(worker)),
        None => ActivationClipboard::Unavailable,
    };
    let activations = Arc::new(ActivationService::new(
        app_state
            .lock()
            .map_err(|_| anyhow::anyhow!("app state is unavailable"))?
            .identity
            .device_id,
        offer_store.clone(),
        Arc::new(activation_clipboard),
        data_dir.clone(),
    ));
    activations
        .recover()
        .map_err(|error| anyhow::anyhow!("activation cleanup is unavailable: {error}"))?;
    let local_runtime = Arc::new(DesktopLocalRuntime {
        app_state: app_state.clone(),
        state_path: data_dir.join("state.json"),
        identity: app_state
            .lock()
            .map_err(|_| anyhow::anyhow!("app state is unavailable"))?
            .identity
            .clone(),
        device_name: device_name.clone(),
        clipboard: clipboard.clone(),
        activations: activations.clone(),
    });
    let window_weak = window.as_weak();
    let control_coordinator = coordinator.clone();
    let control_runtime = local_runtime.clone();
    listen_with_control(
        &data_dir,
        move || {
            let window_weak = window_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = window_weak.upgrade() {
                    raise_window(&window);
                }
            });
        },
        move |request| {
            local_control::dispatch_bytes_with_runtime(
                &control_coordinator,
                request,
                control_runtime.as_ref(),
            )
        },
    )
    .map_err(|error| anyhow::anyhow!("could not start activation listener: {error}"))?;
    let server = Arc::new(Mutex::new(None::<ServerHandle>));
    let send_gate = OperationGate::default();
    let activation_gate = ActivationGate::default();
    let active_activations: ActiveActivations = Arc::new(Mutex::new(HashMap::new()));
    let refresh_gate = OperationGate::default();
    let discovery_events = DiscoveryEventLoop;

    let settings = settings_for_surface(&coordinator).map_err(|error| anyhow::anyhow!(error))?;
    window.set_destination_text(destination_label(&settings.save_destination).into());

    {
        let window_weak = window.as_weak();
        let clipboard = clipboard.clone();
        let coordinator = coordinator.clone();
        let local_runtime = local_runtime.clone();
        let send_gate = send_gate.clone();
        window.on_paste_and_send(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let Some(clipboard) = clipboard.clone() else {
                window.set_status_text("Clipboard adapter is unavailable".into());
                return;
            };
            let Some(permit) = send_gate.try_enter() else {
                window.set_status_text("A mesh send is already in progress".into());
                return;
            };
            window.set_status_text("Sending clipboard item to the mesh…".into());
            let status_window = window_weak.clone();
            let action_clipboard = clipboard.clone();
            let coordinator = coordinator.clone();
            let local_runtime = local_runtime.clone();
            thread::spawn(move || {
                let result = action_clipboard
                    .read_item()
                    .map_err(|error| format!("Could not read clipboard: {error}"))
                    .and_then(|item| match item {
                        ClipboardItem::Text(text) => {
                            if text.trim().is_empty() {
                                return Err("Clipboard contains no text to send".to_owned());
                            }
                            create_and_announce(
                                &coordinator,
                                local_runtime.as_ref(),
                                OfferInput::Text(text),
                            )
                        }
                        ClipboardItem::Files(paths) => {
                            if paths.is_empty() {
                                return Err("Clipboard contains no files or folders".to_owned());
                            }
                            let mut statuses = Vec::new();
                            for path in paths {
                                statuses.push(create_and_announce(
                                    &coordinator,
                                    local_runtime.as_ref(),
                                    OfferInput::Path(path),
                                )?);
                            }
                            Ok(statuses.join("; "))
                        }
                    });
                drop(permit);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = status_window.upgrade() {
                        window.set_status_text(result.unwrap_or_else(|error| error).into());
                    }
                });
            });
        });
    }

    {
        let window_weak = window.as_weak();
        let coordinator = coordinator.clone();
        let app_state = app_state.clone();
        let offer_store = offer_store.clone();
        let clipboard = clipboard.clone();
        let activations = activations.clone();
        let active_activations = active_activations.clone();
        let activation_gate = activation_gate.clone();
        let data_dir = data_dir.clone();
        let peer_names = peer_names.clone();
        let server = server.clone();
        let refresh_gate = refresh_gate.clone();
        let card_store = card_store.clone();
        window.on_activate_offer(move |offer_id_text, mode_text| {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let Ok(offer_id) = offer_id_text.as_str().parse::<OfferId>() else {
                window.set_status_text("The shelf offer ID is invalid".into());
                return;
            };
            let mode = match mode_text.as_str() {
                "clipboard" => ActivationMode::Clipboard,
                "save" => ActivationMode::Save,
                _ => {
                    window.set_status_text("The activation mode is invalid".into());
                    return;
                }
            };
            window.set_status_text("Checking mesh reachability…".into());
            let completion_window = window_weak.clone();
            let coordinator = coordinator.clone();
            let app_state = app_state.clone();
            let offer_store = offer_store.clone();
            let clipboard = clipboard.clone();
            let activations = activations.clone();
            let active_activations = active_activations.clone();
            let activation_gate = activation_gate.clone();
            let data_dir = data_dir.clone();
            let peer_names = peer_names.clone();
            let action_window = window_weak.clone();
            let started =
                discovery_events.dispatch(DiscoveryRefreshTrigger::BeforeUserOperation, || {
                    refresh_in_background(
                        app_state.clone(),
                        peer_names.clone(),
                        server.clone(),
                        offer_store.clone(),
                        card_store.clone(),
                        refresh_gate.clone(),
                        move |refresh_result| {
                            let Some(window) = completion_window.upgrade() else {
                                return;
                            };
                            let view = match refresh_result {
                                Ok(view) => view,
                                Err(error) => {
                                    apply_refresh_error(&window, error);
                                    return;
                                }
                            };
                            apply_peer_view(&window, view);
                            let plan = match coordinator.plan_activation(offer_id, mode) {
                                Ok(plan) => plan,
                                Err(error) => {
                                    window.set_status_text(error.into());
                                    return;
                                }
                            };
                            if active_activations
                                .lock()
                                .map(|active| active.contains_key(&offer_id))
                                .unwrap_or(true)
                            {
                                window.set_status_text(
                                    "This offer is already activating; nothing queued".into(),
                                );
                                return;
                            }
                            if let Err(error) = clipboard_for_activation(mode, clipboard.clone()) {
                                window.set_status_text(error.into());
                                return;
                            }
                            let Some(permit) = activation_gate.try_enter() else {
                                window.set_status_text(
                                    "Two activations are already in progress; nothing queued"
                                        .into(),
                                );
                                return;
                            };
                            let input = match app_state
                                .lock()
                                .map_err(|_| "app state is unavailable".to_owned())
                                .and_then(|state| build_activation_input(&plan, &state))
                            {
                                Ok(input) => input,
                                Err(error) => {
                                    drop(permit);
                                    window.set_status_text(error.into());
                                    return;
                                }
                            };
                            let (cancel, cancel_receiver) = watch::channel(false);
                            if !register_active_activation(
                                &active_activations,
                                offer_id,
                                ActiveActivation {
                                    cancel,
                                    progress: "Pulling…".to_owned(),
                                },
                            ) {
                                drop(permit);
                                window.set_status_text(
                                    "This offer is already activating; nothing queued".into(),
                                );
                                return;
                            }
                            window.set_status_text(
                                if mode == ActivationMode::Save {
                                    "Pulling offer to the configured destination…"
                                } else {
                                    "Pulling offer to the clipboard…"
                                }
                                .into(),
                            );
                            refresh_shelf_in_background(
                                action_window.clone(),
                                offer_store.clone(),
                                peer_names.clone(),
                                active_activations.clone(),
                            );
                            let window_weak = action_window;
                            let offer_store = offer_store.clone();
                            let active_activations = active_activations.clone();
                            let peer_names = peer_names.clone();
                            let _state_root = data_dir.clone();
                            thread::spawn(move || {
                                let result = run_activation(input, activations, cancel_receiver);
                                remove_active_activation(&active_activations, offer_id);
                                drop(permit);
                                let status_window = window_weak.clone();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(window) = status_window.upgrade() {
                                        window.set_status_text(
                                            result
                                                .map(|outcome| outcome.desktop_status())
                                                .unwrap_or_else(|error| error)
                                                .into(),
                                        );
                                    }
                                });
                                refresh_shelf_in_background(
                                    window_weak,
                                    offer_store,
                                    peer_names,
                                    active_activations,
                                );
                            });
                        },
                    )
                });
            if !started {
                window.set_status_text("Mesh refresh is already in progress".into());
            }
        });
    }

    {
        let window_weak = window.as_weak();
        let active_activations = active_activations.clone();
        window.on_cancel_activation(move |offer_id_text| {
            let Ok(offer_id) = offer_id_text.as_str().parse::<OfferId>() else {
                return;
            };
            if let Ok(active) = active_activations.lock()
                && let Some(activation) = active.get(&offer_id)
            {
                let _ = activation.cancel.send(true);
                if let Some(window) = window_weak.upgrade() {
                    window.set_status_text("Cancelling activation…".into());
                }
            }
        });
    }

    {
        let window_weak = window.as_weak();
        let app_state = app_state.clone();
        let peer_names = peer_names.clone();
        let server = server.clone();
        let offer_store_for_refresh = offer_store.clone();
        let refresh_gate = refresh_gate.clone();
        let card_store = card_store.clone();
        let active_activations = active_activations.clone();
        window.on_refresh_peers(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            refresh_shelf_in_background(
                window_weak.clone(),
                offer_store_for_refresh.clone(),
                peer_names.clone(),
                active_activations.clone(),
            );
            let started = discovery_events.dispatch(DiscoveryRefreshTrigger::Explicit, || {
                refresh_in_background(
                    app_state.clone(),
                    peer_names.clone(),
                    server.clone(),
                    offer_store_for_refresh.clone(),
                    card_store.clone(),
                    refresh_gate.clone(),
                    {
                        let window_weak = window_weak.clone();
                        move |result| {
                            if let Some(window) = window_weak.upgrade() {
                                match result {
                                    Ok(view) => apply_peer_view(&window, view),
                                    Err(error) => apply_refresh_error(&window, error),
                                }
                            }
                        }
                    },
                )
            });
            window.set_status_text(
                if started {
                    "Refreshing mesh devices…"
                } else {
                    "Mesh refresh is already in progress"
                }
                .into(),
            );
        });
    }

    {
        let window_weak = window.as_weak();
        let coordinator = coordinator.clone();
        window.on_choose_folder(move || {
            let window_weak = window_weak.clone();
            let coordinator = coordinator.clone();
            thread::spawn(move || {
                let result = choose_folder()
                    .map(|path| {
                        let mut settings = settings_for_surface(&coordinator)?;
                        settings.save_destination = SaveDestination::Custom { path };
                        update_settings_from_surface(&coordinator, settings)
                    })
                    .transpose();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_weak.upgrade() {
                        match result {
                            Ok(Some(settings)) => window.set_destination_text(
                                destination_label(&settings.save_destination).into(),
                            ),
                            Ok(None) => {}
                            Err(error) => window.set_status_text(error.to_string().into()),
                        }
                    }
                });
            });
        });
    }

    {
        let window_weak = window.as_weak();
        let coordinator = coordinator.clone();
        window.on_reset_destination(move || {
            let coordinator = coordinator.clone();
            let window_weak = window_weak.clone();
            thread::spawn(move || {
                let result = settings_for_surface(&coordinator).and_then(|mut settings| {
                    settings.save_destination = SaveDestination::Downloads;
                    update_settings_from_surface(&coordinator, settings)
                });
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_weak.upgrade() {
                        match result {
                            Ok(settings) => window.set_destination_text(
                                destination_label(&settings.save_destination).into(),
                            ),
                            Err(error) => window.set_status_text(error.into()),
                        }
                    }
                });
            });
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_open_window(move || {
            if let Some(window) = window_weak.upgrade() {
                raise_window(&window);
            }
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_send_default(move || {
            if let Some(window) = window_weak.upgrade() {
                window.set_status_text(
                    format!(
                        "Press {} to add the clipboard to the mesh",
                        paste_shortcut()
                    )
                    .into(),
                );
                raise_window(&window);
            }
        });
    }

    tray.on_quit(|| {
        let _ = slint::quit_event_loop();
    });

    window.show()?;
    tray.show()?;
    let shelf_changes = coordinator.shelf_changes().subscribe();
    {
        let window_weak = window.as_weak();
        let offer_store = offer_store.clone();
        let peer_names = peer_names.clone();
        let active_activations = active_activations.clone();
        thread::spawn(move || {
            while shelf_changes.recv().is_ok() {
                refresh_shelf_in_background(
                    window_weak.clone(),
                    offer_store.clone(),
                    peer_names.clone(),
                    active_activations.clone(),
                );
            }
        });
    }
    refresh_shelf_in_background(
        window.as_weak(),
        offer_store.clone(),
        peer_names.clone(),
        active_activations.clone(),
    );
    discovery_events.dispatch(DiscoveryRefreshTrigger::Launch, || {
        refresh_in_background(
            app_state,
            peer_names,
            server,
            offer_store,
            card_store,
            refresh_gate,
            {
                let window_weak = window.as_weak();
                move |result| {
                    if let Some(window) = window_weak.upgrade() {
                        match result {
                            Ok(view) => apply_peer_view(&window, view),
                            Err(error) => apply_refresh_error(&window, error),
                        }
                    }
                }
            },
        )
    });
    slint::run_event_loop()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::{
        Model,
        platform::{Key, WindowEvent},
    };

    #[test]
    fn mixed_family_peer_selects_listener_family_for_bind_and_activation() {
        let ipv6 = "::1".parse().expect("ipv6");
        let ipv4 = "127.0.0.1".parse().expect("ipv4");
        let addresses = [ipv6, ipv4];
        let bind = select_discovered_ip(&addresses).expect("bind");
        let dial = select_discovered_socket(&addresses, MESHELF_PORT).expect("dial");
        assert_eq!(bind, ipv4);
        assert_eq!(dial.ip(), bind);
    }

    #[test]
    fn operation_gate_allows_only_one_in_flight_operation() {
        let gate = OperationGate::default();
        let first = gate.try_enter().expect("first operation starts");
        assert!(gate.try_enter().is_none());
        drop(first);
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn discovery_has_no_repeating_timer() {
        let refreshes = Arc::new(AtomicUsize::new(0));
        let observed = refreshes.clone();
        assert!(
            DiscoveryEventLoop.dispatch(DiscoveryRefreshTrigger::Launch, move || {
                observed.fetch_add(1, Ordering::SeqCst);
                true
            })
        );

        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn launch_refreshes_reachability_once() {
        let refreshes = Arc::new(AtomicUsize::new(0));
        let observed = refreshes.clone();
        assert!(
            DiscoveryEventLoop.dispatch(DiscoveryRefreshTrigger::Launch, move || {
                observed.fetch_add(1, Ordering::SeqCst);
                true
            })
        );
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn explicit_refresh_updates_reachability() {
        let reachability = Arc::new(Mutex::new("stale".to_owned()));
        let observed = reachability.clone();
        assert!(
            DiscoveryEventLoop.dispatch(DiscoveryRefreshTrigger::Explicit, move || {
                *observed.lock().expect("reachability state") = "BZOT".to_owned();
                true
            })
        );
        assert_eq!(*reachability.lock().expect("reachability state"), "BZOT");
    }

    #[test]
    fn user_operation_refreshes_reachability_before_acting() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let observed = order.clone();
        assert!(DiscoveryEventLoop.dispatch(
            DiscoveryRefreshTrigger::BeforeUserOperation,
            move || {
                observed.lock().expect("event order").push("refresh");
                true
            },
        ));
        order.lock().expect("event order").push("act");
        assert_eq!(*order.lock().expect("event order"), ["refresh", "act"]);
    }

    #[test]
    fn generated_ui_status_tooltip_uses_reachable_list() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        apply_peer_view(
            &window,
            PeerView {
                name: "BZOT".to_owned(),
                online: true,
                status: "2 devices reachable · paste text or copied files".to_owned(),
                reachable_names: "BMBA\nBZOT".to_owned(),
            },
        );

        assert_eq!(window.get_reachable_names().as_str(), "BMBA\nBZOT");
    }

    #[test]
    fn failed_refresh_does_not_leave_stale_reachable_names() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        apply_peer_view(
            &window,
            PeerView {
                name: "BZOT".to_owned(),
                online: true,
                status: "1 device reachable · paste text or copied files".to_owned(),
                reachable_names: "BZOT".to_owned(),
            },
        );

        apply_refresh_error(&window, "Refresh failed".to_owned());

        assert_eq!(
            window.get_reachable_names().as_str(),
            "Reachability unavailable"
        );
    }

    fn test_card(descriptor: OfferDescriptor, availability: CardAvailability) -> OfferCardRecord {
        OfferCardRecord {
            source_device: DeviceId::new(),
            offer_id: OfferId::new(),
            descriptor,
            received_sequence: 1,
            availability,
            last_attempt: None,
        }
    }

    fn production_row(record: OfferCardRecord, progress: Option<String>) -> ShelfRow {
        shelf_row(&HashMap::new(), 0, record, progress)
    }

    fn row_text(row: &ShelfRow) -> String {
        [
            row.icon.as_str(),
            row.offer_id.as_str(),
            row.kind.as_str(),
            row.origin_device.as_str(),
            row.name.as_str(),
            row.size.as_str(),
            row.preview.as_str(),
            row.counts.as_str(),
            row.availability.as_str(),
            row.progress.as_str(),
            row.detail.as_str(),
            row.shortcut.as_str(),
            row.save_shortcut.as_str(),
        ]
        .join(" ")
    }

    fn dispatch_shortcut(window: &MainWindow, modifier: Key, key: &str, repeat: bool) {
        window.window().dispatch_event(WindowEvent::KeyPressed {
            text: modifier.into(),
        });
        let event = if repeat {
            WindowEvent::KeyPressRepeated { text: key.into() }
        } else {
            WindowEvent::KeyPressed { text: key.into() }
        };
        window.window().dispatch_event(event);
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text: key.into() });
        window.window().dispatch_event(WindowEvent::KeyReleased {
            text: modifier.into(),
        });
    }

    #[test]
    fn text_shelf_row_contains_preview_but_not_the_full_text() {
        let full_text = format!("unique-full-text-{}", "x".repeat(400));
        let descriptor = OfferDescriptor::text(&full_text).expect("descriptor");
        let expected_preview = match &descriptor {
            OfferDescriptor::Text { preview, .. } => preview.clone(),
            _ => unreachable!(),
        };
        let row = production_row(test_card(descriptor, CardAvailability::Available), None);
        assert_eq!(row.preview.as_str(), expected_preview);
        assert!(row.preview.len() <= meshelf_core::MAX_OFFER_PREVIEW_BYTES);
        assert!(row.preview.len() < full_text.len());
        assert!(!row_text(&row).contains(&full_text));
    }

    #[test]
    fn file_shelf_row_contains_no_receiver_path_before_activation() {
        let row = production_row(
            test_card(
                OfferDescriptor::File {
                    root_name: "report.txt".to_owned(),
                    total_bytes: 42,
                },
                CardAvailability::Available,
            ),
            None,
        );
        let row_text = row_text(&row);
        assert!(row_text.contains("report.txt"));
        assert!(!row_text.contains('/'));
        assert!(!row_text.contains('\\'));
        assert_eq!(row.kind.as_str(), "File");
        assert!(row.can_save);
    }

    #[test]
    fn primary_card_activation_routes_clipboard_mode() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let card = test_card(
            OfferDescriptor::Text {
                utf8_bytes: 5,
                line_count: 1,
                preview: "hello".to_owned(),
            },
            CardAvailability::Available,
        );
        let offer_id = card.offer_id.to_string();
        let events = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let captured = events.clone();
        window.on_activate_offer(move |offer, mode| {
            captured
                .lock()
                .expect("activation events")
                .push((offer.to_string(), mode.to_string()));
        });
        window.set_shelf_items(ModelRc::new(VecModel::from(vec![production_row(
            card, None,
        )])));
        dispatch_shortcut(&window, Key::Control, "1", false);
        assert_eq!(
            *events.lock().expect("activation events"),
            vec![(offer_id, "clipboard".to_owned())]
        );
    }

    #[test]
    fn alternate_file_activation_routes_save_mode() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let card = test_card(
            OfferDescriptor::File {
                root_name: "report.txt".to_owned(),
                total_bytes: 42,
            },
            CardAvailability::Available,
        );
        let offer_id = card.offer_id.to_string();
        let events = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let captured = events.clone();
        window.on_activate_offer(move |offer, mode| {
            captured
                .lock()
                .expect("activation events")
                .push((offer.to_string(), mode.to_string()));
        });
        window.set_shelf_items(ModelRc::new(VecModel::from(vec![production_row(
            card, None,
        )])));
        dispatch_shortcut(&window, Key::Alt, "1", false);
        assert_eq!(
            *events.lock().expect("activation events"),
            vec![(offer_id, "save".to_owned())]
        );
    }

    #[test]
    fn alternate_activation_is_refused_while_that_offer_is_active() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = events.clone();
        window.on_activate_offer(move |offer, mode| {
            captured
                .lock()
                .expect("activation events")
                .push(format!("{}:{}", offer, mode));
        });
        let card = test_card(
            OfferDescriptor::File {
                root_name: "report.txt".to_owned(),
                total_bytes: 42,
            },
            CardAvailability::Available,
        );
        let row = production_row(card, Some("Pulling…".to_owned()));
        assert!(row.can_save);
        assert!(!row.can_activate);
        window.set_shelf_items(ModelRc::new(VecModel::from(vec![row])));

        dispatch_shortcut(&window, Key::Alt, "1", false);

        assert!(events.lock().expect("activation events").is_empty());
    }

    #[test]
    fn save_activation_does_not_require_a_clipboard_adapter() {
        assert!(
            clipboard_for_activation(ActivationMode::Save, None)
                .expect("save mode")
                .is_none()
        );
        assert!(clipboard_for_activation(ActivationMode::Clipboard, None).is_err());
    }

    #[test]
    fn a_second_activation_does_not_drop_the_first_cancel_handle() {
        let active = ActiveActivations::default();
        let offer_id = OfferId::new();
        let (first_cancel, first_receiver) = watch::channel(false);
        assert!(register_active_activation(
            &active,
            offer_id,
            ActiveActivation {
                cancel: first_cancel,
                progress: "Pulling…".to_owned(),
            },
        ));
        let (second_cancel, _second_receiver) = watch::channel(false);
        assert!(!register_active_activation(
            &active,
            offer_id,
            ActiveActivation {
                cancel: second_cancel,
                progress: "Pulling…".to_owned(),
            },
        ));

        active
            .lock()
            .expect("active activations")
            .get(&offer_id)
            .expect("first activation remains")
            .cancel
            .send(true)
            .expect("first cancel handle");
        assert!(first_receiver.has_changed().expect("first cancel state"));
        assert!(*first_receiver.borrow());
    }

    #[test]
    fn alternate_text_activation_is_refused_locally_without_a_network_request() {
        let directory = TestDirectory::new();
        let identity = meshelf_identity::InstallationIdentity::generate();
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("offers.redb")).expect("offer store"));
        let card = test_card(
            OfferDescriptor::Text {
                utf8_bytes: 5,
                line_count: 1,
                preview: "hello".to_owned(),
            },
            CardAvailability::Available,
        );
        let offer_id = card.offer_id;
        store
            .insert_offer_card(meshelf_core::OfferCardInput::new(
                card.source_device,
                card.offer_id,
                card.descriptor,
                card.availability,
            ))
            .expect("card");
        let coordinator = Coordinator::new(
            identity.device_id,
            InstallationStore::new(directory.path().join("state.json")),
            store.clone(),
        )
        .with_card_store(store);
        let error = coordinator
            .plan_activation(offer_id, ActivationMode::Save)
            .expect_err("text save mode must be refused before transport");
        assert!(error.contains("text offers cannot use save activation"));
    }

    #[test]
    fn shortcut_repeat_is_suppressed_for_both_modes() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = events.clone();
        window.on_activate_offer(move |_offer, mode| {
            captured
                .lock()
                .expect("activation events")
                .push(mode.to_string());
        });
        window.set_shelf_items(ModelRc::new(VecModel::from(vec![production_row(
            test_card(
                OfferDescriptor::File {
                    root_name: "report.txt".to_owned(),
                    total_bytes: 42,
                },
                CardAvailability::Available,
            ),
            None,
        )])));
        dispatch_shortcut(&window, Key::Control, "1", false);
        dispatch_shortcut(&window, Key::Control, "1", true);
        dispatch_shortcut(&window, Key::Alt, "1", false);
        dispatch_shortcut(&window, Key::Alt, "1", true);
        assert_eq!(
            *events.lock().expect("activation events"),
            vec!["clipboard".to_owned(), "save".to_owned()]
        );
    }

    #[test]
    fn refresh_shortcut_routes_once_and_uses_the_platform_label() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let refreshes = Arc::new(AtomicUsize::new(0));
        let observed = refreshes.clone();
        window.on_refresh_peers(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        });
        window.set_refresh_shortcut(refresh_shortcut().into());
        dispatch_shortcut(&window, Key::Control, "r", false);
        dispatch_shortcut(&window, Key::Control, "r", true);
        dispatch_shortcut(&window, Key::Meta, "r", false);
        dispatch_shortcut(&window, Key::Meta, "r", true);
        assert_eq!(refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(window.get_refresh_shortcut().as_str(), refresh_shortcut());
    }

    #[test]
    fn third_activation_shows_busy_and_queues_nothing() {
        let gate = ActivationGate::default();
        let first = gate.try_enter().expect("first activation starts");
        let second = gate.try_enter().expect("second activation starts");
        assert!(gate.try_enter().is_none());
        drop(first);
        drop(second);
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn source_changed_status_disables_the_card() {
        let row = production_row(
            test_card(
                OfferDescriptor::File {
                    root_name: "report.txt".to_owned(),
                    total_bytes: 42,
                },
                CardAvailability::SourceChanged,
            ),
            None,
        );
        assert_eq!(row.availability.as_str(), "source changed");
        assert!(!row.can_activate);
    }

    #[test]
    fn offline_status_keeps_manual_retry_available() {
        let row = production_row(
            test_card(
                OfferDescriptor::Text {
                    utf8_bytes: 5,
                    line_count: 1,
                    preview: "hello".to_owned(),
                },
                CardAvailability::SourceUnavailable,
            ),
            None,
        );
        assert!(row.can_activate);
        assert_eq!(row.availability.as_str(), "source unavailable");
    }

    #[test]
    fn settings_ui_reads_and_writes_only_through_the_controller() {
        let directory = TestDirectory::new();
        let identity = meshelf_identity::InstallationIdentity::generate();
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("offers.redb")).expect("offer store"));
        let coordinator = Coordinator::new(
            identity.device_id,
            InstallationStore::new(directory.path().join("state.json")),
            store,
        );
        assert_eq!(
            settings_for_surface(&coordinator)
                .expect("settings")
                .save_destination,
            SaveDestination::Downloads
        );
        let destination = directory.path().join("chosen");
        let mut settings = settings_for_surface(&coordinator).expect("settings");
        settings.save_destination = SaveDestination::Custom {
            path: destination.clone(),
        };
        update_settings_from_surface(&coordinator, settings).expect("write settings");
        assert_eq!(
            settings_for_surface(&coordinator)
                .expect("settings")
                .save_destination,
            SaveDestination::Custom { path: destination }
        );
    }

    #[test]
    fn custom_destination_change_affects_future_activations_only() {
        let directory = TestDirectory::new();
        let identity = meshelf_identity::InstallationIdentity::generate();
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("offers.redb")).expect("offer store"));
        let card = test_card(
            OfferDescriptor::File {
                root_name: "report.txt".to_owned(),
                total_bytes: 42,
            },
            CardAvailability::Available,
        );
        store
            .insert_offer_card(meshelf_core::OfferCardInput::new(
                card.source_device,
                card.offer_id,
                card.descriptor,
                card.availability,
            ))
            .expect("card");
        let coordinator = Coordinator::new(
            identity.device_id,
            InstallationStore::new(directory.path().join("state.json")),
            store.clone(),
        )
        .with_card_store(store);
        let first_destination = directory.path().join("first");
        let second_destination = directory.path().join("second");
        let mut settings = settings_for_surface(&coordinator).expect("settings");
        settings.save_destination = SaveDestination::Custom {
            path: first_destination.clone(),
        };
        update_settings_from_surface(&coordinator, settings).expect("first setting");
        let first = coordinator
            .plan_activation(card.offer_id, ActivationMode::Save)
            .expect("first plan");
        let mut settings = settings_for_surface(&coordinator).expect("settings");
        settings.save_destination = SaveDestination::Custom {
            path: second_destination.clone(),
        };
        update_settings_from_surface(&coordinator, settings).expect("second setting");
        let second = coordinator
            .plan_activation(card.offer_id, ActivationMode::Save)
            .expect("second plan");
        assert_eq!(
            first.destination,
            Some(SaveDestination::Custom {
                path: first_destination
            })
        );
        assert_eq!(
            second.destination,
            Some(SaveDestination::Custom {
                path: second_destination
            })
        );
    }

    #[test]
    fn shelf_updates_without_a_timer() {
        let directory = TestDirectory::new();
        let source = meshelf_identity::InstallationIdentity::generate();
        let target = meshelf_identity::InstallationIdentity::generate();
        let store = Arc::new(
            RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
        );
        let coordinator = Coordinator::new(
            target.device_id,
            InstallationStore::new(directory.path().join("state.json")),
            store.clone(),
        )
        .with_card_store(store.clone());
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
        let offer_id = announcement.offer_id;

        let ack = handler
            .handle_sync(source.device_id, target.device_id, announcement)
            .expect("announcement");

        assert_eq!(ack.code, meshelf_protocol::OfferAckCode::Stored);
        assert!(subscriber.recv_timeout(Duration::from_millis(50)).is_ok());

        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let peer_names = Mutex::new(HashMap::new());
        let active: ActiveActivations = Arc::new(Mutex::new(HashMap::new()));
        let snapshot = load_shelf_snapshot(&store, &peer_names, &active).expect("shelf snapshot");
        apply_shelf_snapshot(&window, snapshot);
        let row = window
            .get_shelf_items()
            .row_data(0)
            .expect("announced shelf row");
        assert_eq!(row.offer_id.as_str(), offer_id.to_string());
    }
}
