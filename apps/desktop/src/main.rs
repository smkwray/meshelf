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
    ActivationPlan, AnnouncePeerState, AnnouncePeerUpdate, Controller, MESHELF_PORT,
    MeshSendReport, PeerView, announce_offer_plan, announce_offer_plan_with_progress,
    capture::{CaptureControl, CaptureHandle, CaptureService, CaptureServiceConfig},
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
    ActivationOutcome, ActivationService, CaptureAnnouncementRouter, FetchActivation,
    FetchClipboard, InstallationTrustGate, OfferAnnouncementHandler, OfferCardStore,
    OfferFetchHandler, PeerClient, ServerIdentity, StoreCatalogOrigin, TrustGate,
    V2CaptureReceiver, V2OfferServices, V2ServerConfig, bind_discovered_tailscale_std_listener,
    select_discovered_ip, select_discovered_socket, serve_v2,
};
use meshelf_platform::{
    ClipboardItem, ClipboardSource, ClipboardWorker, acquire_resident_lock, choose_folder,
    listen_with_control, resolve_save_destination, signal,
};
#[cfg(test)]
use meshelf_protocol::OfferAnnouncement;
use meshelf_protocol::{ClientHello, FetchRequest};
use meshelf_store::{CaptureRequestReconciliation, RedbV2Store};
use meshelf_tailscale::InstallationStore;
use slint::{ComponentHandle, ModelRc, VecModel};
use tokio::{
    runtime::{Builder, Runtime},
    sync::watch,
};
use tracing_subscriber::EnvFilter;

slint::include_modules!();

struct ServerHandle {
    address: SocketAddr,
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

/// This resident's capture transport, in the one form the rest of the app may hold it.
///
/// Only [`start_capture_resident`] can make one, and that is the only place startup
/// reconciliation runs, so a listener cannot be bound for a capture service whose leftover
/// requests have not been ended first. Everything inside is an `Arc`, so a clone is a handle,
/// not a second service.
#[derive(Clone)]
struct CaptureWiring(Arc<CaptureService<ActivationClipboard>>);

impl CaptureWiring {
    /// Records an incoming status durably before it is acknowledged (invariant 11).
    fn receiver(&self) -> Arc<dyn V2CaptureReceiver> {
        self.0.receiver()
    }

    /// Sends a correlated announcement to its capture request instead of the shelf.
    fn router(&self) -> Arc<dyn CaptureAnnouncementRouter> {
        self.0.router()
    }

    /// The seam the local-control channel routes `capture` requests through.
    fn control(&self) -> CaptureHandle<ActivationClipboard> {
        self.0.handle()
    }

    /// The loopback port a `--wait` caller connects to.
    fn wait_port(&self) -> u16 {
        self.0.wait_port()
    }

    /// Wakes every attached waiter with `resident_shutdown`.
    fn shutdown(&self) {
        self.0.shutdown();
    }
}

/// Starts the capture service and ends every request the previous run left behind.
///
/// Ordering is load-bearing and checked, not merely documented: activation recovery clears
/// abandoned journals first, reconciliation then ends the leftover capture requests, and only
/// the [`CaptureWiring`] this returns lets the network listener bind. A capture request that
/// survived a restart is never resumed, so reconciling after the listener is live would let a
/// stale announcement claim a grant this resident can no longer honour.
fn start_capture_resident(
    config: CaptureServiceConfig<ActivationClipboard>,
) -> Result<(CaptureWiring, CaptureRequestReconciliation), String> {
    if config.activations.recovery_runs() == 0 {
        return Err(
            "capture reconciliation must run after activation recovery, not before".to_owned(),
        );
    }
    let service = CaptureService::start(config)
        .map_err(|error| format!("could not start the capture service: {error}"))?;
    // On this error the `Arc` is dropped here, on the calling thread: the service owns a
    // multi-thread runtime, and dropping one inside an async context panics.
    let reconciliation = service.reconcile_at_startup()?;
    Ok((CaptureWiring(service), reconciliation))
}

/// What the desktop answers when local control asks for its capture engine.
///
/// The desktop always has one — `main` refuses to start without it — so it answers for itself
/// instead of taking [`LocalRuntime::capture`]'s default `None`, which reports
/// `resident_unavailable` and would make every `meshelfctl capture` command fail against a
/// running desktop.
fn desktop_capture_control(
    capture: &CaptureHandle<ActivationClipboard>,
) -> Option<&dyn CaptureControl> {
    Some(capture)
}

struct DesktopLocalRuntime {
    app_state: Arc<Mutex<Controller>>,
    state_path: PathBuf,
    identity: meshelf_identity::InstallationIdentity,
    device_name: String,
    clipboard: Option<ClipboardWorker>,
    activations: Arc<ActivationService<ActivationClipboard>>,
    capture: CaptureHandle<ActivationClipboard>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerIndicatorState {
    Reachable,
    Pending,
    Stored,
    Unavailable,
}

#[derive(Debug, Clone)]
struct PeerIndicatorEntry {
    name: String,
    state: PeerIndicatorState,
}

type PeerIndicatorStates = Arc<Mutex<HashMap<DeviceId, PeerIndicatorEntry>>>;

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

    fn capture(&self) -> Option<&dyn CaptureControl> {
        desktop_capture_control(&self.capture)
    }
}

impl DesktopLocalRuntime {
    fn announce_with_progress(
        &self,
        plan: &OfferPlan,
        on_update: Arc<dyn Fn(AnnouncePeerUpdate) + Send + Sync>,
    ) -> Result<MeshSendReport, String> {
        announce_offer_plan_with_progress(
            &self.state_path,
            &self.identity,
            &self.device_name,
            plan,
            on_update,
        )
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

impl ServerHandle {
    fn needs_restart(&self, address: SocketAddr) -> bool {
        self.address != address
            || self
                .worker
                .as_ref()
                .map(JoinHandle::is_finished)
                .unwrap_or(true)
    }
}

/// The announcement receiver for this resident: correlated announcements go to their capture
/// request before any shelf read or insert, so a photo never evicts a shelf entry. Without the
/// router every correlated announcement is refused `capture_not_armed`.
fn desktop_announcement_handler(
    card_store: Arc<dyn OfferCardStore>,
    capture: &CaptureWiring,
) -> OfferAnnouncementHandler {
    OfferAnnouncementHandler::new(card_store).with_capture_router(capture.router())
}

/// The desktop listener's configuration. It is `V2ServerConfig::desktop` — offers and fetches,
/// `offer-pull-v2` on acceptance and on refusal (O-003), no pairing — except that captures reach
/// this resident's own receiver, which records a status durably before acknowledging it.
/// `V2ServerConfig::desktop` alone installs `UnsupportedCaptureReceiver`, which would leave this
/// device advertising nothing it could answer and its own requests unfinishable.
fn desktop_v2_config(
    identity: ServerIdentity,
    gate: Arc<dyn TrustGate>,
    services: V2OfferServices,
    capture: &CaptureWiring,
    io_timeout: Duration,
) -> V2ServerConfig {
    V2ServerConfig {
        capture_receiver: capture.receiver(),
        ..V2ServerConfig::desktop(identity, gate, services, io_timeout)
    }
}

/// Everything the v2 listener is built from. They travel together because a listener is only
/// ever built from all three, and because [`CaptureWiring`] can only exist after startup
/// reconciliation has run.
#[derive(Clone)]
struct ListenerServices {
    offer_store: Arc<RedbV2Store>,
    card_store: Arc<dyn OfferCardStore>,
    capture: CaptureWiring,
}

fn start_v2_listener(
    state: &Controller,
    services: ListenerServices,
) -> Result<ServerHandle, String> {
    let ListenerServices {
        offer_store,
        card_store,
        capture,
    } = services;
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
    let offer_receiver = Arc::new(desktop_announcement_handler(card_store, &capture));
    let catalog_store = Arc::clone(&offer_store);
    let origin_device = state.installation.device_id;
    let fetch_sender = Arc::new(OfferFetchHandler::new(
        state.installation.device_id,
        offer_store,
    ));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let identity = ServerIdentity {
        signing_identity: state.identity.clone(),
        device_name: state.device_name.clone(),
    };
    let gate = Arc::new(InstallationTrustGate::new(
        InstallationStore::new(state.state_path.clone()),
        state.identity.device_id,
    ));
    let worker = thread::Builder::new()
        .name("meshelf-network-v2".to_owned())
        .spawn(move || {
            // Declared before the runtime, so it is dropped after it. The capture service owns a
            // multi-thread tokio runtime, and dropping a runtime from inside another runtime's
            // context panics; this reference makes sure the receiver and router clones that
            // `serve_v2` releases inside `block_on` can never be the last ones.
            let capture_outlives_runtime = capture;
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
            if let Err(error) = runtime.block_on(serve_v2(
                listener,
                desktop_v2_config(
                    identity,
                    gate,
                    V2OfferServices {
                        announcement_receiver: offer_receiver,
                        fetch_sender,
                    },
                    &capture_outlives_runtime,
                    Duration::from_secs(5),
                )
                .with_catalog_origin(Arc::new(StoreCatalogOrigin::new(
                    catalog_store,
                    origin_device,
                ))),
                shutdown_rx,
            )) {
                tracing::error!(%error, "meshelf v2 listener stopped unexpectedly");
            }
            drop(runtime);
            drop(capture_outlives_runtime);
        })
        .map_err(|error| format!("could not start Tailscale v2 listener: {error}"))?;
    Ok(ServerHandle {
        address: SocketAddr::new(address, MESHELF_PORT),
        shutdown,
        worker: Some(worker),
    })
}

fn peer_indicator_priority(state: PeerIndicatorState) -> u8 {
    match state {
        PeerIndicatorState::Reachable
        | PeerIndicatorState::Pending
        | PeerIndicatorState::Stored => 0,
        PeerIndicatorState::Unavailable => 1,
    }
}

fn peer_indicator_display_width(name: &str) -> f32 {
    // Keep a little slack around the 10px UI font so the measured layout does not clip
    // device names at the same width at which it decides they fit.
    18.0 + name.chars().count() as f32 * 6.5
}

fn render_peer_indicators(window: &MainWindow, states: &PeerIndicatorStates) {
    let Ok(states) = states.lock() else {
        return;
    };
    let mut entries = states.values().cloned().collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| {
        peer_indicator_priority(left.state)
            .cmp(&peer_indicator_priority(right.state))
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
    });
    let available_width = window.get_peer_indicator_width();
    let total_width = entries
        .iter()
        .map(|entry| peer_indicator_display_width(&entry.name))
        .sum::<f32>()
        + 7.0 * entries.len().saturating_sub(1) as f32;
    let visible_count =
        if entries.is_empty() || available_width <= 0.0 || total_width <= available_width {
            entries.len()
        } else {
            let mut used = 0.0;
            let mut count = 0;
            for candidate in 0..entries.len() {
                if candidate > 0 {
                    used += peer_indicator_display_width(&entries[candidate - 1].name);
                    if candidate > 1 {
                        used += 7.0;
                    }
                }
                let hidden_count = entries.len() - candidate;
                let overflow_width = 18.0 + (hidden_count.to_string().len() as f32 * 6.5);
                let overflow_separator = if candidate == 0 { 0.0 } else { 7.0 };
                if used + overflow_separator + overflow_width <= available_width {
                    count = candidate;
                }
            }
            count
        };
    let hidden = &entries[visible_count..];
    let overflow_width = if hidden.is_empty() {
        0.0
    } else {
        18.0 + (hidden.len().to_string().len() as f32 * 6.5)
    };
    let indicators = entries
        .iter()
        .take(visible_count)
        .map(|entry| PeerIndicator {
            name: entry.name.clone().into(),
            state: match entry.state {
                PeerIndicatorState::Pending => "pending",
                PeerIndicatorState::Reachable | PeerIndicatorState::Stored => "online",
                PeerIndicatorState::Unavailable => "offline",
            }
            .into(),
            display_width: peer_indicator_display_width(&entry.name),
        })
        .collect::<Vec<_>>();
    window.set_peer_indicators(ModelRc::new(VecModel::from(indicators)));
    window.set_peer_overflow(if hidden.is_empty() {
        "".into()
    } else {
        format!("+{}", hidden.len()).into()
    });
    window.set_peer_overflow_width(overflow_width);
    window.set_peer_overflow_names(
        hidden
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            .into(),
    );
}

fn apply_peer_view(window: &MainWindow, states: &PeerIndicatorStates, view: PeerView) {
    if let Ok(mut states) = states.lock() {
        states.retain(|_, entry| entry.state == PeerIndicatorState::Pending);
        for peer in view.peer_statuses {
            if states.contains_key(&peer.device_id) {
                continue;
            }
            states.insert(
                peer.device_id,
                PeerIndicatorEntry {
                    name: peer.name,
                    state: if peer.reachable {
                        PeerIndicatorState::Reachable
                    } else {
                        PeerIndicatorState::Unavailable
                    },
                },
            );
        }
    }
    render_peer_indicators(window, states);
    window.set_status_text("".into());
}

fn apply_refresh_error(window: &MainWindow, states: &PeerIndicatorStates, error: String) {
    if let Ok(mut states) = states.lock() {
        states.clear();
    }
    render_peer_indicators(window, states);
    window.set_status_text(error.into());
}

fn apply_announce_update(
    window: &MainWindow,
    states: &PeerIndicatorStates,
    update: AnnouncePeerUpdate,
) {
    let state = match update.state {
        AnnouncePeerState::Pending => states
            .lock()
            .ok()
            .and_then(|states| states.get(&update.device_id).map(|entry| entry.state))
            .filter(|state| *state == PeerIndicatorState::Unavailable)
            .unwrap_or(PeerIndicatorState::Pending),
        AnnouncePeerState::Stored => PeerIndicatorState::Stored,
        AnnouncePeerState::Unavailable | AnnouncePeerState::VersionMismatch => {
            PeerIndicatorState::Unavailable
        }
    };
    if let Ok(mut states) = states.lock() {
        states.insert(
            update.device_id,
            PeerIndicatorEntry {
                name: update.hostname,
                state,
            },
        );
    }
    render_peer_indicators(window, states);
}

fn create_and_announce_with_progress(
    coordinator: &Coordinator,
    runtime: &DesktopLocalRuntime,
    input: OfferInput,
    on_update: Arc<dyn Fn(AnnouncePeerUpdate) + Send + Sync>,
) -> Result<MeshSendReport, String> {
    let Some(plan) = coordinator.create_offer(input)? else {
        return Err("no other meshelf device is paired".to_owned());
    };
    runtime.announce_with_progress(&plan, on_update)
}

fn announce_succeeded(report: MeshSendReport) -> Result<Option<String>, String> {
    if report.stored_on.is_empty() {
        Err(report.status())
    } else if report.version_mismatch.is_empty() {
        Ok(None)
    } else {
        Ok(Some(report.version_mismatch.join("; ")))
    }
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
            ..
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

#[derive(Debug, Default)]
struct DoubleClickDetector {
    last_click: Option<std::time::Instant>,
}

impl DoubleClickDetector {
    fn register_click(&mut self, now: std::time::Instant, threshold: Duration) -> bool {
        let is_double = if let Some(prev) = self.last_click {
            now.duration_since(prev) <= threshold
        } else {
            false
        };
        if is_double {
            self.last_click = None;
            true
        } else {
            self.last_click = Some(now);
            false
        }
    }
}

fn double_click_interval() -> Duration {
    #[cfg(target_os = "windows")]
    {
        let ms = unsafe { GetDoubleClickTime() };
        if ms > 0 {
            return Duration::from_millis(ms as u64);
        }
    }
    Duration::from_millis(500)
}

#[cfg(target_os = "windows")]
#[link(name = "user32")]
unsafe extern "system" {
    fn ShowWindow(hwnd: isize, n_cmd_show: i32) -> i32;
    fn SetForegroundWindow(hwnd: isize) -> i32;
    fn BringWindowToTop(hwnd: isize) -> i32;
    fn SetFocus(hwnd: isize) -> isize;
    fn GetForegroundWindow() -> isize;
    fn GetWindowThreadProcessId(hwnd: isize, process_id: *mut u32) -> u32;
    fn AttachThreadInput(id_attach: u32, id_attach_to: u32, attach: i32) -> i32;
    fn IsIconic(hwnd: isize) -> i32;
    fn EnumWindows(
        lp_enum_func: Option<unsafe extern "system" fn(isize, isize) -> i32>,
        l_param: isize,
    ) -> i32;
    fn GetWindowTextW(hwnd: isize, lp_string: *mut u16, n_max_count: i32) -> i32;
    fn GetDoubleClickTime() -> u32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThreadId() -> u32;
}

#[cfg(target_os = "windows")]
fn find_main_hwnd_fallback() -> Option<isize> {
    unsafe extern "system" fn enum_proc(hwnd: isize, lparam: isize) -> i32 {
        let state = unsafe { &mut *(lparam as *mut (u32, Option<isize>)) };
        let mut proc_id = 0u32;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut proc_id);
        }
        if proc_id == state.0 {
            let mut title_buf = [0u16; 64];
            let len =
                unsafe { GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32) };
            if len > 0 {
                let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                if title == "meshelf" {
                    state.1 = Some(hwnd);
                    return 0;
                }
            }
        }
        1
    }

    let pid = std::process::id();
    let mut state = (pid, None::<isize>);
    unsafe {
        EnumWindows(Some(enum_proc), &mut state as *mut _ as isize);
    }
    state.1
}

#[cfg(target_os = "windows")]
fn get_window_hwnd(window: &MainWindow) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    if let Ok(handle) = window.window().window_handle().window_handle()
        && let RawWindowHandle::Win32(win32_handle) = handle.as_raw()
    {
        return Some(win32_handle.hwnd.get());
    }
    find_main_hwnd_fallback()
}

#[cfg(target_os = "windows")]
fn focus_window_windows(hwnd: isize) {
    const SW_RESTORE: i32 = 9;
    const SW_SHOW: i32 = 5;

    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        } else {
            ShowWindow(hwnd, SW_SHOW);
        }

        let fg_hwnd = GetForegroundWindow();
        let fg_thread = GetWindowThreadProcessId(fg_hwnd, std::ptr::null_mut());
        let current_thread = GetCurrentThreadId();

        if fg_thread != 0 && fg_thread != current_thread {
            AttachThreadInput(current_thread, fg_thread, 1);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
            AttachThreadInput(current_thread, fg_thread, 0);
        } else {
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
        }
    }
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
    #[cfg(target_os = "windows")]
    {
        if let Some(hwnd) = get_window_hwnd(window) {
            focus_window_windows(hwnd);
        }
    }
}

fn refresh_in_background(
    app_state: Arc<Mutex<Controller>>,
    peer_names: Arc<Mutex<HashMap<DeviceId, String>>>,
    server: Arc<Mutex<Option<ServerHandle>>>,
    services: ListenerServices,
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
                let discovered_address = state
                    .last_status
                    .as_ref()
                    .and_then(|status| select_discovered_ip(&status.self_node.addresses))
                    .map(|address| SocketAddr::new(address, MESHELF_PORT));
                let needs_server = server
                    .lock()
                    .map(|mut slot| {
                        let stale = slot
                            .as_ref()
                            .zip(discovered_address)
                            .map(|(handle, address)| handle.needs_restart(address))
                            .unwrap_or(false);
                        if stale {
                            slot.take();
                        }
                        slot.is_none()
                    })
                    .unwrap_or(true);
                if needs_server {
                    let listener = start_v2_listener(&state, services.clone())?;
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
    let address = select_discovered_socket(peer.dial_addresses(), MESHELF_PORT)
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
    let identity = app_state
        .lock()
        .map_err(|_| anyhow::anyhow!("app state is unavailable"))?
        .identity
        .clone();
    // After activation recovery and before the network listener binds: the wiring this yields is
    // what `start_v2_listener` requires, so that order cannot be reversed by accident.
    let (capture, reconciliation) = start_capture_resident(CaptureServiceConfig {
        identity: identity.clone(),
        device_name: device_name.clone(),
        coordinator: coordinator.clone(),
        store: offer_store.clone(),
        activations: activations.clone(),
        client: PeerClient::with_timeouts(Duration::from_secs(3), Duration::from_secs(5)),
        port: MESHELF_PORT,
    })
    .map_err(|error| anyhow::anyhow!(error))?;
    tracing::info!(
        wait_port = capture.wait_port(),
        cancelled = reconciliation.cancel.len(),
        restarted_after_expiry = reconciliation.restarted_after_expiry.len(),
        uncertain = reconciliation.uncertain.len(),
        pruned_reported = reconciliation.pruned_reported,
        "capture requests reconciled before network binding"
    );
    let services = ListenerServices {
        offer_store: offer_store.clone(),
        card_store: card_store.clone(),
        capture: capture.clone(),
    };
    let local_runtime = Arc::new(DesktopLocalRuntime {
        app_state: app_state.clone(),
        state_path: data_dir.join("state.json"),
        identity,
        device_name: device_name.clone(),
        clipboard: clipboard.clone(),
        activations: activations.clone(),
        capture: capture.control(),
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
    let peer_indicator_states: PeerIndicatorStates = Arc::new(Mutex::new(HashMap::new()));
    let discovery_events = DiscoveryEventLoop;

    {
        let window_weak = window.as_weak();
        let peer_indicator_states = peer_indicator_states.clone();
        window.on_peer_indicator_width_changed(move |_| {
            if let Some(window) = window_weak.upgrade() {
                render_peer_indicators(&window, &peer_indicator_states);
            }
        });
    }

    let settings = settings_for_surface(&coordinator).map_err(|error| anyhow::anyhow!(error))?;
    window.set_destination_text(destination_label(&settings.save_destination).into());

    {
        let window_weak = window.as_weak();
        let clipboard = clipboard.clone();
        let coordinator = coordinator.clone();
        let local_runtime = local_runtime.clone();
        let send_gate = send_gate.clone();
        let peer_indicator_states = peer_indicator_states.clone();
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
            let status_window = window_weak.clone();
            let action_clipboard = clipboard.clone();
            let coordinator = coordinator.clone();
            let local_runtime = local_runtime.clone();
            let peer_indicator_states = peer_indicator_states.clone();
            thread::spawn(move || {
                let on_update: Arc<dyn Fn(AnnouncePeerUpdate) + Send + Sync> = {
                    let window_weak = status_window.clone();
                    let peer_indicator_states = peer_indicator_states.clone();
                    Arc::new(move |update| {
                        let window_weak = window_weak.clone();
                        let peer_indicator_states = peer_indicator_states.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(window) = window_weak.upgrade() {
                                apply_announce_update(&window, &peer_indicator_states, update);
                            }
                        });
                    })
                };
                let result = action_clipboard
                    .read_item()
                    .map_err(|error| format!("Could not read clipboard: {error}"))
                    .and_then(|item| match item {
                        ClipboardItem::Text(text) => {
                            if text.trim().is_empty() {
                                return Err("Clipboard contains no text to send".to_owned());
                            }
                            create_and_announce_with_progress(
                                &coordinator,
                                local_runtime.as_ref(),
                                OfferInput::Text(text),
                                on_update.clone(),
                            )
                            .and_then(announce_succeeded)
                        }
                        ClipboardItem::Files(paths) => {
                            if paths.is_empty() {
                                return Err("Clipboard contains no files or folders".to_owned());
                            }
                            let mut warning = None;
                            for path in paths {
                                if let Some(message) = create_and_announce_with_progress(
                                    &coordinator,
                                    local_runtime.as_ref(),
                                    OfferInput::Path(path),
                                    on_update.clone(),
                                )
                                .and_then(announce_succeeded)?
                                {
                                    warning = Some(message);
                                }
                            }
                            Ok(warning)
                        }
                    });
                drop(permit);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = status_window.upgrade() {
                        let status = match result {
                            Ok(Some(message)) | Err(message) => message,
                            Ok(None) => String::new(),
                        };
                        window.set_status_text(status.into());
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
        let peer_indicator_states = peer_indicator_states.clone();
        let server = server.clone();
        let refresh_gate = refresh_gate.clone();
        let services = services.clone();
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
            let peer_indicator_states_for_refresh = peer_indicator_states.clone();
            let server_for_refresh = server.clone();
            let services_for_refresh = services.clone();
            let refresh_gate_for_refresh = refresh_gate.clone();
            let started = discovery_events.dispatch(
                DiscoveryRefreshTrigger::BeforeUserOperation,
                move || {
                    let peer_indicator_states = peer_indicator_states_for_refresh.clone();
                    refresh_in_background(
                        app_state.clone(),
                        peer_names.clone(),
                        server_for_refresh.clone(),
                        services_for_refresh.clone(),
                        refresh_gate_for_refresh.clone(),
                        move |refresh_result| {
                            let Some(window) = completion_window.upgrade() else {
                                return;
                            };
                            let view = match refresh_result {
                                Ok(view) => view,
                                Err(error) => {
                                    apply_refresh_error(&window, &peer_indicator_states, error);
                                    return;
                                }
                            };
                            apply_peer_view(&window, &peer_indicator_states, view);
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
                },
            );
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
        let services = services.clone();
        let active_activations = active_activations.clone();
        let peer_indicator_states = peer_indicator_states.clone();
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
            let peer_indicator_states_for_refresh = peer_indicator_states.clone();
            let app_state_for_refresh = app_state.clone();
            let peer_names_for_refresh = peer_names.clone();
            let server_for_refresh = server.clone();
            let services_for_refresh = services.clone();
            let refresh_gate_for_refresh = refresh_gate.clone();
            let window_weak_for_refresh = window_weak.clone();
            let started = discovery_events.dispatch(DiscoveryRefreshTrigger::Explicit, move || {
                let peer_indicator_states = peer_indicator_states_for_refresh.clone();
                refresh_in_background(
                    app_state_for_refresh,
                    peer_names_for_refresh,
                    server_for_refresh,
                    services_for_refresh,
                    refresh_gate_for_refresh,
                    {
                        let window_weak = window_weak_for_refresh.clone();
                        move |result| {
                            if let Some(window) = window_weak.upgrade() {
                                match result {
                                    Ok(view) => {
                                        apply_peer_view(&window, &peer_indicator_states, view)
                                    }
                                    Err(error) => {
                                        apply_refresh_error(&window, &peer_indicator_states, error)
                                    }
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

    let tray_click_detector = Arc::new(Mutex::new(DoubleClickDetector::default()));
    {
        let window_weak = window.as_weak();
        let detector = tray_click_detector.clone();
        tray.on_tray_clicked(move || {
            let now = std::time::Instant::now();
            let threshold = double_click_interval();
            let is_double = detector
                .lock()
                .map(|mut d| d.register_click(now, threshold))
                .unwrap_or(false);
            if is_double && let Some(window) = window_weak.upgrade() {
                raise_window(&window);
            }
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
        refresh_in_background(app_state, peer_names, server, services, refresh_gate, {
            let window_weak = window.as_weak();
            let peer_indicator_states = peer_indicator_states.clone();
            move |result| {
                if let Some(window) = window_weak.upgrade() {
                    match result {
                        Ok(view) => apply_peer_view(&window, &peer_indicator_states, view),
                        Err(error) => apply_refresh_error(&window, &peer_indicator_states, error),
                    }
                }
            }
        })
    });
    finish_resident(slint::run_event_loop(), &capture)
}

/// Ends the resident: every attached waiter is woken with `resident_shutdown` whether the window
/// closed cleanly or the event loop failed, so no caller is left holding a socket that will never
/// answer. The durable request row stays the authority either way; nothing is retried here.
fn finish_resident(
    event_loop: Result<(), slint::PlatformError>,
    capture: &CaptureWiring,
) -> Result<()> {
    capture.shutdown();
    event_loop?;
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
    fn listener_handle_detects_exit_and_address_change() {
        let (shutdown, _shutdown_receiver) = watch::channel(false);
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            release_receiver.recv().expect("release listener");
        });
        let address = SocketAddr::new("100.64.1.10".parse().expect("address"), MESHELF_PORT);
        let other_address = SocketAddr::new("100.64.1.30".parse().expect("address"), MESHELF_PORT);
        let handle = ServerHandle {
            address,
            shutdown,
            worker: Some(worker),
        };

        assert!(!handle.needs_restart(address));
        assert!(handle.needs_restart(other_address));
        release_sender.send(()).expect("stop listener");
        while !handle
            .worker
            .as_ref()
            .expect("listener worker")
            .is_finished()
        {
            thread::yield_now();
        }
        assert!(handle.needs_restart(address));
        drop(handle);
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
                *observed.lock().expect("reachability state") = "FERN".to_owned();
                true
            })
        );
        assert_eq!(*reachability.lock().expect("reachability state"), "FERN");
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
    fn generated_ui_peer_indicators_have_no_overflow_hint_when_they_fit() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let states = Arc::new(Mutex::new(HashMap::new()));
        apply_peer_view(
            &window,
            &states,
            PeerView {
                name: "FERN".to_owned(),
                online: true,
                status: "2 devices reachable · paste text or copied files".to_owned(),
                reachable_names: "BIRCH\nFERN".to_owned(),
                peer_statuses: vec![
                    meshelf_control::PeerStatus {
                        device_id: DeviceId::new(),
                        name: "BIRCH".to_owned(),
                        reachable: true,
                    },
                    meshelf_control::PeerStatus {
                        device_id: DeviceId::new(),
                        name: "FERN".to_owned(),
                        reachable: true,
                    },
                ],
            },
        );

        let indicators = window.get_peer_indicators();
        assert_eq!(indicators.row_count(), 2);
        assert_eq!(window.get_peer_overflow().as_str(), "");
        assert_eq!(
            indicators.row_data(0).expect("first peer").name.as_str(),
            "BIRCH"
        );
        assert_eq!(
            indicators.row_data(0).expect("first peer").state.as_str(),
            "online"
        );
    }

    #[test]
    fn failed_refresh_does_not_leave_stale_peer_overflow() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let states = Arc::new(Mutex::new(HashMap::new()));
        apply_peer_view(
            &window,
            &states,
            PeerView {
                name: "FERN".to_owned(),
                online: true,
                status: "1 device reachable · paste text or copied files".to_owned(),
                reachable_names: "FERN".to_owned(),
                peer_statuses: vec![meshelf_control::PeerStatus {
                    device_id: DeviceId::new(),
                    name: "FERN".to_owned(),
                    reachable: true,
                }],
            },
        );

        apply_refresh_error(&window, &states, "Refresh failed".to_owned());

        assert_eq!(window.get_peer_overflow().as_str(), "");
        assert_eq!(window.get_peer_indicators().row_count(), 0);
    }

    #[test]
    fn peer_indicators_are_compact_and_follow_announce_outcomes() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let fern = DeviceId::new();
        let birch = DeviceId::new();
        let states = Arc::new(Mutex::new(HashMap::from([
            (
                fern,
                PeerIndicatorEntry {
                    name: "FERN".to_owned(),
                    state: PeerIndicatorState::Reachable,
                },
            ),
            (
                birch,
                PeerIndicatorEntry {
                    name: "BIRCH".to_owned(),
                    state: PeerIndicatorState::Unavailable,
                },
            ),
        ])));

        render_peer_indicators(&window, &states);
        assert_eq!(window.get_peer_indicators().row_count(), 2);
        assert_eq!(
            window
                .get_peer_indicators()
                .row_data(0)
                .expect("first peer")
                .name
                .as_str(),
            "FERN"
        );
        assert_eq!(
            window
                .get_peer_indicators()
                .row_data(0)
                .expect("first peer")
                .state
                .as_str(),
            "online"
        );

        apply_announce_update(
            &window,
            &states,
            AnnouncePeerUpdate {
                device_id: fern,
                hostname: "FERN".to_owned(),
                state: AnnouncePeerState::Pending,
            },
        );
        assert_eq!(
            window
                .get_peer_indicators()
                .row_data(0)
                .expect("online peer")
                .state
                .as_str(),
            "pending"
        );

        apply_announce_update(
            &window,
            &states,
            AnnouncePeerUpdate {
                device_id: fern,
                hostname: "FERN".to_owned(),
                state: AnnouncePeerState::Stored,
            },
        );
        assert_eq!(
            window
                .get_peer_indicators()
                .row_data(0)
                .expect("online peer")
                .state
                .as_str(),
            "online"
        );
    }

    #[test]
    fn peer_indicator_overflow_hides_offline_peers_and_reports_them() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let fern = DeviceId::new();
        let birch = DeviceId::new();
        let states = Arc::new(Mutex::new(HashMap::from([
            (
                fern,
                PeerIndicatorEntry {
                    name: "FERN".to_owned(),
                    state: PeerIndicatorState::Reachable,
                },
            ),
            (
                birch,
                PeerIndicatorEntry {
                    name: "BIRCH".to_owned(),
                    state: PeerIndicatorState::Unavailable,
                },
            ),
        ])));

        window.set_peer_indicator_width(76.0);
        render_peer_indicators(&window, &states);

        let indicators = window.get_peer_indicators();
        assert_eq!(indicators.row_count(), 1);
        assert_eq!(
            indicators.row_data(0).expect("online peer").name.as_str(),
            "FERN"
        );
        assert_eq!(window.get_peer_overflow().as_str(), "+1");
        assert_eq!(window.get_peer_overflow_names().as_str(), "BIRCH");
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
                    content_class: meshelf_core::FileContentClass::File,
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
                content_class: meshelf_core::FileContentClass::File,
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
                content_class: meshelf_core::FileContentClass::File,
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
                    content_class: meshelf_core::FileContentClass::File,
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
                    content_class: meshelf_core::FileContentClass::File,
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
                content_class: meshelf_core::FileContentClass::File,
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

    #[test]
    fn double_click_detector_requires_two_clicks_within_threshold() {
        let mut detector = DoubleClickDetector::default();
        let threshold = Duration::from_millis(500);
        let start = std::time::Instant::now();

        // First click
        assert!(!detector.register_click(start, threshold));

        // Click outside threshold
        let late = start + Duration::from_millis(600);
        assert!(!detector.register_click(late, threshold));

        // Click within threshold of the previous click
        let quick = late + Duration::from_millis(200);
        assert!(detector.register_click(quick, threshold));

        // Immediate subsequent click does not re-trigger without a new pair
        let third = quick + Duration::from_millis(100);
        assert!(!detector.register_click(third, threshold));
    }

    // -- capture wiring ------------------------------------------------------------------------

    /// A desktop resident built the way `main` builds one, minus the window: a paired phone that
    /// answers at a loopback port nothing listens on, so anything network-bound fails promptly.
    struct CaptureFixture {
        _directory: TestDirectory,
        root: PathBuf,
        store: Arc<RedbV2Store>,
        coordinator: Arc<Coordinator>,
        activations: Arc<ActivationService<ActivationClipboard>>,
        identity: meshelf_identity::InstallationIdentity,
        /// A device this desktop has never paired with, so anything the capture service tries to
        /// send it is refused before a socket is opened and no background task outlives the test.
        stranger: DeviceId,
    }

    fn unrecovered_capture_fixture() -> CaptureFixture {
        let directory = TestDirectory::new();
        let root = fs::canonicalize(directory.path()).expect("canonical test directory");
        let identity = meshelf_identity::InstallationIdentity::generate();
        let phone = meshelf_identity::InstallationIdentity::generate();
        let state_path = root.join("state.json");
        InstallationStore::new(state_path.clone())
            .update(identity.device_id, |state| {
                state.peers.accept_signed(
                    &meshelf_tailscale::TailNode {
                        node_id: Some("phone-node".to_owned()),
                        hostname: "amber".to_owned(),
                        dns_name: None,
                        addresses: vec!["127.0.0.1".parse().expect("address")],
                        online: true,
                        active: true,
                    },
                    phone.device_id,
                    phone.public_key().to_vec(),
                )
            })
            .expect("record the phone");
        let store = Arc::new(RedbV2Store::open(root.join("offers.redb")).expect("offer store"));
        let coordinator = Arc::new(
            Coordinator::new(
                identity.device_id,
                InstallationStore::new(state_path),
                store.clone(),
            )
            .with_card_store(store.clone()),
        );
        let activations = Arc::new(ActivationService::new(
            identity.device_id,
            store.clone(),
            Arc::new(ActivationClipboard::Unavailable),
            root.join("activation"),
        ));
        CaptureFixture {
            _directory: directory,
            root,
            store,
            coordinator,
            activations,
            identity,
            stranger: meshelf_identity::InstallationIdentity::generate().device_id,
        }
    }

    fn capture_fixture() -> CaptureFixture {
        let fixture = unrecovered_capture_fixture();
        fixture
            .activations
            .recover()
            .expect("activation recovery runs before capture reconciliation");
        fixture
    }

    impl CaptureFixture {
        fn service_config(&self) -> CaptureServiceConfig<ActivationClipboard> {
            CaptureServiceConfig {
                identity: self.identity.clone(),
                device_name: "CEDAR".to_owned(),
                coordinator: self.coordinator.clone(),
                store: self.store.clone(),
                activations: self.activations.clone(),
                client: PeerClient::with_timeouts(
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                ),
                port: MESHELF_PORT,
            }
        }

        fn start_capture(&self) -> (CaptureWiring, meshelf_store::CaptureRequestReconciliation) {
            start_capture_resident(self.service_config()).expect("start the capture resident")
        }

        /// A live request row, written exactly as `CaptureService::start_capture` writes one.
        fn insert_live_request(
            &self,
            output: &str,
            peer: DeviceId,
        ) -> meshelf_core::CaptureRequestId {
            let created_at_unix_ms = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock after the Unix epoch")
                    .as_millis(),
            )
            .expect("clock in range");
            let record = meshelf_core::CaptureRequestRecord {
                request_id: meshelf_core::CaptureRequestId::new(),
                peer,
                peer_label: "amber".to_owned(),
                purpose: "Photograph the router label".to_owned(),
                lens: None,
                created_at_unix_ms,
                grant: meshelf_core::CapturePullGrant {
                    expected_source: peer,
                    kind: meshelf_core::CaptureKind::Photo,
                    exact_output_path: self.root.join(output),
                    expires_at_unix_ms: created_at_unix_ms + meshelf_core::MAX_CAPTURE_LIFETIME_MS,
                },
                phase: meshelf_core::CaptureRequestPhase::AwaitingPresentation,
                terminal_reported: false,
            };
            let request_id = record.request_id;
            match self.store.insert_capture_request(record) {
                Ok(meshelf_store::CaptureRequestInsert::Inserted { .. }) => request_id,
                other => panic!("expected an inserted request, got {other:?}"),
            }
        }

        fn row(
            &self,
            request_id: meshelf_core::CaptureRequestId,
        ) -> meshelf_core::CaptureRequestRecord {
            self.store
                .get_capture_request(request_id)
                .expect("read the request")
                .expect("the request row exists")
        }
    }

    #[test]
    fn capture_reconciliation_refuses_to_run_before_activation_recovery() {
        let fixture = unrecovered_capture_fixture();
        let error = start_capture_resident(fixture.service_config())
            .err()
            .expect("reconciling before activation recovery must be refused, not silently allowed");
        assert!(
            error.contains("after activation recovery"),
            "the refusal must name the ordering it protects, got {error}"
        );
    }

    #[test]
    fn startup_reconciliation_ends_a_request_the_previous_run_left_behind() {
        let fixture = capture_fixture();
        let request_id = fixture.insert_live_request("photo.jpg", fixture.stranger);
        let (capture, reconciliation) = fixture.start_capture();

        assert_eq!(
            reconciliation
                .cancel
                .iter()
                .map(|record| record.request_id)
                .collect::<Vec<_>>(),
            vec![request_id],
            "an unclaimed request left by the previous run is owed one best-effort cancel"
        );
        assert!(
            fixture.row(request_id).outcome().is_some(),
            "a request that survived a restart must be ended, never left live to be claimed"
        );
        capture.shutdown();
    }

    #[test]
    fn the_desktop_answers_local_control_with_its_own_capture_service() {
        let fixture = capture_fixture();
        let (capture, _) = fixture.start_capture();
        let handle = capture.control();
        let control = desktop_capture_control(&handle)
            .expect("a desktop with a capture service must not report resident_unavailable");

        let reply = control.start(meshelf_control::capture::CaptureStartInput {
            peer: "nothing-is-paired-under-this-name".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: None,
            timeout_ms: 60_000,
            output_path: fixture.root.join("photo.jpg"),
            wait: false,
        });

        assert_eq!(
            reply,
            meshelf_control::capture::CaptureReply::NotStarted {
                reason: meshelf_core::CaptureNotStarted::PeerNotPaired
            },
            "the request must reach the real service, which knows the peer is unpaired"
        );
        capture.shutdown();
    }

    #[test]
    fn the_desktop_listener_records_a_capture_status_instead_of_refusing_it() {
        let fixture = capture_fixture();
        let (capture, _) = fixture.start_capture();
        let request_id = fixture.insert_live_request("photo.jpg", fixture.stranger);

        let config = desktop_v2_config(
            ServerIdentity {
                signing_identity: fixture.identity.clone(),
                device_name: "CEDAR".to_owned(),
            },
            Arc::new(InstallationTrustGate::new(
                InstallationStore::new(fixture.root.join("state.json")),
                fixture.identity.device_id,
            )),
            V2OfferServices {
                announcement_receiver: Arc::new(desktop_announcement_handler(
                    fixture.store.clone(),
                    &capture,
                )),
                fetch_sender: Arc::new(OfferFetchHandler::new(
                    fixture.identity.device_id,
                    fixture.store.clone(),
                )),
            },
            &capture,
            Duration::from_secs(5),
        );
        let receiver = config.capture_receiver.clone();
        drop(config);

        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let acknowledged = runtime.block_on(async {
            receiver
                .handle_capture_status(
                    fixture.stranger,
                    fixture.identity.device_id,
                    meshelf_protocol::CaptureStatus {
                        request_id,
                        code: meshelf_protocol::CaptureStatusCode::Declined,
                        detail: None,
                    },
                )
                .await
        });
        drop(runtime);

        assert!(
            acknowledged.is_ok(),
            "the desktop must record a status before acknowledging it, not refuse every one: {acknowledged:?}"
        );
        assert_eq!(
            fixture
                .row(request_id)
                .outcome()
                .map(|outcome| outcome.reason),
            Some(meshelf_core::CaptureTerminalCode::Declined.outcome().reason),
            "acknowledging a status is a promise it was recorded (invariant 11)"
        );
        capture.shutdown();
    }

    #[test]
    fn a_correlated_announcement_goes_to_its_capture_request_not_the_shelf() {
        let fixture = capture_fixture();
        let (capture, _) = fixture.start_capture();
        let request_id = fixture.insert_live_request("photo.jpg", fixture.stranger);
        assert!(
            matches!(
                fixture
                    .store
                    .arm_capture_grant(request_id, 2)
                    .expect("arm the grant"),
                meshelf_store::CaptureTransition::Applied(_)
            ),
            "the phone acknowledged the presentation, so the grant is claimable"
        );
        let handler = desktop_announcement_handler(fixture.store.clone(), &capture);

        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            fixture.stranger,
            fixture.identity.device_id,
            1,
            OfferDescriptor::File {
                root_name: "photo.jpg".to_owned(),
                total_bytes: 1024,
                content_class: meshelf_core::FileContentClass::File,
            },
        )
        .with_capture(meshelf_core::CaptureCorrelation { request_id });

        let ack = handler
            .handle_sync(fixture.stranger, fixture.identity.device_id, announcement)
            .expect("the announcement is answered");

        // Without a router every correlated announcement is refused `capture_not_armed` without
        // the store being touched. With one, the grant is claimed and only then does the pull
        // refuse, because this source is not a peer the desktop can dial.
        assert_eq!(
            ack.detail.as_deref(),
            Some("capture_launch_failed"),
            "a desktop with a capture service must route correlated announcements, not refuse them"
        );
        assert!(
            fixture
                .store
                .read_offer_shelf()
                .expect("read the shelf")
                .is_empty(),
            "a capture result must never take a shelf entry the user is keeping"
        );
        assert!(
            fixture.row(request_id).outcome().is_some(),
            "a claim whose pull could not start ends its request rather than leaving it live"
        );
        capture.shutdown();
    }

    #[test]
    fn leaving_the_desktop_wakes_capture_waiters_even_when_the_event_loop_fails() {
        let fixture = capture_fixture();
        let (capture, _) = fixture.start_capture();
        let before = fixture.insert_live_request("before.jpg", fixture.stranger);
        let after = fixture.insert_live_request("after.jpg", fixture.stranger);
        assert!(
            matches!(
                capture.control().wait_ticket(before),
                meshelf_control::capture::CaptureReply::Started {
                    wait: meshelf_control::capture::CaptureWait::Issued(_),
                    ..
                }
            ),
            "a live request issues a wait ticket while the resident is running"
        );

        let ended = finish_resident(Err(slint::PlatformError::NoPlatform), &capture);

        assert!(
            ended.is_err(),
            "a failed event loop must still be reported as a failure"
        );
        assert_eq!(
            capture.control().wait_ticket(after),
            meshelf_control::capture::CaptureReply::NotStarted {
                reason: meshelf_core::CaptureNotStarted::Capacity
            },
            "after shutdown the wait channel takes no new waiter; every attached one was woken"
        );
    }

    #[test]
    fn double_click_interval_is_non_zero() {
        assert!(double_click_interval() > Duration::ZERO);
    }
}
