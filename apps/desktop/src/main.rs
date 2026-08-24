#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(target_os = "macos")]
use std::process::Command;

use anyhow::Result;
use meshelf_control::{Controller, MESHELF_PORT, PeerView};
use meshelf_core::{ClipboardError, ClipboardSink, ContentKind, DeviceId, ReceiveRecord};
use meshelf_net::{
    CoreEnvelopeHandler, ServerIdentity, TrustDecision, TrustGate,
    bind_discovered_tailscale_std_listener, serve_with_files,
};
use meshelf_platform::{ClipboardItem, ClipboardSource, ClipboardWorker};
use meshelf_store::RedbReceiveStore;
use meshelf_tailscale::InstallationStore;
use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};
use tokio::{runtime::Runtime, sync::watch};
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

#[derive(Debug)]
struct OperationPermit {
    busy: Arc<AtomicBool>,
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
struct ShelfSnapshot {
    records: Vec<ReceiveRecord>,
    peer_names: HashMap<DeviceId, String>,
}

#[derive(Debug, Default)]
struct ShelfOnlyClipboard;

impl ClipboardSink for ShelfOnlyClipboard {
    fn set_text(&self, _text: &str) -> Result<(), ClipboardError> {
        Err(ClipboardError::new(
            "received shelf items require an explicit local copy action",
        ))
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

fn start_listener(
    state: &Controller,
    receive_store: Arc<RedbReceiveStore>,
) -> Result<ServerHandle, String> {
    let status = state
        .last_status
        .as_ref()
        .ok_or_else(|| "Tailscale status is unavailable".to_owned())?;
    let address = status
        .self_node
        .addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4())
        .or_else(|| status.self_node.addresses.first().copied())
        .ok_or_else(|| "Tailscale supplied no local address".to_owned())?;
    let listener = bind_discovered_tailscale_std_listener(
        SocketAddr::new(address, MESHELF_PORT),
        &status.self_node.addresses,
    )
    .map_err(|error| format!("could not bind Tailscale listener: {error}"))?;
    let receiver = Arc::new(meshelf_core::ReceiverService::new(
        state.installation.device_id,
        receive_store,
        Arc::new(ShelfOnlyClipboard),
    ));
    let handler = Arc::new(CoreEnvelopeHandler::new(receiver));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let identity = ServerIdentity {
        signing_identity: state.identity.clone(),
        device_name: state.device_name.clone(),
    };
    let gate = Arc::new(FileBackedTrustGate {
        store: InstallationStore::new(state.state_path.clone()),
        identity: state.identity.device_id,
    });
    let incoming_directory = dirs::download_dir()
        .unwrap_or_else(|| {
            state
                .state_path
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        })
        .join("Meshelf Incoming");
    let worker = thread::Builder::new()
        .name("meshelf-network".to_owned())
        .spawn(move || {
            let Ok(runtime) = Runtime::new() else {
                tracing::error!("meshelf listener runtime could not be created");
                return;
            };
            let Ok(listener) =
                runtime.block_on(async move { tokio::net::TcpListener::from_std(listener) })
            else {
                tracing::error!("meshelf listener could not attach to its server runtime");
                return;
            };
            if let Err(error) = runtime.block_on(serve_with_files(
                listener,
                identity,
                gate,
                handler,
                incoming_directory,
                Duration::from_secs(5),
                shutdown_rx,
            )) {
                tracing::error!(%error, "meshelf listener stopped unexpectedly");
            }
        })
        .map_err(|error| format!("could not start Tailscale listener: {error}"))?;
    Ok(ServerHandle {
        shutdown,
        worker: Some(worker),
    })
}

fn apply_peer_view(window: &MainWindow, view: PeerView) {
    window.set_default_peer(view.name.into());
    window.set_default_peer_online(view.online);
    window.set_status_text(view.status.into());
}

fn load_shelf_snapshot(
    receive_store: &RedbReceiveStore,
    peer_names: &Mutex<HashMap<DeviceId, String>>,
) -> Result<ShelfSnapshot, String> {
    let records = receive_store
        .recent(10)
        .map_err(|error| format!("Could not read local shelf: {error}"))?;
    let peer_names = peer_names
        .lock()
        .map_err(|_| "peer names are unavailable".to_owned())?
        .clone();
    Ok(ShelfSnapshot {
        records,
        peer_names,
    })
}

fn apply_shelf_snapshot(window: &MainWindow, snapshot: ShelfSnapshot) {
    let rows = snapshot
        .records
        .into_iter()
        .enumerate()
        .map(|(index, record)| shelf_row(&snapshot.peer_names, index, record))
        .collect::<Vec<_>>();
    window.set_shelf_items(ModelRc::new(VecModel::from(rows)));
}

fn refresh_shelf_in_background(
    window_weak: slint::Weak<MainWindow>,
    receive_store: Arc<RedbReceiveStore>,
    peer_names: Arc<Mutex<HashMap<DeviceId, String>>>,
    gate: OperationGate,
) {
    let Some(permit) = gate.try_enter() else {
        return;
    };
    thread::spawn(move || {
        let result = load_shelf_snapshot(&receive_store, &peer_names);
        drop(permit);
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
    record: ReceiveRecord,
) -> ShelfRow {
    let source = peer_names
        .get(&record.envelope.source_device)
        .cloned()
        .unwrap_or_else(|| record.envelope.source_device.to_string());
    ShelfRow {
        icon: match record.envelope.content_kind {
            ContentKind::Text => "📝",
            ContentKind::Path => "↗",
            ContentKind::File => "📄",
            ContentKind::Folder => "📁",
        }
        .into(),
        preview: preview(&record.envelope.text).into(),
        detail: format!("From {source} · click to copy").into(),
        payload: record.envelope.text.into(),
        file_item: matches!(
            record.envelope.content_kind,
            ContentKind::File | ContentKind::Folder
        ),
        shortcut: if index < 5 {
            item_shortcut(index + 1).into()
        } else {
            "click".into()
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
fn shelf_shortcut_help() -> &'static str {
    "click or ⌘1–5 to copy"
}

#[cfg(not(target_os = "macos"))]
fn shelf_shortcut_help() -> &'static str {
    "click or Ctrl+1–5 to copy"
}

#[cfg(target_os = "macos")]
fn item_shortcut(index: usize) -> String {
    format!("⌘{index}")
}

#[cfg(not(target_os = "macos"))]
fn item_shortcut(index: usize) -> String {
    format!("Ctrl+{index}")
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
    window_weak: slint::Weak<MainWindow>,
    app_state: Arc<Mutex<Controller>>,
    peer_names: Arc<Mutex<HashMap<DeviceId, String>>>,
    server: Arc<Mutex<Option<ServerHandle>>>,
    receive_store: Arc<RedbReceiveStore>,
    gate: OperationGate,
) -> bool {
    let Some(permit) = gate.try_enter() else {
        return false;
    };
    thread::spawn(move || {
        let result = app_state
            .lock()
            .map_err(|_| "app state is unavailable".to_owned())
            .and_then(|mut state| {
                let view = state.refresh()?;
                if let Ok(mut names) = peer_names.lock() {
                    *names = capture_peer_names(&state);
                }
                let needs_server = server.lock().map(|slot| slot.is_none()).unwrap_or(false);
                if needs_server {
                    let listener = start_listener(&state, receive_store.clone())?;
                    if let Ok(mut slot) = server.lock()
                        && slot.is_none()
                    {
                        *slot = Some(listener);
                    }
                }
                Ok(Some(view))
            });
        drop(permit);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = window_weak.upgrade() {
                match result {
                    Ok(Some(view)) => apply_peer_view(&window, view),
                    Ok(None) => {}
                    Err(error) => window.set_status_text(error.into()),
                }
            }
        });
    });
    true
}

fn preview(text: &str) -> String {
    let single_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = single_line.chars();
    let preview = chars.by_ref().take(180).collect::<String>();
    if chars.next().is_some() {
        format!("{preview}…")
    } else {
        preview
    }
}

fn main() -> Result<()> {
    if std::env::args()
        .any(|argument| argument == "pair-stdio" || argument == "--ssh-bootstrap-stdin")
    {
        return meshelf_bootstrap::run_stdio();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .without_time()
        .init();

    let window = MainWindow::new()?;
    let tray = MeshelfTray::new()?;
    window.set_paste_shortcut(paste_shortcut().into());
    window.set_shelf_shortcut_help(shelf_shortcut_help().into());
    let device_name = std::env::var("MESHELF_DEVICE_NAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".to_owned());
    let data_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("meshelf");
    fs::create_dir_all(&data_dir)?;
    let instance_lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(data_dir.join("desktop.lock"))?;
    if instance_lock.try_lock().is_err() {
        tracing::info!("meshelf desktop is already running");
        return Ok(());
    }
    let _instance_lock = instance_lock;
    let state_path = data_dir.join("state.json");
    let receive_store = Arc::new(
        RedbReceiveStore::open(data_dir.join("meshelf.redb"))
            .map_err(|error| anyhow::anyhow!("could not open receive ledger: {error}"))?,
    );
    let app_state = Arc::new(Mutex::new(
        Controller::load(state_path, device_name).map_err(|error| anyhow::anyhow!(error))?,
    ));
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
    let server = Arc::new(Mutex::new(None::<ServerHandle>));
    let send_gate = OperationGate::default();
    let copy_gate = OperationGate::default();
    let refresh_gate = OperationGate::default();
    let shelf_gate = OperationGate::default();

    {
        let window_weak = window.as_weak();
        let clipboard = clipboard.clone();
        let app_state = app_state.clone();
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
            let window_weak = window_weak.clone();
            let app_state = app_state.clone();
            thread::spawn(move || {
                let result = clipboard
                    .read_item()
                    .map_err(|error| format!("Could not read clipboard: {error}"))
                    .and_then(|item| {
                        let state = app_state
                            .lock()
                            .map_err(|_| "app state is unavailable".to_owned())?;
                        match item {
                            ClipboardItem::Text(text) => {
                                if text.trim().is_empty() {
                                    return Err("Clipboard contains no text to send".to_owned());
                                }
                                state.send_to_mesh(&text).map(|report| report.status())
                            }
                            ClipboardItem::Files(paths) => state.send_paths_to_mesh(&paths),
                        }
                    });
                drop(permit);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_weak.upgrade() {
                        window.set_status_text(result.unwrap_or_else(|error| error).into());
                    }
                });
            });
        });
    }

    {
        let window_weak = window.as_weak();
        let clipboard = clipboard.clone();
        let copy_gate = copy_gate.clone();
        window.on_copy_item(move |text, file_item| {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let Some(clipboard) = clipboard.clone() else {
                window.set_status_text("Clipboard adapter is unavailable".into());
                return;
            };
            let Some(permit) = copy_gate.try_enter() else {
                window.set_status_text("A shelf copy is already in progress".into());
                return;
            };
            window.set_status_text("Copying shelf item…".into());
            let window_weak = window_weak.clone();
            thread::spawn(move || {
                let result = if file_item {
                    let path = PathBuf::from(text.as_str());
                    if !path.exists() {
                        Err(format!(
                            "Received file is no longer present: {}",
                            path.display()
                        ))
                    } else {
                        clipboard
                            .set_files(&[path])
                            .map(|()| "Copied file to this clipboard".to_owned())
                            .map_err(|error| format!("Could not update clipboard: {error}"))
                    }
                } else {
                    clipboard
                        .set_text(text.as_str())
                        .map(|()| "Copied shelf item to this clipboard".to_owned())
                        .map_err(|error| format!("Could not update clipboard: {error}"))
                };
                drop(permit);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_weak.upgrade() {
                        window.set_status_text(result.unwrap_or_else(|error| error).into());
                    }
                });
            });
        });
    }

    {
        let window_weak = window.as_weak();
        let app_state = app_state.clone();
        let peer_names = peer_names.clone();
        let server = server.clone();
        let receive_store = receive_store.clone();
        let refresh_gate = refresh_gate.clone();
        window.on_refresh_peers(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let started = refresh_in_background(
                window_weak.clone(),
                app_state.clone(),
                peer_names.clone(),
                server.clone(),
                receive_store.clone(),
                refresh_gate.clone(),
            );
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

    let shelf_timer = Timer::default();
    {
        let window_weak = window.as_weak();
        let receive_store = receive_store.clone();
        let peer_names = peer_names.clone();
        let shelf_gate = shelf_gate.clone();
        shelf_timer.start(TimerMode::Repeated, Duration::from_millis(500), move || {
            refresh_shelf_in_background(
                window_weak.clone(),
                receive_store.clone(),
                peer_names.clone(),
                shelf_gate.clone(),
            );
        });
    }

    let mesh_timer = Timer::default();
    {
        let window_weak = window.as_weak();
        let app_state = app_state.clone();
        let peer_names = peer_names.clone();
        let server = server.clone();
        let receive_store = receive_store.clone();
        let refresh_gate = refresh_gate.clone();
        mesh_timer.start(TimerMode::Repeated, Duration::from_secs(8), move || {
            refresh_in_background(
                window_weak.clone(),
                app_state.clone(),
                peer_names.clone(),
                server.clone(),
                receive_store.clone(),
                refresh_gate.clone(),
            );
        });
    }

    window.show()?;
    tray.show()?;
    refresh_shelf_in_background(
        window.as_weak(),
        receive_store.clone(),
        peer_names.clone(),
        shelf_gate,
    );
    refresh_in_background(
        window.as_weak(),
        app_state,
        peer_names,
        server,
        receive_store,
        refresh_gate,
    );
    slint::run_event_loop()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::platform::{Key, WindowEvent};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn operation_gate_allows_only_one_in_flight_operation() {
        let gate = OperationGate::default();
        let first = gate.try_enter().expect("first operation starts");
        assert!(gate.try_enter().is_none());
        drop(first);
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn shortcuts_accept_control_once_and_ignore_meta() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().expect("test window");
        let paste_count = Arc::new(AtomicUsize::new(0));
        let callback_count = paste_count.clone();
        window.on_paste_and_send(move || {
            callback_count.fetch_add(1, Ordering::Relaxed);
        });
        let copied = Arc::new(Mutex::new(None::<(String, bool)>));
        let copied_item = copied.clone();
        window.on_copy_item(move |text, file_item| {
            *copied_item.lock().expect("copy result") = Some((text.to_string(), file_item));
        });
        window.set_shelf_items(ModelRc::new(VecModel::from(vec![ShelfRow {
            icon: "📝".into(),
            preview: "first".into(),
            detail: "test".into(),
            payload: "first payload".into(),
            file_item: false,
            shortcut: "Ctrl+1".into(),
        }])));

        window.window().dispatch_event(WindowEvent::KeyPressed {
            text: Key::Control.into(),
        });
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: "v".into() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressRepeated { text: "v".into() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text: "v".into() });
        window.window().dispatch_event(WindowEvent::KeyReleased {
            text: Key::Control.into(),
        });
        assert_eq!(paste_count.load(Ordering::Relaxed), 1);

        window.window().dispatch_event(WindowEvent::KeyPressed {
            text: Key::Control.into(),
        });
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: "1".into() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text: "1".into() });
        window.window().dispatch_event(WindowEvent::KeyReleased {
            text: Key::Control.into(),
        });
        assert_eq!(
            *copied.lock().expect("copy result"),
            Some(("first payload".to_owned(), false))
        );

        window.window().dispatch_event(WindowEvent::KeyPressed {
            text: Key::Meta.into(),
        });
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: "v".into() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text: "v".into() });
        window.window().dispatch_event(WindowEvent::KeyReleased {
            text: Key::Meta.into(),
        });
        assert_eq!(paste_count.load(Ordering::Relaxed), 1);

        *copied.lock().expect("copy result") = None;
        window.window().dispatch_event(WindowEvent::KeyPressed {
            text: Key::Meta.into(),
        });
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: "1".into() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text: "1".into() });
        window.window().dispatch_event(WindowEvent::KeyReleased {
            text: Key::Meta.into(),
        });
        assert_eq!(*copied.lock().expect("copy result"), None);
    }
}
