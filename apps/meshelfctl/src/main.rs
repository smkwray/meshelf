use std::{
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use meshelf_control::{
    ActivationPlan, Controller, MESHELF_PORT, OfferPlan, announce_offer_plan,
    coordinator::Coordinator,
    local_control::{self, LocalRequest, LocalResponse, LocalRuntime},
};
use meshelf_core::{
    ActivationMode, ClipboardError, ClipboardSink, DeviceId, OfferDescriptor, OfferId,
};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    FetchActivation, FetchClipboard, FetchReceiver, OfferAnnouncementHandler, OfferFetchHandler,
    PeerClient, ServerIdentity, TrustDecision, TrustGate, V2OfferServices,
    bind_discovered_tailscale_std_listener, serve_v2_with_offers_and_fetch,
};
use meshelf_platform::{
    ClipboardItem, ClipboardSource, ClipboardWorker, acquire_resident_lock, listen_with_control,
    request as control_request, resolve_save_destination,
};
use meshelf_protocol::{ClientHello, FetchRequest};
use meshelf_store::RedbV2Store;
use meshelf_tailscale::InstallationStore;
use tokio::runtime::Builder;
use tokio::sync::watch;

const MAX_TEXT_BYTES: usize = 1024 * 1024;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return usage();
    };
    if command == "pair-stdio" {
        return meshelf_bootstrap::run_stdio();
    }

    let remaining = args.collect::<Vec<_>>();
    if command == "serve" {
        return run_serve(remaining);
    }
    if command == "announce" {
        return run_announce(remaining);
    }
    if command == "shelf" {
        return run_shelf(remaining);
    }
    if command == "activate" {
        return run_activate(remaining);
    }

    let (selector, options) = take_peer_selector(remaining)?;
    let device_name = std::env::var("MESHELF_DEVICE_NAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".to_owned());
    let config_dir = config_dir()?;
    std::fs::create_dir_all(&config_dir)?;
    let mut controller = Controller::load(config_dir.join("state.json"), device_name)
        .map_err(|error| anyhow::anyhow!(error))?;

    match command.as_str() {
        "status" | "refresh" => {
            let view = controller
                .refresh()
                .map_err(|error| anyhow::anyhow!(error))?;
            if selector.is_some() {
                controller
                    .select_peer(selector.as_deref())
                    .map_err(|error| anyhow::anyhow!(error))?;
            }
            if has_flag(&options, "--json") {
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                println!("{}", view.status);
                println!("peer: {}", view.name);
                println!("online: {}", view.online);
                println!("ssh_trust_available: {}", view.approval_available);
            }
        }
        "trust-ssh" | "approve" => {
            controller
                .refresh()
                .map_err(|error| anyhow::anyhow!(error))?;
            if selector.is_some() {
                bail!(
                    "peer selection for a pending discovery is not needed; refresh exposes the first candidate"
                )
            }
            let view = controller
                .approve_pending()
                .map_err(|error| anyhow::anyhow!(error))?;
            println!("trusted both ways: {}", view.name);
        }
        "clipboard-read" | "paste-clipboard" => {
            let clipboard =
                ClipboardWorker::new().map_err(|error| anyhow::anyhow!(error.to_string()))?;
            match clipboard
                .read_item()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
            {
                ClipboardItem::Text(text) => print!("{text}"),
                ClipboardItem::Files(paths) => {
                    for path in paths {
                        println!("{}", path.display());
                    }
                }
            }
        }
        "send" => {
            if selector.is_some() {
                bail!("meshelf sends are mesh-wide; --peer is not supported for send")
            }
            let mut send_options = options.into_iter();
            let source = parse_send_source(&mut send_options)?;
            let requests = match source {
                SendSource::Text(text) => vec![LocalRequest::AnnounceText { text }],
                SendSource::Stdin => vec![LocalRequest::AnnounceText {
                    text: read_bounded_stdin()?,
                }],
                SendSource::Clipboard => {
                    let clipboard = ClipboardWorker::new()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    match clipboard
                        .read_item()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?
                    {
                        ClipboardItem::Text(text) => vec![LocalRequest::AnnounceText { text }],
                        ClipboardItem::Files(paths) => paths
                            .into_iter()
                            .map(|path| LocalRequest::AnnouncePath { path })
                            .collect(),
                    }
                }
            };
            for request in requests {
                submit_announce_request(&config_dir, request)?;
            }
        }
        _ => return usage(),
    }
    Ok(())
}

enum SendSource {
    Text(String),
    Stdin,
    Clipboard,
}

fn take_peer_selector(args: Vec<String>) -> Result<(Option<String>, Vec<String>)> {
    let mut selector = None;
    let mut remaining = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--peer" {
            selector = Some(
                args.next()
                    .context("--peer requires a hostname or device ID")?,
            );
        } else {
            remaining.push(arg);
        }
    }
    Ok((selector, remaining))
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn parse_send_source(args: &mut impl Iterator<Item = String>) -> Result<SendSource> {
    let mut source = None;
    while let Some(arg) = args.next() {
        let candidate = match arg.as_str() {
            "--clipboard" => SendSource::Clipboard,
            "--stdin" => SendSource::Stdin,
            "--text" => SendSource::Text(args.next().context("--text requires a value")?),
            _ => bail!("unknown send option: {arg}"),
        };
        if source.is_some() {
            bail!("choose exactly one of --clipboard, --stdin, or --text");
        }
        source = Some(candidate);
    }
    source.context("send requires --clipboard, --stdin, or --text")
}

fn read_bounded_stdin() -> Result<String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_TEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_TEXT_BYTES {
        bail!("stdin text exceeds the 1 MiB meshelf limit");
    }
    String::from_utf8(bytes).context("stdin is not valid UTF-8")
}

fn config_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("could not determine the per-user configuration directory")?
        .join("meshelf"))
}

#[derive(Debug, Clone)]
struct HeadlessTrustGate {
    store: InstallationStore,
    identity: DeviceId,
}

impl TrustGate for HeadlessTrustGate {
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
            Some(_) => TrustDecision::Deny(
                "approved peer key or Tailscale address does not match".to_owned(),
            ),
            None => TrustDecision::Deny("meshelf installation has not been approved".to_owned()),
        }
    }
}

struct HeadlessServerHandle {
    shutdown: watch::Sender<bool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for HeadlessServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug)]
struct HeadlessActivationClipboard(Option<ClipboardWorker>);

impl ClipboardSink for HeadlessActivationClipboard {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        self.0
            .as_ref()
            .ok_or_else(|| ClipboardError::new("clipboard is unavailable for this activation"))?
            .set_text(text)
    }
}

impl FetchClipboard for HeadlessActivationClipboard {
    fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
        self.0
            .as_ref()
            .ok_or_else(|| ClipboardError::new("clipboard is unavailable for this activation"))?
            .set_files(paths)
            .map_err(ClipboardError::from)
    }
}

struct HeadlessRuntime {
    state_path: PathBuf,
    identity: InstallationIdentity,
    device_name: String,
    offer_store: Arc<RedbV2Store>,
    state_root: PathBuf,
}

impl LocalRuntime for HeadlessRuntime {
    fn announce(&self, plan: &OfferPlan) -> Result<(), String> {
        let report =
            announce_offer_plan(&self.state_path, &self.identity, &self.device_name, plan)?;
        if report.stored_on.is_empty() {
            return Err(format!(
                "offer was not stored on any peer{}",
                if report.unavailable.is_empty() {
                    String::new()
                } else {
                    format!(": unavailable {}", report.unavailable.join(", "))
                }
            ));
        }
        Ok(())
    }

    fn activate(&self, plan: &ActivationPlan) -> Result<(), String> {
        let state = InstallationStore::new(self.state_path.clone())
            .load_for_identity(self.identity.device_id)
            .map_err(|error| format!("could not load meshelf state: {error}"))?;
        let peer = state
            .peers
            .by_device_id(plan.source_device)
            .ok_or_else(|| "the offer's source device is not paired".to_owned())?;
        let address = peer
            .addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4())
            .or_else(|| peer.addresses.first().copied())
            .map(|address| SocketAddr::new(address, MESHELF_PORT))
            .ok_or_else(|| "the offer's source device has no address".to_owned())?;
        let destination = match plan.mode {
            ActivationMode::Clipboard => None,
            ActivationMode::Save => Some(resolve_save_destination(
                plan.destination
                    .as_ref()
                    .ok_or_else(|| "save activation has no destination setting".to_owned())?,
            )?),
        };
        let request = FetchRequest {
            request_id: plan.activation_id,
            offer_id: plan.offer_id,
            source_device: plan.source_device,
            requester_device: self.identity.device_id,
        };
        let input = HeadlessActivationInput {
            address,
            hello: ClientHello::signed_v2(
                self.identity.device_id,
                self.device_name.clone(),
                plan.activation_id.to_string(),
                &self.identity,
            ),
            request,
            activation: FetchActivation::new(
                plan.activation_id,
                plan.source_device,
                plan.offer_id,
                plan.mode,
                destination,
            ),
            expected_server_public_key: peer.public_key.clone(),
        };
        let offer_store = self.offer_store.clone();
        let state_root = self.state_root.clone();
        let clipboard = if plan.mode == ActivationMode::Clipboard {
            Some(ClipboardWorker::new().map_err(|error| error.to_string())?)
        } else {
            None
        };
        run_headless_activation(input, offer_store, clipboard, state_root)
    }
}

struct HeadlessActivationInput {
    address: SocketAddr,
    hello: ClientHello,
    request: FetchRequest,
    activation: FetchActivation,
    expected_server_public_key: Vec<u8>,
}

fn run_headless_activation(
    input: HeadlessActivationInput,
    offer_store: Arc<RedbV2Store>,
    clipboard: Option<ClipboardWorker>,
    state_root: PathBuf,
) -> Result<(), String> {
    let local_device = input.hello.device_id;
    let receiver = FetchReceiver::new(
        local_device,
        offer_store,
        Arc::new(HeadlessActivationClipboard(clipboard)),
        state_root,
    );
    receiver
        .startup_cleanup()
        .map_err(|error| format!("activation cleanup is unavailable: {error}"))?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("activation runtime unavailable: {error}"))?;
    let client = PeerClient::with_timeouts(Duration::from_secs(3), Duration::from_secs(5));
    runtime.block_on(async move {
        client
            .fetch_v2(
                input.address,
                input.hello,
                input.request,
                input.activation,
                &input.expected_server_public_key,
                &receiver,
            )
            .await
            .map_err(|error| error.to_string())
    })
}

fn start_v2_listener(
    state: &Controller,
    offer_store: Arc<RedbV2Store>,
) -> Result<HeadlessServerHandle, String> {
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
    let announcement_receiver = Arc::new(OfferAnnouncementHandler::new(offer_store.clone()));
    let fetch_sender = Arc::new(OfferFetchHandler::new(
        state.installation.device_id,
        offer_store,
    ));
    let identity = ServerIdentity {
        signing_identity: state.identity.clone(),
        device_name: state.device_name.clone(),
    };
    let gate = Arc::new(HeadlessTrustGate {
        store: InstallationStore::new(state.state_path.clone()),
        identity: state.identity.device_id,
    });
    let (shutdown, shutdown_rx) = watch::channel(false);
    let worker = thread::Builder::new()
        .name("meshelfctl-network-v2".to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                tracing::error!("meshelfctl listener runtime could not be created");
                return;
            };
            let Ok(listener) =
                runtime.block_on(async { tokio::net::TcpListener::from_std(listener) })
            else {
                tracing::error!("meshelfctl listener could not attach to its server runtime");
                return;
            };
            if let Err(error) = runtime.block_on(serve_v2_with_offers_and_fetch(
                listener,
                identity,
                gate,
                V2OfferServices {
                    announcement_receiver,
                    fetch_sender,
                },
                Duration::from_secs(5),
                shutdown_rx,
            )) {
                tracing::error!(%error, "meshelfctl listener stopped unexpectedly");
            }
        })
        .map_err(|error| format!("could not start Tailscale listener: {error}"))?;
    Ok(HeadlessServerHandle {
        shutdown,
        worker: Some(worker),
    })
}

fn run_serve(args: Vec<String>) -> Result<()> {
    if !args.is_empty() {
        bail!("serve does not accept options")
    }
    let data_dir = config_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    let Some(_resident_lock) = acquire_resident_lock(&data_dir)? else {
        bail!("another meshelf resident already owns the local control channel")
    };
    let state_path = data_dir.join("state.json");
    let mut controller =
        Controller::load(state_path.clone(), device_name()?).map_err(anyhow::Error::msg)?;
    let offer_store = Arc::new(
        RedbV2Store::open(data_dir.join("meshelf.redb"))
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
    controller.refresh().map_err(anyhow::Error::msg)?;
    let _server =
        start_v2_listener(&controller, offer_store.clone()).map_err(anyhow::Error::msg)?;
    let coordinator = Arc::new(
        Coordinator::new(
            controller.identity.device_id,
            InstallationStore::new(state_path.clone()),
            offer_store.clone(),
        )
        .with_card_store(offer_store.clone()),
    );
    let runtime = Arc::new(HeadlessRuntime {
        state_path,
        identity: controller.identity.clone(),
        device_name: controller.device_name.clone(),
        offer_store,
        state_root: data_dir.clone(),
    });
    let control_coordinator = coordinator.clone();
    let control_runtime = runtime.clone();
    let (_stop_sender, stop_receiver) = std::sync::mpsc::channel::<()>();
    listen_with_control(
        &data_dir,
        || {},
        move |request| {
            local_control::dispatch_bytes_with_runtime(
                &control_coordinator,
                request,
                control_runtime.as_ref(),
            )
        },
    )?;
    stop_receiver
        .recv()
        .map_err(|_| anyhow::anyhow!("local control listener stopped"))?;
    Ok(())
}

fn device_name() -> Result<String> {
    Ok(std::env::var("MESHELF_DEVICE_NAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".to_owned()))
}

fn submit_announce_request(config: &std::path::Path, request: LocalRequest) -> Result<()> {
    let encoded = local_control::encode_request(&request)?;
    let response =
        control_request(config, &encoded).context("could not contact the meshelf resident")?;
    match serde_json::from_slice::<LocalResponse>(&response)? {
        LocalResponse::OfferCreated {
            offer_id,
            announcements,
            ..
        } => println!(
            "Announced offer {offer_id} to {} paired device(s)",
            announcements.len()
        ),
        LocalResponse::NoPeers => bail!("no other meshelf device is paired"),
        LocalResponse::Error { message } => bail!("{message}"),
        other => bail!("resident returned an unexpected response: {other:?}"),
    }
    Ok(())
}

fn run_announce(args: Vec<String>) -> Result<()> {
    let mut source = None;
    let mut arguments = args.into_iter();
    while let Some(argument) = arguments.next() {
        let candidate = match argument.as_str() {
            "--clipboard" => {
                let clipboard =
                    ClipboardWorker::new().map_err(|error| anyhow::anyhow!(error.to_string()))?;
                match clipboard
                    .read_item()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
                {
                    ClipboardItem::Text(text) => LocalRequest::AnnounceText { text },
                    ClipboardItem::Files(paths) if paths.len() == 1 => LocalRequest::AnnouncePath {
                        path: paths.into_iter().next().expect("one path"),
                    },
                    ClipboardItem::Files(paths) => {
                        bail!(
                            "announce --clipboard requires one file or folder; clipboard contains {}",
                            paths.len()
                        )
                    }
                }
            }
            "--text" => LocalRequest::AnnounceText {
                text: arguments.next().context("--text requires a value")?,
            },
            "--stdin" => LocalRequest::AnnounceText {
                text: read_bounded_stdin()?,
            },
            "--path" => LocalRequest::AnnouncePath {
                path: PathBuf::from(arguments.next().context("--path requires a value")?),
            },
            _ => bail!("unknown announce option: {argument}"),
        };
        if source.is_some() {
            bail!("choose exactly one of --text, --stdin, or --path");
        }
        source = Some(candidate);
    }
    let request = source.context("announce requires --clipboard, --text, --stdin, or --path")?;
    let encoded = local_control::encode_request(&request)?;
    let response = control_request(&config_dir()?, &encoded)
        .context("could not contact the meshelf resident")?;
    let response: LocalResponse = serde_json::from_slice(&response)?;
    match response {
        LocalResponse::OfferCreated {
            offer_id,
            announcements,
            ..
        } => println!(
            "Announced offer {offer_id} to {} paired device(s)",
            announcements.len()
        ),
        LocalResponse::NoPeers => bail!("no other meshelf device is paired"),
        LocalResponse::Error { message } => bail!("{message}"),
        LocalResponse::RefusalRecorded | LocalResponse::Settings { .. } => {
            bail!("resident returned an unexpected response")
        }
        LocalResponse::Shelf { .. }
        | LocalResponse::ActivationCompleted { .. }
        | LocalResponse::ActivationCancelled { .. }
        | LocalResponse::ActivationRefused { .. } => {
            bail!("resident returned an unexpected response")
        }
    }
    Ok(())
}

fn run_shelf(args: Vec<String>) -> Result<()> {
    if !args.is_empty() {
        bail!("shelf does not accept options")
    }
    let request = local_control::encode_request(&LocalRequest::Shelf)?;
    let response = control_request(&config_dir()?, &request)
        .context("could not contact the meshelf resident")?;
    match serde_json::from_slice::<LocalResponse>(&response)? {
        LocalResponse::Shelf { offers } => {
            for offer in offers {
                println!(
                    "{}\t{}\t{}",
                    offer.offer_id,
                    offer.source_device,
                    descriptor_kind(&offer.descriptor)
                );
            }
        }
        LocalResponse::Error { message } => bail!("{message}"),
        other => bail!("resident returned an unexpected response: {other:?}"),
    }
    Ok(())
}

fn descriptor_kind(descriptor: &OfferDescriptor) -> &'static str {
    match descriptor {
        OfferDescriptor::Text { .. } => "text",
        OfferDescriptor::File { .. } => "file",
        OfferDescriptor::Folder { .. } => "folder",
    }
}

fn run_activate(args: Vec<String>) -> Result<()> {
    let mut arguments = args.into_iter();
    let offer_id: OfferId = arguments
        .next()
        .context("activate requires OFFER_ID")?
        .parse()
        .context("OFFER_ID is not a valid offer ID")?;
    let mut mode = ActivationMode::Clipboard;
    for argument in arguments {
        match argument.as_str() {
            "--save" => mode = ActivationMode::Save,
            _ => bail!("unknown activate option: {argument}"),
        }
    }
    let request = local_control::encode_request(&LocalRequest::ActivateOffer { offer_id, mode })?;
    let response = control_request(&config_dir()?, &request)
        .context("could not contact the meshelf resident")?;
    match serde_json::from_slice::<LocalResponse>(&response)? {
        LocalResponse::ActivationCompleted {
            activation_id,
            offer_id,
            mode,
            files_processed,
            bytes_processed,
        } => println!(
            "activation {activation_id} completed for {offer_id} ({mode:?}; files {files_processed}, bytes {bytes_processed})"
        ),
        LocalResponse::ActivationRefused { message } => bail!("{message}"),
        LocalResponse::Error { message } => bail!("{message}"),
        other => bail!("resident returned an unexpected response: {other:?}"),
    }
    Ok(())
}

fn usage() -> Result<()> {
    bail!(
        "usage: meshelfctl [status|refresh|trust-ssh|clipboard-read|send|serve|announce|shelf|activate] [--peer NAME_OR_ID]\n  send requires exactly one of --clipboard, --stdin, or --text TEXT\n  announce requires exactly one of --clipboard, --text TEXT, --stdin, or --path PATH\n  activate requires OFFER_ID and optionally --save\n  pair-stdio is the fixed SSH bootstrap command"
    )
}
