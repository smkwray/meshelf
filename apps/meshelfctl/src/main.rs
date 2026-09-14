use std::{
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use meshelf_control::{
    ActivationPlan, Controller, MESHELF_PORT, OfferPlan, announce_offer_plan,
    capture::{
        CaptureControl, CaptureHandle, CaptureReply, CaptureService, CaptureServiceConfig,
        CaptureStartInput, CaptureWait, WaitTicket,
    },
    coordinator::Coordinator,
    local_control::{self, LocalRequest, LocalResponse, LocalRuntime},
    pairing::{PairInput, PairOutcome, cli_discovery, pair_with_peer},
    report_announce_outcome,
};
use meshelf_core::{
    ActivationMode, CaptureLens, CaptureNotStarted, CaptureOutcome, CaptureReceipt,
    CaptureRequestId, CaptureRequestPhase, CaptureRequestRecord, CaptureTerminalCode,
    ClipboardError, ClipboardSink, MAX_CAPTURE_LIFETIME_MS, OfferDescriptor, OfferId,
    validate_capture_purpose,
};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    ActivationOutcome, ActivationService, CaptureAnnouncementRouter, FetchActivation,
    FetchClipboard, InstallationTrustGate, OfferAnnouncementHandler, OfferFetchHandler, PeerClient,
    ServerIdentity, StoreCatalogOrigin, V2CaptureReceiver, V2OfferServices, V2ServerConfig,
    bind_discovered_tailscale_std_listener, select_discovered_ip, select_discovered_socket,
    serve_v2,
};
use meshelf_platform::{
    ClipboardItem, ClipboardSource, ClipboardWorker, WaitOutcome, WaitToken, acquire_resident_lock,
    listen_with_control, request as control_request, resolve_save_destination,
    wait as attach_to_wait,
};
use meshelf_protocol::{CAP_CAPTURE_REQUEST_V1, ClientHello, FetchRequest, pairing::PairingResult};
use meshelf_store::RedbV2Store;
use meshelf_tailscale::InstallationStore;
use tokio::runtime::Builder;
use tokio::sync::watch;

const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// One capture control operation's connect and I/O bounds, matching the activation client's.
const CAPTURE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CAPTURE_IO_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return usage();
    };
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
    if command == "capture" {
        return run_capture(remaining);
    }
    if command == "pair" {
        return run_pair(remaining);
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
            }
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
    activations: Arc<ActivationService<HeadlessActivationClipboard>>,
    capture: CaptureHandle<HeadlessActivationClipboard>,
}

impl LocalRuntime for HeadlessRuntime {
    fn capture(&self) -> Option<&dyn CaptureControl> {
        Some(&self.capture)
    }

    fn announce(&self, plan: &OfferPlan) -> Result<String, String> {
        report_announce_outcome(announce_offer_plan(
            &self.state_path,
            &self.identity,
            &self.device_name,
            plan,
        )?)
    }

    fn activate(&self, plan: &ActivationPlan) -> Result<ActivationOutcome, String> {
        let state = InstallationStore::new(self.state_path.clone())
            .load_for_identity(self.identity.device_id)
            .map_err(|error| format!("could not load meshelf state: {error}"))?;
        let peer = state
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
        let (_cancel, cancel) = watch::channel(false);
        run_headless_activation(input, self.activations.clone(), cancel)
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
    service: Arc<ActivationService<HeadlessActivationClipboard>>,
    cancel: watch::Receiver<bool>,
) -> Result<ActivationOutcome, String> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("activation runtime unavailable: {error}"))?;
    let client = PeerClient::with_timeouts(Duration::from_secs(3), Duration::from_secs(5));
    runtime.block_on(async move {
        service
            .activate(
                &client,
                input.address,
                input.hello,
                input.request,
                input.activation,
                &input.expected_server_public_key,
                cancel,
            )
            .await
            .map_err(|error| error.to_string())
    })
}

fn start_v2_listener(
    state: &Controller,
    offer_store: Arc<RedbV2Store>,
    capture_router: Arc<dyn CaptureAnnouncementRouter>,
    capture_receiver: Arc<dyn V2CaptureReceiver>,
) -> Result<HeadlessServerHandle, String> {
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
    // Correlated announcements must reach the capture request that authorized them before the
    // shelf sees them; without a router every correlated announcement is refused.
    let announcement_receiver = Arc::new(
        OfferAnnouncementHandler::new(offer_store.clone()).with_capture_router(capture_router),
    );
    let device_id = state.installation.device_id;
    let fetch_sender = Arc::new(OfferFetchHandler::new(device_id, offer_store.clone()));
    let identity = ServerIdentity {
        signing_identity: state.identity.clone(),
        device_name: state.device_name.clone(),
    };
    let gate = Arc::new(InstallationTrustGate::new(
        InstallationStore::new(state.state_path.clone()),
        state.identity.device_id,
    ));
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
            let mut config = V2ServerConfig::desktop(
                identity,
                gate,
                V2OfferServices {
                    announcement_receiver,
                    fetch_sender,
                },
                CAPTURE_IO_TIMEOUT,
            )
            .with_catalog_origin(Arc::new(StoreCatalogOrigin::new(offer_store, device_id)));
            // This resident sends capture requests and durably records the phone's statuses, so it
            // says so in its hello and answers with its own receiver rather than `unsupported`
            // (F7). Refusal capabilities stay as the desktop default: a desktop's refusal still
            // advertises only `offer-pull-v2` (F1).
            config.capture_receiver = capture_receiver;
            config
                .server_capabilities
                .push(CAP_CAPTURE_REQUEST_V1.to_owned());
            if let Err(error) = runtime.block_on(serve_v2(listener, config, shutdown_rx)) {
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
    let coordinator = Arc::new(
        Coordinator::new(
            controller.identity.device_id,
            InstallationStore::new(state_path.clone()),
            offer_store.clone(),
        )
        .with_card_store(offer_store.clone()),
    );
    let activations = Arc::new(ActivationService::new(
        controller.identity.device_id,
        offer_store.clone(),
        Arc::new(HeadlessActivationClipboard(ClipboardWorker::new().ok())),
        data_dir.clone(),
    ));
    activations
        .recover()
        .map_err(|error| anyhow::anyhow!("activation cleanup is unavailable: {error}"))?;
    let capture = CaptureService::start(CaptureServiceConfig {
        identity: controller.identity.clone(),
        device_name: controller.device_name.clone(),
        coordinator: coordinator.clone(),
        store: offer_store.clone(),
        activations: activations.clone(),
        client: PeerClient::with_timeouts(CAPTURE_CONNECT_TIMEOUT, CAPTURE_IO_TIMEOUT),
        port: MESHELF_PORT,
    })
    .map_err(|error| anyhow::anyhow!("could not start the capture service: {error}"))?;
    // Requester-side capture effects are never resumed. Rows this resident left behind end here,
    // before the listener exists to take a correlated announcement for one of them.
    let reconciliation = capture.reconcile_at_startup().map_err(anyhow::Error::msg)?;
    tracing::info!(
        cancelled = reconciliation.cancel.len(),
        restarted_after_expiry = reconciliation.restarted_after_expiry.len(),
        uncertain = reconciliation.uncertain.len(),
        pruned_reported = reconciliation.pruned_reported,
        "capture requests reconciled before network binding"
    );
    let _server = start_v2_listener(
        &controller,
        offer_store.clone(),
        capture.router(),
        capture.receiver(),
    )
    .map_err(anyhow::Error::msg)?;
    let runtime = Arc::new(HeadlessRuntime {
        state_path,
        identity: controller.identity.clone(),
        device_name: controller.device_name.clone(),
        activations,
        capture: capture.handle(),
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
            offer_id, status, ..
        } => println!("Announced offer {offer_id}: {status}"),
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
            offer_id, status, ..
        } => println!("Announced offer {offer_id}: {status}"),
        LocalResponse::NoPeers => bail!("no other meshelf device is paired"),
        LocalResponse::Error { message } => bail!("{message}"),
        LocalResponse::RefusalRecorded | LocalResponse::Settings { .. } => {
            bail!("resident returned an unexpected response")
        }
        LocalResponse::Shelf { .. }
        | LocalResponse::ActivationCompleted { .. }
        | LocalResponse::ActivationCancelled { .. }
        | LocalResponse::ActivationRefused { .. }
        | LocalResponse::Capture { .. } => {
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
        LocalResponse::ActivationCancelled { .. } => bail!("activation cancelled"),
        LocalResponse::ActivationRefused { message } => bail!("{message}"),
        LocalResponse::Error { message } => bail!("{message}"),
        other => bail!("resident returned an unexpected response: {other:?}"),
    }
    Ok(())
}

// --- capture ---------------------------------------------------------------
//
// One command is one durable capture request. The resident owns every decision this CLI reports:
// it preflights the output path, writes the row, and decides the outcome. The CLI's whole job is
// to name the request, sleep on the resident's wait channel until the outcome exists, and print
// exactly one answer.
//
// **A capture is never reissued (invariant 10).** By the time a wait fails, the phone may already
// have taken and sent the photograph. So a lost wait makes exactly one `CaptureQuery` and reports
// what the durable row says; if that row has not finished, the answer is `capture_uncertain` with
// `"replay": "forbidden"`. No path here sends a second `CaptureStart`.

/// The JSON type of an uncertain outcome, read from the core table rather than restated here.
const CAPTURE_UNCERTAIN_TYPE: &str = CaptureTerminalCode::UncertainNoReplay.outcome().json_type;

/// A capture that is durably started but has no outcome yet. Core decides every *finished*
/// answer; it has none for a live request, so these two words and their exit code are the CLI's
/// own vocabulary and are deliberately not `capture_completed`.
const CAPTURE_STARTED: CaptureOutcome = CaptureOutcome {
    json_type: "capture_started",
    reason: "started",
    exit_code: 0,
};

/// Why a wait could not happen at all. The resident issues no ticket when its eight waiter slots
/// are full, and a `Started` reply carrying none is indistinguishable from one for a caller that
/// never asked; the CLI treats it as the refusal it is rather than as a capture it may ignore.
const NO_WAIT_TICKET: &str =
    "the resident issued no wait ticket, so this capture cannot be waited on";

/// Extra client patience on top of the ticket's own deadline, so the resident's deadline answer
/// arrives before the client stops reading.
const WAIT_CLIENT_MARGIN: Duration = Duration::from_secs(5);

/// One finished CLI answer: the outcome authority plus whatever the durable row carried.
#[derive(Debug)]
struct CaptureReport {
    outcome: CaptureOutcome,
    request_id: Option<CaptureRequestId>,
    /// Boxed so a refusal, which is what the parsers return, stays small.
    receipt: Option<Box<CaptureReceipt>>,
    detail: Option<String>,
}

impl CaptureReport {
    fn new(outcome: CaptureOutcome) -> Self {
        Self {
            outcome,
            request_id: None,
            receipt: None,
            detail: None,
        }
    }

    fn not_started(reason: CaptureNotStarted) -> Self {
        Self::new(reason.outcome())
    }

    /// A refusal this CLI can make on its own: the invocation itself is wrong.
    fn invalid(detail: impl Into<String>) -> Self {
        Self::not_started(CaptureNotStarted::InvalidArguments).with_detail(detail)
    }

    fn with_request(mut self, request_id: CaptureRequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Every reported field in one place, so the JSON object and the human line cannot disagree.
    fn fields(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut fields = serde_json::Map::new();
        fields.insert("type".to_owned(), self.outcome.json_type.into());
        fields.insert("reason".to_owned(), self.outcome.reason.into());
        if let Some(request_id) = self.request_id {
            fields.insert("request_id".to_owned(), request_id.to_string().into());
        }
        // The receipt's own serialization is the authority for its values, hex digest included.
        if let Some(receipt) = &self.receipt
            && let Ok(serde_json::Value::Object(recorded)) = serde_json::to_value(receipt)
        {
            for (key, value) in recorded {
                let key = if key == "output_path" {
                    "output".to_owned()
                } else {
                    key
                };
                fields.insert(key, value);
            }
        }
        if let Some(detail) = &self.detail {
            fields.insert("detail".to_owned(), detail.clone().into());
        }
        // Every uncertain answer says so explicitly: the caller must not run the command again.
        if self.outcome.json_type == CAPTURE_UNCERTAIN_TYPE {
            fields.insert("replay".to_owned(), "forbidden".into());
        }
        fields
    }

    fn render(&self, json: bool) -> String {
        render_fields(&self.fields(), json)
    }

    /// One object on stdout, then the exit code the outcome decided. Progress went to stderr.
    fn emit(self, json: bool) -> ! {
        println!("{}", self.render(json));
        std::process::exit(i32::from(self.outcome.exit_code))
    }
}

/// One line: the JSON object itself, or its fields as `key=value` for a person.
fn render_fields(fields: &serde_json::Map<String, serde_json::Value>, json: bool) -> String {
    if json {
        return serde_json::Value::Object(fields.clone()).to_string();
    }
    fields
        .iter()
        .map(|(key, value)| match value {
            serde_json::Value::String(text) => format!("{key}={text}"),
            other => format!("{key}={other}"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_capture(args: Vec<String>) -> Result<()> {
    let config = config_dir()?;
    let mut arguments = args.into_iter();
    let subcommand = arguments.next().unwrap_or_default();
    let rest = arguments.collect::<Vec<_>>();
    let json = has_flag(&rest, "--json");
    let report = match subcommand.as_str() {
        "photo" => capture_photo(&config, rest),
        "status" => capture_status(&config, rest),
        "wait" => capture_wait(&config, rest),
        "cancel" => capture_cancel(&config, rest),
        other => CaptureReport::invalid(format!(
            "capture requires photo, status, wait, or cancel, not {other:?}"
        )),
    };
    report.emit(json)
}

struct PhotoOptions {
    peer: String,
    purpose: String,
    output: PathBuf,
    lens: Option<CaptureLens>,
    timeout_ms: u64,
    wait: bool,
}

fn capture_photo(config: &Path, args: Vec<String>) -> CaptureReport {
    let options = match parse_photo_options(args) {
        Ok(options) => options,
        Err(report) => return report,
    };
    let waited = options.wait;
    let request = LocalRequest::CaptureStart {
        input: CaptureStartInput {
            peer: options.peer,
            purpose: options.purpose,
            lens: options.lens,
            timeout_ms: options.timeout_ms,
            output_path: options.output,
            // A caller that will not wait must never take one of the eight waiter slots.
            wait: waited,
        },
    };
    match submit_capture(config, &request) {
        Ok(CaptureReply::Started { request_id, wait }) => match (waited, wait) {
            (false, _) => CaptureReport::new(CAPTURE_STARTED).with_request(request_id),
            (true, CaptureWait::Issued(ticket)) => {
                wait_for_capture_outcome(config, request_id, &ticket)
            }
            // A caller that asked to wait and was given no ticket was refused, not answered: the
            // resident issues none when the waiter cap is reached. The request is durable all the
            // same, so this is never reported as a capture that did not start, and a second
            // CaptureStart is forbidden however it happened. The one permitted status query
            // decides, and anything short of a finished row is reported uncertain (exit 5) rather
            // than as a started capture the caller would read as success.
            (true, CaptureWait::Refused | CaptureWait::NotRequested) => {
                single_status_query(config, request_id, NO_WAIT_TICKET)
            }
        },
        Ok(CaptureReply::NotStarted { reason }) => CaptureReport::not_started(reason),
        Ok(CaptureReply::Request { record }) => report_for_record(&record),
        Err(detail) => {
            CaptureReport::not_started(CaptureNotStarted::ResidentUnavailable).with_detail(detail)
        }
    }
}

fn capture_status(config: &Path, args: Vec<String>) -> CaptureReport {
    let request_id = match parse_request_id(args, "status") {
        Ok(request_id) => request_id,
        Err(report) => return report,
    };
    report_for_reply(
        submit_capture(config, &LocalRequest::CaptureQuery { request_id }),
        request_id,
    )
}

fn capture_cancel(config: &Path, args: Vec<String>) -> CaptureReport {
    let request_id = match parse_request_id(args, "cancel") {
        Ok(request_id) => request_id,
        Err(report) => return report,
    };
    report_for_reply(
        submit_capture(config, &LocalRequest::CaptureCancel { request_id }),
        request_id,
    )
}

fn capture_wait(config: &Path, args: Vec<String>) -> CaptureReport {
    let request_id = match parse_request_id(args, "wait") {
        Ok(request_id) => request_id,
        Err(report) => return report,
    };
    match submit_capture(config, &LocalRequest::CaptureWaitTicket { request_id }) {
        Ok(CaptureReply::Started {
            request_id,
            wait: CaptureWait::Issued(ticket),
        }) => wait_for_capture_outcome(config, request_id, &ticket),
        Ok(CaptureReply::Started {
            request_id,
            wait: CaptureWait::Refused | CaptureWait::NotRequested,
        }) => single_status_query(config, request_id, NO_WAIT_TICKET),
        other => report_for_reply(other, request_id),
    }
}

/// Sleeps on the resident's wait channel until it resolves. Nothing polls: this blocks in one
/// read, and every wake is a transition that already happened (invariant 12).
fn wait_for_capture_outcome(
    config: &Path,
    request_id: CaptureRequestId,
    ticket: &WaitTicket,
) -> CaptureReport {
    let Ok(token) = WaitToken::from_str(&ticket.token) else {
        return single_status_query(
            config,
            request_id,
            "the resident issued a malformed wait token",
        );
    };
    eprintln!("capture {request_id} started; waiting for its outcome");
    let outcome = attach_to_wait(
        ticket.port,
        &token,
        wait_read_timeout(ticket.deadline_unix_ms),
    );
    match classify_wait(outcome) {
        WaitResolution::Finished(record) => report_for_record(&record),
        WaitResolution::Uncertain(code) => CaptureReport::new(code.outcome())
            .with_request(request_id)
            .with_detail("the wait channel stopped before the capture had an outcome"),
        WaitResolution::Query(detail) => single_status_query(config, request_id, &detail),
    }
}

/// What one wait outcome means to the CLI.
#[derive(Debug)]
enum WaitResolution {
    /// The resident handed over the finished durable row, which is the whole answer.
    Finished(Box<CaptureRequestRecord>),
    Uncertain(CaptureTerminalCode),
    /// The wait delivered no outcome; the one permitted status query decides.
    Query(String),
}

/// `Shutdown` has no word in core, so it is mapped here: a resident that stopped while a capture
/// was live leaves the CLI unable to say whether the photograph was published, which is exactly
/// `resident_disconnected` and exit 5. Everything else that is not a finished row defers to the
/// single status query rather than inventing an outcome.
fn classify_wait(outcome: io::Result<WaitOutcome>) -> WaitResolution {
    match outcome {
        Ok(WaitOutcome::Completed(payload)) => {
            match serde_json::from_slice::<CaptureRequestRecord>(&payload) {
                Ok(record) if record.outcome().is_some() => {
                    WaitResolution::Finished(Box::new(record))
                }
                Ok(_) => WaitResolution::Query(
                    "the wait delivered a request that has not finished".to_owned(),
                ),
                Err(error) => {
                    WaitResolution::Query(format!("the wait outcome could not be read: {error}"))
                }
            }
        }
        Ok(WaitOutcome::Shutdown) => {
            WaitResolution::Uncertain(CaptureTerminalCode::ResidentDisconnected)
        }
        Ok(WaitOutcome::TimedOut) => WaitResolution::Query("the wait deadline passed".to_owned()),
        Ok(WaitOutcome::Refused(reason)) => {
            WaitResolution::Query(format!("the wait was refused: {reason}"))
        }
        Err(error) => WaitResolution::Query(format!("the wait connection failed: {error}")),
    }
}

/// The one status query a lost wait may make. The capture's side effects may already have
/// happened, so `CaptureStart` is never reissued (invariant 10) and a row that has not finished is
/// reported uncertain rather than retried.
fn single_status_query(
    config: &Path,
    request_id: CaptureRequestId,
    context: &str,
) -> CaptureReport {
    let uncertain = |detail: String| {
        CaptureReport::new(CaptureTerminalCode::UncertainNoReplay.outcome())
            .with_request(request_id)
            .with_detail(detail)
    };
    match submit_capture(config, &LocalRequest::CaptureQuery { request_id }) {
        Ok(CaptureReply::Request { record }) if record.outcome().is_some() => {
            report_for_record(&record)
        }
        Ok(CaptureReply::Request { .. }) => uncertain(format!(
            "{context}; the request is still live and is never reissued"
        )),
        Ok(CaptureReply::NotStarted { reason }) => uncertain(format!(
            "{context}; the resident answered {}",
            reason.as_str()
        )),
        Ok(CaptureReply::Started { .. }) => uncertain(format!(
            "{context}; the resident answered a started capture"
        )),
        Err(detail) => uncertain(format!("{context}; {detail}")),
    }
}

fn report_for_reply(
    reply: Result<CaptureReply, String>,
    request_id: CaptureRequestId,
) -> CaptureReport {
    match reply {
        Ok(CaptureReply::Request { record }) => report_for_record(&record),
        Ok(CaptureReply::NotStarted { reason }) => {
            CaptureReport::not_started(reason).with_request(request_id)
        }
        Ok(CaptureReply::Started { request_id, .. }) => {
            CaptureReport::new(CAPTURE_STARTED).with_request(request_id)
        }
        Err(detail) => CaptureReport::not_started(CaptureNotStarted::ResidentUnavailable)
            .with_request(request_id)
            .with_detail(detail),
    }
}

/// Reads a durable row the only way the CLI may: [`CaptureRequestRecord::outcome`] is the sole
/// authority for the reported type, reason, and exit code.
fn report_for_record(record: &CaptureRequestRecord) -> CaptureReport {
    let mut report = match record.outcome() {
        Some(outcome) => CaptureReport::new(outcome),
        None => CaptureReport::new(CaptureOutcome {
            json_type: "capture_pending",
            reason: live_phase_word(&record.phase),
            exit_code: 0,
        }),
    };
    report.request_id = Some(record.request_id);
    match &record.phase {
        CaptureRequestPhase::Completed { receipt } => {
            report.receipt = Some(Box::new(receipt.clone()));
        }
        CaptureRequestPhase::Terminal { detail, .. } => report.detail.clone_from(detail),
        _ => {}
    }
    report
}

/// A live request has no outcome; these words say only which stage it has reached.
fn live_phase_word(phase: &CaptureRequestPhase) -> &'static str {
    match phase {
        CaptureRequestPhase::AwaitingPresentation => "awaiting_presentation",
        CaptureRequestPhase::Armed { .. } => "armed",
        CaptureRequestPhase::Claimed { .. } => "claimed",
        CaptureRequestPhase::Completed { .. } | CaptureRequestPhase::Terminal { .. } => "finished",
    }
}

/// One local-control round trip. The error is a message, not an outcome: each caller decides what
/// a failed round trip means for the operation it was performing.
fn submit_capture(config: &Path, request: &LocalRequest) -> Result<CaptureReply, String> {
    let encoded = local_control::encode_request(request)
        .map_err(|error| format!("could not encode the capture request: {error}"))?;
    let response = control_request(config, &encoded)
        .map_err(|error| format!("could not contact the meshelf resident: {error}"))?;
    match serde_json::from_slice::<LocalResponse>(&response) {
        Ok(LocalResponse::Capture { reply }) => Ok(reply),
        Ok(LocalResponse::Error { message }) => Err(message),
        Ok(other) => Err(format!(
            "resident returned an unexpected response: {other:?}"
        )),
        Err(error) => Err(format!("resident returned invalid JSON: {error}")),
    }
}

fn parse_photo_options(args: Vec<String>) -> Result<PhotoOptions, CaptureReport> {
    let mut peer = None;
    let mut purpose = None;
    let mut output = None;
    let mut lens = None;
    let mut timeout_ms = MAX_CAPTURE_LIFETIME_MS;
    let mut wait = false;
    let mut arguments = args.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--peer" => peer = Some(option_value(&mut arguments, "--peer")?),
            "--purpose" => purpose = Some(option_value(&mut arguments, "--purpose")?),
            "--output" => output = Some(PathBuf::from(option_value(&mut arguments, "--output")?)),
            "--lens" => lens = Some(parse_lens(&option_value(&mut arguments, "--lens")?)?),
            "--timeout" => {
                timeout_ms = parse_capture_timeout(&option_value(&mut arguments, "--timeout")?)?;
            }
            "--wait" => wait = true,
            "--json" => {}
            other => {
                return Err(CaptureReport::invalid(format!(
                    "unknown capture photo option: {other}"
                )));
            }
        }
    }
    let peer = peer.ok_or_else(|| CaptureReport::invalid("capture photo requires --peer"))?;
    let purpose =
        purpose.ok_or_else(|| CaptureReport::invalid("capture photo requires --purpose"))?;
    // The same validator the resident and the protocol use, so a purpose accepted here is one the
    // phone can display. This only saves a round trip; the resident refuses it again.
    validate_capture_purpose(&purpose)
        .map_err(|error| CaptureReport::invalid(format!("capture purpose is invalid: {error}")))?;
    let output = output.ok_or_else(|| CaptureReport::invalid("capture photo requires --output"))?;
    Ok(PhotoOptions {
        peer,
        purpose,
        output: preflight_output(&output)?,
        lens,
        timeout_ms,
        wait,
    })
}

fn option_value(
    arguments: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, CaptureReport> {
    arguments
        .next()
        .ok_or_else(|| CaptureReport::invalid(format!("{flag} requires a value")))
}

fn parse_lens(value: &str) -> Result<CaptureLens, CaptureReport> {
    match value {
        "front" => Ok(CaptureLens::Front),
        "rear" => Ok(CaptureLens::Rear),
        other => Err(CaptureReport::invalid(format!(
            "capture lens must be front or rear, not {other:?}"
        ))),
    }
}

/// Whole seconds, bounded by the protocol's own capture lifetime. This is not the authority for
/// that bound: `validate_capture_lifetime` refuses the same request inside the resident.
fn parse_capture_timeout(value: &str) -> Result<u64, CaptureReport> {
    let seconds: u64 = value.parse().map_err(|_| {
        CaptureReport::invalid(format!(
            "capture timeout is not a whole number of seconds: {value}"
        ))
    })?;
    seconds
        .checked_mul(1_000)
        .filter(|milliseconds| *milliseconds > 0 && *milliseconds <= MAX_CAPTURE_LIFETIME_MS)
        .ok_or_else(|| {
            CaptureReport::invalid(format!(
                "capture timeout must be between 1 and {} seconds",
                MAX_CAPTURE_LIFETIME_MS / 1_000
            ))
        })
}

fn parse_request_id(args: Vec<String>, command: &str) -> Result<CaptureRequestId, CaptureReport> {
    let mut arguments = args.into_iter();
    let Some(value) = arguments.next() else {
        return Err(CaptureReport::invalid(format!(
            "capture {command} requires REQUEST_ID"
        )));
    };
    let request_id = value.parse::<CaptureRequestId>().map_err(|_| {
        CaptureReport::invalid(format!(
            "REQUEST_ID is not a valid capture request id: {value}"
        ))
    })?;
    for argument in arguments {
        if argument != "--json" {
            return Err(CaptureReport::invalid(format!(
                "unknown capture {command} option: {argument}"
            )));
        }
    }
    Ok(request_id)
}

/// A courtesy check that can only refuse what the resident refuses anyway. The resident
/// canonicalizes the parent and re-runs `preflight_exact_output`, and its answer is authoritative,
/// so nothing here inspects the parent. `symlink_metadata`, never `exists`: a dangling symlink is
/// an object at the target and the resident refuses it (F8).
fn preflight_output(requested: &Path) -> Result<PathBuf, CaptureReport> {
    let absolute = std::path::absolute(requested).map_err(|error| {
        CaptureReport::invalid(format!("could not make the output path absolute: {error}"))
    })?;
    match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Err(
            CaptureReport::not_started(CaptureNotStarted::OutputIsDirectory),
        ),
        Ok(_) => Err(CaptureReport::not_started(CaptureNotStarted::OutputExists)),
        // Absent, or unreadable for a reason only the resident can rule on.
        Err(_) => Ok(absolute),
    }
}

fn wait_read_timeout(deadline_unix_ms: u64) -> Duration {
    Duration::from_millis(deadline_unix_ms.saturating_sub(now_unix_ms()))
        .saturating_add(WAIT_CLIENT_MARGIN)
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// --- pair ------------------------------------------------------------------
//
// Pairing runs standalone, with no resident: a person has to compare a six-digit code on two
// screens, which takes longer than the local-control client's five-second read timeout. The code
// goes to stderr, so `--json` stdout stays exactly one object.

fn run_pair(args: Vec<String>) -> Result<()> {
    let json = has_flag(&args, "--json");
    let outcome = pair_peer(args);
    let exit_code = outcome.exit_code();
    println!("{}", render_pair(&outcome, json));
    std::process::exit(i32::from(exit_code))
}

fn pair_peer(args: Vec<String>) -> PairOutcome {
    let mut peer = None;
    let mut arguments = args.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--peer" => match arguments.next() {
                Some(value) => peer = Some(value),
                None => {
                    return unresolved("--peer requires a hostname, node id, or device id");
                }
            },
            "--json" => {}
            other => return unresolved(format!("unknown pair option: {other}")),
        }
    }
    let Some(peer) = peer else {
        return unresolved("pair requires --peer");
    };
    let identity = match InstallationIdentity::load_or_create() {
        Ok(identity) => identity,
        Err(error) => {
            return pairing_failed(format!(
                "could not load the meshelf installation identity: {error}"
            ));
        }
    };
    let config = match config_dir().and_then(|config| {
        std::fs::create_dir_all(&config)?;
        Ok(config)
    }) {
        Ok(config) => config,
        Err(error) => {
            return pairing_failed(format!("could not open the meshelf configuration: {error}"));
        }
    };
    // Discovery is only how the phone's address is found; it is never authorization. Without it
    // nothing is dialled and nothing is recorded.
    let discovery = match cli_discovery() {
        Ok(discovery) => discovery,
        Err(detail) => return unresolved(detail),
    };
    pair_with_peer(PairInput {
        peer: &peer,
        identity,
        device_name: device_name().unwrap_or_else(|_| "This device".to_owned()),
        store: InstallationStore::new(config.join("state.json")),
        discovery: &discovery,
        on_candidate: &|candidate| {
            eprintln!(
                "pairing code for {}: {}",
                candidate.device_name, candidate.code
            );
            eprintln!(
                "compare it on the phone and confirm there within {} seconds",
                candidate.expires_at_unix_ms.saturating_sub(now_unix_ms()) / 1_000
            );
        },
    })
}

fn unresolved(detail: impl Into<String>) -> PairOutcome {
    PairOutcome::Unresolved {
        detail: detail.into(),
    }
}

fn pairing_failed(detail: String) -> PairOutcome {
    PairOutcome::Failed {
        result: PairingResult::Failed,
        trust_recorded: false,
        detail,
    }
}

/// [`PairOutcome::result_word`] and [`PairOutcome::exit_code`] are pairing's only authority for
/// how one ended; nothing is restated here.
fn render_pair(outcome: &PairOutcome, json: bool) -> String {
    let mut fields = serde_json::Map::new();
    fields.insert("type".to_owned(), "pair".into());
    fields.insert("result".to_owned(), outcome.result_word().into());
    match outcome {
        PairOutcome::Paired {
            hostname,
            device_id,
        } => {
            fields.insert("peer".to_owned(), hostname.clone().into());
            fields.insert("device_id".to_owned(), device_id.to_string().into());
        }
        PairOutcome::Unresolved { detail } => {
            fields.insert("detail".to_owned(), detail.clone().into());
        }
        PairOutcome::Failed {
            trust_recorded,
            detail,
            ..
        } => {
            // One-sided trust is the difference between "nothing happened" and "this desktop
            // recorded the phone and never heard back", which a rerun completes without a code.
            fields.insert("trust_recorded".to_owned(), (*trust_recorded).into());
            fields.insert("detail".to_owned(), detail.clone().into());
        }
    }
    render_fields(&fields, json)
}

fn usage() -> Result<()> {
    bail!(
        "usage: meshelfctl [status|refresh|clipboard-read|send|serve|announce|shelf|activate|capture|pair] [--peer NAME_OR_ID]\n  send requires exactly one of --clipboard, --stdin, or --text TEXT\n  announce requires exactly one of --clipboard, --text TEXT, --stdin, or --path PATH\n  activate requires OFFER_ID and optionally --save\n  capture photo --peer PEER --purpose TEXT --output PATH [--wait] [--timeout SECONDS] [--lens front|rear] [--json]\n  capture status|wait|cancel REQUEST_ID [--json]\n  pair --peer PEER [--json]"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, TcpListener},
        sync::Mutex,
    };

    use meshelf_core::{CaptureKind, CapturePullGrant, DeviceId, MessageId};

    #[test]
    fn mixed_family_peer_selects_listener_family_for_bind_and_activation() {
        let ipv6: IpAddr = "::1".parse().expect("ipv6");
        let ipv4: IpAddr = "127.0.0.1".parse().expect("ipv4");
        let addresses = [ipv6, ipv4];
        let bind = select_discovered_ip(&addresses).expect("bind");
        let dial = select_discovered_socket(&addresses, MESHELF_PORT).expect("dial");
        assert_eq!(bind, ipv4);
        assert_eq!(dial.ip(), bind);
    }

    /// A private directory for one test's control channel. This crate has no `tempfile`
    /// dependency and may not add one, so the directory is made and removed here.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("meshelfctl-{label}-{}", MessageId::new()));
            std::fs::create_dir_all(&path).expect("create the scratch directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A resident that answers capture requests from a script and records what it was asked, so a
    /// test can prove what the CLI did and did not send.
    struct FakeResident {
        scratch: Scratch,
        requests: Arc<Mutex<Vec<LocalRequest>>>,
    }

    impl FakeResident {
        fn start(
            label: &str,
            answer: impl Fn(&LocalRequest) -> LocalResponse + Send + Sync + 'static,
        ) -> Self {
            let scratch = Scratch::new(label);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            listen_with_control(
                &scratch.0,
                || {},
                move |bytes| {
                    let request = local_control::decode_request(bytes)?;
                    let response = answer(&request);
                    recorded
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(request);
                    serde_json::to_vec(&response).map_err(io::Error::other)
                },
            )
            .expect("start the fake resident");
            Self { scratch, requests }
        }

        fn config(&self) -> &Path {
            &self.scratch.0
        }

        fn requests(&self) -> Vec<LocalRequest> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn starts(&self) -> usize {
            self.requests()
                .iter()
                .filter(|request| matches!(request, LocalRequest::CaptureStart { .. }))
                .count()
        }

        fn queries(&self) -> usize {
            self.requests()
                .iter()
                .filter(|request| matches!(request, LocalRequest::CaptureQuery { .. }))
                .count()
        }
    }

    fn capture_response(reply: CaptureReply) -> LocalResponse {
        LocalResponse::Capture { reply }
    }

    fn record(phase: CaptureRequestPhase, output: &Path) -> CaptureRequestRecord {
        let peer = DeviceId::new();
        let created_at_unix_ms = now_unix_ms();
        CaptureRequestRecord {
            request_id: CaptureRequestId::new(),
            peer,
            peer_label: "amber".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: None,
            created_at_unix_ms,
            grant: CapturePullGrant {
                expected_source: peer,
                kind: CaptureKind::Photo,
                exact_output_path: output.to_path_buf(),
                expires_at_unix_ms: created_at_unix_ms + MAX_CAPTURE_LIFETIME_MS,
            },
            phase,
            terminal_reported: false,
        }
    }

    fn receipt(output: &Path) -> CaptureReceipt {
        CaptureReceipt {
            output_path: output.to_path_buf(),
            sha256: [0xAB; 32],
            bytes: 2_048,
            width: 4_032,
            height: 3_024,
        }
    }

    fn photo_args(output: &Path, wait: bool) -> Vec<String> {
        let mut args = vec![
            "--peer".to_owned(),
            "amber".to_owned(),
            "--purpose".to_owned(),
            "Photograph the router label".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
        ];
        if wait {
            args.push("--wait".to_owned());
        }
        args
    }

    /// A port nothing listens on, so attaching to the wait channel fails at once.
    fn closed_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind a scratch port");
        let port = listener.local_addr().expect("scratch address").port();
        drop(listener);
        port
    }

    fn ticket(port: u16) -> WaitTicket {
        WaitTicket {
            port,
            token: MessageId::new().to_string(),
            // Short, so a port that was reused by something else cannot hang this test.
            deadline_unix_ms: now_unix_ms() + 200,
        }
    }

    fn field(report: &CaptureReport, key: &str) -> Option<String> {
        report
            .fields()
            .get(key)
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
    }

    #[test]
    fn a_wait_whose_socket_fails_makes_one_status_query_and_never_reissues_the_start() {
        // Invariant 10. By the time the wait failed the phone may already have taken and sent the
        // photograph, so a second CaptureStart could publish a second one.
        let output = Scratch::new("lost-wait-output");
        let target = output.0.join("router-label.jpg");
        let live = record(CaptureRequestPhase::AwaitingPresentation, &target);
        let request_id = live.request_id;
        let port = closed_port();
        let resident = FakeResident::start("lost-wait", move |request| match request {
            LocalRequest::CaptureStart { .. } => capture_response(CaptureReply::Started {
                request_id,
                wait: CaptureWait::Issued(ticket(port)),
            }),
            LocalRequest::CaptureQuery { .. } => capture_response(CaptureReply::Request {
                record: Box::new(live.clone()),
            }),
            other => panic!("unexpected request: {other:?}"),
        });

        let report = capture_photo(resident.config(), photo_args(&target, true));

        assert_eq!(
            (
                report.outcome.json_type,
                report.outcome.reason,
                report.outcome.exit_code
            ),
            ("capture_uncertain", "uncertain_no_replay", 5)
        );
        assert_eq!(field(&report, "replay").as_deref(), Some("forbidden"));
        assert_eq!(
            resident.starts(),
            1,
            "a capture is never reissued after a lost wait"
        );
        assert_eq!(
            resident.queries(),
            1,
            "a lost wait is allowed exactly one status query"
        );
    }

    #[test]
    fn a_lost_wait_reports_the_terminal_row_its_one_status_query_returns() {
        let output = Scratch::new("lost-wait-terminal-output");
        let target = output.0.join("router-label.jpg");
        let declined = record(
            CaptureRequestPhase::Terminal {
                code: CaptureTerminalCode::Declined,
                detail: Some("the person declined".to_owned()),
            },
            &target,
        );
        let request_id = declined.request_id;
        let port = closed_port();
        let resident = FakeResident::start("lost-wait-terminal", move |request| match request {
            LocalRequest::CaptureStart { .. } => capture_response(CaptureReply::Started {
                request_id,
                wait: CaptureWait::Issued(ticket(port)),
            }),
            LocalRequest::CaptureQuery { .. } => capture_response(CaptureReply::Request {
                record: Box::new(declined.clone()),
            }),
            other => panic!("unexpected request: {other:?}"),
        });

        let report = capture_photo(resident.config(), photo_args(&target, true));

        assert_eq!(
            (
                report.outcome.json_type,
                report.outcome.reason,
                report.outcome.exit_code
            ),
            ("capture_failed", "declined", 3)
        );
        assert_eq!(
            field(&report, "detail").as_deref(),
            Some("the person declined")
        );
        assert_eq!(
            field(&report, "replay"),
            None,
            "a decided row is not uncertain"
        );
        assert_eq!(resident.starts(), 1);
        assert_eq!(resident.queries(), 1);
    }

    #[test]
    fn a_wait_that_ends_in_resident_shutdown_is_uncertain_rather_than_failed() {
        // Core deliberately has no word for a shut-down wait service; the CLI must not read it as
        // a refusal, because the photograph may already have been published.
        let output = Scratch::new("shutdown-output");
        let target = output.0.join("router-label.jpg");
        match classify_wait(Ok(WaitOutcome::Shutdown)) {
            WaitResolution::Uncertain(code) => {
                assert_eq!(code, CaptureTerminalCode::ResidentDisconnected);
                assert_eq!(
                    (code.outcome().json_type, code.outcome().exit_code),
                    ("capture_uncertain", 5)
                );
            }
            other => panic!("a shutdown must be uncertain, got {other:?}"),
        }

        // Everything that is not a finished row defers to the one status query instead.
        assert!(matches!(
            classify_wait(Ok(WaitOutcome::TimedOut)),
            WaitResolution::Query(_)
        ));
        assert!(matches!(
            classify_wait(Ok(WaitOutcome::Refused("no slot".to_owned()))),
            WaitResolution::Query(_)
        ));
        assert!(matches!(
            classify_wait(Err(io::Error::other("connection reset"))),
            WaitResolution::Query(_)
        ));
        let live = serde_json::to_vec(&record(CaptureRequestPhase::AwaitingPresentation, &target))
            .expect("serialize a live row");
        assert!(
            matches!(
                classify_wait(Ok(WaitOutcome::Completed(live))),
                WaitResolution::Query(_)
            ),
            "a live row is not an outcome, however it arrived"
        );
        let finished = serde_json::to_vec(&record(
            CaptureRequestPhase::Terminal {
                code: CaptureTerminalCode::Expired,
                detail: None,
            },
            &target,
        ))
        .expect("serialize a finished row");
        assert!(matches!(
            classify_wait(Ok(WaitOutcome::Completed(finished))),
            WaitResolution::Finished(_)
        ));
    }

    #[test]
    fn a_photo_that_does_not_wait_asks_for_no_waiter_slot() {
        // Eight waiter slots exist for the whole resident; a caller that will not wait must not
        // hold one.
        let output = Scratch::new("no-wait-output");
        let target = output.0.join("router-label.jpg");
        let request_id = CaptureRequestId::new();
        let resident = FakeResident::start("no-wait", move |request| match request {
            LocalRequest::CaptureStart { .. } => capture_response(CaptureReply::Started {
                request_id,
                wait: CaptureWait::NotRequested,
            }),
            other => panic!("unexpected request: {other:?}"),
        });

        let report = capture_photo(resident.config(), photo_args(&target, false));

        assert_eq!(
            (report.outcome.json_type, report.outcome.exit_code),
            ("capture_started", 0)
        );
        assert_eq!(
            field(&report, "request_id").as_deref(),
            Some(request_id.to_string().as_str())
        );
        match resident.requests().first() {
            Some(LocalRequest::CaptureStart { input }) => assert!(
                !input.wait,
                "a capture that is not waited on must not register a waiter"
            ),
            other => panic!("expected one CaptureStart, got {other:?}"),
        }
    }

    #[test]
    fn a_wait_the_resident_issued_no_ticket_for_is_never_reported_as_a_started_capture() {
        // A `--wait` caller whose waiter slot was refused still has a durable request. It is not
        // `capture_not_started`; one status query resolves it or reports uncertainty, never exit 0.
        let output = Scratch::new("no-ticket-output");
        let target = output.0.join("router-label.jpg");
        let live = record(CaptureRequestPhase::AwaitingPresentation, &target);
        let request_id = live.request_id;
        let resident = FakeResident::start("no-ticket", move |request| match request {
            LocalRequest::CaptureStart { .. } => capture_response(CaptureReply::Started {
                request_id,
                wait: CaptureWait::Refused,
            }),
            LocalRequest::CaptureQuery { .. } => capture_response(CaptureReply::Request {
                record: Box::new(live.clone()),
            }),
            other => panic!("unexpected request: {other:?}"),
        });

        let report = capture_photo(resident.config(), photo_args(&target, true));

        assert_eq!(
            (
                report.outcome.json_type,
                report.outcome.reason,
                report.outcome.exit_code
            ),
            ("capture_uncertain", "uncertain_no_replay", 5)
        );
        assert_eq!(field(&report, "replay").as_deref(), Some("forbidden"));
        assert!(
            report
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains(NO_WAIT_TICKET)),
            "the refusal says why no wait happened: {:?}",
            report.detail
        );
        assert_eq!(
            resident.starts(),
            1,
            "a refused wait never reissues the start"
        );
        assert_eq!(resident.queries(), 1);
    }

    #[test]
    fn an_occupied_output_is_refused_before_the_resident_is_asked() {
        let resident = FakeResident::start("occupied", |request| {
            panic!("the resident must not be asked about a refused path: {request:?}")
        });
        let file = resident.config().join("taken.jpg");
        std::fs::write(&file, b"an existing photograph").expect("write the occupant");
        let report = capture_photo(resident.config(), photo_args(&file, true));
        assert_eq!(
            (
                report.outcome.json_type,
                report.outcome.reason,
                report.outcome.exit_code
            ),
            ("capture_not_started", "output_exists", 2)
        );

        let directory = resident.config().join("folder");
        std::fs::create_dir_all(&directory).expect("create the occupying directory");
        let report = capture_photo(resident.config(), photo_args(&directory, true));
        assert_eq!(
            (report.outcome.reason, report.outcome.exit_code),
            ("output_is_directory", 2)
        );
        assert!(
            resident.requests().is_empty(),
            "a locally refused capture contacts nothing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_the_output_is_an_object_not_an_absence() {
        // `exists()` follows the link and would report the path free; the resident refuses any
        // link at the target, so the CLI must never say the path is available.
        let resident = FakeResident::start("dangling", |request| {
            panic!("the resident must not be asked about a refused path: {request:?}")
        });
        let link = resident.config().join("dangling.jpg");
        std::os::unix::fs::symlink(resident.config().join("nowhere.jpg"), &link)
            .expect("create the dangling symlink");
        let report = capture_photo(resident.config(), photo_args(&link, true));
        assert_eq!(
            (report.outcome.reason, report.outcome.exit_code),
            ("output_exists", 2)
        );
        assert!(resident.requests().is_empty());
    }

    #[test]
    fn every_reported_outcome_is_the_core_table_verbatim() {
        // The CLI holds no exit-code table: whatever core says about a row is what is printed.
        let output = Scratch::new("outcome-output");
        let target = output.0.join("router-label.jpg");
        for code in [
            CaptureTerminalCode::Declined,
            CaptureTerminalCode::Expired,
            CaptureTerminalCode::Busy,
            CaptureTerminalCode::RequesterBusy,
            CaptureTerminalCode::Unsupported,
            CaptureTerminalCode::Refused,
            CaptureTerminalCode::PeerOffline,
            CaptureTerminalCode::RemoteFailed,
            CaptureTerminalCode::Cancelled,
            CaptureTerminalCode::TransferFailed,
            CaptureTerminalCode::VerificationFailed,
            CaptureTerminalCode::OutputExists,
            CaptureTerminalCode::PublicationFailed,
            CaptureTerminalCode::InsufficientSpace,
            CaptureTerminalCode::ResidentRestarted,
            CaptureTerminalCode::ResidentDisconnected,
            CaptureTerminalCode::UncertainNoReplay,
        ] {
            let report = report_for_record(&record(
                CaptureRequestPhase::Terminal { code, detail: None },
                &target,
            ));
            assert_eq!(report.outcome, code.outcome(), "{code:?}");
            assert_eq!(
                field(&report, "replay").is_some(),
                code.outcome().exit_code == 5,
                "{code:?}: every uncertain answer forbids a replay and no other does"
            );
        }
        for reason in [
            CaptureNotStarted::OutputExists,
            CaptureNotStarted::PeerNotPaired,
            CaptureNotStarted::ResidentUnavailable,
            CaptureNotStarted::Capacity,
            CaptureNotStarted::InvalidArguments,
        ] {
            assert_eq!(CaptureReport::not_started(reason).outcome, reason.outcome());
        }
    }

    #[test]
    fn a_completed_capture_reports_the_receipt_as_one_json_object() {
        let output = Scratch::new("completed-output");
        let target = output.0.join("router-label.jpg");
        let report = report_for_record(&record(
            CaptureRequestPhase::Completed {
                receipt: receipt(&target),
            },
            &target,
        ));
        assert_eq!(report.outcome, CaptureOutcome::COMPLETED);
        assert_eq!(report.outcome.exit_code, 0);

        let rendered = report.render(true);
        assert!(
            !rendered.contains('\n'),
            "exactly one JSON object goes to stdout"
        );
        let value: serde_json::Value =
            serde_json::from_str(&rendered).expect("stdout is one JSON object");
        assert_eq!(value["type"], "capture_completed");
        assert_eq!(value["output"], target.display().to_string());
        assert_eq!(value["bytes"], 2_048);
        assert_eq!(value["width"], 4_032);
        assert_eq!(value["height"], 3_024);
        assert_eq!(value["sha256"], "ab".repeat(32));
        assert_eq!(value.get("replay"), None);
    }

    #[test]
    fn a_live_request_is_reported_pending_and_never_as_completed() {
        let output = Scratch::new("pending-output");
        let target = output.0.join("router-label.jpg");
        for (phase, word) in [
            (
                CaptureRequestPhase::AwaitingPresentation,
                "awaiting_presentation",
            ),
            (
                CaptureRequestPhase::Armed {
                    presented_at_unix_ms: now_unix_ms(),
                },
                "armed",
            ),
        ] {
            let report = report_for_record(&record(phase, &target));
            assert_eq!(report.outcome.json_type, "capture_pending");
            assert_eq!(report.outcome.reason, word);
            assert!(report.receipt.is_none());
        }
    }

    #[test]
    fn a_cancelled_request_reports_the_row_the_resident_wrote() {
        // Cancelling succeeds, and the capture still ended without a photograph: the row says
        // `cancelled`, which the core table puts at exit 3.
        let output = Scratch::new("cancel-output");
        let target = output.0.join("router-label.jpg");
        let cancelled = record(
            CaptureRequestPhase::Terminal {
                code: CaptureTerminalCode::Cancelled,
                detail: None,
            },
            &target,
        );
        let request_id = cancelled.request_id;
        let resident = FakeResident::start("cancel", move |request| match request {
            LocalRequest::CaptureCancel { .. } => capture_response(CaptureReply::Request {
                record: Box::new(cancelled.clone()),
            }),
            other => panic!("unexpected request: {other:?}"),
        });

        let report = capture_cancel(
            resident.config(),
            vec![request_id.to_string(), "--json".to_owned()],
        );

        assert_eq!(
            (report.outcome.reason, report.outcome.exit_code),
            ("cancelled", 3)
        );
        assert_eq!(resident.requests().len(), 1);
    }

    #[test]
    fn a_wait_on_a_request_that_already_finished_attaches_to_nothing() {
        let output = Scratch::new("wait-finished-output");
        let target = output.0.join("router-label.jpg");
        let finished = record(
            CaptureRequestPhase::Completed {
                receipt: receipt(&target),
            },
            &target,
        );
        let request_id = finished.request_id;
        let resident = FakeResident::start("wait-finished", move |request| match request {
            LocalRequest::CaptureWaitTicket { .. } => capture_response(CaptureReply::Request {
                record: Box::new(finished.clone()),
            }),
            other => panic!("unexpected request: {other:?}"),
        });

        let report = capture_wait(resident.config(), vec![request_id.to_string()]);

        assert_eq!(report.outcome.exit_code, 0);
        assert_eq!(report.outcome.json_type, "capture_completed");
        assert_eq!(resident.queries(), 0, "a decided row needs no status query");
    }

    #[test]
    fn a_bad_invocation_is_refused_with_exit_two_and_contacts_nothing() {
        let resident = FakeResident::start("arguments", |request| {
            panic!("a bad invocation must contact nothing: {request:?}")
        });
        let output = resident.config().join("router-label.jpg");
        let invalid = |args: Vec<String>| {
            let report = capture_photo(resident.config(), args);
            assert_eq!(
                (
                    report.outcome.json_type,
                    report.outcome.reason,
                    report.outcome.exit_code
                ),
                ("capture_not_started", "invalid_arguments", 2),
                "{:?}",
                report.detail
            );
        };
        invalid(vec!["--purpose".to_owned(), "Photograph it".to_owned()]);
        invalid(vec!["--peer".to_owned(), "amber".to_owned()]);
        invalid(vec!["--peer".to_owned()]);
        let mut unknown = photo_args(&output, false);
        unknown.push("--overwrite".to_owned());
        invalid(unknown);
        for seconds in ["0", "181", "-1", "forever"] {
            let mut args = photo_args(&output, false);
            args.push("--timeout".to_owned());
            args.push(seconds.to_owned());
            invalid(args);
        }
        let mut lens = photo_args(&output, false);
        lens.push("--lens".to_owned());
        lens.push("telescope".to_owned());
        invalid(lens);
        // The purpose is shown to a person on the phone; a bidirectional override would make the
        // displayed reason differ from the transmitted one.
        let purpose = vec![
            "--peer".to_owned(),
            "amber".to_owned(),
            "--purpose".to_owned(),
            "Photograph the \u{202E}label".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
        ];
        invalid(purpose);
        assert!(resident.requests().is_empty());
    }

    #[test]
    fn a_timeout_within_the_capture_lifetime_is_sent_as_milliseconds() {
        let output = Scratch::new("timeout-output");
        let target = output.0.join("router-label.jpg");
        let mut args = photo_args(&target, false);
        args.push("--timeout".to_owned());
        args.push("90".to_owned());
        args.push("--lens".to_owned());
        args.push("rear".to_owned());
        let resident = FakeResident::start("timeout", |_| {
            capture_response(CaptureReply::Started {
                request_id: CaptureRequestId::new(),
                wait: CaptureWait::NotRequested,
            })
        });

        let _ = capture_photo(resident.config(), args);

        match resident.requests().first() {
            Some(LocalRequest::CaptureStart { input }) => {
                assert_eq!(input.timeout_ms, 90_000);
                assert_eq!(input.lens, Some(CaptureLens::Rear));
                assert!(
                    input.output_path.is_absolute(),
                    "the resident never resolves a relative path against its own directory"
                );
            }
            other => panic!("expected one CaptureStart, got {other:?}"),
        }
    }

    #[test]
    fn an_unreachable_resident_is_reported_not_started_rather_than_uncertain() {
        // Nothing was written and nothing was sent, so this is exit 2, not an uncertain capture.
        let scratch = Scratch::new("no-resident");
        let report = capture_photo(&scratch.0, photo_args(&scratch.0.join("photo.jpg"), true));
        assert_eq!(
            (
                report.outcome.json_type,
                report.outcome.reason,
                report.outcome.exit_code
            ),
            ("capture_not_started", "resident_unavailable", 2)
        );
    }

    #[test]
    fn a_pairing_is_reported_with_pairings_own_word_and_exit_code() {
        // `PairOutcome` is the only authority for how a pairing ended; the CLI restates nothing.
        for result in PairingResult::ALL {
            for trust_recorded in [false, true] {
                let outcome = PairOutcome::Failed {
                    result,
                    trust_recorded,
                    detail: "the phone answered".to_owned(),
                };
                let rendered = render_pair(&outcome, true);
                assert!(!rendered.contains('\n'), "one JSON object on stdout");
                let value: serde_json::Value =
                    serde_json::from_str(&rendered).expect("stdout is one JSON object");
                assert_eq!(value["type"], "pair");
                assert_eq!(value["result"], result.as_str());
                assert_eq!(value["trust_recorded"], trust_recorded);
                if trust_recorded {
                    assert_eq!(
                        outcome.exit_code(),
                        5,
                        "{result}: one-sided trust outranks the reason it ended"
                    );
                } else {
                    assert_ne!(
                        outcome.exit_code(),
                        5,
                        "{result}: nothing was recorded, so nothing is one-sided"
                    );
                }
            }
        }
        let unresolved = unresolved("Tailscale knows no peer \"amber\"");
        let value: serde_json::Value =
            serde_json::from_str(&render_pair(&unresolved, true)).expect("one JSON object");
        assert_eq!(value["result"], "unknown_peer");
        assert_eq!(unresolved.exit_code(), 2);

        let paired = PairOutcome::Paired {
            hostname: "amber".to_owned(),
            device_id: DeviceId::new(),
        };
        let value: serde_json::Value =
            serde_json::from_str(&render_pair(&paired, true)).expect("one JSON object");
        assert_eq!(value["result"], "paired");
        assert_eq!(value["peer"], "amber");
        assert_eq!(paired.exit_code(), 0);
    }

    #[test]
    fn a_pair_invocation_without_a_peer_is_unresolved_and_dials_nothing() {
        let outcome = pair_peer(vec!["--json".to_owned()]);
        assert!(matches!(outcome, PairOutcome::Unresolved { .. }));
        assert_eq!(outcome.exit_code(), 2);
        let outcome = pair_peer(vec!["--peer".to_owned()]);
        assert_eq!(outcome.exit_code(), 2);
        let outcome = pair_peer(vec!["--force".to_owned()]);
        assert_eq!(outcome.exit_code(), 2);
    }
}
