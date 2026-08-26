use std::{
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use meshelf_control::{
    Controller,
    coordinator::Coordinator,
    local_control::{self, LocalRequest, LocalResponse},
};
use meshelf_core::OfferDescriptor;
use meshelf_core::{ActivationMode, OfferId};
use meshelf_platform::{
    ClipboardItem, ClipboardSource, ClipboardWorker, acquire_resident_lock, listen_with_control,
    request as control_request,
};

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
            controller
                .refresh()
                .map_err(|error| anyhow::anyhow!(error))?;
            let report = match source {
                SendSource::Text(text) => {
                    controller.send_to_mesh(&text).map(|report| report.status())
                }
                SendSource::Stdin => controller
                    .send_to_mesh(&read_bounded_stdin()?)
                    .map(|report| report.status()),
                SendSource::Clipboard => {
                    let clipboard = ClipboardWorker::new()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    match clipboard
                        .read_item()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?
                    {
                        ClipboardItem::Text(text) => {
                            controller.send_to_mesh(&text).map(|report| report.status())
                        }
                        ClipboardItem::Files(paths) => controller.send_paths_to_mesh(&paths),
                    }
                }
            }
            .map_err(|error| anyhow::anyhow!(error))?;
            println!("{report}");
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

fn run_serve(args: Vec<String>) -> Result<()> {
    if !args.is_empty() {
        bail!("serve does not accept options")
    }
    let data_dir = config_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    let Some(_resident_lock) = acquire_resident_lock(&data_dir)? else {
        bail!("another meshelf resident already owns the local control channel")
    };
    let (coordinator, _identity) = Coordinator::open(
        data_dir.join("state.json"),
        data_dir.join("meshelf-v2.redb"),
    )
    .map_err(anyhow::Error::msg)?;
    let coordinator = Arc::new(coordinator);
    let control_coordinator = coordinator.clone();
    let (_stop_sender, stop_receiver) = std::sync::mpsc::channel::<()>();
    listen_with_control(
        &data_dir,
        || {},
        move |request| local_control::dispatch_bytes(&control_coordinator, request),
    )?;
    stop_receiver
        .recv()
        .map_err(|_| anyhow::anyhow!("local control listener stopped"))?;
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
        | LocalResponse::ActivationStarted { .. }
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
        LocalResponse::ActivationStarted {
            activation_id,
            offer_id,
            mode,
        } => println!("activation {activation_id} started for {offer_id} ({mode:?})"),
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
