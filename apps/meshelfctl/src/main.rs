use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use meshelf_control::Controller;
use meshelf_platform::{ClipboardSource, ClipboardWorker};

const MAX_TEXT_BYTES: usize = 1024 * 1024;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return usage();
    };
    if command == "pair-stdio" {
        return meshelf_bootstrap::run_stdio();
    }

    let (selector, options) = take_peer_selector(args.collect())?;
    let device_name = std::env::var("MESHELF_DEVICE_NAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".to_owned());
    let config_dir = dirs::config_dir()
        .context("could not determine the per-user configuration directory")?
        .join("meshelf");
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
            print!(
                "{}",
                clipboard
                    .read_text()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
            );
        }
        "send" => {
            let mut send_options = options.into_iter();
            let source = parse_send_source(&mut send_options)?;
            controller
                .refresh()
                .map_err(|error| anyhow::anyhow!(error))?;
            controller
                .select_peer(selector.as_deref())
                .map_err(|error| anyhow::anyhow!(error))?;
            let text = match source {
                SendSource::Text(text) => text,
                SendSource::Stdin => read_bounded_stdin()?,
                SendSource::Clipboard => {
                    let clipboard = ClipboardWorker::new()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    clipboard
                        .read_text()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?
                }
            };
            let receipt = controller
                .send_text(&text)
                .map_err(|error| anyhow::anyhow!(error))?;
            println!("send result: {:?}", receipt.code);
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

fn usage() -> Result<()> {
    bail!(
        "usage: meshelfctl [status|refresh|trust-ssh|clipboard-read|send] [--peer NAME_OR_ID]\n  send requires exactly one of --clipboard, --stdin, or --text TEXT\n  pair-stdio is the fixed SSH bootstrap command"
    )
}
