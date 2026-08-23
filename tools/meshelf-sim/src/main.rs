use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use meshelf_core::{
    ClipboardError, ClipboardSink, MemoryReceiveStore, ReceiptCode, ReceiverService, TextEnvelope,
};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{CoreEnvelopeHandler, ExactDeviceAllowList, PeerClient, ServerIdentity, serve};
use meshelf_protocol::ClientHello;
use tokio::{net::TcpListener, sync::watch};

#[derive(Debug, Default)]
struct SimClipboard(Mutex<Vec<String>>);

impl ClipboardSink for SimClipboard {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        self.0
            .lock()
            .map_err(|_| ClipboardError::new("simulation clipboard mutex poisoned"))?
            .push(text.to_owned());
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let bmst_identity = InstallationIdentity::generate();
    let bzot_identity = InstallationIdentity::generate();
    let bmst = bmst_identity.device_id;
    let bzot = bzot_identity.device_id;
    let clipboard = Arc::new(SimClipboard::default());
    let service = Arc::new(ReceiverService::new(
        bzot,
        Arc::new(MemoryReceiveStore::new()),
        clipboard.clone(),
    ));
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .context("bind loopback receiver")?;
    let address = listener.local_addr().context("read listener address")?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(serve(
        listener,
        ServerIdentity {
            signing_identity: bzot_identity.clone(),
            device_name: "BZOT".to_owned(),
        },
        Arc::new(ExactDeviceAllowList::new([bmst])),
        Arc::new(CoreEnvelopeHandler::new(service)),
        Duration::from_secs(2),
        shutdown_rx,
    ));

    let message = TextEnvelope::clipboard_push(
        bmst,
        bzot,
        now_unix_ms(),
        None,
        "meshelf loopback: α\nβ\n🙂",
    );
    let client = PeerClient::with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
    let first = client
        .push(
            address,
            ClientHello::signed(bmst, "BMST", "simulation-1", &bmst_identity),
            message.clone(),
            &bzot_identity.public_key(),
        )
        .await
        .context("first send")?;
    let duplicate = client
        .push(
            address,
            ClientHello::signed(bmst, "BMST", "simulation-2", &bmst_identity),
            message,
            &bzot_identity.public_key(),
        )
        .await
        .context("duplicate send")?;

    let writes = clipboard
        .0
        .lock()
        .map_err(|_| anyhow::anyhow!("simulation clipboard mutex poisoned"))?
        .clone();
    if first.code != ReceiptCode::Applied
        || duplicate.code != ReceiptCode::DuplicateApplied
        || writes != vec!["meshelf loopback: α\nβ\n🙂".to_owned()]
    {
        bail!(
            "simulation failed: first={:?}, duplicate={:?}, writes={writes:?}",
            first.code,
            duplicate.code
        );
    }

    shutdown_tx.send(true).context("request shutdown")?;
    server.await.context("join server")??;
    println!("PASS: direct two-peer send applied once; duplicate acknowledged without replay");
    Ok(())
}

fn now_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}
