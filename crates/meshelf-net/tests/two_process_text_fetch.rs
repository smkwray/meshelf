use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use meshelf_core::{
    ActivationMode, CardAvailability, ClipboardError, ClipboardSink, DeviceId, OfferCardInput,
    OfferDescriptor, OfferId, OfferSource, OfferSourceInput,
};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    ActivationService, ExactDeviceAllowList, FetchActivation, FetchClipboard,
    OfferAnnouncementHandler, OfferFetchHandler, PeerClient, ServerIdentity, V2OfferServices,
    bind_discovered_tailscale_address, serve_v2_with_offers_and_fetch,
};
use meshelf_protocol::{ClientHello, FetchRequest};
use meshelf_store::RedbV2Store;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

const CHILD_ROLE: &str = "MESHELF_TWO_PROCESS_ORIGIN";
const REQUESTER_ID: &str = "MESHELF_TWO_PROCESS_REQUESTER_ID";
const OFFER_ID: &str = "MESHELF_TWO_PROCESS_OFFER_ID";
const READY_PREFIX: &str = "MESHELF_TWO_PROCESS_READY ";

#[derive(Debug, Serialize, Deserialize)]
struct OriginReady {
    address: String,
    device_id: DeviceId,
    public_key: Vec<u8>,
    descriptor: OfferDescriptor,
}

#[derive(Debug, Default)]
struct RecordingClipboard(Mutex<Vec<String>>);

impl ClipboardSink for RecordingClipboard {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        self.0
            .lock()
            .map_err(|_| ClipboardError::new("recording clipboard lock is unavailable"))?
            .push(text.to_owned());
        Ok(())
    }
}

impl FetchClipboard for RecordingClipboard {
    fn set_files(&self, _paths: &[PathBuf]) -> Result<(), ClipboardError> {
        Err(ClipboardError::new(
            "the text process test does not accept file clipboard writes",
        ))
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn offered_text() -> String {
    let head = "HEAD-two-process-text-";
    let tail = "-TAIL-two-process-fetch";
    let padding = "x".repeat(442 - head.len() - tail.len());
    let text = format!("{head}{padding}{tail}");
    assert_eq!(text.len(), 442);
    text
}

#[test]
fn two_process_text_fetch_delivers_exact_bytes() {
    if std::env::var_os(CHILD_ROLE).is_some() {
        run_origin_child();
        return;
    }

    let requester = InstallationIdentity::generate();
    let offer_id = OfferId::new();
    let executable = std::env::current_exe().expect("current integration-test executable");
    let child = Command::new(executable)
        .args([
            "--exact",
            "two_process_text_fetch_delivers_exact_bytes",
            "--nocapture",
        ])
        .env(CHILD_ROLE, "1")
        .env(REQUESTER_ID, requester.device_id.to_string())
        .env(OFFER_ID, offer_id.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn separate origin process");
    let mut child = ChildGuard(child);
    let stdout = child.0.stdout.take().expect("origin child stdout");
    let mut stdout = BufReader::new(stdout);
    let ready = loop {
        let mut line = String::new();
        let bytes = stdout.read_line(&mut line).expect("read origin readiness");
        assert_ne!(bytes, 0, "origin process exited before becoming ready");
        if let Some(index) = line.find(READY_PREFIX) {
            let encoded = &line[index + READY_PREFIX.len()..];
            break serde_json::from_str::<OriginReady>(encoded.trim()).expect("decode readiness");
        }
    };

    let receiver_directory = tempfile::tempdir().expect("receiver directory");
    let receiver_root =
        std::fs::canonicalize(receiver_directory.path()).expect("canonical receiver directory");
    let receiver_store =
        Arc::new(RedbV2Store::open(receiver_root.join("receiver.redb")).expect("receiver store"));
    receiver_store
        .insert_offer_card(OfferCardInput::new(
            ready.device_id,
            offer_id,
            ready.descriptor,
            CardAvailability::Available,
        ))
        .expect("insert announced card");
    let clipboard = Arc::new(RecordingClipboard::default());
    let service = ActivationService::new(
        requester.device_id,
        receiver_store,
        clipboard.clone(),
        receiver_root,
    );
    let request = FetchRequest::new(offer_id, ready.device_id, requester.device_id);
    let activation = FetchActivation::new(
        request.request_id,
        ready.device_id,
        offer_id,
        ActivationMode::Clipboard,
        None,
    );
    let address = SocketAddr::from_str(&ready.address).expect("origin address");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("requester runtime")
        .block_on(async {
            let client = PeerClient::with_timeouts(Duration::from_secs(3), Duration::from_secs(5));
            let (_cancel, cancel) = watch::channel(false);
            let outcome = service
                .activate(
                    &client,
                    address,
                    ClientHello::signed_v2(
                        requester.device_id,
                        "requester-process",
                        request.request_id.to_string(),
                        &requester,
                    ),
                    request,
                    activation,
                    &ready.public_key,
                    cancel,
                )
                .await
                .expect("two-process text fetch");
            assert_eq!(outcome, meshelf_net::ActivationOutcome::Completed);
        });

    assert_eq!(
        clipboard.0.lock().expect("clipboard result").as_slice(),
        [offered_text()]
    );
    child
        .0
        .stdin
        .take()
        .expect("origin child stdin")
        .write_all(b"stop\n")
        .expect("request origin shutdown");
    let status = child.0.wait().expect("wait for origin process");
    assert!(status.success(), "origin process failed: {status}");
}

fn run_origin_child() {
    let requester = DeviceId::from_str(&std::env::var(REQUESTER_ID).expect("requester ID"))
        .expect("valid requester ID");
    let offer_id =
        OfferId::from_str(&std::env::var(OFFER_ID).expect("offer ID")).expect("valid offer ID");
    let origin = InstallationIdentity::generate();
    let directory = tempfile::tempdir().expect("origin directory");
    let store =
        Arc::new(RedbV2Store::open(directory.path().join("origin.redb")).expect("origin store"));
    let text = offered_text();
    let descriptor = OfferDescriptor::text(&text).expect("text descriptor");
    store
        .insert_offer_source(OfferSourceInput::new(
            offer_id,
            descriptor.clone(),
            HashSet::from([requester]),
            OfferSource::Text { text },
        ))
        .expect("insert origin source");

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("origin runtime")
        .block_on(async {
            let local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let listener =
                bind_discovered_tailscale_address(SocketAddr::new(local_ip, 0), &[local_ip])
                    .await
                    .expect("production private-bind validation");
            let address = listener.local_addr().expect("origin address");
            let (shutdown, shutdown_rx) = watch::channel(false);
            let server = tokio::spawn(serve_v2_with_offers_and_fetch(
                listener,
                ServerIdentity {
                    signing_identity: origin.clone(),
                    device_name: "origin-process".to_owned(),
                },
                Arc::new(ExactDeviceAllowList::new([requester])),
                V2OfferServices {
                    announcement_receiver: Arc::new(OfferAnnouncementHandler::new(store.clone())),
                    fetch_sender: Arc::new(OfferFetchHandler::new(origin.device_id, store)),
                },
                Duration::from_secs(5),
                shutdown_rx,
            ));
            println!(
                "{READY_PREFIX}{}",
                serde_json::to_string(&OriginReady {
                    address: address.to_string(),
                    device_id: origin.device_id,
                    public_key: origin.public_key().to_vec(),
                    descriptor,
                })
                .expect("encode readiness")
            );
            std::io::stdout().flush().expect("flush readiness");
            tokio::task::spawn_blocking(|| {
                let mut stop = String::new();
                std::io::stdin()
                    .read_line(&mut stop)
                    .expect("read shutdown");
            })
            .await
            .expect("shutdown reader");
            shutdown.send(true).expect("signal origin shutdown");
            server
                .await
                .expect("origin server task")
                .expect("origin server");
        });
}
