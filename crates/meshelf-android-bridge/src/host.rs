//! The seam between JNI and the host-testable phone resident.
//!
//! JNI validates arguments and forwards typed values through [`PhoneHost`]. The adapter below
//! starts the production [`PhoneResident`], routes every socket through Android's selected VPN
//! network, and translates resident events into the bounded Kotlin callback queue.

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: core::ffi::c_int,
        tag: *const core::ffi::c_char,
        text: *const core::ffi::c_char,
    ) -> core::ffi::c_int;
}

pub(crate) fn log_android(msg: &str) {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;
        if let (Ok(tag), Ok(text)) = (CString::new("MeshelfNative"), CString::new(msg)) {
            unsafe {
                __android_log_write(4, tag.as_ptr(), text.as_ptr());
            }
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = msg;
    }
}

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use meshelf_control::{
    MESHELF_PORT,
    phone::{PhoneError, PhoneEvents, PhoneResident, PhoneResidentConfig, ShelfAction},
};
use meshelf_core::{CaptureRequestId, CaptureSourceRecord};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    CaptureEventRefused, CaptureWithdrawReason, DocumentSourceProvider, FetchClipboard,
    SocketConnector, SystemClock,
};
use meshelf_protocol::pairing::{PairingCandidate, PairingId, PairingResult, TranscriptHash};

use crate::{
    NativeError,
    args::{CapturedFile, DeclineReason, parse_device_id, parse_offer_id},
    binder::{SocketBinder, bind_listener, connect_bound},
    events::{EventRefused, EventSink, KotlinEvent, PairingOutcome},
    platform_clipboard::{FileExportKind, PlatformClipboard, PlatformFailure},
    state,
};

/// Everything the resident receives when `nativeStart` succeeds.
pub struct PhoneHostContext {
    /// Loaded through `loadInstallationIdentity`, or generated and stored on first start.
    pub identity: InstallationIdentity,
    /// Absolute directory for `meshelf.redb` and `state.json`.
    pub state_dir: PathBuf,
    /// The phone's Tailscale address; the only address the listener may bind.
    pub local_address: Ipv4Addr,
    pub device_name: String,
    /// Routes each socket through the VPN network before bind or connect.
    pub binder: Arc<dyn SocketBinder>,
    pub events: EventSink,
    /// The bridge's two-worker runtime; shut down with a bound by `nativeStop`.
    pub runtime: tokio::runtime::Handle,
    /// Opens platform document leases for ordinary file fetches. `None` on host tests.
    pub documents: Option<Arc<dyn DocumentSourceProvider>>,
}

/// Operations the natives forward to the resident. Called on JNI caller threads (Kotlin's main
/// thread among them), so every method must return promptly and never block on network I/O.
/// Errors should be `InvalidArgument` or `IllegalState`; they are thrown to Kotlin as is.
pub trait PhoneHost: Send + Sync {
    /// Kotlin captured the photo; record it durably before returning, then announce.
    fn capture_captured(&self, capture: CapturedFile) -> Result<(), NativeError>;
    /// Kotlin ended the request without a photo. Unknown or terminal ids are a no-op.
    fn capture_declined(
        &self,
        request_id: CaptureRequestId,
        reason: DeclineReason,
    ) -> Result<(), NativeError>;
    /// Opens the window until `expires_at_unix_ms`, already checked to lie within 120 s.
    fn open_pairing_window(&self, expires_at_unix_ms: u64) -> Result<(), NativeError>;
    /// Closing a closed or expired window is a no-op (A13). A session whose approval is durable
    /// keeps running to completion (A12).
    fn close_pairing_window(&self);
    /// The person confirmed the candidate carrying this exact transcript hash.
    fn confirm_pairing(
        &self,
        pairing_id: PairingId,
        transcript_hash: TranscriptHash,
    ) -> Result<(), NativeError>;
    fn reject_pairing(&self, pairing_id: PairingId) -> Result<(), NativeError>;
    fn shelf_snapshot(&self) -> Result<String, NativeError>;
    fn refresh_origin_catalogs(&self, open_epoch: i64) -> Result<String, NativeError>;
    fn announce_text(&self, text: &str, action_id: &str) -> Result<String, NativeError>;
    /// Announce a gallery/document lease already held by the platform grant store.
    fn announce_document(
        &self,
        lease_id: &str,
        root_name: &str,
        byte_length: u64,
        action_id: &str,
    ) -> Result<String, NativeError>;
    /// Reserve app-private ordinary-photo paths; returns JSON `{leaseId,rawPath,finalPath}`.
    fn reserve_ordinary_photo(&self, action_id: &str) -> Result<String, NativeError>;
    /// Commit a sanitized JPEG at the reserved final path as an ordinary file offer.
    fn commit_ordinary_photo(
        &self,
        lease_id: &str,
        sha256_hex: &str,
        width: i32,
        height: i32,
    ) -> Result<String, NativeError>;
    /// Drop an uncommitted ordinary-photo reservation (safe after commit).
    fn abandon_photo(&self, lease_id: &str) -> Result<(), NativeError>;
    fn activate(
        &self,
        source_device: &str,
        offer_id: &str,
        action: &str,
        gesture_token: &str,
        clipboard: Arc<PlatformClipboard>,
    ) -> Result<String, NativeError>;
    /// Status fields owned by the resident. Must never include a key or the network handle.
    fn status(&self) -> HostStatus;
    /// `nativeStop`: close the window and abort sessions not yet at ApprovedPending (A13). The
    /// runtime is shut down right after this returns.
    fn shutdown(&self);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStatus {
    pub listening: bool,
    pub pairing_window_expires_at_ms: Option<u64>,
    pub live_request: Result<Option<CaptureRequestId>, String>,
    pub paired_peers: Result<u32, String>,
    pub failure_count: u64,
    pub last_failure: Option<(String, u64)>,
}

impl Default for HostStatus {
    fn default() -> Self {
        Self {
            listening: false,
            pairing_window_expires_at_ms: None,
            live_request: Ok(None),
            paired_peers: Ok(0),
            failure_count: 0,
            last_failure: None,
        }
    }
}

struct ResidentHost {
    resident: PhoneResident,
    runtime: tokio::runtime::Handle,
}

impl PhoneHost for ResidentHost {
    fn capture_captured(&self, capture: CapturedFile) -> Result<(), NativeError> {
        self.resident
            .capture_captured(
                capture.request_id,
                &capture.path,
                capture.sha256,
                capture.width,
                capture.height,
            )
            .map_err(native_state)
    }

    fn capture_declined(
        &self,
        request_id: CaptureRequestId,
        reason: DeclineReason,
    ) -> Result<(), NativeError> {
        self.resident
            .capture_declined(request_id, reason.as_str())
            .map_err(native_state)
    }

    fn open_pairing_window(&self, expires_at_unix_ms: u64) -> Result<(), NativeError> {
        self.resident
            .open_pairing_window(expires_at_unix_ms)
            .map_err(native_state)
    }

    fn close_pairing_window(&self) {
        self.resident.close_pairing_window();
    }

    fn confirm_pairing(
        &self,
        pairing_id: PairingId,
        transcript_hash: TranscriptHash,
    ) -> Result<(), NativeError> {
        self.resident
            .confirm_pairing(pairing_id, transcript_hash)
            .map_err(native_state)
    }

    fn reject_pairing(&self, pairing_id: PairingId) -> Result<(), NativeError> {
        self.resident
            .reject_pairing(pairing_id)
            .map_err(native_state)
    }

    fn shelf_snapshot(&self) -> Result<String, NativeError> {
        self.resident.shelf_snapshot_json().map_err(native_state)
    }

    fn refresh_origin_catalogs(&self, _open_epoch: i64) -> Result<String, NativeError> {
        self.runtime
            .block_on(self.resident.refresh_origin_catalogs())
            .map_err(native_state)
    }

    fn announce_text(&self, text: &str, _action_id: &str) -> Result<String, NativeError> {
        self.runtime
            .block_on(self.resident.announce_text(text))
            .and_then(|result| result.to_json())
            .map_err(native_state)
    }

    fn announce_document(
        &self,
        lease_id: &str,
        root_name: &str,
        byte_length: u64,
        _action_id: &str,
    ) -> Result<String, NativeError> {
        if lease_id.trim().is_empty() {
            return Err(crate::invalid("lease id is empty"));
        }
        if root_name.trim().is_empty() {
            return Err(crate::invalid("root name is empty"));
        }
        if byte_length == 0 {
            return Err(crate::invalid("document byte length must be positive"));
        }
        self.runtime
            .block_on(
                self.resident
                    .announce_document(lease_id, root_name, byte_length),
            )
            .and_then(|result| result.to_json())
            .map_err(native_state)
    }

    fn reserve_ordinary_photo(&self, action_id: &str) -> Result<String, NativeError> {
        if action_id.trim().is_empty() {
            return Err(crate::invalid("action id is empty"));
        }
        self.resident
            .reserve_ordinary_photo(action_id)
            .map_err(native_state)
    }

    fn commit_ordinary_photo(
        &self,
        lease_id: &str,
        sha256_hex: &str,
        width: i32,
        height: i32,
    ) -> Result<String, NativeError> {
        if lease_id.trim().is_empty() {
            return Err(crate::invalid("lease id is empty"));
        }
        if width <= 0 || height <= 0 {
            return Err(crate::invalid("ordinary photo dimensions must be positive"));
        }
        let width = u32::try_from(width).map_err(|_| crate::invalid("width out of range"))?;
        let height = u32::try_from(height).map_err(|_| crate::invalid("height out of range"))?;
        self.runtime
            .block_on(
                self.resident
                    .commit_ordinary_photo(lease_id, sha256_hex, width, height),
            )
            .and_then(|result| result.to_json())
            .map_err(native_state)
    }

    fn abandon_photo(&self, lease_id: &str) -> Result<(), NativeError> {
        if lease_id.trim().is_empty() {
            return Err(crate::invalid("lease id is empty"));
        }
        self.resident
            .abandon_ordinary_photo(lease_id)
            .map_err(native_state)
    }

    fn activate(
        &self,
        source_device: &str,
        offer_id: &str,
        action: &str,
        gesture_token: &str,
        clipboard: Arc<PlatformClipboard>,
    ) -> Result<String, NativeError> {
        let source_device = parse_device_id(source_device)?;
        let offer_id = parse_offer_id(offer_id)?;
        let action = ShelfAction::parse(action).ok_or_else(|| {
            crate::invalid("activation action must be COPY_TEXT, SAVE_FILE, or SHARE_FILE")
        })?;
        if gesture_token.is_empty() {
            return Err(crate::invalid("gesture token is empty"));
        }
        clipboard.prepare_gesture(gesture_token.to_owned());
        // Android saves or shares under the card's own name; the verified copy is a cache object.
        let card_name = || {
            self.resident
                .ordinary_shelf_cards()
                .ok()?
                .into_iter()
                .find(|card| card.source_device == source_device && card.offer_id == offer_id)
                .and_then(|card| match card.descriptor {
                    meshelf_core::OfferDescriptor::File { root_name, .. }
                    | meshelf_core::OfferDescriptor::Folder { root_name, .. } => Some(root_name),
                    meshelf_core::OfferDescriptor::Text { .. } => None,
                })
        };
        match action {
            ShelfAction::CopyText => {}
            ShelfAction::ShareFile => {
                clipboard.prepare_file_export(FileExportKind::Share, card_name());
            }
            ShelfAction::SaveFile => {
                clipboard.prepare_file_export(FileExportKind::Save, card_name());
            }
        }
        let mut report = self.runtime.block_on(self.resident.activate(
            source_device,
            offer_id,
            action,
            Arc::clone(&clipboard) as Arc<dyn FetchClipboard>,
        ));
        // Every outcome is a result object; the gesture is spent or withdrawn either way.
        if clipboard.finish_gesture(gesture_token) == Some(PlatformFailure::ForegroundLost) {
            report.foreground_lost();
        }
        report.to_json().map_err(native_state)
    }

    fn status(&self) -> HostStatus {
        let status = self.resident.status();
        HostStatus {
            listening: status.listening,
            pairing_window_expires_at_ms: status.pairing_window_expires_at_unix_ms,
            live_request: status.live_request,
            paired_peers: status.paired_peers,
            failure_count: status.failures.count,
            last_failure: status
                .failures
                .last
                .map(|failure| (failure.detail, failure.at_unix_ms)),
        }
    }

    fn shutdown(&self) {
        self.resident.shutdown();
    }
}

fn native_state(error: PhoneError) -> NativeError {
    state(error.to_string())
}

#[derive(Clone)]
struct BoundConnector {
    binder: Arc<dyn SocketBinder>,
    local_address: Ipv4Addr,
}

#[async_trait]
impl SocketConnector for BoundConnector {
    async fn connect(&self, address: SocketAddr) -> io::Result<tokio::net::TcpStream> {
        let SocketAddr::V4(remote) = address else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the Android capture lane supports Tailscale IPv4 only",
            ));
        };
        connect_bound(self.binder.as_ref(), self.local_address, remote).await
    }
}

#[derive(Clone)]
struct BridgeEvents {
    sink: EventSink,
}

impl BridgeEvents {
    fn emit(&self, event: KotlinEvent) {
        if let Err(error) = self.sink.emit(event) {
            self.sink
                .record_error(format!("resident event could not be queued: {error}"));
        }
    }
}

impl PhoneEvents for BridgeEvents {
    fn capture_requested(&self, record: &CaptureSourceRecord) -> Result<(), CaptureEventRefused> {
        self.sink
            .emit(KotlinEvent::CaptureRequested {
                request_id: record.request_id,
                requester_name: record.requester_label.clone(),
                purpose: record.purpose.clone(),
                expires_at_unix_ms: record.expires_at_unix_ms,
            })
            .map_err(event_refused)
    }

    fn capture_withdrawn(&self, request_id: CaptureRequestId, reason: CaptureWithdrawReason) {
        self.emit(KotlinEvent::CaptureWithdrawn {
            request_id,
            reason: reason.as_str().to_owned(),
        });
    }

    fn capture_delivered(&self, request_id: CaptureRequestId) {
        self.emit(KotlinEvent::CaptureDelivered { request_id });
    }

    fn peer_admitted(&self, device_name: &str) {
        self.emit(KotlinEvent::PeerAdmitted {
            device_name: device_name.to_owned(),
        });
    }

    fn pairing_candidate(&self, candidate: &PairingCandidate) {
        self.emit(KotlinEvent::PairingCandidate {
            pairing_id: candidate.pairing_id,
            device_name: candidate.device_name.clone(),
            code: candidate.code.clone(),
            transcript_hash: candidate.transcript_hash,
            expires_at_unix_ms: candidate.expires_at_unix_ms,
        });
    }

    fn pairing_finished(&self, pairing_id: PairingId, result: PairingResult) {
        self.emit(KotlinEvent::PairingFinished {
            pairing_id,
            outcome: pairing_outcome(result),
        });
    }

    fn shelf_changed(&self) {
        self.emit(KotlinEvent::ShelfChanged);
    }
}

fn event_refused(error: EventRefused) -> CaptureEventRefused {
    CaptureEventRefused(error.to_string())
}

fn pairing_outcome(result: PairingResult) -> PairingOutcome {
    use meshelf_protocol::pairing::PairingAbortCode as Abort;
    match result {
        PairingResult::Paired => PairingOutcome::Paired,
        PairingResult::Declined => PairingOutcome::Aborted(Abort::Declined),
        PairingResult::WindowClosed => PairingOutcome::Aborted(Abort::WindowClosed),
        PairingResult::Timeout => PairingOutcome::Aborted(Abort::Timeout),
        PairingResult::Busy => PairingOutcome::Aborted(Abort::Busy),
        PairingResult::RateLimited => PairingOutcome::Aborted(Abort::RateLimited),
        PairingResult::Invalid => PairingOutcome::Aborted(Abort::Invalid),
        PairingResult::IdentityChanged => PairingOutcome::Aborted(Abort::IdentityChanged),
        PairingResult::Failed => PairingOutcome::Failed,
    }
}

/// Starts the resident and its privately-bound listener. Startup reconciliation runs before the
/// listener accepts a peer, so stale rows and callbacks are settled first.
pub(crate) fn start_phone_host(
    context: PhoneHostContext,
) -> Result<Option<Arc<dyn PhoneHost>>, NativeError> {
    let photo_root = context
        .state_dir
        .parent()
        .ok_or_else(|| state("state directory has no app-private parent"))?
        .join("agent-captures");
    std::fs::create_dir_all(&photo_root)
        .map_err(|error| state(format!("could not create photograph directory: {error}")))?;
    let photo_root = std::fs::canonicalize(&photo_root)
        .map_err(|error| state(format!("could not resolve photograph directory: {error}")))?;
    let connector = Arc::new(BoundConnector {
        binder: Arc::clone(&context.binder),
        local_address: context.local_address,
    });
    let events = Arc::new(BridgeEvents {
        sink: context.events.clone(),
    });
    let resident = PhoneResident::new(PhoneResidentConfig {
        identity: context.identity,
        device_name: context.device_name,
        state_dir: context.state_dir,
        photo_root,
        events,
        runtime: context.runtime.clone(),
        connector: Some(connector),
        clock: Arc::new(SystemClock),
        documents: context.documents,
    })
    .map_err(native_state)?;
    resident.reconcile().map_err(native_state)?;

    let serving = resident.clone();
    let binder = context.binder;
    let local_address = context.local_address;
    let event_errors = context.events;
    context.runtime.spawn(async move {
        log_android(&format!(
            "bind_listener starting for {local_address}:{MESHELF_PORT}"
        ));
        let mut attempts = 0;
        let listener = loop {
            match bind_listener(binder.as_ref(), local_address, MESHELF_PORT, 8) {
                Ok(listener) => {
                    log_android(&format!(
                        "bind_listener SUCCESS for {local_address}:{MESHELF_PORT}"
                    ));
                    break listener;
                }
                Err(error) => {
                    attempts += 1;
                    if attempts >= 10 {
                        log_android(&format!("bind_listener ERROR after 10 attempts: {error}"));
                        event_errors
                            .record_error(format!("phone listener could not bind: {error}"));
                        return;
                    }
                    log_android(&format!(
                        "bind_listener retry {attempts} after error: {error}"
                    ));
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            }
        };
        log_android("serving.serve(listener) starting");
        if let Err(error) = serving.serve(listener).await {
            log_android(&format!("serving.serve ERROR: {error}"));
            event_errors.record_error(format!("phone listener stopped: {error}"));
        } else {
            log_android("serving.serve completed cleanly");
        }
    });

    Ok(Some(Arc::new(ResidentHost {
        resident,
        runtime: context.runtime,
    })))
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr, sync::mpsc, thread, time::Duration};

    use meshelf_core::DeviceId;
    use meshelf_net::PairingClock;
    use meshelf_protocol::pairing;
    use meshelf_tailscale::{InstallationStore, PairedPeer, PeerNetworkBinding};
    use serde_json::Value;

    use super::*;
    use crate::{
        ErrorLog, abi,
        events::{CallArg, EVENT_QUEUE_CAPACITY, Invocation},
    };

    /// No network: the one trusted peer is unreachable, which is also what proves an own card
    /// never needs one.
    struct RefusingConnector;

    #[async_trait]
    impl SocketConnector for RefusingConnector {
        async fn connect(&self, _address: SocketAddr) -> io::Result<tokio::net::TcpStream> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "this test has no network",
            ))
        }
    }

    struct Fixture {
        host: ResidentHost,
        events: EventSink,
        local: DeviceId,
        _runtime: tokio::runtime::Runtime,
        _directory: tempfile::TempDir,
    }

    /// The production host over the production resident, with the bridge's real event sink.
    fn fixture() -> (Fixture, mpsc::Receiver<Invocation>) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().canonicalize().expect("canonical root");
        let state_dir = root.join("state");
        let photo_root = root.join("agent-captures");
        std::fs::create_dir_all(&state_dir).expect("state directory");
        std::fs::create_dir_all(&photo_root).expect("photo directory");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let (events, invocations) = EventSink::channel(EVENT_QUEUE_CAPACITY, ErrorLog::default());
        let identity = InstallationIdentity::generate();
        let local = identity.device_id;
        let resident = PhoneResident::new(PhoneResidentConfig {
            identity,
            device_name: "EMBER".to_owned(),
            state_dir: state_dir.clone(),
            photo_root,
            events: Arc::new(BridgeEvents {
                sink: events.clone(),
            }),
            runtime: runtime.handle().clone(),
            connector: Some(Arc::new(RefusingConnector)),
            clock: Arc::new(SystemClock),
            documents: None,
        })
        .expect("resident");
        let peer = InstallationIdentity::generate();
        let now = SystemClock.now_unix_ms();
        InstallationStore::new(state_dir.join("state.json"))
            .update(local, |state| {
                state.peers.record_paired(
                    PairedPeer {
                        peer: pairing::PairedPeer {
                            device_id: peer.device_id,
                            public_key: peer.public_key(),
                            device_name: "CEDAR".to_owned(),
                            pairing_id: pairing::PairingId::from_str(&"20".repeat(16))
                                .expect("pairing id"),
                            transcript_hash: pairing::TranscriptHash::from_str(&"11".repeat(32))
                                .expect("transcript hash"),
                        },
                        binding: PeerNetworkBinding::ObservedTailscaleAddress {
                            address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
                        },
                        expires_at_unix_ms: now + 120_000,
                    },
                    now,
                    None,
                )
            })
            .expect("trusted peer");
        let host = ResidentHost {
            resident,
            runtime: runtime.handle().clone(),
        };
        (
            Fixture {
                host,
                events,
                local,
                _runtime: runtime,
                _directory: directory,
            },
            invocations,
        )
    }

    /// Kotlin's main thread: answers the next platform dispatch with `outcome`.
    fn kotlin_reports(
        invocations: mpsc::Receiver<Invocation>,
        clipboard: Arc<PlatformClipboard>,
        outcome: &'static str,
    ) -> thread::JoinHandle<Vec<CallArg>> {
        kotlin_reports_for(
            abi::ON_PLATFORM_DISPATCH_PREPARED,
            invocations,
            clipboard,
            outcome,
        )
    }

    fn kotlin_reports_for(
        method: abi::JniMethod,
        invocations: mpsc::Receiver<Invocation>,
        clipboard: Arc<PlatformClipboard>,
        outcome: &'static str,
    ) -> thread::JoinHandle<Vec<CallArg>> {
        thread::spawn(move || {
            loop {
                let invocation = invocations
                    .recv_timeout(Duration::from_secs(10))
                    .expect("a platform dispatch");
                if invocation.method != method {
                    continue;
                }
                let CallArg::Text(dispatch_id) = &invocation.args[0] else {
                    panic!("dispatch id");
                };
                clipboard
                    .report_outcome(dispatch_id, outcome)
                    .expect("report outcome");
                return invocation.args;
            }
        })
    }

    fn announce_own_text(fixture: &Fixture, text: &str) -> String {
        let announced: Value = serde_json::from_str(
            &fixture
                .host
                .announce_text(text, "action-1")
                .expect("announce"),
        )
        .expect("announce json");
        assert_eq!(announced["schemaVersion"], 2);
        assert_eq!(announced["localStored"], true);
        assert_eq!(announced["addedCount"], 0);
        assert_eq!(announced["refusedCount"], 0);
        assert_eq!(announced["unavailableCount"], 1);
        assert_eq!(announced["peers"][0]["displayName"], "CEDAR");
        assert_eq!(announced["peers"][0]["reachability"], "UNAVAILABLE");
        assert_eq!(announced["peers"][0]["outcome"], "TRANSPORT_FAILED");
        announced["offerId"].as_str().expect("offer id").to_owned()
    }

    /// An own text card is copied from the text this phone stored at announce time, through the
    /// platform dispatch with the gesture it was given, and the answer is the ABI-8 result object.
    #[test]
    fn own_text_copy_through_the_bridge_is_a_completed_activation_result() {
        let (fixture, invocations) = fixture();
        let words = "own words on EMBER";
        let offer_id = announce_own_text(&fixture, words);
        let clipboard = PlatformClipboard::new(fixture.events.clone());
        let kotlin = kotlin_reports(invocations, Arc::clone(&clipboard), "APPLIED");
        let result: Value = serde_json::from_str(
            &fixture
                .host
                .activate(
                    &fixture.local.to_string(),
                    &offer_id,
                    "COPY_TEXT",
                    "gesture-own",
                    clipboard,
                )
                .expect("activation result"),
        )
        .expect("result json");
        let dispatched = kotlin.join().expect("kotlin thread");
        assert_eq!(
            dispatched[1],
            CallArg::Text("own words on EMBER".to_owned())
        );
        assert_eq!(dispatched[2], CallArg::Text("gesture-own".to_owned()));
        assert_eq!(result["schemaVersion"], 2);
        assert_eq!(result["sourceDevice"], fixture.local.to_string());
        assert_eq!(result["offerId"], offer_id);
        assert_eq!(result["action"], "COPY_TEXT");
        assert_eq!(result["status"], "COMPLETED");
        assert_eq!(result["code"], "COMPLETED");
        assert_eq!(result["filesProcessed"], 0);
        assert_eq!(result["bytesProcessed"], words.len());
        assert!(result["detail"].is_null());
    }

    /// Android saves or shares a file under the name it is handed. The verified copy it gets is a
    /// `candidate-<id>` cache object, so without the card's name every Save landed in Downloads
    /// as `candidate-…` with no extension, and Share offered that name to other apps.
    #[test]
    fn a_shared_photo_is_offered_under_its_card_name_not_the_cache_name() {
        let (fixture, invocations) = fixture();
        let reserved: Value = serde_json::from_str(
            &fixture
                .host
                .reserve_ordinary_photo("action-photo")
                .expect("reserve"),
        )
        .expect("reserve json");
        let lease_id = reserved["leaseId"].as_str().expect("lease id").to_owned();
        let final_path = PathBuf::from(reserved["finalPath"].as_str().expect("final path"));
        std::fs::write(&final_path, b"meshelf-shelf-photo-bytes").expect("photo bytes");
        let committed: Value = serde_json::from_str(
            &fixture
                .host
                .commit_ordinary_photo(
                    &lease_id,
                    "e30ff56565f21584eefe8c449d94b29ddda7b4767616313f95cf73a57aa80496",
                    4,
                    3,
                )
                .expect("commit"),
        )
        .expect("commit json");
        let offer_id = committed["offerId"].as_str().expect("offer id").to_owned();
        let card_name = final_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("card name")
            .to_owned();
        let clipboard = PlatformClipboard::new(fixture.events.clone());
        let kotlin = kotlin_reports_for(
            abi::ON_PLATFORM_FILE_EXPORT_PREPARED,
            invocations,
            Arc::clone(&clipboard),
            "APPLIED",
        );
        let result: Value = serde_json::from_str(
            &fixture
                .host
                .activate(
                    &fixture.local.to_string(),
                    &offer_id,
                    "SHARE_FILE",
                    "gesture-share",
                    clipboard,
                )
                .expect("activation result"),
        )
        .expect("result json");
        let dispatched = kotlin.join().expect("kotlin thread");
        assert_eq!(result["status"], "COMPLETED", "{result}");
        let CallArg::Text(exported) = &dispatched[1] else {
            panic!("export path");
        };
        assert_ne!(
            PathBuf::from(exported)
                .file_name()
                .and_then(|name| name.to_str()),
            Some(card_name.as_str()),
            "the exported file is a cache copy, so its own name cannot be used"
        );
        assert_eq!(dispatched[2], CallArg::Text(card_name));
        assert_eq!(dispatched[3], CallArg::Text("image/jpeg".to_owned()));
        assert_eq!(dispatched[5], CallArg::Text("SHARE".to_owned()));
    }

    /// A foreground lost before the write applied is FOREGROUND_LOST, not a clipboard failure,
    /// while the card still records that the write did not happen.
    #[test]
    fn a_lost_foreground_is_reported_as_foreground_lost() {
        let (fixture, invocations) = fixture();
        let offer_id = announce_own_text(&fixture, "never applied");
        let clipboard = PlatformClipboard::new(fixture.events.clone());
        let kotlin = kotlin_reports(invocations, Arc::clone(&clipboard), "FOREGROUND_LOST");
        let result: Value = serde_json::from_str(
            &fixture
                .host
                .activate(
                    &fixture.local.to_string(),
                    &offer_id,
                    "COPY_TEXT",
                    "gesture-lost",
                    clipboard,
                )
                .expect("activation result"),
        )
        .expect("result json");
        kotlin.join().expect("kotlin thread");
        assert_eq!(result["status"], "FAILED");
        assert_eq!(result["code"], "FOREGROUND_LOST");
        let snapshot: Value =
            serde_json::from_str(&fixture.host.shelf_snapshot().expect("snapshot")).expect("json");
        assert_eq!(
            snapshot["cards"][0]["lastAttempt"]["code"],
            "CLIPBOARD_FAILED"
        );
    }

    /// A malformed action is a contract violation and throws; a card that is simply gone is an
    /// outcome and returns a result object with nothing dispatched.
    #[test]
    fn only_contract_violations_throw() {
        let (fixture, invocations) = fixture();
        let clipboard = PlatformClipboard::new(fixture.events.clone());
        let unknown_offer = meshelf_core::OfferId::new().to_string();
        assert!(matches!(
            fixture.host.activate(
                &fixture.local.to_string(),
                &unknown_offer,
                "PASTE",
                "gesture-bad",
                Arc::clone(&clipboard),
            ),
            Err(NativeError::InvalidArgument(_))
        ));
        let result: Value = serde_json::from_str(
            &fixture
                .host
                .activate(
                    &fixture.local.to_string(),
                    &unknown_offer,
                    "SAVE_FILE",
                    "gesture-gone",
                    clipboard,
                )
                .expect("a result, not an exception"),
        )
        .expect("result json");
        assert_eq!(result["status"], "FAILED");
        assert_eq!(result["code"], "SOURCE_UNAVAILABLE");
        assert!(
            invocations.try_recv().is_err(),
            "nothing reaches the platform"
        );
    }
}
