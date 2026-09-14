//! The phone's resident: everything the Android bridge drives, with no JNI in it.
//!
//! [`PhoneResident`] is the phone half of work orders 09/10 assembled in one host-testable place: the
//! trust gate and pairing window that decide who may connect, the capture receiver that records a
//! request before acknowledging it, the fetch resolver that serves capture photographs and ordinary
//! shelf sources, the announcement receiver that stores ordinary offer cards (O-026), the announce and
//! `CaptureStatus` senders, startup reconciliation, and the one timer that ends a request at its
//! expiry. The bridge in `meshelf-android-bridge` owns only argument marshalling, socket binding,
//! and the JVM callback thread; it forwards typed values here and implements [`PhoneEvents`].
//!
//! Three rules shape the code, and each is covered by a test below.
//!
//! * **Invariant 11, durable before acknowledgement.** A `CaptureRequest` is acknowledged
//!   `Presented` only after its row is committed *and* [`PhoneEvents::capture_requested`] has
//!   accepted the event. That ordering lives in `meshelf_net::PhoneCaptureReceiver`; this module
//!   supplies that receiver with the requester's label and never acknowledges anything itself.
//! * **Invariant 12, resource restraint.** Nothing here polls. The listener is event driven, and
//!   the single timer task sleeps until a deadline already recorded in the store, waking early only
//!   when a transition changes what the next deadline is. An idle phone with no live request has no
//!   timer armed at all. Every transition reaches the timer because every one of them passes
//!   through a seam this module supplies: the phone's own calls wake it directly, the network
//!   layer's presentation, delivery and withdrawal events arrive at [`CaptureEvents`], and the
//!   fetch transitions it makes without an event — `Announced -> Claimed`, `Claimed -> Uncertain`
//!   — arrive at [`WakingCaptureSources`], the resolver this module hands the fetch handler. A
//!   claimed row owes no deadline, so without that last wake an uncertain photograph would be
//!   recorded with a delete deadline no timer was ever waiting for.
//! * **A photograph is deleted only on proof.** A validated completed receipt proves delivery;
//!   anything else leaves the row `UncertainNoReplay` until its delete deadline, when it ends
//!   `ExpiredUnconfirmed` and is withdrawn rather than recorded as delivered.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    future::Future,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use meshelf_core::{
    ActivationId, ActivationMode, CaptureCorrelation, CaptureRequestId, CaptureSourcePhase,
    CaptureSourceRecord, CaptureSourceTerminalCode, CapturedPhoto, CardAvailability,
    ClipboardError, ClipboardSink, DeviceId, FileContentClass, MAX_OFFER_ATTEMPT_DETAIL_BYTES,
    MAX_OFFER_PREVIEW_BYTES, OfferAttemptCode, OfferAttemptStatus, OfferCardRecord,
    OfferDescriptor, OfferId, OfferSource, OfferSourceInput, StoreError, V2_MAX_LIVE_ENTRIES,
};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    ActivationFailCode, ActivationOutcome, ActivationRefuseCode, ActivationService,
    CaptureEventRefused, CaptureSourceEvents, CaptureSourceResolver, CaptureWithdrawReason,
    ComposedFetchSourceResolver, FetchActivation, FetchClipboard, FetchSourceResolver,
    FetchableSource, InstallationTrustGate, NetError, OfferAnnouncementHandler, OfferFetchHandler,
    PairingClock, PairingControlError, PairingEvents, PairingWindow, PeerClient,
    PhoneCaptureReceiver, PhonePairingResponder, ServerIdentity, ShelfSourceResolver,
    SocketConnector, StoreCatalogOrigin, V2CaptureReceiver, V2OfferServices, V2Pairing,
    V2ServerConfig, apply_catalog_snapshot, serve_v2,
};
use meshelf_protocol::{
    CAP_CAPTURE_PHOTO_V1, CAP_OFFER_PULL_V2, CAP_SHELF_CATALOG_V1, CaptureAck, CaptureAckCode,
    CaptureRequest, CaptureStatus, CaptureStatusCode, CatalogRequest, ClientHello, FetchRequest,
    OfferAckCode, OfferAnnouncement,
    pairing::{PairingCandidate, PairingId, PairingResult, TranscriptHash},
};
use meshelf_store::{
    CaptureSourceClaim, CaptureTombstonePrune, CaptureTransition, MAX_CAPTURE_PHOTO_BYTES,
    RedbV2Store,
};
use meshelf_tailscale::{InstallationStore, RegistryError, TrustedPeer};
use sha2::{Digest, Sha256};
use tokio::{
    net::TcpListener,
    sync::{Notify, watch},
};

use crate::{MESHELF_PORT, offer_source::OfferInput};

/// How long a photograph may outlive its capture on the phone before it is deleted without a
/// recorded delivery. The instant is stamped into the row when the photograph is attached, so it
/// survives a restart. This Rust-owned row is the only live-file retention authority; Android
/// never infers protocol state from a file modification time.
pub const CAPTURE_PHOTO_DELETE_AFTER_MS: u64 = 10 * 60 * 1_000;

/// Read and write bound for one protocol-2 exchange the phone serves.
const PHONE_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Connect bound for the announcements and statuses the phone sends.
const PHONE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Used only when a deadline fell due and could not be cleared, which needs a failing store. It
/// keeps the timer loop from spinning on that failure; a healthy phone never reaches it.
const DEADLINE_RETRY: Duration = Duration::from_secs(1);
/// The photograph is streamed through the hash in blocks of this size.
const HASH_BLOCK_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------------------------
// The seam the JNI callback thread implements

/// What the resident tells the person's phone. Phase 4 implements this over the bridge's bounded
/// event queue, so every method must be cheap and must not block: they are called from the
/// resident's own tasks and, for [`Self::capture_requested`], from inside the acknowledgement path
/// of an inbound connection.
///
/// Each method is exactly one Kotlin callback. Only
/// [`Self::capture_requested`] may refuse, because invariant 11 makes the acknowledgement depend on
/// it: a request that could not be handed to the user interface was never presented.
pub trait PhoneEvents: Send + Sync + 'static {
    /// `onCaptureRequested`. The row is durable before this is called, and the request is
    /// acknowledged `Presented` only if this returns `Ok`.
    fn capture_requested(&self, record: &CaptureSourceRecord) -> Result<(), CaptureEventRefused>;
    /// `onCaptureWithdrawn`. The request ended without delivering a photograph; remove its
    /// notification and delete any file it holds. Emitted only for endings the phone's own user
    /// interface did not ask for.
    fn capture_withdrawn(&self, request_id: CaptureRequestId, reason: CaptureWithdrawReason);
    /// `onCaptureDelivered`. A validated completed receipt proves the requester durably holds the
    /// photograph, so the phone may delete its copy. Never called for an uncertain outcome.
    fn capture_delivered(&self, request_id: CaptureRequestId);
    /// `onPeerAdmitted`. A pairing completed and this peer is now durably trusted.
    fn peer_admitted(&self, device_name: &str);
    /// `onPairingCandidate`. Show these six digits; the answer returns through
    /// [`PhoneResident::confirm_pairing`] or [`PhoneResident::reject_pairing`].
    fn pairing_candidate(&self, candidate: &PairingCandidate);
    /// `onPairingFinished`, with the A11 result vocabulary.
    fn pairing_finished(&self, pairing_id: PairingId, result: PairingResult);
    /// `onShelfChanged`. An inbound announcement stored a new card, so a visible shelf re-reads
    /// its local snapshot. It never starts a catalog round and carries no card data.
    fn shelf_changed(&self);
}

// ---------------------------------------------------------------------------------------------
// Errors and reports

#[derive(Debug, thiserror::Error)]
pub enum PhoneError {
    #[error("{0}")]
    Configuration(String),
    #[error("capture request {0} is not awaiting a photograph on this phone")]
    NoLiveRequest(CaptureRequestId),
    #[error("capture request {0} expired before the photograph was taken")]
    RequestExpired(CaptureRequestId),
    #[error("{0}")]
    InvalidPhoto(String),
    #[error(
        "insufficient local storage: available {available} bytes; need {required} bytes including safety headroom"
    )]
    InsufficientSpace { available: u64, required: u64 },
    #[error("meshelf storage is unavailable: {0}")]
    Storage(#[from] StoreError),
    #[error("meshelf trust state is unavailable: {0}")]
    Trust(#[from] RegistryError),
    #[error("{0}")]
    Pairing(#[from] PairingControlError),
}

/// What [`PhoneResident::reconcile`] found at startup. Nothing is resumed and nothing is retried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneReconciliation {
    /// The one live unexpired request whose photograph had not been taken, presented again under
    /// the same request id, or `None`.
    pub represented: Option<CaptureRequestId>,
    /// Requests ended by reconciliation and withdrawn from the user interface.
    pub withdrawn: Vec<CaptureRequestId>,
    /// Rows that were mid-transfer and are now uncertain: neither withdrawn nor delivered, each
    /// kept until its delete deadline.
    pub uncertain: Vec<CaptureRequestId>,
    /// Uncertain rows whose deadline had already passed, deleted without a recorded delivery.
    pub expired_unconfirmed: Vec<CaptureRequestId>,
    /// A pairing approval past its completion deadline, cleared so nothing stale can be promoted.
    pub cleared_stale_pairing_approval: bool,
}

/// The resident's half of `nativeStatus`. It carries no key and no network handle.
///
/// The two stored reads are `Result`, not bare values, because this is the phone's only window on
/// itself: a store that cannot be read is not "no live request", and a trust file that cannot be
/// read is not "no paired peers". A zero-filled answer here would be indistinguishable from a
/// healthy idle phone, and the person or the agent reading it would have no way to tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneStatus {
    pub listening: bool,
    pub pairing_window_expires_at_unix_ms: Option<u64>,
    /// The one request the phone is working on, or `Err` when the capture store could not be read.
    pub live_request: Result<Option<CaptureRequestId>, String>,
    /// How many peers are paired, or `Err` when the trust state could not be read.
    pub paired_peers: Result<u32, String>,
    /// Background failures since this resident started, and the most recent one. A background
    /// operation has no caller to return a failure to — an announcement, a status, a deadline
    /// pass, or an input arriving too late to act on — so it is counted here rather than dropped.
    pub failures: PhoneFailures,
}

impl Default for PhoneStatus {
    fn default() -> Self {
        Self {
            listening: false,
            pairing_window_expires_at_unix_ms: None,
            live_request: Ok(None),
            paired_peers: Ok(0),
            failures: PhoneFailures::default(),
        }
    }
}

/// Background failures, counted rather than overwritten.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneFailures {
    /// Every failure recorded since this resident started. It never decreases, so a caller that
    /// reads the status twice can tell a fresh failure from one it has already seen, even when the
    /// wording is identical.
    pub count: u64,
    /// The most recent failure, with the instant it was recorded, or `None` when a background
    /// operation has succeeded since. `count` still shows the earlier ones happened, so clearing
    /// the wording never hides that anything went wrong.
    pub last: Option<PhoneFailure>,
}

/// One recorded background failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneFailure {
    pub detail: String,
    pub at_unix_ms: u64,
}

// ---------------------------------------------------------------------------------------------
// Construction

/// Everything [`PhoneResident::new`] needs. Phase 4 fills this from `PhoneHostContext`: the
/// identity it loaded or generated through Kotlin, the state directory Kotlin owns, and a connector
/// that routes every outbound socket through the VPN network before it connects.
pub struct PhoneResidentConfig {
    pub identity: InstallationIdentity,
    /// This phone's name, as peers read it in the server hello.
    pub device_name: String,
    /// Absolute directory holding `meshelf.redb` and `state.json`.
    pub state_dir: PathBuf,
    /// Absolute directory Kotlin writes final captured photographs into under no-backup internal
    /// storage. Raw CameraX temporaries may use cache, but a final pre-receipt photograph may not.
    /// Every accepted photograph must resolve to a path inside it. Without this the only thing
    /// deciding which file the phone hashes, offers and serves is the caller's own argument, and
    /// [`Resident::capture_captured`] is reached from a JNI export that any code in the app
    /// process can call. It is a separate tree from `state_dir`: Kotlin keeps photographs in the
    /// app's no-backup tree beside meshelf's own state.
    pub photo_root: PathBuf,
    pub events: Arc<dyn PhoneEvents>,
    /// The runtime the resident spawns its timer, announcements and statuses on.
    pub runtime: tokio::runtime::Handle,
    /// Routes every outbound socket through the Tailscale VPN network. `None` uses the operating
    /// system's own routing, which is what host tests want and what a phone must never use.
    pub connector: Option<Arc<dyn SocketConnector>>,
    /// The clock the pairing window and the expiry timer both read.
    pub clock: Arc<dyn PairingClock>,
    /// Opens platform document leases for ordinary file fetches. Defaults to unsupported.
    pub documents: Option<Arc<dyn meshelf_net::DocumentSourceProvider>>,
}

/// The phone's resident. Cheap to clone; clones drive the same listener, store and window.
#[derive(Clone)]
pub struct PhoneResident {
    inner: Arc<Resident>,
}

struct Resident {
    identity: InstallationIdentity,
    device_name: String,
    photo_root: PathBuf,
    store: Arc<RedbV2Store>,
    trust: InstallationStore,
    window: PairingWindow,
    clock: Arc<dyn PairingClock>,
    client: PeerClient,
    events: Arc<dyn PhoneEvents>,
    runtime: tokio::runtime::Handle,
    shutdown: watch::Sender<bool>,
    /// Shared with [`CaptureEvents`], so a transition the network layer made wakes the timer.
    deadline_changed: Arc<Notify>,
    listening: AtomicBool,
    failures: Mutex<PhoneFailures>,
    /// Process-local ordinary camera leases. Paths live under `ordinary-photos/` beside captures.
    ordinary_leases: Mutex<std::collections::HashMap<String, OrdinaryPhotoLease>>,
    documents: Arc<dyn meshelf_net::DocumentSourceProvider>,
    /// The latest explicit refresh or announce of this run. Memory only, never a timer.
    peer_observation: Mutex<Option<PeerObservation>>,
}

#[derive(Debug, Clone)]
struct OrdinaryPhotoLease {
    #[allow(dead_code)] // retained for future commit-time action-id matching
    action_id: String,
    dir: PathBuf,
    raw_path: PathBuf,
    final_path: PathBuf,
    committed: bool,
}

impl PhoneResident {
    /// Opens the phone's store and trust state and arms the deadline timer. It does not listen:
    /// call [`Self::reconcile`], then [`Self::serve`].
    pub fn new(config: PhoneResidentConfig) -> Result<Self, PhoneError> {
        let PhoneResidentConfig {
            identity,
            device_name,
            state_dir,
            photo_root,
            events,
            runtime,
            connector,
            clock,
            documents,
        } = config;
        if !photo_root.is_absolute() {
            return Err(PhoneError::Configuration(format!(
                "the captured-photograph directory {} must be absolute",
                photo_root.display()
            )));
        }
        let store = Arc::new(RedbV2Store::open(state_dir.join("meshelf.redb"))?);
        let trust = InstallationStore::new(state_dir.join("state.json"));
        let mut client = PeerClient::with_timeouts(PHONE_CONNECT_TIMEOUT, PHONE_IO_TIMEOUT);
        if let Some(connector) = connector {
            client = client.with_connector(connector);
        }
        let (shutdown, _) = watch::channel(false);
        let documents = documents.unwrap_or_else(|| {
            Arc::new(meshelf_net::UnsupportedDocumentSources)
                as Arc<dyn meshelf_net::DocumentSourceProvider>
        });
        let inner = Arc::new(Resident {
            identity,
            device_name,
            photo_root,
            store,
            trust,
            window: PairingWindow::new(Arc::clone(&clock)),
            clock,
            client,
            events,
            runtime: runtime.clone(),
            shutdown,
            deadline_changed: Arc::new(Notify::new()),
            listening: AtomicBool::new(false),
            failures: Mutex::new(PhoneFailures::default()),
            ordinary_leases: Mutex::new(std::collections::HashMap::new()),
            documents,
            peer_observation: Mutex::new(None),
        });
        runtime.spawn(run_deadlines(Arc::clone(&inner)));
        Ok(Self { inner })
    }

    /// Serves protocol 2 on `listener` until [`Self::shutdown`]. The caller binds the listener,
    /// which on a phone means a discovered Tailscale address routed through the VPN network and
    /// never a wildcard.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), NetError> {
        let config = self.inner.server_config();
        let shutdown = self.inner.shutdown.subscribe();
        self.inner.listening.store(true, Ordering::SeqCst);
        let result = serve_v2(listener, config, shutdown).await;
        self.inner.listening.store(false, Ordering::SeqCst);
        result
    }

    /// Startup reconciliation. Re-presents the one live unexpired request whose photograph has not
    /// been taken, ends every other unfinished row, deletes uncertain photographs whose deadline
    /// has passed, and clears a pairing approval that can no longer complete. Nothing is resumed:
    /// no camera reopens, no announcement is resent, no fetch restarts.
    pub fn reconcile(&self) -> Result<PhoneReconciliation, PhoneError> {
        self.inner.reconcile()
    }

    /// `nativeCaptureCaptured`. Verifies the file against the arguments, records the photograph
    /// durably **before returning**, and only then announces it to the requester alone.
    pub fn capture_captured(
        &self,
        request_id: CaptureRequestId,
        path: &Path,
        sha256: [u8; 32],
        width: u32,
        height: u32,
    ) -> Result<(), PhoneError> {
        self.inner
            .capture_captured(request_id, path, sha256, width, height)
    }

    /// `nativeCaptureDeclined`. `reason` is the Kotlin word the bridge already validated. An
    /// unknown request id, or one that has already finished, is a no-op. No withdrawal event is
    /// emitted: the phone's own user interface is what called this.
    pub fn capture_declined(
        &self,
        request_id: CaptureRequestId,
        reason: &str,
    ) -> Result<(), PhoneError> {
        self.inner.capture_declined(request_id, reason)
    }

    /// `nativeOpenPairingWindow`. Refuses an expiry in the past, or more than the protocol's
    /// 120-second maximum away.
    pub fn open_pairing_window(&self, expires_at_unix_ms: u64) -> Result<(), PhoneError> {
        self.inner.window.open(expires_at_unix_ms)?;
        Ok(())
    }

    /// `nativeClosePairingWindow`. Ends new admissions and aborts a session that has not reached
    /// the person's durable approval; a session past it runs on to completion (A12). Closing a
    /// closed or expired window is a no-op (A13).
    pub fn close_pairing_window(&self) {
        self.inner.window.close();
    }

    /// `nativeConfirmPairing`. Both the pairing id and the transcript hash must be the candidate
    /// being shown, so a stale tap can neither approve nor end a session.
    pub fn confirm_pairing(
        &self,
        pairing_id: PairingId,
        transcript_hash: TranscriptHash,
    ) -> Result<(), PhoneError> {
        self.inner.window.confirm(&pairing_id, &transcript_hash)?;
        Ok(())
    }

    /// `nativeRejectPairing`.
    pub fn reject_pairing(&self, pairing_id: PairingId) -> Result<(), PhoneError> {
        self.inner.window.reject(&pairing_id)?;
        Ok(())
    }

    /// The resident's half of `nativeStatus`.
    pub fn status(&self) -> PhoneStatus {
        self.inner.status()
    }

    /// `nativeRefreshOriginCatalogs`: one explicit Refresh. Dials each paired peer, requests a
    /// bounded catalog snapshot, applies the metadata, and returns the ABI-8 refresh result with
    /// this round's per-peer observation embedded in the snapshot. Nothing is retried or queued.
    pub async fn refresh_origin_catalogs(&self) -> Result<String, PhoneError> {
        self.inner.refresh_origin_catalogs().await
    }

    /// Local ordinary shelf cards for the UI snapshot (newest first, capped).
    pub fn ordinary_shelf_cards(&self) -> Result<Vec<OfferCardRecord>, PhoneError> {
        self.inner.ordinary_shelf_cards()
    }

    /// `nativeShelfSnapshot`: the ABI-8 metadata-only snapshot (schema version 2).
    pub fn shelf_snapshot_json(&self) -> Result<String, PhoneError> {
        self.inner.shelf_snapshot_json()
    }

    /// Stores a text offer and its own card durably, then announces it once to every paired peer.
    pub async fn announce_text(&self, text: &str) -> Result<AnnounceResult, PhoneError> {
        self.inner.announce_text(text).await
    }

    /// `nativeActivate`: one explicit activation of one card. Every outcome, including a refusal
    /// before anything was dispatched, is an [`ActivationReport`]. A card this phone announced is
    /// served from the source it retains and dials no one; a received card is pulled from its
    /// origin. Both end in the same journaled one-shot platform dispatch through `clipboard`.
    pub async fn activate(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
        action: ShelfAction,
        clipboard: Arc<dyn FetchClipboard>,
    ) -> ActivationReport {
        self.inner
            .activate(source_device, offer_id, action, clipboard)
            .await
    }

    /// Reserve app-private raw/final paths for one ordinary shelf camera capture.
    /// Returns JSON: `{leaseId,rawPath,finalPath}`.
    pub fn reserve_ordinary_photo(&self, action_id: &str) -> Result<String, PhoneError> {
        self.inner.reserve_ordinary_photo(action_id)
    }

    /// Commit a sanitized JPEG at the reserved final path as an ordinary file offer and fan out.
    pub async fn commit_ordinary_photo(
        &self,
        lease_id: &str,
        sha256_hex: &str,
        width: u32,
        height: u32,
    ) -> Result<AnnounceResult, PhoneError> {
        self.inner
            .commit_ordinary_photo(lease_id, sha256_hex, width, height)
            .await
    }

    /// Drop an uncommitted ordinary-photo reservation. Safe after commit (no-op for the file).
    pub fn abandon_ordinary_photo(&self, lease_id: &str) -> Result<(), PhoneError> {
        self.inner.abandon_ordinary_photo(lease_id)
    }

    /// Announce a gallery document already held by a platform lease (no bytes copied into app storage).
    pub async fn announce_document(
        &self,
        lease_id: &str,
        root_name: &str,
        byte_length: u64,
    ) -> Result<AnnounceResult, PhoneError> {
        self.inner
            .announce_document(lease_id, root_name, byte_length)
            .await
    }

    /// `nativeStop`. Closes the pairing window and stops the listener and the timer. Idempotent.
    pub fn shutdown(&self) {
        self.inner.window.close();
        let _ = self.inner.shutdown.send(true);
    }
}

// ---------------------------------------------------------------------------------------------
// Resident behaviour

impl Resident {
    fn local_device(&self) -> DeviceId {
        self.identity.device_id
    }

    fn now(&self) -> u64 {
        self.clock.now_unix_ms()
    }

    /// A background failure has no caller to return it to; it is counted and recorded so
    /// `nativeStatus` can report it rather than being dropped.
    ///
    /// A poisoned lock is recovered from rather than skipped: the only way this mutex is poisoned
    /// is a panic while a failure was being recorded, which is exactly when dropping the next one
    /// would be worst. It holds no invariant a panic could have broken — a count and a string.
    fn record_failure(&self, detail: String) {
        let at_unix_ms = self.now();
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        failures.count = failures.count.saturating_add(1);
        failures.last = Some(PhoneFailure { detail, at_unix_ms });
    }

    /// A background operation succeeded, so the recorded failure is no longer the phone's current
    /// state. The count stays: this clears stale wording, never the fact that something failed.
    fn record_success(&self) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last = None;
    }

    /// The listener's configuration. A phone advertises `offer-pull-v2` (it serves fetches),
    /// `capture-photo-v1` (it fulfils capture requests), and `shelf-catalog-v1` (catch-up metadata)
    /// to an admitted peer, advertises nothing on a refusal so no desktop can record it from a
    /// probe (F1), and offers pairing only through the one window the person opens.
    fn server_config(self: &Arc<Self>) -> V2ServerConfig {
        let capture_events: Arc<dyn CaptureSourceEvents> = Arc::new(CaptureEvents {
            events: Arc::clone(&self.events),
            deadlines: Arc::clone(&self.deadline_changed),
        });
        V2ServerConfig::phone(
            ServerIdentity {
                signing_identity: self.identity.clone(),
                device_name: self.device_name.clone(),
            },
            Arc::new(
                InstallationTrustGate::new(self.trust.clone(), self.local_device())
                    .with_auto_observe_cgnat(),
            ),
            V2OfferServices {
                // Ordinary cards enter the same redb shelf as desktop; correlated capture
                // announcements without a phone-side router stay refused as capture_not_armed.
                // Received cards share the O-014 ordinary index with owned entries: purging an
                // owned card also removes its source (no hidden twenty-card union).
                announcement_receiver: Arc::new(OfferAnnouncementHandler::new(Arc::new(
                    OrdinaryShelfCardStore {
                        store: Arc::clone(&self.store),
                        events: Arc::clone(&self.events),
                        local_device: self.local_device(),
                        documents: Arc::clone(&self.documents),
                        photo_root: self.photo_root.clone(),
                    },
                ))),
                fetch_sender: Arc::new(
                    OfferFetchHandler::with_resolver(
                        self.local_device(),
                        Arc::new(ComposedFetchSourceResolver::new(
                            self.capture_sources(Arc::clone(&capture_events)),
                            Arc::new(ShelfSourceResolver::new(
                                Arc::clone(&self.store) as Arc<dyn meshelf_core::OfferSourceStore>
                            )),
                        )),
                    )
                    .with_document_provider(Arc::clone(&self.documents)),
                ),
            },
            Arc::new(PairedLabelCaptureReceiver {
                inner: PhoneCaptureReceiver::new(Arc::clone(&self.store), capture_events),
                trust: self.trust.clone(),
                local_device: self.local_device(),
            }),
            vec![
                CAP_OFFER_PULL_V2.to_owned(),
                CAP_CAPTURE_PHOTO_V1.to_owned(),
                CAP_SHELF_CATALOG_V1.to_owned(),
            ],
            V2Pairing {
                gate: Arc::new(self.window.clone()),
                responder: Arc::new(PhonePairingResponder::new(
                    self.identity.clone(),
                    self.trust.clone(),
                    Arc::clone(&self.clock),
                    Arc::new(PairingReports {
                        events: Arc::clone(&self.events),
                        trust: self.trust.clone(),
                        local_device: self.local_device(),
                    }),
                )),
            },
            PHONE_IO_TIMEOUT,
        )
        .with_catalog_origin(Arc::new(StoreCatalogOrigin::new(
            Arc::clone(&self.store),
            self.local_device(),
        )))
    }

    /// The fetch sources the listener serves photographs from, wrapped so that the two phases the
    /// network layer moves a row through without an event still reach the timer. See
    /// [`WakingCaptureSources`].
    fn capture_sources(
        self: &Arc<Self>,
        events: Arc<dyn CaptureSourceEvents>,
    ) -> Arc<dyn FetchSourceResolver> {
        Arc::new(WakingCaptureSources {
            inner: CaptureSourceResolver::new(Arc::clone(&self.store), events),
            deadlines: Arc::clone(&self.deadline_changed),
            photo_root: self.photo_root.clone(),
        })
    }

    /// Removes a final photograph that is no longer live. The path must resolve under
    /// [`Self::photo_root`]; anything else is refused and left untouched.
    fn delete_photograph(&self, path: &Path) {
        match delete_photograph_under_root(path, &self.photo_root) {
            Ok(()) => {}
            Err(detail) => self.record_failure(detail),
        }
    }

    fn status(&self) -> PhoneStatus {
        let live_request = self
            .store
            .read_capture_sources()
            .map(|records| {
                records
                    .into_iter()
                    .find(|record| is_live(&record.phase))
                    .map(|record| record.request_id)
            })
            .map_err(|error| format!("the capture store could not be read: {error}"));
        let paired_peers = self
            .trust
            .load_for_identity(self.local_device())
            .map(|state| u32::try_from(state.peers.peers().len()).unwrap_or(u32::MAX))
            .map_err(|error| format!("meshelf trust state could not be read: {error}"));
        PhoneStatus {
            listening: self.listening.load(Ordering::SeqCst),
            pairing_window_expires_at_unix_ms: self.window.open_until(),
            live_request,
            paired_peers,
            failures: self
                .failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }

    fn reconcile(self: &Arc<Self>) -> Result<PhoneReconciliation, PhoneError> {
        let now = self.now();
        let mut report = PhoneReconciliation {
            cleared_stale_pairing_approval: self.settle_pending_pairing(now)?,
            ..PhoneReconciliation::default()
        };
        let sources = self.store.reconcile_capture_sources_at_startup(now)?;
        for (request_id, path) in &sources.deleted_photographs {
            let _ = request_id;
            self.delete_photograph(path);
        }
        for record in &sources.withdraw {
            report.withdrawn.push(record.request_id);
            self.events
                .capture_withdrawn(record.request_id, withdraw_reason(&record.phase));
            self.send_status_later(record, status_code(&record.phase), None);
        }
        report
            .uncertain
            .extend(sources.uncertain.iter().map(|record| record.request_id));
        if let Some(record) = &sources.represent {
            match self.events.capture_requested(record) {
                Ok(()) => report.represented = Some(record.request_id),
                Err(refused) => {
                    // Nothing is being shown, so the request ends now rather than holding the
                    // phone busy until it expires. This is the acknowledgement path's own rule.
                    //
                    // The failure is recorded last, after the ending it describes has actually
                    // been committed, so the recorded message never claims an ending that did not
                    // happen. `end_unannounceable` orders itself the same way for the same reason.
                    let ending = self.store.terminate_capture_source(
                        record.request_id,
                        CaptureSourceTerminalCode::Failed,
                    )?;
                    if let CaptureTransition::Applied(ended) = ending {
                        report.withdrawn.push(ended.request_id);
                        self.events
                            .capture_withdrawn(ended.request_id, CaptureWithdrawReason::Failed);
                        self.send_status_later(
                            &ended,
                            Some(CaptureStatusCode::Failed),
                            Some("presentation_unavailable"),
                        );
                        self.record_failure(format!(
                            "capture request {} could not be re-presented and was ended: {refused}",
                            record.request_id
                        ));
                    } else {
                        self.record_failure(format!(
                            "capture request {} could not be re-presented and was not ended: \
                             {refused}",
                            record.request_id
                        ));
                    }
                }
            }
        }
        report.expired_unconfirmed = self.prune_tombstones(now)?;
        self.wake_deadlines();
        Ok(report)
    }

    /// A12 and A17. An approval that can still complete is restored, so a resume carrying
    /// `DesktopCommitted` is admitted without a second comparison of codes; one past its completion
    /// deadline authorizes nothing and is removed, because nothing else ever clears it.
    fn settle_pending_pairing(&self, now: u64) -> Result<bool, PhoneError> {
        let mut cleared = false;
        let state = self.trust.update(self.local_device(), |state| {
            if state
                .pending_pairing
                .as_ref()
                .is_some_and(|pending| now >= pending.approval.completion_deadline_unix_ms())
            {
                state.pending_pairing = None;
                cleared = true;
            }
            Ok(())
        })?;
        if let Some(pending) = &state.pending_pairing {
            self.window.restore_pending(pending);
        }
        Ok(cleared)
    }

    fn capture_captured(
        self: &Arc<Self>,
        request_id: CaptureRequestId,
        path: &Path,
        sha256: [u8; 32],
        width: u32,
        height: u32,
    ) -> Result<(), PhoneError> {
        let Some(record) = self.store.get_capture_source(request_id)? else {
            return Err(PhoneError::NoLiveRequest(request_id));
        };
        match &record.phase {
            CaptureSourcePhase::Presented => {}
            // The same photograph offered twice is the same durable fact. Anything else is a
            // request that is no longer waiting for one.
            CaptureSourcePhase::Captured { photo }
                if photo.path == path && photo.sha256 == sha256 =>
            {
                return Ok(());
            }
            _ => return Err(PhoneError::NoLiveRequest(request_id)),
        }
        let now = self.now();
        if now >= record.expires_at_unix_ms {
            if let CaptureTransition::Applied(ended) = self
                .store
                .terminate_capture_source(request_id, CaptureSourceTerminalCode::Expired)?
            {
                self.events
                    .capture_withdrawn(request_id, CaptureWithdrawReason::Expired);
                self.send_status_later(&ended, Some(CaptureStatusCode::Expired), None);
                self.wake_deadlines();
            }
            return Err(PhoneError::RequestExpired(request_id));
        }
        let photo = verified_photo(path, &self.photo_root, sha256, width, height, now)?;
        match self.store.attach_captured(request_id, photo)? {
            CaptureTransition::Applied(attached) => {
                self.runtime.spawn(announce(Arc::clone(self), attached));
                self.wake_deadlines();
                Ok(())
            }
            CaptureTransition::Unchanged(_) => Ok(()),
            CaptureTransition::Refused(_) | CaptureTransition::Unknown => {
                Err(PhoneError::NoLiveRequest(request_id))
            }
        }
    }

    /// The phone's own user interface ended the request. It may not end one whose photograph is
    /// already being fetched.
    ///
    /// The store accepts `Claimed -> Terminal(Failed)`, because A19 gives the *fetch* that
    /// transition for a transfer that provably delivered nothing: one that ended before
    /// `FetchComplete`. This caller has no idea whether `FetchComplete` was sent. Android stopping
    /// the foreground service mid-transfer arrives here as `service-stopped`, and using the
    /// allowance for it would report the capture failed to a requester that is about to publish
    /// the photograph — the requester publishes once every byte has arrived, and nothing about
    /// this call can rule that out. The transfer's own end is the authority for a claimed row,
    /// exactly as it is for the expiry timer, which refuses a claimed row for the same reason.
    fn capture_declined(
        self: &Arc<Self>,
        request_id: CaptureRequestId,
        reason: &str,
    ) -> Result<(), PhoneError> {
        if let Some(record) = self.store.get_capture_source(request_id)?
            && matches!(record.phase, CaptureSourcePhase::Claimed { .. })
        {
            // Not silently dropped: the input arrived too late to act on, and the count says so.
            self.record_failure(format!(
                "capture request {request_id} was declined as {reason} while its photograph was \
                 being fetched; the transfer decides how it ends"
            ));
            return Ok(());
        }
        let code = decline_terminal_code(reason);
        let held = self
            .store
            .get_capture_source(request_id)?
            .as_ref()
            .and_then(|record| photograph_path(&record.phase).map(Path::to_path_buf));
        if let CaptureTransition::Applied(ended) =
            self.store.terminate_capture_source(request_id, code)?
        {
            if let Some(path) = held {
                self.delete_photograph(&path);
            }
            self.send_status_later(&ended, status_code(&ended.phase), Some(reason));
            self.wake_deadlines();
        }
        Ok(())
    }

    fn prune_tombstones(&self, now: u64) -> Result<Vec<CaptureRequestId>, PhoneError> {
        let CaptureTombstonePrune {
            expired_unconfirmed,
            deleted_photographs,
            ..
        } = self.store.prune_capture_tombstones(now)?;
        for (request_id, path) in deleted_photographs {
            self.delete_photograph(&path);
            // Deleted without a recorded delivery. `expired` is the honest word: the requester
            // may or may not hold it, and `onCaptureDelivered` is never sent for this row.
            self.events
                .capture_withdrawn(request_id, CaptureWithdrawReason::Expired);
        }
        Ok(expired_unconfirmed
            .into_iter()
            .map(|record| record.request_id)
            .collect())
    }

    /// Everything the timer does when a recorded deadline falls due.
    fn on_deadline(self: &Arc<Self>, now: u64) -> Result<(), PhoneError> {
        for record in self.store.read_capture_sources()? {
            if deadline_of(&record) == Some((Deadline::Expiry, record.expires_at_unix_ms))
                && now >= record.expires_at_unix_ms
            {
                let held = photograph_path(&record.phase).map(Path::to_path_buf);
                if let CaptureTransition::Applied(ended) = self.store.terminate_capture_source(
                    record.request_id,
                    CaptureSourceTerminalCode::Expired,
                )? {
                    if let Some(path) = held {
                        self.delete_photograph(&path);
                    }
                    self.events
                        .capture_withdrawn(ended.request_id, CaptureWithdrawReason::Expired);
                    self.send_status_later(&ended, Some(CaptureStatusCode::Expired), None);
                }
            }
        }
        self.prune_tombstones(now)?;
        Ok(())
    }

    /// The earliest instant at which [`Self::on_deadline`] would change something, or `None` when
    /// nothing is pending, which is what lets an idle phone arm no timer at all.
    fn next_deadline(&self) -> Result<Option<u64>, PhoneError> {
        Ok(self
            .store
            .read_capture_sources()?
            .iter()
            .filter_map(|record| deadline_of(record).map(|(_, at)| at))
            .min())
    }

    fn wake_deadlines(&self) {
        self.deadline_changed.notify_one();
    }

    /// Best-effort notice that a request ended, so the requester's wait can stop early instead of
    /// running to its own expiry. Never retried and never queued.
    fn send_status_later(
        self: &Arc<Self>,
        record: &CaptureSourceRecord,
        code: Option<CaptureStatusCode>,
        detail: Option<&str>,
    ) {
        let Some(code) = code else { return };
        let status = CaptureStatus {
            request_id: record.request_id,
            code,
            detail: detail.map(str::to_owned),
        };
        let requester = record.requester;
        let resident = Arc::clone(self);
        self.runtime.spawn(async move {
            match resident.send_status(requester, status).await {
                Ok(()) => resident.record_success(),
                Err(error) => {
                    resident.record_failure(format!("capture status was not delivered: {error}"));
                }
            }
        });
    }

    async fn send_status(
        &self,
        requester: DeviceId,
        status: CaptureStatus,
    ) -> Result<(), NetError> {
        let peer = self.paired_peer(requester)?;
        let address = peer_address(&peer)?;
        let hello = self.outbound_hello(status.request_id.to_string());
        self.client
            .send_capture_status(address, hello, requester, status, &peer.public_key)
            .await
            .map(|_| ())
    }

    fn outbound_hello(&self, nonce: String) -> ClientHello {
        ClientHello::signed_v2_with_capabilities(
            self.local_device(),
            self.device_name.clone(),
            nonce,
            vec![
                CAP_OFFER_PULL_V2.to_owned(),
                CAP_CAPTURE_PHOTO_V1.to_owned(),
                CAP_SHELF_CATALOG_V1.to_owned(),
            ],
            &self.identity,
        )
    }

    /// One coalesced metadata round across every paired peer. Each peer's outcome becomes this
    /// run's observation; nothing is retried or queued.
    async fn refresh_origin_catalogs(&self) -> Result<String, PhoneError> {
        let peers = self
            .trust
            .load_for_identity(self.local_device())?
            .peers
            .peers()
            .to_vec();
        let mut new_items = 0_u32;
        let mut observed = Vec::with_capacity(peers.len());
        for peer in peers {
            let outcome = match peer_address(&peer) {
                Err(_) => PeerOutcome::NoAddress,
                Ok(address) => self.request_catalog(&peer, address, &mut new_items).await?,
            };
            observed.push(PeerObservationEntry::new(&peer, outcome));
        }
        self.observe(PeerObservation {
            trigger: ObservationTrigger::Refresh,
            peers: observed,
        });
        let snapshot = self.shelf_snapshot()?;
        contract_json(
            &RefreshResultJson {
                schema_version: SHELF_SCHEMA_VERSION,
                new_items,
                snapshot,
            },
            "refresh result",
        )
    }

    /// One peer's catalog round. A peer that answers at all, even with a refusal or with no
    /// catalog support, was reached. A catalog the peer did send that this phone cannot store is
    /// that peer's `CatalogFailed` outcome and the round continues to the remaining peers; entries
    /// stored before the failure stay on the shelf but are not counted in `new_items`.
    async fn request_catalog(
        &self,
        peer: &TrustedPeer,
        address: SocketAddr,
        new_items: &mut u32,
    ) -> Result<PeerOutcome, PhoneError> {
        let (after_ordinal, origin_epoch) = self
            .store
            .get_catalog_frontier(peer.device_id)?
            .map_or((0, 0), |frontier| {
                (frontier.accepted_through_ordinal, frontier.origin_epoch)
            });
        let request = CatalogRequest::new(
            peer.device_id,
            self.local_device(),
            after_ordinal,
            origin_epoch,
        );
        let hello = self.outbound_hello(request.request_id.to_string());
        match self
            .client
            .request_catalog_v2(address, hello, request, &peer.public_key)
            .await
        {
            Ok(Ok(snapshot)) => {
                match apply_catalog_snapshot(&self.store, &snapshot, Some(self.local_device())) {
                    Ok(inserted) => {
                        *new_items = new_items.saturating_add(inserted);
                        Ok(PeerOutcome::CatalogApplied)
                    }
                    Err(error) => {
                        self.record_failure(format!(
                            "catalog from {} could not be applied: {error}",
                            peer.hostname
                        ));
                        Ok(PeerOutcome::CatalogFailed)
                    }
                }
            }
            Ok(Err(refusal))
                if matches!(
                    refusal.code,
                    meshelf_protocol::CatalogRefusalCode::Unsupported
                ) =>
            {
                Ok(PeerOutcome::CatalogUnsupported)
            }
            Ok(Err(refusal)) => {
                self.record_failure(format!(
                    "catalog refused: {}",
                    refusal
                        .detail
                        .unwrap_or_else(|| format!("{:?}", refusal.code))
                ));
                Ok(PeerOutcome::Refused)
            }
            Err(error) => {
                self.record_failure(format!("catalog request failed: {error}"));
                Ok(PeerOutcome::TransportFailed)
            }
        }
    }

    /// The paired record for `device`. Trust is what names a peer: a device with no record is not
    /// one this phone will talk to, whatever it calls itself.
    fn paired_peer(&self, device: DeviceId) -> Result<TrustedPeer, NetError> {
        self.trust
            .load_for_identity(self.local_device())
            .map_err(|error| {
                NetError::Rejected(format!("meshelf trust state is unavailable: {error}"))
            })?
            .peers
            .by_device_id(device)
            .cloned()
            .ok_or_else(|| {
                NetError::Rejected(format!("peer {device} is not paired with this phone"))
            })
    }

    fn ordinary_shelf_cards(&self) -> Result<Vec<OfferCardRecord>, PhoneError> {
        let mut cards = self.store.read_offer_shelf().map_err(PhoneError::from)?;
        // O-014 / G08: never hide an over-capacity store behind a truncated UI view.
        if cards.len() > V2_MAX_LIVE_ENTRIES as usize {
            return Err(PhoneError::Configuration(format!(
                "ordinary shelf has {} cards; ten-entry index was exceeded",
                cards.len()
            )));
        }
        cards.sort_by_key(|card| std::cmp::Reverse(card.received_sequence));
        Ok(cards)
    }

    fn shelf_snapshot_json(&self) -> Result<String, PhoneError> {
        contract_json(&self.shelf_snapshot()?, "shelf snapshot")
    }

    /// Names come from the trust registry at read time. A trust state that cannot be read fails
    /// the snapshot rather than rendering every received card as an unknown device.
    fn shelf_snapshot(&self) -> Result<ShelfSnapshotJson, PhoneError> {
        let cards = self.ordinary_shelf_cards()?;
        let trusted = self
            .trust
            .load_for_identity(self.local_device())?
            .peers
            .peers()
            .iter()
            .map(|peer| (peer.device_id, peer.hostname.clone()))
            .collect();
        let observation = self
            .peer_observation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        shelf_snapshot(
            self.local_device(),
            &self.device_name,
            &cards,
            &trusted,
            observation,
        )
    }

    fn observe(&self, observation: PeerObservation) {
        *self
            .peer_observation
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(observation);
    }

    fn announce_peers(&self) -> Result<Vec<TrustedPeer>, PhoneError> {
        let peers = self
            .trust
            .load_for_identity(self.local_device())
            .map_err(|error| PhoneError::Configuration(error.to_string()))?
            .peers
            .peers()
            .to_vec();
        // No trusted peer is not an error: the own card is still stored, and the result reports
        // that no device was reached.
        Ok(peers)
    }

    async fn announce_text(&self, text: &str) -> Result<AnnounceResult, PhoneError> {
        let peers = self.announce_peers()?;
        let prepared = crate::offer_source::prepare_source(crate::offer_source::OfferInput::Text(
            text.to_owned(),
        ))
        .map_err(|error| PhoneError::Configuration(error.to_string()))?;
        let offer_id = OfferId::new();
        let announced_to = peers.iter().map(|peer| peer.device_id).collect();
        let inserted = self
            .store
            .insert_owned_ordinary(
                self.local_device(),
                OfferSourceInput::new(
                    offer_id,
                    prepared.descriptor.clone(),
                    announced_to,
                    prepared.source,
                ),
            )
            .map_err(PhoneError::from)?;
        self.finish_owned_ordinary_admission(&inserted)?;
        Ok(self
            .fan_out(offer_id, &prepared.descriptor, peers, "text")
            .await)
    }

    /// Announces an offer whose own card and source are already durable to each peer once. Each
    /// peer's outcome is observed; an unreachable or refusing peer is not retried and nothing is
    /// queued for later.
    async fn fan_out(
        &self,
        offer_id: OfferId,
        descriptor: &OfferDescriptor,
        peers: Vec<TrustedPeer>,
        what: &str,
    ) -> AnnounceResult {
        let created_at = self.now();
        let mut observed = Vec::with_capacity(peers.len());
        for peer in peers {
            let outcome = match peer_address(&peer) {
                Err(error) => {
                    self.record_failure(format!("{what} announce peer has no address: {error}"));
                    PeerOutcome::NoAddress
                }
                Ok(address) => {
                    let announcement = OfferAnnouncement::new(
                        offer_id,
                        self.local_device(),
                        peer.device_id,
                        created_at,
                        descriptor.clone(),
                    );
                    let hello = self.outbound_hello(offer_id.to_string());
                    match self
                        .client
                        .announce_offer_v2(address, hello, announcement, &peer.public_key)
                        .await
                    {
                        Ok(ack)
                            if matches!(
                                ack.code,
                                OfferAckCode::Stored | OfferAckCode::Duplicate
                            ) =>
                        {
                            self.record_success();
                            PeerOutcome::Stored
                        }
                        Ok(ack) => {
                            self.record_failure(format!(
                                "{what} announce refused: {}",
                                ack.detail
                                    .unwrap_or_else(|| "announcement refused".to_owned())
                            ));
                            PeerOutcome::Refused
                        }
                        Err(error) => {
                            self.record_failure(format!(
                                "{what} announce did not complete: {error}"
                            ));
                            PeerOutcome::TransportFailed
                        }
                    }
                }
            };
            observed.push(PeerObservationEntry::new(&peer, outcome));
        }
        self.observe(PeerObservation {
            trigger: ObservationTrigger::Announce,
            peers: observed.clone(),
        });
        AnnounceResult::stored(offer_id, observed)
    }

    fn ordinary_photo_root(&self) -> Result<PathBuf, PhoneError> {
        let parent = self.photo_root.parent().ok_or_else(|| {
            PhoneError::Configuration(
                "photograph root has no parent for ordinary photos".to_owned(),
            )
        })?;
        let root = parent.join("ordinary-photos");
        std::fs::create_dir_all(&root).map_err(|error| {
            PhoneError::Configuration(format!("could not create ordinary-photo root: {error}"))
        })?;
        std::fs::canonicalize(&root).map_err(|error| {
            PhoneError::Configuration(format!("could not resolve ordinary-photo root: {error}"))
        })
    }

    fn reserve_ordinary_photo(&self, action_id: &str) -> Result<String, PhoneError> {
        if action_id.trim().is_empty() {
            return Err(PhoneError::Configuration("action id is empty".to_owned()));
        }
        let root = self.ordinary_photo_root()?;
        // Raw + final staging under one lease; refuse before creating files when disk is short.
        require_ordinary_disk_budget(&root, MAX_CAPTURE_PHOTO_BYTES.saturating_mul(2))?;
        let lease_id = OfferId::new().to_string();
        let dir = root.join(&lease_id);
        std::fs::create_dir_all(&dir)
            .map_err(|error| map_storage_io("ordinary-photo lease dir", error))?;
        let raw_path = dir.join("raw.jpg");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        // The offer is announced under this file name, so a desktop saves it under this name.
        let final_path = dir.join(ordinary_photo_file_name(now));
        if raw_path.exists() || final_path.exists() {
            return Err(PhoneError::Configuration(
                "ordinary-photo lease paths already exist".to_owned(),
            ));
        }
        let lease = OrdinaryPhotoLease {
            action_id: action_id.to_owned(),
            dir: dir.clone(),
            raw_path: raw_path.clone(),
            final_path: final_path.clone(),
            committed: false,
        };
        self.ordinary_leases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(lease_id.clone(), lease);
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveJson {
            lease_id: String,
            raw_path: String,
            final_path: String,
        }
        serde_json::to_string(&ReserveJson {
            lease_id,
            raw_path: raw_path.to_string_lossy().into_owned(),
            final_path: final_path.to_string_lossy().into_owned(),
        })
        .map_err(|error| {
            PhoneError::Configuration(format!(
                "could not serialize ordinary-photo reservation: {error}"
            ))
        })
    }

    async fn commit_ordinary_photo(
        &self,
        lease_id: &str,
        sha256_hex: &str,
        width: u32,
        height: u32,
    ) -> Result<AnnounceResult, PhoneError> {
        if lease_id.trim().is_empty() {
            return Err(PhoneError::Configuration("lease id is empty".to_owned()));
        }
        if width == 0 || height == 0 {
            return Err(PhoneError::InvalidPhoto(
                "ordinary photo dimensions must be positive".to_owned(),
            ));
        }
        let expected = parse_sha256_hex(sha256_hex)?;
        let final_path = {
            let leases = self
                .ordinary_leases
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let lease = leases.get(lease_id).ok_or_else(|| {
                PhoneError::Configuration("unknown ordinary-photo lease".to_owned())
            })?;
            if lease.committed {
                return Err(PhoneError::Configuration(
                    "ordinary-photo lease is already committed".to_owned(),
                ));
            }
            lease.final_path.clone()
        };
        let meta = std::fs::metadata(&final_path).map_err(|error| {
            PhoneError::InvalidPhoto(format!("ordinary photo final file missing: {error}"))
        })?;
        if !meta.is_file() || meta.len() == 0 {
            return Err(PhoneError::InvalidPhoto(
                "ordinary photo final file is empty or not a file".to_owned(),
            ));
        }
        require_ordinary_disk_budget(
            final_path.parent().unwrap_or(final_path.as_path()),
            meta.len(),
        )?;
        let bytes = std::fs::read(&final_path)
            .map_err(|error| map_storage_io("ordinary photo final file", error))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected {
            return Err(PhoneError::InvalidPhoto(
                "ordinary photo hash does not match reserved final file".to_owned(),
            ));
        }
        let peers = self.announce_peers()?;
        let mut prepared =
            crate::offer_source::prepare_source(OfferInput::Path(final_path.clone()))
                .map_err(|error| PhoneError::Configuration(error.to_string()))?;
        // An ordinary camera photo is a photo because this path took it, never by its extension.
        let OfferDescriptor::File { content_class, .. } = &mut prepared.descriptor else {
            return Err(PhoneError::InvalidPhoto(
                "ordinary photo final path is not a file".to_owned(),
            ));
        };
        *content_class = FileContentClass::Photo;
        let offer_id = OfferId::new();
        let announced_to = peers.iter().map(|peer| peer.device_id).collect();
        let inserted = self
            .store
            .insert_owned_ordinary(
                self.local_device(),
                OfferSourceInput::new(
                    offer_id,
                    prepared.descriptor.clone(),
                    announced_to,
                    prepared.source,
                ),
            )
            .map_err(PhoneError::from)?;
        self.finish_owned_ordinary_admission(&inserted)?;
        {
            let mut leases = self
                .ordinary_leases
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(lease) = leases.get_mut(lease_id) {
                lease.committed = true;
                let _ = std::fs::remove_file(&lease.raw_path);
            }
        }
        Ok(self
            .fan_out(offer_id, &prepared.descriptor, peers, "ordinary photo")
            .await)
    }

    fn abandon_ordinary_photo(&self, lease_id: &str) -> Result<(), PhoneError> {
        if lease_id.trim().is_empty() {
            return Err(PhoneError::Configuration("lease id is empty".to_owned()));
        }
        let lease = self
            .ordinary_leases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(lease_id);
        let Some(lease) = lease else {
            return Ok(());
        };
        if lease.committed {
            // Final file is the durable offer source; only drop the raw temporary if present.
            let _ = std::fs::remove_file(&lease.raw_path);
            return Ok(());
        }
        let _ = std::fs::remove_file(&lease.raw_path);
        let _ = std::fs::remove_file(&lease.final_path);
        let _ = std::fs::remove_dir(&lease.dir);
        Ok(())
    }

    async fn announce_document(
        &self,
        lease_id: &str,
        root_name: &str,
        byte_length: u64,
    ) -> Result<AnnounceResult, PhoneError> {
        use std::str::FromStr;
        let lease_id = meshelf_core::DocumentLeaseId::from_str(lease_id.trim())
            .map_err(|_| PhoneError::Configuration("document lease id is not a UUID".to_owned()))?;
        if root_name.trim().is_empty() || root_name.contains('/') || root_name.contains('\\') {
            return Err(PhoneError::Configuration(
                "document root name must be a portable basename".to_owned(),
            ));
        }
        if byte_length == 0 || byte_length > meshelf_core::MAX_OFFER_FILE_BYTES {
            return Err(PhoneError::InvalidPhoto(
                "document byte length is outside the allowed bound".to_owned(),
            ));
        }
        let peers = self.announce_peers()?;
        let commitment =
            meshelf_net::document_metadata_commitment(lease_id, root_name, byte_length);
        let offer_id = OfferId::new();
        let descriptor = OfferDescriptor::File {
            root_name: root_name.to_owned(),
            total_bytes: byte_length,
            // Only the photo picker announces documents on Android.
            content_class: FileContentClass::Photo,
        };
        let announced_to = peers.iter().map(|peer| peer.device_id).collect();
        let inserted = self
            .store
            .insert_owned_ordinary(
                self.local_device(),
                OfferSourceInput::new(
                    offer_id,
                    descriptor.clone(),
                    announced_to,
                    OfferSource::Document {
                        lease_id,
                        metadata_commitment: commitment,
                    },
                ),
            )
            .map_err(|error| PhoneError::Configuration(error.to_string()))?;
        if !inserted.inserted {
            return Err(PhoneError::Configuration(
                "document offer id collided".to_owned(),
            ));
        }
        self.finish_owned_ordinary_admission(&inserted)?;
        Ok(self.fan_out(offer_id, &descriptor, peers, "document").await)
    }

    async fn activate(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
        action: ShelfAction,
        clipboard: Arc<dyn FetchClipboard>,
    ) -> ActivationReport {
        let refuse = |code, detail: &str| {
            ActivationReport::refused(source_device, offer_id, action, code, detail)
        };
        let card = match self.store.get_offer_card(source_device, offer_id) {
            Ok(Some(card)) => card,
            Ok(None) => {
                return refuse(
                    ActivationCode::SourceUnavailable,
                    "this card is no longer on the shelf",
                );
            }
            Err(error) => return refuse(ActivationCode::Internal, &error.to_string()),
        };
        let kind = CardKind::of(&card.descriptor);
        if !kind.actions().contains(&action) {
            return refuse(ActivationCode::Unsupported, kind.unsupported_detail());
        }
        if card.availability == CardAvailability::SourceChanged {
            return refuse(
                ActivationCode::SourceChanged,
                "the source changed after this card was offered",
            );
        }
        let state_root = self
            .store
            .path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.photo_root.clone());
        // Save and Share use Clipboard mode too: the durable dispatch journal fences the platform
        // write exactly as it fences a Copy, and an uncertain one is never replayed.
        let service = ActivationService::new(
            self.local_device(),
            Arc::clone(&self.store),
            Arc::new(ClipboardBridge(clipboard)),
            state_root,
        );
        // Recovery runs before the fence is read. A row a dead process left `ApplyingClipboard`
        // would otherwise read as a live write and refuse every card as busy, and a refused
        // activation never reaches the service that recovers.
        if let Err(error) = service.recover() {
            return refuse(ActivationCode::Internal, &error.to_string());
        }
        // O-028: an uncertain platform action fences only its own card.
        match self.store.clipboard_fence(source_device, offer_id) {
            Ok(meshelf_core::ClipboardFence::Clear) => {}
            Ok(meshelf_core::ClipboardFence::UncertainCard) => {
                return refuse(
                    ActivationCode::UncertainNoReplay,
                    "this card's last platform action may already have happened; it is never repeated",
                );
            }
            Ok(meshelf_core::ClipboardFence::Busy) => {
                return refuse(
                    ActivationCode::Busy,
                    "another platform action is being applied",
                );
            }
            Err(error) => return refuse(ActivationCode::Internal, &error.to_string()),
        }
        let before = card.last_attempt;
        let activation = FetchActivation::new(
            ActivationId::new(),
            source_device,
            offer_id,
            ActivationMode::Clipboard,
            None,
        );
        let result = if source_device == self.local_device() {
            let record = match self.store.get_offer_source(offer_id) {
                Ok(Some(record)) => record,
                Ok(None) => {
                    return refuse(
                        ActivationCode::SourceUnavailable,
                        "this phone no longer retains the source",
                    );
                }
                Err(error) => return refuse(ActivationCode::Internal, &error.to_string()),
            };
            service
                .activate_local(activation, record, self.documents.as_ref())
                .await
        } else {
            let peer = match self.paired_peer(source_device) {
                Ok(peer) => peer,
                Err(error) => return refuse(ActivationCode::SourceUnavailable, &error.to_string()),
            };
            let address = match peer_address(&peer) {
                Ok(address) => address,
                Err(error) => return refuse(ActivationCode::SourceUnavailable, &error.to_string()),
            };
            let request = FetchRequest {
                request_id: activation.request_id,
                offer_id,
                source_device,
                requester_device: self.local_device(),
            };
            let hello = self.outbound_hello(activation.request_id.to_string());
            let (_cancel, cancel) = watch::channel(false);
            service
                .activate(
                    &self.client,
                    address,
                    hello,
                    request,
                    activation,
                    &peer.public_key,
                    cancel,
                )
                .await
        };
        // The receiver records this activation's attempt on the card; an unchanged attempt is an
        // earlier activation's and says nothing about this one.
        let attempt = self
            .store
            .get_offer_card(source_device, offer_id)
            .ok()
            .flatten()
            .and_then(|card| card.last_attempt)
            .filter(|attempt| before.as_ref() != Some(attempt));
        ActivationReport::settled(source_device, offer_id, action, result, attempt)
    }
}

// ---------------------------------------------------------------------------------------------
// Announcement to the requester alone

/// Announces one photograph to the device that asked for it and to nobody else. `Announced` is
/// committed before the announcement leaves, because only an announced row can be claimed and the
/// requester may fetch the instant it arrives (A19).
async fn announce(resident: Arc<Resident>, record: CaptureSourceRecord) {
    let CaptureSourcePhase::Captured { photo } = &record.phase else {
        return;
    };
    let requester = record.requester;
    let peer = match resident.paired_peer(requester) {
        Ok(peer) => peer,
        Err(error) => return end_unannounceable(&resident, &record, &error.to_string()),
    };
    let address = match peer_address(&peer) {
        Ok(address) => address,
        Err(error) => return end_unannounceable(&resident, &record, &error.to_string()),
    };
    match resident.store.mark_capture_announced(record.request_id) {
        Ok(CaptureTransition::Applied(_) | CaptureTransition::Unchanged(_)) => {}
        Ok(_) => return,
        Err(error) => {
            return resident
                .record_failure(format!("capture photograph was not announced: {error}"));
        }
    }
    let announcement = OfferAnnouncement::new(
        photo.offer_id,
        resident.local_device(),
        requester,
        resident.now(),
        photo.descriptor.clone(),
    )
    .with_capture(CaptureCorrelation {
        request_id: record.request_id,
    });
    let hello = resident.outbound_hello(photo.offer_id.to_string());
    match resident
        .client
        .announce_offer_v2(address, hello, announcement, &peer.public_key)
        .await
    {
        Ok(ack) if matches!(ack.code, OfferAckCode::Stored | OfferAckCode::Duplicate) => {
            resident.record_success();
        }
        // A signed refusal is a definite answer: this photograph will never be pulled, so it ends
        // now rather than being held until expiry.
        Ok(ack) => end_unannounceable(
            &resident,
            &record,
            &ack.detail
                .unwrap_or_else(|| "announcement refused".to_owned()),
        ),
        // A transport failure is not an answer. The requester may have received the announcement
        // and already be pulling, so the row stays announced and its expiry owns it. There is no
        // retry and no queue.
        Err(error) => {
            resident.record_failure(format!("capture announcement did not complete: {error}"));
        }
    }
}

/// Ends a photograph that provably cannot reach its requester. The failure is recorded last, so
/// the recorded message never advertises an ending that has not happened yet.
fn end_unannounceable(resident: &Arc<Resident>, record: &CaptureSourceRecord, detail: &str) {
    let outcome = match resident
        .store
        .terminate_capture_source(record.request_id, CaptureSourceTerminalCode::Failed)
    {
        Ok(CaptureTransition::Applied(ended)) => {
            resident
                .events
                .capture_withdrawn(ended.request_id, CaptureWithdrawReason::Failed);
            resident.send_status_later(&ended, Some(CaptureStatusCode::Failed), Some(detail));
            resident.wake_deadlines();
            format!(
                "capture photograph for {} cannot be announced: {detail}",
                record.request_id
            )
        }
        Ok(_) => format!(
            "capture photograph for {} cannot be announced and had already ended: {detail}",
            record.request_id
        ),
        Err(error) => format!(
            "capture photograph for {} cannot be announced and was not ended: {error}",
            record.request_id
        ),
    };
    resident.record_failure(outcome);
}

fn peer_address(peer: &TrustedPeer) -> Result<SocketAddr, NetError> {
    peer.dial_addresses()
        .first()
        .map(|ip| SocketAddr::new(*ip, MESHELF_PORT))
        .ok_or_else(|| NetError::Rejected("paired peer has no bound address".to_owned()))
}

/// Phone offer-card store that keeps owned sources in sync with the ordinary ten-entry index.
struct OrdinaryShelfCardStore {
    store: Arc<RedbV2Store>,
    events: Arc<dyn PhoneEvents>,
    local_device: DeviceId,
    documents: Arc<dyn meshelf_net::DocumentSourceProvider>,
    photo_root: PathBuf,
}

impl OrdinaryShelfCardStore {
    fn release_purged(&self, inserted: &meshelf_core::OfferCardInsert) {
        for lease in &inserted.releasable_document_leases {
            self.documents.release(*lease);
        }
        let ordinary_root = self
            .photo_root
            .parent()
            .map(|parent| parent.join("ordinary-photos"));
        let Some(root) = ordinary_root else {
            return;
        };
        for path in &inserted.purged_owned_file_paths {
            if path.starts_with(&root) {
                let _ = std::fs::remove_file(path);
                if let Some(parent) = path.parent()
                    && parent.starts_with(&root)
                    && parent != root
                {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        }
    }
}

impl meshelf_net::OfferCardStore for OrdinaryShelfCardStore {
    fn get_offer_card(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
    ) -> Result<Option<OfferCardRecord>, StoreError> {
        self.store.get_offer_card(source_device, offer_id)
    }

    fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError> {
        self.store.read_offer_shelf()
    }

    fn insert_offer_card(
        &self,
        input: meshelf_core::OfferCardInput,
    ) -> Result<meshelf_core::OfferCardInsert, StoreError> {
        let inserted = self
            .store
            .insert_offer_card_on_ordinary_index(input, Some(self.local_device))?;
        self.release_purged(&inserted);
        if inserted.inserted {
            // Without this an open shelf showed a delivered item only after Refresh.
            self.events.shelf_changed();
        }
        Ok(inserted)
    }
}

impl Resident {
    fn finish_owned_ordinary_admission(
        &self,
        inserted: &meshelf_core::OwnedOrdinaryInsert,
    ) -> Result<(), PhoneError> {
        for lease in &inserted.releasable_document_leases {
            self.documents.release(*lease);
        }
        let Ok(root) = self.ordinary_photo_root() else {
            return Ok(());
        };
        for path in &inserted.purged_owned_file_paths {
            if path.starts_with(&root) {
                let _ = std::fs::remove_file(path);
                if let Some(parent) = path.parent()
                    && parent.starts_with(&root)
                    && parent != root
                {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        }
        Ok(())
    }
}

/// O-008/O-012 safety headroom used by fetch reservation; mirrored so ordinary admit refuses
/// explicitly before creating files instead of silently dropping on ENOSPC.
fn ordinary_storage_headroom(total_bytes: u64) -> u64 {
    2_u64
        .saturating_mul(1024 * 1024 * 1024)
        .max((total_bytes / 20).min(16_u64 * 1024 * 1024 * 1024))
}

fn require_ordinary_disk_budget(path: &Path, payload_bytes: u64) -> Result<(), PhoneError> {
    let available = meshelf_platform::available_space(path).map_err(|error| {
        PhoneError::Configuration(format!("could not read available storage: {error}"))
    })?;
    let total = meshelf_platform::total_space(path).map_err(|error| {
        PhoneError::Configuration(format!("could not read total storage: {error}"))
    })?;
    ordinary_disk_budget_allows(available, total, payload_bytes)
}

fn ordinary_disk_budget_allows(
    available: u64,
    total: u64,
    payload_bytes: u64,
) -> Result<(), PhoneError> {
    let required = payload_bytes
        .checked_add(ordinary_storage_headroom(total))
        .ok_or_else(|| PhoneError::Configuration("storage budget overflow".to_owned()))?;
    if available < required {
        return Err(PhoneError::InsufficientSpace {
            available,
            required,
        });
    }
    Ok(())
}

fn map_storage_io(what: &str, error: std::io::Error) -> PhoneError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
    ) {
        return PhoneError::InsufficientSpace {
            available: 0,
            required: 1,
        };
    }
    PhoneError::Configuration(format!("could not use {what}: {error}"))
}

// ---------------------------------------------------------------------------------------------
// Android shelf contract JSON (ABI 8, `handoffs/ANDROID_SHELF_ABI.md`)

/// `schemaVersion` of every shelf JSON document the natives return.
pub const SHELF_SCHEMA_VERSION: u32 = 2;
/// The source name of a received card whose device has no trust record: explicit, never the
/// device UUID and never empty.
pub const UNKNOWN_DEVICE_NAME: &str = "Unknown device";

/// Which explicit operation produced a [`PeerObservation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationTrigger {
    Refresh,
    Announce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reachability {
    Reachable,
    Unavailable,
}

/// What one explicit operation learned from one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PeerOutcome {
    CatalogApplied,
    CatalogUnsupported,
    /// The peer answered with a catalog this phone could not store.
    CatalogFailed,
    Refused,
    Stored,
    TransportFailed,
    NoAddress,
}

impl PeerOutcome {
    /// The only authority for reachability: a peer that answered at all, even with a refusal or
    /// with no catalog support, was reached. Only a failed or impossible dial is unavailable.
    #[must_use]
    pub const fn reachability(self) -> Reachability {
        match self {
            Self::TransportFailed | Self::NoAddress => Reachability::Unavailable,
            Self::CatalogApplied
            | Self::CatalogUnsupported
            | Self::CatalogFailed
            | Self::Refused
            | Self::Stored => Reachability::Reachable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerObservationEntry {
    pub device_id: DeviceId,
    /// The trusted registry name, never a name the peer sent.
    pub display_name: String,
    pub reachability: Reachability,
    pub outcome: PeerOutcome,
}

impl PeerObservationEntry {
    fn new(peer: &TrustedPeer, outcome: PeerOutcome) -> Self {
        Self {
            device_id: peer.device_id,
            display_name: peer.hostname.clone(),
            reachability: outcome.reachability(),
            outcome,
        }
    }
}

/// The latest explicit refresh or announce of this resident run. Held in memory only: never
/// persisted and never produced by a timer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerObservation {
    pub trigger: ObservationTrigger,
    pub peers: Vec<PeerObservationEntry>,
}

/// `nativeAnnounceText`, `nativeAnnounceDocument` and `nativeCommitOrdinaryPhoto`. A value exists
/// only after the own card and its source were durably stored, before fanout; failing to store
/// them is an error instead, so `local_stored` is true in every returned value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnounceResult {
    schema_version: u32,
    pub offer_id: OfferId,
    pub local_stored: bool,
    pub added_count: u32,
    pub unavailable_count: u32,
    pub refused_count: u32,
    pub peers: Vec<PeerObservationEntry>,
}

impl AnnounceResult {
    fn stored(offer_id: OfferId, peers: Vec<PeerObservationEntry>) -> Self {
        let count = |wanted: fn(PeerOutcome) -> bool| {
            u32::try_from(peers.iter().filter(|peer| wanted(peer.outcome)).count())
                .unwrap_or(u32::MAX)
        };
        Self {
            schema_version: SHELF_SCHEMA_VERSION,
            offer_id,
            local_stored: true,
            added_count: count(|outcome| outcome == PeerOutcome::Stored),
            unavailable_count: count(|outcome| outcome.reachability() == Reachability::Unavailable),
            refused_count: count(|outcome| outcome == PeerOutcome::Refused),
            peers,
        }
    }

    pub fn to_json(&self) -> Result<String, PhoneError> {
        refuse_repeated_peers(&self.peers)?;
        contract_json(self, "announce result")
    }
}

/// The contract's activation words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShelfAction {
    CopyText,
    ShareFile,
    SaveFile,
}

impl ShelfAction {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "COPY_TEXT" => Some(Self::CopyText),
            "SHARE_FILE" => Some(Self::ShareFile),
            "SAVE_FILE" => Some(Self::SaveFile),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationStatus {
    Completed,
    Failed,
    /// The platform action may have happened. It is never replayed.
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationCode {
    Completed,
    SourceUnavailable,
    SourceChanged,
    Busy,
    Cancelled,
    ClipboardFailed,
    VerificationFailed,
    PlatformFailed,
    ForegroundLost,
    UncertainNoReplay,
    Unsupported,
    Internal,
}

/// `nativeActivate`'s result object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationReport {
    schema_version: u32,
    pub source_device: DeviceId,
    pub offer_id: OfferId,
    pub action: ShelfAction,
    pub status: ActivationStatus,
    pub code: ActivationCode,
    pub files_processed: u32,
    pub bytes_processed: u64,
    pub detail: Option<String>,
}

impl ActivationReport {
    /// Refused before anything was dispatched.
    fn refused(
        source_device: DeviceId,
        offer_id: OfferId,
        action: ShelfAction,
        code: ActivationCode,
        detail: &str,
    ) -> Self {
        Self {
            schema_version: SHELF_SCHEMA_VERSION,
            source_device,
            offer_id,
            action,
            status: ActivationStatus::Failed,
            code,
            files_processed: 0,
            bytes_processed: 0,
            detail: Some(bounded_detail(detail)),
        }
    }

    /// The end of a dispatched activation. Counts and detail come from the attempt the receiver
    /// recorded on the card for this activation, when it recorded one.
    fn settled(
        source_device: DeviceId,
        offer_id: OfferId,
        action: ShelfAction,
        result: Result<ActivationOutcome, NetError>,
        attempt: Option<OfferAttemptStatus>,
    ) -> Self {
        let (status, code, fallback) = match result {
            Ok(outcome) => {
                let (status, code) = activation_code(outcome, action);
                (status, code, outcome.desktop_status())
            }
            Err(error) => {
                let code = if matches!(error, NetError::Unavailable(_)) {
                    ActivationCode::SourceUnavailable
                } else {
                    ActivationCode::Internal
                };
                (ActivationStatus::Failed, code, error.to_string())
            }
        };
        let (files_processed, bytes_processed, recorded) =
            attempt.map_or((0, 0, None), |attempt| {
                (
                    attempt.files_processed,
                    attempt.bytes_processed,
                    attempt.detail,
                )
            });
        let detail = (status != ActivationStatus::Completed)
            .then(|| bounded_detail(&recorded.unwrap_or(fallback)));
        Self {
            schema_version: SHELF_SCHEMA_VERSION,
            source_device,
            offer_id,
            action,
            status,
            code,
            files_processed,
            bytes_processed,
            detail,
        }
    }

    /// The platform reported that the foreground was lost, or the gesture was superseded, before
    /// the action could apply. Only a platform-stage failure is reworded: an activation refused
    /// before dispatch keeps its own code, and a completed or uncertain one is never reworded.
    pub fn foreground_lost(&mut self) {
        if self.status == ActivationStatus::Failed
            && matches!(
                self.code,
                ActivationCode::ClipboardFailed | ActivationCode::PlatformFailed
            )
        {
            self.code = ActivationCode::ForegroundLost;
        }
    }

    pub fn to_json(&self) -> Result<String, PhoneError> {
        contract_json(self, "activation result")
    }
}

/// The one mapping from the network layer's typed outcome to the contract's status and code.
fn activation_code(
    outcome: ActivationOutcome,
    action: ShelfAction,
) -> (ActivationStatus, ActivationCode) {
    use ActivationCode as Code;
    let failed = |code| (ActivationStatus::Failed, code);
    match outcome {
        ActivationOutcome::Completed => (ActivationStatus::Completed, Code::Completed),
        ActivationOutcome::UncertainNoReplay => {
            (ActivationStatus::Uncertain, Code::UncertainNoReplay)
        }
        ActivationOutcome::Cancelled => failed(Code::Cancelled),
        ActivationOutcome::Refused(code) => failed(match code {
            ActivationRefuseCode::UnknownOffer
            | ActivationRefuseCode::NotAnnouncedToRequester
            | ActivationRefuseCode::SourceUnavailable => Code::SourceUnavailable,
            ActivationRefuseCode::SourceChanged => Code::SourceChanged,
            ActivationRefuseCode::Busy | ActivationRefuseCode::DuplicateActivation => Code::Busy,
            ActivationRefuseCode::Unsupported
            | ActivationRefuseCode::UnsupportedMode
            | ActivationRefuseCode::TooLarge => Code::Unsupported,
            ActivationRefuseCode::InvalidManifest => Code::VerificationFailed,
            ActivationRefuseCode::InsufficientSpace
            | ActivationRefuseCode::DestinationUnavailable
            | ActivationRefuseCode::AllocationFailed => Code::PlatformFailed,
            ActivationRefuseCode::Malformed => Code::Internal,
        }),
        ActivationOutcome::Failed(code) => failed(match code {
            ActivationFailCode::SourceUnavailable | ActivationFailCode::ConnectionLost => {
                Code::SourceUnavailable
            }
            ActivationFailCode::SourceChanged => Code::SourceChanged,
            ActivationFailCode::VerificationFailed => Code::VerificationFailed,
            ActivationFailCode::ClipboardFailed if action == ShelfAction::CopyText => {
                Code::ClipboardFailed
            }
            ActivationFailCode::ClipboardFailed | ActivationFailCode::LocalIo => {
                Code::PlatformFailed
            }
            ActivationFailCode::Protocol | ActivationFailCode::InternalError => Code::Internal,
        }),
    }
}

/// The presentation class of a card, derived from its descriptor alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardKind {
    Text,
    File,
    Photo,
    Folder,
}

impl CardKind {
    fn of(descriptor: &OfferDescriptor) -> Self {
        match descriptor {
            OfferDescriptor::Text { .. } => Self::Text,
            OfferDescriptor::File {
                content_class: FileContentClass::Photo,
                ..
            } => Self::Photo,
            OfferDescriptor::File { .. } => Self::File,
            OfferDescriptor::Folder { .. } => Self::Folder,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::File => "FILE",
            Self::Photo => "PHOTO",
            Self::Folder => "FOLDER",
        }
    }

    /// The single authority for what a ready card can do, used both for `supportedActions` and to
    /// refuse an activation. Share is the primary file action and Save the O-011 alternate, in
    /// that order. A folder has none until Android folder export exists.
    const fn actions(self) -> &'static [ShelfAction] {
        match self {
            Self::Text => &[ShelfAction::CopyText],
            Self::File | Self::Photo => &[ShelfAction::ShareFile, ShelfAction::SaveFile],
            Self::Folder => &[],
        }
    }

    const fn unsupported_detail(self) -> &'static str {
        match self {
            Self::Folder => "folder export is not available on this phone",
            Self::Text => "a text card can only be copied",
            Self::File | Self::Photo => "a file card is shared or saved, not copied",
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ShelfSnapshotJson {
    schema_version: u32,
    ready: bool,
    completeness: &'static str,
    local_display_name: String,
    cards: Vec<ShelfCardJson>,
    peer_observation: Option<PeerObservation>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ShelfCardJson {
    source_device: DeviceId,
    offer_id: OfferId,
    source_display_name: String,
    ownership: &'static str,
    kind: &'static str,
    display_name: String,
    preview: String,
    byte_length: u64,
    shelf_sequence: u64,
    availability: &'static str,
    supported_actions: &'static [ShelfAction],
    /// Always null in ABI 8: activation blocks until terminal. Reserved for a later ABI.
    active_operation: (),
    last_attempt: Option<LastAttemptJson>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LastAttemptJson {
    code: &'static str,
    attempt_sequence: u64,
    files_processed: u32,
    bytes_processed: u64,
    detail: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshResultJson {
    schema_version: u32,
    new_items: u32,
    snapshot: ShelfSnapshotJson,
}

/// Builds the contract snapshot from cards already ordered newest first. It refuses more than
/// ten cards or a repeated `(sourceDevice, offerId)` rather than serializing a shelf the contract
/// says cannot exist.
fn shelf_snapshot(
    local_device: DeviceId,
    local_display_name: &str,
    cards: &[OfferCardRecord],
    trusted_names: &HashMap<DeviceId, String>,
    peer_observation: Option<PeerObservation>,
) -> Result<ShelfSnapshotJson, PhoneError> {
    if cards.len() > V2_MAX_LIVE_ENTRIES as usize {
        return Err(PhoneError::Configuration(format!(
            "shelf snapshot has {} cards; at most {V2_MAX_LIVE_ENTRIES} may be serialized",
            cards.len()
        )));
    }
    if local_display_name.trim().is_empty() {
        return Err(PhoneError::Configuration(
            "shelf snapshot has a blank local display name".to_owned(),
        ));
    }
    if cards
        .windows(2)
        .any(|pair| pair[0].received_sequence <= pair[1].received_sequence)
    {
        return Err(PhoneError::Configuration(
            "shelf snapshot cards are not newest first by strictly descending sequence".to_owned(),
        ));
    }
    if let Some(observation) = &peer_observation {
        refuse_repeated_peers(&observation.peers)?;
    }
    let mut keys = HashSet::with_capacity(cards.len());
    if let Some(repeated) = cards
        .iter()
        .find(|card| !keys.insert((card.source_device, card.offer_id)))
    {
        return Err(PhoneError::Configuration(format!(
            "shelf snapshot repeats offer {} from one source",
            repeated.offer_id
        )));
    }
    Ok(ShelfSnapshotJson {
        schema_version: SHELF_SCHEMA_VERSION,
        ready: true,
        completeness: "COMPLETE",
        local_display_name: local_display_name.to_owned(),
        cards: cards
            .iter()
            .map(|record| shelf_card(local_device, local_display_name, trusted_names, record))
            .collect(),
        peer_observation,
    })
}

fn shelf_card(
    local_device: DeviceId,
    local_display_name: &str,
    trusted_names: &HashMap<DeviceId, String>,
    record: &OfferCardRecord,
) -> ShelfCardJson {
    let kind = CardKind::of(&record.descriptor);
    let own = record.source_device == local_device;
    let source_display_name = if own {
        local_display_name.to_owned()
    } else {
        trusted_names
            .get(&record.source_device)
            .filter(|name| !name.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| UNKNOWN_DEVICE_NAME.to_owned())
    };
    let (display_name, preview, byte_length) = match &record.descriptor {
        OfferDescriptor::Text {
            preview,
            utf8_bytes,
            ..
        } => (
            String::new(),
            truncate_utf8_preview(preview, MAX_OFFER_PREVIEW_BYTES),
            u64::from(*utf8_bytes),
        ),
        OfferDescriptor::File {
            root_name,
            total_bytes,
            ..
        }
        | OfferDescriptor::Folder {
            root_name,
            total_bytes,
            ..
        } => (root_name.clone(), String::new(), *total_bytes),
    };
    let availability = match (kind, &record.availability) {
        (CardKind::Folder, _) => "UNSUPPORTED",
        (_, CardAvailability::Available) => "READY",
        (_, CardAvailability::SourceUnavailable) => "SOURCE_OFFLINE",
        (_, CardAvailability::SourceChanged) => "SOURCE_CHANGED",
    };
    ShelfCardJson {
        source_device: record.source_device,
        offer_id: record.offer_id,
        source_display_name,
        ownership: if own { "OWN" } else { "RECEIVED" },
        kind: kind.as_str(),
        display_name,
        preview,
        byte_length,
        shelf_sequence: record.received_sequence,
        availability,
        supported_actions: if availability == "READY" {
            kind.actions()
        } else {
            &[]
        },
        active_operation: (),
        last_attempt: record.last_attempt.as_ref().map(|attempt| LastAttemptJson {
            code: attempt_code(&attempt.code),
            attempt_sequence: attempt.attempt_sequence,
            files_processed: attempt.files_processed,
            bytes_processed: attempt.bytes_processed,
            detail: attempt.detail.as_deref().map(bounded_detail),
        }),
    }
}

const fn attempt_code(code: &OfferAttemptCode) -> &'static str {
    match code {
        OfferAttemptCode::Completed => "COMPLETED",
        OfferAttemptCode::SourceUnavailable => "SOURCE_UNAVAILABLE",
        OfferAttemptCode::SourceChanged => "SOURCE_CHANGED",
        OfferAttemptCode::Busy => "BUSY",
        OfferAttemptCode::Cancelled => "CANCELLED",
        OfferAttemptCode::ClipboardFailed => "CLIPBOARD_FAILED",
        OfferAttemptCode::VerificationFailed => "VERIFICATION_FAILED",
        OfferAttemptCode::UncertainNoReplay => "UNCERTAIN_NO_REPLAY",
        OfferAttemptCode::Failed => "FAILED",
    }
}

/// Each peer appears once in an observation; the trust registry keys peers by device.
fn refuse_repeated_peers(peers: &[PeerObservationEntry]) -> Result<(), PhoneError> {
    let mut devices = HashSet::with_capacity(peers.len());
    match peers.iter().find(|peer| !devices.insert(peer.device_id)) {
        Some(repeated) => Err(PhoneError::Configuration(format!(
            "peer observation repeats peer {}",
            repeated.display_name
        ))),
        None => Ok(()),
    }
}

fn contract_json<T: serde::Serialize>(value: &T, what: &str) -> Result<String, PhoneError> {
    serde_json::to_string(value)
        .map_err(|error| PhoneError::Configuration(format!("could not serialize {what}: {error}")))
}

/// Ordinary camera photos are named like Android camera files, in UTC, so a desktop that saves one
/// gets a recognizable, time-sorted name instead of the same `final.jpg` for every photo.
fn ordinary_photo_file_name(unix_seconds: u64) -> String {
    let (year, month, day) = civil_from_days(unix_seconds / 86_400);
    let seconds = unix_seconds % 86_400;
    format!(
        "IMG_{year:04}{month:02}{day:02}_{:02}{:02}{:02}.jpg",
        seconds / 3_600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// Proleptic Gregorian `(year, month, day)` for days since 1970-01-01 (Hinnant's algorithm).
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// Details reach the Android surface (`lastAttempt.detail`, activation results), which never
/// carries filesystem paths or content URIs. A path-like token, and following tokens that continue
/// it across spaces, become `<path>`; the rest of the sentence is kept.
fn bounded_detail(detail: &str) -> String {
    truncate_utf8_preview(&scrub_paths(detail), MAX_OFFER_ATTEMPT_DETAIL_BYTES)
}

fn scrub_paths(detail: &str) -> String {
    const OPENERS: &[char] = &['"', '\'', '(', '[', '<', '`'];
    const CLOSERS: &[char] = &['"', '\'', ')', ']', '>', '`', ':', ',', ';'];
    let mut tokens: Vec<String> = Vec::new();
    // The opening punctuation of a path still being consumed across spaces.
    let mut open_path: Option<String> = None;
    for token in detail.split(' ') {
        let body = token.trim_start_matches(OPENERS);
        let lead = &token[..token.len() - body.len()];
        let core = body.trim_end_matches(CLOSERS);
        let tail = &body[core.len()..];
        let continues =
            open_path.is_some() && lead.is_empty() && (core.contains('/') || core.contains('\\'));
        if continues {
            let path_lead = open_path.take().unwrap_or_default();
            tokens.pop();
            tokens.push(format!("{path_lead}<path>{tail}"));
            open_path = tail.is_empty().then_some(path_lead);
        } else if is_path_start(core) {
            tokens.push(format!("{lead}<path>{tail}"));
            open_path = tail.is_empty().then(|| lead.to_owned());
        } else {
            tokens.push(token.to_owned());
            open_path = None;
        }
    }
    tokens.join(" ")
}

fn is_path_start(token: &str) -> bool {
    let bytes = token.as_bytes();
    token.starts_with('/')
        || token.starts_with("~/")
        || token.starts_with("\\\\")
        || token.contains("://")
        || (bytes.len() > 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

fn truncate_utf8_preview(preview: &str, max_bytes: usize) -> String {
    if preview.len() <= max_bytes {
        return preview.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !preview.is_char_boundary(end) {
        end -= 1;
    }
    preview[..end].to_owned()
}

struct ClipboardBridge(Arc<dyn FetchClipboard>);

impl ClipboardSink for ClipboardBridge {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        self.0.set_text(text)
    }
}

impl FetchClipboard for ClipboardBridge {
    fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
        self.0.set_files(paths)
    }
}

// ---------------------------------------------------------------------------------------------
// The one timer

/// The resident's only waiting loop. It sleeps until the earliest deadline already recorded in the
/// store, and is woken early only when a transition changes what that deadline is: no periodic
/// wakeup, no sweep, and nothing armed at all while the phone is idle (invariant 12).
async fn run_deadlines(resident: Arc<Resident>) {
    let mut shutdown = resident.shutdown.subscribe();
    loop {
        let now = resident.clock.now_unix_ms();
        let cleared = resident.on_deadline(now).is_ok();
        let wait = match resident.next_deadline() {
            Ok(Some(deadline)) => {
                let remaining = deadline.saturating_sub(resident.clock.now_unix_ms());
                // Zero remaining after a pass that could not clear it means a failing store.
                Some(if remaining == 0 && !cleared {
                    DEADLINE_RETRY
                } else {
                    Duration::from_millis(remaining)
                })
            }
            Ok(None) => None,
            Err(_) => Some(DEADLINE_RETRY),
        };
        tokio::select! {
            () = sleep_for(wait) => {}
            () = resident.deadline_changed.notified() => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

async fn sleep_for(wait: Option<Duration>) {
    match wait {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}

/// Which recorded instant a row owes something at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deadline {
    /// The request expires and must be withdrawn.
    Expiry,
    /// An uncertain photograph must be deleted without a recorded delivery.
    Delete,
}

/// The deadline a row owes, or `None` for one that owes none. `Claimed` deliberately owes none: a
/// transfer in flight carries its own bounds and the timer must never end it.
fn deadline_of(record: &CaptureSourceRecord) -> Option<(Deadline, u64)> {
    match &record.phase {
        CaptureSourcePhase::Presented
        | CaptureSourcePhase::Captured { .. }
        | CaptureSourcePhase::Announced { .. } => {
            Some((Deadline::Expiry, record.expires_at_unix_ms))
        }
        CaptureSourcePhase::UncertainNoReplay {
            deadline_unix_ms, ..
        } => Some((Deadline::Delete, *deadline_unix_ms)),
        CaptureSourcePhase::Claimed { .. }
        | CaptureSourcePhase::Delivered
        | CaptureSourcePhase::Terminal { .. } => None,
    }
}

/// A request the phone is still working on, including one whose photograph is being served.
fn is_live(phase: &CaptureSourcePhase) -> bool {
    matches!(
        phase,
        CaptureSourcePhase::Presented
            | CaptureSourcePhase::Captured { .. }
            | CaptureSourcePhase::Announced { .. }
            | CaptureSourcePhase::Claimed { .. }
    )
}

// ---------------------------------------------------------------------------------------------
// Vocabulary shared with Kotlin

/// How each `nativeCaptureDeclined` reason ends the request. The work order fixes this mapping:
/// only the person's own refusal is `declined`, and only a lapsed request is `expired`; every other
/// reason is a failure, so the requester learns the photograph is not coming, and why.
fn decline_terminal_code(reason: &str) -> CaptureSourceTerminalCode {
    match reason {
        "user-declined" => CaptureSourceTerminalCode::Declined,
        "expired" => CaptureSourceTerminalCode::Expired,
        _ => CaptureSourceTerminalCode::Failed,
    }
}

/// The `CaptureStatus` a finished row reports to the requester, or `None` when there is nothing to
/// report: a row that is not terminal, or one whose photograph may already have been delivered.
fn status_code(phase: &CaptureSourcePhase) -> Option<CaptureStatusCode> {
    match phase {
        CaptureSourcePhase::Terminal { code } => Some(match code {
            CaptureSourceTerminalCode::Declined => CaptureStatusCode::Declined,
            CaptureSourceTerminalCode::Expired => CaptureStatusCode::Expired,
            CaptureSourceTerminalCode::Cancelled => CaptureStatusCode::Cancelled,
            CaptureSourceTerminalCode::Failed => CaptureStatusCode::Failed,
            // The requester may hold the photograph. Reporting a failure would contradict a
            // publication it has already committed, so nothing is claimed either way.
            CaptureSourceTerminalCode::ExpiredUnconfirmed => return None,
        }),
        _ => None,
    }
}

/// The pinned `onCaptureWithdrawn` word for a row reconciliation ended.
fn withdraw_reason(phase: &CaptureSourcePhase) -> CaptureWithdrawReason {
    match phase {
        CaptureSourcePhase::Terminal {
            code: CaptureSourceTerminalCode::Expired | CaptureSourceTerminalCode::ExpiredUnconfirmed,
        } => CaptureWithdrawReason::Expired,
        CaptureSourcePhase::Terminal {
            code: CaptureSourceTerminalCode::Cancelled,
        } => CaptureWithdrawReason::Cancelled,
        _ => CaptureWithdrawReason::Failed,
    }
}

// ---------------------------------------------------------------------------------------------
// The photograph Kotlin handed over

/// Verifies the file the camera wrote and builds the durable record of it. Every check refuses to
/// trust the arguments: the path must name a real regular file with no symbolic link in it, it
/// must lie inside `root`, the directory the phone's own camera writes into, the bytes must hash
/// to what was declared, and the size must be within the store's bound.
///
/// Containment is what makes the rest of the checks the phone's own rules rather than the calling
/// code's. Without it any canonical regular file on the device that this process can read could be
/// hashed, announced and served — the caller would be the only thing deciding which, and the
/// caller is a JNI export reachable by anything running in the app process.
fn parse_sha256_hex(hex: &str) -> Result<[u8; 32], PhoneError> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PhoneError::InvalidPhoto(
            "photograph sha256 must be 64 hex characters".to_owned(),
        ));
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| PhoneError::InvalidPhoto("photograph sha256 must be hex".to_owned()))?;
        out[index] = u8::from_str_radix(text, 16)
            .map_err(|_| PhoneError::InvalidPhoto("photograph sha256 must be hex".to_owned()))?;
    }
    Ok(out)
}

fn verified_photo(
    path: &Path,
    root: &Path,
    sha256: [u8; 32],
    width: u32,
    height: u32,
    now: u64,
) -> Result<CapturedPhoto, PhoneError> {
    let invalid = PhoneError::InvalidPhoto;
    if width == 0 || height == 0 {
        return Err(invalid(
            "photograph width and height must be positive".to_owned(),
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        invalid(format!(
            "photograph {} cannot be read: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(invalid(format!(
            "photograph {} is not a regular file",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        invalid(format!(
            "photograph {} cannot be resolved: {error}",
            path.display()
        ))
    })?;
    if canonical != path {
        return Err(invalid(format!(
            "photograph path {} is not canonical",
            path.display()
        )));
    }
    let canonical_root = std::fs::canonicalize(root).map_err(|error| {
        invalid(format!(
            "the captured-photograph directory {} cannot be resolved: {error}",
            root.display()
        ))
    })?;
    if !canonical.starts_with(&canonical_root) || canonical == canonical_root {
        return Err(invalid(format!(
            "photograph {} is outside the captured-photograph directory {}",
            canonical.display(),
            canonical_root.display()
        )));
    }
    let bytes = metadata.len();
    if bytes == 0 {
        return Err(invalid("photograph is empty".to_owned()));
    }
    if bytes > MAX_CAPTURE_PHOTO_BYTES {
        return Err(invalid(format!(
            "photograph is {bytes} bytes; the maximum is {MAX_CAPTURE_PHOTO_BYTES}"
        )));
    }
    let measured = hash_file(path).map_err(|error| {
        invalid(format!(
            "photograph {} cannot be hashed: {error}",
            path.display()
        ))
    })?;
    if measured != sha256 {
        return Err(invalid(
            "photograph does not hash to the value the camera reported".to_owned(),
        ));
    }
    let root_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid("photograph path has no usable file name".to_owned()))?
        .to_owned();
    Ok(CapturedPhoto {
        offer_id: OfferId::new(),
        descriptor: OfferDescriptor::File {
            root_name,
            total_bytes: bytes,
            content_class: meshelf_core::FileContentClass::File,
        },
        path: path.to_path_buf(),
        sha256,
        width,
        height,
        delete_deadline_unix_ms: now.saturating_add(CAPTURE_PHOTO_DELETE_AFTER_MS),
    })
}

fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut block = vec![0_u8; HASH_BLOCK_BYTES];
    loop {
        let read = file.read(&mut block)?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    Ok(hasher.finalize().into())
}

fn photograph_path(phase: &CaptureSourcePhase) -> Option<&Path> {
    match phase {
        CaptureSourcePhase::Captured { photo }
        | CaptureSourcePhase::Announced { photo }
        | CaptureSourcePhase::Claimed { photo, .. } => Some(photo.path.as_path()),
        CaptureSourcePhase::UncertainNoReplay { path, .. } => Some(path.as_path()),
        CaptureSourcePhase::Presented
        | CaptureSourcePhase::Delivered
        | CaptureSourcePhase::Terminal { .. } => None,
    }
}

/// Deletes `path` only when it resolves under `photo_root`. Missing files are success; anything
/// outside the root is a recorded failure and is left untouched.
fn delete_photograph_under_root(path: &Path, photo_root: &Path) -> Result<(), String> {
    let canonical = match std::fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "photograph {} could not be resolved for deletion: {error}",
                path.display()
            ));
        }
    };
    let root = std::fs::canonicalize(photo_root).map_err(|error| {
        format!(
            "photograph root {} could not be resolved for deletion: {error}",
            photo_root.display()
        )
    })?;
    if !canonical.starts_with(&root) || canonical == root {
        return Err(format!(
            "refused to delete {} outside photograph root {}",
            canonical.display(),
            root.display()
        ));
    }
    match std::fs::remove_file(&canonical) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "photograph {} could not be deleted: {error}",
            canonical.display()
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Receivers
//
// `V2CaptureReceiver` is declared with `#[async_trait]`. This crate does not depend on
// `async-trait` and its manifest is owned by another worker this phase, so the capture
// implementations below are written in the form that attribute expands to. Offer announcements
// use [`OfferAnnouncementHandler`] from meshelf-net (async_trait there).

/// Names the requester from its paired record, never from the name it sends. A hello's
/// `device_name` is peer-supplied text; the label the person reads while deciding whether to
/// photograph something must come from the record a pairing wrote.
struct PairedLabelCaptureReceiver {
    inner: PhoneCaptureReceiver,
    trust: InstallationStore,
    local_device: DeviceId,
}

impl PairedLabelCaptureReceiver {
    /// The stored hostname, or `None` when this device has no record. Trimming it to the 128-byte
    /// label limit on a character boundary is the capture receiver's own rule, applied there.
    fn paired_hostname(&self, device: DeviceId) -> Option<String> {
        self.trust
            .load_for_identity(self.local_device)
            .ok()?
            .peers
            .by_device_id(device)
            .map(|peer| peer.hostname.clone())
    }
}

impl V2CaptureReceiver for PairedLabelCaptureReceiver {
    fn handle_capture_request<'life0, 'life1, 'async_trait>(
        &'life0 self,
        authenticated_source: DeviceId,
        _hello_name: &'life1 str,
        listener_device: DeviceId,
        request: CaptureRequest,
    ) -> Pin<Box<dyn Future<Output = Result<CaptureAck, NetError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let Some(hostname) = self.paired_hostname(authenticated_source) else {
                return Ok(CaptureAck {
                    request_id: request.request_id,
                    code: CaptureAckCode::Refused,
                    detail: Some("requester_not_paired".to_owned()),
                });
            };
            self.inner
                .handle_capture_request(authenticated_source, &hostname, listener_device, request)
                .await
        })
    }

    fn handle_capture_status<'life0, 'async_trait>(
        &'life0 self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        status: CaptureStatus,
    ) -> Pin<Box<dyn Future<Output = Result<CaptureStatus, NetError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.inner
                .handle_capture_status(authenticated_source, listener_device, status)
                .await
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Event adapters

/// Bridges the network layer's capture events onto the one [`PhoneEvents`] seam, and wakes the
/// deadline timer. These are the only points at which an inbound connection changes which instant
/// the resident is waiting for, so without the wake a request that arrived over the network would
/// have no expiry armed and the timer would sleep past it.
struct CaptureEvents {
    events: Arc<dyn PhoneEvents>,
    deadlines: Arc<Notify>,
}

impl CaptureSourceEvents for CaptureEvents {
    fn capture_presented(&self, record: &CaptureSourceRecord) -> Result<(), CaptureEventRefused> {
        let accepted = self.events.capture_requested(record);
        self.deadlines.notify_one();
        accepted
    }

    fn capture_delivered(&self, request_id: CaptureRequestId) {
        self.events.capture_delivered(request_id);
        self.deadlines.notify_one();
    }

    fn capture_withdrawn(&self, request_id: CaptureRequestId, reason: CaptureWithdrawReason) {
        self.events.capture_withdrawn(request_id, reason);
        self.deadlines.notify_one();
    }
}

/// The phone's fetch sources, wrapped so that every transition serving a photograph makes wakes
/// the deadline timer.
///
/// [`CaptureEvents`] covers only the three transitions that have a user-interface event:
/// presentation, delivery and withdrawal. Serving a photograph also moves a row
/// `Announced -> Claimed` and, when the receipt is lost, `Claimed -> UncertainNoReplay`, and
/// neither of those tells the person anything, so neither has an event. Both change which instant
/// the timer owes something at, and the second one is the dangerous one: a `Claimed` row owes no
/// deadline at all, so the timer is parked on nothing when the uncertain row is written, and
/// without a wake here it would stay parked and the photograph would be kept forever instead of
/// until its delete deadline (invariant 10, A19).
///
/// Wrapping the resolver is what makes that hold for every route rather than for the routes
/// someone remembered: `OfferFetchHandler` reaches these transitions only through the
/// [`FetchSourceResolver`] the resident hands it, so there is no path into them that misses this
/// wake. The wake is unconditional, including on the error paths, because the store may have
/// committed the transition before the call returned; a spurious wake costs one recomputation of
/// a deadline the store already holds.
struct WakingCaptureSources {
    inner: CaptureSourceResolver,
    deadlines: Arc<Notify>,
    photo_root: PathBuf,
}

impl WakingCaptureSources {
    fn woken<T>(&self, outcome: T) -> T {
        self.deadlines.notify_one();
        outcome
    }

    fn delete_held_photograph(&self, phase: &CaptureSourcePhase) {
        if let Some(path) = photograph_path(phase) {
            let _ = delete_photograph_under_root(path, &self.photo_root);
        }
    }
}

impl FetchSourceResolver for WakingCaptureSources {
    /// A lookup, not a transition: nothing to wake for.
    fn resolve(&self, offer_id: OfferId) -> Result<Option<FetchableSource>, StoreError> {
        self.inner.resolve(offer_id)
    }

    fn claim_capture(
        &self,
        offer_id: OfferId,
        requester: DeviceId,
        activation_id: ActivationId,
    ) -> Result<CaptureSourceClaim, StoreError> {
        self.woken(self.inner.claim_capture(offer_id, requester, activation_id))
    }

    fn capture_delivered(
        &self,
        claimed: &CaptureSourceRecord,
        activation_id: ActivationId,
        files_received: u32,
        bytes_received: u64,
    ) -> Result<bool, StoreError> {
        let delivered =
            self.inner
                .capture_delivered(claimed, activation_id, files_received, bytes_received)?;
        if delivered {
            self.delete_held_photograph(&claimed.phase);
        }
        self.woken(Ok(delivered))
    }

    fn capture_failed(&self, claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        let outcome = self.inner.capture_failed(claimed);
        if outcome.is_ok() {
            self.delete_held_photograph(&claimed.phase);
        }
        self.woken(outcome)
    }

    fn capture_uncertain(&self, claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        self.woken(self.inner.capture_uncertain(claimed))
    }
}

/// Bridges pairing events onto the same seam, and turns a completed pairing into the peer-admitted
/// callback by reading the name from the record the pairing just wrote, never from the hello.
struct PairingReports {
    events: Arc<dyn PhoneEvents>,
    trust: InstallationStore,
    local_device: DeviceId,
}

impl PairingReports {
    fn admitted_name(&self, pairing_id: PairingId) -> Option<String> {
        self.trust
            .load_for_identity(self.local_device)
            .ok()?
            .peers
            .peers()
            .iter()
            .find(|peer| {
                peer.pairing()
                    .is_some_and(|evidence| evidence.pairing_id == pairing_id)
            })
            .map(|peer| peer.hostname.clone())
    }
}

impl PairingEvents for PairingReports {
    fn on_candidate(&self, candidate: &PairingCandidate) {
        self.events.pairing_candidate(candidate);
    }

    fn on_finished(&self, pairing_id: PairingId, result: PairingResult) {
        if result == PairingResult::Paired
            && let Some(name) = self.admitted_name(pairing_id)
        {
            self.events.peer_admitted(&name);
        }
        self.events.pairing_finished(pairing_id, result);
    }
}

// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
        sync::atomic::{AtomicBool, AtomicI64},
        time::{SystemTime, UNIX_EPOCH},
    };

    use meshelf_core::{ActivationId, CardAvailability, OfferCardInput};
    use meshelf_net::{
        DocumentSourceProvider, ExactDeviceAllowList, PHONE_HELLO_READ_LIMIT,
        V2AnnouncementReceiver,
    };
    use meshelf_protocol::{CAP_PAIRING_V1, OfferAck, pairing};
    use meshelf_store::{CapturePresentation, CaptureRequestInsert, CaptureSourceClaim};
    use meshelf_tailscale::{ApprovedPending, PairedPeer, PeerNetworkBinding};
    use tempfile::TempDir;

    use super::*;

    const LIFETIME_MS: u64 = 120_000;
    const PURPOSE: &str = "Photograph the router label";

    // --- doubles ----------------------------------------------------------------------------

    /// Wall-clock time the test can move, so expiries and pairing deadlines are decided rather
    /// than waited for.
    #[derive(Default)]
    struct TestClock {
        offset_ms: AtomicI64,
    }

    impl TestClock {
        fn advance(&self, ms: i64) {
            self.offset_ms.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl PairingClock for TestClock {
        fn now_unix_ms(&self) -> u64 {
            let base = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(0));
            base.saturating_add_signed(self.offset_ms.load(Ordering::SeqCst))
        }
    }

    /// The phone's user interface, recorded. Standing in for the bridge's callback queue.
    #[derive(Default)]
    struct Recorder {
        refuse_presentation: AtomicBool,
        presented: Mutex<Vec<CaptureSourceRecord>>,
        withdrawn: Mutex<Vec<(CaptureRequestId, CaptureWithdrawReason)>>,
        delivered: Mutex<Vec<CaptureRequestId>>,
        admitted: Mutex<Vec<String>>,
        candidates: Mutex<Vec<PairingId>>,
        finished: Mutex<Vec<(PairingId, PairingResult)>>,
        shelf_changes: std::sync::atomic::AtomicUsize,
    }

    impl Recorder {
        fn labels(&self) -> Vec<String> {
            self.presented
                .lock()
                .expect("presented")
                .iter()
                .map(|record| record.requester_label.clone())
                .collect()
        }

        fn presented_ids(&self) -> Vec<CaptureRequestId> {
            self.presented
                .lock()
                .expect("presented")
                .iter()
                .map(|record| record.request_id)
                .collect()
        }

        fn withdrawals(&self) -> Vec<(CaptureRequestId, CaptureWithdrawReason)> {
            self.withdrawn.lock().expect("withdrawn").clone()
        }
    }

    impl PhoneEvents for Recorder {
        fn capture_requested(
            &self,
            record: &CaptureSourceRecord,
        ) -> Result<(), CaptureEventRefused> {
            self.presented
                .lock()
                .expect("presented")
                .push(record.clone());
            if self.refuse_presentation.load(Ordering::SeqCst) {
                return Err(CaptureEventRefused("notifications are disabled".to_owned()));
            }
            Ok(())
        }

        fn capture_withdrawn(&self, request_id: CaptureRequestId, reason: CaptureWithdrawReason) {
            self.withdrawn
                .lock()
                .expect("withdrawn")
                .push((request_id, reason));
        }

        fn capture_delivered(&self, request_id: CaptureRequestId) {
            self.delivered.lock().expect("delivered").push(request_id);
        }

        fn peer_admitted(&self, device_name: &str) {
            self.admitted
                .lock()
                .expect("admitted")
                .push(device_name.to_owned());
        }

        fn pairing_candidate(&self, candidate: &PairingCandidate) {
            self.candidates
                .lock()
                .expect("candidates")
                .push(candidate.pairing_id);
        }

        fn pairing_finished(&self, pairing_id: PairingId, result: PairingResult) {
            self.finished
                .lock()
                .expect("finished")
                .push((pairing_id, result));
        }

        fn shelf_changed(&self) {
            self.shelf_changes.fetch_add(1, Ordering::SeqCst);
        }
    }

    // --- fixtures ---------------------------------------------------------------------------

    struct Phone {
        _directory: TempDir,
        /// Where the phone's camera writes, standing in for `CaptureFiles.root(cacheDir)`.
        photo_root: PathBuf,
        resident: PhoneResident,
        events: Arc<Recorder>,
        clock: Arc<TestClock>,
        identity: InstallationIdentity,
    }

    fn phone() -> Phone {
        phone_with_connector(None)
    }

    fn phone_with_connector(connector: Option<Arc<dyn SocketConnector>>) -> Phone {
        phone_with(connector, None)
    }

    fn phone_with_documents(documents: Arc<dyn meshelf_net::DocumentSourceProvider>) -> Phone {
        phone_with(None, Some(documents))
    }

    fn phone_with(
        connector: Option<Arc<dyn SocketConnector>>,
        documents: Option<Arc<dyn meshelf_net::DocumentSourceProvider>>,
    ) -> Phone {
        let directory = tempfile::tempdir().expect("temporary directory");
        // Canonical, because a photograph's path is required to be canonical and some temporary
        // directories reach the same files through a symbolic link.
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical temporary directory");
        // Two trees, as on the phone: meshelf's own state in the app's files directory, and the
        // camera's output in the app cache.
        let state_dir = root.join("state");
        let photo_root = root.join("cache").join("agent-captures");
        std::fs::create_dir_all(&state_dir).expect("state directory");
        std::fs::create_dir_all(&photo_root).expect("photograph directory");
        let identity = InstallationIdentity::generate();
        let events = Arc::new(Recorder::default());
        let clock = Arc::new(TestClock::default());
        let resident = PhoneResident::new(PhoneResidentConfig {
            identity: identity.clone(),
            device_name: "amber".to_owned(),
            state_dir: state_dir.clone(),
            photo_root: photo_root.clone(),
            events: Arc::clone(&events) as Arc<dyn PhoneEvents>,
            runtime: tokio::runtime::Handle::current(),
            connector,
            clock: Arc::clone(&clock) as Arc<dyn PairingClock>,
            documents,
        })
        .expect("phone resident");
        Phone {
            _directory: directory,
            photo_root,
            resident,
            events,
            clock,
            identity,
        }
    }

    impl Phone {
        fn inner(&self) -> &Arc<Resident> {
            &self.resident.inner
        }

        fn store(&self) -> &Arc<RedbV2Store> {
            &self.resident.inner.store
        }

        fn local(&self) -> DeviceId {
            self.identity.device_id
        }

        fn now(&self) -> u64 {
            self.clock.now_unix_ms()
        }

        fn phase(&self, request_id: CaptureRequestId) -> CaptureSourcePhase {
            self.store()
                .get_capture_source(request_id)
                .expect("read")
                .expect("row")
                .phase
        }

        /// Writes the trust record a completed pairing would have written.
        fn pair(
            &self,
            device_id: DeviceId,
            public_key: [u8; 32],
            hostname: &str,
            address: IpAddr,
            pairing_id: PairingId,
        ) {
            let now = self.now();
            self.inner()
                .trust
                .update(self.local(), |state| {
                    state.peers.record_paired(
                        PairedPeer {
                            peer: pairing::PairedPeer {
                                device_id,
                                public_key,
                                device_name: hostname.to_owned(),
                                pairing_id,
                                transcript_hash: transcript(0x11),
                            },
                            binding: PeerNetworkBinding::ObservedTailscaleAddress { address },
                            expires_at_unix_ms: now + LIFETIME_MS,
                        },
                        now,
                        None,
                    )
                })
                .expect("record paired peer");
        }

        fn request(&self, requester: DeviceId) -> CaptureRequest {
            let now = self.now();
            CaptureRequest::photo(
                CaptureRequestId::new(),
                requester,
                self.local(),
                now,
                now + LIFETIME_MS,
                PURPOSE,
            )
        }

        /// Inserts a presented row directly, for fixtures the network path cannot produce (an
        /// already expired request, a captured one, a claimed one).
        fn present_row(
            &self,
            requester: DeviceId,
            created_at_unix_ms: u64,
            expires_at_unix_ms: u64,
        ) -> CaptureSourceRecord {
            let record = CaptureSourceRecord {
                request_id: CaptureRequestId::new(),
                requester,
                requester_label: "CEDAR".to_owned(),
                purpose: PURPOSE.to_owned(),
                lens: None,
                created_at_unix_ms,
                expires_at_unix_ms,
                phase: CaptureSourcePhase::Presented,
            };
            match self.store().present_capture(record).expect("present") {
                CapturePresentation::Presented { record, .. } => record,
                other => panic!("unexpected presentation {other:?}"),
            }
        }

        fn photo(&self, name: &str, bytes: &[u8]) -> (PathBuf, [u8; 32]) {
            let path = self.photo_root.join(name);
            std::fs::write(&path, bytes).expect("write photograph");
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            (path, hasher.finalize().into())
        }

        /// The fetch sources the listener serves photographs from, built by the resident's own
        /// constructor, so a test drives the production wiring rather than a copy of it.
        fn capture_sources(&self) -> Arc<dyn FetchSourceResolver> {
            let events: Arc<dyn CaptureSourceEvents> = Arc::new(CaptureEvents {
                events: Arc::clone(&self.events) as Arc<dyn PhoneEvents>,
                deadlines: Arc::clone(&self.inner().deadline_changed),
            });
            self.inner().capture_sources(events)
        }

        /// Takes a request to a photograph being fetched, by the route the network layer takes:
        /// attached, announced, then claimed through the resolver the listener serves from.
        fn claimed(
            &self,
            requester: DeviceId,
            name: &str,
        ) -> (CaptureRequestId, CaptureSourceRecord) {
            let now = self.now();
            let record = self.present_row(requester, now, now + LIFETIME_MS);
            let (path, sha256) = self.photo(name, b"a plausible jpeg body");
            let photo =
                verified_photo(&path, &self.photo_root, sha256, 12, 12, now).expect("photograph");
            let offer_id = photo.offer_id;
            self.store()
                .attach_captured(record.request_id, photo)
                .expect("attached");
            self.store()
                .mark_capture_announced(record.request_id)
                .expect("announced");
            let claim = self
                .capture_sources()
                .claim_capture(offer_id, requester, ActivationId::new())
                .expect("claim");
            let CaptureSourceClaim::Claimed(claimed) = claim else {
                panic!("an announced photograph must be claimable: {claim:?}");
            };
            (record.request_id, *claimed)
        }
    }

    // --- a desktop peer, in process ---------------------------------------------------------

    /// Answers announcements with one chosen acknowledgement and records what it was sent.
    struct AnsweringAnnouncements {
        code: OfferAckCode,
        detail: Option<&'static str>,
        seen: Arc<Mutex<Vec<OfferAnnouncement>>>,
    }

    impl V2AnnouncementReceiver for AnsweringAnnouncements {
        fn handle_announcement<'life0, 'async_trait>(
            &'life0 self,
            _authenticated_source: DeviceId,
            _listener_device: DeviceId,
            announcement: OfferAnnouncement,
        ) -> Pin<Box<dyn Future<Output = Result<OfferAck, NetError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let ack = OfferAck {
                    offer_id: announcement.offer_id,
                    code: self.code.clone(),
                    live_entries: 0,
                    max_live_entries: V2_MAX_LIVE_ENTRIES,
                    pruned_entries: 0,
                    detail: self.detail.map(str::to_owned),
                };
                self.seen.lock().expect("announcements").push(announcement);
                Ok(ack)
            })
        }
    }

    /// Records the capture statuses the phone reports and echoes each one back, which is how a
    /// requester acknowledges a status it has durably recorded.
    struct RecordingStatuses {
        seen: Arc<Mutex<Vec<CaptureStatus>>>,
    }

    impl V2CaptureReceiver for RecordingStatuses {
        fn handle_capture_request<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _authenticated_source: DeviceId,
            _hello_name: &'life1 str,
            _listener_device: DeviceId,
            request: CaptureRequest,
        ) -> Pin<Box<dyn Future<Output = Result<CaptureAck, NetError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                Ok(CaptureAck {
                    request_id: request.request_id,
                    code: CaptureAckCode::Unsupported,
                    detail: Some("a desktop takes no photographs".to_owned()),
                })
            })
        }

        fn handle_capture_status<'life0, 'async_trait>(
            &'life0 self,
            _authenticated_source: DeviceId,
            _listener_device: DeviceId,
            status: CaptureStatus,
        ) -> Pin<Box<dyn Future<Output = Result<CaptureStatus, NetError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                self.seen.lock().expect("statuses").push(status.clone());
                Ok(status)
            })
        }
    }

    /// This peer serves nothing; it only receives.
    struct NoFetchSources;

    impl FetchSourceResolver for NoFetchSources {
        fn resolve(&self, _offer_id: OfferId) -> Result<Option<FetchableSource>, StoreError> {
            Ok(None)
        }
    }

    /// Sends every outbound connection to one real listener, and records the address the resident
    /// asked for, so a test can pin that the phone dials its paired peer rather than anything it
    /// was told. It stands where the Android binder stands, which is the production seam for
    /// choosing the socket.
    struct RedirectConnector {
        to: SocketAddr,
        dialed: Mutex<Vec<SocketAddr>>,
    }

    impl SocketConnector for RedirectConnector {
        fn connect<'life0, 'async_trait>(
            &'life0 self,
            address: SocketAddr,
        ) -> Pin<
            Box<dyn Future<Output = std::io::Result<tokio::net::TcpStream>> + Send + 'async_trait>,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            self.dialed.lock().expect("dialed").push(address);
            let to = self.to;
            Box::pin(async move { tokio::net::TcpStream::connect(to).await })
        }
    }

    /// A desktop peer inside the test process: a real protocol-2 listener the phone reaches
    /// through the production [`PeerClient`], so the announcement and the capture status are
    /// signed, framed, pinned to a key and answered exactly as they are on a tailnet.
    struct MockDesktop {
        identity: InstallationIdentity,
        announcements: Arc<Mutex<Vec<OfferAnnouncement>>>,
        statuses: Arc<Mutex<Vec<CaptureStatus>>>,
        _shutdown: watch::Sender<bool>,
    }

    impl MockDesktop {
        fn requester(&self) -> DeviceId {
            self.identity.device_id
        }

        fn announcements(&self) -> Vec<OfferAnnouncement> {
            self.announcements.lock().expect("announcements").clone()
        }

        fn statuses(&self) -> Vec<CaptureStatus> {
            self.statuses.lock().expect("statuses").clone()
        }
    }

    /// A phone paired with a desktop peer that answers every announcement with `code`.
    ///
    /// The listener is bound first so the phone can be built with a connector pointing at it, and
    /// serving starts last so the desktop admits exactly this phone's device id.
    async fn paired_phone_and_desktop(
        code: OfferAckCode,
        detail: Option<&'static str>,
    ) -> (Phone, MockDesktop, Arc<RedirectConnector>) {
        let identity = InstallationIdentity::generate();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mock desktop");
        let address = listener.local_addr().expect("mock desktop address");
        let connector = Arc::new(RedirectConnector {
            to: address,
            dialed: Mutex::new(Vec::new()),
        });
        let phone = phone_with_connector(Some(Arc::clone(&connector) as Arc<dyn SocketConnector>));
        phone.pair(
            identity.device_id,
            identity.public_key(),
            "CEDAR-desk",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x20),
        );
        let announcements = Arc::new(Mutex::new(Vec::new()));
        let statuses = Arc::new(Mutex::new(Vec::new()));
        let config = V2ServerConfig {
            capture_receiver: Arc::new(RecordingStatuses {
                seen: Arc::clone(&statuses),
            }),
            ..V2ServerConfig::desktop(
                ServerIdentity {
                    signing_identity: identity.clone(),
                    device_name: "CEDAR-desk".to_owned(),
                },
                Arc::new(ExactDeviceAllowList::new([phone.local()])),
                V2OfferServices {
                    announcement_receiver: Arc::new(AnsweringAnnouncements {
                        code,
                        detail,
                        seen: Arc::clone(&announcements),
                    }),
                    fetch_sender: Arc::new(OfferFetchHandler::with_resolver(
                        identity.device_id,
                        Arc::new(NoFetchSources),
                    )),
                },
                Duration::from_secs(5),
            )
        };
        let (shutdown, stop) = watch::channel(false);
        tokio::spawn(async move {
            let _ = serve_v2(listener, config, stop).await;
        });
        let desktop = MockDesktop {
            identity,
            announcements,
            statuses,
            _shutdown: shutdown,
        };
        (phone, desktop, connector)
    }

    fn pairing_id(byte: u8) -> PairingId {
        PairingId::from_str(&format!("{byte:02x}").repeat(16)).expect("pairing id")
    }

    fn transcript(byte: u8) -> TranscriptHash {
        TranscriptHash::from_str(&format!("{byte:02x}").repeat(32)).expect("transcript hash")
    }

    fn photo_of(phase: &CaptureSourcePhase) -> Option<&CapturedPhoto> {
        match phase {
            CaptureSourcePhase::Captured { photo }
            | CaptureSourcePhase::Announced { photo }
            | CaptureSourcePhase::Claimed { photo, .. } => Some(photo),
            _ => None,
        }
    }

    /// Waits for a background task to reach an observable state, rather than guessing a sleep.
    async fn until<T>(mut ready: impl FnMut() -> Option<T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(value) = ready() {
                    return value;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("background work finished within ten seconds")
    }

    // --- the requester's label --------------------------------------------------------------

    #[tokio::test]
    async fn the_requester_is_named_by_its_paired_record_and_never_by_the_name_it_sends() {
        // The label is what the person reads while deciding whether to photograph something, so it
        // must come from the record a pairing wrote. A hello's device_name is peer-supplied text
        // and an admitted peer could claim to be any other peer by sending its name.
        let phone = phone();
        let requester = DeviceId::new();
        phone.pair(
            requester,
            [7_u8; 32],
            "CEDAR-desk",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x01),
        );
        let config = phone.inner().server_config();
        let ack = config
            .capture_receiver
            .handle_capture_request(
                requester,
                "FERN (not this peer)",
                phone.local(),
                phone.request(requester),
            )
            .await
            .expect("acknowledgement");

        assert_eq!(ack.code, CaptureAckCode::Presented);
        assert_eq!(phone.events.labels(), vec!["CEDAR-desk".to_owned()]);
    }

    #[tokio::test]
    async fn a_requester_with_no_paired_record_is_refused_rather_than_named_from_its_hello() {
        // Reaching the listener is not being paired. Falling back to the hello's name here would
        // present an unpaired device to the person under any name it chose.
        let phone = phone();
        let requester = DeviceId::new();
        let request = phone.request(requester);
        let config = phone.inner().server_config();
        let ack = config
            .capture_receiver
            .handle_capture_request(requester, "CEDAR-desk", phone.local(), request.clone())
            .await
            .expect("acknowledgement");

        assert_eq!(ack.code, CaptureAckCode::Refused);
        assert_eq!(ack.detail.as_deref(), Some("requester_not_paired"));
        assert!(phone.events.presented_ids().is_empty());
        assert!(
            phone
                .store()
                .get_capture_source(request.request_id)
                .expect("read")
                .is_none(),
            "an unpaired request must leave no row"
        );
    }

    #[tokio::test]
    async fn a_hostname_longer_than_the_label_limit_is_cut_on_a_character_boundary() {
        // Kotlin shows at most 128 bytes. Cutting by bytes alone would split a multi-byte
        // character and produce a label that is not text at all, which the validator then refuses,
        // so a peer with an accented hostname could never request a photograph.
        let phone = phone();
        let requester = DeviceId::new();
        let hostname = "é".repeat(100);
        phone.pair(
            requester,
            [9_u8; 32],
            &hostname,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x02),
        );
        let config = phone.inner().server_config();
        let ack = config
            .capture_receiver
            .handle_capture_request(
                requester,
                "ignored",
                phone.local(),
                phone.request(requester),
            )
            .await
            .expect("acknowledgement");

        assert_eq!(ack.code, CaptureAckCode::Presented);
        let label = phone.events.labels().pop().expect("one label");
        assert_eq!(label, "é".repeat(64), "128 bytes is exactly 64 of these");
        assert!(label.len() <= 128);
        assert!(hostname.starts_with(&label));
    }

    // --- invariant 11 -----------------------------------------------------------------------

    #[tokio::test]
    async fn presented_is_acknowledged_only_when_the_user_interface_accepted_the_event() {
        // Durable before acknowledgement means both halves: the row and the callback. A phone that
        // cannot show the request has not presented it, and saying otherwise would leave the
        // requester waiting through the whole expiry for a notification nobody ever saw.
        let phone = phone();
        let requester = DeviceId::new();
        phone.pair(
            requester,
            [3_u8; 32],
            "CEDAR-desk",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x03),
        );
        phone
            .events
            .refuse_presentation
            .store(true, Ordering::SeqCst);
        let request = phone.request(requester);
        let config = phone.inner().server_config();
        let ack = config
            .capture_receiver
            .handle_capture_request(requester, "ignored", phone.local(), request.clone())
            .await
            .expect("acknowledgement");

        assert_eq!(ack.code, CaptureAckCode::Refused);
        assert_eq!(ack.detail.as_deref(), Some("presentation_unavailable"));
        assert_eq!(
            phone.phase(request.request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            },
            "a request nobody saw must end, not hold the phone busy until it expires"
        );
    }

    // --- ordinary shelf cards (O-026) -------------------------------------------------------

    #[tokio::test]
    async fn an_ordinary_offer_announcement_is_stored_on_the_phone_shelf() {
        let phone = phone();
        let source = DeviceId::new();
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            source,
            phone.local(),
            phone.now(),
            OfferDescriptor::text("hello").expect("text descriptor"),
        );
        let config = phone.inner().server_config();
        let ack = config
            .services
            .announcement_receiver
            .handle_announcement(source, phone.local(), announcement.clone())
            .await
            .expect("acknowledgement");

        assert_eq!(ack.code, OfferAckCode::Stored);
        assert_eq!(ack.live_entries, 1);
        let cards = phone.inner().store.read_offer_shelf().expect("shelf");
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].offer_id, announcement.offer_id);
        assert_eq!(cards[0].source_device, source);
        assert_eq!(
            phone.events.shelf_changes.load(Ordering::SeqCst),
            1,
            "an open shelf must redraw when an item arrives, not wait for Refresh"
        );

        let again = config
            .services
            .announcement_receiver
            .handle_announcement(source, phone.local(), announcement)
            .await
            .expect("repeat acknowledgement");
        assert_ne!(again.code, OfferAckCode::Stored);
        assert_eq!(
            phone.events.shelf_changes.load(Ordering::SeqCst),
            1,
            "a repeat delivery stores nothing new and must not redraw"
        );
    }

    #[tokio::test]
    async fn shelf_snapshot_json_returns_a_text_card_after_insert() {
        let phone = phone();
        let source = DeviceId::new();
        let offer_id = OfferId::new();
        phone
            .store()
            .insert_offer_card(OfferCardInput::new(
                source,
                offer_id,
                OfferDescriptor::text("hello shelf").expect("text descriptor"),
                CardAvailability::Available,
            ))
            .expect("insert card");
        let json = phone
            .resident
            .shelf_snapshot_json()
            .expect("shelf snapshot json");
        let snapshot: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(snapshot["schemaVersion"], 2);
        assert_eq!(snapshot["ready"], true);
        assert_eq!(snapshot["completeness"], "COMPLETE");
        let cards = snapshot["cards"].as_array().expect("cards array");
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0]["sourceDevice"], source.to_string());
        assert_eq!(cards[0]["offerId"], offer_id.to_string());
        assert_eq!(cards[0]["kind"], "TEXT");
        assert_eq!(cards[0]["availability"], "READY");
        assert_eq!(cards[0]["preview"], "hello shelf");
        assert_eq!(cards[0]["byteLength"], 11);
    }

    #[tokio::test]
    async fn ordinary_photo_reserve_abandon_removes_uncommitted_paths() {
        let phone = phone();
        let json = phone
            .resident
            .reserve_ordinary_photo("action-1")
            .expect("reserve");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        let lease_id = value["leaseId"].as_str().expect("leaseId").to_owned();
        let raw = PathBuf::from(value["rawPath"].as_str().expect("rawPath"));
        let final_path = PathBuf::from(value["finalPath"].as_str().expect("finalPath"));
        assert!(!raw.exists());
        assert!(!final_path.exists());
        assert!(raw.parent().expect("parent").is_dir());
        phone
            .resident
            .abandon_ordinary_photo(&lease_id)
            .expect("abandon");
        assert!(!raw.parent().expect("parent").exists() || !final_path.exists());
    }

    #[tokio::test]
    async fn ordinary_photo_commit_stores_an_offer_source_and_marks_lease_committed() {
        let phone = phone();
        let peer = DeviceId::new();
        phone.pair(
            peer,
            [0x44_u8; 32],
            "CEDAR",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x44),
        );
        let json = phone
            .resident
            .reserve_ordinary_photo("action-2")
            .expect("reserve");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        let lease_id = value["leaseId"].as_str().expect("leaseId").to_owned();
        let final_path = PathBuf::from(value["finalPath"].as_str().expect("finalPath"));
        let bytes = b"ordinary-shelf-jpeg-body";
        std::fs::write(&final_path, bytes).expect("write final");
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest: [u8; 32] = hasher.finalize().into();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let offer_id = phone
            .resident
            .commit_ordinary_photo(&lease_id, &hex, 640, 480)
            .await
            .expect("commit")
            .offer_id
            .to_string();
        assert!(!offer_id.is_empty());
        let source = phone
            .store()
            .get_offer_source(OfferId::from_str(&offer_id).expect("offer id"))
            .expect("read source")
            .expect("source present");
        match source.source {
            meshelf_core::OfferSource::File { canonical_path, .. } => {
                assert_eq!(canonical_path, final_path.canonicalize().expect("canon"));
            }
            other => panic!("expected file source, got {other:?}"),
        }
        // Abandon after commit must not delete the durable final file.
        phone
            .resident
            .abandon_ordinary_photo(&lease_id)
            .expect("abandon committed");
        assert!(final_path.exists(), "committed ordinary photo must remain");
        let card = phone
            .store()
            .get_offer_card(
                phone.local(),
                OfferId::from_str(&offer_id).expect("offer id"),
            )
            .expect("read card")
            .expect("owned ordinary card on shelf");
        assert_eq!(card.source_device, phone.local());
        // A desktop saves this photo under the offer's name: camera-style, never `final.jpg`.
        let file_name = final_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("photo file name");
        assert!(
            file_name.starts_with("IMG_") && file_name.ends_with(".jpg"),
            "{file_name}"
        );
        match &card.descriptor {
            OfferDescriptor::File { root_name, .. } => assert_eq!(root_name, file_name),
            other => panic!("expected a file descriptor, got {other:?}"),
        }
    }

    #[test]
    fn ordinary_photo_names_are_utc_camera_style() {
        assert_eq!(ordinary_photo_file_name(0), "IMG_19700101_000000.jpg");
        assert_eq!(
            ordinary_photo_file_name(951_782_400),
            "IMG_20000229_000000.jpg"
        );
        assert_eq!(
            ordinary_photo_file_name(1_789_339_545),
            "IMG_20260913_224545.jpg"
        );
        assert_eq!(
            ordinary_photo_file_name(4_102_444_799),
            "IMG_20991231_235959.jpg"
        );
    }

    /// The Android snapshot and activation results never carry app-private paths or provider
    /// URIs, while the human part of the sentence stays readable.
    #[test]
    fn bounded_detail_never_carries_paths_or_content_uris() {
        let cases = [
            (
                "could not open /data/user/0/com.meshelf.android/no_backup/meshelf/My Photos/IMG_1.jpg: Permission denied (os error 13)",
                "could not open <path>: Permission denied (os error 13)",
            ),
            (
                "document content://com.android.providers.media.documents/document/image%3A1 was revoked",
                "document <path> was revoked",
            ),
            (r"missing [local-home]\Downloads\a.txt", "missing <path>"),
            ("open \"/tmp/x y/z.jpg\" failed", "open \"<path>\" failed"),
            (
                "I/O error: Permission denied",
                "I/O error: Permission denied",
            ),
            ("origin offline", "origin offline"),
        ];
        for (input, expected) in cases {
            assert_eq!(bounded_detail(input), expected, "{input}");
        }
    }

    /// One peer whose catalog this phone cannot store must not abort the round: later peers are
    /// still asked, and that peer is reported as reached with `CATALOG_FAILED`.
    #[tokio::test]
    async fn refresh_continues_past_a_catalog_this_phone_cannot_store() {
        let connector = Arc::new(RoutedConnector::default());
        let phone = phone_with_connector(Some(Arc::clone(&connector) as Arc<dyn SocketConnector>));
        let conflicting_directory = tempfile::tempdir().expect("conflicting origin directory");
        let conflicting_store = Arc::new(
            RedbV2Store::open(conflicting_directory.path().join("meshelf.redb"))
                .expect("conflicting origin store"),
        );
        let healthy_directory = tempfile::tempdir().expect("healthy origin directory");
        let healthy_store = Arc::new(
            RedbV2Store::open(healthy_directory.path().join("meshelf.redb"))
                .expect("healthy origin store"),
        );
        let conflicting = routed_peer(
            &phone,
            &connector,
            "CEDAR",
            1,
            OfferAckCode::Stored,
            Some(Arc::clone(&conflicting_store)),
        )
        .await;
        let healthy = routed_peer(
            &phone,
            &connector,
            "FERN",
            2,
            OfferAckCode::Stored,
            Some(Arc::clone(&healthy_store)),
        )
        .await;
        let clashing_offer = OfferId::new();
        conflicting_store
            .insert_owned_ordinary(
                conflicting.identity.device_id,
                OfferSourceInput::new(
                    clashing_offer,
                    OfferDescriptor::text("origin says this").expect("text"),
                    std::collections::HashSet::new(),
                    OfferSource::Text {
                        text: "origin says this".to_owned(),
                    },
                ),
            )
            .expect("conflicting origin offer");
        // The phone already holds that card with a different descriptor, so storing it fails.
        phone
            .store()
            .insert_offer_card_on_ordinary_index(
                meshelf_core::OfferCardInput::new(
                    conflicting.identity.device_id,
                    clashing_offer,
                    OfferDescriptor::text("phone remembers that").expect("text"),
                    CardAvailability::Available,
                ),
                Some(phone.local()),
            )
            .expect("pre-existing card");
        healthy_store
            .insert_owned_ordinary(
                healthy.identity.device_id,
                OfferSourceInput::new(
                    OfferId::new(),
                    OfferDescriptor::text("healthy item").expect("text"),
                    std::collections::HashSet::new(),
                    OfferSource::Text {
                        text: "healthy item".to_owned(),
                    },
                ),
            )
            .expect("healthy origin offer");

        let refreshed: serde_json::Value = serde_json::from_str(
            &phone
                .resident
                .refresh_origin_catalogs()
                .await
                .expect("a single unstorable catalog must not fail the refresh"),
        )
        .expect("refresh json");
        assert_eq!(refreshed["newItems"], 1);
        let peers = refreshed["snapshot"]["peerObservation"]["peers"]
            .as_array()
            .expect("peers")
            .clone();
        let outcome = |device: DeviceId| {
            peers
                .iter()
                .find(|entry| entry["deviceId"] == device.to_string())
                .map(|entry| (entry["reachability"].clone(), entry["outcome"].clone()))
                .expect("observed peer")
        };
        assert_eq!(
            outcome(conflicting.identity.device_id),
            (
                serde_json::json!("REACHABLE"),
                serde_json::json!("CATALOG_FAILED")
            )
        );
        assert_eq!(
            outcome(healthy.identity.device_id),
            (
                serde_json::json!("REACHABLE"),
                serde_json::json!("CATALOG_APPLIED")
            )
        );
    }

    #[tokio::test]
    async fn mixed_own_and_received_cards_share_one_ten_entry_shelf() {
        let phone = phone();
        let remote = DeviceId::new();
        phone.pair(
            remote,
            [0x46_u8; 32],
            "CEDAR",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x46),
        );
        for index in 0..5 {
            phone
                .resident
                .announce_text(&format!("own-{index}"))
                .await
                .expect("announce own");
        }
        let config = phone.inner().server_config();
        for index in 0..5 {
            let announcement = OfferAnnouncement::new(
                OfferId::new(),
                remote,
                phone.local(),
                phone.now(),
                OfferDescriptor::text(format!("recv-{index}")).expect("text"),
            );
            let ack = config
                .services
                .announcement_receiver
                .handle_announcement(remote, phone.local(), announcement)
                .await
                .expect("recv ack");
            assert_eq!(ack.code, OfferAckCode::Stored);
        }
        assert_eq!(phone.store().read_offer_shelf().expect("shelf").len(), 10);
        assert_eq!(
            phone.store().read_offer_sources().expect("sources").len(),
            5
        );

        let overflow = OfferAnnouncement::new(
            OfferId::new(),
            remote,
            phone.local(),
            phone.now(),
            OfferDescriptor::text("recv-overflow").expect("text"),
        );
        let ack = config
            .services
            .announcement_receiver
            .handle_announcement(remote, phone.local(), overflow)
            .await
            .expect("overflow ack");
        assert_eq!(ack.code, OfferAckCode::Stored);
        assert_eq!(ack.live_entries, 10);
        assert_eq!(ack.pruned_entries, 1);
        let shelf = phone.store().read_offer_shelf().expect("shelf");
        assert_eq!(shelf.len(), 10);
        assert_eq!(
            phone.store().read_offer_sources().expect("sources").len(),
            4,
            "oldest owned text must purge with its ordinary card"
        );
        let snapshot = phone.resident.shelf_snapshot_json().expect("snapshot");
        let value: serde_json::Value = serde_json::from_str(&snapshot).expect("json");
        assert_eq!(value["cards"].as_array().expect("cards").len(), 10);
    }

    #[tokio::test]
    async fn ordinary_overflow_purges_owned_original_file_and_leaves_capture() {
        use meshelf_core::{
            CaptureKind, CapturePullGrant, CaptureRequestId, CaptureRequestPhase,
            CaptureRequestRecord, MAX_CAPTURE_LIFETIME_MS,
        };

        let phone = phone();
        let remote = DeviceId::new();
        phone.pair(
            remote,
            [0x47_u8; 32],
            "CEDAR",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x47),
        );

        let json = phone
            .resident
            .reserve_ordinary_photo("g08-purge")
            .expect("reserve");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        let lease_id = value["leaseId"].as_str().expect("leaseId").to_owned();
        let final_path = PathBuf::from(value["finalPath"].as_str().expect("finalPath"));
        let bytes = b"g08-owned-original";
        std::fs::write(&final_path, bytes).expect("write final");
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest: [u8; 32] = hasher.finalize().into();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let offer_id = phone
            .resident
            .commit_ordinary_photo(&lease_id, &hex, 1, 1)
            .await
            .expect("commit")
            .offer_id
            .to_string();
        assert!(final_path.exists(), "owned original present before purge");

        let capture_id = CaptureRequestId::new();
        let capture = CaptureRequestRecord {
            request_id: capture_id,
            peer: remote,
            peer_label: "CEDAR".to_owned(),
            purpose: "G08 capture outside ordinary index".to_owned(),
            lens: None,
            created_at_unix_ms: 1_000,
            grant: CapturePullGrant {
                expected_source: remote,
                kind: CaptureKind::Photo,
                exact_output_path: phone.photo_root.join("g08-capture-out.jpg"),
                expires_at_unix_ms: 1_000 + MAX_CAPTURE_LIFETIME_MS,
            },
            phase: CaptureRequestPhase::AwaitingPresentation,
            terminal_reported: false,
        };
        match phone
            .store()
            .insert_capture_request(capture)
            .expect("capture")
        {
            CaptureRequestInsert::Inserted { .. } => {}
            other => panic!("expected insert, got {other:?}"),
        }

        // Own photo is oldest; ten more received cards force it out of the ordinary index.
        let config = phone.inner().server_config();
        for index in 0..V2_MAX_LIVE_ENTRIES {
            let announcement = OfferAnnouncement::new(
                OfferId::new(),
                remote,
                phone.local(),
                phone.now(),
                OfferDescriptor::text(format!("recv-purge-{index}")).expect("text"),
            );
            let ack = config
                .services
                .announcement_receiver
                .handle_announcement(remote, phone.local(), announcement)
                .await
                .expect("recv ack");
            assert_eq!(ack.code, OfferAckCode::Stored);
        }
        assert_eq!(phone.store().read_offer_shelf().expect("shelf").len(), 10);
        assert!(
            phone
                .store()
                .get_offer_source(OfferId::from_str(&offer_id).expect("id"))
                .expect("read")
                .is_none(),
            "owned source must leave with its purged card"
        );
        assert!(
            !final_path.exists(),
            "owned ordinary original must be unlinked after purge"
        );
        assert!(
            phone
                .store()
                .get_capture_request(capture_id)
                .expect("capture read")
                .is_some(),
            "capture rows must survive ordinary ten/eleven purge"
        );
        phone
            .resident
            .shelf_snapshot_json()
            .expect("snapshot must not hide over-capacity residue");
    }

    #[test]
    fn ordinary_disk_budget_refuses_explicitly_when_space_is_short() {
        let err = ordinary_disk_budget_allows(1_024, 100_u64 * 1024 * 1024 * 1024, 64)
            .expect_err("must refuse");
        match err {
            PhoneError::InsufficientSpace {
                available,
                required,
            } => {
                assert_eq!(available, 1_024);
                assert!(required > available);
            }
            other => panic!("expected InsufficientSpace, got {other:?}"),
        }
        ordinary_disk_budget_allows(u64::MAX / 2, 8_u64 * 1024 * 1024 * 1024, 1024)
            .expect("ample space must pass");
        let io_err = map_storage_io(
            "stage",
            std::io::Error::from(std::io::ErrorKind::StorageFull),
        );
        assert!(matches!(io_err, PhoneError::InsufficientSpace { .. }));
    }

    #[tokio::test]
    async fn ordinary_photo_commit_refuses_hash_mismatch() {
        let phone = phone();
        phone.pair(
            DeviceId::new(),
            [0x45_u8; 32],
            "CEDAR",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x45),
        );
        let json = phone
            .resident
            .reserve_ordinary_photo("action-3")
            .expect("reserve");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        let lease_id = value["leaseId"].as_str().expect("leaseId").to_owned();
        let final_path = PathBuf::from(value["finalPath"].as_str().expect("finalPath"));
        std::fs::write(&final_path, b"body").expect("write");
        let err = phone
            .resident
            .commit_ordinary_photo(&lease_id, &"00".repeat(32), 1, 1)
            .await
            .expect_err("hash mismatch");
        assert!(
            matches!(err, PhoneError::InvalidPhoto(ref detail) if detail.contains("hash")),
            "got {err:?}"
        );
    }

    /// Tempfile-backed document provider: serves lease bytes without copying into app storage.
    struct TempFileDocuments {
        files: Mutex<std::collections::HashMap<meshelf_core::DocumentLeaseId, PathBuf>>,
    }

    impl meshelf_net::DocumentSourceProvider for TempFileDocuments {
        fn open(
            &self,
            lease_id: meshelf_core::DocumentLeaseId,
            expected_bytes: u64,
        ) -> Result<tokio::fs::File, meshelf_net::DocumentOpenError> {
            let path = self
                .files
                .lock()
                .expect("files")
                .get(&lease_id)
                .cloned()
                .ok_or(meshelf_net::DocumentOpenError::Unavailable)?;
            let file = std::fs::File::open(&path)
                .map_err(|_| meshelf_net::DocumentOpenError::Unavailable)?;
            let len = file
                .metadata()
                .map_err(|_| meshelf_net::DocumentOpenError::Unavailable)?
                .len();
            if len != expected_bytes {
                return Err(meshelf_net::DocumentOpenError::Changed);
            }
            Ok(tokio::fs::File::from_std(file))
        }
    }

    #[tokio::test]
    async fn announce_document_stores_document_source_and_provider_serves_bytes() {
        use meshelf_core::DocumentLeaseId;
        use tokio::io::AsyncReadExt;

        let lease_id = DocumentLeaseId::new();
        let directory = tempfile::tempdir().expect("temp");
        let path = directory.path().join("gallery-photo.jpg");
        let bytes = b"document-gallery-bytes-not-copied";
        std::fs::write(&path, bytes).expect("write gallery stand-in");
        let provider = Arc::new(TempFileDocuments {
            files: Mutex::new(std::collections::HashMap::from([(lease_id, path)])),
        });
        let phone = phone_with_documents(
            Arc::clone(&provider) as Arc<dyn meshelf_net::DocumentSourceProvider>
        );
        phone.pair(
            DeviceId::new(),
            [0x46_u8; 32],
            "CEDAR",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x46),
        );
        let offer_id = phone
            .resident
            .announce_document(
                &lease_id.to_string(),
                "gallery-photo.jpg",
                bytes.len() as u64,
            )
            .await
            .expect("announce document")
            .offer_id
            .to_string();
        let source = phone
            .store()
            .get_offer_source(OfferId::from_str(&offer_id).expect("offer id"))
            .expect("read source")
            .expect("source present");
        match source.source {
            meshelf_core::OfferSource::Document {
                lease_id: stored_lease,
                metadata_commitment,
            } => {
                assert_eq!(stored_lease, lease_id);
                assert_eq!(
                    metadata_commitment,
                    meshelf_net::document_metadata_commitment(
                        lease_id,
                        "gallery-photo.jpg",
                        bytes.len() as u64
                    )
                );
            }
            other => panic!("expected document source, got {other:?}"),
        }
        assert_eq!(
            phone
                .store()
                .document_lease_refcount(lease_id)
                .expect("refcount"),
            1
        );
        let mut file = provider
            .open(lease_id, bytes.len() as u64)
            .expect("open document");
        let mut read = Vec::new();
        file.read_to_end(&mut read).await.expect("read");
        assert_eq!(read, bytes);
    }

    #[tokio::test]
    async fn the_phone_listener_advertises_its_capabilities_and_refuses_with_none() {
        // A refusal that advertised offer-pull-v2 would make every desktop refresh record the
        // phone as trusted with no code at all (F1); the capabilities on acceptance are what let a
        // desktop send a capture request in the first place.
        let phone = phone();
        let config = phone.inner().server_config();

        assert_eq!(
            config.server_capabilities,
            vec![
                CAP_OFFER_PULL_V2.to_owned(),
                CAP_CAPTURE_PHOTO_V1.to_owned(),
                CAP_SHELF_CATALOG_V1.to_owned(),
            ]
        );
        assert!(
            config.refusal_capabilities.is_empty(),
            "a phone's refusal must advertise nothing"
        );
        assert!(config.pairing.is_some());
        assert_eq!(config.hello_read_limit, PHONE_HELLO_READ_LIMIT);
    }

    // --- the photograph Kotlin hands over ---------------------------------------------------

    #[tokio::test]
    async fn a_captured_photograph_is_durable_before_the_call_returns() {
        // The announcement is spawned, so on this single-threaded runtime nothing has run when the
        // call returns: whatever is in the store at that instant was committed synchronously.
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");

        let before = phone.now();
        phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 4032, 3024)
            .expect("captured");
        let after = phone.now();

        let phase = phone.phase(record.request_id);
        let photo = photo_of(&phase).expect("the photograph is recorded before the call returns");
        assert_eq!(photo.path, path);
        assert_eq!(photo.sha256, sha256);
        assert_eq!((photo.width, photo.height), (4032, 3024));
        assert!(
            (before + CAPTURE_PHOTO_DELETE_AFTER_MS..=after + CAPTURE_PHOTO_DELETE_AFTER_MS)
                .contains(&photo.delete_deadline_unix_ms),
            "the delete deadline is ten minutes from the moment the photograph was recorded"
        );
    }

    #[tokio::test]
    async fn a_photograph_that_does_not_match_its_declared_hash_is_refused_and_nothing_is_recorded()
    {
        // The hash is the only thing tying the bytes on disk to the bytes the camera reported. A
        // file swapped between the shutter and this call must not become the announced photograph.
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, _) = phone.photo("router.jpg", b"the real bytes");
        let (_, other) = phone.photo("decoy.jpg", b"different bytes entirely");

        let error = phone
            .resident
            .capture_captured(record.request_id, &path, other, 12, 12)
            .expect_err("refused");

        assert!(
            matches!(error, PhoneError::InvalidPhoto(ref detail) if detail.contains("hash")),
            "{error}"
        );
        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Presented
        );
    }

    #[tokio::test]
    async fn a_symbolic_link_an_empty_file_and_a_zero_dimension_are_each_refused() {
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let (real, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");
        let (empty, empty_hash) = phone.photo("empty.jpg", b"");

        // A symbolic link would let the caller name a file it does not own and have the phone
        // serve it. A link to the file is refused as not a regular file; a link standing in for a
        // *directory* on the path is not, because the metadata call follows it and reports an
        // ordinary file, so only comparing against the canonical path refuses that one.
        let link = phone.photo_root.join("link.jpg");
        let linked_directory = phone.photo_root.join("elsewhere");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, &link).expect("symlink");
            std::os::unix::fs::symlink(&phone.photo_root, &linked_directory).expect("symlink");
        }
        #[cfg(not(unix))]
        {
            std::os::windows::fs::symlink_file(&real, &link).expect("symlink");
            std::os::windows::fs::symlink_dir(&phone.photo_root, &linked_directory)
                .expect("symlink");
        }

        for (path, hash, width, height, expected) in [
            (link.clone(), sha256, 12_u32, 12_u32, "not a regular file"),
            (
                linked_directory.join("router.jpg"),
                sha256,
                12,
                12,
                "not canonical",
            ),
            (empty, empty_hash, 12, 12, "empty"),
            (real.clone(), sha256, 0, 12, "positive"),
            (real.clone(), sha256, 12, 0, "positive"),
            (
                phone.photo_root.join("absent.jpg"),
                sha256,
                12,
                12,
                "cannot be read",
            ),
        ] {
            let record = phone.present_row(requester, now, now + LIFETIME_MS);
            let error = phone
                .resident
                .capture_captured(record.request_id, &path, hash, width, height)
                .expect_err("refused");
            assert!(
                matches!(error, PhoneError::InvalidPhoto(ref detail) if detail.contains(expected)),
                "{path:?} {width}x{height}: {error}"
            );
            assert_eq!(
                phone.phase(record.request_id),
                CaptureSourcePhase::Presented,
                "a refused photograph must leave the request exactly as it was"
            );
            phone
                .store()
                .terminate_capture_source(record.request_id, CaptureSourceTerminalCode::Failed)
                .expect("clear the live row for the next case");
        }
    }

    #[tokio::test]
    async fn a_request_whose_expiry_has_passed_takes_no_photograph_and_ends_expired() {
        // The shutter can be pressed after the requester has given up. Announcing then would send
        // a photograph to a peer that already reported the capture expired.
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + 1_000);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");
        phone.clock.advance(2_000);

        let error = phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 12, 12)
            .expect_err("refused");

        assert!(matches!(error, PhoneError::RequestExpired(_)), "{error}");
        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Expired
            }
        );
        assert_eq!(
            phone.events.withdrawals(),
            vec![(record.request_id, CaptureWithdrawReason::Expired)]
        );
    }

    // --- announcement --------------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_announcement_that_never_reaches_the_requester_keeps_the_photograph() {
        // A transport failure is not an answer. The requester may have received the announcement
        // and already be pulling, so deleting the photograph here could destroy the only copy of a
        // transfer in flight. The row stays announced and its expiry owns it; there is no retry.
        let phone = phone();
        let requester = DeviceId::new();
        phone.pair(
            requester,
            [5_u8; 32],
            "CEDAR-desk",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x05),
        );
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");

        phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 12, 12)
            .expect("captured");

        // The row is marked announced before the connection is even attempted, so waiting on the
        // phase would race the send. The recorded failure is what says the attempt is over.
        let reported = until(|| phone.resident.status().failures.last).await;
        assert!(reported.detail.contains("announce"), "{reported:?}");

        let phase = phone.phase(record.request_id);
        assert!(
            matches!(phase, CaptureSourcePhase::Announced { .. }),
            "a photograph the requester may already be pulling stays on offer: {phase:?}"
        );
        assert!(photo_of(&phase).is_some(), "the photograph is still held");
        assert!(
            phone.events.withdrawals().is_empty(),
            "a photograph the requester may be pulling must not be withdrawn"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_photograph_for_a_requester_with_no_trust_record_ends_failed() {
        // Nothing can be announced to a peer this phone has no record of: there is no address to
        // reach and no key to pin. Holding the file until expiry would keep a photograph nobody
        // will ever collect.
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");

        phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 12, 12)
            .expect("captured");

        let withdrawn = until(|| {
            let withdrawals = phone.events.withdrawals();
            (!withdrawals.is_empty()).then_some(withdrawals)
        })
        .await;

        assert_eq!(
            withdrawn,
            vec![(record.request_id, CaptureWithdrawReason::Failed)]
        );
        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_signed_refusal_of_the_announcement_ends_the_photograph_and_reports_it() {
        // The other half of the announcement policy, and the half that destroys data. A signed
        // refusal arrives on a connection whose server hello was verified against the pinned key,
        // so it is a definite answer from the requester itself: this photograph will never be
        // pulled. Holding it until expiry would keep a photograph nobody will collect, so the row
        // ends and the file is given up — and because that is an ending the requester did not
        // watch happen, the failure is reported to it.
        let (phone, desktop, connector) =
            paired_phone_and_desktop(OfferAckCode::RefusedInvalid, Some("capture_not_armed")).await;
        let requester = desktop.requester();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");

        phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 4032, 3024)
            .expect("captured");

        let withdrawn = until(|| {
            let withdrawals = phone.events.withdrawals();
            (!withdrawals.is_empty()).then_some(withdrawals)
        })
        .await;
        assert_eq!(
            withdrawn,
            vec![(record.request_id, CaptureWithdrawReason::Failed)],
            "the phone deletes the photograph it can no longer deliver"
        );
        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );

        // The requester is told, on its own connection, why nothing is coming; without this its
        // wait would run to the full expiry for an answer that already exists.
        let statuses = until(|| {
            let statuses = desktop.statuses();
            (!statuses.is_empty()).then_some(statuses)
        })
        .await;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].request_id, record.request_id);
        assert_eq!(statuses[0].code, CaptureStatusCode::Failed);
        assert_eq!(statuses[0].detail.as_deref(), Some("capture_not_armed"));

        let announcements = desktop.announcements();
        assert_eq!(announcements.len(), 1, "there is no retry and no queue");
        assert_eq!(announcements[0].target_device, requester);
        assert_eq!(
            announcements[0].capture.as_ref().map(|c| c.request_id),
            Some(record.request_id)
        );
        assert_eq!(
            *connector.dialed.lock().expect("dialed"),
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), MESHELF_PORT),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), MESHELF_PORT)
            ],
            "both the announcement and the status dial the paired peer's own address"
        );
        assert!(
            phone.resident.status().failures.count >= 1,
            "an ending the caller never sees is counted, not dropped"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_accepted_announcement_leaves_the_photograph_on_offer_and_reports_nothing() {
        // The conservative half. An acceptance means the requester holds the announcement and may
        // pull at any moment, so nothing ends and nothing is said.
        let (phone, desktop, _connector) =
            paired_phone_and_desktop(OfferAckCode::Stored, None).await;
        let requester = desktop.requester();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");

        phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 4032, 3024)
            .expect("captured");

        until(|| (!desktop.announcements().is_empty()).then_some(())).await;
        timer_settles().await;
        assert!(
            matches!(
                phone.phase(record.request_id),
                CaptureSourcePhase::Announced { .. }
            ),
            "an announced photograph waits for its requester to pull it"
        );
        assert!(phone.events.withdrawals().is_empty());
        assert!(
            desktop.statuses().is_empty(),
            "nothing has happened that the requester does not already know"
        );
        assert_eq!(phone.resident.status().failures, PhoneFailures::default());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_failures_are_counted_and_a_later_success_clears_only_the_wording() {
        // A background operation has no caller to return a failure to, so the status is the only
        // place it can be seen. One slot that the next failure overwrites loses the count, and a
        // slot nothing ever clears reports a failure long after the phone recovered.
        let (phone, desktop, _connector) =
            paired_phone_and_desktop(OfferAckCode::Stored, None).await;

        // A request from a device this phone has no record of: there is no address to reach and no
        // key to pin, so neither the announcement nor the status it then tries to send can go.
        let now = phone.now();
        let stranger = phone.present_row(DeviceId::new(), now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("stranger.jpg", b"a plausible jpeg body");
        phone
            .resident
            .capture_captured(stranger.request_id, &path, sha256, 12, 12)
            .expect("captured");

        let counted = until(|| {
            let failures = phone.resident.status().failures;
            (failures.count >= 2).then_some(failures)
        })
        .await;
        assert_eq!(
            counted.count, 2,
            "the announcement and the status each failed and each was counted"
        );
        let last = counted.last.expect("the most recent failure is described");
        assert!(
            last.at_unix_ms >= now,
            "a failure carries when it happened, so a stale one can be recognised"
        );

        // A second photograph, for the peer this phone is actually paired with, is announced.
        let now = phone.now();
        let record = phone.present_row(desktop.requester(), now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"another plausible jpeg body");
        phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 12, 12)
            .expect("captured");

        let recovered = until(|| {
            let failures = phone.resident.status().failures;
            failures.last.is_none().then_some(failures)
        })
        .await;
        assert_eq!(
            recovered.count, counted.count,
            "the count never forgets that something failed"
        );
    }

    // --- the words Kotlin sends -------------------------------------------------------------

    #[tokio::test]
    async fn each_decline_reason_ends_the_request_the_way_the_work_order_pins() {
        // Only the person's own refusal is a decline and only a lapsed request is an expiry;
        // everything else is a failure. Reporting a permission problem as a decline would tell the
        // agent the person said no.
        let phone = phone();
        let requester = DeviceId::new();
        for (reason, expected) in [
            ("user-declined", CaptureSourceTerminalCode::Declined),
            ("expired", CaptureSourceTerminalCode::Expired),
            (
                "camera-permission-denied",
                CaptureSourceTerminalCode::Failed,
            ),
            ("availability-disabled", CaptureSourceTerminalCode::Failed),
            ("notifications-disabled", CaptureSourceTerminalCode::Failed),
            ("service-stopped", CaptureSourceTerminalCode::Failed),
            ("route-unavailable", CaptureSourceTerminalCode::Failed),
            ("busy", CaptureSourceTerminalCode::Failed),
            ("refused", CaptureSourceTerminalCode::Failed),
            (
                "a word no build ever sends",
                CaptureSourceTerminalCode::Failed,
            ),
        ] {
            let now = phone.now();
            let record = phone.present_row(requester, now, now + LIFETIME_MS);
            phone
                .resident
                .capture_declined(record.request_id, reason)
                .expect("declined");
            assert_eq!(
                phone.phase(record.request_id),
                CaptureSourcePhase::Terminal { code: expected },
                "{reason}"
            );
        }
        assert!(
            phone.events.withdrawals().is_empty(),
            "the phone's own user interface asked for these, so none is withdrawn back to it"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_decline_arriving_while_the_photograph_is_being_fetched_does_not_end_the_transfer() {
        // Every word but `user-declined` and `expired` ends a request `Failed`, and the store
        // accepts `Claimed -> Failed` because A19 gives *the fetch* that transition for a transfer
        // that provably delivered nothing: one that ended before `FetchComplete`. This caller
        // cannot know whether `FetchComplete` was sent. Android stopping the foreground service
        // mid-transfer arrives here as `service-stopped`, and taking the allowance for it would
        // report the capture failed to a requester that is about to publish the photograph,
        // because the requester publishes once every byte has arrived. The two neighbours agree:
        // the expiry timer refuses a claimed row, and a requester's own cancel is refused.
        for reason in ["service-stopped", "user-declined"] {
            let phone = phone();
            let requester = DeviceId::new();
            let (request_id, _claimed) = phone.claimed(requester, "router.jpg");

            phone
                .resident
                .capture_declined(request_id, reason)
                .expect("a decline that arrives too late is not an error");

            assert!(
                matches!(phone.phase(request_id), CaptureSourcePhase::Claimed { .. }),
                "{reason}: the transfer decides how a claimed row ends"
            );
            assert!(
                phone.events.withdrawals().is_empty(),
                "{reason}: nothing may withdraw a photograph mid-transfer"
            );
            let failures = phone.resident.status().failures;
            assert_eq!(
                failures.count, 1,
                "{reason}: the decline is counted, not silently dropped"
            );
            assert!(
                failures
                    .last
                    .expect("the dropped decline is described")
                    .detail
                    .contains("being fetched"),
                "{reason}"
            );
        }
    }

    #[tokio::test]
    async fn the_same_photograph_offered_twice_changes_nothing_and_a_different_one_is_refused() {
        // The camera can report the same capture twice — a retried JNI call, a resumed activity.
        // The same file offered again is the same durable fact, so it is idempotent. A *different*
        // file for a request already photographed is not a repeat: taking it would replace the
        // photograph a requester may already have been announced, under the same request id.
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");
        let photo =
            verified_photo(&path, &phone.photo_root, sha256, 4032, 3024, now).expect("photograph");
        let offer_id = photo.offer_id;
        phone
            .store()
            .attach_captured(record.request_id, photo)
            .expect("attached");

        phone
            .resident
            .capture_captured(record.request_id, &path, sha256, 4032, 3024)
            .expect("the same photograph twice is the same fact");
        assert_eq!(
            photo_of(&phone.phase(record.request_id)).map(|photo| photo.offer_id),
            Some(offer_id),
            "an idempotent repeat must not mint a second offer for the same request"
        );

        let (other, other_hash) = phone.photo("other.jpg", b"a different plausible jpeg body");
        let error = phone
            .resident
            .capture_captured(record.request_id, &other, other_hash, 4032, 3024)
            .expect_err("a second, different photograph is refused");

        assert!(matches!(error, PhoneError::NoLiveRequest(_)), "{error}");
        assert_eq!(
            photo_of(&phone.phase(record.request_id)).map(|photo| photo.offer_id),
            Some(offer_id),
            "the request still holds the photograph it was given first"
        );
    }

    #[tokio::test]
    async fn declining_an_unknown_or_finished_request_changes_nothing() {
        let phone = phone();
        let requester = DeviceId::new();
        phone
            .resident
            .capture_declined(CaptureRequestId::new(), "user-declined")
            .expect("unknown ids are a no-op");
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        phone
            .resident
            .capture_declined(record.request_id, "user-declined")
            .expect("declined");
        phone
            .resident
            .capture_declined(record.request_id, "camera-permission-denied")
            .expect("a finished request is a no-op");

        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Declined
            },
            "a second reason must not rewrite how the request ended"
        );
    }

    #[test]
    fn a_finished_row_reports_the_status_its_code_implies_and_claims_nothing_when_uncertain() {
        // An uncertain photograph may already be published on the requester. Reporting a failure
        // would contradict a publication that peer has already committed.
        for (code, expected) in [
            (
                CaptureSourceTerminalCode::Declined,
                Some(CaptureStatusCode::Declined),
            ),
            (
                CaptureSourceTerminalCode::Expired,
                Some(CaptureStatusCode::Expired),
            ),
            (
                CaptureSourceTerminalCode::Cancelled,
                Some(CaptureStatusCode::Cancelled),
            ),
            (
                CaptureSourceTerminalCode::Failed,
                Some(CaptureStatusCode::Failed),
            ),
            (CaptureSourceTerminalCode::ExpiredUnconfirmed, None),
        ] {
            assert_eq!(
                status_code(&CaptureSourcePhase::Terminal { code }),
                expected,
                "{code:?}"
            );
        }
        assert_eq!(status_code(&CaptureSourcePhase::Presented), None);
    }

    // --- the one timer ----------------------------------------------------------------------

    #[tokio::test]
    async fn a_request_that_reaches_its_expiry_is_ended_and_withdrawn() {
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + 1_000);

        phone
            .inner()
            .on_deadline(now + 1_000)
            .expect("deadline pass");

        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Expired
            }
        );
        assert_eq!(
            phone.events.withdrawals(),
            vec![(record.request_id, CaptureWithdrawReason::Expired)]
        );
    }

    #[tokio::test]
    async fn a_photograph_being_served_is_never_ended_by_the_timer() {
        // A claimed row is a transfer in flight, with its own bounds. Expiring it here would turn
        // a photograph the requester is receiving into one the phone has already written off.
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + 1_000);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");
        let photo =
            verified_photo(&path, &phone.photo_root, sha256, 12, 12, now).expect("photograph");
        let offer_id = photo.offer_id;
        phone
            .store()
            .attach_captured(record.request_id, photo)
            .expect("attached");
        phone
            .store()
            .mark_capture_announced(record.request_id)
            .expect("announced");
        assert!(matches!(
            phone
                .store()
                .claim_capture_source(offer_id, requester, ActivationId::new())
                .expect("claim"),
            CaptureSourceClaim::Claimed(_)
        ));

        assert_eq!(
            phone.inner().next_deadline().expect("next deadline"),
            None,
            "a transfer in flight arms no timer"
        );
        phone
            .inner()
            .on_deadline(now + 10_000)
            .expect("deadline pass");

        assert!(
            matches!(
                phone.phase(record.request_id),
                CaptureSourcePhase::Claimed { .. }
            ),
            "the transfer must be left exactly as it was"
        );
        assert!(phone.events.withdrawals().is_empty());
    }

    /// Lets the deadline timer finish reacting to the transition that just happened and park
    /// again. It is doing two store reads, so this is generous by orders of magnitude; it is here
    /// because the next assertion has to be about the wake that comes *after* it, not this one.
    async fn timer_settles() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_uncertain_photograph_is_kept_until_its_deadline() {
        // A lost receipt is indistinguishable from a requester that never committed. Deleting
        // early could destroy the only copy of an undelivered photograph, and recording a delivery
        // would be a lie. So it is held, and the timer takes the delete deadline as the instant it
        // owes something at.
        let phone = phone();
        let requester = DeviceId::new();
        let (request_id, claimed) = phone.claimed(requester, "router.jpg");
        let CaptureSourcePhase::Claimed { photo, .. } = &claimed.phase else {
            panic!("the claim must hold the photograph");
        };
        let deadline = photo.delete_deadline_unix_ms;
        timer_settles().await;

        phone
            .capture_sources()
            .capture_uncertain(&claimed)
            .expect("uncertain");
        timer_settles().await;

        assert_eq!(
            phone.phase(request_id),
            CaptureSourcePhase::UncertainNoReplay {
                deadline_unix_ms: deadline,
                path: photo.path.clone(),
            },
            "a photograph the requester may hold is kept until its deadline"
        );
        assert!(phone.events.withdrawals().is_empty());
        assert!(
            phone.events.delivered.lock().expect("delivered").is_empty(),
            "an uncertain photograph is never reported delivered"
        );
        assert_eq!(
            phone.inner().next_deadline().expect("next deadline"),
            Some(deadline),
            "the delete deadline is what the timer now owes"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_running_timer_deletes_an_uncertain_photograph_when_its_deadline_has_passed() {
        // The regression this pins is not in the deadline handler; it is in what wakes it. The
        // `Claimed -> UncertainNoReplay` transition is made by the fetch in another crate and has
        // no user-interface event, and a claimed row owes the timer no deadline at all — so at the
        // instant the delete deadline is written, the timer is parked on nothing. Without a wake
        // on that transition it stays parked, the deadline is never reached, and the photograph
        // stays on the phone until the application happens to restart.
        //
        // So the test drives `run_deadlines`, the loop the resident really runs. Calling
        // `on_deadline` here would prove only that the handler is right when something calls it.
        let phone = phone();
        let requester = DeviceId::new();
        let (request_id, claimed) = phone.claimed(requester, "router.jpg");
        let CaptureSourcePhase::Claimed { photo, .. } = &claimed.phase else {
            panic!("the claim must hold the photograph");
        };
        let deadline = photo.delete_deadline_unix_ms;
        // The timer reacts to the claim and parks with nothing to wait for, which is the state the
        // defect needs: the wake this test observes can only be the uncertain transition's own.
        timer_settles().await;
        assert_eq!(phone.inner().next_deadline().expect("next deadline"), None);
        // The transfer took long enough that the photograph is already due for deletion.
        phone
            .clock
            .advance(i64::try_from(CAPTURE_PHOTO_DELETE_AFTER_MS).expect("delay fits"));

        phone
            .capture_sources()
            .capture_uncertain(&claimed)
            .expect("uncertain");

        let withdrawn = until(|| {
            let withdrawals = phone.events.withdrawals();
            (!withdrawals.is_empty()).then_some(withdrawals)
        })
        .await;

        assert_eq!(
            withdrawn,
            vec![(request_id, CaptureWithdrawReason::Expired)],
            "the pinned word for a deletion at the uncertain deadline is `expired`"
        );
        assert_eq!(
            phone.phase(request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::ExpiredUnconfirmed
            }
        );
        assert!(
            phone.now() >= deadline,
            "the deletion happened at or after the recorded deadline, never before it"
        );
        assert!(
            !photo.path.exists(),
            "Rust deletes the photograph bytes when the uncertain deadline falls due"
        );
        assert!(
            phone.events.delivered.lock().expect("delivered").is_empty(),
            "an uncertain photograph is never reported delivered"
        );
    }

    #[tokio::test]
    async fn the_durable_row_is_the_only_retention_clock_for_a_final_photograph() {
        let phone = phone();
        let attached = phone.now();
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");

        let photo =
            verified_photo(&path, &phone.photo_root, sha256, 12, 12, attached).expect("photograph");

        assert_eq!(
            photo.delete_deadline_unix_ms,
            attached + CAPTURE_PHOTO_DELETE_AFTER_MS,
            "the persisted deadline is anchored once, when the final photograph is attached"
        );
    }

    #[tokio::test]
    async fn an_idle_phone_arms_no_timer_at_all() {
        // Invariant 12. With nothing pending there is no instant to wait for, so the loop waits on
        // a transition and nothing else: no sweep, no interval, no wakeup.
        let phone = phone();
        assert_eq!(phone.inner().next_deadline().expect("next deadline"), None);

        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + 1_000);
        assert_eq!(
            phone.inner().next_deadline().expect("next deadline"),
            Some(now + 1_000)
        );

        phone
            .store()
            .terminate_capture_source(record.request_id, CaptureSourceTerminalCode::Declined)
            .expect("declined");
        assert_eq!(phone.inner().next_deadline().expect("next deadline"), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_that_arrived_over_the_network_has_its_expiry_armed() {
        // The receiver that stores the row lives in another crate and knows nothing about this
        // timer. Without the wake on the presented event the loop would still be waiting on the
        // transition that already happened, and the request would outlive its expiry untouched.
        let phone = phone();
        let requester = DeviceId::new();
        phone.pair(
            requester,
            [4_u8; 32],
            "CEDAR-desk",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x04),
        );
        let now = phone.now();
        let request = CaptureRequest::photo(
            CaptureRequestId::new(),
            requester,
            phone.local(),
            now,
            now + 250,
            PURPOSE,
        );
        let config = phone.inner().server_config();
        let ack = config
            .capture_receiver
            .handle_capture_request(requester, "ignored", phone.local(), request.clone())
            .await
            .expect("acknowledgement");
        assert_eq!(ack.code, CaptureAckCode::Presented);

        let withdrawn = until(|| {
            let withdrawals = phone.events.withdrawals();
            (!withdrawals.is_empty()).then_some(withdrawals)
        })
        .await;

        assert_eq!(
            withdrawn,
            vec![(request.request_id, CaptureWithdrawReason::Expired)]
        );
    }

    // --- startup ----------------------------------------------------------------------------

    #[tokio::test]
    async fn startup_presents_the_one_request_still_waiting_for_a_photograph() {
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);

        let report = phone.resident.reconcile().expect("reconcile");

        assert_eq!(report.represented, Some(record.request_id));
        assert_eq!(phone.events.presented_ids(), vec![record.request_id]);
        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Presented
        );
        assert!(report.withdrawn.is_empty());
    }

    #[tokio::test]
    async fn startup_never_reopens_the_camera_for_a_request_already_photographed() {
        // Reconstruction is of one durable request, not a queue and not a replay. A request whose
        // photograph was taken but never delivered is ended, not offered to the camera again.
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        let (path, sha256) = phone.photo("router.jpg", b"a plausible jpeg body");
        let photo =
            verified_photo(&path, &phone.photo_root, sha256, 12, 12, now).expect("photograph");
        phone
            .store()
            .attach_captured(record.request_id, photo)
            .expect("attached");

        let report = phone.resident.reconcile().expect("reconcile");

        assert_eq!(report.represented, None);
        assert!(
            phone.events.presented_ids().is_empty(),
            "an already photographed request is never presented again"
        );
        assert_eq!(report.withdrawn, vec![record.request_id]);
        assert_eq!(
            phone.events.withdrawals(),
            vec![(record.request_id, CaptureWithdrawReason::Failed)]
        );
    }

    #[tokio::test]
    async fn startup_ends_a_request_the_user_interface_cannot_show_again() {
        let phone = phone();
        let requester = DeviceId::new();
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);
        phone
            .events
            .refuse_presentation
            .store(true, Ordering::SeqCst);

        let report = phone.resident.reconcile().expect("reconcile");

        assert_eq!(report.represented, None);
        assert_eq!(report.withdrawn, vec![record.request_id]);
        assert_eq!(
            phone.phase(record.request_id),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );
    }

    // --- pairing ----------------------------------------------------------------------------

    fn approval(peer: &InstallationIdentity, expires_at_unix_ms: u64) -> ApprovedPending {
        ApprovedPending {
            approval: pairing::ApprovedPending {
                pairing_id: pairing_id(0x0a),
                transcript_hash: transcript(0x0b),
                peer_device_id: peer.device_id,
                peer_public_key: peer.public_key(),
                peer_device_name: "CEDAR-desk".to_owned(),
                approved_at_unix_ms: expires_at_unix_ms.saturating_sub(1_000),
                expires_at_unix_ms,
            },
            observed_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn pairing_hello(peer: &InstallationIdentity) -> ClientHello {
        ClientHello::signed_v2_with_capabilities(
            peer.device_id,
            "CEDAR-desk",
            "resume",
            vec![CAP_PAIRING_V1.to_owned()],
            peer,
        )
    }

    #[tokio::test]
    async fn startup_restores_an_approval_that_can_still_complete() {
        // A12. The person already compared the codes; if the desktop's commit was lost, it may
        // resume that exact transcript without a second comparison, even with the window shut.
        let phone = phone();
        let peer = InstallationIdentity::generate();
        let pending = approval(&peer, phone.now() + 30_000);
        phone
            .inner()
            .trust
            .update(phone.local(), |state| {
                state.pending_pairing = Some(pending);
                Ok(())
            })
            .expect("store approval");

        let report = phone.resident.reconcile().expect("reconcile");

        assert!(!report.cleared_stale_pairing_approval);
        let config = phone.inner().server_config();
        let gate = config.pairing.expect("pairing").gate;
        assert!(
            gate.admit(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51_000),
                &pairing_hello(&peer)
            )
            .is_ok(),
            "a stored approval must still be completable after a restart"
        );
    }

    #[tokio::test]
    async fn startup_clears_an_approval_that_can_no_longer_complete() {
        // Nothing else ever clears one, and an approval past its deadline authorizes nothing. Left
        // in place it would sit in state.json indefinitely as an admission path with no window.
        let phone = phone();
        let peer = InstallationIdentity::generate();
        let pending = approval(&peer, phone.now().saturating_sub(200_000));
        phone
            .inner()
            .trust
            .update(phone.local(), |state| {
                state.pending_pairing = Some(pending);
                Ok(())
            })
            .expect("store approval");

        let report = phone.resident.reconcile().expect("reconcile");

        assert!(report.cleared_stale_pairing_approval);
        assert!(
            phone
                .inner()
                .trust
                .load_for_identity(phone.local())
                .expect("state")
                .pending_pairing
                .is_none()
        );
        let config = phone.inner().server_config();
        let gate = config.pairing.expect("pairing").gate;
        assert!(
            gate.admit(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51_001),
                &pairing_hello(&peer)
            )
            .is_err(),
            "a lapsed approval must admit nothing"
        );
    }

    #[tokio::test]
    async fn a_completed_pairing_names_the_peer_from_the_record_it_just_wrote() {
        // The name shown for a new peer must be the one bound to the transcript the person
        // confirmed, not the one the connection claimed. Only a completed pairing admits a peer.
        let phone = phone();
        let requester = DeviceId::new();
        let id = pairing_id(0x0c);
        phone.pair(
            requester,
            [6_u8; 32],
            "CEDAR-desk",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            id,
        );
        let reports = PairingReports {
            events: Arc::clone(&phone.events) as Arc<dyn PhoneEvents>,
            trust: phone.inner().trust.clone(),
            local_device: phone.local(),
        };

        // The same pairing id as the stored record, so only the result distinguishes the two
        // calls: a re-pairing the person declines must not re-admit the peer it would have named.
        reports.on_finished(id, PairingResult::Declined);
        assert!(
            phone.events.admitted.lock().expect("admitted").is_empty(),
            "a pairing that did not complete admits nobody"
        );

        reports.on_finished(id, PairingResult::Paired);
        assert_eq!(
            *phone.events.admitted.lock().expect("admitted"),
            vec!["CEDAR-desk".to_owned()]
        );
        assert_eq!(
            *phone.events.finished.lock().expect("finished"),
            vec![(id, PairingResult::Declined), (id, PairingResult::Paired)]
        );
    }

    #[tokio::test]
    async fn the_pairing_window_refuses_an_expiry_outside_the_protocol_maximum() {
        let phone = phone();
        let now = phone.now();
        assert!(phone.resident.open_pairing_window(now - 1).is_err());
        assert!(phone.resident.open_pairing_window(now + 200_000).is_err());
        phone
            .resident
            .open_pairing_window(now + 60_000)
            .expect("opened");
        assert_eq!(
            phone.resident.status().pairing_window_expires_at_unix_ms,
            Some(now + 60_000)
        );
        // A13: closing twice, and closing an expired window, are no-ops rather than errors.
        phone.resident.close_pairing_window();
        phone.resident.close_pairing_window();
        assert_eq!(
            phone.resident.status().pairing_window_expires_at_unix_ms,
            None
        );
    }

    // --- status -----------------------------------------------------------------------------

    #[tokio::test]
    async fn status_reports_the_live_request_and_the_paired_peers() {
        let phone = phone();
        let requester = DeviceId::new();
        assert_eq!(phone.resident.status(), PhoneStatus::default());

        phone.pair(
            requester,
            [8_u8; 32],
            "CEDAR-desk",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pairing_id(0x0e),
        );
        let now = phone.now();
        let record = phone.present_row(requester, now, now + LIFETIME_MS);

        let status = phone.resident.status();
        assert_eq!(status.live_request, Ok(Some(record.request_id)));
        assert_eq!(status.paired_peers, Ok(1));
        assert!(!status.listening);
        assert_eq!(status.failures, PhoneFailures::default());
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_closes_the_pairing_window() {
        let phone = phone();
        phone
            .resident
            .open_pairing_window(phone.now() + 60_000)
            .expect("opened");
        phone.resident.shutdown();
        phone.resident.shutdown();
        assert_eq!(
            phone.resident.status().pairing_window_expires_at_unix_ms,
            None
        );
    }
    // --- ABI-8 shelf contract ---------------------------------------------------------------

    /// Refuses every dial, so a test that must not reach the network cannot, and records what the
    /// resident tried to dial.
    #[derive(Default)]
    struct RoutedConnector {
        routes: Mutex<std::collections::HashMap<IpAddr, SocketAddr>>,
        dialed: Mutex<Vec<SocketAddr>>,
    }

    impl RoutedConnector {
        fn dials(&self) -> usize {
            self.dialed.lock().expect("dialed").len()
        }
    }

    impl SocketConnector for RoutedConnector {
        fn connect<'life0, 'async_trait>(
            &'life0 self,
            address: SocketAddr,
        ) -> Pin<
            Box<dyn Future<Output = std::io::Result<tokio::net::TcpStream>> + Send + 'async_trait>,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            self.dialed.lock().expect("dialed").push(address);
            let route = self
                .routes
                .lock()
                .expect("routes")
                .get(&address.ip())
                .copied();
            Box::pin(async move {
                match route {
                    Some(to) => tokio::net::TcpStream::connect(to).await,
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "no route to this peer in this test",
                    )),
                }
            })
        }
    }

    /// Answers announcements with one code and records, for each, whether the phone had already
    /// stored its own card and source when the announcement arrived.
    struct ObservingAnnouncements {
        code: OfferAckCode,
        phone_store: Arc<RedbV2Store>,
        phone_device: DeviceId,
        seen: Arc<Mutex<Vec<(OfferAnnouncement, bool)>>>,
    }

    impl V2AnnouncementReceiver for ObservingAnnouncements {
        fn handle_announcement<'life0, 'async_trait>(
            &'life0 self,
            _authenticated_source: DeviceId,
            _listener_device: DeviceId,
            announcement: OfferAnnouncement,
        ) -> Pin<Box<dyn Future<Output = Result<OfferAck, NetError>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let durable = self
                    .phone_store
                    .get_offer_card(self.phone_device, announcement.offer_id)
                    .expect("phone card read")
                    .is_some()
                    && self
                        .phone_store
                        .get_offer_source(announcement.offer_id)
                        .expect("phone source read")
                        .is_some();
                let ack = OfferAck {
                    offer_id: announcement.offer_id,
                    code: self.code.clone(),
                    live_entries: 0,
                    max_live_entries: V2_MAX_LIVE_ENTRIES,
                    pruned_entries: 0,
                    detail: None,
                };
                self.seen
                    .lock()
                    .expect("announcements")
                    .push((announcement, durable));
                Ok(ack)
            })
        }
    }

    struct RoutedPeer {
        identity: InstallationIdentity,
        seen: Arc<Mutex<Vec<(OfferAnnouncement, bool)>>>,
        _shutdown: watch::Sender<bool>,
    }

    /// A trusted peer at a Tailscale-shaped address, served by a real protocol-2 listener the
    /// connector routes to. `catalog` makes it a catalog origin; without one it is a desktop that
    /// predates the catalog and does not advertise it.
    async fn routed_peer(
        phone: &Phone,
        connector: &RoutedConnector,
        hostname: &str,
        octet: u8,
        ack: OfferAckCode,
        catalog: Option<Arc<RedbV2Store>>,
    ) -> RoutedPeer {
        let identity = InstallationIdentity::generate();
        let address = IpAddr::V4(Ipv4Addr::new(100, 64, 0, octet));
        phone.pair(
            identity.device_id,
            identity.public_key(),
            hostname,
            address,
            pairing_id(octet),
        );
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind peer");
        connector
            .routes
            .lock()
            .expect("routes")
            .insert(address, listener.local_addr().expect("peer address"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut config = V2ServerConfig::desktop(
            ServerIdentity {
                signing_identity: identity.clone(),
                device_name: hostname.to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new([phone.local()])),
            V2OfferServices {
                announcement_receiver: Arc::new(ObservingAnnouncements {
                    code: ack,
                    phone_store: Arc::clone(phone.store()),
                    phone_device: phone.local(),
                    seen: Arc::clone(&seen),
                }),
                fetch_sender: Arc::new(OfferFetchHandler::with_resolver(
                    identity.device_id,
                    Arc::new(NoFetchSources),
                )),
            },
            Duration::from_secs(5),
        );
        match catalog {
            Some(store) => {
                config = config.with_catalog_origin(Arc::new(StoreCatalogOrigin::new(
                    store,
                    identity.device_id,
                )));
            }
            // A desktop that predates the catalog: it does not advertise `shelf-catalog-v1`.
            None => config
                .server_capabilities
                .retain(|capability| capability != CAP_SHELF_CATALOG_V1),
        }
        let (shutdown, stop) = watch::channel(false);
        tokio::spawn(async move {
            let _ = serve_v2(listener, config, stop).await;
        });
        RoutedPeer {
            identity,
            seen,
            _shutdown: shutdown,
        }
    }

    /// A trusted peer nobody can reach.
    fn unreachable_peer(phone: &Phone, hostname: &str, octet: u8) -> DeviceId {
        let identity = InstallationIdentity::generate();
        phone.pair(
            identity.device_id,
            identity.public_key(),
            hostname,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, octet)),
            pairing_id(octet),
        );
        identity.device_id
    }

    /// The phone's platform, recorded. At each callback it records whether the side-effect intent
    /// was already durable in the activation journal, and can fail, go uncertain, or crash there.
    struct PlatformDouble {
        store: Arc<RedbV2Store>,
        texts: Mutex<Vec<String>>,
        files: Mutex<Vec<(PathBuf, Vec<u8>)>>,
        intent_journaled: Mutex<Vec<bool>>,
        fail_with: Mutex<Option<ClipboardError>>,
        hold: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl PlatformDouble {
        fn new(phone: &Phone) -> Arc<Self> {
            Arc::new(Self {
                store: Arc::clone(phone.store()),
                texts: Mutex::new(Vec::new()),
                files: Mutex::new(Vec::new()),
                intent_journaled: Mutex::new(Vec::new()),
                fail_with: Mutex::new(None),
                hold: Mutex::new(None),
            })
        }

        fn failing(phone: &Phone, error: ClipboardError) -> Arc<Self> {
            let double = Self::new(phone);
            *double.fail_with.lock().expect("fail") = Some(error);
            double
        }

        fn dispatch(&self) -> Result<(), ClipboardError> {
            self.intent_journaled
                .lock()
                .expect("journaled")
                // A clipboard write being applied means its intent was journaled first.
                .push(
                    self.store
                        .clipboard_fence(DeviceId::new(), OfferId::new())
                        .expect("journal")
                        == meshelf_core::ClipboardFence::Busy,
                );
            if let Some(hold) = self.hold.lock().expect("hold").take() {
                // The process dies here: the test aborts the activation while this callback runs.
                let _ = hold.recv();
            }
            self.fail_with
                .lock()
                .expect("fail")
                .take()
                .map_or(Ok(()), Err)
        }

        fn dispatches(&self) -> usize {
            self.texts.lock().expect("texts").len() + self.files.lock().expect("files").len()
        }
    }

    impl ClipboardSink for PlatformDouble {
        fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
            self.texts.lock().expect("texts").push(text.to_owned());
            self.dispatch()
        }
    }

    impl FetchClipboard for PlatformDouble {
        fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
            let bytes = std::fs::read(&paths[0]).expect("exported file is readable");
            self.files
                .lock()
                .expect("files")
                .push((paths[0].clone(), bytes));
            self.dispatch()
        }
    }

    fn offline_phone() -> (Phone, Arc<RoutedConnector>) {
        let connector = Arc::new(RoutedConnector::default());
        let phone = phone_with_connector(Some(Arc::clone(&connector) as Arc<dyn SocketConnector>));
        unreachable_peer(&phone, "CEDAR", 9);
        (phone, connector)
    }

    async fn own_photo(phone: &Phone, bytes: &[u8]) -> (OfferId, PathBuf) {
        let reserved: serde_json::Value = serde_json::from_str(
            &phone
                .resident
                .reserve_ordinary_photo("own-photo")
                .expect("reserve"),
        )
        .expect("reservation json");
        let final_path = PathBuf::from(reserved["finalPath"].as_str().expect("final path"));
        std::fs::write(&final_path, bytes).expect("write photo");
        let hex: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let result = phone
            .resident
            .commit_ordinary_photo(reserved["leaseId"].as_str().expect("lease"), &hex, 4, 3)
            .await
            .expect("commit");
        (result.offer_id, final_path)
    }

    fn snapshot_card(snapshot: &serde_json::Value, offer_id: OfferId) -> serde_json::Value {
        snapshot["cards"]
            .as_array()
            .expect("cards")
            .iter()
            .find(|card| card["offerId"] == offer_id.to_string())
            .cloned()
            .expect("card in snapshot")
    }

    fn receive_card(
        phone: &Phone,
        source: DeviceId,
        descriptor: OfferDescriptor,
        availability: CardAvailability,
    ) -> OfferId {
        let offer_id = OfferId::new();
        phone
            .store()
            .insert_offer_card_on_ordinary_index(
                OfferCardInput::new(source, offer_id, descriptor, availability),
                Some(phone.local()),
            )
            .expect("received card");
        offer_id
    }

    /// Every card field is Rust's to derive: own cards are named by this phone, received cards by
    /// the trust registry and otherwise "Unknown device"; photos are PHOTO only by class; folders
    /// are unsupported; actions exist only for ready cards; and no path or UUID stands in for a
    /// name.
    #[tokio::test]
    async fn snapshot_v2_derives_every_card_field_for_own_and_received_cards() {
        let (phone, _connector) = offline_phone();
        let cedar = phone
            .inner()
            .trust
            .load_for_identity(phone.local())
            .expect("trust")
            .peers
            .peers()[0]
            .device_id;
        let stranger = DeviceId::new();
        let own_text = phone
            .resident
            .announce_text("own clipboard words")
            .await
            .expect("announce")
            .offer_id;
        let (own_photo_id, photo_path) = own_photo(&phone, b"own-jpeg").await;
        let received_text = receive_card(
            &phone,
            cedar,
            OfferDescriptor::text("from the desk").expect("text"),
            CardAvailability::Available,
        );
        let received_file = receive_card(
            &phone,
            cedar,
            OfferDescriptor::File {
                root_name: "report.pdf".to_owned(),
                total_bytes: 42,
                content_class: FileContentClass::File,
            },
            CardAvailability::Available,
        );
        let received_photo = receive_card(
            &phone,
            cedar,
            OfferDescriptor::File {
                root_name: "IMG_9.jpg".to_owned(),
                total_bytes: 7,
                content_class: FileContentClass::Photo,
            },
            CardAvailability::Available,
        );
        phone
            .store()
            .record_offer_attempt(
                cedar,
                received_photo,
                OfferAttemptStatus::new(
                    OfferAttemptCode::SourceUnavailable,
                    1,
                    0,
                    0,
                    Some("origin offline".to_owned()),
                )
                .expect("attempt"),
            )
            .expect("record attempt");
        let stranger_folder = receive_card(
            &phone,
            stranger,
            OfferDescriptor::Folder {
                root_name: "Projects".to_owned(),
                total_bytes: 10,
                entry_count: 1,
                file_count: 1,
                directory_count: 0,
            },
            CardAvailability::Available,
        );

        let json = phone.resident.shelf_snapshot_json().expect("snapshot");
        let snapshot: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(snapshot["schemaVersion"], 2);
        assert_eq!(snapshot["ready"], true);
        assert_eq!(snapshot["completeness"], "COMPLETE");
        assert_eq!(snapshot["localDisplayName"], "amber");
        assert_eq!(snapshot["peerObservation"]["trigger"], "ANNOUNCE");
        let sequences: Vec<u64> = snapshot["cards"]
            .as_array()
            .expect("cards")
            .iter()
            .map(|card| card["shelfSequence"].as_u64().expect("sequence"))
            .collect();
        assert_eq!(sequences.len(), 6);
        assert!(
            sequences.windows(2).all(|pair| pair[0] > pair[1]),
            "newest first: {sequences:?}"
        );

        let card = snapshot_card(&snapshot, own_text);
        assert_eq!(card["ownership"], "OWN");
        assert_eq!(card["sourceDisplayName"], "amber");
        assert_eq!(card["kind"], "TEXT");
        assert_eq!(card["preview"], "own clipboard words");
        assert_eq!(card["displayName"], "");
        assert_eq!(card["byteLength"], 19);
        assert_eq!(card["availability"], "READY");
        assert_eq!(card["supportedActions"], serde_json::json!(["COPY_TEXT"]));
        assert!(card["activeOperation"].is_null());
        assert!(card["lastAttempt"].is_null());

        let card = snapshot_card(&snapshot, own_photo_id);
        assert_eq!(card["ownership"], "OWN");
        assert_eq!(card["sourceDisplayName"], "amber");
        assert_eq!(card["kind"], "PHOTO");
        assert_eq!(
            card["supportedActions"],
            serde_json::json!(["SHARE_FILE", "SAVE_FILE"])
        );

        let card = snapshot_card(&snapshot, received_text);
        assert_eq!(card["ownership"], "RECEIVED");
        assert_eq!(card["sourceDisplayName"], "CEDAR");
        assert_eq!(card["kind"], "TEXT");

        let card = snapshot_card(&snapshot, received_file);
        assert_eq!(card["kind"], "FILE");
        assert_eq!(card["displayName"], "report.pdf");
        assert_eq!(card["preview"], "");
        assert_eq!(card["byteLength"], 42);
        assert_eq!(
            card["supportedActions"],
            serde_json::json!(["SHARE_FILE", "SAVE_FILE"])
        );

        let card = snapshot_card(&snapshot, received_photo);
        assert_eq!(card["kind"], "PHOTO");
        assert_eq!(card["availability"], "SOURCE_OFFLINE");
        assert_eq!(card["supportedActions"], serde_json::json!([]));
        assert_eq!(card["lastAttempt"]["code"], "SOURCE_UNAVAILABLE");
        assert_eq!(card["lastAttempt"]["attemptSequence"], 1);
        assert_eq!(card["lastAttempt"]["detail"], "origin offline");

        let card = snapshot_card(&snapshot, stranger_folder);
        assert_eq!(card["kind"], "FOLDER");
        assert_eq!(card["sourceDisplayName"], UNKNOWN_DEVICE_NAME);
        assert_ne!(card["sourceDisplayName"], stranger.to_string());
        assert_eq!(card["availability"], "UNSUPPORTED");
        assert_eq!(card["supportedActions"], serde_json::json!([]));

        let photo_path = photo_path.to_string_lossy().into_owned();
        assert!(
            !json.contains(&photo_path),
            "a snapshot never carries a path"
        );
    }

    /// The serializer itself refuses a shelf the contract says cannot exist: an eleventh card or a
    /// repeated card key, while ten distinct cards serialize.
    #[test]
    fn snapshot_serializer_refuses_eleven_cards_and_duplicate_keys() {
        let local = DeviceId::new();
        let record = |sequence| OfferCardRecord {
            source_device: DeviceId::new(),
            offer_id: OfferId::new(),
            descriptor: OfferDescriptor::text("card").expect("text"),
            received_sequence: sequence,
            availability: CardAvailability::Available,
            last_attempt: None,
        };
        let names = std::collections::HashMap::new();
        // Newest first, as the store orders them.
        let ten: Vec<_> = (1..=10).rev().map(record).collect();
        assert!(shelf_snapshot(local, "amber", &ten, &names, None).is_ok());

        let mut eleven = vec![record(11)];
        eleven.extend(ten.iter().cloned());
        assert!(matches!(
            shelf_snapshot(local, "amber", &eleven, &names, None),
            Err(PhoneError::Configuration(detail)) if detail.contains("11 cards")
        ));

        let mut repeated = ten[..9].to_vec();
        let mut copy = repeated[0].clone();
        copy.received_sequence = 1;
        repeated.push(copy);
        assert!(matches!(
            shelf_snapshot(local, "amber", &repeated, &names, None),
            Err(PhoneError::Configuration(detail)) if detail.contains("repeats")
        ));
    }

    /// One refresh against a catalog origin, a peer without catalog support, and a peer nobody can
    /// reach: the unsupported answer is still reachable, the dead dial is unavailable, the one
    /// applied card is counted, and the observation stays for later snapshots of this run.
    #[tokio::test]
    async fn refresh_observes_applied_unsupported_and_transport_failed_peers() {
        let connector = Arc::new(RoutedConnector::default());
        let phone = phone_with_connector(Some(Arc::clone(&connector) as Arc<dyn SocketConnector>));
        let origin_directory = tempfile::tempdir().expect("origin directory");
        let origin_store = Arc::new(
            RedbV2Store::open(origin_directory.path().join("meshelf.redb")).expect("origin store"),
        );
        let applied = routed_peer(
            &phone,
            &connector,
            "CEDAR",
            1,
            OfferAckCode::Stored,
            Some(Arc::clone(&origin_store)),
        )
        .await;
        origin_store
            .insert_owned_ordinary(
                applied.identity.device_id,
                OfferSourceInput::new(
                    OfferId::new(),
                    OfferDescriptor::text("caught up while closed").expect("text"),
                    std::collections::HashSet::new(),
                    OfferSource::Text {
                        text: "caught up while closed".to_owned(),
                    },
                ),
            )
            .expect("origin offer");
        let unsupported =
            routed_peer(&phone, &connector, "FERN", 2, OfferAckCode::Stored, None).await;
        let unreachable = unreachable_peer(&phone, "BIRCH", 3);

        let refreshed: serde_json::Value = serde_json::from_str(
            &phone
                .resident
                .refresh_origin_catalogs()
                .await
                .expect("refresh"),
        )
        .expect("refresh json");
        assert_eq!(refreshed["schemaVersion"], 2);
        assert_eq!(refreshed["newItems"], 1);
        let snapshot = &refreshed["snapshot"];
        assert_eq!(snapshot["schemaVersion"], 2);
        assert_eq!(snapshot["cards"].as_array().expect("cards").len(), 1);
        assert_eq!(snapshot["cards"][0]["sourceDisplayName"], "CEDAR");
        assert_eq!(snapshot["cards"][0]["ownership"], "RECEIVED");
        let observation = &snapshot["peerObservation"];
        assert_eq!(observation["trigger"], "REFRESH");
        let peer = |device: DeviceId| {
            observation["peers"]
                .as_array()
                .expect("peers")
                .iter()
                .find(|entry| entry["deviceId"] == device.to_string())
                .cloned()
                .expect("observed peer")
        };
        let entry = peer(applied.identity.device_id);
        assert_eq!(entry["displayName"], "CEDAR");
        assert_eq!(entry["reachability"], "REACHABLE");
        assert_eq!(entry["outcome"], "CATALOG_APPLIED");
        let entry = peer(unsupported.identity.device_id);
        assert_eq!(entry["displayName"], "FERN");
        assert_eq!(entry["reachability"], "REACHABLE");
        assert_eq!(entry["outcome"], "CATALOG_UNSUPPORTED");
        let entry = peer(unreachable);
        assert_eq!(entry["displayName"], "BIRCH");
        assert_eq!(entry["reachability"], "UNAVAILABLE");
        assert_eq!(entry["outcome"], "TRANSPORT_FAILED");

        let later: serde_json::Value =
            serde_json::from_str(&phone.resident.shelf_snapshot_json().expect("snapshot"))
                .expect("json");
        assert_eq!(later["peerObservation"], *observation);
    }

    /// An announce stores the own card and source before the first peer hears of it, then counts
    /// each peer once: one stored, one refused, one unreachable. Nothing is retried.
    #[tokio::test]
    async fn announce_counts_partial_success_after_storing_the_own_card_first() {
        let connector = Arc::new(RoutedConnector::default());
        let phone = phone_with_connector(Some(Arc::clone(&connector) as Arc<dyn SocketConnector>));
        let stored = routed_peer(&phone, &connector, "CEDAR", 1, OfferAckCode::Stored, None).await;
        let refused = routed_peer(
            &phone,
            &connector,
            "FERN",
            2,
            OfferAckCode::RefusedCapacity,
            None,
        )
        .await;
        let unreachable = unreachable_peer(&phone, "BIRCH", 3);

        let result = phone
            .resident
            .announce_text("partial fanout")
            .await
            .expect("announce");
        assert!(result.local_stored);
        assert_eq!(
            (
                result.added_count,
                result.refused_count,
                result.unavailable_count
            ),
            (1, 1, 1)
        );
        let outcome = |device: DeviceId| {
            result
                .peers
                .iter()
                .find(|entry| entry.device_id == device)
                .map(|entry| (entry.reachability, entry.outcome))
                .expect("peer entry")
        };
        assert_eq!(
            outcome(stored.identity.device_id),
            (Reachability::Reachable, PeerOutcome::Stored)
        );
        assert_eq!(
            outcome(refused.identity.device_id),
            (Reachability::Reachable, PeerOutcome::Refused)
        );
        assert_eq!(
            outcome(unreachable),
            (Reachability::Unavailable, PeerOutcome::TransportFailed)
        );
        let seen = stored.seen.lock().expect("seen").clone();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].1, "own card and source were durable before fanout");
        assert_eq!(
            connector.dials(),
            3,
            "each peer is dialed once, never retried"
        );

        let json: serde_json::Value =
            serde_json::from_str(&result.to_json().expect("json")).expect("parse");
        assert_eq!(json["schemaVersion"], 2);
        assert_eq!(json["offerId"], result.offer_id.to_string());
        assert_eq!(json["localStored"], true);
        assert_eq!(json["addedCount"], 1);
        assert_eq!(json["refusedCount"], 1);
        assert_eq!(json["unavailableCount"], 1);
        let snapshot: serde_json::Value =
            serde_json::from_str(&phone.resident.shelf_snapshot_json().expect("snapshot"))
                .expect("json");
        assert_eq!(snapshot["peerObservation"]["trigger"], "ANNOUNCE");
        assert_eq!(
            snapshot["peerObservation"]["peers"]
                .as_array()
                .expect("peers")
                .len(),
            3
        );
    }

    /// Camera commits and gallery documents are photos by the path that created them, and the
    /// class reaches peers in the announcement itself.
    #[tokio::test]
    async fn camera_and_gallery_offers_are_announced_as_photos() {
        let connector = Arc::new(RoutedConnector::default());
        let lease_id = meshelf_core::DocumentLeaseId::new();
        let directory = tempfile::tempdir().expect("gallery");
        let gallery = directory.path().join("picked.jpg");
        std::fs::write(&gallery, b"picked").expect("gallery file");
        let phone = phone_with(
            Some(Arc::clone(&connector) as Arc<dyn SocketConnector>),
            Some(Arc::new(TempFileDocuments {
                files: Mutex::new(std::collections::HashMap::from([(lease_id, gallery)])),
            })),
        );
        let peer = routed_peer(&phone, &connector, "CEDAR", 1, OfferAckCode::Stored, None).await;
        let (camera, _) = own_photo(&phone, b"camera-jpeg").await;
        let picked = phone
            .resident
            .announce_document(&lease_id.to_string(), "picked.jpg", 6)
            .await
            .expect("document")
            .offer_id;
        for offer_id in [camera, picked] {
            let card = phone
                .store()
                .get_offer_card(phone.local(), offer_id)
                .expect("read")
                .expect("own card");
            assert!(matches!(
                card.descriptor,
                OfferDescriptor::File {
                    content_class: FileContentClass::Photo,
                    ..
                }
            ));
        }
        let classes: Vec<_> = peer
            .seen
            .lock()
            .expect("seen")
            .iter()
            .map(|(announcement, _)| announcement.descriptor.clone())
            .collect();
        assert_eq!(classes.len(), 2);
        assert!(classes.iter().all(|descriptor| matches!(
            descriptor,
            OfferDescriptor::File {
                content_class: FileContentClass::Photo,
                ..
            }
        )));
    }

    /// An own text card is copied from the text this phone stored, through the journaled platform
    /// dispatch, without dialing anyone, and the Android clipboard is never read.
    #[tokio::test]
    async fn own_text_copy_uses_the_stored_text_and_the_dispatch_journal_without_dialing() {
        let (phone, connector) = offline_phone();
        let offer_id = phone
            .resident
            .announce_text("copied from storage")
            .await
            .expect("announce")
            .offer_id;
        let dials = connector.dials();
        let platform = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                offer_id,
                ShelfAction::CopyText,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.status, ActivationStatus::Completed, "{report:?}");
        assert_eq!(report.code, ActivationCode::Completed);
        assert_eq!(report.bytes_processed, 19);
        assert_eq!(report.detail, None);
        assert_eq!(
            *platform.texts.lock().expect("texts"),
            vec!["copied from storage".to_owned()]
        );
        assert_eq!(
            *platform.intent_journaled.lock().expect("journaled"),
            vec![true],
            "the intent was durable before the platform callback"
        );
        assert_eq!(connector.dials(), dials, "an own card dials no one");
        assert!(
            phone
                .store()
                .clipboard_fence(phone.local(), offer_id)
                .expect("journal")
                == meshelf_core::ClipboardFence::Clear,
            "a completed dispatch retires its journal"
        );
        let json: serde_json::Value =
            serde_json::from_str(&report.to_json().expect("json")).expect("parse");
        assert_eq!(json["sourceDevice"], phone.local().to_string());
        assert_eq!(json["action"], "COPY_TEXT");
        assert_eq!(json["status"], "COMPLETED");
        let snapshot: serde_json::Value =
            serde_json::from_str(&phone.resident.shelf_snapshot_json().expect("snapshot"))
                .expect("json");
        assert_eq!(
            snapshot_card(&snapshot, offer_id)["lastAttempt"]["code"],
            "COMPLETED"
        );
    }

    /// Sharing an own camera photo hands the platform a verified staged copy of the original, and
    /// the original the shelf retains is untouched.
    #[tokio::test]
    async fn own_photo_share_exports_a_verified_copy_and_keeps_the_original() {
        let (phone, connector) = offline_phone();
        let bytes = b"own camera original bytes";
        let (offer_id, original) = own_photo(&phone, bytes).await;
        let dials = connector.dials();
        let platform = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                offer_id,
                ShelfAction::ShareFile,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.status, ActivationStatus::Completed, "{report:?}");
        assert_eq!(
            (report.files_processed, report.bytes_processed),
            (1, bytes.len() as u64)
        );
        let files = platform.files.lock().expect("files").clone();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].1, bytes);
        assert_ne!(files[0].0, original, "the platform gets a copy");
        assert_eq!(std::fs::read(&original).expect("original"), bytes);
        assert_eq!(
            *platform.intent_journaled.lock().expect("journaled"),
            vec![true]
        );
        assert_eq!(connector.dials(), dials);
    }

    /// Saving an own gallery document reads it through the granted lease only, and a lease that
    /// no longer matches is SOURCE_CHANGED with nothing dispatched.
    #[tokio::test]
    async fn own_document_save_reads_through_the_lease_and_a_changed_lease_is_refused() {
        let lease_id = meshelf_core::DocumentLeaseId::new();
        let directory = tempfile::tempdir().expect("gallery");
        let gallery = directory.path().join("gallery.jpg");
        let bytes = b"granted gallery bytes";
        std::fs::write(&gallery, bytes).expect("gallery file");
        let connector = Arc::new(RoutedConnector::default());
        let phone = phone_with(
            Some(Arc::clone(&connector) as Arc<dyn SocketConnector>),
            Some(Arc::new(TempFileDocuments {
                files: Mutex::new(std::collections::HashMap::from([(
                    lease_id,
                    gallery.clone(),
                )])),
            })),
        );
        unreachable_peer(&phone, "CEDAR", 9);
        let offer_id = phone
            .resident
            .announce_document(&lease_id.to_string(), "gallery.jpg", bytes.len() as u64)
            .await
            .expect("document")
            .offer_id;
        let platform = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                offer_id,
                ShelfAction::SaveFile,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.status, ActivationStatus::Completed, "{report:?}");
        let files = platform.files.lock().expect("files").clone();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].1, bytes);

        // The provider sees a different document behind the same grant (Android compares size).
        std::fs::write(&gallery, b"edited").expect("edit gallery");
        let platform = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                offer_id,
                ShelfAction::SaveFile,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.status, ActivationStatus::Failed);
        assert_eq!(report.code, ActivationCode::SourceChanged);
        assert_eq!(platform.dispatches(), 0);
    }

    /// Failures are result codes, not errors: a deleted original is SOURCE_UNAVAILABLE and marks the
    /// card offline, a refused write is CLIPBOARD_FAILED, a wrong action is UNSUPPORTED, and a card
    /// from an unpaired device is SOURCE_UNAVAILABLE. None dispatches twice.
    #[tokio::test]
    async fn activation_failures_are_reported_as_contract_codes() {
        let (phone, _connector) = offline_phone();
        let (photo, original) = own_photo(&phone, b"will be deleted").await;
        std::fs::remove_file(&original).expect("delete original");
        let platform = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                photo,
                ShelfAction::ShareFile,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(
            (report.status, report.code),
            (ActivationStatus::Failed, ActivationCode::SourceUnavailable)
        );
        assert_eq!(platform.dispatches(), 0);
        let snapshot: serde_json::Value =
            serde_json::from_str(&phone.resident.shelf_snapshot_json().expect("snapshot"))
                .expect("json");
        assert_eq!(
            snapshot_card(&snapshot, photo)["availability"],
            "SOURCE_OFFLINE"
        );

        let text = phone
            .resident
            .announce_text("write refused")
            .await
            .expect("announce")
            .offer_id;
        let report = phone
            .resident
            .activate(
                phone.local(),
                text,
                ShelfAction::ShareFile,
                PlatformDouble::new(&phone) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.code, ActivationCode::Unsupported);

        let platform = PlatformDouble::failing(
            &phone,
            ClipboardError::new("platform clipboard write failed"),
        );
        let report = phone
            .resident
            .activate(
                phone.local(),
                text,
                ShelfAction::CopyText,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(
            (report.status, report.code),
            (ActivationStatus::Failed, ActivationCode::ClipboardFailed)
        );
        assert_eq!(platform.dispatches(), 1);
        assert_eq!(
            report.detail.as_deref(),
            Some("fetch service failed: platform clipboard write failed")
        );

        let stranger = receive_card(
            &phone,
            DeviceId::new(),
            OfferDescriptor::text("from nowhere").expect("text"),
            CardAvailability::Available,
        );
        let stranger_source = phone
            .store()
            .read_offer_shelf()
            .expect("shelf")
            .into_iter()
            .find(|card| card.offer_id == stranger)
            .expect("card")
            .source_device;
        let report = phone
            .resident
            .activate(
                stranger_source,
                stranger,
                ShelfAction::CopyText,
                PlatformDouble::new(&phone) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.code, ActivationCode::SourceUnavailable);
    }

    /// With no trusted peer the item stays on this phone instead of failing: the own card and
    /// source are stored and the result says no device was reached.
    #[tokio::test]
    async fn an_announce_with_no_trusted_peer_keeps_the_item_on_this_phone() {
        let phone = phone();
        let text = phone
            .resident
            .announce_text("kept here")
            .await
            .expect("announce with no peers");
        assert!(text.local_stored);
        assert_eq!(
            (text.added_count, text.unavailable_count, text.refused_count),
            (0, 0, 0)
        );
        assert!(text.peers.is_empty());
        assert!(
            phone
                .store()
                .get_offer_card(phone.local(), text.offer_id)
                .expect("card")
                .is_some()
        );

        let reserved: serde_json::Value = serde_json::from_str(
            &phone
                .resident
                .reserve_ordinary_photo("no-peer-photo")
                .expect("reserve"),
        )
        .expect("json");
        let lease_id = reserved["leaseId"].as_str().expect("lease id").to_owned();
        let final_path = PathBuf::from(reserved["finalPath"].as_str().expect("final path"));
        let bytes = b"photo with nowhere to go";
        std::fs::write(&final_path, bytes).expect("write photo");
        let hex: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let photo = phone
            .resident
            .commit_ordinary_photo(&lease_id, &hex, 4, 3)
            .await
            .expect("commit with no peers");
        assert!(photo.local_stored);
        assert!(photo.peers.is_empty());
        assert!(
            phone
                .store()
                .get_offer_card(phone.local(), photo.offer_id)
                .expect("card")
                .is_some()
        );
        assert!(
            final_path.exists(),
            "the photo is kept as the card's source"
        );
    }

    /// A process that died mid-write leaves its row `ApplyingClipboard`. The first activation after
    /// a restart must recover before it reads the fence, or that stale row reads as a live write
    /// and every card is refused as busy.
    #[tokio::test]
    async fn after_a_crash_other_cards_activate_and_only_the_crashed_card_is_fenced() {
        let (phone, _connector) = offline_phone();
        let crashed = phone
            .resident
            .announce_text("crashed mid-write")
            .await
            .expect("announce")
            .offer_id;
        let other = phone
            .resident
            .announce_text("still copies")
            .await
            .expect("announce")
            .offer_id;
        let activation_id = ActivationId::new();
        phone
            .store()
            .journal_activation(&meshelf_core::ActivationJournalEntry {
                activation_id,
                source_device: phone.local(),
                offer_id: crashed,
                mode: ActivationMode::Clipboard,
                staging_root: phone
                    .photo_root
                    .join("staging")
                    .join(activation_id.to_string()),
                state: meshelf_core::ActivationState::ApplyingClipboard,
                reserved_entries: 1,
                reserved_bytes: 17,
            })
            .expect("row left by the dead process");

        let platform = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                other,
                ShelfAction::CopyText,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(
            (report.status, report.code),
            (ActivationStatus::Completed, ActivationCode::Completed),
            "{report:?}"
        );
        assert_eq!(platform.dispatches(), 1);

        let again = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                crashed,
                ShelfAction::CopyText,
                Arc::clone(&again) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.code, ActivationCode::UncertainNoReplay);
        assert_eq!(again.dispatches(), 0, "the crashed write is never replayed");
    }

    /// O-028: a platform action that may have applied is UNCERTAIN and is never replayed. It
    /// fences only its own card; another card still copies.
    #[tokio::test]
    async fn an_uncertain_dispatch_is_reported_and_never_replayed() {
        let (phone, _connector) = offline_phone();
        let first = phone
            .resident
            .announce_text("maybe copied")
            .await
            .expect("announce")
            .offer_id;
        let second = phone
            .resident
            .announce_text("never dispatched")
            .await
            .expect("announce")
            .offer_id;
        let platform = PlatformDouble::failing(
            &phone,
            ClipboardError::uncertain("platform clipboard outcome was not reported"),
        );
        let report = phone
            .resident
            .activate(
                phone.local(),
                first,
                ShelfAction::CopyText,
                Arc::clone(&platform) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(
            (report.status, report.code),
            (
                ActivationStatus::Uncertain,
                ActivationCode::UncertainNoReplay
            )
        );
        assert_eq!(platform.dispatches(), 1);
        let snapshot: serde_json::Value =
            serde_json::from_str(&phone.resident.shelf_snapshot_json().expect("snapshot"))
                .expect("json");
        assert_eq!(
            snapshot_card(&snapshot, first)["lastAttempt"]["code"],
            "UNCERTAIN_NO_REPLAY"
        );

        let other = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                second,
                ShelfAction::CopyText,
                Arc::clone(&other) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(
            (report.status, report.code),
            (ActivationStatus::Completed, ActivationCode::Completed),
            "another card is a new explicit activation"
        );
        assert_eq!(other.dispatches(), 1);

        let again = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                first,
                ShelfAction::CopyText,
                Arc::clone(&again) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(
            (report.status, report.code),
            (ActivationStatus::Failed, ActivationCode::UncertainNoReplay)
        );
        assert_eq!(again.dispatches(), 0, "nothing is replayed");
    }

    /// The process dies after the platform callback and before any report. The journaled intent
    /// survives the startup cleanup a restart runs, and the same card is not copied again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_crash_after_the_platform_callback_is_not_replayed() {
        let (phone, _connector) = offline_phone();
        let offer_id = phone
            .resident
            .announce_text("crash cut")
            .await
            .expect("announce")
            .offer_id;
        let dying = PlatformDouble::new(&phone);
        let (release, hold) = std::sync::mpsc::channel::<()>();
        *dying.hold.lock().expect("hold") = Some(hold);
        let resident = phone.resident.clone();
        let local = phone.local();
        let platform = Arc::clone(&dying) as Arc<dyn FetchClipboard>;
        let crashed = tokio::spawn(async move {
            resident
                .activate(local, offer_id, ShelfAction::CopyText, platform)
                .await
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while dying.intent_journaled.lock().expect("journaled").is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the platform callback never ran"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        crashed.abort();
        assert!(
            crashed
                .await
                .expect_err("the activation died")
                .is_cancelled()
        );
        assert_eq!(
            *dying.intent_journaled.lock().expect("journaled"),
            vec![true]
        );

        phone.store().startup_cleanup().expect("restart cleanup");
        assert!(
            phone
                .store()
                .clipboard_fence(phone.local(), offer_id)
                .expect("journal")
                == meshelf_core::ClipboardFence::UncertainCard,
            "an intent that may have applied survives restart cleanup"
        );
        let later = PlatformDouble::new(&phone);
        let report = phone
            .resident
            .activate(
                phone.local(),
                offer_id,
                ShelfAction::CopyText,
                Arc::clone(&later) as Arc<dyn FetchClipboard>,
            )
            .await;
        assert_eq!(report.code, ActivationCode::UncertainNoReplay);
        assert_eq!(later.dispatches(), 0);
        drop(release);
    }
    // --- ABI-8 decoder rules the Android lane enforces -------------------------------------

    fn text_record(sequence: u64) -> OfferCardRecord {
        OfferCardRecord {
            source_device: DeviceId::new(),
            offer_id: OfferId::new(),
            descriptor: OfferDescriptor::text("héllo").expect("text"),
            received_sequence: sequence,
            availability: CardAvailability::Available,
            last_attempt: None,
        }
    }

    /// Kotlin rejects a card that omits `lastAttempt` or `activeOperation`, a snapshot without the
    /// `peerObservation` key, and a TEXT card without an integer byte length, so absent values are
    /// explicit nulls and TEXT carries its UTF-8 byte count.
    #[test]
    fn snapshot_keeps_every_nullable_key_as_an_explicit_null() {
        let record = text_record(7);
        let snapshot = shelf_snapshot(
            DeviceId::new(),
            "amber",
            std::slice::from_ref(&record),
            &std::collections::HashMap::new(),
            None,
        )
        .expect("snapshot");
        let value: serde_json::Value =
            serde_json::from_str(&contract_json(&snapshot, "snapshot").expect("json"))
                .expect("parse");
        let top = value.as_object().expect("object");
        assert!(top.contains_key("peerObservation"));
        assert!(value["peerObservation"].is_null());
        assert_eq!(value["completeness"], "COMPLETE");
        let card = value["cards"][0].as_object().expect("card");
        for key in ["lastAttempt", "activeOperation"] {
            assert!(card.contains_key(key), "{key} must be present");
            assert!(card[key].is_null(), "{key} must be null");
        }
        assert_eq!(
            card["byteLength"],
            serde_json::json!(6),
            "UTF-8 bytes of héllo"
        );
    }

    /// Kotlin requires a non-blank source name and strictly descending shelf sequences; the
    /// serializer refuses rather than emits a shelf that breaks either.
    #[test]
    fn snapshot_refuses_blank_names_and_unordered_sequences() {
        let local = DeviceId::new();
        let names = std::collections::HashMap::new();
        let cards = [text_record(3), text_record(2)];
        assert!(matches!(
            shelf_snapshot(local, "  ", &cards, &names, None),
            Err(PhoneError::Configuration(detail)) if detail.contains("display name")
        ));
        for sequences in [[2, 3], [3, 3]] {
            let unordered = [text_record(sequences[0]), text_record(sequences[1])];
            assert!(matches!(
                shelf_snapshot(local, "amber", &unordered, &names, None),
                Err(PhoneError::Configuration(detail)) if detail.contains("newest first")
            ));
        }
        let blank_host = text_record(1);
        let names = std::collections::HashMap::from([(blank_host.source_device, "   ".to_owned())]);
        let snapshot = shelf_snapshot(
            local,
            "amber",
            std::slice::from_ref(&blank_host),
            &names,
            None,
        )
        .expect("snapshot");
        assert_eq!(snapshot.cards[0].source_display_name, UNKNOWN_DEVICE_NAME);
    }

    /// Kotlin rejects an outcome paired with the wrong reachability and a repeated device.
    #[test]
    fn peer_outcomes_pair_with_their_reachability_and_devices_never_repeat() {
        use PeerOutcome as Outcome;
        let pairs = [
            (Outcome::CatalogApplied, Reachability::Reachable),
            (Outcome::CatalogUnsupported, Reachability::Reachable),
            (Outcome::Refused, Reachability::Reachable),
            (Outcome::Stored, Reachability::Reachable),
            (Outcome::TransportFailed, Reachability::Unavailable),
            (Outcome::NoAddress, Reachability::Unavailable),
        ];
        for (outcome, reachability) in pairs {
            assert_eq!(outcome.reachability(), reachability, "{outcome:?}");
        }
        let entry = |device_id, outcome: PeerOutcome| PeerObservationEntry {
            device_id,
            display_name: "CEDAR".to_owned(),
            reachability: outcome.reachability(),
            outcome,
        };
        let device = DeviceId::new();
        let repeated = vec![
            entry(device, Outcome::Stored),
            entry(device, Outcome::TransportFailed),
        ];
        assert!(matches!(
            shelf_snapshot(
                DeviceId::new(),
                "amber",
                &[],
                &std::collections::HashMap::new(),
                Some(PeerObservation {
                    trigger: ObservationTrigger::Refresh,
                    peers: repeated.clone(),
                }),
            ),
            Err(PhoneError::Configuration(detail)) if detail.contains("repeats peer")
        ));
        assert!(
            AnnounceResult::stored(OfferId::new(), repeated)
                .to_json()
                .is_err()
        );
    }

    /// `lastAttempt.code` renders only the stored attempt vocabulary Kotlin accepts.
    #[test]
    fn last_attempt_codes_are_the_contract_vocabulary() {
        let allowed = [
            "COMPLETED",
            "SOURCE_UNAVAILABLE",
            "SOURCE_CHANGED",
            "BUSY",
            "CANCELLED",
            "CLIPBOARD_FAILED",
            "VERIFICATION_FAILED",
            "UNCERTAIN_NO_REPLAY",
            "FAILED",
            "PLATFORM_FAILED",
            "FOREGROUND_LOST",
            "UNSUPPORTED",
            "INTERNAL",
        ];
        for code in [
            OfferAttemptCode::Completed,
            OfferAttemptCode::SourceUnavailable,
            OfferAttemptCode::SourceChanged,
            OfferAttemptCode::Busy,
            OfferAttemptCode::Cancelled,
            OfferAttemptCode::ClipboardFailed,
            OfferAttemptCode::VerificationFailed,
            OfferAttemptCode::UncertainNoReplay,
            OfferAttemptCode::Failed,
        ] {
            assert!(allowed.contains(&attempt_code(&code)), "{code:?}");
        }
    }

    /// Kotlin reads COMPLETED as success only when status and code agree, so for every network
    /// outcome, every action, and after a foreground-lost report, one is COMPLETED exactly when
    /// the other is.
    #[test]
    fn activation_status_is_completed_exactly_when_code_is() {
        use ActivationFailCode as Fail;
        use ActivationRefuseCode as Refuse;
        let mut outcomes = vec![
            ActivationOutcome::Completed,
            ActivationOutcome::Cancelled,
            ActivationOutcome::UncertainNoReplay,
        ];
        outcomes.extend(
            [
                Refuse::UnknownOffer,
                Refuse::NotAnnouncedToRequester,
                Refuse::SourceUnavailable,
                Refuse::SourceChanged,
                Refuse::Busy,
                Refuse::Malformed,
                Refuse::Unsupported,
                Refuse::InvalidManifest,
                Refuse::TooLarge,
                Refuse::InsufficientSpace,
                Refuse::DestinationUnavailable,
                Refuse::AllocationFailed,
                Refuse::UnsupportedMode,
                Refuse::DuplicateActivation,
            ]
            .map(ActivationOutcome::Refused),
        );
        outcomes.extend(
            [
                Fail::SourceUnavailable,
                Fail::SourceChanged,
                Fail::VerificationFailed,
                Fail::ClipboardFailed,
                Fail::ConnectionLost,
                Fail::LocalIo,
                Fail::Protocol,
                Fail::InternalError,
            ]
            .map(ActivationOutcome::Failed),
        );
        let (device, offer) = (DeviceId::new(), OfferId::new());
        for action in [
            ShelfAction::CopyText,
            ShelfAction::ShareFile,
            ShelfAction::SaveFile,
        ] {
            let mut reports: Vec<ActivationReport> = outcomes
                .iter()
                .map(|outcome| ActivationReport::settled(device, offer, action, Ok(*outcome), None))
                .collect();
            reports.push(ActivationReport::settled(
                device,
                offer,
                action,
                Err(NetError::Unavailable("offline".to_owned())),
                None,
            ));
            reports.push(ActivationReport::refused(
                device,
                offer,
                action,
                ActivationCode::Unsupported,
                "no",
            ));
            for mut report in reports {
                for _ in 0..2 {
                    assert_eq!(
                        report.status == ActivationStatus::Completed,
                        report.code == ActivationCode::Completed,
                        "{report:?}"
                    );
                    assert_eq!(
                        (report.source_device, report.offer_id, report.action),
                        (device, offer, action)
                    );
                    report.foreground_lost();
                }
            }
        }
    }
}
