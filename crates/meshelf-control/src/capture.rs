//! The resident's capture control surface.
//!
//! One agent command becomes one durable request. [`CaptureService::start_capture`] runs the
//! authoritative preflight, writes the `AwaitingPresentation` row together with its pull grant,
//! registers a wait slot, and only then hands the work to its own runtime; nothing
//! network-bound ever runs on the local-control handler thread, whose client gives up after five
//! seconds (`meshelf_platform::activation`).
//!
//! **Waiting is event-driven (invariant 12).** A caller that passed `--wait` receives a
//! [`WaitTicket`] and connects to the separate wait channel, where it sleeps on its own channel
//! holding no lock, no activation permit, and no store transaction. Nothing here polls: every
//! wake is a transition that already happened (an acknowledgement, a recorded status, the pull's
//! own result, a cancel, the request's one-shot expiry timer, or resident shutdown).
//!
//! **Durable before acknowledged (invariant 11).** The request row and its grant are committed
//! before [`CaptureReply::Started`] exists, so a caller that is told a capture started can always
//! ask about it again. The outcome a waiter receives is the serialized durable row, which stays
//! the sole authority; [`meshelf_core::CaptureRequestRecord::outcome`] is the only place the
//! reported type, reason, and exit code are decided.
//!
//! **The output path's parent is canonicalized exactly once, here.** The target itself must not
//! exist, so only the parent can be resolved; resolving it is what lets an agent name a path
//! under a symlinked directory (`/tmp` is a symlink to `/private/tmp` on macOS) instead of having
//! every such request refused. The canonical parent is what the durable row, the grant, the
//! staging directory, the publication, and the result all use. A parent that disappears or
//! becomes a symlink *after* this preflight is refused again at receive and publish time by
//! [`meshelf_net::preflight_exact_output`], which the receiver re-runs.

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use meshelf_core::{
    CaptureKind, CaptureLens, CaptureNotStarted, CapturePullGrant, CaptureRequestId,
    CaptureRequestRecord, CaptureTerminalCode, DeviceId, MAX_CAPTURE_DETAIL_BYTES,
    MAX_CAPTURE_LABEL_BYTES, validate_capture_label, validate_capture_lifetime,
    validate_capture_purpose,
};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    ActivationService, CaptureAnnouncementRouter, CaptureLaunchRefused, CapturePullLauncher,
    CaptureRequestEvents, ExactOutputRefusal, FetchClipboard, NetError, PeerClient,
    RequesterCaptureReceiver, RequesterCaptureRouter, V2CaptureReceiver, preflight_exact_output,
    run_capture_pull, select_discovered_socket,
};
use meshelf_platform::WaitService;
use meshelf_protocol::{
    CAP_CAPTURE_REQUEST_V1, CAP_OFFER_PULL_V2, CaptureAckCode, CaptureRequest, CaptureStatus,
    CaptureStatusCode, ClientHello,
};
use meshelf_store::{
    CaptureRequestInsert, CaptureRequestReconciliation, CaptureTransition, ClaimedCapturePull,
    RedbV2Store,
};
use serde::{Deserialize, Serialize};
use tokio::{runtime::Builder, runtime::Runtime, sync::watch};

use crate::coordinator::{CapturePeer, CapturePeerError, Coordinator};

/// Simultaneously attached waiters across every live capture. Further waiters are refused, never
/// queued: a wait is a convenience over the durable row, which every caller can read instead.
pub const MAX_CAPTURE_WAITERS: usize = 8;

/// How long past a request's own expiry its wait registration stays live, so a transfer that
/// started just before expiry can still deliver its outcome to the waiter. The transfer has its
/// own inactivity bounds; this only keeps the waiter's slot.
pub const CAPTURE_TRANSFER_ALLOWANCE_MS: u64 = 120_000;

/// Worker threads for capture sends, pulls, cancels, and expiry timers. Two activation permits
/// exist, and a capture consumes one, so nothing here benefits from a wider pool.
const CAPTURE_RUNTIME_THREADS: usize = 2;

/// Where to wait for one capture's outcome, and until when.
///
/// The port and token ride the local-control response, which the activation token file already
/// authenticates; no second file is written. The token is request-scoped and single-use: a second
/// waiter on the same request is refused rather than queued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitTicket {
    pub port: u16,
    pub token: String,
    /// When the registration itself lapses. A client sets its own read timeout from this.
    pub deadline_unix_ms: u64,
}

/// What a caller that may have asked to wait was given.
///
/// A refusal is its own answer, not an absent ticket: a caller that asked to wait and was refused
/// must be able to tell that from never having asked, or it will report a finished capture as one
/// it simply did not watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum CaptureWait {
    /// The caller did not ask to wait.
    NotRequested,
    Issued(WaitTicket),
    /// The caller asked to wait and no slot could be issued. The request itself is live and
    /// untouched; one status query still reports its outcome. Never queued behind another waiter.
    Refused,
}

impl CaptureWait {
    /// The ticket, if one was issued.
    #[must_use]
    pub const fn ticket(&self) -> Option<&WaitTicket> {
        match self {
            Self::Issued(ticket) => Some(ticket),
            Self::NotRequested | Self::Refused => None,
        }
    }
}

/// What an agent asked for. The resident, not the caller, decides whether it is admissible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStartInput {
    /// Device id, Tailscale hostname, or Tailscale node id.
    pub peer: String,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens: Option<CaptureLens>,
    pub timeout_ms: u64,
    /// Absolute; the caller absolutizes it, the resident canonicalizes its parent.
    pub output_path: PathBuf,
    /// Issue a wait ticket. A caller that will not wait must not take a waiter slot.
    pub wait: bool,
}

/// Every answer the capture control surface can give.
///
/// None of these carries an exit code: [`meshelf_core::CaptureNotStarted::outcome`] and
/// [`meshelf_core::CaptureRequestRecord::outcome`] are the single authority, and the caller reads
/// it from the reason or the row it is handed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum CaptureReply {
    /// The request is durable. Its outcome arrives on `wait`, or from one later status query.
    Started {
        request_id: CaptureRequestId,
        wait: CaptureWait,
    },
    /// Nothing was written and nothing was sent.
    NotStarted { reason: CaptureNotStarted },
    /// The durable row, live or finished.
    Request { record: Box<CaptureRequestRecord> },
}

/// The four capture operations the local-control channel routes, each returning at once.
///
/// This is the seam a binary attaches a real capture transport to. A resident that has none
/// answers `resident_unavailable`, which is what the desktop and the headless resident do until
/// they are wired.
pub trait CaptureControl: Send + Sync + 'static {
    fn start(&self, input: CaptureStartInput) -> CaptureReply;
    fn status(&self, request_id: CaptureRequestId) -> CaptureReply;
    fn wait_ticket(&self, request_id: CaptureRequestId) -> CaptureReply;
    fn cancel(&self, request_id: CaptureRequestId) -> CaptureReply;
}

/// Everything the capture service needs that only a binary can supply.
pub struct CaptureServiceConfig<C>
where
    C: FetchClipboard,
{
    pub identity: InstallationIdentity,
    pub device_name: String,
    pub coordinator: Arc<Coordinator>,
    pub store: Arc<RedbV2Store>,
    /// The one activation service for this store; a capture consumes one of its two permits.
    pub activations: Arc<ActivationService<C>>,
    pub client: PeerClient,
    /// The port every capture peer is dialled on; `crate::MESHELF_PORT` in production. It is
    /// configured rather than fixed so a test can point a capture at an in-process listener,
    /// which is the only way the best-effort cancel status can be observed at all.
    pub port: u16,
}

/// The resident's capture engine: durable requests, the wait channel, and the automatic pull.
pub struct CaptureService<C>
where
    C: FetchClipboard,
{
    identity: InstallationIdentity,
    device_name: String,
    coordinator: Arc<Coordinator>,
    store: Arc<RedbV2Store>,
    activations: Arc<ActivationService<C>>,
    client: PeerClient,
    port: u16,
    waits: Arc<WaitService>,
    /// One watch per live request. `true` means "stop": it reaches a transfer in flight, and
    /// dropping the sender when the request reaches its outcome stops the expiry timer from
    /// sleeping out the rest of a lifetime nothing is waiting on any more.
    cancels: Mutex<HashMap<CaptureRequestId, watch::Sender<bool>>>,
    /// `None` only while [`Drop`] is taking it.
    runtime: Option<Runtime>,
}

impl<C> CaptureService<C>
where
    C: FetchClipboard,
{
    /// Binds the wait channel and starts the capture runtime. Nothing is sent until a capture is.
    pub fn start(config: CaptureServiceConfig<C>) -> io::Result<Arc<Self>> {
        let waits = Arc::new(WaitService::start(MAX_CAPTURE_WAITERS)?);
        let runtime = Builder::new_multi_thread()
            .worker_threads(CAPTURE_RUNTIME_THREADS)
            .thread_name("meshelf-capture")
            .enable_all()
            .build()?;
        Ok(Arc::new(Self {
            identity: config.identity,
            device_name: config.device_name,
            coordinator: config.coordinator,
            store: config.store,
            activations: config.activations,
            client: config.client,
            port: config.port,
            waits,
            cancels: Mutex::new(HashMap::new()),
            runtime: Some(runtime),
        }))
    }

    /// The capture runtime. Only [`Drop`] ever takes it, so a live service always has one.
    fn runtime(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("the capture runtime outlives every use of the service")
    }

    /// The loopback port waiters connect to.
    #[must_use]
    pub fn wait_port(&self) -> u16 {
        self.waits.port()
    }

    /// The control seam for the local-control channel.
    #[must_use]
    pub fn handle(self: &Arc<Self>) -> CaptureHandle<C> {
        CaptureHandle(Arc::clone(self))
    }

    /// Routes correlated announcements to their capture request, before the shelf is touched.
    #[must_use]
    pub fn router(self: &Arc<Self>) -> Arc<dyn CaptureAnnouncementRouter> {
        Arc::new(RequesterCaptureRouter::new(
            Arc::clone(&self.store),
            Arc::new(self.handle()),
            Arc::new(self.handle()),
        ))
    }

    /// The listener's capture receiver: it fulfils nothing and records a status before acking it.
    #[must_use]
    pub fn receiver(self: &Arc<Self>) -> Arc<dyn V2CaptureReceiver> {
        Arc::new(RequesterCaptureReceiver::new(
            Arc::clone(&self.store),
            Arc::new(self.handle()),
        ))
    }

    /// Ends every request this resident left behind and sends one best-effort cancel for each
    /// unclaimed one the phone may still be presenting. Nothing is ever resumed or replayed.
    pub fn reconcile_at_startup(self: &Arc<Self>) -> Result<CaptureRequestReconciliation, String> {
        let report = self
            .store
            .reconcile_capture_requests_at_startup(now_unix_ms())
            .map_err(|error| format!("could not reconcile capture requests: {error}"))?;
        for record in &report.cancel {
            self.spawn_cancel_status(record.request_id, record.peer);
        }
        Ok(report)
    }

    /// Wakes every attached waiter with `Shutdown` and stops accepting new ones.
    pub fn shutdown(&self) {
        let _ = self.waits.shutdown();
    }

    fn start_capture(self: &Arc<Self>, input: CaptureStartInput) -> CaptureReply {
        let refused = |reason| CaptureReply::NotStarted { reason };

        // The path comes first: an agent that named an impossible output learns that without a
        // peer being contacted or a row being written.
        let exact_output_path = match exact_capture_output(&input.output_path) {
            Ok(path) => path,
            Err(reason) => return refused(reason),
        };
        let peer = match self.coordinator.resolve_capture_peer(&input.peer) {
            Ok(peer) => peer,
            // A selector that matched several paired records named no device at all, which is a
            // bad argument rather than an absent pairing; every other refusal is "not paired".
            Err(CapturePeerError::Ambiguous(_)) => {
                return refused(CaptureNotStarted::InvalidArguments);
            }
            Err(CapturePeerError::NotPaired(_) | CapturePeerError::Unusable(_)) => {
                return refused(CaptureNotStarted::PeerNotPaired);
            }
        };
        if validate_capture_purpose(&input.purpose).is_err() {
            return refused(CaptureNotStarted::InvalidArguments);
        }
        let created_at_unix_ms = now_unix_ms();
        let Some(expires_at_unix_ms) = created_at_unix_ms.checked_add(input.timeout_ms) else {
            return refused(CaptureNotStarted::InvalidArguments);
        };
        if validate_capture_lifetime(created_at_unix_ms, expires_at_unix_ms).is_err() {
            return refused(CaptureNotStarted::InvalidArguments);
        }

        let record = CaptureRequestRecord {
            request_id: CaptureRequestId::new(),
            peer: peer.device_id,
            peer_label: peer_label(&peer),
            purpose: input.purpose,
            lens: input.lens,
            created_at_unix_ms,
            grant: CapturePullGrant {
                expected_source: peer.device_id,
                kind: CaptureKind::Photo,
                exact_output_path,
                expires_at_unix_ms,
            },
            phase: meshelf_core::CaptureRequestPhase::AwaitingPresentation,
            terminal_reported: false,
        };
        let request_id = record.request_id;

        // Durable before acknowledged: the row and its grant exist before the caller is told the
        // capture started, and before a single byte is sent to the phone.
        let stored = match self.store.insert_capture_request(record) {
            Ok(CaptureRequestInsert::Inserted { record, .. }) => record,
            Ok(CaptureRequestInsert::AtCapacity { .. }) => {
                return refused(CaptureNotStarted::Capacity);
            }
            Ok(CaptureRequestInsert::Duplicate(_) | CaptureRequestInsert::Conflict) => {
                return refused(CaptureNotStarted::InvalidArguments);
            }
            Err(_) => return refused(CaptureNotStarted::ResidentUnavailable),
        };

        // Registered before the send is spawned, so an immediate failure has a waiter to wake.
        // A caller that asked to wait and could not be given a slot is told so; the request is
        // already durable, so silently answering as though it had not asked would leave it
        // believing a finished capture was one it merely chose not to watch.
        let wait = if input.wait {
            match self.issue_ticket(request_id, expires_at_unix_ms) {
                Some(ticket) => CaptureWait::Issued(ticket),
                None => CaptureWait::Refused,
            }
        } else {
            CaptureWait::NotRequested
        };

        // One watch per request: a cancel reaches the transfer through it, and dropping it when
        // the request ends releases the expiry timer. Both spawned tasks are given it now, before
        // either can finish, so neither can find it missing.
        let (ended, expiry) = watch::channel(false);
        self.lock_cancels().insert(request_id, ended);

        let service = Arc::clone(self);
        let request = stored.clone();
        self.runtime().spawn(async move {
            service.send_request(request, peer).await;
        });
        let service = Arc::clone(self);
        self.runtime().spawn(async move {
            service.expire_at(expires_at_unix_ms, expiry).await;
        });

        CaptureReply::Started { request_id, wait }
    }

    fn capture_status(&self, request_id: CaptureRequestId) -> CaptureReply {
        match self.store.get_capture_request(request_id) {
            Ok(Some(record)) => {
                // Reporting a finished outcome discharges the row, which is what lets startup
                // cleanup remove it. The store refuses to mark a live row reported; this only
                // keeps a status query on a live request from opening a write transaction.
                if record.outcome().is_some() {
                    let _ = self.store.mark_capture_reported(request_id);
                }
                CaptureReply::Request {
                    record: Box::new(record),
                }
            }
            Ok(None) => CaptureReply::NotStarted {
                reason: CaptureNotStarted::InvalidArguments,
            },
            Err(_) => CaptureReply::NotStarted {
                reason: CaptureNotStarted::ResidentUnavailable,
            },
        }
    }

    fn capture_wait_ticket(&self, request_id: CaptureRequestId) -> CaptureReply {
        match self.store.get_capture_request(request_id) {
            Ok(Some(record)) if record.outcome().is_some() => {
                let _ = self.store.mark_capture_reported(request_id);
                CaptureReply::Request {
                    record: Box::new(record),
                }
            }
            // A live request whose slot cannot be issued (one waiter is already attached, or the
            // global cap is reached) is refused here rather than queued; the request is unharmed
            // and a status query still reports it.
            Ok(Some(record)) => {
                match self.issue_ticket(request_id, record.grant.expires_at_unix_ms) {
                    Some(ticket) => CaptureReply::Started {
                        request_id,
                        wait: CaptureWait::Issued(ticket),
                    },
                    None => CaptureReply::NotStarted {
                        reason: CaptureNotStarted::Capacity,
                    },
                }
            }
            Ok(None) => CaptureReply::NotStarted {
                reason: CaptureNotStarted::InvalidArguments,
            },
            Err(_) => CaptureReply::NotStarted {
                reason: CaptureNotStarted::ResidentUnavailable,
            },
        }
    }

    /// Cancels a request, and never reports an outcome its pull has not agreed to.
    ///
    /// The watch is fired first and unconditionally: it is how a transfer already in flight learns,
    /// and only a claimed request has one. The row itself is ended only while it is *unclaimed*.
    /// Ending a claimed row here would race its own pull — between the last byte arriving and
    /// `complete_capture` the row would be forced to `Cancelled`, the photo would be published
    /// anyway, and the agent would be told the capture failed while an unannounced file sat at the
    /// path it named. A claimed request is therefore returned as it stands, still claimed: the
    /// pull records the real outcome, cancelled or completed, and the waiter receives that.
    fn cancel_capture(self: &Arc<Self>, request_id: CaptureRequestId) -> CaptureReply {
        if let Some(cancel) = self.lock_cancels().get(&request_id) {
            let _ = cancel.send(true);
        }
        let record = match self.store.terminate_capture_unless_claimed(
            request_id,
            CaptureTerminalCode::Cancelled,
            None,
        ) {
            Ok(CaptureTransition::Applied(record)) => {
                self.spawn_cancel_status(request_id, record.peer);
                self.complete_wait(&record);
                record
            }
            Ok(CaptureTransition::Unchanged(record) | CaptureTransition::Refused(record)) => record,
            Ok(CaptureTransition::Unknown) => {
                return CaptureReply::NotStarted {
                    reason: CaptureNotStarted::InvalidArguments,
                };
            }
            Err(_) => {
                return CaptureReply::NotStarted {
                    reason: CaptureNotStarted::ResidentUnavailable,
                };
            }
        };
        CaptureReply::Request {
            record: Box::new(record),
        }
    }

    fn issue_ticket(
        &self,
        request_id: CaptureRequestId,
        expires_at_unix_ms: u64,
    ) -> Option<WaitTicket> {
        let deadline_unix_ms = expires_at_unix_ms.saturating_add(CAPTURE_TRANSFER_ALLOWANCE_MS);
        let remaining = deadline_unix_ms.checked_sub(now_unix_ms())?;
        let token = self
            .waits
            .register(
                &wait_key(request_id),
                Instant::now() + Duration::from_millis(remaining),
            )
            .ok()?;
        Some(WaitTicket {
            port: self.waits.port(),
            token: token.as_str().to_owned(),
            deadline_unix_ms,
        })
    }

    /// Hands a finished row to its waiter. The row is the payload, so the waiter and a later
    /// status query report the same thing. Marking it reported only once the outcome has been
    /// handed over keeps an unread outcome readable by the one status query a lost wait makes.
    fn complete_wait(&self, record: &CaptureRequestRecord) {
        if record.outcome().is_none() {
            return;
        }
        // The request is over, so its watch is dropped here. Dropping it is what releases the
        // expiry timer, which would otherwise sleep out the rest of a lifetime nothing can use.
        self.lock_cancels().remove(&record.request_id);
        let Ok(payload) = serde_json::to_vec(record) else {
            return;
        };
        if self
            .waits
            .complete(&wait_key(record.request_id), payload)
            .is_ok()
        {
            let _ = self.store.mark_capture_reported(record.request_id);
        }
    }

    /// Ends a request that has not been claimed. A claimed request belongs to its pull, which
    /// owns the outcome; ending it here would turn a published photo into an unrecorded one.
    fn end_unclaimed(
        &self,
        request_id: CaptureRequestId,
        code: CaptureTerminalCode,
        detail: Option<String>,
    ) {
        let detail = detail.map(|detail| bounded_detail(&detail));
        if let Ok(CaptureTransition::Applied(record)) = self
            .store
            .terminate_capture_unless_claimed(request_id, code, detail)
        {
            self.complete_wait(&record);
        }
    }

    async fn send_request(&self, record: CaptureRequestRecord, peer: CapturePeer) {
        let request_id = record.request_id;
        let Some(address) = select_discovered_socket(&peer.addresses, self.port) else {
            self.end_unclaimed(
                request_id,
                CaptureTerminalCode::PeerOffline,
                Some("the capture peer has no Tailscale address".to_owned()),
            );
            return;
        };
        let request = CaptureRequest {
            request_id,
            requester: self.identity.device_id,
            target: peer.device_id,
            kind: record.grant.kind,
            created_at_unix_ms: record.created_at_unix_ms,
            expires_at_unix_ms: record.grant.expires_at_unix_ms,
            purpose: record.purpose.clone(),
            lens: record.lens,
        };
        let hello = capture_hello(&self.identity, &self.device_name, request_id);
        match self
            .client
            .send_capture_request(address, hello, request, &peer.public_key)
            .await
        {
            Ok(ack) => match ack.code {
                // The grant arms only on a presentation from the pinned key, and only before it
                // expires; a refusal here means the request already ended some other way.
                CaptureAckCode::Presented => {
                    match self.store.arm_capture_grant(request_id, now_unix_ms()) {
                        // Armed, or already armed by a repeated acknowledgement.
                        Ok(CaptureTransition::Applied(_) | CaptureTransition::Unchanged(_)) => {}
                        // The row is no longer awaiting presentation: a cancel, a status, or the
                        // expiry reached it first. That outcome stands and nothing is re-armed.
                        Ok(CaptureTransition::Refused(_) | CaptureTransition::Unknown) => {}
                        // The grant could not be armed, so no announcement will ever be claimable.
                        // Say so now rather than letting the request decay into a slow `expired`
                        // with no recorded reason.
                        Err(error) => self.end_unclaimed(
                            request_id,
                            CaptureTerminalCode::TransferFailed,
                            Some(format!("could not arm the capture pull grant: {error}")),
                        ),
                    }
                }
                CaptureAckCode::Busy => {
                    self.end_unclaimed(request_id, CaptureTerminalCode::Busy, ack.detail);
                }
                CaptureAckCode::Unsupported => {
                    self.end_unclaimed(request_id, CaptureTerminalCode::Unsupported, ack.detail);
                }
                CaptureAckCode::Expired => {
                    self.end_unclaimed(request_id, CaptureTerminalCode::Expired, ack.detail);
                }
                CaptureAckCode::Refused => {
                    self.end_unclaimed(request_id, CaptureTerminalCode::Refused, ack.detail);
                }
            },
            // A direct operation that failed is reported now, never queued for a later retry.
            Err(error) => {
                let code = if is_peer_offline(&error) {
                    CaptureTerminalCode::PeerOffline
                } else {
                    CaptureTerminalCode::RemoteFailed
                };
                self.end_unclaimed(request_id, code, Some(error.to_string()));
            }
        }
    }

    /// One shot, at one durable deadline. Nothing wakes to check state in between.
    ///
    /// `ended` is the request's own watch: it is set by a cancel and dropped when the request
    /// reaches its outcome, and either releases this timer at once. Sleeping on past the end of
    /// the request would hold a reference to the whole service for the rest of a lifetime nobody
    /// is waiting on, which is how a resident that finishes a capture and quits ends up dropping
    /// its last reference — and so its own runtime — on one of that runtime's worker threads.
    async fn expire_at(&self, expires_at_unix_ms: u64, mut ended: watch::Receiver<bool>) {
        let remaining = expires_at_unix_ms.saturating_sub(now_unix_ms());
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(remaining)) => {}
            _ = ended.changed() => return,
        }
        if let Ok(expired) = self.store.expire_due(now_unix_ms()) {
            for record in &expired {
                self.complete_wait(record);
            }
        }
    }

    /// Tells the phone to stop presenting a request this desktop has already ended. Best effort:
    /// the durable row is already terminal, so nothing depends on this arriving.
    fn spawn_cancel_status(self: &Arc<Self>, request_id: CaptureRequestId, peer: DeviceId) {
        let service = Arc::clone(self);
        self.runtime().spawn(async move {
            let Ok(peer) = service.coordinator.capture_peer_by_device(peer) else {
                return;
            };
            let Some(address) = select_discovered_socket(&peer.addresses, service.port) else {
                return;
            };
            let hello = capture_hello(&service.identity, &service.device_name, request_id);
            let _ = service
                .client
                .send_capture_status(
                    address,
                    hello,
                    peer.device_id,
                    CaptureStatus {
                        request_id,
                        code: CaptureStatusCode::Cancelled,
                        detail: None,
                    },
                    &peer.public_key,
                )
                .await;
        });
    }

    fn lock_cancels(&self) -> MutexGuard<'_, HashMap<CaptureRequestId, watch::Sender<bool>>> {
        // Critical sections never panic; recover rather than wedge every later capture.
        self.cancels.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<C> Drop for CaptureService<C>
where
    C: FetchClipboard,
{
    /// Every task this service spawns holds a reference to it, so the last reference can be
    /// released by one of its own tasks — a resident that finishes a capture and exits does
    /// exactly that. Dropping a tokio runtime from a thread of that same runtime panics with
    /// "Cannot drop a runtime in a context where blocking is not allowed", which would take down
    /// the task rather than the process and leave the failure invisible. `shutdown_background` is
    /// the documented way to release a runtime from inside one: it stops the workers and returns
    /// without waiting for them.
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// An owned reference to the capture service, so the local-control channel, the announcement
/// router, and the capture receiver can each hold one.
pub struct CaptureHandle<C>(Arc<CaptureService<C>>)
where
    C: FetchClipboard;

impl<C> CaptureHandle<C>
where
    C: FetchClipboard,
{
    #[must_use]
    pub fn service(&self) -> &Arc<CaptureService<C>> {
        &self.0
    }
}

impl<C> Clone for CaptureHandle<C>
where
    C: FetchClipboard,
{
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<C> CaptureControl for CaptureHandle<C>
where
    C: FetchClipboard,
{
    fn start(&self, input: CaptureStartInput) -> CaptureReply {
        self.0.start_capture(input)
    }

    fn status(&self, request_id: CaptureRequestId) -> CaptureReply {
        self.0.capture_status(request_id)
    }

    fn wait_ticket(&self, request_id: CaptureRequestId) -> CaptureReply {
        self.0.capture_wait_ticket(request_id)
    }

    fn cancel(&self, request_id: CaptureRequestId) -> CaptureReply {
        self.0.cancel_capture(request_id)
    }
}

impl<C> CapturePullLauncher for CaptureHandle<C>
where
    C: FetchClipboard,
{
    /// Called on the announcement connection, so it resolves the peer and returns; the transfer
    /// itself runs on the capture runtime.
    fn launch(&self, pull: ClaimedCapturePull) -> Result<(), CaptureLaunchRefused> {
        let offline = |detail: CapturePeerError| CaptureLaunchRefused {
            code: CaptureTerminalCode::PeerOffline,
            detail: Some(detail.to_string()),
        };
        // The grant's expected source, not anything the announcement carried, decides who is
        // dialled and which pinned key the hello is checked against.
        let peer = self
            .0
            .coordinator
            .capture_peer_by_device(pull.source)
            .map_err(offline)?;
        let address = select_discovered_socket(&peer.addresses, self.0.port).ok_or_else(|| {
            CaptureLaunchRefused {
                code: CaptureTerminalCode::PeerOffline,
                detail: Some("the capture peer has no Tailscale address".to_owned()),
            }
        })?;

        // The request's own watch, so a cancel that arrived before the claim is already set on it
        // and one that arrives during the transfer reaches this pull. A request started by another
        // resident run has none; it gets one here rather than running uncancellable.
        let receiver = {
            let mut cancels = self.0.lock_cancels();
            match cancels.get(&pull.request_id) {
                Some(sender) => sender.subscribe(),
                None => {
                    let (sender, receiver) = watch::channel(false);
                    cancels.insert(pull.request_id, sender);
                    receiver
                }
            }
        };
        let service = Arc::clone(&self.0);
        self.0.runtime().spawn(async move {
            let hello = ClientHello::signed_v2(
                service.identity.device_id,
                service.device_name.clone(),
                pull.activation_id.to_string(),
                &service.identity,
            );
            let outcome = run_capture_pull(
                &service.activations,
                &service.client,
                address,
                hello,
                &peer.public_key,
                &pull,
                receiver,
            )
            .await;
            service.lock_cancels().remove(&pull.request_id);
            // On an error the row could not be read or written, so it is still claimed and no
            // outcome is invented here. Startup reconciliation ends it as uncertain and the
            // waiter's own deadline releases it; the pull is never replayed.
            if let Ok(record) = outcome {
                service.complete_wait(&record);
            }
        });
        Ok(())
    }
}

impl<C> CaptureRequestEvents for CaptureHandle<C>
where
    C: FetchClipboard,
{
    fn capture_finished(&self, record: &CaptureRequestRecord) {
        self.0.lock_cancels().remove(&record.request_id);
        self.0.complete_wait(record);
    }
}

/// The hello a capture control operation opens with. Every v2 operation is gated on
/// `offer-pull-v2`, and the capture arms additionally require `capture-request-v1`, so both are
/// advertised or the phone refuses the connection before reading the request.
fn capture_hello(
    identity: &InstallationIdentity,
    device_name: &str,
    request_id: CaptureRequestId,
) -> ClientHello {
    ClientHello::signed_v2_with_capabilities(
        identity.device_id,
        device_name,
        request_id.to_string(),
        vec![
            CAP_OFFER_PULL_V2.to_owned(),
            CAP_CAPTURE_REQUEST_V1.to_owned(),
        ],
        identity,
    )
}

/// Whether a failure means the phone was not there to answer, rather than that something went
/// wrong once a conversation had started. Only the connect attempt can say "not there": a reset or
/// a protocol error mid-exchange is a remote failure, and reporting it as offline would tell an
/// agent to retry something that will fail the same way.
fn is_peer_offline(error: &NetError) -> bool {
    match error {
        // The connect attempt timed out.
        NetError::Unavailable(_) => true,
        NetError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::NetworkDown
        ),
        _ => false,
    }
}

fn wait_key(request_id: CaptureRequestId) -> String {
    request_id.to_string()
}

fn now_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn bounded_detail(detail: &str) -> String {
    truncate_utf8(detail, MAX_CAPTURE_DETAIL_BYTES).to_owned()
}

/// The longest prefix of `value` that is at most `maximum_bytes` long and ends on a character
/// boundary.
fn truncate_utf8(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// The name shown beside the request. A peer names itself, so the name may be longer than a
/// capture label allows or may not be plain text; the device id is always a valid label and is
/// what a capture falls back to rather than failing for a reason the agent cannot fix.
fn peer_label(peer: &CapturePeer) -> String {
    let candidate = truncate_utf8(&peer.hostname, MAX_CAPTURE_LABEL_BYTES);
    if validate_capture_label(candidate).is_ok() {
        candidate.to_owned()
    } else {
        peer.device_id.to_string()
    }
}

/// The one exact output path a capture may publish to, with its parent canonicalized.
///
/// Canonicalizing the *parent* rather than the target is what makes this work: the target must
/// not exist, and a path under `/tmp` on macOS (a symlink to `/private/tmp`) would otherwise be
/// refused outright by the parent-is-not-a-link rule that publication still enforces.
///
/// **Accepted cost, recorded by the integrator.** Because the parent is resolved here,
/// `ExactOutputRefusal::ParentIsLink` cannot be reached through this path for a symlinked
/// component that existed *before* preflight: such a capture follows the link, exactly as `cp`
/// and `mv` do, to the directory the owner named. Refusing it instead would refuse every path
/// under `/tmp` on macOS. What makes it honest is disclosure: the canonical path — not the path
/// the agent typed — is what the durable row, the grant, the publication, and therefore the
/// result JSON the agent reads all carry. A parent swapped for a link *after* this preflight is a
/// different thing and stays refused, by the same function the receiver re-runs at publication.
fn exact_capture_output(requested: &Path) -> Result<PathBuf, CaptureNotStarted> {
    // The resident's working directory is not the caller's, so a relative path is meaningless
    // here and is never resolved against it.
    if !requested.is_absolute() {
        return Err(CaptureNotStarted::InvalidArguments);
    }
    let name = literal_file_name(requested).ok_or(CaptureNotStarted::OutputNameInvalid)?;
    let parent = requested
        .parent()
        .ok_or(CaptureNotStarted::OutputNameInvalid)?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => {
            CaptureNotStarted::OutputParentMissing
        }
        _ => CaptureNotStarted::InvalidArguments,
    })?;
    // Every remaining condition is decided by the same function the receiver re-runs at
    // admission and publication, so preflight and publication cannot drift apart.
    preflight_exact_output(&canonical_parent.join(name)).map_err(not_started)
}

/// `Path::file_name` normalizes `dir/` and `dir/.` to `dir`, which would publish a file where the
/// agent named a directory. Require the raw path to end in exactly that name.
fn literal_file_name(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    // A Windows verbatim path (`\\?\C:\...`, what `canonicalize` returns) treats `/` as an
    // ordinary character, so `photo.jpg/` arrives as one name rather than a directory.
    if name.contains(['/', '\\']) {
        return None;
    }
    path.to_str()?.ends_with(name).then_some(name)
}

fn not_started(refusal: ExactOutputRefusal) -> CaptureNotStarted {
    match refusal {
        ExactOutputRefusal::NotAbsolute => CaptureNotStarted::InvalidArguments,
        ExactOutputRefusal::InvalidName => CaptureNotStarted::OutputNameInvalid,
        ExactOutputRefusal::ParentMissing => CaptureNotStarted::OutputParentMissing,
        ExactOutputRefusal::ParentNotDirectory => CaptureNotStarted::OutputParentNotDirectory,
        ExactOutputRefusal::ParentIsLink => CaptureNotStarted::OutputParentIsLink,
        ExactOutputRefusal::IsDirectory => CaptureNotStarted::OutputIsDirectory,
        ExactOutputRefusal::Exists => CaptureNotStarted::OutputExists,
        ExactOutputRefusal::InspectFailed(_) => CaptureNotStarted::InvalidArguments,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{Ipv4Addr, SocketAddr},
        str::FromStr,
        thread,
        time::{Duration, Instant},
    };

    use meshelf_core::{
        ActivationId, CaptureCorrelation, CaptureReceipt, CaptureRequestPhase, CaptureSourcePhase,
        CapturedPhoto, ClipboardError, ClipboardSink, MAX_CAPTURE_LIFETIME_MS, OfferDescriptor,
        OfferId,
    };
    use meshelf_net::{
        CaptureEventRefused, CaptureRoute, CaptureSourceEvents, CaptureSourceResolver,
        CaptureWithdrawReason, ExactDeviceAllowList, OfferAnnouncementHandler, OfferFetchHandler,
        PhoneCaptureReceiver, ServerIdentity, V2OfferServices, V2ServerConfig, serve_v2,
    };
    use meshelf_platform::{WaitOutcome, WaitToken};
    use meshelf_protocol::{CAP_CAPTURE_PHOTO_V1, OfferAnnouncement};
    use meshelf_store::{CaptureGrantClaim, MAX_LIVE_CAPTURE_REQUESTS};
    use meshelf_tailscale::{InstallationStore, PeerNetworkBinding};
    use sha2::{Digest, Sha256};
    use tempfile::{TempDir, tempdir};

    use super::*;

    /// Long enough that a loaded machine never decides a working path failed, short enough that a
    /// broken one fails within a test run rather than hanging it.
    const PATIENCE: Duration = Duration::from_secs(20);

    /// A capture publishes to an exact file and never to the clipboard, so a clipboard that
    /// refuses everything is the honest fixture: any test that reached it would fail loudly.
    struct NoClipboard;

    impl ClipboardSink for NoClipboard {
        fn set_text(&self, _text: &str) -> Result<(), ClipboardError> {
            Err(ClipboardError::new("a capture never sets the clipboard"))
        }
    }

    impl FetchClipboard for NoClipboard {
        fn set_files(&self, _paths: &[PathBuf]) -> Result<(), ClipboardError> {
            Err(ClipboardError::new("a capture never sets the clipboard"))
        }
    }

    struct Fixture {
        _directory: TempDir,
        root: PathBuf,
        service: Arc<CaptureService<NoClipboard>>,
        store: Arc<RedbV2Store>,
        coordinator: Arc<Coordinator>,
        peer: DeviceId,
    }

    /// A resident paired with one peer that answers at a loopback port nothing listens on, so
    /// every send fails the way an absent phone does, promptly and without a network.
    fn fixture() -> Fixture {
        fixture_reaching("127.0.0.1", Duration::from_millis(500))
    }

    fn fixture_reaching(peer_address: &str, connect_timeout: Duration) -> Fixture {
        fixture_dialling(
            InstallationIdentity::generate(),
            &InstallationIdentity::generate(),
            peer_address,
            crate::MESHELF_PORT,
            connect_timeout,
        )
    }

    /// The resident, with exactly one **paired** peer. Pairing, not discovery, is what authorizes
    /// a capture, so the fixture records trust the way a completed pairing does; a record written
    /// by the O-003 discovery rule would be refused before anything is sent.
    fn fixture_dialling(
        identity: InstallationIdentity,
        phone: &InstallationIdentity,
        peer_address: &str,
        port: u16,
        connect_timeout: Duration,
    ) -> Fixture {
        let directory = tempdir().expect("temporary directory");
        let root = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let device_id = identity.device_id;
        let state_store = InstallationStore::new(root.join("state.json"));
        state_store
            .update(device_id, |state| {
                state.peers.record_paired(
                    meshelf_tailscale::PairedPeer {
                        peer: meshelf_protocol::pairing::PairedPeer {
                            device_id: phone.device_id,
                            public_key: phone.public_key(),
                            device_name: "amber".to_owned(),
                            pairing_id: meshelf_protocol::pairing::PairingId::generate(),
                            transcript_hash: meshelf_protocol::pairing::TranscriptHash::from_bytes(
                                [5; 32],
                            ),
                        },
                        binding: PeerNetworkBinding::TailscaleNode {
                            node_id: "phone-node".to_owned(),
                            addresses: vec![peer_address.parse().expect("address")],
                        },
                        expires_at_unix_ms: now_unix_ms() + 120_000,
                    },
                    now_unix_ms(),
                    None,
                )
            })
            .expect("record the phone");
        let store =
            Arc::new(RedbV2Store::open(root.join("offers.redb")).expect("open the offer store"));
        let coordinator = Arc::new(
            Coordinator::new(device_id, state_store, store.clone()).with_card_store(store.clone()),
        );
        let activations = Arc::new(ActivationService::new(
            device_id,
            store.clone(),
            Arc::new(NoClipboard),
            root.join("state"),
        ));
        let service = CaptureService::start(CaptureServiceConfig {
            identity,
            device_name: "CEDAR".to_owned(),
            coordinator: coordinator.clone(),
            store: store.clone(),
            activations,
            client: PeerClient::with_timeouts(connect_timeout, Duration::from_secs(10)),
            port,
        })
        .expect("start the capture service");
        Fixture {
            _directory: directory,
            root,
            service,
            store,
            coordinator,
            peer: phone.device_id,
        }
    }

    impl Fixture {
        fn control(&self) -> CaptureHandle<NoClipboard> {
            self.service.handle()
        }

        fn start(&self, output: PathBuf, wait: bool) -> CaptureReply {
            self.start_within(output, wait, 60_000)
        }

        fn start_within(&self, output: PathBuf, wait: bool, timeout_ms: u64) -> CaptureReply {
            self.control().start(CaptureStartInput {
                peer: "amber".to_owned(),
                purpose: "Photograph the router label".to_owned(),
                lens: None,
                timeout_ms,
                output_path: output,
                wait,
            })
        }

        fn refusal(&self, output: PathBuf) -> CaptureNotStarted {
            match self.start(output, false) {
                CaptureReply::NotStarted { reason } => reason,
                other => panic!("expected a refusal, got {other:?}"),
            }
        }

        fn started(&self, output: PathBuf, wait: bool) -> (CaptureRequestId, CaptureWait) {
            match self.start(output, wait) {
                CaptureReply::Started { request_id, wait } => (request_id, wait),
                other => panic!("expected a started capture, got {other:?}"),
            }
        }

        /// The ticket a live request's waiter attaches with.
        fn ticket(&self, request_id: CaptureRequestId) -> WaitTicket {
            match self.control().wait_ticket(request_id) {
                CaptureReply::Started {
                    wait: CaptureWait::Issued(ticket),
                    ..
                } => ticket,
                other => panic!("a live request must be waitable, got {other:?}"),
            }
        }

        /// Arms and claims a request the way a presentation and a correlated announcement do, so
        /// a test can act on a request whose pull owns its outcome.
        fn claim(&self, request_id: CaptureRequestId, bytes: u64) -> ActivationId {
            assert!(matches!(
                self.store
                    .arm_capture_grant(request_id, now_unix_ms())
                    .expect("arm the grant"),
                CaptureTransition::Applied(_)
            ));
            let activation_id = ActivationId::new();
            match self
                .store
                .claim_capture_grant(
                    request_id,
                    self.peer,
                    OfferId::new(),
                    activation_id,
                    OfferDescriptor::File {
                        root_name: "IMG_0001.jpg".to_owned(),
                        total_bytes: bytes,
                        content_class: meshelf_core::FileContentClass::File,
                    },
                    now_unix_ms(),
                )
                .expect("claim the grant")
            {
                CaptureGrantClaim::Claimed(_) => activation_id,
                other => panic!("the grant was not claimed: {other:?}"),
            }
        }

        /// Whether the request's stop watch has been fired, which is how a transfer in flight
        /// learns that it was cancelled.
        fn cancel_signalled(&self, request_id: CaptureRequestId) -> bool {
            self.service
                .lock_cancels()
                .get(&request_id)
                .is_some_and(|cancel| *cancel.borrow())
        }

        fn row(&self, request_id: CaptureRequestId) -> CaptureRequestRecord {
            self.store
                .get_capture_request(request_id)
                .expect("read the request")
                .expect("the request row exists")
        }

        /// A live row written the way `start_capture` writes one, for tests about what happens to
        /// a request that is still waiting for the phone.
        fn insert_live_request(&self, output: PathBuf) -> CaptureRequestId {
            self.insert_request(output, now_unix_ms(), MAX_CAPTURE_LIFETIME_MS)
        }

        fn insert_request(
            &self,
            output: PathBuf,
            created_at_unix_ms: u64,
            lifetime_ms: u64,
        ) -> CaptureRequestId {
            let record = CaptureRequestRecord {
                request_id: CaptureRequestId::new(),
                peer: self.peer,
                peer_label: "amber".to_owned(),
                purpose: "Photograph the router label".to_owned(),
                lens: None,
                created_at_unix_ms,
                grant: CapturePullGrant {
                    expected_source: self.peer,
                    kind: CaptureKind::Photo,
                    exact_output_path: output,
                    expires_at_unix_ms: created_at_unix_ms + lifetime_ms,
                },
                phase: CaptureRequestPhase::AwaitingPresentation,
                terminal_reported: false,
            };
            let request_id = record.request_id;
            match self.store.insert_capture_request(record) {
                Ok(CaptureRequestInsert::Inserted { .. }) => request_id,
                other => panic!("expected an inserted request, got {other:?}"),
            }
        }
    }

    fn directory(path: &Path) -> &Path {
        fs::create_dir(path).expect("create directory");
        path
    }

    /// Waits the way a `--wait` caller does: one connection, one sleep, no polling.
    fn wait_on(ticket: &WaitTicket, patience: Duration) -> WaitOutcome {
        let token = WaitToken::from_str(&ticket.token).expect("the issued token is canonical");
        meshelf_platform::wait(ticket.port, &token, patience).expect("wait")
    }

    fn completed_record(outcome: &WaitOutcome) -> CaptureRequestRecord {
        let WaitOutcome::Completed(payload) = outcome else {
            panic!("expected a completed wait, got {outcome:?}");
        };
        serde_json::from_slice(payload).expect("the wait payload is the durable row")
    }

    // -- the integrator's canonical-parent decision -------------------------------------------

    #[cfg(unix)]
    #[test]
    fn an_output_under_a_symlinked_parent_is_accepted_and_records_the_canonical_path() {
        let fixture = fixture();
        let real = directory(&fixture.root.join("real")).to_path_buf();
        let link = fixture.root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink the parent");

        let (request_id, _) = fixture.started(link.join("router-label.jpg"), false);

        let recorded = fixture.row(request_id).grant.exact_output_path;
        assert_eq!(
            recorded,
            real.join("router-label.jpg"),
            "the grant must hold the canonical path, not the path the agent typed"
        );
        assert_ne!(
            recorded,
            link.join("router-label.jpg"),
            "a symlinked parent must be resolved, not carried through to publication"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_parent_replaced_by_a_symlink_after_preflight_is_still_refused_before_publication() {
        let fixture = fixture();
        let real = directory(&fixture.root.join("real")).to_path_buf();
        let (request_id, _) = fixture.started(real.join("router-label.jpg"), false);
        let exact = fixture.row(request_id).grant.exact_output_path;

        // Swap the canonical parent for a link to somewhere else, exactly as an attacker racing
        // the transfer would.
        let elsewhere = directory(&fixture.root.join("elsewhere")).to_path_buf();
        fs::remove_dir(&real).expect("remove the real parent");
        std::os::unix::fs::symlink(&elsewhere, &real).expect("replace the parent with a symlink");

        assert_eq!(
            preflight_exact_output(&exact),
            Err(ExactOutputRefusal::ParentIsLink),
            "the check the receiver re-runs must still refuse a parent swapped after preflight"
        );
    }

    // -- preflight ----------------------------------------------------------------------------

    #[test]
    fn a_relative_output_path_is_refused_rather_than_resolved_against_the_residents_directory() {
        let fixture = fixture();
        assert_eq!(
            fixture.refusal(PathBuf::from("router-label.jpg")),
            CaptureNotStarted::InvalidArguments
        );
        assert!(
            fixture
                .store
                .read_capture_requests()
                .expect("read")
                .is_empty(),
            "a refused preflight writes nothing"
        );
    }

    #[test]
    fn the_preflight_matrix_names_each_reason_exactly() {
        let fixture = fixture();
        let root = &fixture.root;

        let occupied = root.join("occupied.jpg");
        fs::write(&occupied, b"already here").expect("write");
        assert_eq!(
            fixture.refusal(occupied),
            CaptureNotStarted::OutputExists,
            "an existing file is never renamed around"
        );

        let folder = directory(&root.join("folder")).to_path_buf();
        assert_eq!(
            fixture.refusal(folder),
            CaptureNotStarted::OutputIsDirectory
        );

        assert_eq!(
            fixture.refusal(root.join("absent").join("photo.jpg")),
            CaptureNotStarted::OutputParentMissing,
            "exact output never creates the directories an agent did not ask for"
        );
        assert!(
            !root.join("absent").exists(),
            "a refused preflight creates nothing"
        );

        let trailing = PathBuf::from(format!("{}/", root.join("photo.jpg").display()));
        assert_eq!(
            fixture.refusal(trailing),
            CaptureNotStarted::OutputNameInvalid,
            "a path that names a directory must not be published to as a file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_at_the_target_is_an_object_rather_than_an_absence() {
        let fixture = fixture();
        let dangling = fixture.root.join("dangling.jpg");
        std::os::unix::fs::symlink(fixture.root.join("nothing-here.jpg"), &dangling)
            .expect("dangling symlink");
        assert_eq!(fixture.refusal(dangling), CaptureNotStarted::OutputExists);
    }

    // -- durability, waiting, and ending ------------------------------------------------------

    #[test]
    fn the_request_and_its_grant_are_durable_before_the_caller_is_told_it_started() {
        let fixture = fixture();
        let output = fixture.root.join("router-label.jpg");
        let (request_id, _) = fixture.started(output.clone(), false);

        // Read the store as the caller receives its reply: the row is already there.
        let record = fixture.row(request_id);
        assert_eq!(record.peer, fixture.peer);
        assert_eq!(record.grant.expected_source, fixture.peer);
        assert_eq!(record.grant.exact_output_path, output);
        assert_eq!(record.grant.kind, CaptureKind::Photo);
        assert_eq!(record.purpose, "Photograph the router label");
        assert!(
            !record.terminal_reported,
            "nothing has been reported to the caller yet"
        );
    }

    #[test]
    fn a_phone_that_does_not_answer_ends_the_request_and_wakes_its_waiter() {
        let fixture = fixture();
        let (request_id, wait) = fixture.started(fixture.root.join("photo.jpg"), true);
        let CaptureWait::Issued(ticket) = wait else {
            panic!("a waiting caller is given a ticket, got {wait:?}");
        };

        let outcome = wait_on(&ticket, PATIENCE);

        let record = completed_record(&outcome);
        assert_eq!(record.request_id, request_id);
        let reported = record.outcome().expect("the request finished");
        assert_eq!(reported.reason, "peer_offline");
        assert_eq!(reported.exit_code, 3);
        assert_eq!(
            record,
            CaptureRequestRecord {
                terminal_reported: false,
                ..fixture.row(request_id)
            },
            "the waiter is handed the durable row itself"
        );
    }

    #[test]
    fn cancelling_ends_the_request_and_hands_the_cancelled_row_to_its_waiter() {
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));
        let ticket = fixture.ticket(request_id);
        // The cancel runs on another thread; this one is the waiting caller. `wait` can only
        // return once the cancel has produced an outcome, so nothing here polls or sleeps.
        let control = fixture.control();
        let canceller = thread::spawn(move || control.cancel(request_id));

        let outcome = wait_on(&ticket, PATIENCE);
        assert_eq!(
            completed_record(&outcome)
                .outcome()
                .expect("cancelled")
                .reason,
            "cancelled"
        );

        let CaptureReply::Request { record } = canceller.join().expect("cancel thread") else {
            panic!("cancelling a live request returns its row");
        };
        assert_eq!(record.outcome().expect("cancelled").reason, "cancelled");
    }

    #[test]
    fn control_requests_finish_promptly_while_a_caller_waits_for_a_capture() {
        // Invariant 12 and the five-second control client: a sleeping waiter must hold no lock,
        // no permit, and no store transaction that the control channel needs.
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));
        let ticket = fixture.ticket(request_id);

        let control = fixture.control();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            for _ in 0..20 {
                let before = Instant::now();
                let reply = control.status(request_id);
                assert!(
                    matches!(reply, CaptureReply::Request { .. }),
                    "the control channel answered {reply:?} while a caller waited"
                );
                assert!(
                    before.elapsed() < Duration::from_secs(5),
                    "one control request took {:?}, past the control client's timeout",
                    before.elapsed()
                );
            }
            let elapsed = started.elapsed();
            control.cancel(request_id);
            elapsed
        });

        // This thread is the waiting caller. `wait` returns only once the worker's cancel has
        // produced an outcome, so the twenty control requests demonstrably ran alongside it.
        let outcome = wait_on(&ticket, PATIENCE);
        assert_eq!(
            completed_record(&outcome)
                .outcome()
                .expect("cancelled")
                .reason,
            "cancelled"
        );
        let elapsed = worker.join().expect("control worker");
        assert!(
            elapsed < Duration::from_secs(5),
            "twenty control requests took {elapsed:?} while a caller waited"
        );
    }

    #[test]
    fn a_stopped_resident_issues_no_further_wait_tickets() {
        // Waking the waiters that are already attached is the wait service's own behaviour and is
        // tested there; what belongs here is that stopping the capture service stops that service.
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));
        assert!(matches!(
            fixture.control().wait_ticket(request_id),
            CaptureReply::Started {
                wait: CaptureWait::Issued(_),
                ..
            }
        ));

        fixture.service.shutdown();

        let second = fixture.insert_live_request(fixture.root.join("second.jpg"));
        assert_eq!(
            fixture.control().wait_ticket(second),
            CaptureReply::NotStarted {
                reason: CaptureNotStarted::Capacity
            },
            "a stopped resident must refuse a wait rather than hand out a ticket to nothing"
        );
        assert!(
            fixture.row(second).outcome().is_none(),
            "refusing a wait never invents an outcome for the durable row"
        );
    }

    #[test]
    fn a_second_wait_ticket_for_one_request_is_refused_rather_than_queued() {
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));
        let ticket = fixture.ticket(request_id);
        assert_eq!(
            fixture.control().wait_ticket(request_id),
            CaptureReply::NotStarted {
                reason: CaptureNotStarted::Capacity
            },
            "a second wait on one request is refused, never queued behind the first"
        );
        drop(ticket);
    }

    #[test]
    fn starting_a_capture_returns_without_waiting_for_the_phone() {
        // F6 and the control client's five-second read timeout: the handler must return before any
        // network I/O. The peer is in TEST-NET-1 (RFC 5737), which is not routed, so a send that
        // ran on this thread would hold it for the full connect timeout.
        let fixture = fixture_reaching("192.0.2.1", Duration::from_secs(3));
        let started = Instant::now();
        let (request_id, _) = fixture.started(fixture.root.join("photo.jpg"), false);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(500),
            "starting a capture took {elapsed:?}; it must not wait for the phone"
        );
        assert_eq!(fixture.row(request_id).peer, fixture.peer);
    }

    // -- reporting and capacity ---------------------------------------------------------------

    #[test]
    fn only_a_finished_outcome_is_marked_reported() {
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));

        assert!(matches!(
            fixture.control().status(request_id),
            CaptureReply::Request { .. }
        ));
        assert!(
            !fixture.row(request_id).terminal_reported,
            "a live request must survive being asked about"
        );

        fixture.control().cancel(request_id);
        fixture.control().status(request_id);
        assert!(
            fixture.row(request_id).terminal_reported,
            "a reported outcome is what lets startup cleanup remove the row"
        );
    }

    #[test]
    fn a_ninth_live_request_is_refused_rather_than_growing_the_table() {
        let fixture = fixture();
        for index in 0..MAX_LIVE_CAPTURE_REQUESTS {
            fixture.insert_live_request(fixture.root.join(format!("photo-{index}.jpg")));
        }
        assert_eq!(
            fixture.refusal(fixture.root.join("one-too-many.jpg")),
            CaptureNotStarted::Capacity
        );
    }

    #[test]
    fn an_unpaired_peer_is_refused_before_any_row_exists() {
        let fixture = fixture();
        let reply = fixture.control().start(CaptureStartInput {
            peer: "not-a-peer".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: None,
            timeout_ms: 60_000,
            output_path: fixture.root.join("photo.jpg"),
            wait: true,
        });
        assert_eq!(
            reply,
            CaptureReply::NotStarted {
                reason: CaptureNotStarted::PeerNotPaired
            },
            "tailnet membership is not authorization and an unknown name is not a peer"
        );
        assert!(
            fixture
                .store
                .read_capture_requests()
                .expect("read")
                .is_empty()
        );
    }

    #[test]
    fn an_unusable_purpose_or_lifetime_is_refused_before_any_row_exists() {
        let fixture = fixture();
        let bidirectional_override = fixture.control().start(CaptureStartInput {
            peer: "amber".to_owned(),
            // U+202E reorders what the person holding the phone reads.
            purpose: "Photograph the router label\u{202e}".to_owned(),
            lens: None,
            timeout_ms: 60_000,
            output_path: fixture.root.join("photo.jpg"),
            wait: false,
        });
        assert_eq!(
            bidirectional_override,
            CaptureReply::NotStarted {
                reason: CaptureNotStarted::InvalidArguments
            }
        );

        let too_long = fixture.control().start(CaptureStartInput {
            peer: "amber".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: None,
            timeout_ms: MAX_CAPTURE_LIFETIME_MS + 1,
            output_path: fixture.root.join("photo.jpg"),
            wait: false,
        });
        assert_eq!(
            too_long,
            CaptureReply::NotStarted {
                reason: CaptureNotStarted::InvalidArguments
            }
        );
        assert!(
            fixture
                .store
                .read_capture_requests()
                .expect("read")
                .is_empty()
        );
    }

    // -- the phone's end of the wire ------------------------------------------------------------

    /// What the phone resident would show. The capture receiver is told before it acknowledges,
    /// so these are the phone's own record of what it was asked to do.
    #[derive(Default)]
    struct PhoneEvents {
        presented: Mutex<Vec<CaptureRequestId>>,
        delivered: Mutex<Vec<CaptureRequestId>>,
        withdrawn: Mutex<Vec<(CaptureRequestId, &'static str)>>,
    }

    impl PhoneEvents {
        fn presented(&self) -> Vec<CaptureRequestId> {
            self.presented
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn delivered(&self) -> Vec<CaptureRequestId> {
            self.delivered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn withdrawn(&self) -> Vec<(CaptureRequestId, &'static str)> {
            self.withdrawn
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl CaptureSourceEvents for PhoneEvents {
        fn capture_presented(
            &self,
            record: &meshelf_core::CaptureSourceRecord,
        ) -> Result<(), CaptureEventRefused> {
            self.presented
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(record.request_id);
            Ok(())
        }

        fn capture_delivered(&self, request_id: CaptureRequestId) {
            self.delivered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request_id);
        }

        fn capture_withdrawn(&self, request_id: CaptureRequestId, reason: CaptureWithdrawReason) {
            self.withdrawn
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((request_id, reason.as_str()));
        }
    }

    /// A phone listening on loopback, built from the production phone-side pieces: the capture
    /// receiver that records a presentation before acknowledging it, and the fetch handler that
    /// serves a captured photo exactly once. Only the camera is simulated.
    struct FakePhone {
        _directory: TempDir,
        root: PathBuf,
        _runtime: Runtime,
        store: Arc<RedbV2Store>,
        identity: InstallationIdentity,
        events: Arc<PhoneEvents>,
        address: SocketAddr,
        _shutdown: watch::Sender<bool>,
    }

    impl FakePhone {
        fn start(identity: &InstallationIdentity, desktop: DeviceId) -> Self {
            let directory = tempdir().expect("phone directory");
            let root = fs::canonicalize(directory.path()).expect("canonical phone directory");
            let store =
                Arc::new(RedbV2Store::open(root.join("phone.redb")).expect("open the phone store"));
            let events = Arc::new(PhoneEvents::default());
            let runtime = Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("fake-phone")
                .enable_all()
                .build()
                .expect("phone runtime");
            let listener = runtime
                .block_on(async { tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await })
                .expect("bind the phone listener");
            let address = listener.local_addr().expect("phone address");
            let mut config = V2ServerConfig::desktop(
                ServerIdentity {
                    signing_identity: identity.clone(),
                    device_name: "amber".to_owned(),
                },
                Arc::new(ExactDeviceAllowList::new([desktop])),
                V2OfferServices {
                    announcement_receiver: Arc::new(OfferAnnouncementHandler::new(store.clone())),
                    fetch_sender: Arc::new(OfferFetchHandler::with_resolver(
                        identity.device_id,
                        Arc::new(CaptureSourceResolver::new(store.clone(), events.clone())),
                    )),
                },
                Duration::from_secs(10),
            );
            config.capture_receiver =
                Arc::new(PhoneCaptureReceiver::new(store.clone(), events.clone()));
            config.server_capabilities = vec![
                CAP_OFFER_PULL_V2.to_owned(),
                CAP_CAPTURE_PHOTO_V1.to_owned(),
            ];
            let (shutdown, stop) = watch::channel(false);
            runtime.spawn(serve_v2(listener, config, stop));
            Self {
                _directory: directory,
                root,
                _runtime: runtime,
                store,
                identity: identity.clone(),
                events,
                address,
                _shutdown: shutdown,
            }
        }

        /// Takes the photograph and announces it, which is everything between the person tapping
        /// the notification and the requester's announcement handler being called.
        fn photograph(&self, request_id: CaptureRequestId, bytes: &[u8]) -> OfferAnnouncement {
            let root_name = format!("{request_id}.jpg");
            let path = self.root.join(&root_name);
            fs::write(&path, bytes).expect("write the photo");
            let descriptor = OfferDescriptor::File {
                root_name,
                total_bytes: bytes.len() as u64,
                content_class: meshelf_core::FileContentClass::File,
            };
            let photo = CapturedPhoto {
                offer_id: OfferId::new(),
                descriptor: descriptor.clone(),
                path,
                sha256: Sha256::digest(bytes).into(),
                width: 4032,
                height: 3024,
                delete_deadline_unix_ms: now_unix_ms() + 600_000,
            };
            let offer_id = photo.offer_id;
            assert!(matches!(
                self.store
                    .attach_captured(request_id, photo)
                    .expect("attach the photo"),
                CaptureTransition::Applied(_)
            ));
            assert!(matches!(
                self.store
                    .mark_capture_announced(request_id)
                    .expect("announce the photo"),
                CaptureTransition::Applied(_)
            ));
            OfferAnnouncement::new(
                offer_id,
                self.identity.device_id,
                DeviceId::new(),
                now_unix_ms(),
                descriptor,
            )
        }

        fn phase(&self, request_id: CaptureRequestId) -> Option<CaptureSourcePhase> {
            self.store
                .get_capture_source(request_id)
                .expect("read the phone row")
                .map(|record| record.phase)
        }
    }

    /// A desktop and a phone that trust each other, dialling each other in process.
    fn paired_phone() -> (Fixture, FakePhone) {
        let desktop = InstallationIdentity::generate();
        let phone_identity = InstallationIdentity::generate();
        let phone = FakePhone::start(&phone_identity, desktop.device_id);
        let fixture = fixture_dialling(
            desktop,
            &phone_identity,
            "127.0.0.1",
            phone.address.port(),
            Duration::from_secs(3),
        );
        (fixture, phone)
    }

    /// A minimal baseline JPEG whose frame header carries the given dimensions; publication
    /// refuses a payload it cannot read dimensions from, so a capture needs a real one.
    fn jpeg(width: u16, height: u16, filler: usize) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xD8];
        bytes.extend_from_slice(&[
            0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0,
        ]);
        bytes.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01]);
        bytes.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        bytes.extend((0..filler).map(|index| (index % 127) as u8));
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        bytes
    }

    /// Waits for something that happens on another machine's schedule — here, another process's
    /// listener answering over loopback. Production waiting is event-driven (invariant 12); this
    /// is a test watching the far end of a socket, which has no event to subscribe to.
    fn eventually(what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            if ready() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("{what} did not happen within {PATIENCE:?}");
    }

    // -- presentation, the pull, and the published photo ----------------------------------------

    #[test]
    fn a_presented_acknowledgement_arms_the_grant_and_nothing_else_does() {
        // Without this the grant stays `AwaitingPresentation`, every correlated announcement is
        // refused `capture_not_armed`, and every capture in the product ends `expired`.
        let (fixture, phone) = paired_phone();
        let (request_id, _) = fixture.started(fixture.root.join("router-label.jpg"), false);

        eventually("the phone presented the request", || {
            phone.events.presented().contains(&request_id)
        });
        eventually("the desktop armed the grant", || {
            matches!(
                fixture.row(request_id).phase,
                CaptureRequestPhase::Armed { .. }
            )
        });

        // Armed is exactly what a correlated announcement needs; an unarmed grant is refused.
        let announcement = phone.photograph(request_id, &jpeg(640, 480, 64));
        assert_eq!(
            fixture
                .service
                .router()
                .route(
                    phone.identity.device_id,
                    &announcement,
                    CaptureCorrelation { request_id },
                )
                .expect("route the announcement"),
            CaptureRoute::Attached
        );
    }

    #[test]
    fn a_capture_runs_from_request_to_a_published_photo_and_hands_the_row_to_its_waiter() {
        let (fixture, phone) = paired_phone();
        let bytes = jpeg(4032, 3024, 20_000);
        let output = fixture.root.join("router-label.jpg");
        let (request_id, wait) = fixture.started(output.clone(), true);
        let CaptureWait::Issued(ticket) = wait else {
            panic!("a waiting caller is given a ticket, got {wait:?}");
        };

        eventually("the desktop armed the grant", || {
            matches!(
                fixture.row(request_id).phase,
                CaptureRequestPhase::Armed { .. }
            )
        });
        let announcement = phone.photograph(request_id, &bytes);
        assert_eq!(
            fixture
                .service
                .router()
                .route(
                    phone.identity.device_id,
                    &announcement,
                    CaptureCorrelation { request_id },
                )
                .expect("route the announcement"),
            CaptureRoute::Attached
        );

        let record = completed_record(&wait_on(&ticket, PATIENCE));
        let outcome = record.outcome().expect("the capture finished");
        assert_eq!(
            (outcome.json_type, outcome.reason, outcome.exit_code),
            ("capture_completed", "completed", 0),
            "a capture that published its photo reports success to its waiter: {record:?}"
        );
        let CaptureRequestPhase::Completed { receipt } = &record.phase else {
            panic!("expected a completed capture, got {:?}", record.phase);
        };
        assert_eq!(receipt.output_path, output, "published at the named path");
        assert_eq!(receipt.bytes, bytes.len() as u64);
        assert_eq!((receipt.width, receipt.height), (4032, 3024));
        assert_eq!(fs::read(&output).expect("the published photo"), bytes);
        eventually("the handed-over outcome to be marked reported", || {
            fixture.row(request_id).terminal_reported
        });

        // The phone served it exactly once and holds no photo any more.
        eventually("the phone recorded one delivery", || {
            phone.events.delivered() == vec![request_id]
        });
        assert_eq!(phone.phase(request_id), Some(CaptureSourcePhase::Delivered));
        assert!(
            fixture.store.read_offer_shelf().expect("shelf").is_empty(),
            "a capture never reaches the shelf"
        );
    }

    #[test]
    fn cancelling_a_request_the_phone_is_presenting_tells_the_phone_to_stop() {
        // Best effort, and unobservable until the port a capture dials is configuration rather
        // than a constant: the durable row is already terminal whether or not this arrives.
        let (fixture, phone) = paired_phone();
        let (request_id, _) = fixture.started(fixture.root.join("router-label.jpg"), false);
        eventually("the phone presented the request", || {
            phone.events.presented().contains(&request_id)
        });

        let CaptureReply::Request { record } = fixture.control().cancel(request_id) else {
            panic!("cancelling a live request returns its row");
        };
        assert_eq!(record.outcome().expect("cancelled").reason, "cancelled");

        eventually("the phone withdrew the request", || {
            phone.events.withdrawn() == vec![(request_id, "cancelled")]
        });
        assert_eq!(
            phone.phase(request_id),
            Some(CaptureSourcePhase::Terminal {
                code: meshelf_core::CaptureSourceTerminalCode::Cancelled
            })
        );
    }

    // -- a cancel never speaks for a pull -------------------------------------------------------

    #[test]
    fn cancelling_a_claimed_capture_leaves_the_outcome_to_its_pull() {
        // The race this refuses: between the last byte arriving and `complete_capture`, forcing
        // the row to `Cancelled` would tell the agent the capture failed while the photo was
        // published anyway — leaving an unannounced file at the path it named, so that its retry
        // fails `output_exists`.
        let fixture = fixture_reaching("192.0.2.1", Duration::from_secs(3));
        let output = fixture.root.join("router-label.jpg");
        let bytes = jpeg(64, 48, 16);
        let (request_id, _) = fixture.started(output.clone(), false);
        let ticket = fixture.ticket(request_id);
        let (finished, outcome) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let _ = finished.send(wait_on(&ticket, PATIENCE));
        });
        let activation_id = fixture.claim(request_id, bytes.len() as u64);

        let CaptureReply::Request { record } = fixture.control().cancel(request_id) else {
            panic!("cancelling a claimed request returns its row");
        };
        assert!(
            matches!(record.phase, CaptureRequestPhase::Claimed { .. }),
            "a claimed request keeps its phase; its pull owns the outcome"
        );
        assert!(
            record.outcome().is_none(),
            "nothing may report an outcome the pull has not reached"
        );
        assert!(
            fixture.cancel_signalled(request_id),
            "the transfer in flight must still be told to stop"
        );
        assert!(!fixture.row(request_id).terminal_reported);
        assert!(
            outcome.recv_timeout(Duration::from_millis(400)).is_err(),
            "the waiter must not be handed a cancellation the pull never agreed to",
        );

        // The pull finishes the way it does when every byte had already arrived, and that is
        // what the agent is told.
        fs::write(&output, &bytes).expect("publish the photo");
        let CaptureTransition::Applied(completed) = fixture
            .store
            .complete_capture(
                request_id,
                activation_id,
                CaptureReceipt {
                    output_path: output.clone(),
                    sha256: Sha256::digest(&bytes).into(),
                    bytes: bytes.len() as u64,
                    width: 64,
                    height: 48,
                },
            )
            .expect("complete the capture")
        else {
            panic!("a cancelled-but-claimed request must still be completable by its pull");
        };
        fixture.control().capture_finished(&completed);
        assert_eq!(
            completed_record(
                &outcome
                    .recv_timeout(PATIENCE)
                    .expect("the original waiter receives the pull outcome"),
            )
            .outcome()
            .expect("completed")
            .reason,
            "completed"
        );
        waiter.join().expect("waiter thread");
    }

    #[test]
    fn ending_an_unclaimed_request_never_ends_a_claimed_one() {
        // Every network answer that arrives after a claim goes through this: a status from the
        // phone, an acknowledgement, an expiry. Ending the row here would turn a published photo
        // into an unrecorded one.
        let fixture = fixture_reaching("192.0.2.1", Duration::from_secs(3));
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));
        let ticket = fixture.ticket(request_id);
        fixture.claim(request_id, 1_024);

        fixture
            .service
            .end_unclaimed(request_id, CaptureTerminalCode::Expired, None);

        assert!(
            matches!(
                fixture.row(request_id).phase,
                CaptureRequestPhase::Claimed { .. }
            ),
            "a claimed request belongs to its pull"
        );
        assert_eq!(
            wait_on(&ticket, Duration::from_millis(400)),
            WaitOutcome::TimedOut,
            "no waiter may be woken with an outcome the pull did not reach"
        );

        // The same call on an unclaimed request does end it, which is what the ack path needs.
        let unclaimed = fixture.insert_live_request(fixture.root.join("second.jpg"));
        fixture
            .service
            .end_unclaimed(unclaimed, CaptureTerminalCode::Expired, None);
        assert_eq!(
            fixture.row(unclaimed).outcome().expect("ended").reason,
            "expired"
        );
    }

    // -- the expiry timer -----------------------------------------------------------------------

    #[test]
    fn the_expiry_timer_ends_a_request_the_phone_never_answered() {
        // The peer is in TEST-NET-1, so the send is still waiting to connect when the request's
        // own expiry passes: the timer, not the failed send, is what ends this capture.
        let fixture = fixture_reaching("192.0.2.1", Duration::from_secs(30));
        let (request_id, wait) =
            match fixture.start_within(fixture.root.join("photo.jpg"), true, 400) {
                CaptureReply::Started { request_id, wait } => (request_id, wait),
                other => panic!("expected a started capture, got {other:?}"),
            };
        let CaptureWait::Issued(ticket) = wait else {
            panic!("a waiting caller is given a ticket, got {wait:?}");
        };

        let record = completed_record(&wait_on(&ticket, PATIENCE));
        assert_eq!(record.request_id, request_id);
        let outcome = record.outcome().expect("the request finished");
        assert_eq!(
            (outcome.reason, outcome.exit_code),
            ("expired", 3),
            "a request nobody answered expires at its own deadline, and its waiter is woken then"
        );
    }

    #[test]
    fn a_finished_request_stops_its_expiry_timer_from_sleeping_out_its_lifetime() {
        // The timer holds a reference to the whole service while it sleeps. A resident that
        // finishes a capture and quits would otherwise drop its last reference — and its own
        // runtime — on one of that runtime's worker threads.
        let fixture = fixture();
        let (request_id, _) = fixture.started(fixture.root.join("photo.jpg"), false);
        eventually("the unanswered request ended", || {
            fixture.row(request_id).outcome().is_some()
        });
        eventually("the request's watch was released", || {
            fixture.service.lock_cancels().get(&request_id).is_none()
        });
    }

    #[test]
    fn the_services_last_reference_may_be_released_by_one_of_its_own_tasks() {
        // Reproduces the drop that panics "Cannot drop a runtime in a context where blocking is
        // not allowed": a panic inside a task is swallowed by the runtime, so the hook is how a
        // test sees it at all.
        let panics: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&panics);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            recorder
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(info.to_string());
            previous(info);
        }));

        let fixture = fixture();
        let held = Arc::clone(&fixture.service);
        let (go, wait_for_go) = tokio::sync::oneshot::channel::<()>();
        let (dropped, released) = std::sync::mpsc::channel::<()>();
        fixture.service.runtime().spawn(async move {
            let _ = wait_for_go.await;
            // The test has let go, so this is the last reference and releasing it here drops the
            // runtime this task is running on. `dropped` is disconnected either way, so the test
            // is never left waiting on a panic.
            drop(held);
            drop(dropped);
        });
        let Fixture { _directory, .. } = fixture;
        go.send(()).expect("the capture task is still running");
        assert!(
            released.recv_timeout(PATIENCE).is_err(),
            "the task ends by dropping the service, so nothing is ever sent"
        );

        let _ = std::panic::take_hook();
        let recorded = panics
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert!(
            !recorded
                .iter()
                .any(|panic| panic.contains("Cannot drop a runtime")),
            "releasing the last reference from a capture task must not panic: {recorded:?}"
        );
    }

    // -- reporting an outcome exactly once ------------------------------------------------------

    #[test]
    fn only_a_finished_row_wakes_a_waiter_and_is_marked_reported() {
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));
        let ticket = fixture.ticket(request_id);
        let (finished, outcome) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let _ = finished.send(wait_on(&ticket, PATIENCE));
        });

        fixture.service.complete_wait(&fixture.row(request_id));
        assert!(
            outcome.recv_timeout(Duration::from_millis(400)).is_err(),
            "a live row is not an outcome and must never be handed to a waiter",
        );
        assert!(
            !fixture.row(request_id).terminal_reported,
            "a live request has nothing to report"
        );

        fixture.control().cancel(request_id);
        assert_eq!(
            completed_record(
                &outcome
                    .recv_timeout(PATIENCE)
                    .expect("the original waiter receives the finished row"),
            )
            .outcome()
            .expect("cancelled")
            .reason,
            "cancelled"
        );
        waiter.join().expect("waiter thread");
        assert!(
            fixture.row(request_id).terminal_reported,
            "handing the outcome to its waiter is what reports it, so startup can remove the row"
        );
    }

    #[test]
    fn a_wait_ticket_for_a_finished_request_hands_back_its_row_and_reports_it() {
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));
        fixture.control().cancel(request_id);
        assert!(
            !fixture.row(request_id).terminal_reported,
            "nobody has been told yet: the cancel had no waiter attached"
        );

        let CaptureReply::Request { record } = fixture.control().wait_ticket(request_id) else {
            panic!("a finished request must answer with its row, never with a ticket to nothing");
        };
        assert_eq!(record.outcome().expect("cancelled").reason, "cancelled");
        assert!(
            fixture.row(request_id).terminal_reported,
            "the row is discharged by the answer that carried its outcome"
        );
    }

    #[test]
    fn a_wait_registration_lives_past_its_request_by_the_transfer_allowance() {
        // A transfer that started just before expiry still has to deliver its outcome to the
        // waiter, so the slot outlives the request by exactly the allowance and no longer.
        let fixture = fixture();
        let (request_id, wait) = fixture.started(fixture.root.join("photo.jpg"), true);
        let CaptureWait::Issued(ticket) = wait else {
            panic!("a waiting caller is given a ticket, got {wait:?}");
        };
        assert_eq!(
            ticket.deadline_unix_ms,
            fixture.row(request_id).grant.expires_at_unix_ms + CAPTURE_TRANSFER_ALLOWANCE_MS
        );
        assert_eq!(ticket.port, fixture.service.wait_port());
    }

    #[test]
    fn every_live_request_may_attach_one_waiter_and_a_further_waiter_is_refused() {
        // One waiter per live request and no slack: fewer would refuse a capture its own wait,
        // more would let waiters accumulate on a resident that has no request left to wake them.
        assert_eq!(
            MAX_CAPTURE_WAITERS, MAX_LIVE_CAPTURE_REQUESTS,
            "the waiter cap is the live-request cap, so exactly every live capture may be waited on"
        );
        let fixture = fixture();
        let waiters: Vec<_> = (0..MAX_LIVE_CAPTURE_REQUESTS)
            .map(|index| {
                let request_id =
                    fixture.insert_live_request(fixture.root.join(format!("photo-{index}.jpg")));
                let ticket = fixture.ticket(request_id);
                thread::spawn(move || wait_on(&ticket, PATIENCE))
            })
            .collect();
        // Give the accept loop time to attach every deliberately long-lived waiter. The wait
        // service's own tests prove the exact attachment count; this integration test proves that
        // CaptureService supplies the configured cap rather than an unbounded value.
        thread::sleep(Duration::from_millis(250));

        // A ninth registration is legitimate — the wait service holds many more — but attaching
        // to it must be refused while every slot is in use.
        let token = fixture
            .service
            .waits
            .register("one-too-many", Instant::now() + PATIENCE)
            .expect("the wait service still accepts registrations");
        let extra = WaitTicket {
            port: fixture.service.wait_port(),
            token: token.as_str().to_owned(),
            deadline_unix_ms: 0,
        };
        match wait_on(&extra, Duration::from_secs(2)) {
            WaitOutcome::Refused(reason) => {
                assert!(reason.contains("too many waiters"), "{reason}");
            }
            other => panic!("a ninth waiter was admitted: {other:?}"),
        }

        fixture.service.shutdown();
        for waiter in waiters {
            assert_eq!(waiter.join().expect("waiter"), WaitOutcome::Shutdown);
        }
    }

    // -- what a caller is told about waiting ----------------------------------------------------

    #[test]
    fn a_caller_refused_a_wait_is_told_so_rather_than_treated_as_not_having_asked() {
        let fixture = fixture();
        fixture.service.shutdown();

        let (request_id, wait) = fixture.started(fixture.root.join("photo.jpg"), true);
        assert_eq!(
            wait,
            CaptureWait::Refused,
            "a caller that asked to wait and was refused must be able to tell that from never \
             having asked"
        );
        assert!(
            fixture.row(request_id).outcome().is_none(),
            "refusing a wait never harms the request itself"
        );

        let (_, not_asked) = fixture.started(fixture.root.join("second.jpg"), false);
        assert_eq!(not_asked, CaptureWait::NotRequested);
    }

    // -- reconciliation -----------------------------------------------------------------------

    #[test]
    fn startup_reconciliation_ends_what_the_last_run_left_and_resumes_nothing() {
        let fixture = fixture();
        let request_id = fixture.insert_live_request(fixture.root.join("photo.jpg"));

        let report = fixture
            .service
            .reconcile_at_startup()
            .expect("reconcile at startup");

        assert_eq!(
            report.cancel.len(),
            1,
            "the phone may still be presenting it"
        );
        assert_eq!(report.cancel[0].request_id, request_id);
        assert!(report.uncertain.is_empty());
        assert_eq!(
            fixture.row(request_id).outcome().expect("ended").reason,
            "resident_restarted",
            "an unclaimed request is ended, never resumed"
        );
    }

    // -- peer labels --------------------------------------------------------------------------

    #[test]
    fn only_a_connect_that_found_nobody_is_reported_as_the_peer_being_offline() {
        // An agent told `peer_offline` learns the phone was not reachable. Reporting a failure
        // that happened mid-exchange that way would tell it to retry something that will not work.
        assert!(is_peer_offline(&NetError::Unavailable(
            "capture target is offline".to_owned()
        )));
        assert!(is_peer_offline(&NetError::Io(io::Error::from(
            io::ErrorKind::ConnectionRefused
        ))));
        assert!(!is_peer_offline(&NetError::Io(io::Error::from(
            io::ErrorKind::ConnectionReset
        ))));
        assert!(!is_peer_offline(&NetError::Rejected(
            "capture request refused".to_owned()
        )));
        assert!(!is_peer_offline(&NetError::Timeout("capture request")));
    }

    #[test]
    fn a_peer_name_too_long_or_not_plain_text_never_blocks_a_capture() {
        let long = CapturePeer {
            device_id: DeviceId::new(),
            hostname: "n".repeat(MAX_CAPTURE_LABEL_BYTES + 40),
            addresses: Vec::new(),
            public_key: Vec::new(),
        };
        let label = peer_label(&long);
        assert_eq!(label.len(), MAX_CAPTURE_LABEL_BYTES);
        assert!(validate_capture_label(&label).is_ok());

        // A phone names itself, so its name can be anything; the capture must still start.
        let hostile = CapturePeer {
            hostname: "phone\u{202e}".to_owned(),
            ..long
        };
        assert_eq!(peer_label(&hostile), hostile.device_id.to_string());
        assert!(validate_capture_label(&peer_label(&hostile)).is_ok());
    }

    #[test]
    fn a_peer_is_resolved_by_device_id_hostname_or_node_id() {
        let fixture = fixture();
        for selector in ["amber", "AMBER", "phone-node", &fixture.peer.to_string()] {
            let peer = fixture
                .coordinator
                .resolve_capture_peer(selector)
                .unwrap_or_else(|error| panic!("selector {selector:?} did not resolve: {error}"));
            assert_eq!(peer.device_id, fixture.peer);
        }
        assert!(fixture.coordinator.resolve_capture_peer("  ").is_err());
    }
}
