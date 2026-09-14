//! Async drivers for one pairing exchange over the typestate machines of
//! `meshelf_protocol::pairing` (work order 09 decision 12; amendments A11, A12).
//!
//! The phone side is [`PhonePairingResponder`], handed a pairing-only connection by the listener
//! together with the [`PairingPermit`] that admitted it. The desktop side is
//! [`PeerClient::pair_initiate`], and [`PeerClient::pair_resume`] when a final `Complete` was lost.
//! Each persists before releasing the frame that tells the peer, as the machines' types require:
//! the phone its `ApprovedPending` before `Decision{Confirm}` and the desktop's trust before
//! `Complete`; the desktop the phone's trust before `DesktopCommitted`.
//!
//! Every frame is read under [`PAIRING_MAX_FRAME_BYTES`] and validated. A read that waits for the
//! peer's next protocol step is bounded by [`PAIRING_INACTIVITY`] and by the state's deadline. A
//! wait for a person's decision is bounded by the pairing expiry only: nobody compares six digits
//! in fifteen seconds (interpretation recorded in the lane plan, Area 2(c)).

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use meshelf_core::DeviceId;
use meshelf_identity::InstallationIdentity;
use meshelf_protocol::{
    CAP_PAIRING_V1, ClientHello, ServerHello, V2_PROTOCOL_VERSION, V2Message, WireMessage,
    pairing::{
        DesktopAwaitingComplete, DesktopPairing, PAIRING_MAX_FRAME_BYTES, PAIRING_WINDOW_MAX_MS,
        PairedPeer, PairingAbortCode, PairingCandidate, PairingFailure, PairingFrame, PairingId,
        PairingNonce, PairingResult, PhonePairing, PhoneTrustPending, SignedPairingFrame,
    },
    read_frame_async, read_v2_frame_async_limited, validate_v2_message, write_frame_async,
    write_v2_frame_async,
};
use meshelf_tailscale::{ApprovedPending, InstallationStore, PeerNetworkBinding, RegistryError};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::timeout,
};

use crate::{
    PeerClient,
    admission::{PairingClock, PairingPermit, PhoneDecision, SystemClock},
};

/// Longest silence tolerated while the peer owes the next protocol step.
pub const PAIRING_INACTIVITY: Duration = Duration::from_secs(15);

/// Any byte stream a pairing runs over: the listener's TCP stream, or an in-memory pipe in tests.
pub trait PairingStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> PairingStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// The connection a pairing-only permit was issued for. Both hellos are exactly those sent on it,
/// because their signing bytes enter the transcript (A2).
pub struct PairingConnection<'a> {
    pub remote: SocketAddr,
    pub client_hello: &'a ClientHello,
    pub server_hello: &'a ServerHello,
}

/// Runs one admitted pairing-only connection to its end and returns the A11 result.
#[async_trait]
pub trait PairingResponder: Send + Sync + 'static {
    async fn respond(
        &self,
        stream: &mut dyn PairingStream,
        connection: PairingConnection<'_>,
        permit: PairingPermit,
    ) -> PairingResult;
}

/// What the phone resident shows. Nothing is reported for a connection that never produced a
/// candidate: the person is told only once both reveals verified (no notification, no queue).
pub trait PairingEvents: Send + Sync + 'static {
    /// Show this code; the answer goes to `PairingWindow::confirm` or `PairingWindow::reject`.
    fn on_candidate(&self, candidate: &PairingCandidate);
    /// A session that showed a candidate, or a resume of an approved one, ended. `result` is an
    /// A11 word; a later resume of the same pairing id may still end `paired`.
    fn on_finished(&self, pairing_id: PairingId, result: PairingResult);
}

#[derive(Debug)]
enum Stop {
    Timeout,
    WindowClosed,
    Wire(String),
}

impl Stop {
    fn code(&self) -> PairingAbortCode {
        match self {
            Self::Timeout => PairingAbortCode::Timeout,
            Self::WindowClosed => PairingAbortCode::WindowClosed,
            Self::Wire(_) => PairingAbortCode::Invalid,
        }
    }
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("the peer did not answer in time"),
            Self::WindowClosed => f.write_str("the pairing window was closed"),
            Self::Wire(detail) => write!(f, "pairing connection failed: {detail}"),
        }
    }
}

/// Reads the next pairing frame before `deadline_unix_ms`, and before `inactivity` if given.
/// `abort`, when given, ends the wait as soon as the window is closed.
async fn next_frame(
    mut stream: &mut dyn PairingStream,
    clock: &dyn PairingClock,
    deadline_unix_ms: u64,
    inactivity: Option<Duration>,
    abort: Option<&mut watch::Receiver<bool>>,
) -> Result<SignedPairingFrame, Stop> {
    let remaining = Duration::from_millis(deadline_unix_ms.saturating_sub(clock.now_unix_ms()));
    let limit = inactivity.map_or(remaining, |inactivity| inactivity.min(remaining));
    let read = async move {
        let message = read_v2_frame_async_limited(&mut stream, PAIRING_MAX_FRAME_BYTES)
            .await
            .map_err(|error| Stop::Wire(error.to_string()))?;
        validate_v2_message(&message).map_err(|error| Stop::Wire(error.to_string()))?;
        match message {
            V2Message::Pair(frame) => Ok(frame),
            _ => Err(Stop::Wire("expected a pairing frame".to_owned())),
        }
    };
    let bounded = async move { timeout(limit, read).await.unwrap_or(Err(Stop::Timeout)) };
    match abort {
        None => bounded.await,
        Some(abort) => tokio::select! {
            result = bounded => result,
            () = window_closed(abort) => Err(Stop::WindowClosed),
        },
    }
}

async fn window_closed(abort: &mut watch::Receiver<bool>) {
    loop {
        if *abort.borrow_and_update() {
            return;
        }
        if abort.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn send(mut stream: &mut dyn PairingStream, frame: SignedPairingFrame) -> Result<(), Stop> {
    timeout(
        PAIRING_INACTIVITY,
        write_v2_frame_async(&mut stream, &V2Message::Pair(frame)),
    )
    .await
    .map_err(|_| Stop::Timeout)?
    .map_err(|error| Stop::Wire(error.to_string()))
}

/// The A11 result and abort code for a trust-store refusal.
fn store_refusal(error: &RegistryError) -> (PairingResult, PairingAbortCode) {
    match error {
        RegistryError::PendingPairingExpired => (PairingResult::Timeout, PairingAbortCode::Timeout),
        RegistryError::PriorIdentityMismatch | RegistryError::DeviceIdentityConflict { .. } => (
            PairingResult::IdentityChanged,
            PairingAbortCode::IdentityChanged,
        ),
        _ => (PairingResult::Failed, PairingAbortCode::Invalid),
    }
}

/// How a phone session ended, and what to tell the desktop and the person.
struct Ended {
    pairing_id: Option<PairingId>,
    result: PairingResult,
    reply: Option<SignedPairingFrame>,
    /// The person saw this session (a candidate, or a resume of their approval).
    report: bool,
}

impl Ended {
    fn new(
        pairing_id: Option<PairingId>,
        result: PairingResult,
        reply: Option<SignedPairingFrame>,
        report: bool,
    ) -> Self {
        Self {
            pairing_id,
            result,
            reply,
            report,
        }
    }

    fn failed(pairing_id: Option<PairingId>, failure: PairingFailure, report: bool) -> Self {
        Self::new(
            pairing_id,
            failure.result(),
            failure.abort.map(|abort| *abort),
            report,
        )
    }

    fn stopped(
        pairing_id: PairingId,
        code: PairingAbortCode,
        abort: Result<SignedPairingFrame, meshelf_protocol::pairing::PairingError>,
        report: bool,
    ) -> Self {
        Self::new(
            Some(pairing_id),
            PairingResult::from(code),
            abort.ok(),
            report,
        )
    }
}

/// The phone's pairing driver. It owns no window state: the permit carries the session's slot,
/// close signal, and decision channel.
pub struct PhonePairingResponder {
    identity: InstallationIdentity,
    store: InstallationStore,
    clock: Arc<dyn PairingClock>,
    events: Arc<dyn PairingEvents>,
}

impl PhonePairingResponder {
    /// `store` is the phone's `state.json`; the local device is `identity`'s. `clock` should be
    /// the one the `PairingWindow` uses.
    #[must_use]
    pub fn new(
        identity: InstallationIdentity,
        store: InstallationStore,
        clock: Arc<dyn PairingClock>,
        events: Arc<dyn PairingEvents>,
    ) -> Self {
        Self {
            identity,
            store,
            clock,
            events,
        }
    }

    fn local(&self) -> DeviceId {
        self.identity.device_id
    }

    fn now(&self) -> u64 {
        self.clock.now_unix_ms()
    }

    /// An abort signed outside any session, for a connection refused before a machine exists.
    fn abort_frame(
        &self,
        pairing_id: PairingId,
        code: PairingAbortCode,
    ) -> Option<SignedPairingFrame> {
        SignedPairingFrame::sign(
            PairingFrame::Abort {
                pairing_id,
                code,
                detail: None,
            },
            &self.identity,
        )
        .ok()
    }

    /// The trusted identity a pairing with this desktop would displace, read when the session
    /// begins, so a record that changes while the person compares codes is refused, not replaced.
    /// A hello claiming a trusted device id under another key from another address is refused
    /// here, before `Commit`, so no code is ever shown for it.
    fn displaced(
        &self,
        hello: &ClientHello,
        address: IpAddr,
    ) -> Result<Option<(DeviceId, Vec<u8>)>, RegistryError> {
        let state = self.store.load_for_identity(self.local())?;
        state.peers.displaced_identity(
            hello.device_id,
            &hello.public_key,
            &PeerNetworkBinding::ObservedTailscaleAddress { address },
        )
    }

    async fn run(
        &self,
        stream: &mut dyn PairingStream,
        connection: &PairingConnection<'_>,
        permit: &PairingPermit,
    ) -> Ended {
        let mut abort = permit.abort_signal();
        let fresh = match permit.fresh_until() {
            Some(until) => match PhonePairing::new(
                self.identity.clone(),
                connection.client_hello,
                connection.server_hello,
                PairingNonce::generate(),
                until,
                self.now(),
            ) {
                Ok(phone) => Some(phone),
                Err(failure) => return Ended::failed(None, failure, false),
            },
            None => None,
        };
        let deadline = fresh
            .as_ref()
            .map_or(u64::MAX, PhonePairing::deadline_unix_ms);
        let first = match next_frame(
            stream,
            &*self.clock,
            deadline,
            Some(PAIRING_INACTIVITY),
            Some(&mut abort),
        )
        .await
        {
            Ok(frame) => frame,
            // Before `Begin` there is no pairing id to abort under, and nothing was shown.
            Err(stop) => return Ended::new(None, PairingResult::from(stop.code()), None, false),
        };
        let pairing_id = *first.frame.pairing_id();
        if matches!(first.frame, PairingFrame::DesktopCommitted { .. }) {
            return self.resume(connection, permit, &first);
        }
        let Some(phone) = fresh else {
            // With no window open a connection may only resume an approved transcript.
            return Ended::new(
                Some(pairing_id),
                PairingResult::WindowClosed,
                self.abort_frame(pairing_id, PairingAbortCode::WindowClosed),
                false,
            );
        };
        self.fresh(stream, connection, permit, phone, &first, abort)
            .await
    }

    async fn fresh(
        &self,
        stream: &mut dyn PairingStream,
        connection: &PairingConnection<'_>,
        permit: &PairingPermit,
        phone: PhonePairing,
        begin: &SignedPairingFrame,
        mut abort: watch::Receiver<bool>,
    ) -> Ended {
        let clock = &*self.clock;
        let (phone, commit) = match phone.on_frame(begin, self.now()) {
            Ok(next) => next,
            Err(failure) => return Ended::failed(Some(*begin.frame.pairing_id()), failure, false),
        };
        let id = phone.pairing_id();
        let remote = connection.remote.ip();
        let prior = match self.displaced(connection.client_hello, remote) {
            Ok(prior) => prior,
            Err(error) => {
                let (result, code) = store_refusal(&error);
                return Ended::new(Some(id), result, phone.abort(code, None).ok(), false);
            }
        };
        if let Err(stop) = send(stream, commit).await {
            return Ended::stopped(id, stop.code(), phone.abort(stop.code(), None), false);
        }
        let reveal = match next_frame(
            stream,
            clock,
            phone.deadline_unix_ms(),
            Some(PAIRING_INACTIVITY),
            Some(&mut abort),
        )
        .await
        {
            Ok(frame) => frame,
            Err(stop) => {
                return Ended::stopped(id, stop.code(), phone.abort(stop.code(), None), false);
            }
        };
        let (shown, reveal) = match phone.on_frame(&reveal, self.now()) {
            Ok(next) => next,
            Err(failure) => return Ended::failed(Some(id), failure, false),
        };
        if let Err(stop) = send(stream, reveal).await {
            return Ended::stopped(id, stop.code(), shown.abort(stop.code(), None), false);
        }

        // Both reveals verified: only now is the person told anything, and from here the end of
        // the session is reported.
        let candidate = shown.candidate().clone();
        let mut decision = permit.offer_candidate(&candidate);
        self.events.on_candidate(&candidate);
        let deadline = shown.deadline_unix_ms();
        let waited = tokio::select! {
            decided = &mut decision => Ok(decided.ok()),
            read = next_frame(stream, clock, deadline, None, Some(&mut abort)) => Err(read),
        };
        let hash = match waited {
            Ok(Some(PhoneDecision::Confirm(hash))) => hash,
            Ok(Some(PhoneDecision::Reject)) => {
                return Ended::new(Some(id), PairingResult::Declined, shown.reject().ok(), true);
            }
            Ok(None) => {
                let abort = shown.abort(PairingAbortCode::Invalid, None).ok();
                return Ended::new(Some(id), PairingResult::Failed, abort, true);
            }
            // While the person compares codes the desktop may only abort.
            Err(Ok(frame)) => {
                return Ended::failed(Some(id), shown.on_frame(&frame, self.now()), true);
            }
            Err(Err(stop)) => {
                return Ended::stopped(id, stop.code(), shown.abort(stop.code(), None), true);
            }
        };
        if !permit.enter_approved() {
            let code = PairingAbortCode::WindowClosed;
            return Ended::stopped(id, code, shown.abort(code, None), true);
        }
        let pending = match shown.confirm(&hash, self.now()) {
            Ok(pending) => pending,
            Err(failure) => return Ended::failed(Some(id), failure, true),
        };
        let stored = ApprovedPending {
            approval: pending.approved_pending().clone(),
            observed_address: remote,
        };
        if let Err(error) = self.store.update(self.local(), |state| {
            state.pending_pairing = Some(stored.clone());
            Ok(())
        }) {
            let (result, code) = store_refusal(&error);
            return Ended::new(Some(id), result, pending.abort(code, None).ok(), true);
        }
        permit.note_resumable(&stored);
        let (waiting, decision) = match pending.approval_persisted() {
            Ok(next) => next,
            Err(failure) => return Ended::failed(Some(id), failure, true),
        };
        if let Err(stop) = send(stream, decision).await {
            return Ended::stopped(id, stop.code(), waiting.abort(stop.code(), None), true);
        }
        // Past the durable approval, closing the window no longer ends the session (A12).
        let committed = match next_frame(
            stream,
            clock,
            waiting.deadline_unix_ms(),
            Some(PAIRING_INACTIVITY),
            None,
        )
        .await
        {
            Ok(frame) => frame,
            Err(stop) => {
                return Ended::stopped(id, stop.code(), waiting.abort(stop.code(), None), true);
            }
        };
        match waiting.on_frame(&committed, self.now()) {
            Ok(trust) => self.complete(trust, prior, permit),
            Err(failure) => Ended::failed(Some(id), failure, true),
        }
    }

    /// A12: a new connection whose first frame is `DesktopCommitted` for the stored approval,
    /// from the same key and the address it was approved at, completes without a new code.
    fn resume(
        &self,
        connection: &PairingConnection<'_>,
        permit: &PairingPermit,
        frame: &SignedPairingFrame,
    ) -> Ended {
        let id = *frame.frame.pairing_id();
        let state = match self.store.load_for_identity(self.local()) {
            Ok(state) => state,
            Err(error) => {
                let (result, code) = store_refusal(&error);
                return Ended::new(Some(id), result, self.abort_frame(id, code), false);
            }
        };
        let Some(stored) = state
            .pending_pairing
            .clone()
            .filter(|pending| pending.approval.pairing_id == id)
        else {
            let abort = self.abort_frame(id, PairingAbortCode::Invalid);
            return Ended::new(Some(id), PairingResult::Invalid, abort, false);
        };
        // The machine checks the key and transcript; the observed address is this layer's check.
        if stored.observed_address != connection.remote.ip() {
            let abort = self.abort_frame(id, PairingAbortCode::IdentityChanged);
            return Ended::new(Some(id), PairingResult::IdentityChanged, abort, true);
        }
        if !permit.enter_approved() {
            let abort = self.abort_frame(id, PairingAbortCode::WindowClosed);
            return Ended::new(Some(id), PairingResult::WindowClosed, abort, true);
        }
        let paired = stored.paired_peer();
        let prior = match state.peers.displaced_identity(
            paired.peer.device_id,
            &paired.peer.public_key,
            &paired.binding,
        ) {
            Ok(prior) => prior,
            Err(error) => {
                let (result, code) = store_refusal(&error);
                return Ended::new(Some(id), result, self.abort_frame(id, code), true);
            }
        };
        match PhonePairing::resume(
            self.identity.clone(),
            connection.client_hello,
            &stored.approval,
            frame,
            self.now(),
        ) {
            Ok(trust) => self.complete(trust, prior, permit),
            Err(failure) => Ended::failed(Some(id), failure, true),
        }
    }

    /// Promotes the approval to desktop trust and clears it in one atomic write, then releases
    /// `Complete`.
    fn complete(
        &self,
        trust: PhoneTrustPending,
        prior: Option<(DeviceId, Vec<u8>)>,
        permit: &PairingPermit,
    ) -> Ended {
        let id = trust.pairing_id();
        let (pairing_id, transcript_hash) = (trust.peer().pairing_id, trust.peer().transcript_hash);
        if let Err(error) = self.store.promote_pending_pairing(
            self.local(),
            &pairing_id,
            &transcript_hash,
            self.now(),
            prior,
        ) {
            let (result, code) = store_refusal(&error);
            return Ended::new(Some(id), result, trust.abort(code, None).ok(), true);
        }
        permit.clear_resumable();
        match trust.trust_persisted() {
            Ok(complete) => Ended::new(Some(id), PairingResult::Paired, Some(complete), true),
            Err(failure) => Ended::failed(Some(id), failure, true),
        }
    }
}

#[async_trait]
impl PairingResponder for PhonePairingResponder {
    async fn respond(
        &self,
        stream: &mut dyn PairingStream,
        connection: PairingConnection<'_>,
        permit: PairingPermit,
    ) -> PairingResult {
        let ended = self.run(stream, &connection, &permit).await;
        if let Some(reply) = ended.reply {
            let _ = send(stream, reply).await;
        }
        let _ = stream.shutdown().await;
        drop(permit);
        if ended.report
            && let Some(pairing_id) = ended.pairing_id
        {
            self.events.on_finished(pairing_id, ended.result);
        }
        ended.result
    }
}

/// What a desktop needs to pair with a phone it found through Tailscale discovery.
#[derive(Debug, Clone)]
pub struct DesktopPairingRequest {
    pub identity: InstallationIdentity,
    pub device_name: String,
    /// The desktop's `state.json`.
    pub store: InstallationStore,
    /// How the phone is bound once trusted: the Tailscale node discovery reported it as.
    pub phone_binding: PeerNetworkBinding,
}

/// Why a desktop pairing did not complete.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("pairing ended {result}: {detail}")]
pub struct DesktopPairingFailure {
    /// The A11 word. A phone's refusal reason is its A11 word; any other refusal is `invalid`,
    /// and a local connection or store failure is `failed`.
    pub result: PairingResult,
    /// Phone trust is durably recorded and `DesktopCommitted` may have been sent, but `Complete`
    /// never arrived. [`PeerClient::pair_resume`] inside the allowance finishes without a new code.
    pub trust_recorded: bool,
    pub detail: String,
}

impl DesktopPairingFailure {
    fn new(result: PairingResult, trust_recorded: bool, detail: impl Into<String>) -> Self {
        Self {
            result,
            trust_recorded,
            detail: detail.into(),
        }
    }

    fn stopped(stop: &Stop, trust_recorded: bool) -> Self {
        Self::new(
            PairingResult::from(stop.code()),
            trust_recorded,
            stop.to_string(),
        )
    }
}

/// Sends `reply` if there is one, closes, and returns `failure`.
async fn abandon(
    stream: &mut dyn PairingStream,
    reply: Option<SignedPairingFrame>,
    failure: DesktopPairingFailure,
) -> DesktopPairingFailure {
    if let Some(reply) = reply {
        let _ = send(stream, reply).await;
    }
    let _ = stream.shutdown().await;
    failure
}

async fn abandon_failure(
    stream: &mut dyn PairingStream,
    failure: PairingFailure,
    trust_recorded: bool,
) -> DesktopPairingFailure {
    let result =
        DesktopPairingFailure::new(failure.result(), trust_recorded, failure.error.to_string());
    abandon(stream, failure.abort.map(|abort| *abort), result).await
}

fn refusal_result(reason: &str) -> PairingResult {
    PairingResult::ALL
        .into_iter()
        .find(|result| *result != PairingResult::Paired && result.as_str() == reason)
        .unwrap_or(PairingResult::Invalid)
}

pub(crate) fn pairing_hello(identity: &InstallationIdentity, device_name: &str) -> ClientHello {
    ClientHello::signed_v2_with_capabilities(
        identity.device_id,
        device_name,
        PairingId::generate().to_string(),
        vec![CAP_PAIRING_V1.to_owned()],
        identity,
    )
}

impl PeerClient {
    /// Pairs with the phone at `address`: connects with a pairing-only hello, runs the exchange,
    /// calls `on_candidate` with the code to show, records the phone's trust durably when the
    /// phone confirms, and returns the paired phone once it confirms it trusts this desktop too.
    pub async fn pair_initiate(
        &self,
        address: SocketAddr,
        request: &DesktopPairingRequest,
        on_candidate: &(dyn Fn(&PairingCandidate) + Send + Sync),
    ) -> Result<PairedPeer, DesktopPairingFailure> {
        let hello = pairing_hello(&request.identity, &request.device_name);
        let (mut stream, server) = self.open_pairing(address, &hello, false).await?;
        desktop_pair(
            &mut stream,
            &SystemClock,
            request,
            &hello,
            &server,
            on_candidate,
        )
        .await
    }

    /// Resends `DesktopCommitted` for a pairing this desktop already recorded (`paired` is
    /// `TrustedPeer::paired()` of that record) so a phone still holding the approval completes
    /// it without a new code (A12).
    pub async fn pair_resume(
        &self,
        address: SocketAddr,
        identity: &InstallationIdentity,
        device_name: &str,
        paired: &meshelf_tailscale::PairedPeer,
    ) -> Result<(), DesktopPairingFailure> {
        let hello = pairing_hello(identity, device_name);
        let (mut stream, server) = self.open_pairing(address, &hello, true).await?;
        desktop_resume(&mut stream, &SystemClock, identity, &hello, &server, paired).await
    }

    async fn open_pairing(
        &self,
        address: SocketAddr,
        hello: &ClientHello,
        trust_recorded: bool,
    ) -> Result<(TcpStream, ServerHello), DesktopPairingFailure> {
        let failed = |detail: String| {
            DesktopPairingFailure::new(PairingResult::Failed, trust_recorded, detail)
        };
        let invalid = |detail: &str| {
            DesktopPairingFailure::new(PairingResult::Invalid, trust_recorded, detail)
        };
        let mut stream = self
            .connect(address, "pairing connect")
            .await
            .map_err(|error| failed(error.to_string()))?;
        timeout(
            self.io_timeout(),
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello.clone())),
        )
        .await
        .map_err(|_| failed("timed out sending the pairing hello".to_owned()))?
        .map_err(|error| failed(error.to_string()))?;
        let response = timeout(self.io_timeout(), read_frame_async(&mut stream))
            .await
            .map_err(|_| failed("timed out waiting for the phone's hello".to_owned()))?
            .map_err(|error| invalid(&error.to_string()))?;
        let WireMessage::ServerHello(server) = response else {
            return Err(invalid("expected a server hello"));
        };
        if !server.has_valid_signature() || server.protocol_version != V2_PROTOCOL_VERSION {
            return Err(invalid(
                "the phone's hello is not a signed protocol-2 hello",
            ));
        }
        if !server.accepted {
            let reason = server.reason.unwrap_or_default();
            return Err(DesktopPairingFailure::new(
                refusal_result(&reason),
                trust_recorded,
                reason,
            ));
        }
        // The machines refuse any hello that does not advertise exactly `pairing-v1`.
        Ok((stream, server))
    }
}

pub(crate) async fn desktop_pair(
    stream: &mut dyn PairingStream,
    clock: &dyn PairingClock,
    request: &DesktopPairingRequest,
    hello: &ClientHello,
    server: &ServerHello,
    on_candidate: &(dyn Fn(&PairingCandidate) + Send + Sync),
) -> Result<PairedPeer, DesktopPairingFailure> {
    let local = request.identity.device_id;
    // The identity this pairing would displace, as it stood when the session began. A phone
    // claiming a trusted device id under another key at another endpoint is refused here, before
    // `Begin`: the desktop records trust with no human step, so nothing may be sent to it.
    let prior = request
        .store
        .load_for_identity(local)
        .and_then(|state| {
            state.peers.displaced_identity(
                server.device_id,
                &server.public_key,
                &request.phone_binding,
            )
        })
        .map_err(|error| {
            DesktopPairingFailure::new(store_refusal(&error).0, false, error.to_string())
        })?;
    let now = clock.now_unix_ms();
    let expires_at_unix_ms = now.saturating_add(PAIRING_WINDOW_MAX_MS);
    let (desktop, begin) = match DesktopPairing::start(
        request.identity.clone(),
        hello,
        server,
        PairingId::generate(),
        PairingNonce::generate(),
        expires_at_unix_ms,
        now,
    ) {
        Ok(started) => started,
        Err(failure) => return Err(abandon_failure(stream, failure, false).await),
    };
    if let Err(stop) = send(stream, begin).await {
        let abort = desktop.abort(stop.code(), None).ok();
        return Err(abandon(stream, abort, DesktopPairingFailure::stopped(&stop, false)).await);
    }
    let commit = match next_frame(
        stream,
        clock,
        desktop.deadline_unix_ms(),
        Some(PAIRING_INACTIVITY),
        None,
    )
    .await
    {
        Ok(frame) => frame,
        Err(stop) => {
            let abort = desktop.abort(stop.code(), None).ok();
            return Err(abandon(stream, abort, DesktopPairingFailure::stopped(&stop, false)).await);
        }
    };
    let (desktop, reveal) = match desktop.on_frame(&commit, clock.now_unix_ms()) {
        Ok(next) => next,
        Err(failure) => return Err(abandon_failure(stream, failure, false).await),
    };
    if let Err(stop) = send(stream, reveal).await {
        let abort = desktop.abort(stop.code(), None).ok();
        return Err(abandon(stream, abort, DesktopPairingFailure::stopped(&stop, false)).await);
    }
    let phone_reveal = match next_frame(
        stream,
        clock,
        desktop.deadline_unix_ms(),
        Some(PAIRING_INACTIVITY),
        None,
    )
    .await
    {
        Ok(frame) => frame,
        Err(stop) => {
            let abort = desktop.abort(stop.code(), None).ok();
            return Err(abandon(stream, abort, DesktopPairingFailure::stopped(&stop, false)).await);
        }
    };
    let desktop = match desktop.on_frame(&phone_reveal, clock.now_unix_ms()) {
        Ok(next) => next,
        Err(failure) => return Err(abandon_failure(stream, failure, false).await),
    };
    on_candidate(desktop.candidate());
    // The person compares codes now; that wait is bounded by the pairing expiry, not inactivity.
    let decision = match next_frame(stream, clock, desktop.deadline_unix_ms(), None, None).await {
        Ok(frame) => frame,
        Err(stop) => {
            let abort = desktop.abort(stop.code(), None).ok();
            return Err(abandon(stream, abort, DesktopPairingFailure::stopped(&stop, false)).await);
        }
    };
    let trust = match desktop.on_frame(&decision, clock.now_unix_ms()) {
        Ok(trust) => trust,
        Err(failure) => return Err(abandon_failure(stream, failure, false).await),
    };
    let paired = meshelf_tailscale::PairedPeer {
        peer: trust.peer().clone(),
        binding: request.phone_binding.clone(),
        expires_at_unix_ms,
    };
    if let Err(error) = request.store.update(local, |state| {
        state
            .peers
            .record_paired(paired.clone(), clock.now_unix_ms(), prior.clone())
    }) {
        let (result, code) = store_refusal(&error);
        let abort = trust.abort(code, None).ok();
        let failure = DesktopPairingFailure::new(result, false, error.to_string());
        return Err(abandon(stream, abort, failure).await);
    }
    let (waiting, committed) = match trust.trust_persisted() {
        Ok(next) => next,
        Err(failure) => return Err(abandon_failure(stream, failure, true).await),
    };
    finish_committed(stream, clock, waiting, committed).await?;
    Ok(paired.peer)
}

pub(crate) async fn desktop_resume(
    stream: &mut dyn PairingStream,
    clock: &dyn PairingClock,
    identity: &InstallationIdentity,
    hello: &ClientHello,
    server: &ServerHello,
    paired: &meshelf_tailscale::PairedPeer,
) -> Result<(), DesktopPairingFailure> {
    let (waiting, committed) = match DesktopPairing::resume(
        identity.clone(),
        hello,
        server,
        &paired.peer,
        paired.expires_at_unix_ms,
        clock.now_unix_ms(),
    ) {
        Ok(next) => next,
        Err(failure) => return Err(abandon_failure(stream, failure, true).await),
    };
    finish_committed(stream, clock, waiting, committed).await
}

/// Releases `DesktopCommitted` (phone trust is already durable) and waits for `Complete`.
async fn finish_committed(
    stream: &mut dyn PairingStream,
    clock: &dyn PairingClock,
    waiting: DesktopAwaitingComplete,
    committed: SignedPairingFrame,
) -> Result<(), DesktopPairingFailure> {
    if let Err(stop) = send(stream, committed).await {
        let abort = waiting.abort(stop.code(), None).ok();
        return Err(abandon(stream, abort, DesktopPairingFailure::stopped(&stop, true)).await);
    }
    let complete = match next_frame(
        stream,
        clock,
        waiting.deadline_unix_ms(),
        Some(PAIRING_INACTIVITY),
        None,
    )
    .await
    {
        Ok(frame) => frame,
        Err(stop) => {
            let abort = waiting.abort(stop.code(), None).ok();
            return Err(abandon(stream, abort, DesktopPairingFailure::stopped(&stop, true)).await);
        }
    };
    if let Err(failure) = waiting.on_frame(&complete, clock.now_unix_ms()) {
        return Err(abandon_failure(stream, failure, true).await);
    }
    let _ = stream.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        path::PathBuf,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering::SeqCst},
        },
    };

    use meshelf_core::{CaptureRequestId, OfferDescriptor, OfferId};
    use meshelf_protocol::{
        CAP_CAPTURE_PHOTO_V1, CAP_OFFER_PULL_V2, CaptureAck, CaptureAckCode, CaptureRequest,
        CaptureStatus, FetchRequest, OfferAck, OfferAnnouncement,
        pairing::{DesktopTrustPending, TranscriptHash},
        read_v2_frame_async,
    };
    use meshelf_tailscale::{InstallationState, TrustOrigin};
    use tempfile::TempDir;
    use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

    use super::*;
    use crate::{
        InstallationTrustGate, NetError, PAIRING_PER_IP_INTERVAL_MS, PHONE_HELLO_READ_LIMIT,
        PairingGate, PairingWindow, ServerIdentity, TrustDecision, TrustGate,
        V2AnnouncementReceiver, V2CaptureReceiver, V2FetchSender, V2OfferServices, V2Pairing,
        V2ServerConfig,
        admission::tests::{ManualClock, T0},
        serve_v2,
    };

    /// Wall time that moves with tokio's (paused) clock, so expiry and inactivity agree.
    struct TokioClock {
        base: u64,
        start: tokio::time::Instant,
    }

    impl TokioClock {
        fn start(base: u64) -> Arc<Self> {
            Arc::new(Self {
                base,
                start: tokio::time::Instant::now(),
            })
        }
    }

    impl PairingClock for TokioClock {
        fn now_unix_ms(&self) -> u64 {
            self.base + u64::try_from(self.start.elapsed().as_millis()).expect("elapsed")
        }
    }

    #[derive(Default)]
    struct Touched {
        announcements: AtomicUsize,
        fetches: AtomicUsize,
        captures: AtomicUsize,
    }

    impl Touched {
        fn total(&self) -> usize {
            self.announcements.load(SeqCst) + self.fetches.load(SeqCst) + self.captures.load(SeqCst)
        }
    }

    struct CountingAnnouncements(Arc<Touched>);

    #[async_trait]
    impl V2AnnouncementReceiver for CountingAnnouncements {
        async fn handle_announcement(
            &self,
            _source: DeviceId,
            _listener: DeviceId,
            _announcement: OfferAnnouncement,
        ) -> Result<OfferAck, NetError> {
            self.0.announcements.fetch_add(1, SeqCst);
            Err(NetError::Rejected("test store".to_owned()))
        }
    }

    struct CountingFetch(Arc<Touched>);

    #[async_trait]
    impl V2FetchSender for CountingFetch {
        async fn handle_fetch(
            &self,
            _requester: DeviceId,
            _request: FetchRequest,
            _stream: &mut TcpStream,
            _io_timeout: Duration,
        ) -> Result<(), NetError> {
            self.0.fetches.fetch_add(1, SeqCst);
            Err(NetError::Rejected("test store".to_owned()))
        }
    }

    struct CountingCapture(Arc<Touched>);

    #[async_trait]
    impl V2CaptureReceiver for CountingCapture {
        async fn handle_capture_request(
            &self,
            _source: DeviceId,
            _requester_name: &str,
            _listener: DeviceId,
            request: CaptureRequest,
        ) -> Result<CaptureAck, NetError> {
            self.0.captures.fetch_add(1, SeqCst);
            Ok(CaptureAck {
                request_id: request.request_id,
                code: CaptureAckCode::Presented,
                detail: None,
            })
        }

        async fn handle_capture_status(
            &self,
            _source: DeviceId,
            _listener: DeviceId,
            status: CaptureStatus,
        ) -> Result<CaptureStatus, NetError> {
            self.0.captures.fetch_add(1, SeqCst);
            Ok(status)
        }
    }

    struct CountingGate {
        window: PairingWindow,
        calls: AtomicUsize,
    }

    impl PairingGate for CountingGate {
        fn admit(&self, remote: SocketAddr, hello: &ClientHello) -> Result<PairingPermit, String> {
            self.calls.fetch_add(1, SeqCst);
            self.window.admit(remote, hello)
        }
    }

    struct CountingResponder {
        inner: PhonePairingResponder,
        entered: AtomicUsize,
        finished: AtomicUsize,
    }

    #[async_trait]
    impl PairingResponder for CountingResponder {
        async fn respond(
            &self,
            stream: &mut dyn PairingStream,
            connection: PairingConnection<'_>,
            permit: PairingPermit,
        ) -> PairingResult {
            self.entered.fetch_add(1, SeqCst);
            let result = self.inner.respond(stream, connection, permit).await;
            self.finished.fetch_add(1, SeqCst);
            result
        }
    }

    #[derive(Clone, Copy)]
    enum Answer {
        Confirm,
        CloseWindow,
        Nothing,
    }

    /// The phone resident's stand-in: records what the person would see and answers as told.
    struct Events {
        window: PairingWindow,
        answer: Answer,
        candidates: Mutex<Vec<PairingCandidate>>,
        finished: Mutex<Vec<(PairingId, PairingResult)>>,
    }

    impl Events {
        fn new(window: PairingWindow, answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                window,
                answer,
                candidates: Mutex::new(Vec::new()),
                finished: Mutex::new(Vec::new()),
            })
        }

        fn candidates(&self) -> Vec<PairingCandidate> {
            self.candidates.lock().expect("candidates").clone()
        }

        fn finished(&self) -> Vec<(PairingId, PairingResult)> {
            self.finished.lock().expect("finished").clone()
        }
    }

    impl PairingEvents for Events {
        fn on_candidate(&self, candidate: &PairingCandidate) {
            self.candidates
                .lock()
                .expect("candidates")
                .push(candidate.clone());
            match self.answer {
                Answer::Confirm => self
                    .window
                    .confirm(&candidate.pairing_id, &candidate.transcript_hash)
                    .expect("confirm the shown candidate"),
                Answer::CloseWindow => self.window.close(),
                Answer::Nothing => {}
            }
        }

        fn on_finished(&self, pairing_id: PairingId, result: PairingResult) {
            self.finished
                .lock()
                .expect("finished")
                .push((pairing_id, result));
        }
    }

    struct Phone {
        identity: InstallationIdentity,
        state_path: PathBuf,
        store: InstallationStore,
        window: PairingWindow,
        events: Arc<Events>,
        gate: Arc<CountingGate>,
        responder: Arc<CountingResponder>,
        touched: Arc<Touched>,
        address: SocketAddr,
        shutdown: watch::Sender<bool>,
        server: JoinHandle<Result<(), NetError>>,
        _directory: TempDir,
    }

    impl Phone {
        fn state(&self) -> InstallationState {
            self.store
                .load_for_identity(self.identity.device_id)
                .expect("phone state")
        }

        async fn stop(self) {
            self.shutdown.send(true).expect("stop phone");
            self.server
                .await
                .expect("phone task")
                .expect("phone listener");
        }
    }

    /// A phone listener exactly as the resident configures one, with counting stand-ins for
    /// every store an operation could touch.
    async fn start_phone(clock: Arc<dyn PairingClock>, answer: Answer) -> Phone {
        start_phone_as(InstallationIdentity::generate(), clock, answer).await
    }

    async fn start_phone_as(
        identity: InstallationIdentity,
        clock: Arc<dyn PairingClock>,
        answer: Answer,
    ) -> Phone {
        let directory = tempfile::tempdir().expect("phone directory");
        let state_path = directory.path().join("state.json");
        let store = InstallationStore::new(state_path.clone());
        let window = PairingWindow::new(clock.clone());
        let events = Events::new(window.clone(), answer);
        let gate = Arc::new(CountingGate {
            window: window.clone(),
            calls: AtomicUsize::new(0),
        });
        let responder = Arc::new(CountingResponder {
            inner: PhonePairingResponder::new(
                identity.clone(),
                store.clone(),
                clock,
                events.clone(),
            ),
            entered: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
        });
        let touched = Arc::new(Touched::default());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind phone");
        let address = listener.local_addr().expect("phone address");
        let config = V2ServerConfig::phone(
            ServerIdentity {
                signing_identity: identity.clone(),
                device_name: "Pixel".to_owned(),
            },
            Arc::new(InstallationTrustGate::new(
                store.clone(),
                identity.device_id,
            )),
            V2OfferServices {
                announcement_receiver: Arc::new(CountingAnnouncements(touched.clone())),
                fetch_sender: Arc::new(CountingFetch(touched.clone())),
            },
            Arc::new(CountingCapture(touched.clone())),
            vec![
                CAP_OFFER_PULL_V2.to_owned(),
                CAP_CAPTURE_PHOTO_V1.to_owned(),
            ],
            V2Pairing {
                gate: gate.clone(),
                responder: responder.clone(),
            },
            Duration::from_secs(5),
        );
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_v2(listener, config, shutdown_rx));
        Phone {
            identity,
            state_path,
            store,
            window,
            events,
            gate,
            responder,
            touched,
            address,
            shutdown,
            server,
            _directory: directory,
        }
    }

    struct Desktop {
        identity: InstallationIdentity,
        state_path: PathBuf,
        store: InstallationStore,
        _directory: TempDir,
    }

    impl Desktop {
        fn new() -> Self {
            Self::with_identity(InstallationIdentity::generate())
        }

        fn with_identity(identity: InstallationIdentity) -> Self {
            let directory = tempfile::tempdir().expect("desktop directory");
            let state_path = directory.path().join("state.json");
            Self {
                identity,
                store: InstallationStore::new(state_path.clone()),
                state_path,
                _directory: directory,
            }
        }

        fn state(&self) -> InstallationState {
            self.store
                .load_for_identity(self.identity.device_id)
                .expect("desktop state")
        }

        fn request(&self) -> DesktopPairingRequest {
            DesktopPairingRequest {
                identity: self.identity.clone(),
                device_name: "CEDAR".to_owned(),
                store: self.store.clone(),
                phone_binding: phone_binding(),
            }
        }
    }

    /// How the desktop's discovery reports the phone.
    fn phone_binding() -> PeerNetworkBinding {
        PeerNetworkBinding::TailscaleNode {
            node_id: "node-pixel".to_owned(),
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        }
    }

    fn phone_hello(identity: &InstallationIdentity) -> ServerHello {
        ServerHello::signed(
            V2_PROTOCOL_VERSION,
            identity.device_id,
            "Pixel".to_owned(),
            true,
            None,
            vec![CAP_PAIRING_V1.to_owned()],
            identity,
        )
    }

    async fn hello_exchange(address: SocketAddr, hello: &ClientHello) -> (TcpStream, ServerHello) {
        let mut stream = TcpStream::connect(address).await.expect("connect");
        write_frame_async(&mut stream, &WireMessage::ClientHello(hello.clone()))
            .await
            .expect("write hello");
        let WireMessage::ServerHello(server) =
            read_frame_async(&mut stream).await.expect("server hello")
        else {
            panic!("expected a server hello");
        };
        (stream, server)
    }

    async fn write_pair(stream: &mut TcpStream, frame: SignedPairingFrame) {
        write_v2_frame_async(stream, &V2Message::Pair(frame))
            .await
            .expect("write pairing frame");
    }

    async fn read_pair(stream: &mut TcpStream) -> SignedPairingFrame {
        let V2Message::Pair(frame) = read_v2_frame_async(stream).await.expect("read") else {
            panic!("expected a pairing frame");
        };
        frame
    }

    /// Drives the desktop by hand until the phone's `Decision{Confirm}` arrives, which the phone
    /// sends only once its approval is durable.
    async fn desktop_until_confirmed(
        address: SocketAddr,
        desktop: &InstallationIdentity,
    ) -> (TcpStream, DesktopTrustPending, u64) {
        let hello = pairing_hello(desktop, "CEDAR");
        let (mut stream, server) = hello_exchange(address, &hello).await;
        assert!(server.accepted, "pairing refused: {:?}", server.reason);
        let now = SystemClock.now_unix_ms();
        let expires = now + PAIRING_WINDOW_MAX_MS;
        let (desktop, begin) = DesktopPairing::start(
            desktop.clone(),
            &hello,
            &server,
            PairingId::generate(),
            PairingNonce::generate(),
            expires,
            now,
        )
        .expect("start");
        write_pair(&mut stream, begin).await;
        let (desktop, reveal) = desktop
            .on_frame(&read_pair(&mut stream).await, now)
            .expect("commit");
        write_pair(&mut stream, reveal).await;
        let desktop = desktop
            .on_frame(&read_pair(&mut stream).await, now)
            .expect("reveal");
        let trust = desktop
            .on_frame(&read_pair(&mut stream).await, SystemClock.now_unix_ms())
            .expect("the phone confirmed");
        (stream, trust, expires)
    }

    async fn eventually(mut condition: impl FnMut() -> bool) {
        for _ in 0..500 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition was not reached");
    }

    #[tokio::test]
    async fn a_shut_window_hammered_repeatedly_admits_nothing_and_persists_nothing() {
        // With the window shut an attacker gets one signature check and a refusal per
        // connection. The refusal must not advertise offer-pull-v2 (F1), the pairing driver must
        // never run, and no attempt may be spent, or hammering could lock the person out.
        // A hundred connections prove that; a thousand left enough sockets in TIME_WAIT that
        // back-to-back suite runs exhausted loopback connects on macOS.
        const HAMMER_CONNECTIONS: usize = 100;
        let phone = start_phone(Arc::new(SystemClock), Answer::Confirm).await;
        let attackers = (0..10)
            .map(|_| InstallationIdentity::generate())
            .collect::<Vec<_>>();
        for index in 0..HAMMER_CONNECTIONS {
            let hello = pairing_hello(&attackers[index % attackers.len()], "attacker");
            let (mut stream, server) = hello_exchange(phone.address, &hello).await;
            assert!(!server.accepted);
            assert!(server.has_valid_signature());
            assert!(
                server.capabilities.is_empty(),
                "a phone refusal advertised {:?}",
                server.capabilities
            );
            assert_eq!(server.reason.as_deref(), Some("window_closed"));
            assert!(read_frame_async(&mut stream).await.is_err());
        }
        assert_eq!(phone.gate.calls.load(SeqCst), HAMMER_CONNECTIONS);
        assert_eq!(phone.responder.entered.load(SeqCst), 0);
        assert!(!phone.state_path.exists(), "a refused attempt wrote state");
        assert!(phone.events.candidates().is_empty());

        phone
            .window
            .open(SystemClock.now_unix_ms() + 60_000)
            .expect("open");
        let (_stream, server) =
            hello_exchange(phone.address, &pairing_hello(&attackers[0], "CEDAR")).await;
        assert!(server.accepted, "the hammering spent the person's attempts");
        assert_eq!(server.capabilities, vec![CAP_PAIRING_V1.to_owned()]);
        phone.stop().await;
    }

    #[tokio::test]
    async fn a_phone_refuses_an_oversized_hello_before_reading_it() {
        // The first frame arrives before any authentication, so its declared length alone must
        // be enough to refuse it; the phone never waits for or buffers the payload.
        let phone = start_phone(Arc::new(SystemClock), Answer::Nothing).await;
        let mut stream = TcpStream::connect(phone.address).await.expect("connect");
        let declared = u32::try_from(PHONE_HELLO_READ_LIMIT + 1).expect("length");
        stream
            .write_all(&declared.to_be_bytes())
            .await
            .expect("length");
        let closed = timeout(Duration::from_secs(2), read_frame_async(&mut stream))
            .await
            .expect("the phone closed without waiting for the payload");
        assert!(closed.is_err());
        assert_eq!(phone.gate.calls.load(SeqCst), 0);
        phone.stop().await;
    }

    #[tokio::test]
    async fn a_pairing_only_connection_reaches_no_offer_fetch_or_capture_operation() {
        // Pairing admits an untrusted installation; if any ordinary operation could follow on
        // that connection, pairing would be a trust bypass.
        let clock = ManualClock::at(T0);
        let phone = start_phone(clock.clone(), Answer::Nothing).await;
        let desktop = InstallationIdentity::generate();
        let target = phone.identity.device_id;
        let operations = [
            V2Message::OfferAnnouncement(OfferAnnouncement::new(
                OfferId::new(),
                desktop.device_id,
                target,
                1,
                OfferDescriptor::text("must not be stored").expect("descriptor"),
            )),
            V2Message::FetchRequest(FetchRequest::new(OfferId::new(), target, desktop.device_id)),
            V2Message::CaptureRequest(CaptureRequest::photo(
                CaptureRequestId::new(),
                desktop.device_id,
                target,
                T0,
                T0 + 60_000,
                "Photograph the router label",
            )),
        ];
        for (index, operation) in operations.into_iter().enumerate() {
            phone
                .window
                .open(clock.now_unix_ms() + 60_000)
                .expect("open");
            let (mut stream, server) =
                hello_exchange(phone.address, &pairing_hello(&desktop, "CEDAR")).await;
            assert!(server.accepted);
            assert_eq!(server.capabilities, vec![CAP_PAIRING_V1.to_owned()]);
            write_v2_frame_async(&mut stream, &operation)
                .await
                .expect("write operation");
            assert!(
                read_v2_frame_async(&mut stream).await.is_err(),
                "a pairing-only connection answered {operation:?}"
            );
            eventually(|| phone.responder.finished.load(SeqCst) == index + 1).await;
            clock.advance(PAIRING_PER_IP_INTERVAL_MS);
        }
        assert_eq!(phone.touched.total(), 0);
        assert!(!phone.state_path.exists());
        phone.stop().await;
    }

    #[tokio::test]
    async fn desktop_and_phone_pair_over_loopback_and_each_ends_trusting_the_other() {
        let phone = start_phone(Arc::new(SystemClock), Answer::Confirm).await;
        let desktop = Desktop::new();
        phone
            .window
            .open(SystemClock.now_unix_ms() + PAIRING_WINDOW_MAX_MS)
            .expect("open");
        let shown = Mutex::new(Vec::new());
        let paired = PeerClient::default()
            .pair_initiate(phone.address, &desktop.request(), &|candidate| {
                shown.lock().expect("shown").push(candidate.clone());
            })
            .await
            .expect("paired");

        // The person compared one code: both ends derived it independently.
        let desktop_view = shown.lock().expect("shown")[0].clone();
        let phone_view = phone.events.candidates()[0].clone();
        assert_eq!(desktop_view.code, phone_view.code);
        assert_eq!(desktop_view.transcript_hash, phone_view.transcript_hash);
        assert_eq!(paired.device_id, phone.identity.device_id);

        // The desktop binds the phone as discovery reports it.
        let desktop_state = desktop.state();
        let phone_record = desktop_state
            .peers
            .by_device_id(phone.identity.device_id)
            .expect("desktop trusts the phone");
        assert_eq!(phone_record.origin(), TrustOrigin::Paired);
        assert_eq!(phone_record.node_id(), Some("node-pixel"));
        assert_eq!(phone_record.public_key, phone.identity.public_key());

        // The phone binds the desktop to the address it saw, and its approval is consumed.
        let phone_state = phone.state();
        let desktop_record = phone_state
            .peers
            .by_device_id(desktop.identity.device_id)
            .expect("phone trusts the desktop");
        assert_eq!(desktop_record.origin(), TrustOrigin::Paired);
        assert_eq!(
            desktop_record.binding(),
            &PeerNetworkBinding::ObservedTailscaleAddress {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
        );
        assert_eq!(phone_state.pending_pairing, None);
        eventually(|| {
            phone.events.finished() == vec![(phone_view.pairing_id, PairingResult::Paired)]
        })
        .await;

        // From now on the desktop is admitted by identity, key, and address alone.
        let ordinary = ClientHello::signed_v2(
            desktop.identity.device_id,
            "CEDAR",
            "after-pairing",
            &desktop.identity,
        );
        let gate = InstallationTrustGate::new(phone.store.clone(), phone.identity.device_id);
        assert!(matches!(
            gate.authorize(SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000)), &ordinary),
            TrustDecision::AllowTrusted
        ));
        phone.stop().await;
    }

    #[tokio::test]
    async fn a_resume_completes_the_approved_transcript_with_no_new_code_and_the_window_closed() {
        // A12: once the person approved, a lost DesktopCommitted must not strand the desktop in
        // one-sided trust; a new connection finishes that exact transcript without another code.
        let clock = ManualClock::at(SystemClock.now_unix_ms());
        let phone = start_phone(clock.clone(), Answer::Confirm).await;
        let desktop = Desktop::new();
        phone
            .window
            .open(clock.now_unix_ms() + 60_000)
            .expect("open");
        let (stream, trust, expires) =
            desktop_until_confirmed(phone.address, &desktop.identity).await;
        let record = meshelf_tailscale::PairedPeer {
            peer: trust.peer().clone(),
            binding: phone_binding(),
            expires_at_unix_ms: expires,
        };
        desktop
            .store
            .update(desktop.identity.device_id, |state| {
                state
                    .peers
                    .record_paired(record.clone(), SystemClock.now_unix_ms(), None)
            })
            .expect("desktop records the phone");
        // The connection drops before DesktopCommitted reaches the phone.
        drop(trust);
        drop(stream);
        eventually(|| phone.events.finished().len() == 1).await;
        let pending = phone.state().pending_pairing.expect("approval is durable");
        assert_eq!(pending.approval.pairing_id, record.peer.pairing_id);
        assert!(phone.state().peers.peers().is_empty());

        phone.window.close();
        clock.advance(PAIRING_PER_IP_INTERVAL_MS);
        PeerClient::default()
            .pair_resume(phone.address, &desktop.identity, "CEDAR", &record)
            .await
            .expect("resume completes");

        let state = phone.state();
        assert_eq!(state.pending_pairing, None);
        let trusted = state
            .peers
            .by_device_id(desktop.identity.device_id)
            .expect("phone trusts the desktop");
        assert_eq!(
            trusted.pairing().expect("evidence").transcript_hash,
            record.peer.transcript_hash
        );
        assert_eq!(
            phone.events.candidates().len(),
            1,
            "a resume showed a new code"
        );
        eventually(|| phone.events.finished().len() == 2).await;
        assert_eq!(
            phone.events.finished()[1],
            (record.peer.pairing_id, PairingResult::Paired)
        );
        phone.stop().await;
    }

    #[tokio::test]
    async fn a_resume_from_another_address_is_refused_and_changes_nothing() {
        // The phone binds the desktop to the address it approved. Completing the approval from
        // anywhere else would turn "holds the desktop key" into "may be trusted from any node".
        let clock = ManualClock::at(T0);
        let window = PairingWindow::new(clock.clone());
        let directory = tempfile::tempdir().expect("directory");
        let phone = InstallationIdentity::generate();
        let store = InstallationStore::new(directory.path().join("state.json"));
        let desktop = InstallationIdentity::generate();
        let pairing_id = PairingId::from_bytes([3; 16]);
        let transcript_hash = TranscriptHash::from_bytes([4; 32]);
        let pending = ApprovedPending {
            approval: meshelf_protocol::pairing::ApprovedPending {
                pairing_id,
                transcript_hash,
                peer_device_id: desktop.device_id,
                peer_public_key: desktop.public_key(),
                peer_device_name: "CEDAR".to_owned(),
                approved_at_unix_ms: T0,
                expires_at_unix_ms: T0 + 60_000,
            },
            observed_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        store
            .update(phone.device_id, |state| {
                state.pending_pairing = Some(pending.clone());
                Ok(())
            })
            .expect("store approval");
        window.restore_pending(&pending);
        let elsewhere = SocketAddr::from(([100, 64, 0, 9], 40_000));
        let hello = pairing_hello(&desktop, "CEDAR");
        assert_eq!(
            window.admit(elsewhere, &hello).expect_err("window shut"),
            "window_closed"
        );

        window.open(T0 + 60_000).expect("open");
        let permit = window.admit(elsewhere, &hello).expect("admitted to pair");
        let events = Events::new(window.clone(), Answer::Nothing);
        let responder = PhonePairingResponder::new(phone.clone(), store.clone(), clock, events);
        let server_hello = phone_hello(&phone);
        let (mut desktop_end, mut phone_end) = tokio::io::duplex(16 * 1024);
        let committed = SignedPairingFrame::sign(
            PairingFrame::DesktopCommitted {
                pairing_id,
                transcript_hash,
            },
            &desktop,
        )
        .expect("sign");
        write_v2_frame_async(&mut desktop_end, &V2Message::Pair(committed))
            .await
            .expect("write");
        let result = responder
            .respond(
                &mut phone_end,
                PairingConnection {
                    remote: elsewhere,
                    client_hello: &hello,
                    server_hello: &server_hello,
                },
                permit,
            )
            .await;
        assert_eq!(result, PairingResult::IdentityChanged);
        let V2Message::Pair(reply) = read_v2_frame_async(&mut desktop_end).await.expect("reply")
        else {
            panic!("expected an abort");
        };
        assert!(reply.verify(&phone.public_key()));
        assert!(matches!(
            reply.frame,
            PairingFrame::Abort {
                code: PairingAbortCode::IdentityChanged,
                ..
            }
        ));
        let state = store.load_for_identity(phone.device_id).expect("state");
        assert_eq!(state.pending_pairing, Some(pending));
        assert!(state.peers.peers().is_empty());
    }

    #[tokio::test]
    async fn closing_the_window_before_approval_aborts_the_session_on_both_sides() {
        let phone = start_phone(Arc::new(SystemClock), Answer::CloseWindow).await;
        let desktop = Desktop::new();
        phone
            .window
            .open(SystemClock.now_unix_ms() + 60_000)
            .expect("open");
        let failure = PeerClient::default()
            .pair_initiate(phone.address, &desktop.request(), &|_| {})
            .await
            .expect_err("the person closed the window");
        assert_eq!(failure.result, PairingResult::WindowClosed);
        assert!(!failure.trust_recorded);
        assert!(desktop.state().peers.peers().is_empty());
        let id = phone.events.candidates()[0].pairing_id;
        eventually(|| phone.events.finished() == vec![(id, PairingResult::WindowClosed)]).await;
        let state = phone.state();
        assert_eq!(state.pending_pairing, None);
        assert!(state.peers.peers().is_empty());
        phone.stop().await;
    }

    #[tokio::test]
    async fn closing_the_window_after_approval_lets_the_session_finish() {
        // A12: the person already compared codes and approved; leaving the screen a moment later
        // must not leave the desktop trusting a phone that does not trust it.
        let phone = start_phone(Arc::new(SystemClock), Answer::Confirm).await;
        let desktop = Desktop::new();
        phone
            .window
            .open(SystemClock.now_unix_ms() + 60_000)
            .expect("open");
        let (mut stream, trust, _expires) =
            desktop_until_confirmed(phone.address, &desktop.identity).await;
        phone.window.close();
        let (waiting, committed) = trust.trust_persisted().expect("committed");
        write_pair(&mut stream, committed).await;
        let complete = read_pair(&mut stream).await;
        waiting
            .on_frame(&complete, SystemClock.now_unix_ms())
            .expect("the phone completed after the window closed");
        assert!(
            phone
                .state()
                .peers
                .by_device_id(desktop.identity.device_id)
                .is_some()
        );
        phone.stop().await;
    }

    #[tokio::test]
    async fn every_phone_refusal_advertises_nothing() {
        // F1: desktop discovery records any validly signed refusal that advertises
        // offer-pull-v2 (O-003). Every refusal a phone listener sends must advertise nothing.
        let phone = start_phone(Arc::new(SystemClock), Answer::Nothing).await;
        let probe = PeerClient::default()
            .probe(phone.address)
            .await
            .expect("probe");
        assert!(!probe.accepted && probe.has_valid_signature());
        assert!(probe.capabilities.is_empty());

        let stranger = InstallationIdentity::generate();
        let unpaired = ClientHello::signed_v2(stranger.device_id, "FERN", "n", &stranger);
        let (_stream, refused) = hello_exchange(phone.address, &unpaired).await;
        assert!(!refused.accepted && refused.capabilities.is_empty());
        assert_eq!(
            refused.reason.as_deref(),
            Some("meshelf installation has not been approved")
        );

        let mut v1 = unpaired.clone();
        v1.protocol_version = 1;
        let (_stream, refused) = hello_exchange(phone.address, &v1).await;
        assert!(!refused.accepted && refused.capabilities.is_empty());

        let mixed = ClientHello::signed_v2_with_capabilities(
            stranger.device_id,
            "FERN",
            "n",
            vec![CAP_PAIRING_V1.to_owned(), CAP_OFFER_PULL_V2.to_owned()],
            &stranger,
        );
        let (_stream, refused) = hello_exchange(phone.address, &mixed).await;
        assert!(!refused.accepted && refused.capabilities.is_empty());
        assert_eq!(
            phone.gate.calls.load(SeqCst),
            0,
            "a hello asking for pairing and more reached the pairing gate"
        );
        phone.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn fifteen_seconds_of_silence_ends_a_session_but_a_person_deciding_is_not_cut_off() {
        // Silence from the peer is bounded by 15 s. A person comparing codes is bounded by the
        // pairing expiry instead: a minute of looking at two screens must not fail the pairing.
        let clock = TokioClock::start(T0);
        let window = PairingWindow::new(clock.clone());
        window.open(T0 + PAIRING_WINDOW_MAX_MS).expect("open");
        let directory = tempfile::tempdir().expect("directory");
        let state_path = directory.path().join("phone.json");
        let phone = InstallationIdentity::generate();
        let events = Events::new(window.clone(), Answer::Nothing);
        let responder = Arc::new(PhonePairingResponder::new(
            phone.clone(),
            InstallationStore::new(state_path.clone()),
            clock.clone(),
            events.clone(),
        ));
        let desktop = Desktop::new();
        let hello = pairing_hello(&desktop.identity, "CEDAR");
        let server_hello = phone_hello(&phone);
        let remote = SocketAddr::from(([100, 64, 0, 7], 40_000));

        let permit = window.admit(remote, &hello).expect("admit");
        let (_silent_desktop, mut phone_end) = tokio::io::duplex(16 * 1024);
        let started = tokio::time::Instant::now();
        let result = responder
            .respond(
                &mut phone_end,
                PairingConnection {
                    remote,
                    client_hello: &hello,
                    server_hello: &server_hello,
                },
                permit,
            )
            .await;
        assert_eq!(result, PairingResult::Timeout);
        assert!(started.elapsed() >= PAIRING_INACTIVITY);
        assert!(started.elapsed() < PAIRING_INACTIVITY + Duration::from_secs(1));
        assert!(events.candidates().is_empty() && events.finished().is_empty());
        assert!(!state_path.exists());

        let permit = window.admit(remote, &hello).expect("second attempt");
        let (mut desktop_end, mut phone_end) = tokio::io::duplex(16 * 1024);
        let phone_task = {
            let (responder, hello, server_hello) =
                (responder.clone(), hello.clone(), server_hello.clone());
            tokio::spawn(async move {
                responder
                    .respond(
                        &mut phone_end,
                        PairingConnection {
                            remote,
                            client_hello: &hello,
                            server_hello: &server_hello,
                        },
                        permit,
                    )
                    .await
            })
        };
        let desktop_task = {
            let (clock, request) = (clock.clone(), desktop.request());
            tokio::spawn(async move {
                desktop_pair(
                    &mut desktop_end,
                    &*clock,
                    &request,
                    &hello,
                    &server_hello,
                    &|_| {},
                )
                .await
            })
        };
        while events.candidates().is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        let candidate = events.candidates()[0].clone();
        window
            .confirm(&candidate.pairing_id, &candidate.transcript_hash)
            .expect("confirm after a minute");
        assert_eq!(phone_task.await.expect("phone"), PairingResult::Paired);
        desktop_task
            .await
            .expect("desktop")
            .expect("desktop paired");
    }

    fn approval_for(desktop: &InstallationIdentity, address: IpAddr) -> ApprovedPending {
        ApprovedPending {
            approval: meshelf_protocol::pairing::ApprovedPending {
                pairing_id: PairingId::from_bytes([3; 16]),
                transcript_hash: TranscriptHash::from_bytes([4; 32]),
                peer_device_id: desktop.device_id,
                peer_public_key: desktop.public_key(),
                peer_device_name: "CEDAR".to_owned(),
                approved_at_unix_ms: T0,
                expires_at_unix_ms: T0 + 60_000,
            },
            observed_address: address,
        }
    }

    #[tokio::test]
    async fn a_hello_claiming_a_trusted_desktops_id_from_elsewhere_is_refused_before_any_code() {
        // The device id in a hello is only a claim. Someone at another address presenting CEDAR's
        // id with their own key must be refused before a code is shown, so the person can never
        // be led into approving the replacement of a desktop the phone already trusts.
        let phone = start_phone(Arc::new(SystemClock), Answer::Confirm).await;
        let desktop = InstallationIdentity::generate();
        phone
            .store
            .update(phone.identity.device_id, |state| {
                state.peers.record_paired(
                    meshelf_tailscale::PairedPeer {
                        peer: PairedPeer {
                            device_id: desktop.device_id,
                            public_key: desktop.public_key(),
                            device_name: "CEDAR".to_owned(),
                            pairing_id: PairingId::from_bytes([1; 16]),
                            transcript_hash: TranscriptHash::from_bytes([1; 32]),
                        },
                        binding: PeerNetworkBinding::ObservedTailscaleAddress {
                            address: "100.64.0.7".parse().expect("address"),
                        },
                        expires_at_unix_ms: T0,
                    },
                    T0,
                    None,
                )
            })
            .expect("the phone trusts CEDAR");
        let before = std::fs::read(&phone.state_path).expect("state");
        let mut attacker = InstallationIdentity::generate();
        attacker.device_id = desktop.device_id;
        let attacker = Desktop::with_identity(attacker);
        phone
            .window
            .open(SystemClock.now_unix_ms() + 60_000)
            .expect("open");

        let failure = PeerClient::default()
            .pair_initiate(phone.address, &attacker.request(), &|_| {})
            .await
            .expect_err("a device-id takeover is refused");

        assert_eq!(failure.result, PairingResult::IdentityChanged);
        eventually(|| phone.responder.finished.load(SeqCst) == 1).await;
        assert!(
            phone.events.candidates().is_empty(),
            "a code was shown for a device-id takeover"
        );
        assert!(phone.events.finished().is_empty());
        assert_eq!(std::fs::read(&phone.state_path).expect("state"), before);
        phone.stop().await;
    }

    #[tokio::test]
    async fn a_phone_claiming_a_trusted_peers_id_is_refused_before_begin() {
        // The desktop records trust with no human step. A hostile node answering with FERN's
        // device id must be refused before anything is sent to it, or it would replace FERN's
        // trusted record and lock the real FERN out of discovery.
        let fern = InstallationIdentity::generate();
        let mut hostile = InstallationIdentity::generate();
        hostile.device_id = fern.device_id;
        let phone = start_phone_as(hostile, Arc::new(SystemClock), Answer::Confirm).await;
        phone
            .window
            .open(SystemClock.now_unix_ms() + 60_000)
            .expect("open");
        let desktop = Desktop::new();
        desktop
            .store
            .update(desktop.identity.device_id, |state| {
                state.peers.accept_signed(
                    &meshelf_tailscale::TailNode {
                        node_id: Some("node-fern".to_owned()),
                        hostname: "FERN".to_owned(),
                        dns_name: None,
                        addresses: vec!["100.64.1.30".parse().expect("address")],
                        online: true,
                        active: true,
                    },
                    fern.device_id,
                    fern.public_key().to_vec(),
                )
            })
            .expect("the desktop trusts FERN");
        let before = std::fs::read(&desktop.state_path).expect("state");
        let shown = Mutex::new(Vec::new());

        let failure = PeerClient::default()
            .pair_initiate(phone.address, &desktop.request(), &|candidate| {
                shown.lock().expect("shown").push(candidate.clone());
            })
            .await
            .expect_err("a device-id takeover is refused");

        assert_eq!(failure.result, PairingResult::IdentityChanged);
        assert!(!failure.trust_recorded);
        assert!(shown.lock().expect("shown").is_empty());
        eventually(|| phone.responder.finished.load(SeqCst) == 1).await;
        assert!(
            phone.events.candidates().is_empty(),
            "the hostile phone was sent a Begin"
        );
        assert_eq!(std::fs::read(&desktop.state_path).expect("state"), before);
        phone.stop().await;
    }

    #[tokio::test]
    async fn a_resume_only_admission_cannot_start_a_fresh_pairing() {
        // With the window shut, a connection is let in only to finish an approval the person
        // already gave. A Begin on it would start a code the person never opened a window for.
        let clock = ManualClock::at(T0);
        let window = PairingWindow::new(clock.clone());
        let directory = tempfile::tempdir().expect("directory");
        let state_path = directory.path().join("state.json");
        let store = InstallationStore::new(state_path.clone());
        let phone = InstallationIdentity::generate();
        let desktop = InstallationIdentity::generate();
        let remote = SocketAddr::from(([100, 64, 0, 7], 40_000));
        let pending = approval_for(&desktop, remote.ip());
        store
            .update(phone.device_id, |state| {
                state.pending_pairing = Some(pending.clone());
                Ok(())
            })
            .expect("store approval");
        window.restore_pending(&pending);
        let before = std::fs::read(&state_path).expect("state");
        let hello = pairing_hello(&desktop, "CEDAR");
        let permit = window.admit(remote, &hello).expect("admitted to resume");
        let events = Events::new(window.clone(), Answer::Confirm);
        let responder =
            PhonePairingResponder::new(phone.clone(), store, clock.clone(), events.clone());
        let server_hello = phone_hello(&phone);
        let (mut desktop_end, mut phone_end) = tokio::io::duplex(16 * 1024);
        let begin = SignedPairingFrame::sign(
            PairingFrame::Begin {
                pairing_id: PairingId::generate(),
                commitment: meshelf_protocol::pairing::NonceCommitment::from_bytes([5; 32]),
                expires_at_unix_ms: T0 + 60_000,
            },
            &desktop,
        )
        .expect("sign");
        write_v2_frame_async(&mut desktop_end, &V2Message::Pair(begin))
            .await
            .expect("write");

        let result = responder
            .respond(
                &mut phone_end,
                PairingConnection {
                    remote,
                    client_hello: &hello,
                    server_hello: &server_hello,
                },
                permit,
            )
            .await;

        assert_eq!(result, PairingResult::WindowClosed);
        let V2Message::Pair(reply) = read_v2_frame_async(&mut desktop_end).await.expect("reply")
        else {
            panic!("expected an abort");
        };
        assert!(reply.verify(&phone.public_key()));
        assert!(matches!(
            reply.frame,
            PairingFrame::Abort {
                code: PairingAbortCode::WindowClosed,
                ..
            }
        ));
        assert!(
            read_v2_frame_async(&mut desktop_end).await.is_err(),
            "the phone sent more than the refusal"
        );
        assert!(events.candidates().is_empty());
        assert_eq!(std::fs::read(&state_path).expect("state"), before);
    }
}
