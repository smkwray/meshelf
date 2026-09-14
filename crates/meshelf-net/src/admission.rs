//! Who may use a protocol-2 connection, and on what terms (work order 09 decision 12).
//!
//! Ordinary operations are admitted by a [`TrustGate`]; the gate every resident uses is
//! [`InstallationTrustGate`], which applies the one shared predicate `PeerRegistry::admit`.
//! Pairing is the only path on which an untrusted installation is let in at all, so it has its own
//! gate, [`PairingWindow`], whose limits make hammering it achieve nothing: no admission unless the
//! person opened the window, one live session, three started attempts per window, one new attempt
//! per remote address per five seconds, no queue and no notification. An admission yields a
//! [`PairingPermit`], which only this module constructs and whose drop frees the live-session slot.

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use meshelf_core::DeviceId;
use meshelf_protocol::{
    ClientHello,
    pairing::{
        PAIRING_WINDOW_MAX_MS, PairingAbortCode, PairingCandidate, PairingId, PairingResult,
        TranscriptHash,
    },
};
use meshelf_tailscale::{ApprovedPending, InstallationStore, PeerAdmission};
use thiserror::Error;
use tokio::sync::{oneshot, watch};

use crate::{TrustDecision, TrustGate};

/// One new pairing attempt per remote address per this interval.
pub const PAIRING_PER_IP_INTERVAL_MS: u64 = 5_000;
/// Attempts started per opening of the window.
pub const PAIRING_MAX_ATTEMPTS: u32 = 3;

/// Wall-clock milliseconds since the Unix epoch, injected so limits and expiries are testable.
pub trait PairingClock: Send + Sync + 'static {
    fn now_unix_ms(&self) -> u64;
}

/// The system clock. A clock before the epoch reads as 0, which only ever makes a window or a
/// pairing look expired.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl PairingClock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// The ordinary gate every resident uses: a connection is trusted only when its signed hello
/// matches a stored record's device, key, and network binding exactly. State is reread on every
/// connection, so a new trust record needs no restart. It is never asked about pairing.
///
/// When [`Self::auto_observe_cgnat`] is set (O-025 phone interim), an unknown but validly signed
/// hello from a Tailscale CGNAT address is recorded as a discovery peer and admitted, matching
/// desktop O-003 private-test behaviour until the pairing ceremony returns.
#[derive(Debug, Clone)]
pub struct InstallationTrustGate {
    store: InstallationStore,
    local_device: DeviceId,
    auto_observe_cgnat: bool,
}

impl InstallationTrustGate {
    #[must_use]
    pub fn new(store: InstallationStore, local_device: DeviceId) -> Self {
        Self {
            store,
            local_device,
            auto_observe_cgnat: false,
        }
    }

    /// Phone interim (O-025): auto-record CGNAT peers that present a valid signature.
    #[must_use]
    pub fn with_auto_observe_cgnat(mut self) -> Self {
        self.auto_observe_cgnat = true;
        self
    }
}

impl TrustGate for InstallationTrustGate {
    fn authorize(&self, remote: SocketAddr, hello: &ClientHello) -> TrustDecision {
        if !hello.has_valid_signature() {
            return TrustDecision::Deny("client hello signature is invalid".to_owned());
        }
        let Ok(state) = self.store.load_for_identity(self.local_device) else {
            return TrustDecision::Deny("local meshelf state is unavailable".to_owned());
        };
        match state
            .peers
            .admit(hello.device_id, &hello.public_key, remote.ip())
        {
            PeerAdmission::Trusted => TrustDecision::AllowTrusted,
            PeerAdmission::UnknownDevice if self.auto_observe_cgnat => {
                if !meshelf_tailscale::is_tailscale_cgnat_v4(remote.ip()) {
                    return TrustDecision::Deny(
                        "meshelf installation has not been approved".to_owned(),
                    );
                }
                let recorded = self.store.update(self.local_device, |state| {
                    state.peers.accept_observed_signed(
                        hello.device_name.clone(),
                        remote.ip(),
                        hello.device_id,
                        hello.public_key.clone(),
                    )
                });
                match recorded {
                    Ok(_) => TrustDecision::AllowTrusted,
                    Err(error) => {
                        TrustDecision::Deny(format!("could not record observed peer: {error}"))
                    }
                }
            }
            PeerAdmission::UnknownDevice => {
                TrustDecision::Deny("meshelf installation has not been approved".to_owned())
            }
            PeerAdmission::KeyChanged => TrustDecision::Deny("peer_identity_changed".to_owned()),
            PeerAdmission::NetworkIdentityChanged => {
                TrustDecision::Deny("peer_network_identity_changed".to_owned())
            }
        }
    }
}

/// Admits pairing-only connections. Only [`PairingWindow`] can produce the permit.
pub trait PairingGate: Send + Sync + 'static {
    /// Admit one connection whose pairing-only hello already verified, or refuse it with the A11
    /// word that says why (`window_closed`, `rate_limited`, `busy`).
    fn admit(&self, remote: SocketAddr, hello: &ClientHello) -> Result<PairingPermit, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PairingControlError {
    #[error(
        "a pairing window must end in the future and at most {PAIRING_WINDOW_MAX_MS} ms from now"
    )]
    InvalidExpiry,
    #[error("no pairing candidate is waiting for a decision")]
    NoCandidate,
    #[error("the pairing id or transcript hash is not the candidate being shown")]
    CandidateMismatch,
}

/// The person's answer to a shown candidate, delivered to the live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhoneDecision {
    Confirm(TranscriptHash),
    Reject,
}

/// The phone's pairing window: the gate for pairing-only connections and the control surface the
/// resident drives (open, close, confirm, reject). Cheap to clone; clones share one window.
#[derive(Clone)]
pub struct PairingWindow {
    shared: Arc<Shared>,
}

struct Shared {
    clock: Arc<dyn PairingClock>,
    state: Mutex<WindowState>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, WindowState> {
        // The state holds plain counters and handles; a panic elsewhere cannot leave it
        // half-updated in a way that would widen admission, so a poisoned lock is recovered.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Default)]
struct WindowState {
    open_until: Option<u64>,
    attempts: u32,
    last_attempt: HashMap<IpAddr, u64>,
    live: Option<LiveSession>,
    next_session: u64,
    resumable: Option<Resumable>,
}

struct LiveSession {
    id: u64,
    /// Past the person's durable approval: closing the window no longer ends it (A12).
    approved: bool,
    abort: watch::Sender<bool>,
    candidate: Option<CandidateSlot>,
}

struct CandidateSlot {
    pairing_id: PairingId,
    transcript_hash: TranscriptHash,
    decide: oneshot::Sender<PhoneDecision>,
}

/// The one approved transcript a new connection may complete without an open window (A12).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Resumable {
    device_id: DeviceId,
    public_key: [u8; 32],
    address: IpAddr,
    deadline_unix_ms: u64,
}

impl From<&ApprovedPending> for Resumable {
    fn from(pending: &ApprovedPending) -> Self {
        Self {
            device_id: pending.approval.peer_device_id,
            public_key: pending.approval.peer_public_key,
            address: pending.observed_address,
            deadline_unix_ms: pending.approval.completion_deadline_unix_ms(),
        }
    }
}

impl fmt::Debug for PairingWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.lock();
        f.debug_struct("PairingWindow")
            .field("open_until", &state.open_until)
            .field("attempts", &state.attempts)
            .field("live", &state.live.is_some())
            .finish_non_exhaustive()
    }
}

impl PairingWindow {
    #[must_use]
    pub fn new(clock: Arc<dyn PairingClock>) -> Self {
        Self {
            shared: Arc::new(Shared {
                clock,
                state: Mutex::new(WindowState::default()),
            }),
        }
    }

    /// Opens the window until `until_unix_ms`, which must be in the future and at most
    /// [`PAIRING_WINDOW_MAX_MS`] away. Resets the attempt count and per-address history; a live
    /// session is left running.
    pub fn open(&self, until_unix_ms: u64) -> Result<(), PairingControlError> {
        let now = self.shared.clock.now_unix_ms();
        if until_unix_ms <= now || until_unix_ms - now > PAIRING_WINDOW_MAX_MS {
            return Err(PairingControlError::InvalidExpiry);
        }
        let mut state = self.shared.lock();
        state.open_until = Some(until_unix_ms);
        state.attempts = 0;
        state.last_attempt.clear();
        Ok(())
    }

    /// Ends new admissions and aborts a live session that has not reached the person's durable
    /// approval; a session past it finishes (A12). Closing a closed or expired window changes
    /// nothing and is not an error (A13).
    pub fn close(&self) {
        let mut state = self.shared.lock();
        state.open_until = None;
        if let Some(live) = state.live.as_ref().filter(|live| !live.approved) {
            live.abort.send_replace(true);
        }
    }

    /// The instant the window closes, while it is open.
    #[must_use]
    pub fn open_until(&self) -> Option<u64> {
        let now = self.shared.clock.now_unix_ms();
        self.shared.lock().open_until.filter(|until| *until > now)
    }

    /// The person approved the shown candidate. Delivered only when both the pairing id and the
    /// transcript hash are the candidate's, so a stale tap can neither approve nor end a session.
    pub fn confirm(
        &self,
        pairing_id: &PairingId,
        transcript_hash: &TranscriptHash,
    ) -> Result<(), PairingControlError> {
        self.decide(
            pairing_id,
            Some(transcript_hash),
            PhoneDecision::Confirm(*transcript_hash),
        )
    }

    /// The person rejected the shown candidate.
    pub fn reject(&self, pairing_id: &PairingId) -> Result<(), PairingControlError> {
        self.decide(pairing_id, None, PhoneDecision::Reject)
    }

    /// After a restart, re-allows the one resume a still-valid stored approval may complete (A12).
    /// An approval past its completion deadline is ignored.
    pub fn restore_pending(&self, pending: &ApprovedPending) {
        let resumable = Resumable::from(pending);
        if resumable.deadline_unix_ms > self.shared.clock.now_unix_ms() {
            self.shared.lock().resumable = Some(resumable);
        }
    }

    fn decide(
        &self,
        pairing_id: &PairingId,
        transcript_hash: Option<&TranscriptHash>,
        decision: PhoneDecision,
    ) -> Result<(), PairingControlError> {
        let mut state = self.shared.lock();
        let live = state
            .live
            .as_mut()
            .ok_or(PairingControlError::NoCandidate)?;
        let slot = live
            .candidate
            .as_ref()
            .ok_or(PairingControlError::NoCandidate)?;
        if slot.pairing_id != *pairing_id
            || transcript_hash.is_some_and(|hash| *hash != slot.transcript_hash)
        {
            return Err(PairingControlError::CandidateMismatch);
        }
        let slot = live
            .candidate
            .take()
            .ok_or(PairingControlError::NoCandidate)?;
        slot.decide
            .send(decision)
            .map_err(|_| PairingControlError::NoCandidate)
    }
}

impl PairingGate for PairingWindow {
    fn admit(&self, remote: SocketAddr, hello: &ClientHello) -> Result<PairingPermit, String> {
        let now = self.shared.clock.now_unix_ms();
        let ip = remote.ip();
        let mut state = self.shared.lock();
        let fresh_until = state.open_until.filter(|until| *until > now);
        let resume = state.resumable.as_ref().is_some_and(|resumable| {
            resumable.device_id == hello.device_id
                && resumable.public_key.as_slice() == hello.public_key.as_slice()
                && resumable.address == ip
                && now < resumable.deadline_unix_ms
        });
        if fresh_until.is_none() && !resume {
            return Err(refusal(PairingAbortCode::WindowClosed));
        }
        if state
            .last_attempt
            .get(&ip)
            .is_some_and(|last| now.saturating_sub(*last) < PAIRING_PER_IP_INTERVAL_MS)
        {
            return Err(refusal(PairingAbortCode::RateLimited));
        }
        if state.attempts >= PAIRING_MAX_ATTEMPTS {
            return Err(refusal(PairingAbortCode::RateLimited));
        }
        if state.live.is_some() {
            return Err(refusal(PairingAbortCode::Busy));
        }
        state.attempts += 1;
        state.last_attempt.insert(ip, now);
        let id = state.next_session;
        state.next_session += 1;
        let (abort, abort_rx) = watch::channel(false);
        state.live = Some(LiveSession {
            id,
            // With no window open the connection can only complete an approved transcript.
            approved: fresh_until.is_none(),
            abort,
            candidate: None,
        });
        Ok(PairingPermit {
            shared: Arc::clone(&self.shared),
            session: id,
            fresh_until,
            abort: abort_rx,
        })
    }
}

fn refusal(code: PairingAbortCode) -> String {
    PairingResult::from(code).as_str().to_owned()
}

/// The right to run one pairing session. Only [`PairingWindow`] constructs it; dropping it frees
/// the window's single live-session slot, however the session ended.
pub struct PairingPermit {
    shared: Arc<Shared>,
    session: u64,
    fresh_until: Option<u64>,
    abort: watch::Receiver<bool>,
}

impl fmt::Debug for PairingPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingPermit")
            .field("session", &self.session)
            .field("fresh_until", &self.fresh_until)
            .finish_non_exhaustive()
    }
}

impl Drop for PairingPermit {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        if state
            .live
            .as_ref()
            .is_some_and(|live| live.id == self.session)
        {
            state.live = None;
        }
    }
}

impl PairingPermit {
    /// The window's end when a fresh pairing may start on this connection; `None` when it may
    /// only resume an approved transcript.
    pub(crate) fn fresh_until(&self) -> Option<u64> {
        self.fresh_until
    }

    /// Becomes `true` when closing the window ends this session.
    pub(crate) fn abort_signal(&self) -> watch::Receiver<bool> {
        self.abort.clone()
    }

    /// Marks the session as past the person's approval, so closing the window no longer ends it
    /// (A12). `false` when a close already ended it.
    pub(crate) fn enter_approved(&self) -> bool {
        let mut state = self.shared.lock();
        match state.live.as_mut() {
            Some(live) if live.id == self.session && !*self.abort.borrow() => {
                live.approved = true;
                true
            }
            _ => false,
        }
    }

    /// Registers the candidate being shown and returns where the person's decision arrives.
    pub(crate) fn offer_candidate(
        &self,
        candidate: &PairingCandidate,
    ) -> oneshot::Receiver<PhoneDecision> {
        let (decide, decision) = oneshot::channel();
        let mut state = self.shared.lock();
        if let Some(live) = state.live.as_mut().filter(|live| live.id == self.session) {
            live.candidate = Some(CandidateSlot {
                pairing_id: candidate.pairing_id,
                transcript_hash: candidate.transcript_hash,
                decide,
            });
        }
        decision
    }

    /// The approval just persisted may be completed by a later connection (A12).
    pub(crate) fn note_resumable(&self, pending: &ApprovedPending) {
        self.shared.lock().resumable = Some(Resumable::from(pending));
    }

    /// The approval was promoted to trust; nothing remains to resume.
    pub(crate) fn clear_resumable(&self) {
        self.shared.lock().resumable = None;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use meshelf_identity::InstallationIdentity;
    use meshelf_protocol::{CAP_OFFER_PULL_V2, CAP_PAIRING_V1, pairing};
    use meshelf_tailscale::PeerNetworkBinding;

    use super::*;

    pub(crate) const T0: u64 = 1_800_000_000_000;

    /// A wall clock the test moves by hand.
    #[derive(Debug)]
    pub(crate) struct ManualClock(AtomicU64);

    impl ManualClock {
        pub(crate) fn at(now: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(now)))
        }

        pub(crate) fn advance(&self, milliseconds: u64) {
            self.0.fetch_add(milliseconds, Ordering::SeqCst);
        }
    }

    impl PairingClock for ManualClock {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn at(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::from((ip, 45_832))
    }

    pub(crate) fn pairing_hello(identity: &InstallationIdentity) -> ClientHello {
        ClientHello::signed_v2_with_capabilities(
            identity.device_id,
            "CEDAR",
            "pairing",
            vec![CAP_PAIRING_V1.to_owned()],
            identity,
        )
    }

    fn window() -> (Arc<ManualClock>, PairingWindow) {
        let clock = ManualClock::at(T0);
        let window = PairingWindow::new(clock.clone());
        (clock, window)
    }

    fn stored_approval(desktop: &InstallationIdentity, address: IpAddr) -> ApprovedPending {
        ApprovedPending {
            approval: pairing::ApprovedPending {
                pairing_id: PairingId::from_bytes([7; 16]),
                transcript_hash: TranscriptHash::from_bytes([7; 32]),
                peer_device_id: desktop.device_id,
                peer_public_key: desktop.public_key(),
                peer_device_name: "CEDAR".to_owned(),
                approved_at_unix_ms: T0,
                expires_at_unix_ms: T0 + 60_000,
            },
            observed_address: address,
        }
    }

    #[test]
    fn a_closed_window_admits_nobody_and_remembers_nothing() {
        // With the window shut the only thing an attacker gets is a refusal: no attempt is
        // counted, so hammering cannot use up the attempts the person will need later.
        let (clock, window) = window();
        let hello = pairing_hello(&InstallationIdentity::generate());
        for index in 0..100_u8 {
            let refused = window
                .admit(at([100, 64, 0, index]), &hello)
                .expect_err("closed");
            assert_eq!(refused, "window_closed");
        }
        window.open(T0 + 120_000).expect("open");
        assert!(window.admit(at([100, 64, 0, 1]), &hello).is_ok());
        // An expired window is closed even though nobody called close().
        clock.advance(120_000);
        window.close();
        assert_eq!(window.open_until(), None);
    }

    #[test]
    fn open_window_limits_are_three_attempts_one_per_address_per_five_seconds_one_live() {
        // These limits are what make an interposer's one-in-a-million guess stay one guess.
        let (clock, window) = window();
        window.open(T0 + 120_000).expect("open");
        let hello = pairing_hello(&InstallationIdentity::generate());

        let first = window
            .admit(at([100, 64, 0, 1]), &hello)
            .expect("first attempt");
        assert_eq!(first.fresh_until(), Some(T0 + 120_000));
        assert_eq!(
            window
                .admit(at([100, 64, 0, 2]), &hello)
                .expect_err("one live"),
            "busy"
        );
        drop(first);

        clock.advance(1_000);
        assert_eq!(
            window
                .admit(at([100, 64, 0, 1]), &hello)
                .expect_err("same address within 5 s"),
            "rate_limited"
        );
        drop(
            window
                .admit(at([100, 64, 0, 2]), &hello)
                .expect("second attempt"),
        );
        drop(
            window
                .admit(at([100, 64, 0, 3]), &hello)
                .expect("third attempt"),
        );
        clock.advance(10_000);
        assert_eq!(
            window
                .admit(at([100, 64, 0, 4]), &hello)
                .expect_err("fourth attempt"),
            "rate_limited"
        );
        assert_eq!(
            window
                .admit(at([100, 64, 0, 1]), &hello)
                .expect_err("fourth attempt from an old address"),
            "rate_limited"
        );

        // Reopening is the person's explicit act, and it starts a fresh budget.
        window.open(clock.now_unix_ms() + 60_000).expect("reopen");
        drop(
            window
                .admit(at([100, 64, 0, 1]), &hello)
                .expect("new window"),
        );
    }

    #[test]
    fn opening_requires_a_bounded_future_expiry() {
        let (_clock, window) = window();
        assert_eq!(window.open(T0), Err(PairingControlError::InvalidExpiry));
        assert_eq!(
            window.open(T0 + PAIRING_WINDOW_MAX_MS + 1),
            Err(PairingControlError::InvalidExpiry)
        );
        window.open(T0 + PAIRING_WINDOW_MAX_MS).expect("maximum");
        assert_eq!(window.open_until(), Some(T0 + PAIRING_WINDOW_MAX_MS));
    }

    #[test]
    fn closing_aborts_only_a_session_that_has_not_reached_approval() {
        // A12: once the person approved and it is durable, leaving the screen must not strand
        // the desktop in one-sided trust; before that, closing means stop.
        let (_clock, window) = window();
        let hello = pairing_hello(&InstallationIdentity::generate());
        window.open(T0 + 60_000).expect("open");
        let early = window.admit(at([100, 64, 0, 1]), &hello).expect("admit");
        let signal = early.abort_signal();
        window.close();
        assert!(*signal.borrow(), "a session before approval is aborted");
        assert!(!early.enter_approved(), "an aborted session cannot approve");
        drop(early);

        window.open(T0 + 60_000).expect("reopen");
        let approved = window.admit(at([100, 64, 0, 2]), &hello).expect("admit");
        assert!(approved.enter_approved());
        window.close();
        window.close();
        assert!(
            !*approved.abort_signal().borrow(),
            "an approved session runs on"
        );
    }

    #[test]
    fn a_resume_is_admitted_without_a_window_only_for_the_approved_peer_and_address() {
        let (clock, window) = window();
        let desktop = InstallationIdentity::generate();
        let hello = pairing_hello(&desktop);
        let pending = stored_approval(&desktop, "100.64.0.7".parse().expect("ip"));
        window.restore_pending(&pending);

        assert_eq!(
            window
                .admit(at([100, 64, 0, 9]), &hello)
                .expect_err("another address"),
            "window_closed"
        );
        let stranger = pairing_hello(&InstallationIdentity::generate());
        assert_eq!(
            window
                .admit(at([100, 64, 0, 7]), &stranger)
                .expect_err("another key"),
            "window_closed"
        );
        let resume = window.admit(at([100, 64, 0, 7]), &hello).expect("resume");
        assert_eq!(
            resume.fresh_until(),
            None,
            "a resume cannot start a fresh pairing"
        );
        drop(resume);
        // It still counts as an attempt from that address.
        assert_eq!(
            window.admit(at([100, 64, 0, 7]), &hello).expect_err("5 s"),
            "rate_limited"
        );
        clock.advance(pending.approval.completion_deadline_unix_ms() - T0);
        assert_eq!(
            window
                .admit(at([100, 64, 0, 7]), &hello)
                .expect_err("expired"),
            "window_closed"
        );
    }

    #[test]
    fn decisions_reach_only_the_candidate_being_shown() {
        let (_clock, window) = window();
        window.open(T0 + 60_000).expect("open");
        let permit = window
            .admit(
                at([100, 64, 0, 1]),
                &pairing_hello(&InstallationIdentity::generate()),
            )
            .expect("admit");
        let candidate = PairingCandidate {
            pairing_id: PairingId::from_bytes([1; 16]),
            device_name: "CEDAR".to_owned(),
            code: pairing::sas(&TranscriptHash::from_bytes([2; 32])),
            transcript_hash: TranscriptHash::from_bytes([2; 32]),
            expires_at_unix_ms: T0 + 60_000,
        };
        assert_eq!(
            window.confirm(&candidate.pairing_id, &candidate.transcript_hash),
            Err(PairingControlError::NoCandidate)
        );
        let mut decision = permit.offer_candidate(&candidate);
        assert_eq!(
            window.confirm(&PairingId::from_bytes([9; 16]), &candidate.transcript_hash),
            Err(PairingControlError::CandidateMismatch)
        );
        assert_eq!(
            window.confirm(&candidate.pairing_id, &TranscriptHash::from_bytes([9; 32])),
            Err(PairingControlError::CandidateMismatch)
        );
        assert!(decision.try_recv().is_err(), "a mismatch delivers nothing");
        window
            .confirm(&candidate.pairing_id, &candidate.transcript_hash)
            .expect("confirm");
        assert_eq!(
            decision.try_recv().expect("delivered"),
            PhoneDecision::Confirm(candidate.transcript_hash)
        );
        assert_eq!(
            window.reject(&candidate.pairing_id),
            Err(PairingControlError::NoCandidate)
        );
    }

    #[test]
    fn ordinary_gate_refuses_a_changed_key_or_address_and_never_moves_the_record() {
        // Key change always needs explicit re-pairing, and a copied key used from another node is
        // refused; neither refusal may write anything.
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.json");
        let store = InstallationStore::new(path.clone());
        let local = DeviceId::new();
        let desktop = InstallationIdentity::generate();
        store
            .update(local, |state| {
                state.peers.record_paired(
                    meshelf_tailscale::PairedPeer {
                        peer: pairing::PairedPeer {
                            device_id: desktop.device_id,
                            public_key: desktop.public_key(),
                            device_name: "CEDAR".to_owned(),
                            pairing_id: PairingId::from_bytes([1; 16]),
                            transcript_hash: TranscriptHash::from_bytes([1; 32]),
                        },
                        binding: PeerNetworkBinding::ObservedTailscaleAddress {
                            address: "100.64.0.7".parse().expect("ip"),
                        },
                        expires_at_unix_ms: T0,
                    },
                    T0,
                    None,
                )
            })
            .expect("pair");
        let before = std::fs::read(&path).expect("state");
        let gate = InstallationTrustGate::new(store, local);
        let ordinary = |identity: &InstallationIdentity| {
            ClientHello::signed_v2_with_capabilities(
                desktop.device_id,
                "CEDAR",
                "n",
                vec![CAP_OFFER_PULL_V2.to_owned()],
                identity,
            )
        };

        let decision = gate.authorize(at([100, 64, 0, 7]), &ordinary(&desktop));
        assert!(matches!(decision, TrustDecision::AllowTrusted));
        let rotated = InstallationIdentity::generate();
        let decision = gate.authorize(at([100, 64, 0, 7]), &ordinary(&rotated));
        assert!(
            matches!(decision, TrustDecision::Deny(ref reason) if reason == "peer_identity_changed")
        );
        let decision = gate.authorize(at([100, 64, 0, 8]), &ordinary(&desktop));
        assert!(
            matches!(decision, TrustDecision::Deny(ref reason) if reason == "peer_network_identity_changed")
        );
        let mut forged = ordinary(&desktop);
        forged.nonce = "tampered".to_owned();
        assert!(matches!(
            gate.authorize(at([100, 64, 0, 7]), &forged),
            TrustDecision::Deny(_)
        ));
        assert_eq!(std::fs::read(&path).expect("state"), before);
    }
}
