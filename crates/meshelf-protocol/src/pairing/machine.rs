//! Pure pairing state machines over the frozen frames of the parent module (work order 09 decision
//! 12; amendments A2, A11, A12).
//!
//! [`DesktopPairing`] is the initiator and [`PhonePairing`] the responder. Every state is its own
//! type and every transition consumes it, so a frame can only be produced in the order the protocol
//! allows:
//!
//! ```text
//! desktop                                             phone
//! DesktopPairing::start           ---- Begin ---->    PhonePairing::on_frame
//! DesktopPairing::on_frame        <--- Commit ----
//!                                 ---- Reveal --->    PhoneAwaitingReveal::on_frame
//! DesktopAwaitingReveal::on_frame <--- Reveal ----      (verifies the desktop reveal first)
//!   both screens now show the same PairingCandidate
//!                                                     PhoneCandidate::confirm
//!                                                     [persist ApprovedPending]
//!                                                     PhoneApprovalPending::approval_persisted
//! DesktopAwaitingDecision         <-- Decision{Confirm}
//! [persist phone trust]
//! DesktopTrustPending::trust_persisted --- DesktopCommitted --> PhoneAwaitingCommitted::on_frame
//!                                                     [persist desktop trust]
//! DesktopAwaitingComplete::on_frame <-- Complete --   PhoneTrustPending::trust_persisted
//! ```
//!
//! Durable-before-send is a property of the types, not of caller discipline: the phone's
//! `Decision{Confirm}`, the desktop's `DesktopCommitted`, and the phone's `Complete` are returned only
//! by `approval_persisted` / `trust_persisted`, each of which consumes the pending state that carries
//! the record to persist. Nothing here performs I/O or reads a clock; every time check uses the
//! caller's `now_unix_ms`.

use meshelf_core::DeviceId;
use meshelf_identity::InstallationIdentity;
use thiserror::Error;

use super::{
    NonceCommitment, PAIRING_MAX_HELLO_BYTES, PairingAbortCode, PairingDecision, PairingFrame,
    PairingId, PairingNonce, PairingParty, PairingRole, Sas, SignedPairingFrame, TranscriptHash,
    commit, sas, transcript_hash_for_view, verify_reveal,
};
use crate::{CAP_PAIRING_V1, ClientHello, ServerHello, V2_PROTOCOL_VERSION};

/// Longest session the desktop may propose and the phone may allow, measured from `now`.
pub const PAIRING_WINDOW_MAX_MS: u64 = 120_000;

/// A12: once the phone has durably approved a transcript, the rest of that exchange (and a resume
/// of it on a new connection) may finish until the pairing expiry plus this allowance. The person
/// has already compared codes, so leaving the screen a moment later must not strand the desktop in
/// one-sided trust; nothing unapproved survives past this bound.
pub const PAIRING_RECONCILE_ALLOWANCE_MS: u64 = 60_000;

/// Why a pairing session ended on this side.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PairingError {
    #[error("pairing signature does not verify under the peer's hello key")]
    BadSignature,
    #[error("pairing frame belongs to another pairing id")]
    WrongPairingId,
    #[error("pairing frame {received} arrived out of order; expected {expected}")]
    OutOfOrder {
        expected: &'static str,
        received: &'static str,
    },
    #[error("revealed nonce does not open the peer's commitment")]
    CommitmentMismatch,
    #[error("pairing session expired")]
    Expired,
    #[error("the phone declined the pairing")]
    Declined,
    #[error("transcript hash does not match this pairing")]
    TranscriptMismatch,
    #[error("peer presented this installation's own identity")]
    OwnKey,
    #[error("peer aborted the pairing: {0:?}")]
    Aborted(PairingAbortCode),
    #[error("peer identity differs from the approved pairing")]
    IdentityChanged,
    #[error("invalid pairing input: {0}")]
    Invalid(String),
}

impl PairingError {
    /// The A11 word the phone's UI (and the desktop's exit mapping) reports for this error.
    #[must_use]
    pub fn result(&self) -> PairingResult {
        match self {
            Self::Declined => PairingResult::Declined,
            Self::Aborted(code) => PairingResult::from(*code),
            Self::Expired => PairingResult::Timeout,
            Self::IdentityChanged => PairingResult::IdentityChanged,
            Self::BadSignature
            | Self::WrongPairingId
            | Self::OutOfOrder { .. }
            | Self::CommitmentMismatch
            | Self::TranscriptMismatch
            | Self::OwnKey
            | Self::Invalid(_) => PairingResult::Invalid,
        }
    }

    /// The code this side tells the peer when this error ends the session; `None` when the peer
    /// ended it (a decline or an abort needs no reply).
    fn abort_code(&self) -> Option<PairingAbortCode> {
        match self {
            Self::Declined | Self::Aborted(_) => None,
            Self::Expired => Some(PairingAbortCode::Timeout),
            Self::IdentityChanged => Some(PairingAbortCode::IdentityChanged),
            Self::BadSignature
            | Self::WrongPairingId
            | Self::OutOfOrder { .. }
            | Self::CommitmentMismatch
            | Self::TranscriptMismatch
            | Self::OwnKey
            | Self::Invalid(_) => Some(PairingAbortCode::Invalid),
        }
    }
}

/// A failed transition: the typed error plus, when this side ended a session whose pairing id it
/// knows, the signed `Abort` to send the peer before closing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{error}")]
pub struct PairingFailure {
    pub error: PairingError,
    pub abort: Option<Box<SignedPairingFrame>>,
}

impl PairingFailure {
    #[must_use]
    pub fn result(&self) -> PairingResult {
        self.error.result()
    }

    fn silent(error: PairingError) -> Self {
        Self { error, abort: None }
    }
}

/// A11: the only words `onPairingFinished` may carry. They are the [`PairingAbortCode`] snake-case
/// names plus `paired` for success and `failed` for an internal error (for example a store write
/// that failed). Map through this type; no other layer may invent a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairingResult {
    Paired,
    Declined,
    WindowClosed,
    Timeout,
    Busy,
    RateLimited,
    Invalid,
    IdentityChanged,
    Failed,
}

impl PairingResult {
    pub const ALL: [Self; 9] = [
        Self::Paired,
        Self::Declined,
        Self::WindowClosed,
        Self::Timeout,
        Self::Busy,
        Self::RateLimited,
        Self::Invalid,
        Self::IdentityChanged,
        Self::Failed,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Paired => "paired",
            Self::Declined => "declined",
            Self::WindowClosed => "window_closed",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::IdentityChanged => "identity_changed",
            Self::Failed => "failed",
        }
    }
}

impl From<PairingAbortCode> for PairingResult {
    fn from(code: PairingAbortCode) -> Self {
        match code {
            PairingAbortCode::WindowClosed => Self::WindowClosed,
            PairingAbortCode::Busy => Self::Busy,
            PairingAbortCode::RateLimited => Self::RateLimited,
            PairingAbortCode::Timeout => Self::Timeout,
            PairingAbortCode::Invalid => Self::Invalid,
            PairingAbortCode::Declined => Self::Declined,
            PairingAbortCode::IdentityChanged => Self::IdentityChanged,
        }
    }
}

impl std::fmt::Display for PairingResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What each screen shows once both reveals have verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCandidate {
    pub pairing_id: PairingId,
    /// The peer's self-reported name from its hello; unverified until the person confirms.
    pub device_name: String,
    pub code: Sas,
    pub transcript_hash: TranscriptHash,
    pub expires_at_unix_ms: u64,
}

/// A peer this side may now durably trust, with the pairing evidence that authorizes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedPeer {
    pub device_id: DeviceId,
    pub public_key: [u8; 32],
    /// The name from the hello of the connection whose transcript the person confirmed.
    pub device_name: String,
    pub pairing_id: PairingId,
    pub transcript_hash: TranscriptHash,
}

/// The phone's approval of one exact transcript. It must be durable before the phone's
/// `Decision{Confirm}` exists, and it is what [`PhonePairing::resume`] completes from. The network
/// layer stores it together with the remote address it observed; a resume must also match that
/// address, which this crate never sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPending {
    pub pairing_id: PairingId,
    pub transcript_hash: TranscriptHash,
    pub peer_device_id: DeviceId,
    pub peer_public_key: [u8; 32],
    pub peer_device_name: String,
    pub approved_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl ApprovedPending {
    /// A12: this approval may complete (in its own session or a resume) while `now_unix_ms` is
    /// below this instant. Past it, the record authorizes nothing and should be discarded.
    #[must_use]
    pub fn completion_deadline_unix_ms(&self) -> u64 {
        approved_deadline(self.expires_at_unix_ms)
    }

    fn paired_peer(&self) -> PairedPeer {
        PairedPeer {
            device_id: self.peer_device_id,
            public_key: self.peer_public_key,
            device_name: self.peer_device_name.clone(),
            pairing_id: self.pairing_id,
            transcript_hash: self.transcript_hash,
        }
    }
}

/// The fields of one pairing hello this module relies on, taken from a hello that verified.
#[derive(Debug)]
struct Hello {
    device_id: DeviceId,
    device_name: String,
    public_key: [u8; 32],
    /// Exactly `ClientHello::signing_bytes()` / `ServerHello::signing_bytes()` (A2).
    signing_bytes: Vec<u8>,
}

impl Hello {
    fn from_client(hello: &ClientHello) -> Result<Self, PairingError> {
        check_pairing_hello(
            "client",
            hello.protocol_version,
            &hello.capabilities,
            hello.has_valid_signature(),
        )?;
        Self::new(
            hello.device_id,
            &hello.device_name,
            &hello.public_key,
            hello.signing_bytes(),
        )
    }

    fn from_server(hello: &ServerHello) -> Result<Self, PairingError> {
        if !hello.accepted {
            return Err(invalid("server hello refused the connection"));
        }
        check_pairing_hello(
            "server",
            hello.protocol_version,
            &hello.capabilities,
            hello.has_valid_signature(),
        )?;
        Self::new(
            hello.device_id,
            &hello.device_name,
            &hello.public_key,
            hello.signing_bytes(),
        )
    }

    fn new(
        device_id: DeviceId,
        device_name: &str,
        public_key: &[u8],
        signing_bytes: Vec<u8>,
    ) -> Result<Self, PairingError> {
        let public_key = <[u8; 32]>::try_from(public_key)
            .map_err(|_| invalid("hello public key is not 32 bytes"))?;
        if signing_bytes.len() > PAIRING_MAX_HELLO_BYTES {
            return Err(invalid(
                "hello is larger than the pairing transcript allows",
            ));
        }
        Ok(Self {
            device_id,
            device_name: device_name.to_owned(),
            public_key,
            signing_bytes,
        })
    }

    /// This installation's own hello, as it was sent on this connection.
    fn own(self, identity: &InstallationIdentity) -> Result<Self, PairingError> {
        if self.public_key != identity.public_key() || self.device_id != identity.device_id {
            return Err(invalid("own hello was not signed by this installation"));
        }
        Ok(self)
    }

    /// A2: reveal frames carry no sender role, so a peer presenting this installation's own key
    /// could reflect this side's frames back at it. Refuse such a peer outright.
    fn peer(self, identity: &InstallationIdentity) -> Result<Self, PairingError> {
        if self.public_key == identity.public_key() || self.device_id == identity.device_id {
            return Err(PairingError::OwnKey);
        }
        Ok(self)
    }
}

/// A pairing transcript binds a pairing-only hello: signed, protocol 2, and advertising exactly
/// `pairing-v1`, so no other operation can have been admitted on the connection.
fn check_pairing_hello(
    label: &str,
    protocol_version: u16,
    capabilities: &[String],
    signature_valid: bool,
) -> Result<(), PairingError> {
    if !signature_valid {
        return Err(PairingError::BadSignature);
    }
    if protocol_version != V2_PROTOCOL_VERSION {
        return Err(invalid(format!(
            "{label} hello is protocol {protocol_version}; pairing requires {V2_PROTOCOL_VERSION}"
        )));
    }
    if !matches!(capabilities, [only] if only == CAP_PAIRING_V1) {
        return Err(invalid(format!(
            "{label} hello must advertise exactly {CAP_PAIRING_V1}"
        )));
    }
    Ok(())
}

/// What every state with a known pairing id shares.
#[derive(Debug)]
struct Session {
    identity: InstallationIdentity,
    peer_public_key: [u8; 32],
    pairing_id: PairingId,
    expires_at_unix_ms: u64,
}

impl Session {
    /// Bound for every step before the phone's durable approval.
    fn open_deadline(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Bound for every step from the phone's durable approval onward (A12).
    fn approved_deadline(&self) -> u64 {
        approved_deadline(self.expires_at_unix_ms)
    }

    /// Admits a frame that is in time, signed by the peer's hello key, and for this pairing id.
    /// A peer `Abort` ends the session here; any other frame is returned for the state to order.
    fn receive<'f>(
        &self,
        signed: &'f SignedPairingFrame,
        now_unix_ms: u64,
        deadline_unix_ms: u64,
    ) -> Result<&'f PairingFrame, PairingError> {
        if now_unix_ms >= deadline_unix_ms {
            return Err(PairingError::Expired);
        }
        if !signed.verify(&self.peer_public_key) {
            return Err(PairingError::BadSignature);
        }
        if signed.frame.pairing_id() != &self.pairing_id {
            return Err(PairingError::WrongPairingId);
        }
        if let PairingFrame::Abort { code, .. } = &signed.frame {
            return Err(PairingError::Aborted(*code));
        }
        Ok(&signed.frame)
    }

    fn sign(&self, frame: PairingFrame) -> Result<SignedPairingFrame, PairingError> {
        SignedPairingFrame::sign(frame, &self.identity)
            .map_err(|error| PairingError::Invalid(error.to_string()))
    }

    fn fail(&self, error: PairingError) -> PairingFailure {
        let abort = error
            .abort_code()
            .and_then(|code| self.abort(code, None).ok())
            .map(Box::new);
        PairingFailure { error, abort }
    }

    fn abort(
        &self,
        code: PairingAbortCode,
        detail: Option<String>,
    ) -> Result<SignedPairingFrame, PairingError> {
        self.sign(PairingFrame::Abort {
            pairing_id: self.pairing_id,
            code,
            detail,
        })
    }
}

/// One side's commit-reveal material, kept until the peer's reveal has verified.
#[derive(Debug)]
struct Exchange {
    role: PairingRole,
    own: Hello,
    peer: Hello,
    nonce: PairingNonce,
    commitment: NonceCommitment,
}

impl Exchange {
    /// Only called once the peer's reveal has opened its commitment.
    fn candidate(
        &self,
        session: &Session,
        peer_commitment: NonceCommitment,
        peer_nonce: PairingNonce,
    ) -> Result<PairingCandidate, PairingError> {
        let mine = PairingParty {
            device_id: self.own.device_id,
            public_key: self.own.public_key,
            hello: self.own.signing_bytes.clone(),
            commitment: self.commitment,
            nonce: self.nonce,
        };
        let theirs = PairingParty {
            device_id: self.peer.device_id,
            public_key: self.peer.public_key,
            hello: self.peer.signing_bytes.clone(),
            commitment: peer_commitment,
            nonce: peer_nonce,
        };
        let transcript_hash =
            transcript_hash_for_view(&session.pairing_id, self.role, &mine, &theirs)
                .map_err(|error| PairingError::Invalid(error.to_string()))?;
        Ok(PairingCandidate {
            pairing_id: session.pairing_id,
            device_name: self.peer.device_name.clone(),
            code: sas(&transcript_hash),
            transcript_hash,
            expires_at_unix_ms: session.expires_at_unix_ms,
        })
    }

    fn paired_peer(self, transcript_hash: TranscriptHash, pairing_id: PairingId) -> PairedPeer {
        PairedPeer {
            device_id: self.peer.device_id,
            public_key: self.peer.public_key,
            device_name: self.peer.device_name,
            pairing_id,
            transcript_hash,
        }
    }
}

fn approved_deadline(expires_at_unix_ms: u64) -> u64 {
    expires_at_unix_ms.saturating_add(PAIRING_RECONCILE_ALLOWANCE_MS)
}

fn check_proposed_expiry(expires_at_unix_ms: u64, now_unix_ms: u64) -> Result<(), PairingError> {
    if expires_at_unix_ms <= now_unix_ms {
        return Err(PairingError::Expired);
    }
    if expires_at_unix_ms - now_unix_ms > PAIRING_WINDOW_MAX_MS {
        return Err(invalid(format!(
            "pairing expiry is more than {PAIRING_WINDOW_MAX_MS} ms away"
        )));
    }
    Ok(())
}

fn out_of_order(expected: &'static str, received: &PairingFrame) -> PairingError {
    PairingError::OutOfOrder {
        expected,
        received: frame_kind(received),
    }
}

fn frame_kind(frame: &PairingFrame) -> &'static str {
    match frame {
        PairingFrame::Begin { .. } => "begin",
        PairingFrame::Commit { .. } => "commit",
        PairingFrame::Reveal { .. } => "reveal",
        PairingFrame::Decision { .. } => "decision",
        PairingFrame::DesktopCommitted { .. } => "desktop_committed",
        PairingFrame::Complete { .. } => "complete",
        PairingFrame::Abort { .. } => "abort",
    }
}

fn invalid(detail: impl Into<String>) -> PairingError {
    PairingError::Invalid(detail.into())
}

/// Desktop (initiator), `Begin` sent, waiting for the phone's `Commit`.
#[derive(Debug)]
pub struct DesktopPairing {
    session: Session,
    exchange: Exchange,
}

/// Desktop, own `Reveal` sent, waiting for the phone's `Reveal`.
#[derive(Debug)]
pub struct DesktopAwaitingReveal {
    session: Session,
    exchange: Exchange,
    phone_commitment: NonceCommitment,
}

/// Desktop showing the code, waiting for the phone's `Decision`.
#[derive(Debug)]
pub struct DesktopAwaitingDecision {
    session: Session,
    exchange: Exchange,
    candidate: PairingCandidate,
}

/// Desktop holding the phone's confirmation. Persist [`Self::peer`] as a paired trust record, then
/// call [`Self::trust_persisted`]; `DesktopCommitted` exists only after that call.
///
/// ```
/// use meshelf_protocol::pairing::{DesktopTrustPending, PairedPeer, SignedPairingFrame};
///
/// fn commit(pending: DesktopTrustPending, persist: impl FnOnce(&PairedPeer)) -> SignedPairingFrame {
///     persist(pending.peer());
///     pending.trust_persisted().expect("sign").1
/// }
/// ```
///
/// Receiving the confirmation yields the record to persist, never the frame:
///
/// ```compile_fail
/// use meshelf_protocol::pairing::{DesktopAwaitingDecision, SignedPairingFrame};
///
/// fn commit_early(waiting: DesktopAwaitingDecision, confirm: &SignedPairingFrame) -> SignedPairingFrame {
///     waiting.on_frame(confirm, 0).expect("confirmed")
/// }
/// ```
#[derive(Debug)]
#[must_use = "persist the peer and call trust_persisted, or the phone never learns it is trusted"]
pub struct DesktopTrustPending {
    session: Session,
    peer: PairedPeer,
}

/// Desktop, `DesktopCommitted` sent, waiting for the phone's `Complete`.
#[derive(Debug)]
pub struct DesktopAwaitingComplete {
    session: Session,
    transcript_hash: TranscriptHash,
}

impl DesktopPairing {
    /// Opens a pairing from the desktop. `client_hello` is the hello this desktop sent on the
    /// connection and `server_hello` the verified pairing-only hello the phone answered with; their
    /// exact signing bytes enter the transcript (A2). Returns the `Begin` frame to send.
    pub fn start(
        identity: InstallationIdentity,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        pairing_id: PairingId,
        nonce: PairingNonce,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(Self, SignedPairingFrame), PairingFailure> {
        let own = Hello::from_client(client_hello)
            .and_then(|hello| hello.own(&identity))
            .map_err(PairingFailure::silent)?;
        let peer = Hello::from_server(server_hello)
            .and_then(|hello| hello.peer(&identity))
            .map_err(PairingFailure::silent)?;
        check_proposed_expiry(expires_at_unix_ms, now_unix_ms).map_err(PairingFailure::silent)?;
        let session = Session {
            identity,
            peer_public_key: peer.public_key,
            pairing_id,
            expires_at_unix_ms,
        };
        let commitment = commit(PairingRole::Initiator, &pairing_id, &nonce);
        let begin = session
            .sign(PairingFrame::Begin {
                pairing_id,
                commitment,
                expires_at_unix_ms,
            })
            .map_err(PairingFailure::silent)?;
        let exchange = Exchange {
            role: PairingRole::Initiator,
            own,
            peer,
            nonce,
            commitment,
        };
        Ok((Self { session, exchange }, begin))
    }

    /// Resends `DesktopCommitted` for a transcript this desktop already trusts, on a new
    /// connection, so a phone holding the matching [`ApprovedPending`] can complete without a new
    /// code. `paired` is the record the desktop persisted; `expires_at_unix_ms` is that session's
    /// original expiry, which bounds the resume (A12).
    pub fn resume(
        identity: InstallationIdentity,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        paired: &PairedPeer,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(DesktopAwaitingComplete, SignedPairingFrame), PairingFailure> {
        Hello::from_client(client_hello)
            .and_then(|hello| hello.own(&identity))
            .map_err(PairingFailure::silent)?;
        let peer = Hello::from_server(server_hello)
            .and_then(|hello| hello.peer(&identity))
            .map_err(PairingFailure::silent)?;
        let session = Session {
            identity,
            peer_public_key: paired.public_key,
            pairing_id: paired.pairing_id,
            expires_at_unix_ms,
        };
        if peer.public_key != paired.public_key || peer.device_id != paired.device_id {
            return Err(session.fail(PairingError::IdentityChanged));
        }
        if now_unix_ms >= session.approved_deadline() {
            return Err(session.fail(PairingError::Expired));
        }
        let committed = session
            .sign(PairingFrame::DesktopCommitted {
                pairing_id: paired.pairing_id,
                transcript_hash: paired.transcript_hash,
            })
            .map_err(|error| session.fail(error))?;
        let waiting = DesktopAwaitingComplete {
            session,
            transcript_hash: paired.transcript_hash,
        };
        Ok((waiting, committed))
    }

    /// Takes the phone's `Commit` and returns the desktop `Reveal` to send.
    pub fn on_frame(
        self,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<(DesktopAwaitingReveal, SignedPairingFrame), PairingFailure> {
        let session = &self.session;
        let received = session
            .receive(frame, now_unix_ms, session.open_deadline())
            .map_err(|error| session.fail(error))?;
        let PairingFrame::Commit { commitment, .. } = received else {
            return Err(session.fail(out_of_order("commit", received)));
        };
        let reveal = session
            .sign(PairingFrame::Reveal {
                pairing_id: session.pairing_id,
                nonce: self.exchange.nonce,
            })
            .map_err(|error| session.fail(error))?;
        let next = DesktopAwaitingReveal {
            phone_commitment: *commitment,
            session: self.session,
            exchange: self.exchange,
        };
        Ok((next, reveal))
    }
}

impl DesktopAwaitingReveal {
    /// Takes the phone's `Reveal`, verifies it against the phone's commitment, and derives the
    /// code to display.
    pub fn on_frame(
        self,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<DesktopAwaitingDecision, PairingFailure> {
        let session = &self.session;
        let received = session
            .receive(frame, now_unix_ms, session.open_deadline())
            .map_err(|error| session.fail(error))?;
        let PairingFrame::Reveal { nonce, .. } = received else {
            return Err(session.fail(out_of_order("reveal", received)));
        };
        if !verify_reveal(
            PairingRole::Responder,
            &session.pairing_id,
            nonce,
            &self.phone_commitment,
        ) {
            return Err(session.fail(PairingError::CommitmentMismatch));
        }
        let candidate = self
            .exchange
            .candidate(session, self.phone_commitment, *nonce)
            .map_err(|error| session.fail(error))?;
        Ok(DesktopAwaitingDecision {
            session: self.session,
            exchange: self.exchange,
            candidate,
        })
    }
}

impl DesktopAwaitingDecision {
    /// The code and transcript to display while the person compares screens.
    #[must_use]
    pub fn candidate(&self) -> &PairingCandidate {
        &self.candidate
    }

    /// Takes the phone's `Decision`. A confirmation for this exact transcript yields the phone to
    /// trust; a decline ends the session with [`PairingError::Declined`].
    pub fn on_frame(
        self,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<DesktopTrustPending, PairingFailure> {
        let session = &self.session;
        let received = session
            .receive(frame, now_unix_ms, session.approved_deadline())
            .map_err(|error| session.fail(error))?;
        let PairingFrame::Decision {
            decision,
            transcript_hash,
            ..
        } = received
        else {
            return Err(session.fail(out_of_order("decision", received)));
        };
        if *decision == PairingDecision::Decline {
            return Err(session.fail(PairingError::Declined));
        }
        if transcript_hash != &self.candidate.transcript_hash {
            return Err(session.fail(PairingError::TranscriptMismatch));
        }
        let peer = self
            .exchange
            .paired_peer(self.candidate.transcript_hash, self.candidate.pairing_id);
        Ok(DesktopTrustPending {
            session: self.session,
            peer,
        })
    }
}

impl DesktopTrustPending {
    /// The phone identity and pairing evidence to persist before acknowledging.
    #[must_use]
    pub fn peer(&self) -> &PairedPeer {
        &self.peer
    }

    /// Acknowledges that [`Self::peer`] is durably recorded and returns `DesktopCommitted`.
    pub fn trust_persisted(
        self,
    ) -> Result<(DesktopAwaitingComplete, SignedPairingFrame), PairingFailure> {
        let committed = self
            .session
            .sign(PairingFrame::DesktopCommitted {
                pairing_id: self.peer.pairing_id,
                transcript_hash: self.peer.transcript_hash,
            })
            .map_err(|error| self.session.fail(error))?;
        let waiting = DesktopAwaitingComplete {
            session: self.session,
            transcript_hash: self.peer.transcript_hash,
        };
        Ok((waiting, committed))
    }
}

impl DesktopAwaitingComplete {
    /// Takes the phone's `Complete`. `Ok` means both sides hold durable trust:
    /// [`PairingResult::Paired`].
    pub fn on_frame(
        self,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<(), PairingFailure> {
        let session = &self.session;
        let received = session
            .receive(frame, now_unix_ms, session.approved_deadline())
            .map_err(|error| session.fail(error))?;
        let PairingFrame::Complete {
            transcript_hash, ..
        } = received
        else {
            return Err(session.fail(out_of_order("complete", received)));
        };
        if transcript_hash != &self.transcript_hash {
            return Err(session.fail(PairingError::TranscriptMismatch));
        }
        Ok(())
    }
}

/// Phone (responder) on a pairing-only connection, waiting for the desktop's `Begin`.
#[derive(Debug)]
pub struct PhonePairing {
    identity: InstallationIdentity,
    own: Hello,
    peer: Hello,
    nonce: PairingNonce,
    max_expires_at_unix_ms: u64,
}

/// Phone, `Commit` sent, waiting for the desktop's `Reveal`.
#[derive(Debug)]
pub struct PhoneAwaitingReveal {
    session: Session,
    exchange: Exchange,
    desktop_commitment: NonceCommitment,
}

/// Phone showing the code, waiting for the person to confirm or reject.
#[derive(Debug)]
pub struct PhoneCandidate {
    session: Session,
    exchange: Exchange,
    candidate: PairingCandidate,
}

/// Phone holding the person's approval. Persist [`Self::approved_pending`], then call
/// [`Self::approval_persisted`]; the `Decision{Confirm}` frame (the work order's "PairAccept")
/// exists only after that call.
///
/// ```
/// use meshelf_protocol::pairing::{
///     ApprovedPending, PhoneCandidate, SignedPairingFrame, TranscriptHash,
/// };
///
/// fn accept(
///     candidate: PhoneCandidate,
///     shown: &TranscriptHash,
///     now_unix_ms: u64,
///     persist: impl FnOnce(&ApprovedPending),
/// ) -> SignedPairingFrame {
///     let pending = candidate.confirm(shown, now_unix_ms).expect("approved");
///     persist(pending.approved_pending());
///     pending.approval_persisted().expect("sign").1
/// }
/// ```
///
/// Confirming yields the record to persist, never the frame:
///
/// ```compile_fail
/// use meshelf_protocol::pairing::{PhoneCandidate, SignedPairingFrame, TranscriptHash};
///
/// fn accept_early(candidate: PhoneCandidate, shown: &TranscriptHash) -> SignedPairingFrame {
///     candidate.confirm(shown, 0).expect("approved")
/// }
/// ```
#[derive(Debug)]
#[must_use = "persist the approval and call approval_persisted, or the desktop never hears it"]
pub struct PhoneApprovalPending {
    session: Session,
    approved: ApprovedPending,
}

/// Phone, `Decision{Confirm}` sent, waiting for `DesktopCommitted`.
#[derive(Debug)]
pub struct PhoneAwaitingCommitted {
    session: Session,
    approved: ApprovedPending,
}

/// Phone holding the desktop's commitment. Persist [`Self::peer`] as a paired trust record (and
/// clear the [`ApprovedPending`] in the same write), then call [`Self::trust_persisted`]; `Complete`
/// exists only after that call.
///
/// ```
/// use meshelf_protocol::pairing::{PairedPeer, PhoneTrustPending, SignedPairingFrame};
///
/// fn complete(pending: PhoneTrustPending, persist: impl FnOnce(&PairedPeer)) -> SignedPairingFrame {
///     persist(pending.peer());
///     pending.trust_persisted().expect("sign")
/// }
/// ```
///
/// Receiving `DesktopCommitted` yields the record to persist, never `Complete`:
///
/// ```compile_fail
/// use meshelf_protocol::pairing::{PhoneAwaitingCommitted, SignedPairingFrame};
///
/// fn complete_early(waiting: PhoneAwaitingCommitted, committed: &SignedPairingFrame) -> SignedPairingFrame {
///     waiting.on_frame(committed, 0).expect("committed")
/// }
/// ```
#[derive(Debug)]
#[must_use = "persist the peer and call trust_persisted, or the desktop never learns pairing finished"]
pub struct PhoneTrustPending {
    session: Session,
    peer: PairedPeer,
}

impl PhonePairing {
    /// Prepares the phone side of a pairing-only connection. `server_hello` is the hello this phone
    /// sent and `client_hello` the verified pairing-only hello the desktop opened with; their exact
    /// signing bytes enter the transcript (A2). The session expires at the earlier of the desktop's
    /// proposed expiry and `max_expires_at_unix_ms`, which must lie within
    /// [`PAIRING_WINDOW_MAX_MS`] of now.
    pub fn new(
        identity: InstallationIdentity,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        nonce: PairingNonce,
        max_expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<Self, PairingFailure> {
        let own = Hello::from_server(server_hello)
            .and_then(|hello| hello.own(&identity))
            .map_err(PairingFailure::silent)?;
        let peer = Hello::from_client(client_hello)
            .and_then(|hello| hello.peer(&identity))
            .map_err(PairingFailure::silent)?;
        check_proposed_expiry(max_expires_at_unix_ms, now_unix_ms)
            .map_err(PairingFailure::silent)?;
        Ok(Self {
            identity,
            own,
            peer,
            nonce,
            max_expires_at_unix_ms,
        })
    }

    /// Frames from the desktop are accepted while `now_unix_ms` is below this instant.
    #[must_use]
    pub fn deadline_unix_ms(&self) -> u64 {
        self.max_expires_at_unix_ms
    }

    /// Takes the desktop's `Begin` and returns the phone `Commit` to send. The pairing id is the
    /// desktop's; before `Begin` there is no id to abort under, so failures here carry no `Abort`.
    pub fn on_frame(
        self,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<(PhoneAwaitingReveal, SignedPairingFrame), PairingFailure> {
        if now_unix_ms >= self.max_expires_at_unix_ms {
            return Err(PairingFailure::silent(PairingError::Expired));
        }
        if !frame.verify(&self.peer.public_key) {
            return Err(PairingFailure::silent(PairingError::BadSignature));
        }
        let (pairing_id, desktop_commitment, proposed_expiry) = match &frame.frame {
            PairingFrame::Begin {
                pairing_id,
                commitment,
                expires_at_unix_ms,
            } => (*pairing_id, *commitment, *expires_at_unix_ms),
            PairingFrame::Abort { code, .. } => {
                return Err(PairingFailure::silent(PairingError::Aborted(*code)));
            }
            other => {
                return Err(PairingFailure::silent(out_of_order("begin", other)));
            }
        };
        let session = Session {
            identity: self.identity,
            peer_public_key: self.peer.public_key,
            pairing_id,
            expires_at_unix_ms: proposed_expiry.min(self.max_expires_at_unix_ms),
        };
        if proposed_expiry <= now_unix_ms {
            return Err(session.fail(PairingError::Expired));
        }
        let commitment = commit(PairingRole::Responder, &pairing_id, &self.nonce);
        let commit_frame = session
            .sign(PairingFrame::Commit {
                pairing_id,
                commitment,
            })
            .map_err(|error| session.fail(error))?;
        let exchange = Exchange {
            role: PairingRole::Responder,
            own: self.own,
            peer: self.peer,
            nonce: self.nonce,
            commitment,
        };
        let next = PhoneAwaitingReveal {
            session,
            exchange,
            desktop_commitment,
        };
        Ok((next, commit_frame))
    }

    /// A12 resume: a new pairing-only connection whose first frame is `DesktopCommitted` for the
    /// stored `approved` transcript, from the same desktop key and device id, completes without a
    /// new code while `now_unix_ms` is below [`ApprovedPending::completion_deadline_unix_ms`].
    /// The caller must also check the remote address against the one stored with the approval.
    pub fn resume(
        identity: InstallationIdentity,
        client_hello: &ClientHello,
        approved: &ApprovedPending,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<PhoneTrustPending, PairingFailure> {
        let session = Session {
            identity,
            peer_public_key: approved.peer_public_key,
            pairing_id: approved.pairing_id,
            expires_at_unix_ms: approved.expires_at_unix_ms,
        };
        let peer = Hello::from_client(client_hello)
            .and_then(|hello| hello.peer(&session.identity))
            .map_err(|error| session.fail(error))?;
        if peer.public_key != approved.peer_public_key || peer.device_id != approved.peer_device_id
        {
            return Err(session.fail(PairingError::IdentityChanged));
        }
        let received = session
            .receive(frame, now_unix_ms, session.approved_deadline())
            .map_err(|error| session.fail(error))?;
        let PairingFrame::DesktopCommitted {
            transcript_hash, ..
        } = received
        else {
            return Err(session.fail(out_of_order("desktop_committed", received)));
        };
        if transcript_hash != &approved.transcript_hash {
            return Err(session.fail(PairingError::TranscriptMismatch));
        }
        Ok(PhoneTrustPending {
            session,
            peer: approved.paired_peer(),
        })
    }
}

impl PhoneAwaitingReveal {
    /// Takes the desktop's `Reveal`, verifies it against the desktop's commitment, and only then
    /// returns the phone `Reveal` to send together with the candidate to show.
    pub fn on_frame(
        self,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<(PhoneCandidate, SignedPairingFrame), PairingFailure> {
        let session = &self.session;
        let received = session
            .receive(frame, now_unix_ms, session.open_deadline())
            .map_err(|error| session.fail(error))?;
        let PairingFrame::Reveal { nonce, .. } = received else {
            return Err(session.fail(out_of_order("reveal", received)));
        };
        if !verify_reveal(
            PairingRole::Initiator,
            &session.pairing_id,
            nonce,
            &self.desktop_commitment,
        ) {
            return Err(session.fail(PairingError::CommitmentMismatch));
        }
        let candidate = self
            .exchange
            .candidate(session, self.desktop_commitment, *nonce)
            .map_err(|error| session.fail(error))?;
        let reveal = session
            .sign(PairingFrame::Reveal {
                pairing_id: session.pairing_id,
                nonce: self.exchange.nonce,
            })
            .map_err(|error| session.fail(error))?;
        let next = PhoneCandidate {
            session: self.session,
            exchange: self.exchange,
            candidate,
        };
        Ok((next, reveal))
    }
}

impl PhoneCandidate {
    /// The pairing id, claimed device name, code, transcript hash, and expiry for the UI.
    #[must_use]
    pub fn candidate(&self) -> &PairingCandidate {
        &self.candidate
    }

    /// The person approved the code showing `transcript_hash`, which must be this candidate's.
    /// Returns the [`ApprovedPending`] to persist; any mismatch or lateness ends the session.
    pub fn confirm(
        self,
        transcript_hash: &TranscriptHash,
        now_unix_ms: u64,
    ) -> Result<PhoneApprovalPending, PairingFailure> {
        if now_unix_ms >= self.session.open_deadline() {
            return Err(self.session.fail(PairingError::Expired));
        }
        if transcript_hash != &self.candidate.transcript_hash {
            return Err(self.session.fail(PairingError::TranscriptMismatch));
        }
        let peer = self.exchange.peer;
        let approved = ApprovedPending {
            pairing_id: self.candidate.pairing_id,
            transcript_hash: self.candidate.transcript_hash,
            peer_device_id: peer.device_id,
            peer_public_key: peer.public_key,
            peer_device_name: peer.device_name,
            approved_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: self.session.expires_at_unix_ms,
        };
        Ok(PhoneApprovalPending {
            session: self.session,
            approved,
        })
    }

    /// The person rejected the code: returns `Decision{Decline}`. The session ends with
    /// [`PairingResult::Declined`].
    pub fn reject(self) -> Result<SignedPairingFrame, PairingError> {
        self.session.sign(PairingFrame::Decision {
            pairing_id: self.candidate.pairing_id,
            decision: PairingDecision::Decline,
            transcript_hash: self.candidate.transcript_hash,
        })
    }

    /// While the person compares codes the desktop may only abort, so any frame ends the session.
    #[must_use]
    pub fn on_frame(self, frame: &SignedPairingFrame, now_unix_ms: u64) -> PairingFailure {
        let session = &self.session;
        match session.receive(frame, now_unix_ms, session.open_deadline()) {
            Err(error) => session.fail(error),
            Ok(received) => session.fail(out_of_order("no frame", received)),
        }
    }
}

impl PhoneApprovalPending {
    /// The approval to persist before acknowledging.
    #[must_use]
    pub fn approved_pending(&self) -> &ApprovedPending {
        &self.approved
    }

    /// Acknowledges that [`Self::approved_pending`] is durably recorded and returns
    /// `Decision{Confirm}`.
    pub fn approval_persisted(
        self,
    ) -> Result<(PhoneAwaitingCommitted, SignedPairingFrame), PairingFailure> {
        let decision = self
            .session
            .sign(PairingFrame::Decision {
                pairing_id: self.approved.pairing_id,
                decision: PairingDecision::Confirm,
                transcript_hash: self.approved.transcript_hash,
            })
            .map_err(|error| self.session.fail(error))?;
        let waiting = PhoneAwaitingCommitted {
            session: self.session,
            approved: self.approved,
        };
        Ok((waiting, decision))
    }
}

impl PhoneAwaitingCommitted {
    /// Takes `DesktopCommitted` for the approved transcript and yields the desktop to trust.
    pub fn on_frame(
        self,
        frame: &SignedPairingFrame,
        now_unix_ms: u64,
    ) -> Result<PhoneTrustPending, PairingFailure> {
        let session = &self.session;
        let received = session
            .receive(frame, now_unix_ms, session.approved_deadline())
            .map_err(|error| session.fail(error))?;
        let PairingFrame::DesktopCommitted {
            transcript_hash, ..
        } = received
        else {
            return Err(session.fail(out_of_order("desktop_committed", received)));
        };
        if transcript_hash != &self.approved.transcript_hash {
            return Err(session.fail(PairingError::TranscriptMismatch));
        }
        Ok(PhoneTrustPending {
            peer: self.approved.paired_peer(),
            session: self.session,
        })
    }
}

impl PhoneTrustPending {
    /// The desktop identity and pairing evidence to persist before acknowledging.
    #[must_use]
    pub fn peer(&self) -> &PairedPeer {
        &self.peer
    }

    /// Acknowledges that [`Self::peer`] is durably recorded and returns `Complete`. The session
    /// ends with [`PairingResult::Paired`].
    pub fn trust_persisted(self) -> Result<SignedPairingFrame, PairingFailure> {
        self.session
            .sign(PairingFrame::Complete {
                pairing_id: self.peer.pairing_id,
                transcript_hash: self.peer.transcript_hash,
            })
            .map_err(|error| self.session.fail(error))
    }
}

macro_rules! session_state {
    ($($state:ident: $deadline:ident),+ $(,)?) => {$(
        impl $state {
            #[must_use]
            pub fn pairing_id(&self) -> PairingId {
                self.session.pairing_id
            }

            /// Frames from the peer are accepted while `now_unix_ms` is below this instant.
            #[must_use]
            pub fn deadline_unix_ms(&self) -> u64 {
                self.session.$deadline()
            }

            /// Ends the session from this side and returns the `Abort` to send the peer.
            pub fn abort(
                self,
                code: PairingAbortCode,
                detail: Option<String>,
            ) -> Result<SignedPairingFrame, PairingError> {
                self.session.abort(code, detail)
            }
        }
    )+};
}

session_state!(
    DesktopPairing: open_deadline,
    DesktopAwaitingReveal: open_deadline,
    DesktopAwaitingDecision: approved_deadline,
    DesktopTrustPending: approved_deadline,
    DesktopAwaitingComplete: approved_deadline,
    PhoneAwaitingReveal: open_deadline,
    PhoneCandidate: open_deadline,
    PhoneApprovalPending: approved_deadline,
    PhoneAwaitingCommitted: approved_deadline,
    PhoneTrustPending: approved_deadline,
);
