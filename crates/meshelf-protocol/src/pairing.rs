//! Pure cryptographic core of one-time device pairing (work order 09, design decision 12).
//!
//! Both endpoints commit to a fresh nonce, reveal it only after the other side has committed, and
//! then independently derive a transcript hash and a six-digit short authentication string (SAS)
//! from both signed hellos, device ids, keys, commitments, and nonces. A human comparing the two
//! screens is what authenticates the keys, so every byte here is specified exactly and re-derivable
//! from the work order. This module performs no I/O. Frames travel as `V2Message::Pair`, and the
//! pure state machines that order an exchange live in the `machine` submodule, re-exported here.

use std::fmt;
use std::str::FromStr;

use meshelf_core::DeviceId;
use meshelf_identity::InstallationIdentity;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{MAX_FRAME_BYTES, ProtocolError, V2_MAX_STATUS_DETAIL_BYTES, check_frame_len};

mod machine;

pub use machine::{
    ApprovedPending, DesktopAwaitingComplete, DesktopAwaitingDecision, DesktopAwaitingReveal,
    DesktopPairing, DesktopTrustPending, PAIRING_RECONCILE_ALLOWANCE_MS, PAIRING_WINDOW_MAX_MS,
    PairedPeer, PairingCandidate, PairingError, PairingFailure, PairingResult,
    PhoneApprovalPending, PhoneAwaitingCommitted, PhoneAwaitingReveal, PhoneCandidate,
    PhonePairing, PhoneTrustPending,
};

/// Hard bound on one encoded signed pairing frame.
pub const PAIRING_MAX_FRAME_BYTES: usize = 4 * 1024;
/// A hello's signing bytes never exceed the hello frame bound; anything larger is refused rather
/// than hashed, so the length prefix can never be truncated.
pub const PAIRING_MAX_HELLO_BYTES: usize = MAX_FRAME_BYTES;

const NONCE_DOMAIN: &[u8] = b"meshelf-pairing-nonce-v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"meshelf-pairing-transcript-v1";
const SUITE: &[u8] = b"sha256+ed25519+sas6r20";
const SAS_DOMAIN: &[u8] = b"meshelf-pairing-sas-v1";
const SAS_BOUND: u32 = 1_000_000;
const SAS_CANDIDATE_MASK: u32 = 0x000F_FFFF;
/// Prefixed to the frame JSON before `InstallationIdentity::sign`. Hello signing bytes are a JSON
/// object and so begin with `{`; pairing signing bytes begin with this prefix. The two signed
/// message sets are disjoint, so neither signature can be replayed as the other.
const FRAME_SIGNING_DOMAIN: &[u8] = b"meshelf/pairing-frame-signature/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairingRole {
    /// The desktop that opens the exchange.
    Initiator,
    /// The phone whose pairing window admitted the exchange.
    Responder,
}

impl PairingRole {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Initiator => 0x01,
            Self::Responder => 0x02,
        }
    }
}

macro_rules! hex_bytes {
    ($(#[$meta:meta])* $name:ident, $len:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name([u8; $len]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&encode_hex(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                decode_hex::<$len>(&text).map(Self).ok_or_else(|| {
                    serde::de::Error::custom(concat!(
                        stringify!($name),
                        " must be exactly ",
                        stringify!($len),
                        " bytes of lowercase hex"
                    ))
                })
            }
        }
    };
}

hex_bytes!(
    /// Fresh per-attempt identifier chosen by the initiator.
    PairingId,
    16
);
hex_bytes!(
    /// One side's secret contribution. Secret until its reveal, so `Debug` never prints it.
    PairingNonce,
    32
);
hex_bytes!(NonceCommitment, 32);
hex_bytes!(TranscriptHash, 32);

impl PairingId {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl PairingNonce {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl fmt::Debug for PairingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PairingId({})", encode_hex(&self.0))
    }
}

impl fmt::Debug for PairingNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingNonce(<redacted>)")
    }
}

impl fmt::Debug for NonceCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NonceCommitment({})", encode_hex(&self.0))
    }
}

impl fmt::Debug for TranscriptHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TranscriptHash({})", encode_hex(&self.0))
    }
}

// The two public identifiers render and parse as the same lowercase hex their JSON uses, so a UI
// boundary (the Android bridge) can pass them as strings. The nonce deliberately has neither.
macro_rules! hex_text {
    ($name:ident, $len:literal) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&encode_hex(&self.0))
            }
        }

        impl FromStr for $name {
            type Err = ProtocolError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                decode_hex::<$len>(text).map(Self).ok_or_else(|| {
                    pairing_validation(concat!(
                        stringify!($name),
                        " must be exactly ",
                        stringify!($len),
                        " bytes of lowercase hex"
                    ))
                })
            }
        }
    };
}

hex_text!(PairingId, 16);
hex_text!(TranscriptHash, 32);

/// Six ASCII digits, leading zeros included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sas(String);

impl Sas {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One side's contribution to the transcript, as that endpoint observed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingParty {
    pub device_id: DeviceId,
    pub public_key: [u8; 32],
    /// That party's hello signing bytes, opaque here.
    pub hello: Vec<u8>,
    pub commitment: NonceCommitment,
    pub nonce: PairingNonce,
}

#[must_use]
pub fn commit(role: PairingRole, pairing_id: &PairingId, nonce: &PairingNonce) -> NonceCommitment {
    let mut preimage = Vec::with_capacity(4 * 4 + NONCE_DOMAIN.len() + 1 + 16 + 32);
    put(&mut preimage, NONCE_DOMAIN);
    put(&mut preimage, &[role.as_byte()]);
    put(&mut preimage, pairing_id.as_bytes());
    put(&mut preimage, nonce.as_bytes());
    NonceCommitment(sha256(&preimage))
}

/// Constant-time check that `nonce` opens `commitment` for exactly this role and pairing id.
#[must_use]
pub fn verify_reveal(
    role: PairingRole,
    pairing_id: &PairingId,
    nonce: &PairingNonce,
    commitment: &NonceCommitment,
) -> bool {
    constant_time_eq(
        commit(role, pairing_id, nonce).as_bytes(),
        commitment.as_bytes(),
    )
}

/// Hashes the transcript in fixed role order. Callers must have checked each reveal with
/// [`verify_reveal`] before showing a code derived from this hash.
pub fn transcript_hash(
    pairing_id: &PairingId,
    initiator: &PairingParty,
    responder: &PairingParty,
) -> Result<TranscriptHash, ProtocolError> {
    Ok(TranscriptHash(sha256(&transcript_bytes(
        pairing_id, initiator, responder,
    )?)))
}

/// Same as [`transcript_hash`] from one endpoint's point of view: `mine` is this endpoint, `theirs`
/// the peer. Ordering by role, never "mine then theirs", is what makes both screens agree.
pub fn transcript_hash_for_view(
    pairing_id: &PairingId,
    my_role: PairingRole,
    mine: &PairingParty,
    theirs: &PairingParty,
) -> Result<TranscriptHash, ProtocolError> {
    let (initiator, responder) = by_role(my_role, mine, theirs);
    transcript_hash(pairing_id, initiator, responder)
}

/// Six-digit code by rejection sampling over a counter-expanded hash stream. Never a modulus.
#[must_use]
pub fn sas(transcript_hash: &TranscriptHash) -> Sas {
    sas_from_blocks(|counter| sas_block(transcript_hash, counter))
}

fn by_role<'a>(
    my_role: PairingRole,
    mine: &'a PairingParty,
    theirs: &'a PairingParty,
) -> (&'a PairingParty, &'a PairingParty) {
    match my_role {
        PairingRole::Initiator => (mine, theirs),
        PairingRole::Responder => (theirs, mine),
    }
}

fn transcript_bytes(
    pairing_id: &PairingId,
    initiator: &PairingParty,
    responder: &PairingParty,
) -> Result<Vec<u8>, ProtocolError> {
    for (label, party) in [("initiator", initiator), ("responder", responder)] {
        if party.hello.is_empty() {
            return Err(pairing_validation(format!(
                "{label} hello signing bytes are empty; the code must bind both hellos"
            )));
        }
        if party.hello.len() > PAIRING_MAX_HELLO_BYTES {
            return Err(pairing_validation(format!(
                "{label} hello signing bytes are {} bytes; maximum is {PAIRING_MAX_HELLO_BYTES}",
                party.hello.len()
            )));
        }
    }
    let mut transcript = Vec::with_capacity(512 + initiator.hello.len() + responder.hello.len());
    put(&mut transcript, TRANSCRIPT_DOMAIN);
    put(&mut transcript, SUITE);
    put(&mut transcript, pairing_id.as_bytes());
    for (role, party) in [
        (PairingRole::Initiator, initiator),
        (PairingRole::Responder, responder),
    ] {
        put(&mut transcript, &[role.as_byte()]);
        put(&mut transcript, party.device_id.as_uuid().as_bytes());
        put(&mut transcript, &party.public_key);
        put(&mut transcript, &party.hello);
        put(&mut transcript, party.commitment.as_bytes());
    }
    put(&mut transcript, initiator.nonce.as_bytes());
    put(&mut transcript, responder.nonce.as_bytes());
    Ok(transcript)
}

fn sas_block(transcript_hash: &TranscriptHash, counter: u32) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(3 * 4 + SAS_DOMAIN.len() + 32 + 4);
    put(&mut preimage, SAS_DOMAIN);
    put(&mut preimage, transcript_hash.as_bytes());
    put(&mut preimage, &counter.to_be_bytes());
    sha256(&preimage)
}

fn sas_from_blocks(mut block_at: impl FnMut(u32) -> [u8; 32]) -> Sas {
    // Each block rejects all ten candidates with probability (48_576 / 1_048_576)^10, about
    // 5e-14, so the counter never approaches overflow.
    let mut counter = 0_u32;
    loop {
        if let Some(value) = first_code_in_block(&block_at(counter)) {
            return Sas(format!("{value:06}"));
        }
        counter += 1;
    }
}

/// Scans ten 3-byte chunks from `block[0..30]` (the last two bytes are ignored) and returns the
/// first low-20-bit candidate below 1,000,000.
fn first_code_in_block(block: &[u8; 32]) -> Option<u32> {
    block[..30]
        .chunks_exact(3)
        .map(|chunk| {
            ((u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]))
                & SAS_CANDIDATE_MASK
        })
        .find(|&candidate| candidate < SAS_BOUND)
}

/// Appends a u32 big-endian length prefix and the bytes. Every caller passes a fixed-size field or
/// a hello already checked against `PAIRING_MAX_HELLO_BYTES`, so the length always fits.
fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("pairing preimage fields are bounded below u32");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |acc, (l, r)| acc | (l ^ r));
    std::hint::black_box(difference) == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = text.as_bytes();
    if raw.len() != N * 2 {
        return None;
    }
    let mut bytes = [0_u8; N];
    for (slot, pair) in bytes.iter_mut().zip(raw.chunks_exact(2)) {
        *slot = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(bytes)
}

fn hex_nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingDecision {
    Confirm,
    Decline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingAbortCode {
    WindowClosed,
    Busy,
    RateLimited,
    Timeout,
    Invalid,
    Declined,
    IdentityChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum PairingFrame {
    /// Initiator to responder.
    Begin {
        pairing_id: PairingId,
        commitment: NonceCommitment,
        expires_at_unix_ms: u64,
    },
    /// Responder to initiator.
    Commit {
        pairing_id: PairingId,
        commitment: NonceCommitment,
    },
    /// Either direction, only after both commitments are exchanged.
    Reveal {
        pairing_id: PairingId,
        nonce: PairingNonce,
    },
    /// Responder (phone) to initiator, after the human compared codes.
    Decision {
        pairing_id: PairingId,
        decision: PairingDecision,
        transcript_hash: TranscriptHash,
    },
    /// Initiator to responder, after durably recording responder trust.
    DesktopCommitted {
        pairing_id: PairingId,
        transcript_hash: TranscriptHash,
    },
    /// Responder to initiator, after durably recording initiator trust.
    Complete {
        pairing_id: PairingId,
        transcript_hash: TranscriptHash,
    },
    Abort {
        pairing_id: PairingId,
        code: PairingAbortCode,
        detail: Option<String>,
    },
}

impl PairingFrame {
    #[must_use]
    pub fn pairing_id(&self) -> &PairingId {
        match self {
            Self::Begin { pairing_id, .. }
            | Self::Commit { pairing_id, .. }
            | Self::Reveal { pairing_id, .. }
            | Self::Decision { pairing_id, .. }
            | Self::DesktopCommitted { pairing_id, .. }
            | Self::Complete { pairing_id, .. }
            | Self::Abort { pairing_id, .. } => pairing_id,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.pairing_id().as_bytes() == &[0_u8; 16] {
            return Err(pairing_validation("pairing id is all zero"));
        }
        match self {
            Self::Begin {
                expires_at_unix_ms: 0,
                ..
            } => Err(pairing_validation("pairing begin has no expiry")),
            Self::Abort {
                detail: Some(detail),
                ..
            } if detail.is_empty() => Err(pairing_validation(
                "pairing abort detail is present but empty",
            )),
            Self::Abort {
                detail: Some(detail),
                ..
            } if detail.len() > V2_MAX_STATUS_DETAIL_BYTES => Err(pairing_validation(format!(
                "pairing abort detail is {} bytes; maximum is {V2_MAX_STATUS_DETAIL_BYTES}",
                detail.len()
            ))),
            _ => Ok(()),
        }
    }
}

/// A pairing frame signed by the key carried in the sender's hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPairingFrame {
    pub frame: PairingFrame,
    pub signature: Vec<u8>,
}

impl SignedPairingFrame {
    /// Refuses to sign an invalid frame.
    pub fn sign(
        frame: PairingFrame,
        identity: &InstallationIdentity,
    ) -> Result<Self, ProtocolError> {
        frame.validate()?;
        let signature = identity.sign(&frame_signing_bytes(&frame)?);
        Ok(Self { frame, signature })
    }

    /// True only for a valid frame whose signature verifies under `public_key` in the pairing
    /// domain.
    #[must_use]
    pub fn verify(&self, public_key: &[u8]) -> bool {
        if self.frame.validate().is_err() {
            return false;
        }
        let Ok(message) = frame_signing_bytes(&self.frame) else {
            return false;
        };
        InstallationIdentity::verify(public_key, &message, &self.signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.frame.validate()?;
        let bytes = serde_json::to_vec(self)?;
        check_pairing_frame_len(bytes.len())?;
        Ok(bytes)
    }

    /// Enforces the 4 KiB bound before parsing, then validates. Does not verify the signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_pairing_frame_len(bytes.len())?;
        let signed: Self = serde_json::from_slice(bytes)?;
        signed.frame.validate()?;
        Ok(signed)
    }
}

fn frame_signing_bytes(frame: &PairingFrame) -> Result<Vec<u8>, ProtocolError> {
    let mut message = FRAME_SIGNING_DOMAIN.to_vec();
    serde_json::to_writer(&mut message, frame)?;
    Ok(message)
}

fn check_pairing_frame_len(length: usize) -> Result<(), ProtocolError> {
    check_frame_len(length, PAIRING_MAX_FRAME_BYTES)
}

fn pairing_validation(detail: impl Into<String>) -> ProtocolError {
    ProtocolError::V2Validation {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientHello;

    fn ascending<const N: usize>(start: u8) -> [u8; N] {
        std::array::from_fn(|index| start.wrapping_add(index as u8))
    }

    fn descending<const N: usize>(start: u8) -> [u8; N] {
        std::array::from_fn(|index| start.wrapping_sub(index as u8))
    }

    fn pid_with_suffix(suffix: u8) -> PairingId {
        let mut bytes = [0_u8; 16];
        bytes[..15].copy_from_slice(b"meshelf-vector-");
        bytes[15] = suffix;
        PairingId::from_bytes(bytes)
    }

    fn party(
        role: PairingRole,
        pairing_id: &PairingId,
        device_id: &str,
        public_key: [u8; 32],
        hello: &[u8],
        nonce: [u8; 32],
    ) -> PairingParty {
        let nonce = PairingNonce::from_bytes(nonce);
        PairingParty {
            device_id: device_id.parse().expect("literal device id"),
            public_key,
            hello: hello.to_vec(),
            commitment: commit(role, pairing_id, &nonce),
            nonce,
        }
    }

    #[derive(Clone)]
    struct Exchange {
        pairing_id: PairingId,
        initiator: PairingParty,
        responder: PairingParty,
    }

    impl Exchange {
        fn hash(&self) -> TranscriptHash {
            transcript_hash(&self.pairing_id, &self.initiator, &self.responder)
                .expect("bounded transcript")
        }
    }

    // The three frozen vectors. Every input is a literal so the outputs can be recomputed from the
    // work-order byte encoding alone.
    fn vector_a() -> Exchange {
        let pairing_id = PairingId::from_bytes(ascending(0x00));
        Exchange {
            initiator: party(
                PairingRole::Initiator,
                &pairing_id,
                "11111111-2222-3333-4444-555555555555",
                ascending(0x20),
                b"initiator hello signing bytes",
                ascending(0x40),
            ),
            responder: party(
                PairingRole::Responder,
                &pairing_id,
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                ascending(0x60),
                b"responder hello signing bytes",
                ascending(0x80),
            ),
            pairing_id,
        }
    }

    fn vector_b() -> Exchange {
        let pairing_id = pid_with_suffix(0x0a);
        Exchange {
            initiator: party(
                PairingRole::Initiator,
                &pairing_id,
                "00000000-0000-0000-0000-000000000001",
                [0x01; 32],
                b"{}",
                [0xaa; 32],
            ),
            responder: party(
                PairingRole::Responder,
                &pairing_id,
                "ffffffff-ffff-ffff-ffff-fffffffffffe",
                [0x02; 32],
                br#"{"protocol_version":2}"#,
                [0x55; 32],
            ),
            pairing_id,
        }
    }

    fn vector_c() -> Exchange {
        let pairing_id = pid_with_suffix(0x02);
        let mut initiator_nonce = [0_u8; 32];
        initiator_nonce[31] = 0x01;
        Exchange {
            initiator: party(
                PairingRole::Initiator,
                &pairing_id,
                "0f0e0d0c-0b0a-0908-0706-050403020100",
                descending(0xff),
                b"desktop",
                initiator_nonce,
            ),
            responder: party(
                PairingRole::Responder,
                &pairing_id,
                "01234567-89ab-cdef-0123-456789abcdef",
                descending(0x9f),
                b"phone",
                [0xfe; 32],
            ),
            pairing_id,
        }
    }

    fn assert_vector(
        exchange: &Exchange,
        initiator_commitment: &str,
        responder_commitment: &str,
        transcript: &str,
        code: &str,
    ) -> TranscriptHash {
        assert_eq!(
            encode_hex(exchange.initiator.commitment.as_bytes()),
            initiator_commitment
        );
        assert_eq!(
            encode_hex(exchange.responder.commitment.as_bytes()),
            responder_commitment
        );
        let hash = exchange.hash();
        assert_eq!(encode_hex(hash.as_bytes()), transcript);
        assert_eq!(sas(&hash).as_str(), code);
        hash
    }

    #[test]
    fn frozen_vector_a() {
        assert_vector(
            &vector_a(),
            "b51d6f99a82abbbfcd1af788983b29d7725f9ea83115acd8cd79c48b192f37e5",
            "c7a5691d0fa1bb4b2de4b8a7c1bb8a0136af9f4135ad9766a9634ad093a843bd",
            "6ab519383daa1aba556cdaa515b27812abf3e326cf75ad0d37db35974ebf6002",
            "846787",
        );
    }

    #[test]
    fn frozen_vector_b_exercises_rejection_end_to_end() {
        let hash = assert_vector(
            &vector_b(),
            "c2b17a653ff0c03eb522f0b4ae9bbb7b5a5f50ba28d3f0397979002f56d7a7b3",
            "945b439e46a6387883e5ba9f60d002fa599094476f0bdf3809442ec0029e5e1b",
            "c2c5e5b25076728ad212dc5df90521c56cb9aa01aedd7b2df9911abf0041746b",
            "278855",
        );
        // This vector was chosen so its first candidate is out of range: an implementation that
        // reduced it instead of rejecting it would print a different code.
        let block = sas_block(&hash, 0);
        let first =
            ((u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]))
                & SAS_CANDIDATE_MASK;
        assert!(
            first >= SAS_BOUND,
            "first candidate {first} was expected to be rejected"
        );
        assert_ne!(format!("{:06}", first % SAS_BOUND), "278855");
    }

    #[test]
    fn frozen_vector_c_keeps_its_leading_zero() {
        let hash = assert_vector(
            &vector_c(),
            "276e2b082fa9e8c55df290c14b8633f8eeee6acf8b5d5becbe7f9995b8b27cf4",
            "8757f4c05b52161aa9ee32b5869b909c7c9a549dfc342a813de44300f8e12e1a",
            "bd774a2c304c2bad9ff608eafe9c67be99a71bd2184370e9992f8ef7e73403e7",
            "031407",
        );
        // The phone and desktop display these characters; "31407" would never match a
        // six-digit screen.
        assert_eq!(sas(&hash).as_str().len(), 6);
    }

    /// The desktop's view and the phone's view of one exchange, each side holding its own party and
    /// the peer's values reconstructed from the frames it received.
    #[test]
    fn both_endpoints_build_identical_transcripts_so_a_human_can_compare_screens() {
        let exchange = vector_a();
        let wire = |frame: PairingFrame| -> PairingFrame {
            let json = serde_json::to_vec(&frame).expect("encode");
            serde_json::from_slice(&json).expect("decode")
        };
        let received_party = |own: &PairingParty, commit_frame, reveal_frame| -> PairingParty {
            let (PairingFrame::Begin { commitment, .. } | PairingFrame::Commit { commitment, .. }) =
                wire(commit_frame)
            else {
                panic!("expected a commitment frame");
            };
            let PairingFrame::Reveal { nonce, .. } = wire(reveal_frame) else {
                panic!("expected a reveal frame");
            };
            PairingParty {
                commitment,
                nonce,
                ..own.clone()
            }
        };
        let pairing_id = exchange.pairing_id;
        let desktop_seen_by_phone = received_party(
            &exchange.initiator,
            PairingFrame::Begin {
                pairing_id,
                commitment: exchange.initiator.commitment,
                expires_at_unix_ms: 1,
            },
            PairingFrame::Reveal {
                pairing_id,
                nonce: exchange.initiator.nonce,
            },
        );
        let phone_seen_by_desktop = received_party(
            &exchange.responder,
            PairingFrame::Commit {
                pairing_id,
                commitment: exchange.responder.commitment,
            },
            PairingFrame::Reveal {
                pairing_id,
                nonce: exchange.responder.nonce,
            },
        );

        let (d_init, d_resp) = by_role(
            PairingRole::Initiator,
            &exchange.initiator,
            &phone_seen_by_desktop,
        );
        let (p_init, p_resp) = by_role(
            PairingRole::Responder,
            &exchange.responder,
            &desktop_seen_by_phone,
        );
        assert_eq!(
            transcript_bytes(&pairing_id, d_init, d_resp).expect("desktop transcript"),
            transcript_bytes(&pairing_id, p_init, p_resp).expect("phone transcript"),
        );

        let desktop = transcript_hash_for_view(
            &pairing_id,
            PairingRole::Initiator,
            &exchange.initiator,
            &phone_seen_by_desktop,
        )
        .expect("desktop hash");
        let phone = transcript_hash_for_view(
            &pairing_id,
            PairingRole::Responder,
            &exchange.responder,
            &desktop_seen_by_phone,
        )
        .expect("phone hash");
        assert_eq!(desktop, phone);
        assert_eq!(sas(&desktop), sas(&phone));
        assert_eq!(desktop, exchange.hash());
    }

    fn assert_mutation_changes_transcript(mutate: impl FnOnce(&mut Exchange)) {
        let baseline = vector_a();
        let mut mutated = baseline.clone();
        mutate(&mut mutated);
        assert_ne!(baseline.hash(), mutated.hash());
    }

    #[test]
    fn interposer_substituting_its_own_key_for_the_desktop_changes_the_code() {
        assert_mutation_changes_transcript(|e| e.initiator.public_key[0] ^= 1);
    }

    #[test]
    fn interposer_substituting_its_own_key_for_the_phone_changes_the_code() {
        assert_mutation_changes_transcript(|e| e.responder.public_key[31] ^= 1);
    }

    #[test]
    fn rewritten_desktop_hello_changes_the_code() {
        assert_mutation_changes_transcript(|e| e.initiator.hello[0] ^= 1);
    }

    #[test]
    fn rewritten_phone_hello_changes_the_code() {
        assert_mutation_changes_transcript(|e| e.responder.hello.push(b' '));
    }

    #[test]
    fn claiming_another_desktop_device_id_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            e.initiator.device_id = "11111111-2222-3333-4444-555555555556".parse().expect("id");
        });
    }

    #[test]
    fn claiming_another_phone_device_id_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            e.responder.device_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeef".parse().expect("id");
        });
    }

    #[test]
    fn substituted_desktop_commitment_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            let mut bytes = *e.initiator.commitment.as_bytes();
            bytes[0] ^= 1;
            e.initiator.commitment = NonceCommitment::from_bytes(bytes);
        });
    }

    #[test]
    fn substituted_phone_commitment_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            let mut bytes = *e.responder.commitment.as_bytes();
            bytes[31] ^= 1;
            e.responder.commitment = NonceCommitment::from_bytes(bytes);
        });
    }

    #[test]
    fn grinding_the_desktop_nonce_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            let mut bytes = *e.initiator.nonce.as_bytes();
            bytes[0] ^= 1;
            e.initiator.nonce = PairingNonce::from_bytes(bytes);
        });
    }

    #[test]
    fn grinding_the_phone_nonce_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            let mut bytes = *e.responder.nonce.as_bytes();
            bytes[31] ^= 1;
            e.responder.nonce = PairingNonce::from_bytes(bytes);
        });
    }

    #[test]
    fn replaying_an_exchange_under_another_pairing_id_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            let mut bytes = *e.pairing_id.as_bytes();
            bytes[15] ^= 1;
            e.pairing_id = PairingId::from_bytes(bytes);
        });
    }

    #[test]
    fn reflecting_roles_so_the_phone_poses_as_the_desktop_changes_the_code() {
        assert_mutation_changes_transcript(|e| {
            std::mem::swap(&mut e.initiator, &mut e.responder);
        });
        // A caller that mislabels its own role also gets a different code, never a match.
        let e = vector_a();
        let mislabelled = transcript_hash_for_view(
            &e.pairing_id,
            PairingRole::Responder,
            &e.initiator,
            &e.responder,
        )
        .expect("hash");
        assert_ne!(mislabelled, e.hash());
    }

    #[test]
    fn hello_must_be_present_and_bounded_rather_than_silently_hashed() {
        let mut e = vector_a();
        e.responder.hello.clear();
        let error = transcript_hash(&e.pairing_id, &e.initiator, &e.responder)
            .expect_err("empty hello binds nothing");
        assert!(error.to_string().contains("responder hello"));

        e.responder.hello = vec![b'x'; PAIRING_MAX_HELLO_BYTES];
        transcript_hash(&e.pairing_id, &e.initiator, &e.responder).expect("hello at the bound");
        e.responder.hello.push(b'x');
        transcript_hash(&e.pairing_id, &e.initiator, &e.responder)
            .expect_err("hello over the bound is refused");
    }

    #[test]
    fn reveal_opens_only_its_own_role_and_pairing_commitment() {
        let pairing_id = PairingId::from_bytes(ascending(0x10));
        let other_pairing_id = PairingId::from_bytes(ascending(0x11));
        let nonce = PairingNonce::from_bytes(ascending(0x30));
        let other_nonce = PairingNonce::from_bytes(ascending(0x31));
        let commitment = commit(PairingRole::Responder, &pairing_id, &nonce);

        assert!(verify_reveal(
            PairingRole::Responder,
            &pairing_id,
            &nonce,
            &commitment
        ));
        // A side that saw the other's reveal cannot swap in a nonce chosen afterwards.
        assert!(!verify_reveal(
            PairingRole::Responder,
            &pairing_id,
            &other_nonce,
            &commitment
        ));
        // Role binding: an interposer cannot reflect the phone's commitment back as the desktop's.
        assert!(!verify_reveal(
            PairingRole::Initiator,
            &pairing_id,
            &nonce,
            &commitment
        ));
        // Pairing binding: a commitment from one attempt cannot be replayed into another.
        assert!(!verify_reveal(
            PairingRole::Responder,
            &other_pairing_id,
            &nonce,
            &commitment
        ));
    }

    fn block_with(chunks: &[[u8; 3]], fill: u8) -> [u8; 32] {
        let mut block = [fill; 32];
        for (index, chunk) in chunks.iter().enumerate() {
            block[3 * index..3 * index + 3].copy_from_slice(chunk);
        }
        block
    }

    #[test]
    fn scanner_rejects_out_of_range_candidate_and_falls_through_to_the_next_chunk() {
        // 0xFFFFFF has low 20 bits 0xFFFFF = 1,048,575: rejected. 0x01E240 = 123,456: accepted.
        let block = block_with(&[[0xff, 0xff, 0xff], [0x01, 0xe2, 0x40]], 0xff);
        assert_eq!(first_code_in_block(&block), Some(123_456));

        // Exact boundary: 1,000,000 (0x0F4240) is rejected, 999,999 (0x0F423F) is accepted.
        let block = block_with(&[[0x0f, 0x42, 0x40], [0x0f, 0x42, 0x3f]], 0xff);
        assert_eq!(first_code_in_block(&block), Some(999_999));

        // Only the low 20 bits count: the high nibble of the first byte is discarded.
        let block = block_with(&[[0xf1, 0xe2, 0x40]], 0xff);
        assert_eq!(first_code_in_block(&block), Some(123_456));
    }

    #[test]
    fn scanner_ignores_the_last_two_bytes_and_the_counter_advances() {
        // Ten rejected chunks followed by two bytes that would be a valid candidate if read.
        let mut block = [0xff; 32];
        block[30] = 0x00;
        block[31] = 0x00;
        assert_eq!(first_code_in_block(&block), None);

        let mut requested = Vec::new();
        let code = sas_from_blocks(|counter| {
            requested.push(counter);
            if counter == 0 {
                block
            } else {
                block_with(&[[0x00, 0x00, 0x2a]], 0xff)
            }
        });
        assert_eq!(requested, vec![0, 1]);
        // 42 renders with its leading zeros; a human compares all six characters.
        assert_eq!(code.as_str(), "000042");
    }

    fn chi_square(counts: &[u64; 10], samples: u64) -> f64 {
        let expected = samples as f64 / 10.0;
        counts
            .iter()
            .map(|&count| {
                let delta = count as f64 - expected;
                delta * delta / expected
            })
            .sum()
    }

    /// Modulo-bias guard. With 9 degrees of freedom the chi-square 99.9th percentile is 27.877; the
    /// inputs are fixed, so this is a deterministic check against that bound. Reducing a 20-bit
    /// candidate with `% 1_000_000` instead of rejecting it gives leading digit 0 a probability of
    /// 148,576/1,048,576 (about 0.142 against 0.1), an expected statistic near 3,900 at 200,000
    /// samples. The test computes that forbidden reduction over the same hash stream and requires
    /// it to fail, which shows the check can detect the bias.
    #[test]
    fn leading_digit_is_uniform_so_no_code_is_favoured() {
        const SAMPLES: u32 = 200_000;
        const CHI_SQUARE_9_DOF_P999: f64 = 27.877;
        let exchange = vector_a();
        let mut honest = [0_u64; 10];
        let mut forbidden = [0_u64; 10];
        let mut responder = exchange.responder.clone();
        for sample in 0..SAMPLES {
            let mut nonce = *exchange.responder.nonce.as_bytes();
            nonce[..4].copy_from_slice(&sample.to_be_bytes());
            responder.nonce = PairingNonce::from_bytes(nonce);
            let hash = transcript_hash(&exchange.pairing_id, &exchange.initiator, &responder)
                .expect("bounded transcript");

            let code = sas(&hash);
            let leading = code.as_str().as_bytes()[0] - b'0';
            honest[usize::from(leading)] += 1;

            let block = sas_block(&hash, 0);
            let candidate =
                ((u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]))
                    & SAS_CANDIDATE_MASK;
            forbidden[(candidate % SAS_BOUND / 100_000) as usize] += 1;
        }
        let honest_statistic = chi_square(&honest, u64::from(SAMPLES));
        let forbidden_statistic = chi_square(&forbidden, u64::from(SAMPLES));
        assert!(
            honest_statistic < CHI_SQUARE_9_DOF_P999,
            "rejection-sampled leading digits {honest:?} give chi-square {honest_statistic}"
        );
        assert!(
            forbidden_statistic > CHI_SQUARE_9_DOF_P999,
            "the modulo reduction {forbidden:?} should be detected; chi-square {forbidden_statistic}"
        );
    }

    fn sample_frames() -> Vec<PairingFrame> {
        let pairing_id = PairingId::from_bytes(ascending(0x01));
        let commitment = NonceCommitment::from_bytes(ascending(0x40));
        let transcript_hash = TranscriptHash::from_bytes(ascending(0x80));
        vec![
            PairingFrame::Begin {
                pairing_id,
                commitment,
                expires_at_unix_ms: 1_789_000_000_000,
            },
            PairingFrame::Commit {
                pairing_id,
                commitment,
            },
            PairingFrame::Reveal {
                pairing_id,
                nonce: PairingNonce::from_bytes(ascending(0xc0)),
            },
            PairingFrame::Decision {
                pairing_id,
                decision: PairingDecision::Confirm,
                transcript_hash,
            },
            PairingFrame::DesktopCommitted {
                pairing_id,
                transcript_hash,
            },
            PairingFrame::Complete {
                pairing_id,
                transcript_hash,
            },
            PairingFrame::Abort {
                pairing_id,
                code: PairingAbortCode::IdentityChanged,
                detail: Some("peer key differs from the paired key".to_owned()),
            },
            PairingFrame::Abort {
                pairing_id,
                code: PairingAbortCode::WindowClosed,
                detail: None,
            },
        ]
    }

    #[test]
    fn every_frame_round_trips_and_verifies_under_its_signer() {
        let identity = InstallationIdentity::generate();
        for frame in sample_frames() {
            let signed = SignedPairingFrame::sign(frame, &identity).expect("sign");
            let encoded = signed.encode().expect("encode");
            let decoded = SignedPairingFrame::decode(&encoded).expect("decode");
            assert_eq!(decoded, signed);
            assert!(decoded.verify(&identity.public_key()));
        }
    }

    #[test]
    fn frame_wire_shape_uses_tagged_body_and_lowercase_hex() {
        let frame = PairingFrame::Commit {
            pairing_id: PairingId::from_bytes(ascending(0xa0)),
            commitment: NonceCommitment::from_bytes([0xab; 32]),
        };
        let json = serde_json::to_string(&frame).expect("json");
        assert_eq!(
            json,
            format!(
                r#"{{"type":"commit","body":{{"pairing_id":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf","commitment":"{}"}}}}"#,
                "ab".repeat(32)
            )
        );
        let code = serde_json::to_string(&PairingAbortCode::RateLimited).expect("json");
        assert_eq!(code, r#""rate_limited""#);
    }

    #[test]
    fn hex_fields_accept_only_exact_lowercase_hex() {
        let lower = format!("\"{}\"", "0f".repeat(16));
        serde_json::from_str::<PairingId>(&lower).expect("lowercase");
        let upper = format!("\"{}\"", "0F".repeat(16));
        serde_json::from_str::<PairingId>(&upper).expect_err("uppercase is not canonical");
        let short = format!("\"{}\"", "0f".repeat(15));
        serde_json::from_str::<PairingId>(&short).expect_err("wrong length");
        let bad = format!("\"{}zz\"", "0f".repeat(15));
        serde_json::from_str::<PairingId>(&bad).expect_err("not hex");
    }

    #[test]
    fn nonce_debug_output_never_exposes_the_secret() {
        let nonce = PairingNonce::from_bytes([0x5a; 32]);
        let rendered = format!("{nonce:?}");
        assert!(!rendered.contains("5a5a"));
        let frame = PairingFrame::Reveal {
            pairing_id: PairingId::from_bytes([1; 16]),
            nonce,
        };
        assert!(!format!("{frame:?}").contains("5a5a"));
    }

    #[test]
    fn signature_by_one_key_does_not_verify_under_another() {
        let signer = InstallationIdentity::generate();
        let interposer = InstallationIdentity::generate();
        for frame in sample_frames() {
            let signed = SignedPairingFrame::sign(frame, &signer).expect("sign");
            assert!(!signed.verify(&interposer.public_key()));
        }
    }

    #[test]
    fn tampered_frame_fields_fail_verification() {
        let identity = InstallationIdentity::generate();
        let key = identity.public_key();
        let transcript_hash = TranscriptHash::from_bytes(ascending(0x80));
        let pairing_id = PairingId::from_bytes(ascending(0x01));
        let signed = SignedPairingFrame::sign(
            PairingFrame::Decision {
                pairing_id,
                decision: PairingDecision::Decline,
                transcript_hash,
            },
            &identity,
        )
        .expect("sign");
        assert!(signed.verify(&key));

        // A phone's decline rewritten in transit as a confirm must not verify.
        let mut flipped = signed.clone();
        flipped.frame = PairingFrame::Decision {
            pairing_id,
            decision: PairingDecision::Confirm,
            transcript_hash,
        };
        assert!(!flipped.verify(&key));

        // A decision for one transcript must not be moved onto another.
        let mut moved = signed.clone();
        let mut other = *transcript_hash.as_bytes();
        other[0] ^= 1;
        moved.frame = PairingFrame::Decision {
            pairing_id,
            decision: PairingDecision::Decline,
            transcript_hash: TranscriptHash::from_bytes(other),
        };
        assert!(!moved.verify(&key));

        let mut corrupted = signed;
        corrupted.signature[0] ^= 1;
        assert!(!corrupted.verify(&key));
    }

    #[test]
    fn pairing_and_hello_signatures_are_domain_separated() {
        let identity = InstallationIdentity::generate();
        let key = identity.public_key();
        let frame = sample_frames().remove(0);
        let frame_json = serde_json::to_vec(&frame).expect("json");

        // A pairing signature does not verify as a hello-style signature over the same frame bytes.
        let signed = SignedPairingFrame::sign(frame.clone(), &identity).expect("sign");
        assert!(!InstallationIdentity::verify(
            &key,
            &frame_json,
            &signed.signature
        ));

        // A hello-style signature over the same bytes does not verify as a pairing frame.
        let hello_style = SignedPairingFrame {
            frame,
            signature: identity.sign(&frame_json),
        };
        assert!(!hello_style.verify(&key));

        // A real hello signature cannot be attached to a pairing frame either.
        let hello = ClientHello::signed_v2(identity.device_id, "CEDAR", "nonce", &identity);
        assert!(hello.has_valid_signature());
        let grafted = SignedPairingFrame {
            frame: sample_frames().remove(1),
            signature: hello.signature,
        };
        assert!(!grafted.verify(&key));
    }

    fn padded_to(json: &[u8], length: usize) -> Vec<u8> {
        let mut padded = json.to_vec();
        padded.resize(length, b' ');
        padded
    }

    #[test]
    fn decode_enforces_the_four_kib_bound_before_parsing() {
        let identity = InstallationIdentity::generate();
        let encoded = SignedPairingFrame::sign(sample_frames().remove(0), &identity)
            .expect("sign")
            .encode()
            .expect("encode");

        let at_bound = padded_to(&encoded, PAIRING_MAX_FRAME_BYTES);
        SignedPairingFrame::decode(&at_bound).expect("exactly 4 KiB is accepted");

        let over = padded_to(&encoded, PAIRING_MAX_FRAME_BYTES + 1);
        let error = SignedPairingFrame::decode(&over).expect_err("oversized");
        assert!(matches!(
            error,
            ProtocolError::FrameTooLarge {
                bytes: 4097,
                maximum: PAIRING_MAX_FRAME_BYTES
            }
        ));
        assert!(matches!(
            SignedPairingFrame::decode(&[]),
            Err(ProtocolError::EmptyFrame)
        ));
    }

    #[test]
    fn encode_refuses_an_oversized_frame() {
        let identity = InstallationIdentity::generate();
        let mut signed =
            SignedPairingFrame::sign(sample_frames().remove(1), &identity).expect("sign");
        signed.signature = vec![0xff; 2_000];
        assert!(matches!(
            signed.encode(),
            Err(ProtocolError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn largest_valid_frame_still_fits_the_bound() {
        // A detail at the limit made of bytes JSON escapes as \u00XX is the worst case, so no
        // legitimate abort is ever refused by the frame bound.
        let identity = InstallationIdentity::generate();
        let signed = SignedPairingFrame::sign(
            PairingFrame::Abort {
                pairing_id: PairingId::from_bytes([0xff; 16]),
                code: PairingAbortCode::IdentityChanged,
                detail: Some("\u{1}".repeat(V2_MAX_STATUS_DETAIL_BYTES)),
            },
            &identity,
        )
        .expect("sign");
        let mut worst = signed.clone();
        worst.signature = vec![0xff; 64];
        assert!(worst.encode().expect("fits").len() <= PAIRING_MAX_FRAME_BYTES);
        let decoded =
            SignedPairingFrame::decode(&signed.encode().expect("encode")).expect("decode");
        assert!(decoded.verify(&identity.public_key()));
    }

    #[test]
    fn invalid_frames_are_refused_at_sign_encode_decode_and_verify() {
        let identity = InstallationIdentity::generate();
        let pairing_id = PairingId::from_bytes([7; 16]);
        let invalid = [
            PairingFrame::Begin {
                pairing_id,
                commitment: NonceCommitment::from_bytes([1; 32]),
                expires_at_unix_ms: 0,
            },
            PairingFrame::Abort {
                pairing_id,
                code: PairingAbortCode::Invalid,
                detail: Some(String::new()),
            },
            PairingFrame::Abort {
                pairing_id,
                code: PairingAbortCode::Invalid,
                detail: Some("x".repeat(V2_MAX_STATUS_DETAIL_BYTES + 1)),
            },
            PairingFrame::Commit {
                pairing_id: PairingId::from_bytes([0; 16]),
                commitment: NonceCommitment::from_bytes([1; 32]),
            },
        ];
        for frame in invalid {
            assert!(frame.validate().is_err(), "{frame:?} should be invalid");
            SignedPairingFrame::sign(frame.clone(), &identity).expect_err("sign refuses");

            // A peer that signed it anyway is still refused on every path.
            let forged = SignedPairingFrame {
                signature: identity.sign(&frame_signing_bytes(&frame).expect("bytes")),
                frame,
            };
            assert!(!forged.verify(&identity.public_key()));
            assert!(forged.encode().is_err());
            let json = serde_json::to_vec(&forged).expect("json");
            assert!(matches!(
                SignedPairingFrame::decode(&json),
                Err(ProtocolError::V2Validation { .. })
            ));
        }

        let at_limit = PairingFrame::Abort {
            pairing_id,
            code: PairingAbortCode::Busy,
            detail: Some("x".repeat(V2_MAX_STATUS_DETAIL_BYTES)),
        };
        at_limit.validate().expect("detail at the limit is valid");
    }

    #[test]
    fn generated_identifiers_are_fresh() {
        assert_ne!(PairingNonce::generate(), PairingNonce::generate());
        assert_ne!(PairingId::generate(), PairingId::generate());
    }
}
