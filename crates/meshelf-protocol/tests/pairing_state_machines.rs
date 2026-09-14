//! The pairing state machines through their public API, exactly as the network phase drives them.
//! Every frame crosses a simulated wire as `V2Message::Pair` under the pairing bound.

use meshelf_identity::InstallationIdentity;
use meshelf_protocol::pairing::{
    ApprovedPending, DesktopAwaitingDecision, DesktopPairing, NonceCommitment,
    PAIRING_MAX_FRAME_BYTES, PAIRING_RECONCILE_ALLOWANCE_MS, PairedPeer, PairingAbortCode,
    PairingDecision, PairingError, PairingFailure, PairingFrame, PairingId, PairingNonce,
    PairingParty, PairingResult, PairingRole, PhoneAwaitingCommitted, PhoneCandidate, PhonePairing,
    SignedPairingFrame, TranscriptHash, commit, sas, transcript_hash,
};
use meshelf_protocol::{
    CAP_OFFER_PULL_V2, CAP_PAIRING_V1, ClientHello, ServerHello, V2_PROTOCOL_VERSION, V2Message,
    decode_v2_payload, encode_v2_frame, validate_v2_message,
};

const NOW: u64 = 1_800_000_000_000;
const EXPIRES: u64 = NOW + 120_000;
const DESKTOP_NONCE: [u8; 32] = [0x11; 32];
const PHONE_NONCE: [u8; 32] = [0x22; 32];

fn desktop_hello(identity: &InstallationIdentity, name: &str) -> ClientHello {
    ClientHello::signed_v2_with_capabilities(
        identity.device_id,
        name,
        "hello-nonce",
        vec![CAP_PAIRING_V1.to_owned()],
        identity,
    )
}

fn phone_hello(identity: &InstallationIdentity, name: &str) -> ServerHello {
    ServerHello::signed(
        V2_PROTOCOL_VERSION,
        identity.device_id,
        name.to_owned(),
        true,
        None,
        vec![CAP_PAIRING_V1.to_owned()],
        identity,
    )
}

/// Sends one frame across the pairing wire: encoded as a V2 message, bounded, decoded, validated.
fn wire(frame: SignedPairingFrame) -> SignedPairingFrame {
    let bytes = encode_v2_frame(&V2Message::Pair(frame)).expect("honest frames fit the wire");
    let payload = &bytes[4..];
    assert!(payload.len() <= PAIRING_MAX_FRAME_BYTES);
    let message = decode_v2_payload(payload).expect("decode");
    validate_v2_message(&message).expect("validate");
    let V2Message::Pair(frame) = message else {
        panic!("expected a pairing frame");
    };
    frame
}

fn signed(frame: PairingFrame, by: &InstallationIdentity) -> SignedPairingFrame {
    SignedPairingFrame::sign(frame, by).expect("sign")
}

/// One desktop and one phone with the hellos of one pairing-only connection.
struct Devices {
    desktop: InstallationIdentity,
    phone: InstallationIdentity,
    client_hello: ClientHello,
    server_hello: ServerHello,
    pairing_id: PairingId,
}

impl Devices {
    fn new() -> Self {
        let desktop = InstallationIdentity::generate();
        let phone = InstallationIdentity::generate();
        Self {
            client_hello: desktop_hello(&desktop, "CEDAR"),
            server_hello: phone_hello(&phone, "Pixel"),
            desktop,
            phone,
            pairing_id: PairingId::generate(),
        }
    }

    fn start_desktop(&self) -> (DesktopPairing, SignedPairingFrame) {
        DesktopPairing::start(
            self.desktop.clone(),
            &self.client_hello,
            &self.server_hello,
            self.pairing_id,
            PairingNonce::from_bytes(DESKTOP_NONCE),
            EXPIRES,
            NOW,
        )
        .expect("desktop starts")
    }

    fn new_phone(&self) -> PhonePairing {
        PhonePairing::new(
            self.phone.clone(),
            &self.client_hello,
            &self.server_hello,
            PairingNonce::from_bytes(PHONE_NONCE),
            EXPIRES,
            NOW,
        )
        .expect("phone accepts the connection")
    }

    /// Runs commit and reveal honestly until both screens show a code.
    fn to_candidates(&self) -> (DesktopAwaitingDecision, PhoneCandidate) {
        let (desktop, begin) = self.start_desktop();
        let (phone, commit_frame) = self.new_phone().on_frame(&wire(begin), NOW).expect("begin");
        let (desktop, desktop_reveal) = desktop.on_frame(&wire(commit_frame), NOW).expect("commit");
        let (phone, phone_reveal) = phone
            .on_frame(&wire(desktop_reveal), NOW)
            .expect("desktop reveal");
        let desktop = desktop
            .on_frame(&wire(phone_reveal), NOW)
            .expect("phone reveal");
        (desktop, phone)
    }

    /// Runs until the phone has sent `Decision{Confirm}` and the desktop has persisted phone trust,
    /// returning the phone's approval, the desktop's trust record, and the `DesktopCommitted` frame.
    fn to_desktop_committed(
        &self,
    ) -> (
        PhoneAwaitingCommitted,
        ApprovedPending,
        PairedPeer,
        SignedPairingFrame,
    ) {
        let (desktop, phone) = self.to_candidates();
        let hash = phone.candidate().transcript_hash;
        let pending = phone.confirm(&hash, NOW + 1).expect("approve");
        let approved = pending.approved_pending().clone();
        let (phone, decision) = pending.approval_persisted().expect("decision");
        let trust = desktop.on_frame(&wire(decision), NOW + 2).expect("confirm");
        let paired = trust.peer().clone();
        let (_desktop, committed) = trust.trust_persisted().expect("committed");
        (phone, approved, paired, committed)
    }
}

fn failure<T>(result: Result<T, PairingFailure>) -> PairingFailure {
    match result {
        Ok(_) => panic!("expected the transition to fail"),
        Err(failure) => failure,
    }
}

fn abort_code(failure: &PairingFailure) -> Option<PairingAbortCode> {
    failure.abort.as_deref().map(|abort| match abort.frame {
        PairingFrame::Abort { code, .. } => code,
        ref other => panic!("failure carried a non-abort frame {other:?}"),
    })
}

#[test]
fn honest_run_shows_the_same_code_on_both_screens_and_ends_in_mutual_durable_trust() {
    let devices = Devices::new();
    let (desktop, phone) = devices.to_candidates();

    // The property the person relies on: both screens show one code, derived independently.
    let desktop_view = desktop.candidate().clone();
    let phone_view = phone.candidate().clone();
    assert_eq!(desktop_view.code, phone_view.code);
    assert_eq!(desktop_view.transcript_hash, phone_view.transcript_hash);
    assert_eq!(desktop_view.code.as_str().len(), 6);
    assert_eq!(desktop_view.pairing_id, devices.pairing_id);
    assert_eq!(phone_view.expires_at_unix_ms, EXPIRES);
    assert_eq!(phone_view.device_name, "CEDAR");
    assert_eq!(desktop_view.device_name, "Pixel");

    // A2: the machines bind exactly ClientHello::signing_bytes() and ServerHello::signing_bytes()
    // of this connection, so the frozen transcript function over those inputs gives the same hash.
    let party = |role, identity: &InstallationIdentity, hello: Vec<u8>, nonce: [u8; 32]| {
        let nonce = PairingNonce::from_bytes(nonce);
        PairingParty {
            device_id: identity.device_id,
            public_key: identity.public_key(),
            hello,
            commitment: commit(role, &devices.pairing_id, &nonce),
            nonce,
        }
    };
    let expected = transcript_hash(
        &devices.pairing_id,
        &party(
            PairingRole::Initiator,
            &devices.desktop,
            devices.client_hello.signing_bytes(),
            DESKTOP_NONCE,
        ),
        &party(
            PairingRole::Responder,
            &devices.phone,
            devices.server_hello.signing_bytes(),
            PHONE_NONCE,
        ),
    )
    .expect("reference transcript");
    assert_eq!(phone_view.transcript_hash, expected);
    assert_eq!(phone_view.code, sas(&expected));

    // The phone approves the exact transcript it displayed.
    let pending = phone
        .confirm(&phone_view.transcript_hash, NOW + 10)
        .expect("approve");
    let approved = pending.approved_pending().clone();
    assert_eq!(
        approved,
        ApprovedPending {
            pairing_id: devices.pairing_id,
            transcript_hash: expected,
            peer_device_id: devices.desktop.device_id,
            peer_public_key: devices.desktop.public_key(),
            peer_device_name: "CEDAR".to_owned(),
            approved_at_unix_ms: NOW + 10,
            expires_at_unix_ms: EXPIRES,
        }
    );
    let (phone, decision) = pending.approval_persisted().expect("decision");
    assert!(matches!(
        decision.frame,
        PairingFrame::Decision {
            decision: PairingDecision::Confirm,
            ..
        }
    ));

    let trust = desktop
        .on_frame(&wire(decision), NOW + 11)
        .expect("confirm");
    assert_eq!(
        trust.peer(),
        &PairedPeer {
            device_id: devices.phone.device_id,
            public_key: devices.phone.public_key(),
            device_name: "Pixel".to_owned(),
            pairing_id: devices.pairing_id,
            transcript_hash: expected,
        }
    );
    let (desktop, committed) = trust.trust_persisted().expect("committed");

    let trust = phone
        .on_frame(&wire(committed), NOW + 12)
        .expect("committed");
    assert_eq!(trust.peer().device_id, devices.desktop.device_id);
    assert_eq!(trust.peer().public_key, devices.desktop.public_key());
    assert_eq!(trust.peer().transcript_hash, expected);
    let complete = trust.trust_persisted().expect("complete");

    desktop
        .on_frame(&wire(complete), NOW + 13)
        .expect("both sides now hold durable trust");
}

/// Why the six digits authenticate the keys: an interposer who relays every commitment and nonce
/// between two legs, so both legs share the same random material, still cannot make the legs'
/// transcripts agree, because each leg binds the keys and hellos actually on that connection.
#[test]
fn two_leg_interposer_relaying_all_nonce_material_gets_different_transcripts() {
    let desktop = InstallationIdentity::generate();
    let phone = InstallationIdentity::generate();
    let interposer = InstallationIdentity::generate();
    let pairing_id = PairingId::generate();

    // Leg A: the real desktop talks to the interposer posing as a phone.
    let (desktop_leg, begin_a) = DesktopPairing::start(
        desktop.clone(),
        &desktop_hello(&desktop, "CEDAR"),
        &phone_hello(&interposer, "Pixel"),
        pairing_id,
        PairingNonce::from_bytes(DESKTOP_NONCE),
        EXPIRES,
        NOW,
    )
    .expect("leg A starts");
    let PairingFrame::Begin {
        commitment: desktop_commitment,
        ..
    } = begin_a.frame
    else {
        panic!("begin");
    };

    // Leg B: the interposer poses as a desktop to the real phone, reusing the desktop's commitment.
    let phone_leg = PhonePairing::new(
        phone.clone(),
        &desktop_hello(&interposer, "CEDAR"),
        &phone_hello(&phone, "Pixel"),
        PairingNonce::from_bytes(PHONE_NONCE),
        EXPIRES,
        NOW,
    )
    .expect("leg B accepts");
    let begin_b = signed(
        PairingFrame::Begin {
            pairing_id,
            commitment: desktop_commitment,
            expires_at_unix_ms: EXPIRES,
        },
        &interposer,
    );
    let (phone_leg, commit_b) = phone_leg.on_frame(&wire(begin_b), NOW).expect("begin B");
    let PairingFrame::Commit {
        commitment: phone_commitment,
        ..
    } = commit_b.frame
    else {
        panic!("commit");
    };

    // Relay the phone's commitment into leg A, the desktop's reveal into leg B, and back.
    let commit_a = signed(
        PairingFrame::Commit {
            pairing_id,
            commitment: phone_commitment,
        },
        &interposer,
    );
    let (desktop_leg, reveal_a) = desktop_leg
        .on_frame(&wire(commit_a), NOW)
        .expect("commit A");
    let PairingFrame::Reveal {
        nonce: desktop_nonce,
        ..
    } = reveal_a.frame
    else {
        panic!("reveal");
    };
    let reveal_b = signed(
        PairingFrame::Reveal {
            pairing_id,
            nonce: desktop_nonce,
        },
        &interposer,
    );
    let (phone_leg, phone_reveal) = phone_leg
        .on_frame(&wire(reveal_b), NOW)
        .expect("relayed reveal opens the relayed commitment");
    let PairingFrame::Reveal {
        nonce: phone_nonce, ..
    } = phone_reveal.frame
    else {
        panic!("reveal");
    };
    let relayed = signed(
        PairingFrame::Reveal {
            pairing_id,
            nonce: phone_nonce,
        },
        &interposer,
    );
    let desktop_leg = desktop_leg
        .on_frame(&wire(relayed), NOW)
        .expect("relayed reveal opens the relayed commitment");

    // Both legs completed commit-reveal over identical random material, yet the transcripts
    // differ. (The six-digit codes then collide only with probability about one in a million,
    // which is why the admission limits bound the interposer to one try per window.)
    assert_ne!(
        desktop_leg.candidate().transcript_hash,
        phone_leg.candidate().transcript_hash
    );
}

#[test]
fn reveal_that_does_not_open_its_commitment_aborts_the_session() {
    // Phone side: the desktop reveals a nonce other than the one it committed to, which is how a
    // side that grinds its contribution after seeing the other's would show up.
    let devices = Devices::new();
    let (desktop, begin) = devices.start_desktop();
    let (phone, commit_frame) = devices
        .new_phone()
        .on_frame(&wire(begin), NOW)
        .expect("begin");
    let (desktop, _honest_reveal) = desktop.on_frame(&wire(commit_frame), NOW).expect("commit");
    let ground = signed(
        PairingFrame::Reveal {
            pairing_id: devices.pairing_id,
            nonce: PairingNonce::from_bytes([0x99; 32]),
        },
        &devices.desktop,
    );
    let refused = failure(phone.on_frame(&wire(ground), NOW));
    assert_eq!(refused.error, PairingError::CommitmentMismatch);
    assert_eq!(abort_code(&refused), Some(PairingAbortCode::Invalid));

    // The desktop receiving that abort ends with the A11 word the phone reported.
    let abort = *refused.abort.expect("abort");
    let ended = failure(desktop.on_frame(&wire(abort), NOW));
    assert_eq!(
        ended.error,
        PairingError::Aborted(PairingAbortCode::Invalid)
    );
    assert_eq!(ended.result().as_str(), "invalid");
    assert_eq!(
        ended.abort, None,
        "an abort is never answered with an abort"
    );

    // Desktop side: the phone reveals a nonce other than the one it committed to.
    let devices = Devices::new();
    let (desktop, begin) = devices.start_desktop();
    let (_phone, commit_frame) = devices
        .new_phone()
        .on_frame(&wire(begin), NOW)
        .expect("begin");
    let (desktop, _reveal) = desktop.on_frame(&wire(commit_frame), NOW).expect("commit");
    let ground = signed(
        PairingFrame::Reveal {
            pairing_id: devices.pairing_id,
            nonce: PairingNonce::from_bytes([0x98; 32]),
        },
        &devices.phone,
    );
    let refused = failure(desktop.on_frame(&wire(ground), NOW));
    assert_eq!(refused.error, PairingError::CommitmentMismatch);
    assert_eq!(refused.result(), PairingResult::Invalid);
}

/// A reveal before both commitments are exchanged would let the other side choose its own
/// contribution after seeing this one, so it is refused wherever it can arrive.
#[test]
fn reveal_before_both_commitments_are_exchanged_is_out_of_order() {
    let devices = Devices::new();
    let (desktop, _begin) = devices.start_desktop();
    let early = signed(
        PairingFrame::Reveal {
            pairing_id: devices.pairing_id,
            nonce: PairingNonce::from_bytes(PHONE_NONCE),
        },
        &devices.phone,
    );
    let refused = failure(desktop.on_frame(&wire(early), NOW));
    assert_eq!(
        refused.error,
        PairingError::OutOfOrder {
            expected: "commit",
            received: "reveal"
        }
    );
    assert_eq!(abort_code(&refused), Some(PairingAbortCode::Invalid));

    let early = signed(
        PairingFrame::Reveal {
            pairing_id: devices.pairing_id,
            nonce: PairingNonce::from_bytes(DESKTOP_NONCE),
        },
        &devices.desktop,
    );
    let refused = failure(devices.new_phone().on_frame(&wire(early), NOW));
    assert_eq!(
        refused.error,
        PairingError::OutOfOrder {
            expected: "begin",
            received: "reveal"
        }
    );
    assert_eq!(refused.abort, None, "before Begin there is no pairing id");
}

/// `Complete` means the phone durably trusts the desktop; it cannot precede the desktop's own
/// durable commitment, and the desktop cannot claim that commitment before the phone approved.
#[test]
fn completion_frames_before_their_prerequisites_are_out_of_order() {
    let devices = Devices::new();
    let (desktop, phone) = devices.to_candidates();
    let hash = desktop.candidate().transcript_hash;
    let premature_complete = signed(
        PairingFrame::Complete {
            pairing_id: devices.pairing_id,
            transcript_hash: hash,
        },
        &devices.phone,
    );
    let refused = failure(desktop.on_frame(&wire(premature_complete), NOW));
    assert_eq!(
        refused.error,
        PairingError::OutOfOrder {
            expected: "decision",
            received: "complete"
        }
    );

    let premature_commit = signed(
        PairingFrame::DesktopCommitted {
            pairing_id: devices.pairing_id,
            transcript_hash: hash,
        },
        &devices.desktop,
    );
    let refused = phone.on_frame(&wire(premature_commit), NOW);
    assert!(matches!(
        refused.error,
        PairingError::OutOfOrder {
            received: "desktop_committed",
            ..
        }
    ));
}

#[test]
fn frame_signed_by_any_key_but_the_peers_hello_key_is_rejected() {
    let devices = Devices::new();
    let stranger = InstallationIdentity::generate();
    let (desktop, _begin) = devices.start_desktop();
    let forged = signed(
        PairingFrame::Commit {
            pairing_id: devices.pairing_id,
            commitment: NonceCommitment::from_bytes([7; 32]),
        },
        &stranger,
    );
    let refused = failure(desktop.on_frame(&wire(forged), NOW));
    assert_eq!(refused.error, PairingError::BadSignature);

    let forged_begin = signed(
        PairingFrame::Begin {
            pairing_id: devices.pairing_id,
            commitment: NonceCommitment::from_bytes([7; 32]),
            expires_at_unix_ms: EXPIRES,
        },
        &stranger,
    );
    let refused = failure(devices.new_phone().on_frame(&wire(forged_begin), NOW));
    assert_eq!(refused.error, PairingError::BadSignature);
}

/// Frames from one attempt (validly signed by the same peer) must not steer another attempt.
#[test]
fn frames_replayed_from_another_pairing_id_are_rejected() {
    let first = Devices::new();
    let (_phone, _approved, _paired, old_committed) = first.to_desktop_committed();
    let (old_desktop, old_begin) = first.start_desktop();
    let (_phone, old_commit) = first
        .new_phone()
        .on_frame(&wire(old_begin), NOW)
        .expect("begin");
    let (_desktop, old_reveal) = old_desktop
        .on_frame(&wire(old_commit.clone()), NOW)
        .expect("commit");

    // Same desktop, phone, and hellos; a fresh pairing id.
    let second = Devices {
        desktop: first.desktop.clone(),
        phone: first.phone.clone(),
        client_hello: first.client_hello.clone(),
        server_hello: first.server_hello.clone(),
        pairing_id: PairingId::generate(),
    };

    let (desktop, begin) = second.start_desktop();
    let replayed_commit = failure(desktop.on_frame(&wire(old_commit), NOW));
    assert_eq!(replayed_commit.error, PairingError::WrongPairingId);

    let (phone, _commit) = second
        .new_phone()
        .on_frame(&wire(begin), NOW)
        .expect("begin");
    let replayed_reveal = failure(phone.on_frame(&wire(old_reveal), NOW));
    assert_eq!(replayed_reveal.error, PairingError::WrongPairingId);

    let (phone, _approved, _paired, _committed) = second.to_desktop_committed();
    let replayed_committed = failure(phone.on_frame(&wire(old_committed), NOW + 3));
    assert_eq!(replayed_committed.error, PairingError::WrongPairingId);
    assert_eq!(
        abort_code(&replayed_committed),
        Some(PairingAbortCode::Invalid)
    );
}

#[test]
fn frames_after_expiry_are_rejected_and_only_an_approved_transcript_gets_the_allowance() {
    let devices = Devices::new();
    let (desktop, begin) = devices.start_desktop();
    let (_phone, commit_frame) = devices
        .new_phone()
        .on_frame(&wire(begin), NOW)
        .expect("begin");
    let late = failure(desktop.on_frame(&wire(commit_frame), EXPIRES));
    assert_eq!(late.error, PairingError::Expired);
    assert_eq!(late.result().as_str(), "timeout");
    assert_eq!(abort_code(&late), Some(PairingAbortCode::Timeout));

    // A person cannot approve a code after the session expired.
    let (_desktop, phone) = devices.to_candidates();
    let hash = phone.candidate().transcript_hash;
    assert_eq!(
        failure(phone.confirm(&hash, EXPIRES)).error,
        PairingError::Expired
    );

    // A12: once approval is durable, the rest of that exchange may finish inside the allowance.
    let (phone, _approved, _paired, committed) = devices.to_desktop_committed();
    assert_eq!(
        phone.deadline_unix_ms(),
        EXPIRES + PAIRING_RECONCILE_ALLOWANCE_MS
    );
    phone
        .on_frame(&wire(committed.clone()), EXPIRES + 1)
        .expect("inside the allowance")
        .trust_persisted()
        .expect("complete");
    let (phone, _approved, _paired, committed) = devices.to_desktop_committed();
    let too_late =
        failure(phone.on_frame(&wire(committed), EXPIRES + PAIRING_RECONCILE_ALLOWANCE_MS));
    assert_eq!(too_late.error, PairingError::Expired);

    // The desktop may not propose an expiry already past or beyond the window.
    let start = |expires| {
        DesktopPairing::start(
            devices.desktop.clone(),
            &devices.client_hello,
            &devices.server_hello,
            devices.pairing_id,
            PairingNonce::from_bytes(DESKTOP_NONCE),
            expires,
            NOW,
        )
    };
    assert_eq!(failure(start(NOW)).error, PairingError::Expired);
    assert!(matches!(
        failure(start(NOW + 120_001)).error,
        PairingError::Invalid(_)
    ));

    // The phone's session never outlives its own bound, whatever the desktop proposes.
    let phone = PhonePairing::new(
        devices.phone.clone(),
        &devices.client_hello,
        &devices.server_hello,
        PairingNonce::from_bytes(PHONE_NONCE),
        NOW + 30_000,
        NOW,
    )
    .expect("phone");
    let (_desktop, begin) = devices.start_desktop();
    let (phone, _commit) = phone.on_frame(&wire(begin), NOW).expect("begin");
    assert_eq!(phone.deadline_unix_ms(), NOW + 30_000);
}

/// A2: a reveal carries no role, so a peer presenting this installation's own identity could
/// reflect its frames back as the other side's. Such a peer is refused before any frame is read.
#[test]
fn peer_presenting_this_installations_own_identity_is_refused() {
    let devices = Devices::new();
    let reflected_phone = phone_hello(&devices.desktop, "Pixel");
    let refused = failure(DesktopPairing::start(
        devices.desktop.clone(),
        &devices.client_hello,
        &reflected_phone,
        devices.pairing_id,
        PairingNonce::from_bytes(DESKTOP_NONCE),
        EXPIRES,
        NOW,
    ));
    assert_eq!(refused.error, PairingError::OwnKey);
    assert_eq!(refused.result().as_str(), "invalid");

    let reflected_desktop = desktop_hello(&devices.phone, "CEDAR");
    let refused = failure(PhonePairing::new(
        devices.phone.clone(),
        &reflected_desktop,
        &devices.server_hello,
        PairingNonce::from_bytes(PHONE_NONCE),
        EXPIRES,
        NOW,
    ));
    assert_eq!(refused.error, PairingError::OwnKey);
}

/// The transcript must bind a pairing-only hello this connection actually carried: a hello that
/// admitted other operations, a tampered hello, or someone else's hello as "ours" are refused.
#[test]
fn only_signed_pairing_only_hellos_can_enter_a_transcript() {
    let devices = Devices::new();
    let phone = |client: &ClientHello, server: &ServerHello| {
        failure(PhonePairing::new(
            devices.phone.clone(),
            client,
            server,
            PairingNonce::from_bytes(PHONE_NONCE),
            EXPIRES,
            NOW,
        ))
        .error
    };

    let ordinary = ClientHello::signed_v2_with_capabilities(
        devices.desktop.device_id,
        "CEDAR",
        "n",
        vec![CAP_PAIRING_V1.to_owned(), CAP_OFFER_PULL_V2.to_owned()],
        &devices.desktop,
    );
    assert!(matches!(
        phone(&ordinary, &devices.server_hello),
        PairingError::Invalid(_)
    ));

    let mut tampered = devices.client_hello.clone();
    tampered.device_name.push('!');
    assert_eq!(
        phone(&tampered, &devices.server_hello),
        PairingError::BadSignature
    );

    let someone_elses = phone_hello(&InstallationIdentity::generate(), "Pixel");
    assert!(matches!(
        phone(&devices.client_hello, &someone_elses),
        PairingError::Invalid(_)
    ));

    let refused = ServerHello::signed(
        V2_PROTOCOL_VERSION,
        devices.phone.device_id,
        "Pixel".to_owned(),
        false,
        Some("window closed".to_owned()),
        vec![CAP_PAIRING_V1.to_owned()],
        &devices.phone,
    );
    assert!(matches!(
        failure(DesktopPairing::start(
            devices.desktop.clone(),
            &devices.client_hello,
            &refused,
            devices.pairing_id,
            PairingNonce::from_bytes(DESKTOP_NONCE),
            EXPIRES,
            NOW,
        ))
        .error,
        PairingError::Invalid(_)
    ));
}

/// Durable-before-send, crash by crash. The types make each confirming frame reachable only
/// through the persistence acknowledgement (see the compile-fail doc tests on the pending types);
/// this shows what that buys: a crash before the acknowledgement leaves the peer without the
/// frame, so it can never act on a record that does not exist.
#[test]
fn a_crash_before_each_persistence_acknowledgement_leaves_the_peer_without_the_frame() {
    let devices = Devices::new();

    // Phone crashes after the person approved but before the approval was durable: the pending
    // state is dropped, no Decision exists, and the desktop can only time out, never trust.
    let (desktop, phone) = devices.to_candidates();
    let hash = phone.candidate().transcript_hash;
    drop(phone.confirm(&hash, NOW + 1).expect("approve"));
    let timed_out = failure(desktop.on_frame(
        &signed(
            PairingFrame::Abort {
                pairing_id: devices.pairing_id,
                code: PairingAbortCode::Timeout,
                detail: None,
            },
            &devices.phone,
        ),
        NOW + 2,
    ));
    assert_eq!(timed_out.result(), PairingResult::Timeout);

    // Desktop crashes before its trust was durable: no DesktopCommitted exists, so the phone's
    // approval is never promoted to trust and lapses at its deadline.
    let (desktop, phone) = devices.to_candidates();
    let hash = phone.candidate().transcript_hash;
    let (phone, decision) = phone
        .confirm(&hash, NOW + 1)
        .expect("approve")
        .approval_persisted()
        .expect("decision");
    drop(desktop.on_frame(&wire(decision), NOW + 2).expect("confirm"));
    assert_eq!(
        failure(phone.on_frame(
            &signed(
                PairingFrame::Complete {
                    pairing_id: devices.pairing_id,
                    transcript_hash: hash,
                },
                &devices.desktop,
            ),
            NOW + 3,
        ))
        .error,
        PairingError::OutOfOrder {
            expected: "desktop_committed",
            received: "complete"
        }
    );

    // Phone crashes after DesktopCommitted but before desktop trust was durable: no Complete
    // exists; the desktop holds one-sided trust (which cannot authorize a capture) until a
    // resume from the durable ApprovedPending completes it without a new code.
    let (phone, approved, paired, committed) = devices.to_desktop_committed();
    drop(
        phone
            .on_frame(&wire(committed), NOW + 3)
            .expect("committed"),
    );
    let (desktop, committed) = DesktopPairing::resume(
        devices.desktop.clone(),
        &desktop_hello(&devices.desktop, "CEDAR"),
        &phone_hello(&devices.phone, "Pixel"),
        &paired,
        EXPIRES,
        NOW + 4,
    )
    .expect("desktop resumes");
    let complete = PhonePairing::resume(
        devices.phone.clone(),
        &desktop_hello(&devices.desktop, "CEDAR"),
        &approved,
        &wire(committed),
        NOW + 5,
    )
    .expect("phone resumes")
    .trust_persisted()
    .expect("complete");
    desktop.on_frame(&wire(complete), NOW + 6).expect("paired");
}

#[test]
fn decline_and_abort_end_both_sides_with_the_matching_a11_word() {
    // The person rejects the code on the phone.
    let devices = Devices::new();
    let (desktop, phone) = devices.to_candidates();
    let decline = phone.reject().expect("decline");
    let declined = failure(desktop.on_frame(&wire(decline), NOW));
    assert_eq!(declined.error, PairingError::Declined);
    assert_eq!(declined.result().as_str(), "declined");
    assert_eq!(declined.abort, None, "a decline is not answered");

    // The phone's window closes while the person is still comparing.
    let (desktop, phone) = devices.to_candidates();
    let abort = phone
        .abort(PairingAbortCode::WindowClosed, None)
        .expect("abort");
    let closed = failure(desktop.on_frame(&wire(abort), NOW));
    assert_eq!(
        closed.error,
        PairingError::Aborted(PairingAbortCode::WindowClosed)
    );
    assert_eq!(closed.result().as_str(), "window_closed");

    // The desktop gives up while the phone shows the code.
    let (desktop, phone) = devices.to_candidates();
    let abort = desktop
        .abort(
            PairingAbortCode::Timeout,
            Some("desktop cancelled".to_owned()),
        )
        .expect("abort");
    let ended = phone.on_frame(&wire(abort), NOW);
    assert_eq!(
        ended.error,
        PairingError::Aborted(PairingAbortCode::Timeout)
    );
    assert_eq!(ended.result().as_str(), "timeout");
}

#[test]
fn result_words_are_exactly_the_a11_vocabulary() {
    let words: Vec<_> = PairingResult::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(
        words,
        [
            "paired",
            "declined",
            "window_closed",
            "timeout",
            "busy",
            "rate_limited",
            "invalid",
            "identity_changed",
            "failed",
        ]
    );
    // Every abort code reports its own wire name, so the phone never shows a word the desktop
    // did not send.
    for code in [
        PairingAbortCode::WindowClosed,
        PairingAbortCode::Busy,
        PairingAbortCode::RateLimited,
        PairingAbortCode::Timeout,
        PairingAbortCode::Invalid,
        PairingAbortCode::Declined,
        PairingAbortCode::IdentityChanged,
    ] {
        let wire_name = serde_json::to_value(code).expect("json");
        assert_eq!(wire_name, PairingResult::from(code).as_str());
        assert_eq!(
            PairingError::Aborted(code).result(),
            PairingResult::from(code)
        );
    }
    for error in [
        PairingError::BadSignature,
        PairingError::WrongPairingId,
        PairingError::OutOfOrder {
            expected: "a",
            received: "b",
        },
        PairingError::CommitmentMismatch,
        PairingError::Expired,
        PairingError::Declined,
        PairingError::TranscriptMismatch,
        PairingError::OwnKey,
        PairingError::IdentityChanged,
        PairingError::Invalid("x".to_owned()),
    ] {
        assert!(PairingResult::ALL.contains(&error.result()));
        assert_ne!(error.result(), PairingResult::Paired);
    }
}

#[test]
fn resume_from_a_stored_approval_completes_without_a_new_code() {
    let devices = Devices::new();
    let (_phone, approved, paired, _lost) = devices.to_desktop_committed();
    assert_eq!(
        approved.completion_deadline_unix_ms(),
        EXPIRES + PAIRING_RECONCILE_ALLOWANCE_MS
    );

    // A new connection after the original expiry but inside the allowance. The resume API has no
    // candidate state, so no code is derived or shown.
    let late = EXPIRES + 30_000;
    let client_hello = desktop_hello(&devices.desktop, "CEDAR");
    let (desktop, committed) = DesktopPairing::resume(
        devices.desktop.clone(),
        &client_hello,
        &phone_hello(&devices.phone, "Pixel"),
        &paired,
        EXPIRES,
        late,
    )
    .expect("desktop resumes");
    let trust = PhonePairing::resume(
        devices.phone.clone(),
        &client_hello,
        &approved,
        &wire(committed),
        late,
    )
    .expect("phone resumes");
    assert_eq!(trust.peer().device_id, devices.desktop.device_id);
    assert_eq!(trust.peer().public_key, devices.desktop.public_key());
    assert_eq!(trust.peer().transcript_hash, approved.transcript_hash);
    assert_eq!(trust.peer().device_name, "CEDAR");
    let complete = trust.trust_persisted().expect("complete");
    desktop.on_frame(&wire(complete), late).expect("paired");
}

#[test]
fn resume_with_another_key_transcript_pairing_id_or_too_late_is_refused() {
    let devices = Devices::new();
    let (_phone, approved, _paired, _lost) = devices.to_desktop_committed();
    let resume = |hello: &ClientHello, frame: PairingFrame, by: &InstallationIdentity, now| {
        failure(PhonePairing::resume(
            devices.phone.clone(),
            hello,
            &approved,
            &wire(signed(frame, by)),
            now,
        ))
    };
    let committed = |transcript_hash| PairingFrame::DesktopCommitted {
        pairing_id: approved.pairing_id,
        transcript_hash,
    };
    let own_hello = desktop_hello(&devices.desktop, "CEDAR");

    // Another installation replays the approved pairing id and hash under its own key.
    let interposer = InstallationIdentity::generate();
    let refused = resume(
        &desktop_hello(&interposer, "CEDAR"),
        committed(approved.transcript_hash),
        &interposer,
        NOW,
    );
    assert_eq!(refused.error, PairingError::IdentityChanged);
    assert_eq!(refused.result().as_str(), "identity_changed");

    // It replays the real desktop's hello, but cannot sign as the desktop.
    let refused = resume(
        &own_hello,
        committed(approved.transcript_hash),
        &interposer,
        NOW,
    );
    assert_eq!(refused.error, PairingError::BadSignature);

    // The right desktop with a different transcript needs a new code.
    let refused = resume(
        &own_hello,
        committed(TranscriptHash::from_bytes([3; 32])),
        &devices.desktop,
        NOW,
    );
    assert_eq!(refused.error, PairingError::TranscriptMismatch);

    let refused = resume(
        &own_hello,
        PairingFrame::DesktopCommitted {
            pairing_id: PairingId::generate(),
            transcript_hash: approved.transcript_hash,
        },
        &devices.desktop,
        NOW,
    );
    assert_eq!(refused.error, PairingError::WrongPairingId);

    let refused = resume(
        &own_hello,
        committed(approved.transcript_hash),
        &devices.desktop,
        approved.completion_deadline_unix_ms(),
    );
    assert_eq!(refused.error, PairingError::Expired);

    let refused = resume(
        &own_hello,
        PairingFrame::Begin {
            pairing_id: approved.pairing_id,
            commitment: NonceCommitment::from_bytes([1; 32]),
            expires_at_unix_ms: EXPIRES,
        },
        &devices.desktop,
        NOW,
    );
    assert!(matches!(
        refused.error,
        PairingError::OutOfOrder {
            expected: "desktop_committed",
            ..
        }
    ));

    // The desktop's resume also refuses a phone presenting a different key.
    let (_phone, _approved, paired, _lost) = devices.to_desktop_committed();
    let impostor = InstallationIdentity::generate();
    let refused = failure(DesktopPairing::resume(
        devices.desktop.clone(),
        &own_hello,
        &phone_hello(&impostor, "Pixel"),
        &paired,
        EXPIRES,
        NOW,
    ));
    assert_eq!(refused.error, PairingError::IdentityChanged);
}

#[test]
fn confirming_a_transcript_other_than_the_one_shown_is_refused() {
    let devices = Devices::new();
    let (_desktop, phone) = devices.to_candidates();
    let mut other = *phone.candidate().transcript_hash.as_bytes();
    other[0] ^= 1;
    let refused = failure(phone.confirm(&TranscriptHash::from_bytes(other), NOW));
    assert_eq!(refused.error, PairingError::TranscriptMismatch);
    assert_eq!(abort_code(&refused), Some(PairingAbortCode::Invalid));
}

#[test]
fn identifiers_render_and_parse_as_the_lowercase_hex_of_their_json() {
    let devices = Devices::new();
    let (desktop, _phone) = devices.to_candidates();
    let hash = desktop.candidate().transcript_hash;
    let text = hash.to_string();
    assert_eq!(text.len(), 64);
    assert_eq!(serde_json::to_value(hash).expect("json"), text.as_str());
    assert_eq!(text.parse::<TranscriptHash>().expect("parse"), hash);
    assert!(text.to_uppercase().parse::<TranscriptHash>().is_err());

    let pairing_id = devices.pairing_id.to_string();
    assert_eq!(
        pairing_id.parse::<PairingId>().expect("parse"),
        devices.pairing_id
    );
    assert!(pairing_id[..30].parse::<PairingId>().is_err());
}
