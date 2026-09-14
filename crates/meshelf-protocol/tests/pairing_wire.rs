//! `V2Message::Pair` on the wire and the bounded readers a pre-authentication listener uses.

use std::pin::Pin;
use std::task::{Context, Poll};

use meshelf_identity::InstallationIdentity;
use meshelf_protocol::pairing::{
    PAIRING_MAX_FRAME_BYTES, PairingAbortCode, PairingFrame, PairingId, PairingNonce,
    SignedPairingFrame,
};
use meshelf_protocol::{
    CAP_PAIRING_V1, ClientHello, MAX_FRAME_BYTES, ProtocolError, V2_MAX_CONTROL_FRAME_BYTES,
    V2_MAX_STATUS_DETAIL_BYTES, V2Message, WireMessage, encode_v2_frame, read_client_hello_async,
    read_client_hello_async_limited, read_v2_frame_async, read_v2_frame_async_limited,
    validate_v2_message, write_frame_async,
};
use tokio::io::{AsyncRead, ReadBuf};

/// Serves a four-byte length prefix and records every later read the decoder attempts, so a test
/// can show the payload was never requested (and so never allocated for) after a refused prefix.
struct PrefixThenRecord {
    prefix: [u8; 4],
    served: usize,
    payload_read_sizes: Vec<usize>,
}

impl PrefixThenRecord {
    fn new(declared_length: u32) -> Self {
        Self {
            prefix: declared_length.to_be_bytes(),
            served: 0,
            payload_read_sizes: Vec::new(),
        }
    }
}

impl AsyncRead for PrefixThenRecord {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.served < self.prefix.len() {
            let take = buf.remaining().min(self.prefix.len() - self.served);
            let start = self.served;
            buf.put_slice(&self.prefix[start..start + take]);
            self.served += take;
        } else {
            let requested = buf.remaining();
            self.payload_read_sizes.push(requested);
        }
        Poll::Ready(Ok(()))
    }
}

async fn v2_limited(declared: u32, max: usize) -> (Result<V2Message, ProtocolError>, Vec<usize>) {
    let mut reader = PrefixThenRecord::new(declared);
    let result = read_v2_frame_async_limited(&mut reader, max).await;
    (result, reader.payload_read_sizes)
}

async fn hello_limited(
    declared: u32,
    max: usize,
) -> (Result<ClientHello, ProtocolError>, Vec<usize>) {
    let mut reader = PrefixThenRecord::new(declared);
    let result = read_client_hello_async_limited(&mut reader, max).await;
    (result, reader.payload_read_sizes)
}

fn too_large(result: &Result<impl std::fmt::Debug, ProtocolError>, bytes: usize, maximum: usize) {
    match result {
        Err(ProtocolError::FrameTooLarge {
            bytes: got,
            maximum: bound,
        }) => assert_eq!((*got, *bound), (bytes, maximum)),
        other => panic!("expected FrameTooLarge {{ {bytes}, {maximum} }}, got {other:?}"),
    }
}

/// The phone listener reads pre-authentication frames with small bounds; a peer declaring a huge
/// frame must cost nothing beyond the four prefix bytes.
#[tokio::test]
async fn limited_readers_refuse_an_over_limit_prefix_before_requesting_the_payload() {
    for declared in [4_097_u32, u32::MAX] {
        let (result, reads) = v2_limited(declared, PAIRING_MAX_FRAME_BYTES).await;
        too_large(&result, declared as usize, PAIRING_MAX_FRAME_BYTES);
        assert!(reads.is_empty(), "payload was requested: {reads:?}");
    }
    for declared in [8_193_u32, u32::MAX] {
        let (result, reads) = hello_limited(declared, 8 * 1024).await;
        too_large(&result, declared as usize, 8 * 1024);
        assert!(reads.is_empty(), "payload was requested: {reads:?}");
    }

    // At exactly the bound the reader goes on to request the payload (and here hits EOF).
    let (_result, reads) = v2_limited(4_096, PAIRING_MAX_FRAME_BYTES).await;
    assert_eq!(reads.first(), Some(&4_096));
    let (_result, reads) = hello_limited(8_192, 8 * 1024).await;
    assert_eq!(reads.first(), Some(&8_192));

    assert!(matches!(
        v2_limited(0, PAIRING_MAX_FRAME_BYTES).await.0,
        Err(ProtocolError::EmptyFrame)
    ));
}

/// Callers that pass a larger bound still never exceed the crate's own frame bounds, and the
/// existing readers keep exactly their previous limits.
#[tokio::test]
async fn limits_are_clamped_to_the_crate_bounds_and_existing_readers_are_unchanged() {
    let over_v2 = (V2_MAX_CONTROL_FRAME_BYTES + 1) as u32;
    let (result, reads) = v2_limited(over_v2, usize::MAX).await;
    too_large(&result, over_v2 as usize, V2_MAX_CONTROL_FRAME_BYTES);
    assert!(reads.is_empty());

    let over_hello = (MAX_FRAME_BYTES + 1) as u32;
    let (result, reads) = hello_limited(over_hello, usize::MAX).await;
    too_large(&result, over_hello as usize, MAX_FRAME_BYTES);
    assert!(reads.is_empty());

    let mut reader = PrefixThenRecord::new(over_v2);
    too_large(
        &read_v2_frame_async(&mut reader).await,
        over_v2 as usize,
        V2_MAX_CONTROL_FRAME_BYTES,
    );
    let mut reader = PrefixThenRecord::new(V2_MAX_CONTROL_FRAME_BYTES as u32);
    let _ = read_v2_frame_async(&mut reader).await;
    assert_eq!(
        reader.payload_read_sizes.first(),
        Some(&V2_MAX_CONTROL_FRAME_BYTES)
    );

    let mut reader = PrefixThenRecord::new(over_hello);
    too_large(
        &read_client_hello_async(&mut reader).await,
        over_hello as usize,
        MAX_FRAME_BYTES,
    );
    let mut reader = PrefixThenRecord::new(MAX_FRAME_BYTES as u32);
    let _ = read_client_hello_async(&mut reader).await;
    assert_eq!(reader.payload_read_sizes.first(), Some(&MAX_FRAME_BYTES));
}

#[tokio::test]
async fn a_signed_pairing_hello_and_every_pairing_frame_read_back_under_their_small_bounds() {
    let identity = InstallationIdentity::generate();
    let hello = ClientHello::signed_v2_with_capabilities(
        identity.device_id,
        "CEDAR",
        "hello-nonce",
        vec![CAP_PAIRING_V1.to_owned()],
        &identity,
    );
    let (mut left, mut right) = tokio::io::duplex(64 * 1024);
    write_frame_async(&mut left, &WireMessage::ClientHello(hello.clone()))
        .await
        .expect("write hello");
    let read = read_client_hello_async_limited(&mut right, 8 * 1024)
        .await
        .expect("a pairing hello fits the phone's 8 KiB bound");
    assert_eq!(read, hello);
    assert!(read.has_valid_signature());

    let frame = SignedPairingFrame::sign(
        PairingFrame::Reveal {
            pairing_id: PairingId::generate(),
            nonce: PairingNonce::generate(),
        },
        &identity,
    )
    .expect("sign");
    let message = V2Message::Pair(frame);
    let bytes = encode_v2_frame(&message).expect("encode");
    tokio::io::AsyncWriteExt::write_all(&mut left, &bytes)
        .await
        .expect("write");
    let read = read_v2_frame_async_limited(&mut right, PAIRING_MAX_FRAME_BYTES)
        .await
        .expect("read");
    assert_eq!(read, message);
    validate_v2_message(&read).expect("valid");
}

fn worst_case_abort(identity: &InstallationIdentity) -> SignedPairingFrame {
    let mut signed = SignedPairingFrame::sign(
        PairingFrame::Abort {
            pairing_id: PairingId::from_bytes([0xff; 16]),
            code: PairingAbortCode::IdentityChanged,
            detail: Some("\u{1}".repeat(V2_MAX_STATUS_DETAIL_BYTES)),
        },
        identity,
    )
    .expect("sign");
    signed.signature = vec![0xff; 64];
    signed
}

/// A2: the 4 KiB bound is measured on the frame as it travels, inside its `V2Message` tag. A frame
/// that fits the bare `SignedPairingFrame` bound but not once wrapped is refused on every path,
/// while the largest legitimate frame still fits wrapped.
#[tokio::test]
async fn pairing_bound_applies_to_the_v2_message_encoding() {
    let identity = InstallationIdentity::generate();
    let largest_legitimate = V2Message::Pair(worst_case_abort(&identity));
    let wrapped = serde_json::to_vec(&largest_legitimate).expect("json").len();
    assert!(wrapped <= PAIRING_MAX_FRAME_BYTES, "{wrapped}");
    validate_v2_message(&largest_legitimate).expect("the largest valid abort fits wrapped");

    // Grow the (unchecked-length) signature until the bare frame fits 4 KiB but the wrapped one
    // does not. Each extra zero byte adds two JSON bytes, finer than the ~22-byte tag overhead.
    let mut signed = SignedPairingFrame::sign(
        PairingFrame::Reveal {
            pairing_id: PairingId::generate(),
            nonce: PairingNonce::generate(),
        },
        &identity,
    )
    .expect("sign");
    signed.signature.clear();
    let (bare, wrapped) = loop {
        signed.signature.push(0);
        let bare = serde_json::to_vec(&signed).expect("json").len();
        let wrapped = serde_json::to_vec(&V2Message::Pair(signed.clone()))
            .expect("json")
            .len();
        if wrapped > PAIRING_MAX_FRAME_BYTES {
            break (bare, wrapped);
        }
    };
    assert!(bare <= PAIRING_MAX_FRAME_BYTES, "bare {bare}");
    signed
        .encode()
        .expect("the bare frame is within its own bound");

    let message = V2Message::Pair(signed);
    too_large(
        &validate_v2_message(&message),
        wrapped,
        PAIRING_MAX_FRAME_BYTES,
    );
    too_large(&encode_v2_frame(&message), wrapped, PAIRING_MAX_FRAME_BYTES);

    // A peer that sends it anyway is refused by the pairing reader before the payload is read.
    let payload = serde_json::to_vec(&message).expect("json");
    let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&payload);
    too_large(
        &read_v2_frame_async_limited(&mut bytes.as_slice(), PAIRING_MAX_FRAME_BYTES).await,
        wrapped,
        PAIRING_MAX_FRAME_BYTES,
    );
}

#[test]
fn pair_variant_is_tagged_pair_and_invalid_frames_are_refused() {
    let identity = InstallationIdentity::generate();
    let pairing_id = PairingId::from_bytes([0xa0; 16]);
    let message = V2Message::Pair(
        SignedPairingFrame::sign(
            PairingFrame::Abort {
                pairing_id,
                code: PairingAbortCode::Busy,
                detail: None,
            },
            &identity,
        )
        .expect("sign"),
    );
    let json = serde_json::to_string(&message).expect("json");
    assert!(
        json.starts_with(&format!(
            r#"{{"type":"pair","body":{{"frame":{{"type":"abort","body":{{"pairing_id":"{}","#,
            "a0".repeat(16)
        )),
        "{json}"
    );

    // A frame no honest signer would produce (all-zero pairing id) is refused at validation.
    let forged = V2Message::Pair(SignedPairingFrame {
        frame: PairingFrame::Abort {
            pairing_id: PairingId::from_bytes([0; 16]),
            code: PairingAbortCode::Busy,
            detail: None,
        },
        signature: vec![1; 64],
    });
    assert!(matches!(
        validate_v2_message(&forged),
        Err(ProtocolError::V2Validation { .. })
    ));
    assert!(encode_v2_frame(&forged).is_err());
}
