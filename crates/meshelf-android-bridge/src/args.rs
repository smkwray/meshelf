//! Validation of every argument Kotlin passes to a native. Kotlin validates first; Rust is
//! authoritative and refuses with `IllegalArgumentException` rather than trusting the caller.

use std::{fmt, fs, net::Ipv4Addr, path::PathBuf, str::FromStr};

use meshelf_core::{CaptureRequestId, DeviceId, OfferId, validate_capture_label};
use meshelf_protocol::pairing::{PairingId, TranscriptHash};
use serde::de::{DeserializeOwned, IntoDeserializer, value::Error as ValueError};

use crate::{NativeError, invalid};

/// `RequestText.MAX_DEVICE_NAME_UTF8_BYTES` in the Android client.
pub const MAX_DEVICE_NAME_BYTES: usize = 80;
/// Work order 09 decision 12; Kotlin `MeshelfNative.PAIRING_WINDOW_MS`.
pub const PAIRING_WINDOW_MAX_MS: u64 = 120_000;

/// Android's `Network.getNetworkHandle()`. It lives only in memory, is never persisted, and its
/// `Debug` form never prints the value.
pub struct NetworkHandle(u64);

impl NetworkHandle {
    pub fn new(raw: i64) -> Result<Self, NativeError> {
        if raw == 0 {
            return Err(invalid("network handle must be non-zero"));
        }
        // `net_handle_t` is an opaque `uint64_t`; Kotlin carries it in a signed Long.
        Ok(Self(raw.cast_unsigned()))
    }

    #[must_use]
    pub const fn get(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for NetworkHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkHandle(<redacted>)")
    }
}

/// `nativeStart(stateDir, localAddress, networkHandle, deviceName)`.
#[derive(Debug)]
pub struct StartArgs {
    pub state_dir: PathBuf,
    pub local_address: Ipv4Addr,
    pub network: NetworkHandle,
    pub device_name: String,
}

impl StartArgs {
    pub fn parse(
        state_dir: &str,
        local_address: &str,
        network_handle: i64,
        device_name: &str,
    ) -> Result<Self, NativeError> {
        let state_dir = PathBuf::from(state_dir);
        if !state_dir.is_absolute() {
            return Err(invalid("state directory must be an absolute path"));
        }
        match fs::metadata(&state_dir) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(invalid("state directory is not a directory")),
            Err(error) => return Err(invalid(format!("state directory is unavailable: {error}"))),
        }
        let local_address = parse_tailscale_ipv4(local_address)?;
        let network = NetworkHandle::new(network_handle)?;
        validate_device_name(device_name).map_err(invalid)?;
        Ok(Self {
            state_dir,
            local_address,
            network,
            device_name: device_name.to_owned(),
        })
    }
}

/// True for the Tailscale CGNAT range `100.64.0.0/10`, the only addresses the phone binds.
#[must_use]
pub fn is_tailscale_cgnat(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    first == 100 && (second & 0b1100_0000) == 0b0100_0000
}

pub fn parse_tailscale_ipv4(text: &str) -> Result<Ipv4Addr, NativeError> {
    let address =
        Ipv4Addr::from_str(text).map_err(|_| invalid("local address must be an IPv4 literal"))?;
    if !is_tailscale_cgnat(address) {
        return Err(invalid(
            "local address must be a Tailscale address inside 100.64.0.0/10",
        ));
    }
    Ok(address)
}

/// Non-empty plain text of at most [`MAX_DEVICE_NAME_BYTES`], under core's Cc and Cf rule.
pub fn validate_device_name(name: &str) -> Result<(), String> {
    if name.len() > MAX_DEVICE_NAME_BYTES {
        return Err(format!(
            "device name is {} UTF-8 bytes; maximum is {MAX_DEVICE_NAME_BYTES}",
            name.len()
        ));
    }
    validate_capture_label(name).map_err(|error| format!("device name {error}"))
}

/// A request id exactly as Rust rendered it in `onCaptureRequested`.
pub fn parse_request_id(text: &str) -> Result<CaptureRequestId, NativeError> {
    CaptureRequestId::from_str(text)
        .ok()
        .filter(|id| id.to_string() == text)
        .ok_or_else(|| invalid("request id is not a canonical capture request id"))
}

/// A device id exactly as Rust rendered it in shelf metadata.
pub fn parse_device_id(text: &str) -> Result<DeviceId, NativeError> {
    DeviceId::from_str(text)
        .ok()
        .filter(|id| id.to_string() == text)
        .ok_or_else(|| invalid("source device id is not a canonical device id"))
}

/// An offer id exactly as Rust rendered it in shelf metadata.
pub fn parse_offer_id(text: &str) -> Result<OfferId, NativeError> {
    OfferId::from_str(text)
        .ok()
        .filter(|id| id.to_string() == text)
        .ok_or_else(|| invalid("offer id is not a canonical offer id"))
}

/// `nativeCaptureCaptured(requestId, path, sha256, width, height)`. File checks (canonical path,
/// regular file, re-hash) belong to the resident, which acts on the file under its own lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFile {
    pub request_id: CaptureRequestId,
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub width: u32,
    pub height: u32,
}

impl CapturedFile {
    pub fn parse(
        request_id: &str,
        path: &str,
        sha256: &str,
        width: i32,
        height: i32,
    ) -> Result<Self, NativeError> {
        let request_id = parse_request_id(request_id)?;
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(invalid("capture path must be absolute"));
        }
        let sha256 = decode_lower_hex::<32>(sha256)
            .ok_or_else(|| invalid("sha256 must be 64 lowercase hexadecimal characters"))?;
        let dimension = |value: i32, label: &str| {
            u32::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| invalid(format!("{label} must be positive")))
        };
        Ok(Self {
            request_id,
            path,
            sha256,
            width: dimension(width, "width")?,
            height: dimension(height, "height")?,
        })
    }
}

/// Exactly the reasons the Android client sends to `nativeCaptureDeclined`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclineReason {
    UserDeclined,
    CameraPermissionDenied,
    AvailabilityDisabled,
    NotificationsDisabled,
    ServiceStopped,
    RouteUnavailable,
    Busy,
    Expired,
    Refused,
}

impl DeclineReason {
    pub const ALL: [Self; 9] = [
        Self::UserDeclined,
        Self::CameraPermissionDenied,
        Self::AvailabilityDisabled,
        Self::NotificationsDisabled,
        Self::ServiceStopped,
        Self::RouteUnavailable,
        Self::Busy,
        Self::Expired,
        Self::Refused,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDeclined => "user-declined",
            Self::CameraPermissionDenied => "camera-permission-denied",
            Self::AvailabilityDisabled => "availability-disabled",
            Self::NotificationsDisabled => "notifications-disabled",
            Self::ServiceStopped => "service-stopped",
            Self::RouteUnavailable => "route-unavailable",
            Self::Busy => "busy",
            Self::Expired => "expired",
            Self::Refused => "refused",
        }
    }

    pub fn parse(text: &str) -> Result<Self, NativeError> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == text)
            .ok_or_else(|| invalid("unknown capture decline reason"))
    }
}

/// `nativeOpenPairingWindow(expiresAtMs)` requires `now < expiresAtMs <= now + 120 s`.
pub fn pairing_window_deadline(now_unix_ms: u64, expires_at_ms: i64) -> Result<u64, NativeError> {
    u64::try_from(expires_at_ms)
        .ok()
        .filter(|expires| *expires > now_unix_ms && *expires - now_unix_ms <= PAIRING_WINDOW_MAX_MS)
        .ok_or_else(|| invalid("pairing window must end within 120 seconds from now"))
}

pub fn parse_pairing_id(text: &str) -> Result<PairingId, NativeError> {
    from_protocol_hex(
        text,
        "pairing id must be 32 lowercase hexadecimal characters",
    )
}

pub fn parse_transcript_hash(text: &str) -> Result<TranscriptHash, NativeError> {
    from_protocol_hex(
        text,
        "transcript hash must be 64 lowercase hexadecimal characters",
    )
}

/// Parses with the protocol's own wire encoding, so the bridge never has a second hex rule for
/// pairing values.
fn from_protocol_hex<T: DeserializeOwned>(text: &str, refusal: &str) -> Result<T, NativeError> {
    T::deserialize(IntoDeserializer::<ValueError>::into_deserializer(text))
        .map_err(|_| invalid(refusal))
}

fn decode_lower_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = text.as_bytes();
    if raw.len() != N * 2 {
        return None;
    }
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut bytes = [0_u8; N];
    for (slot, pair) in bytes.iter_mut().zip(raw.chunks_exact(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = env!("CARGO_MANIFEST_DIR");
    const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    const ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn is_invalid<T: fmt::Debug>(result: Result<T, NativeError>) -> bool {
        matches!(result, Err(NativeError::InvalidArgument(_)))
    }

    #[test]
    fn start_accepts_valid_arguments() {
        let args = StartArgs::parse(DIR, "100.64.1.50", -7, "Owner's Pixel").expect("valid");
        assert_eq!(args.local_address, Ipv4Addr::new(100, 64, 1, 50));
        assert_eq!(args.network.get(), (-7_i64).cast_unsigned());
        assert_eq!(format!("{:?}", args.network), "NetworkHandle(<redacted>)");
    }

    #[test]
    fn start_refuses_each_bad_field() {
        assert!(is_invalid(StartArgs::parse(
            "relative/dir",
            "100.64.0.1",
            1,
            "p"
        )));
        assert!(is_invalid(StartArgs::parse(FILE, "100.64.0.1", 1, "p")));
        assert!(is_invalid(StartArgs::parse(
            "/nonexistent/meshelf-state",
            "100.64.0.1",
            1,
            "p"
        )));
        // A listener must never bind a wildcard, loopback, LAN, or non-Tailscale address.
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.20",
            "100.63.255.255",
            "100.128.0.0",
            "fd7a:115c:a1e0::9",
            "100.64.0.1 ",
            "",
        ] {
            assert!(
                is_invalid(StartArgs::parse(DIR, address, 1, "p")),
                "{address}"
            );
        }
        assert!(StartArgs::parse(DIR, "100.64.0.0", 1, "p").is_ok());
        assert!(StartArgs::parse(DIR, "100.127.255.255", 1, "p").is_ok());
        assert!(is_invalid(StartArgs::parse(DIR, "100.64.0.1", 0, "p")));
        for name in ["", "a\nb", "\u{202e}evil", &"x".repeat(81)] {
            assert!(is_invalid(StartArgs::parse(DIR, "100.64.0.1", 1, name)));
        }
        assert!(StartArgs::parse(DIR, "100.64.0.1", 1, &"x".repeat(80)).is_ok());
    }

    #[test]
    fn start_refusal_never_echoes_the_network_handle() {
        let Err(error) = StartArgs::parse(DIR, "10.0.0.1", 0x5eed_1234_abcd, "p") else {
            panic!("must refuse");
        };
        assert!(
            !error
                .to_string()
                .contains(&0x5eed_1234_abcd_i64.to_string())
        );
    }

    /// Absolute on the host running the tests; `/data/...` is not absolute on Windows.
    const CAPTURED_JPEG: &str = if cfg!(windows) {
        r"C:\data\cache\a.jpg"
    } else {
        "/data/cache/a.jpg"
    };

    #[test]
    fn captured_accepts_valid_and_refuses_each_bad_field() {
        let file = CapturedFile::parse(ID, CAPTURED_JPEG, SHA, 4032, 3024).expect("valid");
        assert_eq!(file.request_id.to_string(), ID);
        assert_eq!(file.sha256[0], 0x9f);
        assert_eq!((file.width, file.height), (4032, 3024));
        // Kotlin echoes exactly the id Rust sent; any other rendering signals a bug.
        assert!(is_invalid(CapturedFile::parse(
            &ID.to_uppercase(),
            "/a",
            SHA,
            1,
            1
        )));
        assert!(is_invalid(CapturedFile::parse(
            "not-an-id",
            "/a",
            SHA,
            1,
            1
        )));
        assert!(is_invalid(CapturedFile::parse(
            ID,
            "relative.jpg",
            SHA,
            1,
            1
        )));
        assert!(is_invalid(CapturedFile::parse(
            ID,
            "/a",
            &SHA.to_uppercase(),
            1,
            1
        )));
        assert!(is_invalid(CapturedFile::parse(ID, "/a", &SHA[1..], 1, 1)));
        assert!(is_invalid(CapturedFile::parse(ID, "/a", SHA, 0, 1)));
        assert!(is_invalid(CapturedFile::parse(ID, "/a", SHA, 1, -1)));
    }

    #[test]
    fn decline_reasons_are_exactly_the_kotlin_words() {
        let kotlin = [
            "user-declined",
            "camera-permission-denied",
            "availability-disabled",
            "notifications-disabled",
            "service-stopped",
            "route-unavailable",
            "busy",
            "expired",
            "refused",
        ];
        for word in kotlin {
            assert_eq!(DeclineReason::parse(word).expect(word).as_str(), word);
        }
        assert_eq!(DeclineReason::ALL.len(), kotlin.len());
        for word in ["declined", "USER-DECLINED", "busy ", "", "cancelled"] {
            assert!(is_invalid(DeclineReason::parse(word)), "{word}");
        }
        assert!(is_invalid(parse_request_id("")));
    }

    #[test]
    fn pairing_window_must_end_in_the_next_120_seconds() {
        let now = 1_700_000_000_000;
        let at = |offset: i64| pairing_window_deadline(now, now.cast_signed() + offset);
        assert!(is_invalid(at(0)));
        assert!(is_invalid(at(-1)));
        assert_eq!(at(1).expect("1 ms"), now + 1);
        assert_eq!(at(120_000).expect("120 s"), now + 120_000);
        assert!(is_invalid(at(120_001)));
        assert!(is_invalid(pairing_window_deadline(now, -5)));
    }

    #[test]
    fn pairing_values_use_the_protocol_lowercase_hex() {
        let id = "00112233445566778899aabbccddeeff";
        assert_eq!(parse_pairing_id(id).expect("id").as_bytes()[15], 0xff);
        assert!(is_invalid(parse_pairing_id(&id.to_uppercase())));
        assert!(is_invalid(parse_pairing_id(&id[2..])));
        let hash = SHA;
        assert_eq!(
            parse_transcript_hash(hash).expect("hash").as_bytes()[0],
            0x9f
        );
        assert!(is_invalid(parse_transcript_hash(id)));
        assert!(is_invalid(parse_transcript_hash(&hash.to_uppercase())));
    }
}
