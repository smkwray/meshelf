//! Agent-requested photo capture over the existing offer-and-pull lane.
//!
//! A capture is not a shelf item. On the requester, a correlated announcement is routed here
//! before the shelf is read or written; it claims the request's pull grant in one transaction and
//! starts exactly one automatic pull, which lands at the exact output path or nowhere. On the
//! phone, a request is recorded before it is acknowledged, a photo is served at most once and only
//! to the device that asked for it, and it is reported delivered only after a validated completed
//! receipt, which is what allows the phone to delete it.

use std::{
    io::Read,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use meshelf_core::{
    ActivationId, CaptureCorrelation, CaptureRequestId, CaptureRequestPhase, CaptureRequestRecord,
    CaptureSourcePhase, CaptureSourceRecord, CaptureSourceTerminalCode, CaptureTerminalCode,
    DeviceId, MAX_CAPTURE_DETAIL_BYTES, MAX_CAPTURE_LABEL_BYTES, OfferId, StoreError,
    validate_capture_label,
};
use meshelf_protocol::{
    CaptureAck, CaptureAckCode, CaptureRequest, CaptureStatus, CaptureStatusCode, ClientHello,
    FetchRequest, OfferAnnouncement,
};
use meshelf_store::{
    CaptureGrantClaim, CapturePresentation, CaptureSourceClaim, CaptureTransition,
    ClaimedCapturePull, RedbV2Store,
};
use tokio::sync::watch;

use crate::{
    ActivationFailCode, ActivationOutcome, ActivationRefuseCode, ActivationService,
    FetchActivation, FetchClipboard, FetchSourceResolver, FetchableSource, NetError, PeerClient,
    destination::truncate_utf8,
};

fn unix_now_ms() -> Result<u64, NetError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NetError::FetchService("system clock is before the Unix epoch"))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| NetError::FetchService("system clock is out of range"))
}

fn storage(error: StoreError) -> NetError {
    NetError::OfferStorage(error.to_string())
}

fn bounded_detail(detail: &str) -> String {
    truncate_utf8(detail, MAX_CAPTURE_DETAIL_BYTES).to_owned()
}

// ---------------------------------------------------------------------------------------------
// Capture control receivers

#[async_trait]
pub trait V2CaptureReceiver: Send + Sync + 'static {
    async fn handle_capture_request(
        &self,
        authenticated_source: DeviceId,
        requester_name: &str,
        listener_device: DeviceId,
        request: CaptureRequest,
    ) -> Result<CaptureAck, NetError>;

    /// Acknowledging a status is a promise that it was durably recorded; an implementation that
    /// cannot record it returns an error so that no acknowledgement is sent.
    async fn handle_capture_status(
        &self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        status: CaptureStatus,
    ) -> Result<CaptureStatus, NetError>;
}

#[derive(Debug, Default)]
pub struct UnsupportedCaptureReceiver;

#[async_trait]
impl V2CaptureReceiver for UnsupportedCaptureReceiver {
    async fn handle_capture_request(
        &self,
        _authenticated_source: DeviceId,
        _requester_name: &str,
        _listener_device: DeviceId,
        request: CaptureRequest,
    ) -> Result<CaptureAck, NetError> {
        Ok(unsupported_capture_ack(&request))
    }

    /// This receiver records nothing, so it refuses rather than echo the status back.
    async fn handle_capture_status(
        &self,
        _authenticated_source: DeviceId,
        _listener_device: DeviceId,
        _status: CaptureStatus,
    ) -> Result<CaptureStatus, NetError> {
        Err(NetError::Rejected(
            "capture status refused: this listener keeps no capture request to record it"
                .to_owned(),
        ))
    }
}

fn unsupported_capture_ack(request: &CaptureRequest) -> CaptureAck {
    CaptureAck {
        request_id: request.request_id,
        code: CaptureAckCode::Unsupported,
        detail: Some("photo capture is not supported by this desktop peer".to_owned()),
    }
}

// ---------------------------------------------------------------------------------------------
// Requester side

/// How a correlated announcement was disposed of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRoute {
    /// Durably attached to its capture request and the automatic pull launched. Acknowledged as
    /// `Stored`, which for a capture never means the shelf.
    Attached,
    /// This same offer already claimed the request; nothing changed.
    Duplicate,
    /// Refused with a stable detail word. Nothing changed, except that a claim whose launch
    /// failed has ended the request.
    Refused(&'static str),
}

/// Routes correlated announcements to capture requests, before the shelf is touched.
pub trait CaptureAnnouncementRouter: Send + Sync + 'static {
    fn route(
        &self,
        authenticated_source: DeviceId,
        announcement: &OfferAnnouncement,
        correlation: CaptureCorrelation,
    ) -> Result<CaptureRoute, NetError>;
}

/// Why a won claim's pull could not be started; the request ends with `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureLaunchRefused {
    pub code: CaptureTerminalCode,
    pub detail: Option<String>,
}

/// Starts the automatic pull for a claim this device just won. Implemented by the resident,
/// which alone can resolve the phone's address and pinned key; it builds the hello and hands
/// [`run_capture_pull`] to a task.
pub trait CapturePullLauncher: Send + Sync + 'static {
    /// Called on the announcement connection, so it must return at once. Exactly one call is
    /// made per request, because only one announcement can win the claim. An error ends the
    /// request with the given code; a claim is never re-armed.
    fn launch(&self, pull: ClaimedCapturePull) -> Result<(), CaptureLaunchRefused>;
}

/// Told when a request reaches its outcome through the network rather than through the pull the
/// resident launched: a recorded status from the phone, or a launch that could not start. The row
/// is durable before this is called; the resident wakes the request's waiter.
pub trait CaptureRequestEvents: Send + Sync + 'static {
    fn capture_finished(&self, record: &CaptureRequestRecord);
}

/// The requester's router: a correlated announcement claims its request's pull grant in one
/// transaction, so exactly one announcement can ever start a pull.
pub struct RequesterCaptureRouter {
    store: Arc<RedbV2Store>,
    launcher: Arc<dyn CapturePullLauncher>,
    events: Arc<dyn CaptureRequestEvents>,
}

impl RequesterCaptureRouter {
    #[must_use]
    pub fn new(
        store: Arc<RedbV2Store>,
        launcher: Arc<dyn CapturePullLauncher>,
        events: Arc<dyn CaptureRequestEvents>,
    ) -> Self {
        Self {
            store,
            launcher,
            events,
        }
    }
}

impl CaptureAnnouncementRouter for RequesterCaptureRouter {
    fn route(
        &self,
        authenticated_source: DeviceId,
        announcement: &OfferAnnouncement,
        correlation: CaptureCorrelation,
    ) -> Result<CaptureRoute, NetError> {
        let claim = self
            .store
            .claim_capture_grant(
                correlation.request_id,
                authenticated_source,
                announcement.offer_id,
                ActivationId::new(),
                announcement.descriptor.clone(),
                unix_now_ms()?,
            )
            .map_err(storage)?;
        Ok(match claim {
            CaptureGrantClaim::Claimed(pull) => {
                let request_id = pull.request_id;
                match self.launcher.launch(pull) {
                    Ok(()) => CaptureRoute::Attached,
                    Err(refused) => {
                        let detail = refused.detail.as_deref().map(bounded_detail);
                        if let CaptureTransition::Applied(record) = self
                            .store
                            .terminate_capture(request_id, refused.code, detail)
                            .map_err(storage)?
                        {
                            self.events.capture_finished(&record);
                        }
                        CaptureRoute::Refused("capture_launch_failed")
                    }
                }
            }
            CaptureGrantClaim::AlreadyClaimed { offer_id, .. }
                if offer_id == announcement.offer_id =>
            {
                CaptureRoute::Duplicate
            }
            CaptureGrantClaim::AlreadyClaimed { .. } => {
                CaptureRoute::Refused("capture_already_claimed")
            }
            CaptureGrantClaim::NotArmed => CaptureRoute::Refused("capture_not_armed"),
            CaptureGrantClaim::WrongSource => CaptureRoute::Refused("capture_wrong_source"),
            CaptureGrantClaim::Expired => CaptureRoute::Refused("capture_expired"),
            CaptureGrantClaim::NotSingleFile => CaptureRoute::Refused("capture_not_single_file"),
            CaptureGrantClaim::TooLarge => CaptureRoute::Refused("capture_too_large"),
            CaptureGrantClaim::Unknown => CaptureRoute::Refused("capture_unknown_request"),
        })
    }
}

/// Runs one automatic capture pull through the activation service, so it consumes one of the
/// two activation permits exactly like a user activation. With both permits in use it ends
/// `RequesterBusy` at once: no queue, no retry, and no staging.
///
/// `hello` is this device's signed protocol-2 hello; `address` and the key are the phone's.
/// Returns the request's final row, which is the authority for what the agent is told. An error
/// means the row could not be read or written; startup reconciliation then ends a still-claimed
/// row as uncertain.
#[allow(clippy::too_many_arguments)]
pub async fn run_capture_pull<C>(
    activations: &ActivationService<C>,
    client: &PeerClient,
    address: SocketAddr,
    hello: ClientHello,
    expected_server_public_key: &[u8],
    pull: &ClaimedCapturePull,
    cancel: watch::Receiver<bool>,
) -> Result<CaptureRequestRecord, NetError>
where
    C: FetchClipboard,
{
    let request = FetchRequest {
        request_id: pull.activation_id,
        offer_id: pull.offer_id,
        source_device: pull.source,
        requester_device: hello.device_id,
    };
    let outcome = activations
        .activate(
            client,
            address,
            hello,
            request,
            FetchActivation::capture(pull),
            expected_server_public_key,
            cancel,
        )
        .await;
    let store = activations.store();
    let record = store
        .get_capture_request(pull.request_id)
        .map_err(storage)?
        .ok_or_else(|| {
            NetError::FetchServiceOwned(
                "capture request row disappeared during its pull".to_owned(),
            )
        })?;
    let still_claimed = matches!(
        record.phase,
        CaptureRequestPhase::Claimed { activation_id, .. } if activation_id == pull.activation_id
    );
    if !still_claimed {
        // The receiver recorded completion or a precise failure, or the request was ended
        // elsewhere (a cancel); that first outcome stands.
        return Ok(record);
    }
    let (code, detail) = match &outcome {
        Ok(outcome) => (pull_outcome_code(*outcome), outcome.desktop_status()),
        Err(error) => (CaptureTerminalCode::TransferFailed, error.to_string()),
    };
    match store
        .terminate_capture(pull.request_id, code, Some(bounded_detail(&detail)))
        .map_err(storage)?
    {
        CaptureTransition::Applied(record)
        | CaptureTransition::Unchanged(record)
        | CaptureTransition::Refused(record) => Ok(record),
        CaptureTransition::Unknown => Err(NetError::FetchServiceOwned(
            "capture request row disappeared during its pull".to_owned(),
        )),
    }
}

/// The outcome of a pull that ended before the receiver ran, or without the receiver recording a
/// more precise one.
fn pull_outcome_code(outcome: ActivationOutcome) -> CaptureTerminalCode {
    match outcome {
        // Both activation permits were in use: refused, never queued.
        ActivationOutcome::Refused(ActivationRefuseCode::Busy) => {
            CaptureTerminalCode::RequesterBusy
        }
        ActivationOutcome::Refused(ActivationRefuseCode::InsufficientSpace) => {
            CaptureTerminalCode::InsufficientSpace
        }
        ActivationOutcome::Failed(ActivationFailCode::VerificationFailed) => {
            CaptureTerminalCode::VerificationFailed
        }
        ActivationOutcome::Cancelled => CaptureTerminalCode::Cancelled,
        // A completed receipt is sent only after completion is recorded, so a claim still open
        // here cannot be proven either way.
        ActivationOutcome::Completed | ActivationOutcome::UncertainNoReplay => {
            CaptureTerminalCode::UncertainNoReplay
        }
        ActivationOutcome::Refused(_) | ActivationOutcome::Failed(_) => {
            CaptureTerminalCode::TransferFailed
        }
    }
}

/// The requester's capture listener. It fulfils no capture requests, and it records a phone's
/// status durably before acknowledging it.
pub struct RequesterCaptureReceiver {
    store: Arc<RedbV2Store>,
    events: Arc<dyn CaptureRequestEvents>,
}

impl RequesterCaptureReceiver {
    #[must_use]
    pub fn new(store: Arc<RedbV2Store>, events: Arc<dyn CaptureRequestEvents>) -> Self {
        Self { store, events }
    }
}

#[async_trait]
impl V2CaptureReceiver for RequesterCaptureReceiver {
    async fn handle_capture_request(
        &self,
        _authenticated_source: DeviceId,
        _requester_name: &str,
        _listener_device: DeviceId,
        request: CaptureRequest,
    ) -> Result<CaptureAck, NetError> {
        Ok(unsupported_capture_ack(&request))
    }

    async fn handle_capture_status(
        &self,
        authenticated_source: DeviceId,
        _listener_device: DeviceId,
        status: CaptureStatus,
    ) -> Result<CaptureStatus, NetError> {
        let Some(record) = self
            .store
            .get_capture_request(status.request_id)
            .map_err(storage)?
        else {
            return Err(NetError::Rejected(
                "capture status names no request on this device".to_owned(),
            ));
        };
        if record.peer != authenticated_source {
            return Err(NetError::IdentityMismatch(
                "capture status sender is not the requested peer".to_owned(),
            ));
        }
        let code = match status.code {
            CaptureStatusCode::Declined => CaptureTerminalCode::Declined,
            CaptureStatusCode::Expired => CaptureTerminalCode::Expired,
            CaptureStatusCode::Cancelled => CaptureTerminalCode::Cancelled,
            CaptureStatusCode::Failed => CaptureTerminalCode::RemoteFailed,
        };
        // Once claimed, the pull owns the request's outcome; a status must not end it
        // mid-transfer, where it would turn a published photo into an unrecorded one. The phase
        // check and the write are one transaction, so a claim can never slip in between.
        match self
            .store
            .terminate_capture_unless_claimed(status.request_id, code, status.detail.clone())
            .map_err(storage)?
        {
            CaptureTransition::Applied(record) => {
                self.events.capture_finished(&record);
                Ok(status)
            }
            CaptureTransition::Unchanged(_) => Ok(status),
            CaptureTransition::Refused(_) | CaptureTransition::Unknown => Err(NetError::Rejected(
                "capture status was not recorded: the request was already claimed or finished"
                    .to_owned(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Phone side

/// Why a presented request or photo was withdrawn. The words are pinned by the Android contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureWithdrawReason {
    Expired,
    Cancelled,
    Failed,
}

impl CaptureWithdrawReason {
    /// The exact word passed to `onCaptureWithdrawn`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

/// The phone's user-facing queue refused an event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("capture event was not accepted: {0}")]
pub struct CaptureEventRefused(pub String);

/// What the phone resident tells its UI. Each call happens after the row it reports is durable.
pub trait CaptureSourceEvents: Send + Sync + 'static {
    /// Hands the "request presented" event to the UI queue. The request is acknowledged
    /// `Presented` only if this succeeds.
    fn capture_presented(&self, record: &CaptureSourceRecord) -> Result<(), CaptureEventRefused>;
    /// The requester durably holds the photo; the phone may delete its copy now.
    fn capture_delivered(&self, request_id: CaptureRequestId);
    /// The request ended without delivery; remove its notification or photo.
    fn capture_withdrawn(&self, request_id: CaptureRequestId, reason: CaptureWithdrawReason);
}

/// The phone's capture listener.
pub struct PhoneCaptureReceiver {
    store: Arc<RedbV2Store>,
    events: Arc<dyn CaptureSourceEvents>,
}

impl PhoneCaptureReceiver {
    #[must_use]
    pub fn new(store: Arc<RedbV2Store>, events: Arc<dyn CaptureSourceEvents>) -> Self {
        Self { store, events }
    }
}

#[async_trait]
impl V2CaptureReceiver for PhoneCaptureReceiver {
    /// Acknowledges `Presented` only after the request's row is durable and the presented event
    /// has been handed to the UI queue. `Busy` while another request is live, `Expired` once its
    /// expiry has passed, and for a repeated request id the ack its stored row implies.
    async fn handle_capture_request(
        &self,
        authenticated_source: DeviceId,
        requester_name: &str,
        listener_device: DeviceId,
        request: CaptureRequest,
    ) -> Result<CaptureAck, NetError> {
        let ack = |code: CaptureAckCode, detail: Option<&str>| CaptureAck {
            request_id: request.request_id,
            code,
            detail: detail.map(str::to_owned),
        };
        if request.validate().is_err() {
            return Ok(ack(CaptureAckCode::Refused, Some("invalid_request")));
        }
        if request.requester != authenticated_source || request.target != listener_device {
            return Ok(ack(CaptureAckCode::Refused, Some("identity_mismatch")));
        }
        if unix_now_ms()? >= request.expires_at_unix_ms {
            return Ok(ack(CaptureAckCode::Expired, None));
        }
        // The label is the paired peer's authenticated hello name, cut to what the phone shows.
        let label = truncate_utf8(requester_name.trim(), MAX_CAPTURE_LABEL_BYTES);
        if validate_capture_label(label).is_err() {
            return Ok(ack(
                CaptureAckCode::Refused,
                Some("requester_label_invalid"),
            ));
        }
        let record = CaptureSourceRecord {
            request_id: request.request_id,
            requester: authenticated_source,
            requester_label: label.to_owned(),
            purpose: request.purpose.clone(),
            lens: request.lens,
            created_at_unix_ms: request.created_at_unix_ms,
            expires_at_unix_ms: request.expires_at_unix_ms,
            phase: CaptureSourcePhase::Presented,
        };
        Ok(match self.store.present_capture(record).map_err(storage)? {
            CapturePresentation::Presented { record, .. } => {
                match self.events.capture_presented(&record) {
                    Ok(()) => ack(CaptureAckCode::Presented, None),
                    Err(refused) => {
                        // Nothing was shown, so the request ends now instead of holding the
                        // phone busy until it expires.
                        tracing::warn!(request = %record.request_id, error = %refused, "capture request could not be presented");
                        self.store
                            .terminate_capture_source(
                                record.request_id,
                                CaptureSourceTerminalCode::Failed,
                            )
                            .map_err(storage)?;
                        ack(CaptureAckCode::Refused, Some("presentation_unavailable"))
                    }
                }
            }
            // A repeated id repeats what the stored row implies, so a request that already ended
            // fails fast instead of arming the requester for a photo that will never come.
            CapturePresentation::Duplicate(phase) => {
                let (code, detail) = repeated_ack(&phase);
                ack(code, detail)
            }
            CapturePresentation::Busy => ack(CaptureAckCode::Busy, None),
            CapturePresentation::AtCapacity => ack(
                CaptureAckCode::Busy,
                Some("earlier photos are awaiting deletion"),
            ),
            CapturePresentation::Conflict => {
                ack(CaptureAckCode::Refused, Some("request_id_conflict"))
            }
        })
    }

    /// A requester may only cancel. The cancel is recorded, and the UI told, before it is
    /// acknowledged.
    async fn handle_capture_status(
        &self,
        authenticated_source: DeviceId,
        _listener_device: DeviceId,
        status: CaptureStatus,
    ) -> Result<CaptureStatus, NetError> {
        if status.code != CaptureStatusCode::Cancelled {
            return Err(NetError::Rejected(
                "a requester may only cancel a capture".to_owned(),
            ));
        }
        let Some(record) = self
            .store
            .get_capture_source(status.request_id)
            .map_err(storage)?
        else {
            return Err(NetError::Rejected(
                "capture status names no request on this phone".to_owned(),
            ));
        };
        if record.requester != authenticated_source {
            return Err(NetError::IdentityMismatch(
                "capture status sender did not request this capture".to_owned(),
            ));
        }
        match self
            .store
            .terminate_capture_source(status.request_id, CaptureSourceTerminalCode::Cancelled)
            .map_err(storage)?
        {
            CaptureTransition::Applied(_) => {
                self.events
                    .capture_withdrawn(status.request_id, CaptureWithdrawReason::Cancelled);
                Ok(status)
            }
            CaptureTransition::Unchanged(_) => Ok(status),
            CaptureTransition::Refused(_) | CaptureTransition::Unknown => Err(NetError::Rejected(
                "capture can no longer be cancelled on this phone".to_owned(),
            )),
        }
    }
}

/// The acknowledgement a repeated request id receives, derived from its stored row. A live row
/// repeats `Presented`; a finished row reports how it finished, in the ack vocabulary, with the
/// stored word as detail.
fn repeated_ack(phase: &CaptureSourcePhase) -> (CaptureAckCode, Option<&'static str>) {
    match phase {
        CaptureSourcePhase::Presented
        | CaptureSourcePhase::Captured { .. }
        | CaptureSourcePhase::Announced { .. }
        | CaptureSourcePhase::Claimed { .. } => (CaptureAckCode::Presented, None),
        // The photo was already served; it will never be presented or served again.
        CaptureSourcePhase::Delivered => (CaptureAckCode::Refused, Some("delivered")),
        CaptureSourcePhase::UncertainNoReplay { .. } => {
            (CaptureAckCode::Refused, Some("uncertain_no_replay"))
        }
        CaptureSourcePhase::Terminal { code } => match code {
            CaptureSourceTerminalCode::Expired => (CaptureAckCode::Expired, None),
            CaptureSourceTerminalCode::ExpiredUnconfirmed => {
                (CaptureAckCode::Expired, Some("expired_unconfirmed"))
            }
            CaptureSourceTerminalCode::Declined => (CaptureAckCode::Refused, Some("declined")),
            CaptureSourceTerminalCode::Cancelled => (CaptureAckCode::Refused, Some("cancelled")),
            CaptureSourceTerminalCode::Failed => (CaptureAckCode::Refused, Some("failed")),
        },
    }
}

/// The phone's fetch sources: captured photos in `capture_sources_v2`. The phone has no shelf.
pub struct CaptureSourceResolver {
    store: Arc<RedbV2Store>,
    events: Arc<dyn CaptureSourceEvents>,
}

impl CaptureSourceResolver {
    #[must_use]
    pub fn new(store: Arc<RedbV2Store>, events: Arc<dyn CaptureSourceEvents>) -> Self {
        Self { store, events }
    }
}

impl FetchSourceResolver for CaptureSourceResolver {
    fn resolve(&self, offer_id: OfferId) -> Result<Option<FetchableSource>, StoreError> {
        Ok(self
            .store
            .get_capture_source_by_offer(offer_id)?
            .map(|record| FetchableSource::Capture(Box::new(record))))
    }

    fn claim_capture(
        &self,
        offer_id: OfferId,
        requester: DeviceId,
        activation_id: ActivationId,
    ) -> Result<CaptureSourceClaim, StoreError> {
        self.store
            .claim_capture_source(offer_id, requester, activation_id)
    }

    fn capture_delivered(
        &self,
        claimed: &CaptureSourceRecord,
        activation_id: ActivationId,
        files_received: u32,
        bytes_received: u64,
    ) -> Result<bool, StoreError> {
        match self.store.mark_capture_delivered(
            claimed.request_id,
            activation_id,
            files_received,
            bytes_received,
        )? {
            CaptureTransition::Applied(_) => {
                self.events.capture_delivered(claimed.request_id);
                Ok(true)
            }
            // Already recorded, and announced when it was.
            CaptureTransition::Unchanged(_) => Ok(true),
            CaptureTransition::Refused(_) | CaptureTransition::Unknown => Ok(false),
        }
    }

    fn capture_failed(&self, claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        if let CaptureTransition::Applied(_) = self
            .store
            .terminate_capture_source(claimed.request_id, CaptureSourceTerminalCode::Failed)?
        {
            self.events
                .capture_withdrawn(claimed.request_id, CaptureWithdrawReason::Failed);
        }
        Ok(())
    }

    fn capture_uncertain(&self, claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        let CaptureSourcePhase::Claimed { photo, .. } = &claimed.phase else {
            return Err(StoreError::new(
                "an uncertain capture must have been claimed",
            ));
        };
        self.store
            .mark_capture_uncertain(claimed.request_id, photo.delete_deadline_unix_ms)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Photo dimensions

/// At most this much of a staged photo is read to find its frame header.
const JPEG_HEADER_SCAN_BYTES: u64 = 64 * 1024;

/// Width and height from the frame header of the JPEG at `path`, reading at most the first
/// [`JPEG_HEADER_SCAN_BYTES`]. `None` when no frame header with positive dimensions is found
/// there.
pub(crate) fn jpeg_dimensions(path: &Path) -> Option<(u32, u32)> {
    let file = std::fs::File::open(path).ok()?;
    let mut head = Vec::new();
    file.take(JPEG_HEADER_SCAN_BYTES)
        .read_to_end(&mut head)
        .ok()?;
    parse_jpeg_dimensions(&head)
}

fn parse_jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..2)? != [0xFF, 0xD8] {
        return None;
    }
    let mut index = 2_usize;
    loop {
        if *bytes.get(index)? != 0xFF {
            return None;
        }
        // Any number of fill bytes may precede a marker.
        while *bytes.get(index)? == 0xFF {
            index += 1;
        }
        let marker = *bytes.get(index)?;
        index += 1;
        match marker {
            // Standalone markers carry no length.
            0x01 | 0xD0..=0xD7 => continue,
            // A stuffed zero, a second start of image, the end of image, or the start of scan
            // before any frame header: there is no frame header to read.
            0x00 | 0xD8 | 0xD9 | 0xDA => return None,
            _ => {}
        }
        let length = usize::from(u16::from_be_bytes([
            *bytes.get(index)?,
            *bytes.get(index + 1)?,
        ]));
        if length < 2 {
            return None;
        }
        if is_start_of_frame(marker) {
            // Length (2), sample precision (1), height (2), width (2).
            let frame = bytes.get(index + 2..index + 7)?;
            let height = u32::from(u16::from_be_bytes([frame[1], frame[2]]));
            let width = u32::from(u16::from_be_bytes([frame[3], frame[4]]));
            return (width > 0 && height > 0).then_some((width, height));
        }
        index = index.checked_add(length)?;
    }
}

/// SOF0-SOF15 except DHT (C4), JPG (C8), and DAC (CC), which share the range.
fn is_start_of_frame(marker: u8) -> bool {
    matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        net::SocketAddr,
        path::PathBuf,
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use meshelf_core::{
        ActivationMode, CaptureKind, CapturePullGrant, CaptureReceipt, CapturedPhoto,
        CardAvailability, ClipboardError, OfferCardInput, OfferCardInsert, OfferCardRecord,
        OfferDescriptor,
    };
    use meshelf_identity::InstallationIdentity;
    use meshelf_protocol::{
        CAP_CAPTURE_PHOTO_V1, CAP_CAPTURE_REQUEST_V1, CAP_OFFER_PULL_V2, FetchAdmission,
        FetchAdmissionCode, FetchComplete, FetchHeader, FetchReceipt, FetchReceiptCode,
        FetchRefusalCode, FileEnd, FileEntryKind, FileStart, ManifestChunk, ManifestEnd,
        ManifestEntry, OfferAckCode, V2Message, read_v2_frame_async, write_v2_frame_async,
    };
    use sha2::{Digest, Sha256};
    use tokio::{
        io::AsyncReadExt,
        net::{TcpListener, TcpStream},
        task::JoinHandle,
        time::timeout,
    };

    use super::*;
    use crate::{
        ExactDeviceAllowList, FetchReceiver, OfferAnnouncementHandler, OfferCardStore,
        OfferFetchHandler, ReservationLedger, ServerIdentity, V2FetchSender, V2OfferServices,
        V2ServerConfig, serve_v2,
    };

    const IO: Duration = Duration::from_secs(10);
    const PURPOSE: &str = "Photograph the router label";

    fn now() -> u64 {
        unix_now_ms().expect("system clock")
    }

    /// A minimal baseline JPEG: start of image, a JFIF segment, a frame header with the given
    /// dimensions, a start of scan, entropy-coded filler with no marker bytes, end of image.
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

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn photo_descriptor(bytes: &[u8]) -> OfferDescriptor {
        OfferDescriptor::File {
            root_name: "IMG_0001.jpg".to_owned(),
            total_bytes: bytes.len() as u64,
            content_class: meshelf_core::FileContentClass::File,
        }
    }

    fn entry_names(directory: &std::path::Path) -> BTreeSet<String> {
        fs::read_dir(directory)
            .expect("read directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// A capture must never touch the clipboard; any attempt fails loudly.
    #[derive(Debug, Default)]
    struct NoClipboard;

    impl meshelf_core::ClipboardSink for NoClipboard {
        fn set_text(&self, _text: &str) -> Result<(), ClipboardError> {
            Err(ClipboardError::new("a capture never writes the clipboard"))
        }
    }

    impl FetchClipboard for NoClipboard {
        fn set_files(&self, _paths: &[PathBuf]) -> Result<(), ClipboardError> {
            Err(ClipboardError::new("a capture never writes the clipboard"))
        }
    }

    #[derive(Default)]
    struct RecordingRequestEvents {
        finished: Mutex<Vec<CaptureRequestRecord>>,
    }

    impl CaptureRequestEvents for RecordingRequestEvents {
        fn capture_finished(&self, record: &CaptureRequestRecord) {
            self.finished.lock().expect("events").push(record.clone());
        }
    }

    #[derive(Default)]
    struct CountingLauncher {
        launched: Mutex<Vec<ClaimedCapturePull>>,
        refuse: Option<CaptureTerminalCode>,
    }

    impl CapturePullLauncher for CountingLauncher {
        fn launch(&self, pull: ClaimedCapturePull) -> Result<(), CaptureLaunchRefused> {
            if let Some(code) = self.refuse {
                return Err(CaptureLaunchRefused {
                    code,
                    detail: Some("phone address is unknown".to_owned()),
                });
            }
            self.launched.lock().expect("launches").push(pull);
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingSourceEvents {
        /// When set, each presented event checks that its row was already durable.
        store: Option<Arc<RedbV2Store>>,
        refuse_presented: bool,
        presented: Mutex<Vec<(CaptureRequestId, bool)>>,
        delivered: Mutex<Vec<CaptureRequestId>>,
        withdrawn: Mutex<Vec<(CaptureRequestId, &'static str)>>,
    }

    impl CaptureSourceEvents for RecordingSourceEvents {
        fn capture_presented(
            &self,
            record: &CaptureSourceRecord,
        ) -> Result<(), CaptureEventRefused> {
            let durable = self.store.as_ref().is_some_and(|store| {
                store
                    .get_capture_source(record.request_id)
                    .expect("read row")
                    .is_some()
            });
            self.presented
                .lock()
                .expect("presented")
                .push((record.request_id, durable));
            if self.refuse_presented {
                Err(CaptureEventRefused("event queue is full".to_owned()))
            } else {
                Ok(())
            }
        }

        fn capture_delivered(&self, request_id: CaptureRequestId) {
            self.delivered.lock().expect("delivered").push(request_id);
        }

        fn capture_withdrawn(&self, request_id: CaptureRequestId, reason: CaptureWithdrawReason) {
            self.withdrawn
                .lock()
                .expect("withdrawn")
                .push((request_id, reason.as_str()));
        }
    }

    impl RecordingSourceEvents {
        fn delivered(&self) -> Vec<CaptureRequestId> {
            self.delivered.lock().expect("delivered").clone()
        }

        fn withdrawn(&self) -> Vec<(CaptureRequestId, &'static str)> {
            self.withdrawn.lock().expect("withdrawn").clone()
        }
    }

    /// Counts every shelf operation so a test can prove a capture never reached the shelf.
    struct CountingCardStore {
        inner: Arc<RedbV2Store>,
        inserts: AtomicUsize,
        lookups: AtomicUsize,
    }

    impl OfferCardStore for CountingCardStore {
        fn get_offer_card(
            &self,
            source_device: DeviceId,
            offer_id: OfferId,
        ) -> Result<Option<OfferCardRecord>, StoreError> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.inner.get_offer_card(source_device, offer_id)
        }

        fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError> {
            self.inner.read_offer_shelf()
        }

        fn insert_offer_card(&self, input: OfferCardInput) -> Result<OfferCardInsert, StoreError> {
            self.inserts.fetch_add(1, Ordering::SeqCst);
            self.inner.insert_offer_card(input)
        }
    }

    struct Requester {
        _directory: tempfile::TempDir,
        root: PathBuf,
        store: Arc<RedbV2Store>,
        output_dir: PathBuf,
    }

    impl Requester {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("requester directory");
            let root = fs::canonicalize(directory.path()).expect("canonical root");
            let store =
                Arc::new(RedbV2Store::open(root.join("meshelf.redb")).expect("requester store"));
            let output_dir = root.join("out");
            fs::create_dir(&output_dir).expect("output directory");
            Self {
                _directory: directory,
                root,
                store,
                output_dir,
            }
        }

        fn output(&self) -> PathBuf {
            self.output_dir.join("router-label.jpg")
        }

        fn armed_with_id(
            &self,
            request_id: CaptureRequestId,
            phone: DeviceId,
            output: PathBuf,
        ) -> CaptureRequestRecord {
            let created = now();
            let record = CaptureRequestRecord {
                request_id,
                peer: phone,
                peer_label: "amber".to_owned(),
                purpose: PURPOSE.to_owned(),
                lens: None,
                created_at_unix_ms: created,
                grant: CapturePullGrant {
                    expected_source: phone,
                    kind: CaptureKind::Photo,
                    exact_output_path: output,
                    expires_at_unix_ms: created + 170_000,
                },
                phase: CaptureRequestPhase::AwaitingPresentation,
                terminal_reported: false,
            };
            assert!(matches!(
                self.store
                    .insert_capture_request(record)
                    .expect("insert request"),
                meshelf_store::CaptureRequestInsert::Inserted { .. }
            ));
            match self
                .store
                .arm_capture_grant(request_id, now())
                .expect("arm")
            {
                CaptureTransition::Applied(record) => record,
                other => panic!("grant was not armed: {other:?}"),
            }
        }

        fn armed(&self, phone: DeviceId, output: PathBuf) -> CaptureRequestRecord {
            self.armed_with_id(CaptureRequestId::new(), phone, output)
        }

        fn claimed(
            &self,
            phone: DeviceId,
            output: PathBuf,
            descriptor: OfferDescriptor,
        ) -> ClaimedCapturePull {
            let request = self.armed(phone, output);
            match self
                .store
                .claim_capture_grant(
                    request.request_id,
                    phone,
                    OfferId::new(),
                    ActivationId::new(),
                    descriptor,
                    now(),
                )
                .expect("claim")
            {
                CaptureGrantClaim::Claimed(pull) => pull,
                other => panic!("grant was not claimed: {other:?}"),
            }
        }

        fn phase(&self, request_id: CaptureRequestId) -> CaptureRequestPhase {
            self.store
                .get_capture_request(request_id)
                .expect("read request")
                .expect("request row")
                .phase
        }

        fn receiver(&self) -> Arc<FetchReceiver<NoClipboard>> {
            Arc::new(FetchReceiver::with_ledger(
                DeviceId::new(),
                self.store.clone(),
                Arc::new(NoClipboard),
                self.root.clone(),
                ReservationLedger::default(),
            ))
        }

        fn router(&self, launcher: Arc<dyn CapturePullLauncher>) -> RequesterCaptureRouter {
            RequesterCaptureRouter::new(
                self.store.clone(),
                launcher,
                Arc::new(RecordingRequestEvents::default()),
            )
        }
    }

    fn terminal_code(phase: &CaptureRequestPhase) -> Option<CaptureTerminalCode> {
        match phase {
            CaptureRequestPhase::Terminal { code, .. } => Some(*code),
            _ => None,
        }
    }

    // --- Photo dimensions ----------------------------------------------------------------------

    #[test]
    fn frame_header_dimensions_are_read_past_application_segments_fill_bytes_and_progressive_frames()
     {
        assert_eq!(
            parse_jpeg_dimensions(&jpeg(4032, 3024, 64)),
            Some((4032, 3024))
        );

        let mut filled = jpeg(640, 480, 8);
        // Extra 0xFF fill bytes before the frame header marker are legal.
        let frame = filled
            .windows(2)
            .position(|pair| pair == [0xFF, 0xC0])
            .expect("frame marker");
        filled.splice(frame..frame, [0xFF, 0xFF]);
        assert_eq!(parse_jpeg_dimensions(&filled), Some((640, 480)));

        let mut progressive = jpeg(1920, 1080, 8);
        let frame = progressive
            .windows(2)
            .position(|pair| pair == [0xFF, 0xC0])
            .expect("frame marker");
        progressive[frame + 1] = 0xC2;
        assert_eq!(parse_jpeg_dimensions(&progressive), Some((1920, 1080)));
    }

    #[test]
    fn a_file_without_a_frame_header_in_its_first_64_kib_has_no_dimensions() {
        assert_eq!(parse_jpeg_dimensions(b"not a jpeg at all"), None);
        let full = jpeg(4032, 3024, 16);
        assert_eq!(parse_jpeg_dimensions(&full[..20]), None, "truncated");

        let mut scan_first = vec![0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02];
        scan_first.extend_from_slice(&full[2..]);
        assert_eq!(
            parse_jpeg_dimensions(&scan_first),
            None,
            "scan before frame"
        );

        let mut zero_height = jpeg(4032, 0, 8);
        zero_height.truncate(zero_height.len());
        assert_eq!(parse_jpeg_dimensions(&zero_height), None, "zero height");

        // A maximal application segment pushes the frame header past the 64 KiB bound. The whole
        // file parses, but the bounded read refuses it rather than reading further.
        let mut far = vec![0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF];
        far.extend(std::iter::repeat_n(0_u8, 0xFFFF - 2));
        far.extend_from_slice(&full[2..]);
        assert_eq!(parse_jpeg_dimensions(&far), Some((4032, 3024)));
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("far.jpg");
        fs::write(&path, &far).expect("write far jpeg");
        assert_eq!(jpeg_dimensions(&path), None);
        let near = directory.path().join("near.jpg");
        fs::write(&near, &full).expect("write near jpeg");
        assert_eq!(jpeg_dimensions(&near), Some((4032, 3024)));
    }

    // --- Requester routing ---------------------------------------------------------------------

    #[test]
    fn correlated_announcements_are_routed_before_the_shelf_and_never_insert_a_card() {
        let requester = Requester::new();
        let phone = DeviceId::new();
        let listener = DeviceId::new();
        let cards = Arc::new(CountingCardStore {
            inner: requester.store.clone(),
            inserts: AtomicUsize::new(0),
            lookups: AtomicUsize::new(0),
        });
        let launcher = Arc::new(CountingLauncher::default());
        let handler = OfferAnnouncementHandler::new(cards.clone())
            .with_capture_router(Arc::new(requester.router(launcher.clone())));
        let request = requester.armed(phone, requester.output());
        let bytes = jpeg(4032, 3024, 64);
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            phone,
            listener,
            now(),
            photo_descriptor(&bytes),
        )
        .with_capture(CaptureCorrelation {
            request_id: request.request_id,
        });

        let ack = handler
            .handle_sync(phone, listener, announcement.clone())
            .expect("attached");
        assert_eq!(ack.code, OfferAckCode::Stored);
        assert_eq!((ack.live_entries, ack.pruned_entries), (0, 0));
        let repeat = handler
            .handle_sync(phone, listener, announcement)
            .expect("repeat");
        assert_eq!(repeat.code, OfferAckCode::Duplicate);

        // Another device may not claim this request, even with its id.
        let impostor = DeviceId::new();
        let stolen = OfferAnnouncement::new(
            OfferId::new(),
            impostor,
            listener,
            now(),
            photo_descriptor(&bytes),
        )
        .with_capture(CaptureCorrelation {
            request_id: request.request_id,
        });
        let refused = handler
            .handle_sync(impostor, listener, stolen)
            .expect("typed refusal");
        assert_eq!(refused.code, OfferAckCode::RefusedInvalid);
        assert_eq!(refused.detail.as_deref(), Some("capture_wrong_source"));

        assert_eq!(cards.inserts.load(Ordering::SeqCst), 0);
        assert_eq!(cards.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(launcher.launched.lock().expect("launches").len(), 1);
        assert!(
            requester
                .store
                .read_offer_shelf()
                .expect("shelf")
                .is_empty()
        );

        // An uncorrelated announcement still reaches the shelf through the same handler.
        let plain = OfferAnnouncement::new(
            OfferId::new(),
            phone,
            listener,
            now(),
            OfferDescriptor::text("kept on the shelf").expect("text"),
        );
        let stored = handler
            .handle_sync(phone, listener, plain)
            .expect("shelf ack");
        assert_eq!(stored.code, OfferAckCode::Stored);
        assert_eq!(cards.inserts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn two_racing_correlated_announcements_for_one_armed_request_start_exactly_one_pull() {
        let requester = Requester::new();
        let phone = DeviceId::new();
        let listener = DeviceId::new();
        let launcher = Arc::new(CountingLauncher::default());
        let handler = Arc::new(
            OfferAnnouncementHandler::new(requester.store.clone())
                .with_capture_router(Arc::new(requester.router(launcher.clone()))),
        );
        let request = requester.armed(phone, requester.output());
        let bytes = jpeg(4032, 3024, 64);
        const RACERS: usize = 8;
        let barrier = Arc::new(Barrier::new(RACERS));
        let racers: Vec<_> = (0..RACERS)
            .map(|_| {
                let handler = handler.clone();
                let barrier = barrier.clone();
                let announcement = OfferAnnouncement::new(
                    OfferId::new(),
                    phone,
                    listener,
                    now(),
                    photo_descriptor(&bytes),
                )
                .with_capture(CaptureCorrelation {
                    request_id: request.request_id,
                });
                std::thread::spawn(move || {
                    barrier.wait();
                    handler
                        .handle_sync(phone, listener, announcement)
                        .expect("ack")
                })
            })
            .collect();
        let acks: Vec<_> = racers
            .into_iter()
            .map(|racer| racer.join().expect("racer"))
            .collect();

        let winners: Vec<_> = acks
            .iter()
            .filter(|ack| ack.code == OfferAckCode::Stored)
            .collect();
        assert_eq!(winners.len(), 1, "{acks:?}");
        let launched = launcher.launched.lock().expect("launches").clone();
        assert_eq!(launched.len(), 1);
        assert_eq!(launched[0].offer_id, winners[0].offer_id);
        for ack in acks.iter().filter(|ack| ack.code != OfferAckCode::Stored) {
            assert_eq!(ack.code, OfferAckCode::RefusedInvalid);
            assert_eq!(ack.detail.as_deref(), Some("capture_already_claimed"));
        }
        assert!(matches!(
            requester.phase(request.request_id),
            CaptureRequestPhase::Claimed { offer_id, .. } if offer_id == winners[0].offer_id
        ));
    }

    #[test]
    fn a_claim_whose_pull_cannot_launch_ends_the_request_and_is_never_rearmed() {
        let requester = Requester::new();
        let phone = DeviceId::new();
        let listener = DeviceId::new();
        let launcher = Arc::new(CountingLauncher {
            refuse: Some(CaptureTerminalCode::PeerOffline),
            ..CountingLauncher::default()
        });
        let events = Arc::new(RecordingRequestEvents::default());
        let handler =
            OfferAnnouncementHandler::new(requester.store.clone()).with_capture_router(Arc::new(
                RequesterCaptureRouter::new(requester.store.clone(), launcher, events.clone()),
            ));
        let request = requester.armed(phone, requester.output());
        let bytes = jpeg(4032, 3024, 64);
        let announce = || {
            OfferAnnouncement::new(
                OfferId::new(),
                phone,
                listener,
                now(),
                photo_descriptor(&bytes),
            )
            .with_capture(CaptureCorrelation {
                request_id: request.request_id,
            })
        };
        let first = handler
            .handle_sync(phone, listener, announce())
            .expect("ack");
        assert_eq!(first.detail.as_deref(), Some("capture_launch_failed"));
        assert_eq!(
            terminal_code(&requester.phase(request.request_id)),
            Some(CaptureTerminalCode::PeerOffline)
        );
        assert_eq!(events.finished.lock().expect("events").len(), 1);

        let second = handler
            .handle_sync(phone, listener, announce())
            .expect("ack");
        assert_eq!(second.code, OfferAckCode::RefusedInvalid);
        assert_eq!(second.detail.as_deref(), Some("capture_not_armed"));
    }

    // --- Requester receive ---------------------------------------------------------------------

    struct OriginScript {
        chunk: ManifestChunk,
        manifest_sha256: Vec<u8>,
        manifest_encoded_bytes: u64,
    }

    fn origin_script(pull: &ClaimedCapturePull, bytes: &[u8]) -> OriginScript {
        let entry = ManifestEntry {
            relative_path: String::new(),
            kind: FileEntryKind::File,
            byte_len: bytes.len() as u64,
        };
        let manifest_sha256 =
            Sha256::digest(serde_json::to_vec(std::slice::from_ref(&entry)).expect("manifest"))
                .to_vec();
        let chunk = ManifestChunk::new(pull.activation_id, 0, vec![entry]).expect("chunk");
        let manifest_encoded_bytes =
            meshelf_protocol::encoded_manifest_bytes(std::slice::from_ref(&chunk))
                .expect("manifest size") as u64;
        OriginScript {
            chunk,
            manifest_sha256,
            manifest_encoded_bytes,
        }
    }

    /// Plays the phone's side by hand up to the requester's admission frame.
    async fn start_capture_receive(
        receiver: Arc<FetchReceiver<NoClipboard>>,
        pull: &ClaimedCapturePull,
        bytes: &[u8],
    ) -> (
        TcpStream,
        JoinHandle<Result<ActivationOutcome, NetError>>,
        FetchAdmission,
        OriginScript,
    ) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let activation = FetchActivation::capture(pull);
        let source = pull.source;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            receiver.receive(source, activation, &mut stream, IO).await
        });
        let mut client = TcpStream::connect(address).await.expect("connect");
        let script = origin_script(pull, bytes);
        for message in [
            V2Message::FetchHeader(FetchHeader {
                request_id: pull.activation_id,
                offer_id: pull.offer_id,
                descriptor: pull.descriptor.clone(),
                manifest_entries: 1,
                manifest_encoded_bytes: script.manifest_encoded_bytes,
                text_sha256: None,
                manifest_sha256: Some(script.manifest_sha256.clone()),
            }),
            V2Message::ManifestChunk(script.chunk.clone()),
            V2Message::ManifestEnd(ManifestEnd {
                request_id: pull.activation_id,
                entry_count: 1,
                file_count: 1,
                total_bytes: bytes.len() as u64,
                manifest_sha256: script.manifest_sha256.clone(),
            }),
        ] {
            write_v2_frame_async(&mut client, &message)
                .await
                .expect("write origin frame");
        }
        let V2Message::FetchAdmission(admission) = read_frame(&mut client).await else {
            panic!("expected fetch admission");
        };
        (client, server, admission, script)
    }

    async fn read_frame(stream: &mut TcpStream) -> V2Message {
        timeout(IO, read_v2_frame_async(stream))
            .await
            .expect("frame in time")
            .expect("frame")
    }

    async fn send_file(client: &mut TcpStream, pull: &ClaimedCapturePull, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt;
        write_v2_frame_async(
            client,
            &V2Message::FileStart(FileStart {
                request_id: pull.activation_id,
                entry_index: 0,
                byte_len: bytes.len() as u64,
            }),
        )
        .await
        .expect("file start");
        client.write_all(bytes).await.expect("file bytes");
        write_v2_frame_async(
            client,
            &V2Message::FileEnd(FileEnd {
                request_id: pull.activation_id,
                entry_index: 0,
                sha256: sha256(bytes).to_vec(),
            }),
        )
        .await
        .expect("file end");
    }

    async fn complete(
        client: &mut TcpStream,
        pull: &ClaimedCapturePull,
        script: &OriginScript,
        bytes: &[u8],
    ) -> FetchReceipt {
        let mut content_set = Sha256::new();
        content_set.update(&script.manifest_sha256);
        content_set.update(sha256(bytes));
        write_v2_frame_async(
            client,
            &V2Message::FetchComplete(FetchComplete {
                request_id: pull.activation_id,
                files_sent: 1,
                bytes_sent: bytes.len() as u64,
                content_set_sha256: content_set.finalize().to_vec(),
            }),
        )
        .await
        .expect("fetch complete");
        let V2Message::FetchReceipt(receipt) = read_frame(client).await else {
            panic!("expected fetch receipt");
        };
        receipt
    }

    #[tokio::test]
    async fn a_verified_capture_lands_at_exactly_the_named_path_with_the_streamed_digest_and_frame_size()
     {
        let requester = Requester::new();
        let bytes = jpeg(4032, 3024, 3_000);
        // The origin's file name differs from the output name: the agent's path wins.
        let pull = requester.claimed(
            DeviceId::new(),
            requester.output(),
            photo_descriptor(&bytes),
        );
        let (mut client, server, admission, script) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        send_file(&mut client, &pull, &bytes).await;
        let receipt = complete(&mut client, &pull, &script, &bytes).await;
        assert_eq!(receipt.code, FetchReceiptCode::Completed);
        assert_eq!(
            (receipt.files_received, receipt.bytes_received),
            (1, bytes.len() as u64)
        );
        assert_eq!(
            server.await.expect("join").expect("outcome"),
            ActivationOutcome::Completed
        );

        assert_eq!(fs::read(requester.output()).expect("published"), bytes);
        assert_eq!(
            requester.phase(pull.request_id),
            CaptureRequestPhase::Completed {
                receipt: CaptureReceipt {
                    output_path: requester.output(),
                    sha256: sha256(&bytes),
                    bytes: bytes.len() as u64,
                    width: 4032,
                    height: 3024,
                }
            }
        );
        assert_eq!(
            entry_names(&requester.output_dir),
            BTreeSet::from(["router-label.jpg".to_owned()]),
            "no staging or renamed copy may remain"
        );
        assert!(
            requester
                .store
                .get_activation_journal(pull.activation_id)
                .expect("journal")
                .is_none()
        );
        assert!(
            requester
                .store
                .read_offer_shelf()
                .expect("shelf")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_photo_published_but_not_recorded_is_kept_and_its_receipt_is_never_completed() {
        // Completion is recorded before the receipt is sent. Make the record fail after
        // publication: had the receipt been sent first, the origin would have seen `Completed`.
        let requester = Requester::new();
        let bytes = jpeg(4032, 3024, 3_000);
        let pull = requester.claimed(
            DeviceId::new(),
            requester.output(),
            photo_descriptor(&bytes),
        );
        let (mut client, server, admission, script) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        send_file(&mut client, &pull, &bytes).await;
        requester
            .store
            .terminate_capture(pull.request_id, CaptureTerminalCode::Cancelled, None)
            .expect("end the request mid-transfer");
        let receipt = complete(&mut client, &pull, &script, &bytes).await;
        assert_eq!(receipt.code, FetchReceiptCode::UncertainNoReplay);
        assert_eq!(
            server.await.expect("join").expect("outcome"),
            ActivationOutcome::UncertainNoReplay
        );
        assert_eq!(
            fs::read(requester.output()).expect("the published photo stays"),
            bytes
        );
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::Cancelled)
        );
    }

    #[tokio::test]
    async fn a_target_created_after_preflight_is_never_replaced_or_renamed() {
        let requester = Requester::new();
        let bytes = jpeg(4032, 3024, 3_000);
        let pull = requester.claimed(
            DeviceId::new(),
            requester.output(),
            photo_descriptor(&bytes),
        );
        let (mut client, server, admission, script) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        send_file(&mut client, &pull, &bytes).await;
        fs::write(requester.output(), b"another process").expect("racing writer");
        let receipt = complete(&mut client, &pull, &script, &bytes).await;
        assert_ne!(receipt.code, FetchReceiptCode::Completed);
        let _ = server.await.expect("join");

        assert_eq!(
            fs::read(requester.output()).expect("racing file"),
            b"another process"
        );
        assert_eq!(
            entry_names(&requester.output_dir),
            BTreeSet::from(["router-label.jpg".to_owned()]),
            "no renamed copy and no staging may remain"
        );
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::OutputExists)
        );
        assert_eq!(CaptureTerminalCode::OutputExists.outcome().exit_code, 4);
    }

    #[tokio::test]
    async fn a_target_that_exists_at_admission_is_refused_before_any_staging() {
        let requester = Requester::new();
        let bytes = jpeg(4032, 3024, 64);
        let pull = requester.claimed(
            DeviceId::new(),
            requester.output(),
            photo_descriptor(&bytes),
        );
        fs::write(requester.output(), b"keep me").expect("existing file");
        let (_client, server, admission, _) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::DestinationUnavailable);
        assert_eq!(admission.detail.as_deref(), Some("output_exists"));
        let _ = server.await.expect("join");
        assert_eq!(fs::read(requester.output()).expect("kept"), b"keep me");
        assert_eq!(
            entry_names(&requester.output_dir),
            BTreeSet::from(["router-label.jpg".to_owned()])
        );
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::OutputExists)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_output_parent_is_refused_and_nothing_is_written_through_it() {
        let requester = Requester::new();
        let elsewhere = requester.root.join("elsewhere");
        fs::create_dir(&elsewhere).expect("link target");
        let linked = requester.root.join("linked");
        std::os::unix::fs::symlink(&elsewhere, &linked).expect("parent symlink");
        let bytes = jpeg(4032, 3024, 64);
        let pull = requester.claimed(
            DeviceId::new(),
            linked.join("router-label.jpg"),
            photo_descriptor(&bytes),
        );
        let (_client, server, admission, _) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::DestinationUnavailable);
        assert_eq!(admission.detail.as_deref(), Some("output_parent_is_link"));
        let _ = server.await.expect("join");
        assert!(entry_names(&elsewhere).is_empty());
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::PublicationFailed)
        );
    }

    #[tokio::test]
    async fn a_missing_output_parent_is_refused_and_no_directory_is_created() {
        let requester = Requester::new();
        let missing = requester.root.join("missing");
        let bytes = jpeg(4032, 3024, 64);
        let pull = requester.claimed(
            DeviceId::new(),
            missing.join("nested").join("router-label.jpg"),
            photo_descriptor(&bytes),
        );
        let (_client, server, admission, _) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::DestinationUnavailable);
        assert_eq!(admission.detail.as_deref(), Some("output_parent_missing"));
        let _ = server.await.expect("join");
        assert!(fs::symlink_metadata(&missing).is_err());
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::PublicationFailed)
        );
    }

    fn disk_full(_file: &std::fs::File, _length: u64) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
    }

    #[tokio::test]
    async fn a_full_disk_at_preallocation_ends_insufficient_space_and_leaves_no_staging() {
        let requester = Requester::new();
        let bytes = jpeg(4032, 3024, 64);
        let pull = requester.claimed(
            DeviceId::new(),
            requester.output(),
            photo_descriptor(&bytes),
        );
        let receiver = Arc::new(FetchReceiver::with_preallocator_for_test(
            DeviceId::new(),
            requester.store.clone(),
            Arc::new(NoClipboard),
            requester.root.clone(),
            ReservationLedger::default(),
            disk_full,
        ));
        let (_client, server, admission, _) = start_capture_receive(receiver, &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::InsufficientSpace);
        let _ = server.await.expect("join");
        assert!(entry_names(&requester.output_dir).is_empty());
        assert!(
            requester
                .store
                .get_activation_journal(pull.activation_id)
                .expect("journal")
                .is_none()
        );
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::InsufficientSpace)
        );
    }

    #[tokio::test]
    async fn a_failed_capture_removes_only_its_staging_and_never_the_empty_output_directory() {
        let requester = Requester::new();
        let bytes = jpeg(4032, 3024, 3_000);
        let pull = requester.claimed(
            DeviceId::new(),
            requester.output(),
            photo_descriptor(&bytes),
        );
        let (mut client, server, admission, _) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let mut tampered = bytes.clone();
        tampered[100] ^= 0x01;
        // The bytes do not match the file end's digest.
        {
            use tokio::io::AsyncWriteExt;
            write_v2_frame_async(
                &mut client,
                &V2Message::FileStart(FileStart {
                    request_id: pull.activation_id,
                    entry_index: 0,
                    byte_len: bytes.len() as u64,
                }),
            )
            .await
            .expect("file start");
            client.write_all(&tampered).await.expect("bytes");
            write_v2_frame_async(
                &mut client,
                &V2Message::FileEnd(FileEnd {
                    request_id: pull.activation_id,
                    entry_index: 0,
                    sha256: sha256(&bytes).to_vec(),
                }),
            )
            .await
            .expect("file end");
        }
        let V2Message::FetchReceipt(receipt) = read_frame(&mut client).await else {
            panic!("expected fetch receipt");
        };
        assert_eq!(receipt.code, FetchReceiptCode::VerificationFailed);
        let _ = server.await.expect("join");
        assert!(requester.output_dir.is_dir(), "the agent's directory stays");
        assert!(entry_names(&requester.output_dir).is_empty());
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::VerificationFailed)
        );
    }

    #[tokio::test]
    async fn a_payload_without_a_jpeg_frame_header_is_never_published() {
        let requester = Requester::new();
        let bytes = b"these bytes are not a photograph".to_vec();
        let pull = requester.claimed(
            DeviceId::new(),
            requester.output(),
            photo_descriptor(&bytes),
        );
        let (mut client, server, admission, script) =
            start_capture_receive(requester.receiver(), &pull, &bytes).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        send_file(&mut client, &pull, &bytes).await;
        let receipt = complete(&mut client, &pull, &script, &bytes).await;
        assert_eq!(receipt.code, FetchReceiptCode::VerificationFailed);
        let _ = server.await.expect("join");
        assert!(entry_names(&requester.output_dir).is_empty());
        assert_eq!(
            terminal_code(&requester.phase(pull.request_id)),
            Some(CaptureTerminalCode::VerificationFailed)
        );
    }

    #[tokio::test]
    async fn with_both_activation_permits_in_use_a_capture_ends_requester_busy_without_staging() {
        let requester = Requester::new();
        let identity = InstallationIdentity::generate();
        let service = Arc::new(ActivationService::with_ledger(
            identity.device_id,
            requester.store.clone(),
            Arc::new(NoClipboard),
            requester.root.clone(),
            ReservationLedger::default(),
        ));
        service.recover().expect("recovery");
        // A peer that accepts and never answers holds two manual activations in flight.
        let stall = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind stall");
        let stall_address = stall.local_addr().expect("stall address");
        let accepting = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (stream, _) = stall.accept().await.expect("accept");
                held.push(stream);
            }
        });
        let client = PeerClient::with_timeouts(IO, Duration::from_secs(120));
        let origin = DeviceId::new();
        let mut manual = Vec::new();
        for _ in 0..2 {
            let request = FetchRequest::new(OfferId::new(), origin, identity.device_id);
            let activation = FetchActivation::new(
                request.request_id,
                origin,
                request.offer_id,
                ActivationMode::Save,
                Some(requester.root.join("received")),
            );
            let hello = ClientHello::signed_v2(
                identity.device_id,
                "CEDAR",
                request.request_id.to_string(),
                &identity,
            );
            let (cancel_tx, cancel_rx) = watch::channel(false);
            let service = service.clone();
            let client = client.clone();
            let task = tokio::spawn(async move {
                service
                    .activate(
                        &client,
                        stall_address,
                        hello,
                        request,
                        activation,
                        &[],
                        cancel_rx,
                    )
                    .await
            });
            manual.push((cancel_tx, task));
        }
        let deadline = std::time::Instant::now() + IO;
        while service.live_count() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "manual activations did not start"
            );
            tokio::task::yield_now().await;
        }

        let bytes = jpeg(4032, 3024, 64);
        let pull = requester.claimed(origin, requester.output(), photo_descriptor(&bytes));
        let hello = ClientHello::signed_v2(identity.device_id, "CEDAR", "capture", &identity);
        let (_cancel, cancel) = watch::channel(false);
        let record = run_capture_pull(&service, &client, stall_address, hello, &[], &pull, cancel)
            .await
            .expect("capture pull");
        assert_eq!(
            terminal_code(&record.phase),
            Some(CaptureTerminalCode::RequesterBusy)
        );
        assert_eq!(
            Some(record),
            requester
                .store
                .get_capture_request(pull.request_id)
                .expect("read"),
            "the returned row is the durable row"
        );
        assert!(
            entry_names(&requester.output_dir).is_empty(),
            "a refused capture creates no staging"
        );
        assert_eq!(service.live_count(), 2, "nothing was queued behind them");
        for (_cancel, task) in manual {
            task.abort();
        }
        accepting.abort();
    }

    // --- Phone serving -------------------------------------------------------------------------

    struct Phone {
        _directory: tempfile::TempDir,
        store: Arc<RedbV2Store>,
        events: Arc<RecordingSourceEvents>,
        handler: Arc<OfferFetchHandler>,
        device: DeviceId,
        request_id: CaptureRequestId,
        photo: CapturedPhoto,
        bytes: Vec<u8>,
    }

    impl Phone {
        fn with_announced_photo(
            device: DeviceId,
            requester: DeviceId,
            request_id: CaptureRequestId,
        ) -> Self {
            let directory = tempfile::tempdir().expect("phone directory");
            let root = fs::canonicalize(directory.path()).expect("canonical root");
            let store = Arc::new(RedbV2Store::open(root.join("meshelf.redb")).expect("store"));
            let bytes = jpeg(4032, 3024, 5_000);
            let photo_dir = root.join("agent-captures").join(request_id.to_string());
            fs::create_dir_all(&photo_dir).expect("photo directory");
            let path = photo_dir.join("IMG_0001.jpg");
            fs::write(&path, &bytes).expect("photo");
            let created = now();
            let record = CaptureSourceRecord {
                request_id,
                requester,
                requester_label: "CEDAR".to_owned(),
                purpose: PURPOSE.to_owned(),
                lens: None,
                created_at_unix_ms: created,
                expires_at_unix_ms: created + 170_000,
                phase: CaptureSourcePhase::Presented,
            };
            assert!(matches!(
                store.present_capture(record).expect("present"),
                CapturePresentation::Presented { .. }
            ));
            let photo = CapturedPhoto {
                offer_id: OfferId::new(),
                descriptor: photo_descriptor(&bytes),
                path,
                sha256: sha256(&bytes),
                width: 4032,
                height: 3024,
                delete_deadline_unix_ms: created + 600_000,
            };
            assert!(matches!(
                store
                    .attach_captured(request_id, photo.clone())
                    .expect("attach"),
                CaptureTransition::Applied(_)
            ));
            assert!(matches!(
                store.mark_capture_announced(request_id).expect("announce"),
                CaptureTransition::Applied(_)
            ));
            let events = Arc::new(RecordingSourceEvents::default());
            let handler = Arc::new(OfferFetchHandler::with_resolver(
                device,
                Arc::new(CaptureSourceResolver::new(store.clone(), events.clone())),
            ));
            Self {
                _directory: directory,
                store,
                events,
                handler,
                device,
                request_id,
                photo,
                bytes,
            }
        }

        fn phase(&self) -> CaptureSourcePhase {
            self.store
                .get_capture_source(self.request_id)
                .expect("read")
                .expect("row")
                .phase
        }

        /// Starts serving one fetch of this photo to `requester`, as the listener would.
        async fn serve(
            &self,
            requester: DeviceId,
        ) -> (TcpStream, FetchRequest, JoinHandle<Result<(), NetError>>) {
            let request = FetchRequest::new(self.photo.offer_id, self.device, requester);
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind");
            let address = listener.local_addr().expect("address");
            let handler = self.handler.clone();
            let served = request.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                handler
                    .handle_fetch(requester, served, &mut stream, IO)
                    .await
            });
            let client = TcpStream::connect(address).await.expect("connect");
            (client, request, server)
        }
    }

    /// Plays the requester by hand through `FetchComplete`.
    async fn pull_through_complete(client: &mut TcpStream, request: &FetchRequest, bytes: &[u8]) {
        let V2Message::FetchHeader(header) = read_frame(client).await else {
            panic!("expected fetch header");
        };
        assert_eq!(header.request_id, request.request_id);
        assert!(matches!(
            read_frame(client).await,
            V2Message::ManifestChunk(_)
        ));
        assert!(matches!(
            read_frame(client).await,
            V2Message::ManifestEnd(_)
        ));
        write_v2_frame_async(
            client,
            &V2Message::FetchAdmission(FetchAdmission {
                request_id: request.request_id,
                code: FetchAdmissionCode::Accepted,
                entries_reserved: 1,
                bytes_reserved: bytes.len() as u64,
                detail: None,
            }),
        )
        .await
        .expect("admission");
        assert!(matches!(read_frame(client).await, V2Message::FileStart(_)));
        let mut payload = vec![0_u8; bytes.len()];
        timeout(IO, client.read_exact(&mut payload))
            .await
            .expect("payload in time")
            .expect("payload");
        assert_eq!(payload, bytes);
        assert!(matches!(read_frame(client).await, V2Message::FileEnd(_)));
        assert!(matches!(
            read_frame(client).await,
            V2Message::FetchComplete(_)
        ));
    }

    async fn send_receipt(
        client: &mut TcpStream,
        request: &FetchRequest,
        code: FetchReceiptCode,
        bytes_received: u64,
    ) {
        write_v2_frame_async(
            client,
            &V2Message::FetchReceipt(FetchReceipt {
                request_id: request.request_id,
                offer_id: request.offer_id,
                code,
                files_received: 1,
                bytes_received,
                detail: None,
            }),
        )
        .await
        .expect("receipt");
    }

    #[tokio::test]
    async fn a_validated_completed_receipt_marks_the_photo_delivered_and_announces_it_once() {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let (mut client, request, server) = phone.serve(requester).await;
        pull_through_complete(&mut client, &request, &phone.bytes).await;
        send_receipt(
            &mut client,
            &request,
            FetchReceiptCode::Completed,
            phone.bytes.len() as u64,
        )
        .await;
        server.await.expect("join").expect("served");
        assert_eq!(phone.phase(), CaptureSourcePhase::Delivered);
        assert_eq!(phone.events.delivered(), vec![phone.request_id]);
        assert!(phone.events.withdrawn().is_empty());
    }

    #[tokio::test]
    async fn a_receipt_lost_after_fetch_complete_leaves_the_photo_uncertain_and_never_served_again()
    {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let (mut client, request, server) = phone.serve(requester).await;
        pull_through_complete(&mut client, &request, &phone.bytes).await;
        drop(client);
        assert!(server.await.expect("join").is_err());
        assert_eq!(
            phone.phase(),
            CaptureSourcePhase::UncertainNoReplay {
                deadline_unix_ms: phone.photo.delete_deadline_unix_ms,
                path: phone.photo.path.clone(),
            }
        );
        assert!(
            phone.events.delivered().is_empty(),
            "an unconfirmed photo must never be reported delivered"
        );
        assert!(phone.events.withdrawn().is_empty());

        let (mut again, _, server) = phone.serve(requester).await;
        let V2Message::FetchRefusal(refusal) = read_frame(&mut again).await else {
            panic!("expected refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::UnknownOffer);
        server.await.expect("join").expect("refused");
    }

    #[tokio::test]
    async fn a_completed_receipt_with_the_wrong_byte_count_is_not_a_delivery() {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let (mut client, request, server) = phone.serve(requester).await;
        pull_through_complete(&mut client, &request, &phone.bytes).await;
        send_receipt(
            &mut client,
            &request,
            FetchReceiptCode::Completed,
            phone.bytes.len() as u64 - 1,
        )
        .await;
        assert!(server.await.expect("join").is_err());
        assert!(matches!(
            phone.phase(),
            CaptureSourcePhase::UncertainNoReplay { .. }
        ));
        assert!(phone.events.delivered().is_empty());
    }

    #[tokio::test]
    async fn a_photo_is_served_at_most_once_even_to_the_device_that_asked_for_it() {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let (mut first, _, first_server) = phone.serve(requester).await;
        assert!(matches!(
            read_frame(&mut first).await,
            V2Message::FetchHeader(_)
        ));
        let (mut second, _, second_server) = phone.serve(requester).await;
        let V2Message::FetchRefusal(refusal) = read_frame(&mut second).await else {
            panic!("expected refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::SourceUnavailable);
        second_server.await.expect("join").expect("refused");
        drop(first);
        let _ = first_server.await.expect("join");
    }

    #[tokio::test]
    async fn a_fetch_that_fails_before_fetch_complete_ends_failed_so_the_photo_may_go_now() {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let (mut client, request, server) = phone.serve(requester).await;
        assert!(matches!(
            read_frame(&mut client).await,
            V2Message::FetchHeader(_)
        ));
        assert!(matches!(
            read_frame(&mut client).await,
            V2Message::ManifestChunk(_)
        ));
        assert!(matches!(
            read_frame(&mut client).await,
            V2Message::ManifestEnd(_)
        ));
        write_v2_frame_async(
            &mut client,
            &V2Message::FetchAdmission(FetchAdmission {
                request_id: request.request_id,
                code: FetchAdmissionCode::InsufficientSpace,
                entries_reserved: 0,
                bytes_reserved: 0,
                detail: None,
            }),
        )
        .await
        .expect("refused admission");
        assert!(server.await.expect("join").is_err());
        assert_eq!(
            phone.phase(),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );
        assert_eq!(phone.events.withdrawn(), vec![(phone.request_id, "failed")]);
        assert!(phone.events.delivered().is_empty());
    }

    /// The phone hashes a photo when the person takes it and announces that digest. If the file
    /// changes afterwards, every size, name and metadata check still passes — the serving plan is
    /// built from the file as it is now — so the recorded digest is the only thing that can tell
    /// the swapped bytes from the captured ones. It has to be checked here: the requester verifies
    /// what it receives against the digest this same stream declares, so a phone that streamed
    /// whatever the file holds would be verified as correct and would publish the wrong photo.
    #[tokio::test]
    async fn a_photo_whose_bytes_changed_after_capture_is_never_completed_to_its_requester() {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let mut swapped = phone.bytes.clone();
        // One byte inside the entropy-coded filler: same length, same name, different photo.
        let filler = swapped.len() - 3;
        swapped[filler] ^= 0x01;
        assert_ne!(swapped, phone.bytes);
        fs::write(&phone.photo.path, &swapped).expect("swap the photo file");

        let (mut client, request, server) = phone.serve(requester).await;
        let V2Message::FetchHeader(header) = read_frame(&mut client).await else {
            panic!("expected fetch header");
        };
        assert_eq!(header.descriptor, photo_descriptor(&phone.bytes));
        assert!(matches!(
            read_frame(&mut client).await,
            V2Message::ManifestChunk(_)
        ));
        assert!(matches!(
            read_frame(&mut client).await,
            V2Message::ManifestEnd(_)
        ));
        write_v2_frame_async(
            &mut client,
            &V2Message::FetchAdmission(FetchAdmission {
                request_id: request.request_id,
                code: FetchAdmissionCode::Accepted,
                entries_reserved: 1,
                bytes_reserved: swapped.len() as u64,
                detail: None,
            }),
        )
        .await
        .expect("admission");
        assert!(matches!(
            read_frame(&mut client).await,
            V2Message::FileStart(_)
        ));
        let mut payload = vec![0_u8; swapped.len()];
        timeout(IO, client.read_exact(&mut payload))
            .await
            .expect("payload in time")
            .expect("payload");
        // Raw bytes crossed the wire, so the phone closes without a file end: the requester is
        // left with nothing it can verify or publish.
        let next = timeout(IO, read_v2_frame_async(&mut client))
            .await
            .expect("the phone closes the connection instead of holding it open");
        assert!(
            next.is_err(),
            "a digest mismatch ends the stream; no frame may follow it, got {next:?}"
        );
        let mut tail = Vec::new();
        timeout(IO, client.read_to_end(&mut tail))
            .await
            .expect("the connection closes")
            .expect("read the tail of the stream");
        assert!(tail.is_empty(), "nothing follows the truncated payload");
        server
            .await
            .expect("join")
            .expect("serving ends without error");
        assert_eq!(
            phone.phase(),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );
        assert_eq!(phone.events.withdrawn(), vec![(phone.request_id, "failed")]);
        assert!(phone.events.delivered().is_empty());
    }

    /// A fetch that stops before `FetchComplete` — here a refusal, because the phone's own cache
    /// sweep removed the photo file — ends the claim `Failed`, never uncertain. The requester
    /// publishes only after the last byte and that frame, so a stop before it provably delivered
    /// nothing; `Failed` is what releases the photo for deletion now instead of holding the row
    /// open to its uncertain deadline for a copy that cannot exist.
    #[tokio::test]
    async fn a_fetch_stopped_before_fetch_complete_ends_failed_not_uncertain_so_the_photo_may_go_now()
     {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        fs::remove_file(&phone.photo.path).expect("the phone's sweep removes the photo file");

        let (mut client, _, server) = phone.serve(requester).await;
        let V2Message::FetchRefusal(refusal) = read_frame(&mut client).await else {
            panic!("expected a refusal before any byte");
        };
        assert_eq!(refusal.code, FetchRefusalCode::SourceUnavailable);
        server
            .await
            .expect("join")
            .expect("a refusal is not an error");
        assert_eq!(
            phone.phase(),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            },
            "a stop before fetch complete delivered nothing, so the photo may be deleted at once"
        );
        assert_eq!(phone.events.withdrawn(), vec![(phone.request_id, "failed")]);
        assert!(phone.events.delivered().is_empty());
    }

    #[tokio::test]
    async fn a_receipt_affirming_nothing_was_published_ends_the_photo_failed_and_withdraws_it() {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let (mut client, request, server) = phone.serve(requester).await;
        pull_through_complete(&mut client, &request, &phone.bytes).await;
        send_receipt(
            &mut client,
            &request,
            FetchReceiptCode::VerificationFailed,
            phone.bytes.len() as u64,
        )
        .await;
        assert!(server.await.expect("join").is_err());
        assert_eq!(
            phone.phase(),
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );
        assert_eq!(phone.events.withdrawn(), vec![(phone.request_id, "failed")]);
    }

    #[tokio::test]
    async fn a_third_peer_is_refused_and_the_photo_stays_available_to_its_requester() {
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let fern = DeviceId::new();
        let (mut client, _, server) = phone.serve(fern).await;
        let V2Message::FetchRefusal(refusal) = read_frame(&mut client).await else {
            panic!("expected refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::NotAnnouncedToRequester);
        server.await.expect("join").expect("refused");
        assert!(matches!(
            phone.phase(),
            CaptureSourcePhase::Announced { .. }
        ));

        let (mut client, request, server) = phone.serve(requester).await;
        pull_through_complete(&mut client, &request, &phone.bytes).await;
        send_receipt(
            &mut client,
            &request,
            FetchReceiptCode::Completed,
            phone.bytes.len() as u64,
        )
        .await;
        server.await.expect("join").expect("served");
        assert_eq!(phone.phase(), CaptureSourcePhase::Delivered);
    }

    // --- Phone capture requests ----------------------------------------------------------------

    fn phone_receiver(
        refuse_presented: bool,
    ) -> (
        tempfile::TempDir,
        Arc<RedbV2Store>,
        Arc<RecordingSourceEvents>,
        PhoneCaptureReceiver,
    ) {
        let directory = tempfile::tempdir().expect("phone directory");
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("meshelf.redb")).expect("store"));
        let events = Arc::new(RecordingSourceEvents {
            store: Some(store.clone()),
            refuse_presented,
            ..RecordingSourceEvents::default()
        });
        let receiver = PhoneCaptureReceiver::new(store.clone(), events.clone());
        (directory, store, events, receiver)
    }

    fn capture_request(requester: DeviceId, phone: DeviceId) -> CaptureRequest {
        let created = now();
        CaptureRequest::photo(
            CaptureRequestId::new(),
            requester,
            phone,
            created,
            created + 170_000,
            PURPOSE,
        )
    }

    #[tokio::test]
    async fn a_request_is_acknowledged_presented_only_after_its_row_is_durable_and_its_event_queued()
     {
        let (_directory, store, events, receiver) = phone_receiver(false);
        let (requester, phone) = (DeviceId::new(), DeviceId::new());
        let request = capture_request(requester, phone);
        let ack = receiver
            .handle_capture_request(requester, "CEDAR", phone, request.clone())
            .await
            .expect("ack");
        assert_eq!(ack.code, CaptureAckCode::Presented);
        assert_eq!(
            events.presented.lock().expect("presented").clone(),
            vec![(request.request_id, true)],
            "the event must see a durable row"
        );
        assert_eq!(
            store
                .get_capture_source(request.request_id)
                .expect("read")
                .expect("row")
                .requester_label,
            "CEDAR"
        );

        // A repeated request id repeats the acknowledgement without presenting it again.
        let repeat = receiver
            .handle_capture_request(requester, "CEDAR", phone, request)
            .await
            .expect("ack");
        assert_eq!(repeat.code, CaptureAckCode::Presented);
        assert_eq!(events.presented.lock().expect("presented").len(), 1);
    }

    #[tokio::test]
    async fn a_second_live_request_is_busy_and_an_expired_one_is_expired_without_a_row() {
        let (_directory, store, events, receiver) = phone_receiver(false);
        let (requester, phone) = (DeviceId::new(), DeviceId::new());
        let first = receiver
            .handle_capture_request(requester, "CEDAR", phone, capture_request(requester, phone))
            .await
            .expect("ack");
        assert_eq!(first.code, CaptureAckCode::Presented);
        let busy = receiver
            .handle_capture_request(requester, "CEDAR", phone, capture_request(requester, phone))
            .await
            .expect("ack");
        assert_eq!(busy.code, CaptureAckCode::Busy);

        let created = now() - 170_000;
        let stale = CaptureRequest::photo(
            CaptureRequestId::new(),
            requester,
            phone,
            created,
            created + 169_000,
            PURPOSE,
        );
        let expired = receiver
            .handle_capture_request(requester, "CEDAR", phone, stale.clone())
            .await
            .expect("ack");
        assert_eq!(expired.code, CaptureAckCode::Expired);
        assert!(
            store
                .get_capture_source(stale.request_id)
                .expect("read")
                .is_none()
        );
        assert_eq!(events.presented.lock().expect("presented").len(), 1);
    }

    #[tokio::test]
    async fn a_request_the_phone_cannot_present_is_refused_and_does_not_hold_the_phone_busy() {
        let (_directory, store, _events, receiver) = phone_receiver(true);
        let (requester, phone) = (DeviceId::new(), DeviceId::new());
        let request = capture_request(requester, phone);
        let ack = receiver
            .handle_capture_request(requester, "CEDAR", phone, request.clone())
            .await
            .expect("ack");
        assert_eq!(ack.code, CaptureAckCode::Refused);
        assert_eq!(
            store
                .get_capture_source(request.request_id)
                .expect("read")
                .expect("row")
                .phase,
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );
        // The phone is free for the next request rather than busy until expiry.
        let next = capture_request(requester, phone);
        assert!(matches!(
            store
                .present_capture(CaptureSourceRecord {
                    request_id: next.request_id,
                    requester,
                    requester_label: "CEDAR".to_owned(),
                    purpose: PURPOSE.to_owned(),
                    lens: None,
                    created_at_unix_ms: next.created_at_unix_ms,
                    expires_at_unix_ms: next.expires_at_unix_ms,
                    phase: CaptureSourcePhase::Presented,
                })
                .expect("present"),
            CapturePresentation::Presented { .. }
        ));
    }

    #[tokio::test]
    async fn a_requester_cancel_is_recorded_and_withdrawn_before_it_is_acknowledged() {
        let (_directory, store, events, receiver) = phone_receiver(false);
        let (requester, phone) = (DeviceId::new(), DeviceId::new());
        let request = capture_request(requester, phone);
        receiver
            .handle_capture_request(requester, "CEDAR", phone, request.clone())
            .await
            .expect("presented");
        let cancel = CaptureStatus {
            request_id: request.request_id,
            code: CaptureStatusCode::Cancelled,
            detail: None,
        };
        assert!(
            receiver
                .handle_capture_status(DeviceId::new(), phone, cancel.clone())
                .await
                .is_err(),
            "only the requester may cancel"
        );
        let acknowledged = receiver
            .handle_capture_status(requester, phone, cancel.clone())
            .await
            .expect("recorded");
        assert_eq!(acknowledged, cancel);
        assert_eq!(
            store
                .get_capture_source(request.request_id)
                .expect("read")
                .expect("row")
                .phase,
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Cancelled
            }
        );
        assert_eq!(events.withdrawn(), vec![(request.request_id, "cancelled")]);
    }

    #[tokio::test]
    async fn an_uncertain_receipt_keeps_the_photo_until_its_deadline_because_the_requester_may_hold_it()
     {
        // The requester answers `UncertainNoReplay` when the photo may already be published. Only
        // a validated completed receipt proves delivery and only an affirmed failure disproves
        // it; anything between keeps the photo, never served again, until its delete deadline.
        let requester = DeviceId::new();
        let phone =
            Phone::with_announced_photo(DeviceId::new(), requester, CaptureRequestId::new());
        let (mut client, request, server) = phone.serve(requester).await;
        pull_through_complete(&mut client, &request, &phone.bytes).await;
        send_receipt(
            &mut client,
            &request,
            FetchReceiptCode::UncertainNoReplay,
            phone.bytes.len() as u64,
        )
        .await;
        assert!(server.await.expect("join").is_err());
        assert_eq!(
            phone.phase(),
            CaptureSourcePhase::UncertainNoReplay {
                deadline_unix_ms: phone.photo.delete_deadline_unix_ms,
                path: phone.photo.path.clone(),
            }
        );
        assert!(
            phone.events.withdrawn().is_empty(),
            "a photo the requester may hold must not be deleted early"
        );
        assert!(phone.events.delivered().is_empty());
    }

    #[tokio::test]
    async fn a_repeated_request_id_repeats_the_ack_its_stored_row_implies_so_a_failed_request_fails_fast()
     {
        // The first delivery could not be presented, so the row ended failed. A repeat of the
        // same id must say so; a blind `Presented` would arm the requester for a photo that will
        // never come, and it would wait until expiry instead of failing now.
        let (_directory, _store, events, receiver) = phone_receiver(true);
        let (requester, phone) = (DeviceId::new(), DeviceId::new());
        let request = capture_request(requester, phone);
        let first = receiver
            .handle_capture_request(requester, "CEDAR", phone, request.clone())
            .await
            .expect("ack");
        assert_eq!(first.code, CaptureAckCode::Refused);
        let repeat = receiver
            .handle_capture_request(requester, "CEDAR", phone, request)
            .await
            .expect("ack");
        assert_eq!(repeat.code, CaptureAckCode::Refused);
        assert_eq!(repeat.detail.as_deref(), Some("failed"));
        assert_eq!(
            events.presented.lock().expect("presented").len(),
            1,
            "a repeat is never presented again"
        );

        // A request that expired on the phone repeats as expired; a live one as presented.
        let (_directory, store, _events, receiver) = phone_receiver(false);
        let expired = capture_request(requester, phone);
        receiver
            .handle_capture_request(requester, "CEDAR", phone, expired.clone())
            .await
            .expect("presented");
        store
            .terminate_capture_source(expired.request_id, CaptureSourceTerminalCode::Expired)
            .expect("expire");
        let repeat = receiver
            .handle_capture_request(requester, "CEDAR", phone, expired)
            .await
            .expect("ack");
        assert_eq!(repeat.code, CaptureAckCode::Expired);

        let live = capture_request(requester, phone);
        receiver
            .handle_capture_request(requester, "CEDAR", phone, live.clone())
            .await
            .expect("presented");
        let repeat = receiver
            .handle_capture_request(requester, "CEDAR", phone, live)
            .await
            .expect("ack");
        assert_eq!(repeat.code, CaptureAckCode::Presented);
    }

    // --- Requester status ----------------------------------------------------------------------

    #[tokio::test]
    async fn a_phone_status_is_recorded_before_it_is_acknowledged_and_only_from_that_phone() {
        let requester = Requester::new();
        let phone = DeviceId::new();
        let events = Arc::new(RecordingRequestEvents::default());
        let receiver = RequesterCaptureReceiver::new(requester.store.clone(), events.clone());
        let request = requester.armed(phone, requester.output());
        let declined = CaptureStatus {
            request_id: request.request_id,
            code: CaptureStatusCode::Declined,
            detail: Some("user-declined".to_owned()),
        };
        assert!(
            receiver
                .handle_capture_status(DeviceId::new(), DeviceId::new(), declined.clone())
                .await
                .is_err(),
            "another device cannot end this request"
        );
        assert!(matches!(
            requester.phase(request.request_id),
            CaptureRequestPhase::Armed { .. }
        ));

        let acknowledged = receiver
            .handle_capture_status(phone, DeviceId::new(), declined.clone())
            .await
            .expect("recorded");
        assert_eq!(acknowledged, declined);
        assert_eq!(
            terminal_code(&requester.phase(request.request_id)),
            Some(CaptureTerminalCode::Declined)
        );
        assert_eq!(events.finished.lock().expect("events").len(), 1);
        // A repeat is already recorded and acknowledged again, with no second wake-up.
        receiver
            .handle_capture_status(phone, DeviceId::new(), declined)
            .await
            .expect("repeat");
        assert_eq!(events.finished.lock().expect("events").len(), 1);
    }

    #[tokio::test]
    async fn a_phone_status_cannot_end_a_claimed_pull() {
        let requester = Requester::new();
        let phone = DeviceId::new();
        let receiver = RequesterCaptureReceiver::new(
            requester.store.clone(),
            Arc::new(RecordingRequestEvents::default()),
        );
        let bytes = jpeg(4032, 3024, 64);
        let pull = requester.claimed(phone, requester.output(), photo_descriptor(&bytes));
        let failed = CaptureStatus {
            request_id: pull.request_id,
            code: CaptureStatusCode::Failed,
            detail: None,
        };
        assert!(
            receiver
                .handle_capture_status(phone, DeviceId::new(), failed)
                .await
                .is_err()
        );
        assert!(matches!(
            requester.phase(pull.request_id),
            CaptureRequestPhase::Claimed { .. }
        ));
    }

    // --- End to end over loopback --------------------------------------------------------------

    /// The one place a listener is started, so a change to the serve entry point touches only
    /// this helper.
    async fn spawn_server(
        identity: &InstallationIdentity,
        name: &str,
        allowed: DeviceId,
        services: V2OfferServices,
        capture_receiver: Arc<dyn V2CaptureReceiver>,
        capabilities: &[&str],
    ) -> (
        SocketAddr,
        watch::Sender<bool>,
        JoinHandle<Result<(), NetError>>,
    ) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut config = V2ServerConfig::desktop(
            ServerIdentity {
                signing_identity: identity.clone(),
                device_name: name.to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new([allowed])),
            services,
            IO,
        );
        // Only the capture policy differs between the two test listeners.
        config.capture_receiver = capture_receiver;
        config.server_capabilities = capabilities
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect();
        let server = tokio::spawn(serve_v2(listener, config, shutdown_rx));
        (address, shutdown_tx, server)
    }

    /// The resident's launcher, reduced to what the test needs: it pulls from a known address.
    struct PullingLauncher {
        service: Arc<ActivationService<NoClipboard>>,
        identity: InstallationIdentity,
        phone_address: SocketAddr,
        phone_key: Vec<u8>,
        launches: AtomicUsize,
        results: tokio::sync::mpsc::UnboundedSender<Result<CaptureRequestRecord, NetError>>,
    }

    impl CapturePullLauncher for PullingLauncher {
        fn launch(&self, pull: ClaimedCapturePull) -> Result<(), CaptureLaunchRefused> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            let service = self.service.clone();
            let hello = ClientHello::signed_v2(
                self.identity.device_id,
                "CEDAR",
                pull.activation_id.to_string(),
                &self.identity,
            );
            let (address, key, results) = (
                self.phone_address,
                self.phone_key.clone(),
                self.results.clone(),
            );
            tokio::spawn(async move {
                let (cancel_tx, cancel_rx) = watch::channel(false);
                let result = run_capture_pull(
                    &service,
                    &PeerClient::with_timeouts(IO, IO),
                    address,
                    hello,
                    &key,
                    &pull,
                    cancel_rx,
                )
                .await;
                drop(cancel_tx);
                let _ = results.send(result);
            });
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_correlated_announcement_pulls_the_photo_to_the_exact_path_once_and_the_phone_records_one_delivery()
     {
        let phone_identity = InstallationIdentity::generate();
        let desktop_identity = InstallationIdentity::generate();
        let (phone_id, desktop_id) = (phone_identity.device_id, desktop_identity.device_id);

        // Desktop: a full shelf the capture must not disturb, and one armed request.
        let desktop = Requester::new();
        for index in 0..meshelf_core::V2_MAX_LIVE_ENTRIES {
            desktop
                .store
                .insert_offer_card(OfferCardInput::new(
                    phone_id,
                    OfferId::new(),
                    OfferDescriptor::text(format!("kept {index}")).expect("text"),
                    CardAvailability::Available,
                ))
                .expect("card");
        }
        let shelf_before = desktop.store.read_offer_shelf().expect("shelf");
        assert_eq!(
            shelf_before.len(),
            meshelf_core::V2_MAX_LIVE_ENTRIES as usize
        );
        let request_id = CaptureRequestId::new();
        desktop.armed_with_id(request_id, phone_id, desktop.output());

        // Phone: the photo is captured and announced to the requester only.
        let phone = Phone::with_announced_photo(phone_id, desktop_id, request_id);
        let (phone_address, phone_shutdown, phone_server) = spawn_server(
            &phone_identity,
            "amber",
            desktop_id,
            V2OfferServices {
                announcement_receiver: Arc::new(OfferAnnouncementHandler::new(phone.store.clone())),
                fetch_sender: phone.handler.clone(),
            },
            Arc::new(PhoneCaptureReceiver::new(
                phone.store.clone(),
                phone.events.clone(),
            )),
            &[CAP_OFFER_PULL_V2, CAP_CAPTURE_PHOTO_V1],
        )
        .await;

        let service = Arc::new(ActivationService::with_ledger(
            desktop_id,
            desktop.store.clone(),
            Arc::new(NoClipboard),
            desktop.root.clone(),
            ReservationLedger::default(),
        ));
        let (results_tx, mut results) = tokio::sync::mpsc::unbounded_channel();
        let launcher = Arc::new(PullingLauncher {
            service,
            identity: desktop_identity.clone(),
            phone_address,
            phone_key: phone_identity.public_key().to_vec(),
            launches: AtomicUsize::new(0),
            results: results_tx,
        });
        let request_events = Arc::new(RecordingRequestEvents::default());
        let (desktop_address, desktop_shutdown, desktop_server) = spawn_server(
            &desktop_identity,
            "CEDAR",
            phone_id,
            V2OfferServices {
                announcement_receiver: Arc::new(
                    OfferAnnouncementHandler::new(desktop.store.clone()).with_capture_router(
                        Arc::new(RequesterCaptureRouter::new(
                            desktop.store.clone(),
                            launcher.clone(),
                            request_events.clone(),
                        )),
                    ),
                ),
                fetch_sender: Arc::new(OfferFetchHandler::new(desktop_id, desktop.store.clone())),
            },
            Arc::new(RequesterCaptureReceiver::new(
                desktop.store.clone(),
                request_events,
            )),
            &[CAP_OFFER_PULL_V2, CAP_CAPTURE_REQUEST_V1],
        )
        .await;

        let announcement = OfferAnnouncement::new(
            phone.photo.offer_id,
            phone_id,
            desktop_id,
            now(),
            phone.photo.descriptor.clone(),
        )
        .with_capture(CaptureCorrelation { request_id });
        let ack = PeerClient::with_timeouts(IO, IO)
            .announce_offer_v2(
                desktop_address,
                ClientHello::signed_v2(phone_id, "amber", "announce", &phone_identity),
                announcement,
                &desktop_identity.public_key(),
            )
            .await
            .expect("announce");
        assert_eq!(ack.code, OfferAckCode::Stored);
        assert_eq!(ack.pruned_entries, 0);

        let record = timeout(IO, results.recv())
            .await
            .expect("pull finished in time")
            .expect("pull result")
            .expect("pull");
        assert_eq!(
            record.phase,
            CaptureRequestPhase::Completed {
                receipt: CaptureReceipt {
                    output_path: desktop.output(),
                    sha256: sha256(&phone.bytes),
                    bytes: phone.bytes.len() as u64,
                    width: 4032,
                    height: 3024,
                }
            }
        );
        assert_eq!(fs::read(desktop.output()).expect("published"), phone.bytes);
        assert_eq!(
            entry_names(&desktop.output_dir),
            BTreeSet::from(["router-label.jpg".to_owned()])
        );

        // The phone records the delivery after reading the receipt, on its own connection task.
        let deadline = std::time::Instant::now() + IO;
        while phone.phase() != CaptureSourcePhase::Delivered {
            assert!(
                std::time::Instant::now() < deadline,
                "phone never recorded the delivery: {:?}",
                phone.phase()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(phone.events.delivered(), vec![request_id]);
        assert!(phone.events.withdrawn().is_empty());
        assert_eq!(launcher.launches.load(Ordering::SeqCst), 1);
        assert_eq!(
            desktop.store.read_offer_shelf().expect("shelf after"),
            shelf_before
        );

        let _ = phone_shutdown.send(true);
        let _ = desktop_shutdown.send(true);
        phone_server.await.expect("join").expect("phone server");
        desktop_server.await.expect("join").expect("desktop server");
    }
}
