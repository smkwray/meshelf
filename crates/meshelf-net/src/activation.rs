//! Resident-owned activation service and the typed terminal result it returns.
//!
//! Recovery cleanup runs once before the first admission. Concurrent activations share
//! journal ownership, cancellation, and clipboard-uncertainty flags. A dropped future
//! cannot skip cleanup: cooperative cancel completes the state machine, and a staging
//! guard removes residue if the future is dropped before the clipboard side-effect.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use meshelf_core::{ActivationId, DeviceId};
use meshelf_protocol::{
    ClientHello, FetchAbortCode, FetchAdmissionCode, FetchReceiptCode, FetchRefusalCode,
    FetchRequest,
};
use meshelf_store::RedbV2Store;
use tokio::sync::watch;

use crate::{
    FetchActivation, FetchClipboard, FetchReceiver, NetError, PeerClient, ReservationLedger,
};

/// Two concurrent activations are allowed; a third is refused busy, never queued.
pub const MAX_CONCURRENT_ACTIVATIONS: usize = 2;

/// One typed terminal result for FetchReceiver, PeerClient, and both resident surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    Completed,
    Refused(ActivationRefuseCode),
    Failed(ActivationFailCode),
    Cancelled,
    UncertainNoReplay,
}

/// Pre-admission refusal from the origin or from receiver admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationRefuseCode {
    UnknownOffer,
    NotAnnouncedToRequester,
    SourceUnavailable,
    SourceChanged,
    Busy,
    Malformed,
    Unsupported,
    InvalidManifest,
    TooLarge,
    InsufficientSpace,
    DestinationUnavailable,
    AllocationFailed,
    UnsupportedMode,
    DuplicateActivation,
}

/// Post-admission failure. Origin abort codes are preserved here, not collapsed to Cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationFailCode {
    SourceUnavailable,
    SourceChanged,
    VerificationFailed,
    ClipboardFailed,
    ConnectionLost,
    LocalIo,
    Protocol,
    InternalError,
}

impl ActivationOutcome {
    /// Status line for the desktop and `meshelfctl`. Only [`Self::Completed`] mentions completion.
    #[must_use]
    pub fn desktop_status(&self) -> String {
        match self {
            Self::Completed => "Offer activation completed".to_owned(),
            Self::Refused(code) => format!("Offer activation refused ({code})"),
            Self::Failed(code) => format!("Offer activation failed ({code})"),
            Self::Cancelled => "Offer activation cancelled".to_owned(),
            Self::UncertainNoReplay => {
                "Offer activation is uncertain and will not be replayed".to_owned()
            }
        }
    }

    #[must_use]
    pub const fn is_completed(self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl fmt::Display for ActivationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.desktop_status())
    }
}

impl fmt::Display for ActivationRefuseCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownOffer => "unknown offer",
            Self::NotAnnouncedToRequester => "not announced to requester",
            Self::SourceUnavailable => "source unavailable",
            Self::SourceChanged => "source changed",
            Self::Busy => "busy",
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
            Self::InvalidManifest => "invalid manifest",
            Self::TooLarge => "too large",
            Self::InsufficientSpace => "insufficient space",
            Self::DestinationUnavailable => "destination unavailable",
            Self::AllocationFailed => "allocation failed",
            Self::UnsupportedMode => "unsupported mode",
            Self::DuplicateActivation => "duplicate activation",
        })
    }
}

impl fmt::Display for ActivationFailCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailable => "source unavailable",
            Self::SourceChanged => "source changed",
            Self::VerificationFailed => "verification failed",
            Self::ClipboardFailed => "clipboard failed",
            Self::ConnectionLost => "connection lost",
            Self::LocalIo => "local storage failed",
            Self::Protocol => "protocol error",
            Self::InternalError => "internal error",
        })
    }
}

impl From<FetchRefusalCode> for ActivationRefuseCode {
    fn from(code: FetchRefusalCode) -> Self {
        match code {
            FetchRefusalCode::UnknownOffer => Self::UnknownOffer,
            FetchRefusalCode::NotAnnouncedToRequester => Self::NotAnnouncedToRequester,
            FetchRefusalCode::SourceUnavailable => Self::SourceUnavailable,
            FetchRefusalCode::SourceChanged => Self::SourceChanged,
            FetchRefusalCode::Busy => Self::Busy,
            FetchRefusalCode::Malformed => Self::Malformed,
            FetchRefusalCode::Unsupported => Self::Unsupported,
        }
    }
}

impl From<FetchAdmissionCode> for ActivationOutcome {
    fn from(code: FetchAdmissionCode) -> Self {
        match code {
            FetchAdmissionCode::Accepted => Self::Completed,
            FetchAdmissionCode::Cancelled => Self::Cancelled,
            FetchAdmissionCode::RefusedBusy => Self::Refused(ActivationRefuseCode::Busy),
            FetchAdmissionCode::InvalidManifest => {
                Self::Refused(ActivationRefuseCode::InvalidManifest)
            }
            FetchAdmissionCode::TooLarge => Self::Refused(ActivationRefuseCode::TooLarge),
            FetchAdmissionCode::InsufficientSpace => {
                Self::Refused(ActivationRefuseCode::InsufficientSpace)
            }
            FetchAdmissionCode::DestinationUnavailable => {
                Self::Refused(ActivationRefuseCode::DestinationUnavailable)
            }
            FetchAdmissionCode::AllocationFailed => {
                Self::Refused(ActivationRefuseCode::AllocationFailed)
            }
            FetchAdmissionCode::UnsupportedMode => {
                Self::Refused(ActivationRefuseCode::UnsupportedMode)
            }
        }
    }
}

impl From<FetchAbortCode> for ActivationOutcome {
    fn from(code: FetchAbortCode) -> Self {
        match code {
            FetchAbortCode::Cancelled => Self::Cancelled,
            FetchAbortCode::SourceUnavailable => {
                Self::Failed(ActivationFailCode::SourceUnavailable)
            }
            FetchAbortCode::SourceChanged => Self::Failed(ActivationFailCode::SourceChanged),
            FetchAbortCode::InternalError => Self::Failed(ActivationFailCode::InternalError),
        }
    }
}

impl From<FetchReceiptCode> for ActivationOutcome {
    fn from(code: FetchReceiptCode) -> Self {
        match code {
            FetchReceiptCode::Completed => Self::Completed,
            FetchReceiptCode::Cancelled => Self::Cancelled,
            FetchReceiptCode::UncertainNoReplay => Self::UncertainNoReplay,
            FetchReceiptCode::VerificationFailed => {
                Self::Failed(ActivationFailCode::VerificationFailed)
            }
            FetchReceiptCode::ClipboardFailed => Self::Failed(ActivationFailCode::ClipboardFailed),
            FetchReceiptCode::ConnectionLost => Self::Failed(ActivationFailCode::ConnectionLost),
            FetchReceiptCode::InternalError => Self::Failed(ActivationFailCode::InternalError),
        }
    }
}

/// Map a transport-level fetch error onto the typed activation result.
pub(crate) fn classify_activation_result(
    result: Result<(), NetError>,
) -> Result<ActivationOutcome, NetError> {
    match result {
        Ok(()) => Ok(ActivationOutcome::Completed),
        Err(NetError::FetchRefused { code, .. }) => Ok(ActivationOutcome::Refused(code.into())),
        Err(NetError::FetchAdmissionRefused { code, .. }) => Ok(ActivationOutcome::from(code)),
        Err(NetError::FetchTerminal { code, .. }) => Ok(ActivationOutcome::from(code)),
        Err(NetError::FetchAborted { code, .. }) => Ok(ActivationOutcome::from(code)),
        Err(NetError::Rejected(reason))
            if reason.contains("cleanup is unresolved") || reason.contains("uncertain") =>
        {
            Ok(ActivationOutcome::Refused(ActivationRefuseCode::Busy))
        }
        Err(NetError::Rejected(reason))
            if reason.contains("destination") || reason.contains("absolute") =>
        {
            Ok(ActivationOutcome::Refused(
                ActivationRefuseCode::DestinationUnavailable,
            ))
        }
        Err(NetError::IdentityMismatch(_)) => {
            Ok(ActivationOutcome::Refused(ActivationRefuseCode::Malformed))
        }
        Err(NetError::Timeout(_)) => Ok(ActivationOutcome::Failed(
            ActivationFailCode::ConnectionLost,
        )),
        Err(NetError::Protocol(_) | NetError::UnexpectedMessage(_)) => {
            Ok(ActivationOutcome::Failed(ActivationFailCode::Protocol))
        }
        Err(NetError::FetchLocalIo { .. }) => {
            Ok(ActivationOutcome::Failed(ActivationFailCode::LocalIo))
        }
        Err(NetError::Io(_)) => Ok(ActivationOutcome::Failed(
            ActivationFailCode::ConnectionLost,
        )),
        Err(
            NetError::FetchServiceOwned(_) | NetError::FetchService(_) | NetError::OfferStorage(_),
        ) => Ok(ActivationOutcome::Failed(ActivationFailCode::InternalError)),
        Err(error) => Err(error),
    }
}

pub(crate) struct SharedActivationOwner {
    recovered: AtomicBool,
    recovery_runs: AtomicUsize,
    recovery: Mutex<()>,
    live: Mutex<HashSet<ActivationId>>,
    pub(crate) cleanup_blocked: Arc<AtomicBool>,
    pub(crate) uncertain_clipboard: Arc<AtomicBool>,
}

pub(crate) fn shared_owner(store_path: &Path) -> Arc<SharedActivationOwner> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<SharedActivationOwner>>>> =
        OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    // Callers pass `RedbV2Store::path()`, already a `store_identity`. Re-deriving
    // from a raw spelling is how two equivalent paths used to get two owners.
    let key = store_path.to_path_buf();
    let mut map = registry.lock().unwrap_or_else(|error| error.into_inner());
    map.entry(key)
        .or_insert_with(|| {
            Arc::new(SharedActivationOwner {
                recovered: AtomicBool::new(false),
                recovery_runs: AtomicUsize::new(0),
                recovery: Mutex::new(()),
                live: Mutex::new(HashSet::new()),
                cleanup_blocked: Arc::new(AtomicBool::new(false)),
                uncertain_clipboard: Arc::new(AtomicBool::new(false)),
            })
        })
        .clone()
}

/// One logical owner per process and offer store. Recovery and in-flight IDs are shared
/// across every `ActivationService` constructed against the same store.
pub struct ActivationService<C>
where
    C: FetchClipboard,
{
    receiver: FetchReceiver<C>,
    owner: Arc<SharedActivationOwner>,
}

impl<C> ActivationService<C>
where
    C: FetchClipboard,
{
    #[must_use]
    pub fn new(
        local_device: DeviceId,
        store: Arc<RedbV2Store>,
        clipboard: Arc<C>,
        state_root: PathBuf,
    ) -> Self {
        Self::with_receiver(FetchReceiver::new(
            local_device,
            store,
            clipboard,
            state_root,
        ))
    }

    #[must_use]
    pub fn with_ledger(
        local_device: DeviceId,
        store: Arc<RedbV2Store>,
        clipboard: Arc<C>,
        state_root: PathBuf,
        ledger: ReservationLedger,
    ) -> Self {
        Self::with_receiver(FetchReceiver::with_ledger(
            local_device,
            store,
            clipboard,
            state_root,
            ledger,
        ))
    }

    #[must_use]
    pub fn with_receiver(receiver: FetchReceiver<C>) -> Self {
        let owner = shared_owner(receiver.store().path());
        Self { receiver, owner }
    }

    #[must_use]
    pub fn store(&self) -> &Arc<RedbV2Store> {
        self.receiver.store()
    }

    /// How many times startup recovery actually completed. Shared across every
    /// service constructed against the same store.
    #[must_use]
    pub fn recovery_runs(&self) -> usize {
        self.owner.recovery_runs.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn live_count(&self) -> usize {
        self.owner.live.lock().map(|live| live.len()).unwrap_or(0)
    }

    /// Run abandoned-journal cleanup once per store. Later calls, including those
    /// on a second `ActivationService` for the same store, are no-ops.
    pub fn recover(&self) -> Result<(), NetError> {
        let _guard = self.owner.recovery.lock().map_err(|_| {
            NetError::FetchServiceOwned("activation recovery lock is poisoned".to_owned())
        })?;
        if self.owner.recovered.load(Ordering::Acquire) {
            return Ok(());
        }
        self.receiver.startup_cleanup()?;
        self.owner.recovery_runs.fetch_add(1, Ordering::AcqRel);
        self.owner.recovered.store(true, Ordering::Release);
        Ok(())
    }

    /// Admit one activation through the shared receiver. Recovery runs first, once.
    #[allow(clippy::too_many_arguments)]
    pub async fn activate(
        &self,
        client: &PeerClient,
        address: SocketAddr,
        hello: ClientHello,
        request: FetchRequest,
        activation: FetchActivation,
        expected_server_public_key: &[u8],
        cancel: watch::Receiver<bool>,
    ) -> Result<ActivationOutcome, NetError> {
        self.recover()?;
        let request_id = activation.request_id;
        {
            let mut live = self.owner.live.lock().map_err(|_| {
                NetError::FetchServiceOwned("activation lock is poisoned".to_owned())
            })?;
            if live.contains(&request_id) {
                return Ok(ActivationOutcome::Refused(
                    ActivationRefuseCode::DuplicateActivation,
                ));
            }
            if live.len() >= MAX_CONCURRENT_ACTIVATIONS {
                return Ok(ActivationOutcome::Refused(ActivationRefuseCode::Busy));
            }
            live.insert(request_id);
        }
        let result = client
            .fetch_v2_with_cancel(
                address,
                hello,
                request,
                activation,
                expected_server_public_key,
                &self.receiver,
                Some(cancel),
            )
            .await;
        if let Ok(mut live) = self.owner.live.lock() {
            live.remove(&request_id);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_status_names_completion_only_for_completed() {
        let completed = ActivationOutcome::Completed.desktop_status();
        assert!(
            completed.to_ascii_lowercase().contains("completed"),
            "{completed}"
        );
        let non_completed = [
            ActivationOutcome::Refused(ActivationRefuseCode::SourceUnavailable),
            ActivationOutcome::Refused(ActivationRefuseCode::SourceChanged),
            ActivationOutcome::Refused(ActivationRefuseCode::DestinationUnavailable),
            ActivationOutcome::Refused(ActivationRefuseCode::InsufficientSpace),
            ActivationOutcome::Refused(ActivationRefuseCode::AllocationFailed),
            ActivationOutcome::Refused(ActivationRefuseCode::InvalidManifest),
            ActivationOutcome::Refused(ActivationRefuseCode::Busy),
            ActivationOutcome::Refused(ActivationRefuseCode::DuplicateActivation),
            ActivationOutcome::Failed(ActivationFailCode::SourceUnavailable),
            ActivationOutcome::Failed(ActivationFailCode::SourceChanged),
            ActivationOutcome::Failed(ActivationFailCode::VerificationFailed),
            ActivationOutcome::Failed(ActivationFailCode::ClipboardFailed),
            ActivationOutcome::Failed(ActivationFailCode::ConnectionLost),
            ActivationOutcome::Failed(ActivationFailCode::LocalIo),
            ActivationOutcome::Failed(ActivationFailCode::Protocol),
            ActivationOutcome::Failed(ActivationFailCode::InternalError),
            ActivationOutcome::Cancelled,
            ActivationOutcome::UncertainNoReplay,
        ];
        for outcome in non_completed {
            let status = outcome.desktop_status();
            assert!(
                !status.to_ascii_lowercase().contains("completed"),
                "{outcome:?} displayed as {status}"
            );
        }
    }

    #[test]
    fn abort_codes_are_not_collapsed_to_cancelled() {
        assert_eq!(
            ActivationOutcome::from(FetchAbortCode::SourceUnavailable),
            ActivationOutcome::Failed(ActivationFailCode::SourceUnavailable)
        );
        assert_eq!(
            ActivationOutcome::from(FetchAbortCode::SourceChanged),
            ActivationOutcome::Failed(ActivationFailCode::SourceChanged)
        );
        assert_eq!(
            ActivationOutcome::from(FetchAbortCode::InternalError),
            ActivationOutcome::Failed(ActivationFailCode::InternalError)
        );
        assert_eq!(
            ActivationOutcome::from(FetchAbortCode::Cancelled),
            ActivationOutcome::Cancelled
        );
    }

    #[test]
    fn local_storage_failure_is_not_connection_lost() {
        let outcome = classify_activation_result(Err(NetError::FetchLocalIo {
            files_processed: 1,
            bytes_processed: 3,
            detail: Some("disk full".to_owned()),
        }))
        .expect("classified");
        assert_eq!(
            outcome,
            ActivationOutcome::Failed(ActivationFailCode::LocalIo)
        );
        let status = outcome.desktop_status().to_ascii_lowercase();
        assert!(status.contains("local storage"), "{status}");
        assert!(!status.contains("connection lost"), "{status}");
    }

    #[test]
    fn malformed_protocol_is_not_connection_lost() {
        let outcome = classify_activation_result(Err(NetError::Protocol(
            meshelf_protocol::ProtocolError::EmptyFrame,
        )))
        .expect("classified");
        assert_eq!(
            outcome,
            ActivationOutcome::Failed(ActivationFailCode::Protocol)
        );
        let status = outcome.desktop_status().to_ascii_lowercase();
        assert!(status.contains("protocol"), "{status}");
        assert!(!status.contains("connection lost"), "{status}");
        let unexpected =
            classify_activation_result(Err(NetError::UnexpectedMessage("expected file_start")))
                .expect("classified unexpected");
        assert_eq!(
            unexpected,
            ActivationOutcome::Failed(ActivationFailCode::Protocol)
        );
    }

    #[test]
    fn transport_io_remains_connection_lost() {
        let outcome = classify_activation_result(Err(NetError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "peer reset",
        ))))
        .expect("classified");
        assert_eq!(
            outcome,
            ActivationOutcome::Failed(ActivationFailCode::ConnectionLost)
        );
    }
}
