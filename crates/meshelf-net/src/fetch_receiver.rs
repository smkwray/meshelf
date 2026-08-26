//! Receiver-side protocol-v2 activation, admission, staging, publication, and cleanup.
//!
//! This is deliberately an activation API, not a background fetch service.  A caller supplies a
//! locally initiated activation and this module performs one bounded request from byte zero.  No
//! card announcement invokes this path.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use meshelf_core::{
    ActivationId, ActivationJournalEntry, ActivationMode, ActivationState, ClipboardCacheRecord,
    ClipboardCacheState, ClipboardError, ClipboardSink, ContentKind, DeviceId, OfferAttemptCode,
    OfferAttemptStatus, OfferCardRecord, OfferDescriptor, OfferId, validate_relative_path,
};
use meshelf_platform::{
    FilesystemKey, available_space, create_new_file, ensure_directory_tree, filesystem_key,
    preallocate, reject_reparse_point, remove_owned_tree, require_directory, sync_directory,
    total_space,
};
use meshelf_protocol::{
    FetchAbort, FetchAbortCode, FetchAdmission, FetchAdmissionCode, FetchComplete, FetchHeader,
    FetchReceipt, FetchReceiptCode, FileEntryKind, ManifestEnd, ManifestEntry, ProtocolError,
    V2_MAX_FILE_BYTES, V2_MAX_MANIFEST_BYTES, V2_MAX_RELATIVE_PATH_BYTES, V2_MAX_TRANSFER_BYTES,
    V2Message, validate_v2_message, write_v2_frame_async,
};
use meshelf_store::RedbV2Store;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::timeout,
};

use super::{ActivationOutcome, NetError, io_timeout};
use crate::activation::{classify_activation_result, shared_owner};

/// The local user action that authorizes one pull. A card or announcement never creates this
/// value, so metadata-only announcement reception cannot write payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchActivation {
    pub request_id: ActivationId,
    pub source_device: DeviceId,
    pub offer_id: OfferId,
    pub mode: ActivationMode,
    pub destination: Option<PathBuf>,
}

impl FetchActivation {
    #[must_use]
    pub fn new(
        request_id: ActivationId,
        source_device: DeviceId,
        offer_id: OfferId,
        mode: ActivationMode,
        destination: Option<PathBuf>,
    ) -> Self {
        Self {
            request_id,
            source_device,
            offer_id,
            mode,
            destination,
        }
    }
}

/// The file-list operation needed by file/folder clipboard activation.
pub trait FetchClipboard: ClipboardSink {
    fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError>;
}

impl FetchClipboard for meshelf_platform::ClipboardWorker {
    fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
        meshelf_platform::ClipboardWorker::set_files(self, paths).map_err(ClipboardError::from)
    }
}

/// Receiver handler shape used by a later composition layer once UI activation routing exists.
#[async_trait]
pub trait V2FetchReceiver: Send + Sync + 'static {
    async fn receive_fetch(
        &self,
        authenticated_source: DeviceId,
        activation: FetchActivation,
        stream: &mut TcpStream,
        io_timeout_duration: Duration,
    ) -> Result<ActivationOutcome, NetError>;
}

/// One process-wide logical reservation ledger. Physical preallocated files remain the crash
/// authority; this map is intentionally not persisted or reconstructed at startup.
#[derive(Clone, Debug, Default)]
pub struct ReservationLedger {
    reservations: Arc<Mutex<HashMap<FilesystemKey, u64>>>,
}

impl ReservationLedger {
    #[must_use]
    pub fn global() -> Self {
        static GLOBAL: OnceLock<Arc<Mutex<HashMap<FilesystemKey, u64>>>> = OnceLock::new();
        Self {
            reservations: GLOBAL
                .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
                .clone(),
        }
    }

    /// Reserve payload bytes and the mandated safety headroom atomically with the space check.
    pub fn reserve(
        &self,
        destination: &Path,
        payload_bytes: u64,
    ) -> Result<ReservationPermit, ReservationError> {
        let key = filesystem_key(destination).map_err(ReservationError::Filesystem)?;
        let available = available_space(destination).map_err(ReservationError::Filesystem)?;
        let total = total_space(destination).map_err(ReservationError::Filesystem)?;
        self.reserve_with_capacity(key, available, total, payload_bytes)
    }

    /// Testable form of [`Self::reserve`] with a caller-supplied filesystem capacity snapshot.
    /// Production code always uses [`Self::reserve`], so the check and increment remain under one
    /// lock in both paths.
    pub fn reserve_with_capacity(
        &self,
        key: FilesystemKey,
        available: u64,
        total: u64,
        payload_bytes: u64,
    ) -> Result<ReservationPermit, ReservationError> {
        let headroom = 2_u64
            .saturating_mul(1024 * 1024 * 1024)
            .max((total / 20).min(16_u64 * 1024 * 1024 * 1024));
        let required = payload_bytes
            .checked_add(headroom)
            .ok_or(ReservationError::Overflow)?;
        let mut active = self
            .reservations
            .lock()
            .map_err(|_| ReservationError::LedgerPoisoned)?;
        let already_reserved = active.get(&key).copied().unwrap_or(0);
        if available.saturating_sub(already_reserved) < required {
            return Err(ReservationError::InsufficientSpace {
                available,
                active_reserved: already_reserved,
                required,
            });
        }
        let next = already_reserved
            .checked_add(required)
            .ok_or(ReservationError::Overflow)?;
        active.insert(key.clone(), next);
        Ok(ReservationPermit {
            ledger: self.reservations.clone(),
            key,
            reserved_bytes: required,
        })
    }
}

pub struct ReservationPermit {
    ledger: Arc<Mutex<HashMap<FilesystemKey, u64>>>,
    key: FilesystemKey,
    reserved_bytes: u64,
}

impl std::fmt::Debug for ReservationPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReservationPermit")
            .field("key", &self.key)
            .field("reserved_bytes", &self.reserved_bytes)
            .finish()
    }
}

impl Drop for ReservationPermit {
    fn drop(&mut self) {
        let Ok(mut active) = self.ledger.lock() else {
            return;
        };
        if let Some(value) = active.get_mut(&self.key) {
            *value = value.saturating_sub(self.reserved_bytes);
            if *value == 0 {
                active.remove(&self.key);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    #[error("filesystem operation failed: {0}")]
    Filesystem(std::io::Error),
    #[error("reservation ledger is poisoned")]
    LedgerPoisoned,
    #[error("reservation arithmetic overflow")]
    Overflow,
    #[error(
        "insufficient space: available={available}, active_reserved={active_reserved}, required={required}"
    )]
    InsufficientSpace {
        available: u64,
        active_reserved: u64,
        required: u64,
    },
}

#[derive(Debug)]
pub struct FetchReceiver<C> {
    local_device: DeviceId,
    store: Arc<RedbV2Store>,
    clipboard: Arc<C>,
    state_root: PathBuf,
    ledger: ReservationLedger,
    cleanup_blocked: Arc<AtomicBool>,
    uncertain_clipboard: Arc<AtomicBool>,
    #[cfg(test)]
    preallocate_override: Option<fn(&File, u64) -> std::io::Result<()>>,
}

impl<C> FetchReceiver<C>
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
        let owner = shared_owner(store.path());
        Self {
            local_device,
            store,
            clipboard,
            state_root,
            ledger: ReservationLedger::global(),
            cleanup_blocked: owner.cleanup_blocked.clone(),
            uncertain_clipboard: owner.uncertain_clipboard.clone(),
            #[cfg(test)]
            preallocate_override: None,
        }
    }

    #[must_use]
    pub fn with_ledger(
        local_device: DeviceId,
        store: Arc<RedbV2Store>,
        clipboard: Arc<C>,
        state_root: PathBuf,
        ledger: ReservationLedger,
    ) -> Self {
        let owner = shared_owner(store.path());
        Self {
            local_device,
            store,
            clipboard,
            state_root,
            ledger,
            cleanup_blocked: owner.cleanup_blocked.clone(),
            uncertain_clipboard: owner.uncertain_clipboard.clone(),
            #[cfg(test)]
            preallocate_override: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_preallocator_for_test(
        local_device: DeviceId,
        store: Arc<RedbV2Store>,
        clipboard: Arc<C>,
        state_root: PathBuf,
        ledger: ReservationLedger,
        preallocate_override: fn(&File, u64) -> std::io::Result<()>,
    ) -> Self {
        let mut receiver = Self::with_ledger(local_device, store, clipboard, state_root, ledger);
        receiver.preallocate_override = Some(preallocate_override);
        receiver
    }

    /// Remove abandoned journal-owned staging. Uncertain clipboard side effects stay recorded.
    pub(crate) fn startup_cleanup(&self) -> Result<(), NetError> {
        let result = self
            .store
            .startup_cleanup()
            .map(|_| ())
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()));
        if result.is_err() {
            self.cleanup_blocked.store(true, Ordering::Release);
            return result;
        }
        if self
            .store
            .has_uncertain_side_effect()
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?
        {
            self.uncertain_clipboard.store(true, Ordering::Release);
        }
        if let Err(error) = self.cleanup_unindexed_cache_objects() {
            self.cleanup_blocked.store(true, Ordering::Release);
            return Err(NetError::FetchServiceOwned(error.to_string()));
        }
        result
    }

    pub fn store(&self) -> &Arc<RedbV2Store> {
        &self.store
    }

    pub async fn receive(
        &self,
        authenticated_source: DeviceId,
        activation: FetchActivation,
        stream: &mut TcpStream,
        io_timeout_duration: Duration,
    ) -> Result<ActivationOutcome, NetError> {
        classify_activation_result(
            self.receive_one(
                authenticated_source,
                activation,
                stream,
                io_timeout_duration,
                None,
            )
            .await,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn receive_with_cancel(
        &self,
        authenticated_source: DeviceId,
        activation: FetchActivation,
        stream: &mut TcpStream,
        io_timeout_duration: Duration,
        cancel: watch::Receiver<bool>,
    ) -> Result<ActivationOutcome, NetError> {
        classify_activation_result(
            self.receive_one(
                authenticated_source,
                activation,
                stream,
                io_timeout_duration,
                Some(cancel),
            )
            .await,
        )
    }

    #[must_use]
    pub const fn local_device(&self) -> DeviceId {
        self.local_device
    }

    fn cleanup_unindexed_cache_objects(&self) -> Result<(), std::io::Error> {
        let cache_root = self.state_root.join("clipboard-cache");
        let completed = self
            .store
            .get_clipboard_cache(ClipboardCacheState::Completed)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .map(|record| record.payload_path);
        let in_flight = self
            .store
            .get_clipboard_cache(ClipboardCacheState::InFlight)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .map(|record| record.payload_path);
        let entries = match fs::read_dir(&cache_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("candidate-"))
            {
                continue;
            }
            if completed.as_deref() == Some(path.as_path())
                || in_flight.as_deref() == Some(path.as_path())
            {
                continue;
            }
            remove_owned_tree(&path)?;
        }
        Ok(())
    }

    async fn receive_one(
        &self,
        authenticated_source: DeviceId,
        activation: FetchActivation,
        stream: &mut TcpStream,
        io_timeout_duration: Duration,
        mut cancel: Option<watch::Receiver<bool>>,
    ) -> Result<(), NetError> {
        let mut staging_guard = StagingGuard::inactive(self.cleanup_blocked.clone());
        if self.cleanup_blocked.load(Ordering::Acquire) {
            return Err(NetError::FetchAdmissionRefused {
                code: FetchAdmissionCode::RefusedBusy,
                entries_reserved: 0,
                bytes_reserved: 0,
                detail: Some(
                    "receiver cleanup is unresolved; listener admission is blocked".to_owned(),
                ),
            });
        }
        if cancel_requested(&cancel) {
            let _ = stream.shutdown().await;
            return Err(NetError::FetchTerminal {
                code: FetchReceiptCode::Cancelled,
                files_processed: 0,
                bytes_processed: 0,
                detail: None,
            });
        }
        if authenticated_source != activation.source_device
            || activation.request_id == ActivationId::default()
            || activation.offer_id == OfferId::default()
        {
            return Err(NetError::IdentityMismatch(
                "fetch activation does not match the authenticated request".to_owned(),
            ));
        }
        let card = self
            .store
            .get_offer_card(activation.source_device, activation.offer_id)
            .map_err(|error| NetError::OfferStorage(error.to_string()))?
            .ok_or_else(|| NetError::Rejected("offer card is not available".to_owned()))?;

        let header = match self
            .read_header(stream, &activation, &card, io_timeout_duration, &mut cancel)
            .await
        {
            Ok(header) => header,
            Err(error) => {
                let attempt_code = match &error {
                    NetError::FetchRefused {
                        code: meshelf_protocol::FetchRefusalCode::SourceUnavailable,
                        ..
                    } => OfferAttemptCode::SourceUnavailable,
                    NetError::FetchRefused {
                        code: meshelf_protocol::FetchRefusalCode::SourceChanged,
                        ..
                    } => OfferAttemptCode::SourceChanged,
                    NetError::FetchRefused {
                        code: meshelf_protocol::FetchRefusalCode::Busy,
                        ..
                    } => OfferAttemptCode::Busy,
                    _ => OfferAttemptCode::Failed,
                };
                self.record_attempt_with_counts(
                    &activation,
                    attempt_code,
                    0,
                    0,
                    Some(safe_detail(&error.to_string())),
                )?;
                return Err(error);
            }
        };
        let mut plan = match validate_header(&header, &card, &activation) {
            Ok(plan) => plan,
            Err(code) => {
                return self
                    .refuse_admission(stream, &activation, code, None, io_timeout_duration)
                    .await;
            }
        };

        match self
            .read_manifest(stream, &header, &mut plan, io_timeout_duration, &mut cancel)
            .await
        {
            Ok(()) => {}
            Err(ReceiveFailure::LocalCancelled { .. }) => {
                return self
                    .refuse_admission(
                        stream,
                        &activation,
                        FetchAdmissionCode::Cancelled,
                        None,
                        io_timeout_duration,
                    )
                    .await;
            }
            Err(ReceiveFailure::Protocol { detail, .. }) => {
                return Err(NetError::Protocol(ProtocolError::V2Validation { detail }));
            }
            Err(ReceiveFailure::Io(error)) => return Err(error),
            Err(ReceiveFailure::Disconnected { .. }) => {
                return Err(NetError::FetchTerminal {
                    code: FetchReceiptCode::ConnectionLost,
                    files_processed: 0,
                    bytes_processed: 0,
                    detail: None,
                });
            }
            Err(_) => {
                return self
                    .refuse_admission(
                        stream,
                        &activation,
                        FetchAdmissionCode::InvalidManifest,
                        None,
                        io_timeout_duration,
                    )
                    .await;
            }
        }
        if let Err(code) = validate_manifest(&header, &card.descriptor, &plan) {
            return self
                .refuse_admission(stream, &activation, code, None, io_timeout_duration)
                .await;
        }

        let destination = match self.destination_for(&activation, &header.descriptor) {
            Ok(destination) => destination,
            Err(code) => {
                return self
                    .refuse_admission(stream, &activation, code, None, io_timeout_duration)
                    .await;
            }
        };
        let clipboard_uncertain = self.uncertain_clipboard.load(Ordering::Acquire)
            || self
                .store
                .has_uncertain_side_effect()
                .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?;
        if activation.mode == ActivationMode::Clipboard && clipboard_uncertain {
            return self
                .refuse_admission(
                    stream,
                    &activation,
                    FetchAdmissionCode::RefusedBusy,
                    Some("clipboard activation is uncertain after recovery".to_owned()),
                    io_timeout_duration,
                )
                .await;
        }
        if let Some(destination) = &destination {
            if let Err(error) = ensure_directory_tree(destination) {
                return self
                    .refuse_admission(
                        stream,
                        &activation,
                        FetchAdmissionCode::DestinationUnavailable,
                        Some(safe_detail(&error.to_string())),
                        io_timeout_duration,
                    )
                    .await;
            }
            if let Err(error) = require_directory(destination) {
                return self
                    .refuse_admission(
                        stream,
                        &activation,
                        FetchAdmissionCode::DestinationUnavailable,
                        Some(safe_detail(&error.to_string())),
                        io_timeout_duration,
                    )
                    .await;
            }
        }

        let payload_bytes = plan.total_bytes;
        let permit = if !needs_filesystem_reservation(plan.content_kind, payload_bytes) {
            None
        } else {
            let Some(destination) = destination.as_deref() else {
                return Err(NetError::FetchServiceOwned(
                    "file transfer has no destination filesystem".to_owned(),
                ));
            };
            match self.ledger.reserve(destination, payload_bytes) {
                Ok(permit) => Some(permit),
                Err(ReservationError::InsufficientSpace { .. }) => {
                    return self
                        .refuse_admission(
                            stream,
                            &activation,
                            FetchAdmissionCode::InsufficientSpace,
                            None,
                            io_timeout_duration,
                        )
                        .await;
                }
                Err(error) => {
                    return self
                        .refuse_admission(
                            stream,
                            &activation,
                            FetchAdmissionCode::DestinationUnavailable,
                            Some(safe_detail(&error.to_string())),
                            io_timeout_duration,
                        )
                        .await;
                }
            }
        };

        let staging_root = self
            .state_root
            .join("staging")
            .join(activation.request_id.to_string());
        let journal = ActivationJournalEntry {
            activation_id: activation.request_id,
            source_device: activation.source_device,
            offer_id: activation.offer_id,
            mode: activation.mode,
            staging_root: staging_root.clone(),
            state: ActivationState::Staging,
            reserved_entries: plan.file_count,
            reserved_bytes: payload_bytes,
        };
        self.store
            .journal_activation(&journal)
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?;
        staging_guard.arm(
            self.store.clone(),
            staging_root.clone(),
            activation.request_id,
        );
        if let Err(error) = self.prepare_staging(&staging_root, &mut plan).await {
            let cleanup_result = self
                .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                .await;
            if let Err(cleanup_error) = cleanup_result {
                self.cleanup_blocked.store(true, Ordering::Release);
                staging_guard.keep();
                drop(permit);
                return Err(NetError::FetchServiceOwned(format!(
                    "allocation failed: {error}; {cleanup_error}"
                )));
            }
            staging_guard.disarm();
            drop(permit);
            return self
                .refuse_admission(
                    stream,
                    &activation,
                    FetchAdmissionCode::AllocationFailed,
                    Some(safe_detail(&error.to_string())),
                    io_timeout_duration,
                )
                .await;
        }
        reject_reparse_point(&staging_root)?;

        self.write_admission(
            stream,
            activation.request_id,
            FetchAdmissionCode::Accepted,
            plan.file_count,
            payload_bytes,
            None,
            io_timeout_duration,
        )
        .await?;
        self.store
            .update_activation_state(activation.request_id, ActivationState::Transferring)
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?;
        if cancel_requested(&cancel) {
            let cleanup_result = self
                .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                .await;
            drop(permit);
            if let Err(cleanup_error) = cleanup_result {
                self.cleanup_blocked.store(true, Ordering::Release);
                staging_guard.keep();
                return Err(cleanup_error);
            }
            staging_guard.disarm();
            self.record_attempt_with_counts(&activation, OfferAttemptCode::Cancelled, 0, 0, None)?;
            let _ = stream.shutdown().await;
            return Err(NetError::FetchTerminal {
                code: FetchReceiptCode::Cancelled,
                files_processed: 0,
                bytes_processed: 0,
                detail: None,
            });
        }

        let receive = self
            .receive_payload(
                stream,
                &activation,
                &mut plan,
                &staging_root,
                io_timeout_duration,
                &mut cancel,
            )
            .await;
        match receive {
            Ok(()) => {
                if cancel_requested(&cancel) {
                    let cleanup_result = self
                        .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                        .await;
                    drop(permit);
                    if let Err(cleanup_error) = cleanup_result {
                        self.cleanup_blocked.store(true, Ordering::Release);
                        staging_guard.keep();
                        return Err(cleanup_error);
                    }
                    staging_guard.disarm();
                    self.record_attempt_with_counts(
                        &activation,
                        OfferAttemptCode::Cancelled,
                        plan.file_count,
                        plan.total_bytes,
                        None,
                    )?;
                    let _ = stream.shutdown().await;
                    return Err(NetError::FetchTerminal {
                        code: FetchReceiptCode::Cancelled,
                        files_processed: plan.file_count,
                        bytes_processed: plan.total_bytes,
                        detail: None,
                    });
                }
                self.store
                    .update_activation_state(activation.request_id, ActivationState::Verified)
                    .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?;
                let published = match self
                    .publish(
                        &activation,
                        &header.descriptor,
                        &staging_root,
                        &plan,
                        destination.as_deref(),
                    )
                    .await
                {
                    Ok(path) => path,
                    Err(error) => {
                        let cleanup_result = self
                            .cleanup_activation_state(
                                &mut plan,
                                &staging_root,
                                activation.request_id,
                            )
                            .await;
                        drop(permit);
                        if let Err(cleanup_error) = cleanup_result {
                            self.cleanup_blocked.store(true, Ordering::Release);
                            staging_guard.keep();
                            return Err(NetError::FetchServiceOwned(format!(
                                "publication failed: {error}; {cleanup_error}"
                            )));
                        }
                        staging_guard.disarm();
                        let detail = safe_detail(&error.to_string());
                        self.record_attempt_with_counts(
                            &activation,
                            OfferAttemptCode::Failed,
                            plan.file_count,
                            plan.total_bytes,
                            Some(detail.clone()),
                        )?;
                        if matches!(error, NetError::Io(_) | NetError::FetchLocalIo { .. }) {
                            return Err(NetError::FetchLocalIo {
                                files_processed: plan.file_count,
                                bytes_processed: plan.total_bytes,
                                detail: Some(detail),
                            });
                        }
                        return self
                            .finish_terminal(
                                stream,
                                FetchReceiptCode::InternalError,
                                plan.file_count,
                                plan.total_bytes,
                                Some(detail),
                                &activation,
                                io_timeout_duration,
                            )
                            .await;
                    }
                };
                staging_guard.keep();
                match self
                    .apply_side_effect(
                        &activation,
                        &header.descriptor,
                        plan.text.as_deref(),
                        published.as_deref(),
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(SideEffectFailure::Terminal(error)) => {
                        let cleanup_result = self
                            .cleanup_activation_state(
                                &mut plan,
                                &staging_root,
                                activation.request_id,
                            )
                            .await;
                        drop(permit);
                        if let Err(cleanup_error) = cleanup_result {
                            self.cleanup_blocked.store(true, Ordering::Release);
                            staging_guard.keep();
                            return Err(NetError::FetchServiceOwned(format!(
                                "side effect failed: {error}; {cleanup_error}"
                            )));
                        }
                        staging_guard.disarm();
                        self.record_attempt_with_counts(
                            &activation,
                            OfferAttemptCode::ClipboardFailed,
                            plan.file_count,
                            plan.total_bytes,
                            Some(safe_detail(&error.to_string())),
                        )?;
                        return self
                            .finish_terminal(
                                stream,
                                FetchReceiptCode::ClipboardFailed,
                                plan.file_count,
                                plan.total_bytes,
                                Some(safe_detail(&error.to_string())),
                                &activation,
                                io_timeout_duration,
                            )
                            .await;
                    }
                    Err(SideEffectFailure::Uncertain(error)) => {
                        staging_guard.keep();
                        drop(permit);
                        return self
                            .finish_uncertain(
                                stream,
                                &activation,
                                &plan,
                                plan.file_count,
                                plan.total_bytes,
                                error.to_string(),
                                io_timeout_duration,
                            )
                            .await;
                    }
                }
                if let Err(error) = cleanup_activation(&mut plan, &staging_root).await {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return self
                        .finish_uncertain(
                            stream,
                            &activation,
                            &plan,
                            plan.file_count,
                            plan.total_bytes,
                            format!("staging cleanup failed after side effect: {error}"),
                            io_timeout_duration,
                        )
                        .await;
                }
                if let Err(error) = self
                    .store
                    .update_activation_state(activation.request_id, ActivationState::Completed)
                {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    return self
                        .finish_uncertain(
                            stream,
                            &activation,
                            &plan,
                            plan.file_count,
                            plan.total_bytes,
                            error.to_string(),
                            io_timeout_duration,
                        )
                        .await;
                }
                if let Err(error) =
                    self.record_attempt(&activation, OfferAttemptCode::Completed, &plan, None)
                {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    return self
                        .finish_uncertain(
                            stream,
                            &activation,
                            &plan,
                            plan.file_count,
                            plan.total_bytes,
                            error.to_string(),
                            io_timeout_duration,
                        )
                        .await;
                }
                if let Err(error) = self.store.remove_activation_journal(activation.request_id) {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return self
                        .finish_uncertain(
                            stream,
                            &activation,
                            &plan,
                            plan.file_count,
                            plan.total_bytes,
                            error.to_string(),
                            io_timeout_duration,
                        )
                        .await;
                }
                staging_guard.disarm();
                drop(permit);
                self.send_receipt(
                    stream,
                    FetchReceiptCode::Completed,
                    plan.file_count,
                    plan.total_bytes,
                    None,
                    &activation,
                    io_timeout_duration,
                )
                .await
            }
            Err(ReceiveFailure::Disconnected { files, bytes }) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    drop(permit);
                    return Err(cleanup_error);
                }
                staging_guard.disarm();
                drop(permit);
                let detail = format!("connection lost after {files} files and {bytes} bytes");
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::Failed,
                    files,
                    bytes,
                    Some(detail.clone()),
                )?;
                Err(NetError::FetchTerminal {
                    code: FetchReceiptCode::ConnectionLost,
                    files_processed: files,
                    bytes_processed: bytes,
                    detail: Some(detail),
                })
            }
            Err(ReceiveFailure::LocalCancelled { files, bytes }) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return Err(cleanup_error);
                }
                staging_guard.disarm();
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::Cancelled,
                    files,
                    bytes,
                    None,
                )?;
                let _ = self
                    .send_receipt(
                        stream,
                        FetchReceiptCode::Cancelled,
                        files,
                        bytes,
                        None,
                        &activation,
                        io_timeout_duration,
                    )
                    .await;
                let _ = stream.shutdown().await;
                Err(NetError::FetchTerminal {
                    code: FetchReceiptCode::Cancelled,
                    files_processed: files,
                    bytes_processed: bytes,
                    detail: None,
                })
            }
            Err(ReceiveFailure::Aborted { code, files, bytes }) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return Err(cleanup_error);
                }
                staging_guard.disarm();
                let attempt_code = match code {
                    FetchAbortCode::SourceUnavailable => OfferAttemptCode::SourceUnavailable,
                    FetchAbortCode::SourceChanged => OfferAttemptCode::SourceChanged,
                    FetchAbortCode::Cancelled => OfferAttemptCode::Cancelled,
                    FetchAbortCode::InternalError => OfferAttemptCode::Failed,
                };
                self.record_attempt_with_counts(&activation, attempt_code, files, bytes, None)?;
                let receipt_code = match code {
                    FetchAbortCode::Cancelled => FetchReceiptCode::Cancelled,
                    _ => FetchReceiptCode::InternalError,
                };
                self.send_receipt(
                    stream,
                    receipt_code,
                    files,
                    bytes,
                    None,
                    &activation,
                    io_timeout_duration,
                )
                .await?;
                Err(NetError::FetchAborted {
                    code,
                    files_processed: files,
                    bytes_processed: bytes,
                    detail: None,
                })
            }
            Err(ReceiveFailure::Verification {
                files,
                bytes,
                detail,
            }) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return Err(cleanup_error);
                }
                staging_guard.disarm();
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::VerificationFailed,
                    files,
                    bytes,
                    Some(detail.clone()),
                )?;
                self.finish_terminal(
                    stream,
                    FetchReceiptCode::VerificationFailed,
                    files,
                    bytes,
                    Some(safe_detail(&detail)),
                    &activation,
                    io_timeout_duration,
                )
                .await
            }
            Err(ReceiveFailure::Protocol {
                files,
                bytes,
                detail,
            }) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return Err(cleanup_error);
                }
                staging_guard.disarm();
                let detail = safe_detail(&detail);
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::Failed,
                    files,
                    bytes,
                    Some(detail.clone()),
                )?;
                Err(NetError::Protocol(
                    meshelf_protocol::ProtocolError::V2Validation { detail },
                ))
            }
            Err(ReceiveFailure::LocalIo {
                files,
                bytes,
                detail,
            }) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return Err(cleanup_error);
                }
                staging_guard.disarm();
                let detail = safe_detail(&detail);
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::Failed,
                    files,
                    bytes,
                    Some(detail.clone()),
                )?;
                Err(NetError::FetchLocalIo {
                    files_processed: files,
                    bytes_processed: bytes,
                    detail: Some(detail),
                })
            }
            Err(ReceiveFailure::Io(error)) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    staging_guard.keep();
                    return Err(cleanup_error);
                }
                staging_guard.disarm();
                let detail = safe_detail(&error.to_string());
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::Failed,
                    0,
                    0,
                    Some(detail.clone()),
                )?;
                Err(NetError::FetchTerminal {
                    code: FetchReceiptCode::ConnectionLost,
                    files_processed: 0,
                    bytes_processed: 0,
                    detail: Some(detail),
                })
            }
        }
    }

    async fn read_header(
        &self,
        stream: &mut TcpStream,
        activation: &FetchActivation,
        card: &OfferCardRecord,
        io_timeout_duration: Duration,
        cancel: &mut Option<watch::Receiver<bool>>,
    ) -> Result<FetchHeader, NetError> {
        let message = match read_v2_cancellable(stream, io_timeout_duration, cancel, 0, 0).await {
            Ok(message) => message,
            Err(ReceiveFailure::LocalCancelled { .. }) => {
                return Err(NetError::FetchTerminal {
                    code: FetchReceiptCode::Cancelled,
                    files_processed: 0,
                    bytes_processed: 0,
                    detail: None,
                });
            }
            Err(ReceiveFailure::Io(error)) => return Err(error),
            Err(ReceiveFailure::Protocol { detail, .. }) => {
                return Err(NetError::Protocol(ProtocolError::V2Validation { detail }));
            }
            Err(ReceiveFailure::Disconnected { .. }) => {
                return Err(NetError::FetchTerminal {
                    code: FetchReceiptCode::ConnectionLost,
                    files_processed: 0,
                    bytes_processed: 0,
                    detail: None,
                });
            }
            Err(_) => {
                return Err(NetError::UnexpectedMessage(
                    "expected fetch header or refusal",
                ));
            }
        };
        validate_v2_message(&message)?;
        match message {
            V2Message::FetchHeader(header) => Ok(header),
            V2Message::FetchRefusal(refusal) => {
                if refusal.request_id != activation.request_id
                    || refusal.offer_id != activation.offer_id
                {
                    return Err(NetError::IdentityMismatch(
                        "fetch refusal does not match the activation".to_owned(),
                    ));
                }
                refusal.validate_for(&card.descriptor)?;
                Err(NetError::FetchRefused {
                    code: refusal.code,
                    active_streams: refusal.active_streams,
                    max_active_streams: refusal.max_active_streams,
                    detail: refusal.detail,
                })
            }
            _ => Err(NetError::UnexpectedMessage(
                "expected fetch header or refusal",
            )),
        }
    }

    async fn read_manifest(
        &self,
        stream: &mut TcpStream,
        header: &FetchHeader,
        plan: &mut ReceivePlan,
        io_timeout_duration: Duration,
        cancel: &mut Option<watch::Receiver<bool>>,
    ) -> Result<(), ReceiveFailure> {
        if header.manifest_entries == 0 {
            return Ok(());
        }
        let mut expected_index = 0_u32;
        while expected_index < header.manifest_entries {
            let message = read_manifest_frame(stream, io_timeout_duration, cancel).await?;
            validate_v2_message(&message).map_err(|error| ReceiveFailure::Protocol {
                files: 0,
                bytes: 0,
                detail: error.to_string(),
            })?;
            let V2Message::ManifestChunk(chunk) = message else {
                return Err(manifest_invalid());
            };
            if chunk.request_id != header.request_id
                || chunk.first_index != expected_index
                || chunk.entries.is_empty()
            {
                return Err(manifest_invalid());
            }
            expected_index = expected_index
                .checked_add(u32::try_from(chunk.entries.len()).map_err(|_| manifest_invalid())?)
                .ok_or_else(manifest_invalid)?;
            if expected_index > header.manifest_entries {
                return Err(manifest_invalid());
            }
            plan.manifest_encoded_bytes = plan
                .manifest_encoded_bytes
                .checked_add(
                    serde_json::to_vec(&V2Message::ManifestChunk(chunk.clone()))
                        .map_err(|_| manifest_invalid())?
                        .len(),
                )
                .ok_or_else(manifest_invalid)?;
            plan.entries.extend(chunk.entries);
        }
        let message = read_manifest_frame(stream, io_timeout_duration, cancel).await?;
        validate_v2_message(&message).map_err(|error| ReceiveFailure::Protocol {
            files: 0,
            bytes: 0,
            detail: error.to_string(),
        })?;
        let V2Message::ManifestEnd(end) = message else {
            return Err(manifest_invalid());
        };
        if end.request_id != header.request_id {
            return Err(manifest_invalid());
        }
        plan.manifest_end = Some(end);
        if plan.manifest_encoded_bytes > V2_MAX_MANIFEST_BYTES
            || plan.manifest_encoded_bytes
                != usize::try_from(header.manifest_encoded_bytes).unwrap_or(usize::MAX)
        {
            return Err(manifest_invalid());
        }
        Ok(())
    }

    fn destination_for(
        &self,
        activation: &FetchActivation,
        descriptor: &OfferDescriptor,
    ) -> Result<Option<PathBuf>, FetchAdmissionCode> {
        if descriptor.is_text() {
            return Ok(None);
        }
        let path = match activation.mode {
            ActivationMode::Save => activation
                .destination
                .clone()
                .ok_or(FetchAdmissionCode::DestinationUnavailable)?,
            ActivationMode::Clipboard => self.state_root.join("clipboard-cache"),
        };
        if !path.is_absolute() {
            return Err(FetchAdmissionCode::DestinationUnavailable);
        }
        Ok(Some(path))
    }

    async fn prepare_staging(
        &self,
        staging_root: &Path,
        plan: &mut ReceivePlan,
    ) -> Result<(), std::io::Error> {
        let parent = staging_root
            .parent()
            .ok_or_else(|| std::io::Error::other("staging root has no parent"))?;
        ensure_directory_tree(parent)?;
        fs::create_dir(staging_root)?;
        reject_reparse_point(staging_root)?;
        let payload_root = staging_root.join("payload");
        if plan.content_kind == ContentKind::Folder {
            ensure_directory_tree(&payload_root)?;
        }
        let mut directory_paths = HashSet::new();
        for entry in &plan.entries {
            if entry.kind == FileEntryKind::Directory {
                let path =
                    payload_root.join(crate::destination::relative_path(&entry.relative_path));
                directory_paths.insert(path);
            }
        }
        let mut directory_paths = directory_paths.into_iter().collect::<Vec<_>>();
        directory_paths.sort_by_key(|path| path.components().count());
        for directory in directory_paths {
            ensure_directory_tree(&directory)?;
        }

        for entry in plan
            .entries
            .iter()
            .filter(|entry| entry.kind == FileEntryKind::File)
        {
            let path = if plan.content_kind == ContentKind::File {
                payload_root.clone()
            } else {
                payload_root.join(crate::destination::relative_path(&entry.relative_path))
            };
            if let Some(parent) = path.parent() {
                ensure_directory_tree(parent)?;
            }
            let file = create_new_file(&path)?;
            reject_reparse_point(&path)?;
            self.preallocate_file(&file, entry.byte_len)?;
            plan.staged_files.push(StagedFile {
                entry_index: plan
                    .entries
                    .iter()
                    .position(|candidate| std::ptr::eq(candidate, entry))
                    .unwrap_or(0) as u32,
                path,
                file: Some(file),
            });
        }
        sync_directory(staging_root)?;
        Ok(())
    }

    fn preallocate_file(&self, file: &File, length: u64) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(preallocate_override) = self.preallocate_override {
            return preallocate_override(file, length);
        }
        preallocate(file, length)
    }

    async fn receive_payload(
        &self,
        stream: &mut TcpStream,
        activation: &FetchActivation,
        plan: &mut ReceivePlan,
        staging_root: &Path,
        io_timeout_duration: Duration,
        cancel: &mut Option<watch::Receiver<bool>>,
    ) -> Result<(), ReceiveFailure> {
        if plan.content_kind == ContentKind::Text {
            let expected = plan.total_bytes as usize;
            let mut bytes = vec![0_u8; expected];
            read_exact_cancellable(stream, &mut bytes, io_timeout_duration, cancel, 0, 0).await?;
            let digest = Sha256::digest(&bytes).to_vec();
            let message =
                read_v2_cancellable(stream, io_timeout_duration, cancel, 0, expected as u64)
                    .await?;
            let V2Message::TextEnd(end) = message else {
                if let V2Message::FetchAbort(abort) = message
                    && abort.request_id == activation.request_id
                {
                    return Err(abort_failure(abort));
                }
                return Err(ReceiveFailure::Verification {
                    files: 0,
                    bytes: expected as u64,
                    detail: "expected text_end".to_owned(),
                });
            };
            if end.request_id != activation.request_id || end.sha256 != digest {
                return Err(ReceiveFailure::Verification {
                    files: 0,
                    bytes: expected as u64,
                    detail: "text digest mismatch".to_owned(),
                });
            }
            let complete = read_complete(stream, io_timeout_duration, cancel).await?;
            if complete.request_id != activation.request_id
                || complete.files_sent != 0
                || complete.bytes_sent != expected as u64
                || complete.content_set_sha256 != digest
            {
                return Err(ReceiveFailure::Verification {
                    files: 0,
                    bytes: expected as u64,
                    detail: "text completion counts or digest mismatch".to_owned(),
                });
            }
            plan.text =
                Some(
                    String::from_utf8(bytes).map_err(|_| ReceiveFailure::Verification {
                        files: 0,
                        bytes: expected as u64,
                        detail: "text payload is not UTF-8".to_owned(),
                    })?,
                );
            return Ok(());
        }

        let mut files_received = 0_u32;
        let mut bytes_received = 0_u64;
        let mut content_set = Sha256::new();
        content_set.update(plan.manifest_sha256.as_deref().unwrap_or_default());
        for staged in &mut plan.staged_files {
            let message = read_v2_cancellable(
                stream,
                io_timeout_duration,
                cancel,
                files_received,
                bytes_received,
            )
            .await?;
            if let V2Message::FetchAbort(abort) = &message
                && abort.request_id == activation.request_id
            {
                return Err(abort_failure(abort.clone()));
            }
            let V2Message::FileStart(start) = message else {
                return Err(ReceiveFailure::Verification {
                    files: files_received,
                    bytes: bytes_received,
                    detail: "expected file_start".to_owned(),
                });
            };
            let entry = plan
                .entries
                .get(staged.entry_index as usize)
                .ok_or_else(|| ReceiveFailure::Verification {
                    files: files_received,
                    bytes: bytes_received,
                    detail: "file entry index is out of range".to_owned(),
                })?;
            if start.request_id != activation.request_id
                || start.entry_index != staged.entry_index
                || start.byte_len != entry.byte_len
            {
                return Err(ReceiveFailure::Verification {
                    files: files_received,
                    bytes: bytes_received,
                    detail: "file_start ordering or length mismatch".to_owned(),
                });
            }
            let mut file = tokio::fs::File::from_std(staged.file.take().ok_or_else(|| {
                ReceiveFailure::Verification {
                    files: files_received,
                    bytes: bytes_received,
                    detail: "staging file was not preallocated".to_owned(),
                }
            })?);
            let mut remaining = entry.byte_len;
            let mut buffer = vec![0_u8; meshelf_protocol::V2_STREAM_BUFFER_BYTES];
            let mut hasher = Sha256::new();
            while remaining > 0 {
                if cancel_requested(cancel) {
                    return Err(ReceiveFailure::LocalCancelled {
                        files: files_received,
                        bytes: bytes_received,
                    });
                }
                let wanted =
                    usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                let read = read_chunk_cancellable(
                    stream,
                    &mut buffer[..wanted],
                    io_timeout_duration,
                    cancel,
                    files_received,
                    bytes_received,
                )
                .await?;
                if read == 0 {
                    return Err(ReceiveFailure::Disconnected {
                        files: files_received,
                        bytes: bytes_received,
                    });
                }
                hasher.update(&buffer[..read]);
                file.write_all(&buffer[..read])
                    .await
                    .map_err(|error| ReceiveFailure::LocalIo {
                        files: files_received,
                        bytes: bytes_received,
                        detail: error.to_string(),
                    })?;
                remaining -= read as u64;
                bytes_received = bytes_received.saturating_add(read as u64);
            }
            file.sync_all()
                .await
                .map_err(|error| ReceiveFailure::LocalIo {
                    files: files_received,
                    bytes: bytes_received,
                    detail: error.to_string(),
                })?;
            let digest = hasher.finalize().to_vec();
            let message = read_v2_cancellable(
                stream,
                io_timeout_duration,
                cancel,
                files_received,
                bytes_received,
            )
            .await?;
            if let V2Message::FetchAbort(abort) = &message
                && abort.request_id == activation.request_id
            {
                return Err(abort_failure(abort.clone()));
            }
            let V2Message::FileEnd(end) = message else {
                return Err(ReceiveFailure::Verification {
                    files: files_received,
                    bytes: bytes_received,
                    detail: "expected file_end".to_owned(),
                });
            };
            if end.request_id != activation.request_id
                || end.entry_index != staged.entry_index
                || end.sha256 != digest
            {
                return Err(ReceiveFailure::Verification {
                    files: files_received,
                    bytes: bytes_received,
                    detail: "file digest or ordering mismatch".to_owned(),
                });
            }
            content_set.update(&digest);
            files_received += 1;
        }
        let complete = read_complete(stream, io_timeout_duration, cancel).await?;
        let expected_content_set = content_set.finalize().to_vec();
        if complete.request_id != activation.request_id
            || complete.files_sent != files_received
            || complete.bytes_sent != bytes_received
            || complete.content_set_sha256 != expected_content_set
        {
            return Err(ReceiveFailure::Verification {
                files: files_received,
                bytes: bytes_received,
                detail: "fetch completion counts or content-set digest mismatch".to_owned(),
            });
        }
        sync_directory(staging_root).map_err(|error| ReceiveFailure::LocalIo {
            files: files_received,
            bytes: bytes_received,
            detail: error.to_string(),
        })
    }

    async fn publish(
        &self,
        activation: &FetchActivation,
        descriptor: &OfferDescriptor,
        staging_root: &Path,
        plan: &ReceivePlan,
        destination: Option<&Path>,
    ) -> Result<Option<PathBuf>, NetError> {
        self.store
            .update_activation_state(activation.request_id, ActivationState::Publishing)
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?;
        if descriptor.is_text() {
            return Ok(None);
        }
        let destination = destination
            .ok_or_else(|| NetError::Rejected("file activation has no destination".to_owned()))?;
        require_directory(destination)?;
        let payload = staging_root.join("payload");
        let root_name = match descriptor {
            OfferDescriptor::File { root_name, .. } | OfferDescriptor::Folder { root_name, .. } => {
                root_name
            }
            OfferDescriptor::Text { .. } => unreachable!(),
        };
        let final_path = if activation.mode == ActivationMode::Clipboard {
            let candidate = destination.join(format!("candidate-{}", activation.request_id));
            super::destination::finalize_payload(&payload, &candidate, plan.content_kind).await?;
            candidate
        } else {
            super::destination::finalize_payload_without_overwrite(
                &payload,
                destination,
                root_name,
                plan.content_kind,
            )
            .await?
        };
        if let Some(parent) = final_path.parent() {
            sync_directory(parent)?;
        }
        Ok(Some(final_path))
    }

    async fn apply_side_effect(
        &self,
        activation: &FetchActivation,
        descriptor: &OfferDescriptor,
        text: Option<&str>,
        published: Option<&Path>,
    ) -> Result<(), SideEffectFailure> {
        self.store
            .update_activation_state(activation.request_id, ActivationState::ApplyingClipboard)
            .map_err(|error| {
                SideEffectFailure::Terminal(NetError::FetchServiceOwned(error.to_string()))
            })?;
        match (descriptor, activation.mode, published) {
            (OfferDescriptor::Text { .. }, ActivationMode::Clipboard, None) => {
                let text = text.ok_or_else(|| {
                    SideEffectFailure::Terminal(NetError::FetchServiceOwned(
                        "text payload was not retained".to_owned(),
                    ))
                })?;
                self.clipboard.set_text(text).map_err(|error| {
                    if error.is_uncertain() {
                        self.uncertain_clipboard.store(true, Ordering::Release);
                    }
                    classify_clipboard_failure(error)
                })
            }
            (OfferDescriptor::Text { .. }, ActivationMode::Save, None) => {
                Err(SideEffectFailure::Terminal(NetError::Rejected(
                    "text save activation is unsupported".to_owned(),
                )))
            }
            (_, ActivationMode::Clipboard, Some(path)) => {
                let candidate = ClipboardCacheRecord {
                    activation_id: activation.request_id,
                    state: ClipboardCacheState::InFlight,
                    payload_path: path.to_owned(),
                };
                self.store
                    .set_clipboard_cache(&candidate)
                    .map_err(|error| {
                        let cleanup = remove_published_cache_object(path);
                        let detail = match cleanup {
                            Ok(()) => error.to_string(),
                            Err(cleanup_error) => {
                                self.cleanup_blocked.store(true, Ordering::Release);
                                format!("{error}; candidate cleanup failed: {cleanup_error}")
                            }
                        };
                        SideEffectFailure::Terminal(NetError::FetchServiceOwned(detail))
                    })?;
                if let Err(error) = self.clipboard.set_files(&[path.to_owned()]) {
                    if error.is_uncertain() {
                        self.uncertain_clipboard.store(true, Ordering::Release);
                        return Err(SideEffectFailure::Uncertain(NetError::FetchServiceOwned(
                            error.message().to_owned(),
                        )));
                    }
                    let cache_cleanup = self
                        .store
                        .clear_clipboard_cache(ClipboardCacheState::InFlight);
                    let path_cleanup = remove_published_cache_object(path);
                    let mut detail = error.message().to_owned();
                    if let Err(cleanup_error) = cache_cleanup {
                        self.cleanup_blocked.store(true, Ordering::Release);
                        detail.push_str(&format!("; cache index cleanup failed: {cleanup_error}"));
                    }
                    if let Err(cleanup_error) = path_cleanup {
                        self.cleanup_blocked.store(true, Ordering::Release);
                        detail.push_str(&format!("; candidate cleanup failed: {cleanup_error}"));
                    }
                    return Err(SideEffectFailure::Terminal(NetError::FetchServiceOwned(
                        detail,
                    )));
                }
                let previous = self
                    .store
                    .promote_clipboard_cache(&candidate)
                    .map_err(|error| {
                        SideEffectFailure::Uncertain(NetError::FetchServiceOwned(error.to_string()))
                    })?;
                if let Some(previous) = previous
                    && previous.payload_path != *path
                {
                    remove_published_cache_object(&previous.payload_path).map_err(|error| {
                        self.uncertain_clipboard.store(true, Ordering::Release);
                        SideEffectFailure::Uncertain(NetError::FetchServiceOwned(error.to_string()))
                    })?;
                }
                self.uncertain_clipboard.store(false, Ordering::Release);
                Ok(())
            }
            (_, ActivationMode::Save, Some(_)) => Ok(()),
            _ => Err(SideEffectFailure::Terminal(NetError::FetchServiceOwned(
                "activation side-effect shape is invalid".to_owned(),
            ))),
        }
    }

    fn record_attempt(
        &self,
        activation: &FetchActivation,
        code: OfferAttemptCode,
        plan: &ReceivePlan,
        detail: Option<String>,
    ) -> Result<(), NetError> {
        self.record_attempt_with_counts(activation, code, plan.file_count, plan.total_bytes, detail)
    }

    async fn cleanup_activation_state(
        &self,
        plan: &mut ReceivePlan,
        staging_root: &Path,
        activation_id: ActivationId,
    ) -> Result<(), NetError> {
        cleanup_activation(plan, staging_root)
            .await
            .map_err(|error| {
                NetError::FetchServiceOwned(format!("activation cleanup failed: {error}"))
            })?;
        self.store
            .remove_activation_journal(activation_id)
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))
    }

    fn record_attempt_with_counts(
        &self,
        activation: &FetchActivation,
        code: OfferAttemptCode,
        files: u32,
        bytes: u64,
        detail: Option<String>,
    ) -> Result<(), NetError> {
        let status = OfferAttemptStatus::new(code, 1, files, bytes, detail)
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?;
        self.store
            .record_offer_attempt(activation.source_device, activation.offer_id, status)
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_uncertain(
        &self,
        stream: &mut TcpStream,
        activation: &FetchActivation,
        plan: &ReceivePlan,
        files: u32,
        bytes: u64,
        detail: String,
        io_timeout_duration: Duration,
    ) -> Result<(), NetError> {
        if let Err(error) = self
            .store
            .update_activation_state(activation.request_id, ActivationState::UncertainNoReplay)
        {
            self.cleanup_blocked.store(true, Ordering::Release);
            return Err(NetError::FetchServiceOwned(format!(
                "could not record uncertain activation: {error}"
            )));
        }
        if let Err(error) = self.record_attempt(
            activation,
            OfferAttemptCode::UncertainNoReplay,
            plan,
            Some(detail.clone()),
        ) {
            self.cleanup_blocked.store(true, Ordering::Release);
            return Err(error);
        }
        self.uncertain_clipboard.store(true, Ordering::Release);
        self.finish_terminal(
            stream,
            FetchReceiptCode::UncertainNoReplay,
            files,
            bytes,
            Some(safe_detail(&detail)),
            activation,
            io_timeout_duration,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn refuse_admission(
        &self,
        stream: &mut TcpStream,
        activation: &FetchActivation,
        code: FetchAdmissionCode,
        detail: Option<String>,
        io_timeout_duration: Duration,
    ) -> Result<(), NetError> {
        self.write_admission(
            stream,
            activation.request_id,
            code.clone(),
            0,
            0,
            detail.clone(),
            io_timeout_duration,
        )
        .await?;
        let attempt_code = match code {
            FetchAdmissionCode::RefusedBusy => OfferAttemptCode::Busy,
            FetchAdmissionCode::Cancelled => OfferAttemptCode::Cancelled,
            _ => OfferAttemptCode::Failed,
        };
        let attempt_detail = detail
            .clone()
            .or_else(|| Some(format!("fetch admission refused with {code:?}")));
        self.record_attempt_with_counts(activation, attempt_code, 0, 0, attempt_detail)?;
        Err(NetError::FetchAdmissionRefused {
            code,
            entries_reserved: 0,
            bytes_reserved: 0,
            detail,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_admission(
        &self,
        stream: &mut TcpStream,
        request_id: ActivationId,
        code: FetchAdmissionCode,
        entries_reserved: u32,
        bytes_reserved: u64,
        detail: Option<String>,
        io_timeout_duration: Duration,
    ) -> Result<(), NetError> {
        io_timeout(
            io_timeout_duration,
            write_v2_frame_async(
                stream,
                &V2Message::FetchAdmission(FetchAdmission {
                    request_id,
                    code,
                    entries_reserved,
                    bytes_reserved,
                    detail,
                }),
            ),
            "write fetch admission",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_receipt(
        &self,
        stream: &mut TcpStream,
        code: FetchReceiptCode,
        files_received: u32,
        bytes_received: u64,
        detail: Option<String>,
        activation: &FetchActivation,
        io_timeout_duration: Duration,
    ) -> Result<(), NetError> {
        io_timeout(
            io_timeout_duration,
            write_v2_frame_async(
                stream,
                &V2Message::FetchReceipt(FetchReceipt {
                    request_id: activation.request_id,
                    offer_id: activation.offer_id,
                    code,
                    files_received,
                    bytes_received,
                    detail,
                }),
            ),
            "write fetch receipt",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_terminal(
        &self,
        stream: &mut TcpStream,
        code: FetchReceiptCode,
        files_processed: u32,
        bytes_processed: u64,
        detail: Option<String>,
        activation: &FetchActivation,
        io_timeout_duration: Duration,
    ) -> Result<(), NetError> {
        self.send_receipt(
            stream,
            code.clone(),
            files_processed,
            bytes_processed,
            detail.clone(),
            activation,
            io_timeout_duration,
        )
        .await?;
        Err(NetError::FetchTerminal {
            code,
            files_processed,
            bytes_processed,
            detail,
        })
    }
}

fn classify_clipboard_failure(error: ClipboardError) -> SideEffectFailure {
    let detail = NetError::FetchServiceOwned(error.message().to_owned());
    if error.is_uncertain() {
        SideEffectFailure::Uncertain(detail)
    } else {
        SideEffectFailure::Terminal(detail)
    }
}

#[async_trait]
impl<C> V2FetchReceiver for FetchReceiver<C>
where
    C: FetchClipboard,
{
    async fn receive_fetch(
        &self,
        authenticated_source: DeviceId,
        activation: FetchActivation,
        stream: &mut TcpStream,
        io_timeout_duration: Duration,
    ) -> Result<ActivationOutcome, NetError> {
        self.receive(
            authenticated_source,
            activation,
            stream,
            io_timeout_duration,
        )
        .await
    }
}

pub type OfferFetchReceiver<C> = FetchReceiver<C>;

#[derive(Debug)]
struct ReceivePlan {
    content_kind: ContentKind,
    total_bytes: u64,
    file_count: u32,
    entries: Vec<ManifestEntry>,
    manifest_end: Option<ManifestEnd>,
    manifest_encoded_bytes: usize,
    manifest_sha256: Option<Vec<u8>>,
    text: Option<String>,
    staged_files: Vec<StagedFile>,
}

struct StagedFile {
    entry_index: u32,
    path: PathBuf,
    file: Option<File>,
}

impl std::fmt::Debug for StagedFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedFile")
            .field("entry_index", &self.entry_index)
            .field("path", &self.path)
            .field("file_open", &self.file.is_some())
            .finish()
    }
}

#[derive(Debug)]
enum ReceiveFailure {
    Disconnected {
        files: u32,
        bytes: u64,
    },
    LocalCancelled {
        files: u32,
        bytes: u64,
    },
    Aborted {
        code: FetchAbortCode,
        files: u32,
        bytes: u64,
    },
    Verification {
        files: u32,
        bytes: u64,
        detail: String,
    },
    Protocol {
        files: u32,
        bytes: u64,
        detail: String,
    },
    LocalIo {
        files: u32,
        bytes: u64,
        detail: String,
    },
    Io(NetError),
}

#[derive(Debug)]
enum SideEffectFailure {
    /// The native side effect did not complete. The activation can be cleaned and reported as a
    /// terminal platform failure.
    Terminal(NetError),
    /// The native side effect may have completed, but durable cache/terminal bookkeeping did not.
    /// Preserve the cache/journal and refuse another file-to-clipboard activation.
    Uncertain(NetError),
}

impl From<std::io::Error> for ReceiveFailure {
    fn from(error: std::io::Error) -> Self {
        Self::Io(NetError::Io(error))
    }
}

fn validate_header(
    header: &FetchHeader,
    card: &OfferCardRecord,
    activation: &FetchActivation,
) -> Result<ReceivePlan, FetchAdmissionCode> {
    if header.request_id != activation.request_id || header.offer_id != activation.offer_id {
        return Err(FetchAdmissionCode::InvalidManifest);
    }
    if header.descriptor != card.descriptor {
        return Err(FetchAdmissionCode::InvalidManifest);
    }
    let content_kind = if header.descriptor.is_text() {
        if header.manifest_entries != 0
            || header.manifest_encoded_bytes != 0
            || header.manifest_sha256.is_some()
            || header
                .text_sha256
                .as_ref()
                .is_none_or(|hash| hash.len() != 32)
        {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
        ContentKind::Text
    } else {
        if header.text_sha256.is_some()
            || header
                .manifest_sha256
                .as_ref()
                .is_none_or(|hash| hash.len() != 32)
        {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
        match header.descriptor {
            OfferDescriptor::File { .. } => ContentKind::File,
            OfferDescriptor::Folder { .. } => ContentKind::Folder,
            OfferDescriptor::Text { .. } => unreachable!(),
        }
    };
    let total_bytes = match &header.descriptor {
        OfferDescriptor::Text { utf8_bytes, .. } => u64::from(*utf8_bytes),
        OfferDescriptor::File { total_bytes, .. } | OfferDescriptor::Folder { total_bytes, .. } => {
            *total_bytes
        }
    };
    let file_count = match &header.descriptor {
        OfferDescriptor::Text { .. } => 0,
        OfferDescriptor::File { .. } => 1,
        OfferDescriptor::Folder { file_count, .. } => *file_count,
    };
    Ok(ReceivePlan {
        content_kind,
        total_bytes,
        file_count,
        entries: Vec::new(),
        manifest_end: None,
        manifest_encoded_bytes: 0,
        manifest_sha256: header.manifest_sha256.clone(),
        text: None,
        staged_files: Vec::new(),
    })
}

fn needs_filesystem_reservation(content_kind: ContentKind, payload_bytes: u64) -> bool {
    content_kind != ContentKind::Text && payload_bytes > 0
}

fn validate_manifest(
    header: &FetchHeader,
    descriptor: &OfferDescriptor,
    plan: &ReceivePlan,
) -> Result<(), FetchAdmissionCode> {
    let entries = &plan.entries;
    if entries.len() != usize::try_from(header.manifest_entries).unwrap_or(usize::MAX) {
        return Err(FetchAdmissionCode::InvalidManifest);
    }
    let mut seen = HashSet::new();
    let mut directories = HashSet::new();
    let mut files = HashSet::new();
    let mut total_bytes = 0_u64;
    let mut file_count = 0_u32;
    let mut directory_count = 0_u32;
    for entry in entries {
        if entry.relative_path.len() > V2_MAX_RELATIVE_PATH_BYTES {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
        if entry.relative_path.is_empty() {
            if entry.kind != FileEntryKind::File {
                return Err(FetchAdmissionCode::InvalidManifest);
            }
        } else {
            validate_relative_path(&entry.relative_path)
                .map_err(|_| FetchAdmissionCode::InvalidManifest)?;
        }
        let folded = entry.relative_path.to_lowercase();
        if !seen.insert(folded) {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
        match entry.kind {
            FileEntryKind::File => {
                if entry.byte_len > V2_MAX_FILE_BYTES {
                    return Err(FetchAdmissionCode::TooLarge);
                }
                file_count = file_count
                    .checked_add(1)
                    .ok_or(FetchAdmissionCode::TooLarge)?;
                files.insert(entry.relative_path.to_lowercase());
                total_bytes = total_bytes
                    .checked_add(entry.byte_len)
                    .ok_or(FetchAdmissionCode::TooLarge)?;
            }
            FileEntryKind::Directory => {
                if entry.byte_len != 0 {
                    return Err(FetchAdmissionCode::InvalidManifest);
                }
                directory_count = directory_count
                    .checked_add(1)
                    .ok_or(FetchAdmissionCode::TooLarge)?;
                directories.insert(entry.relative_path.to_lowercase());
            }
        }
    }
    for entry in entries
        .iter()
        .filter(|entry| !entry.relative_path.is_empty())
    {
        let folded = entry.relative_path.to_lowercase();
        let components = folded.split('/').collect::<Vec<_>>();
        for end in 1..components.len() {
            let parent = components[..end].join("/");
            if files.contains(&parent) {
                return Err(FetchAdmissionCode::InvalidManifest);
            }
            if !directories.contains(&parent) {
                return Err(FetchAdmissionCode::InvalidManifest);
            }
        }
    }
    if total_bytes > V2_MAX_TRANSFER_BYTES {
        return Err(FetchAdmissionCode::TooLarge);
    }
    let expected_entries = match descriptor {
        OfferDescriptor::Text { .. } => 0,
        OfferDescriptor::File {
            total_bytes: expected,
            ..
        } => {
            if entries.len() != 1
                || entries[0].kind != FileEntryKind::File
                || !entries[0].relative_path.is_empty()
                || total_bytes != *expected
            {
                return Err(FetchAdmissionCode::InvalidManifest);
            }
            1
        }
        OfferDescriptor::Folder {
            total_bytes: expected_total,
            entry_count,
            file_count: expected_files,
            directory_count: expected_directories,
            ..
        } => {
            if total_bytes != *expected_total
                || file_count != *expected_files
                || directory_count != *expected_directories
            {
                return Err(FetchAdmissionCode::InvalidManifest);
            }
            *entry_count
        }
    };
    if u32::try_from(entries.len()).unwrap_or(u32::MAX) != expected_entries {
        return Err(FetchAdmissionCode::InvalidManifest);
    }
    if let Some(end) = &header.manifest_sha256 {
        let digest = Sha256::digest(
            serde_json::to_vec(entries).map_err(|_| FetchAdmissionCode::InvalidManifest)?,
        );
        if digest.as_slice() != end.as_slice() {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
        let Some(manifest_end) = &plan.manifest_end else {
            return Err(FetchAdmissionCode::InvalidManifest);
        };
        if manifest_end.entry_count != u32::try_from(entries.len()).unwrap_or(u32::MAX)
            || manifest_end.file_count != file_count
            || manifest_end.total_bytes != total_bytes
            || manifest_end.manifest_sha256 != *end
        {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
    }
    Ok(())
}

fn is_disconnect_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    )
}

fn protocol_read_failure(error: ProtocolError, files: u32, bytes: u64) -> ReceiveFailure {
    match error {
        ProtocolError::Io(error) if is_disconnect_io(&error) => {
            ReceiveFailure::Disconnected { files, bytes }
        }
        ProtocolError::Io(error) => ReceiveFailure::Io(NetError::Io(error)),
        error => ReceiveFailure::Protocol {
            files,
            bytes,
            detail: error.to_string(),
        },
    }
}

async fn read_v2_timeout(
    stream: &mut TcpStream,
    duration: Duration,
    files: u32,
    bytes: u64,
) -> Result<V2Message, ReceiveFailure> {
    let message = timeout(duration, meshelf_protocol::read_v2_frame_async(stream))
        .await
        .map_err(|_| ReceiveFailure::Io(NetError::Timeout("read fetch control")))?
        .map_err(|error| protocol_read_failure(error, files, bytes))?;
    validate_v2_message(&message).map_err(|error| ReceiveFailure::Protocol {
        files,
        bytes,
        detail: error.to_string(),
    })?;
    Ok(message)
}

async fn read_complete(
    stream: &mut TcpStream,
    duration: Duration,
    cancel: &mut Option<watch::Receiver<bool>>,
) -> Result<FetchComplete, ReceiveFailure> {
    let message = read_v2_cancellable(stream, duration, cancel, 0, 0).await?;
    match message {
        V2Message::FetchComplete(complete) => Ok(complete),
        V2Message::FetchAbort(abort) => Err(abort_failure(abort)),
        _ => Err(ReceiveFailure::Verification {
            files: 0,
            bytes: 0,
            detail: "expected fetch_complete".to_owned(),
        }),
    }
}

fn cancel_requested(cancel: &Option<watch::Receiver<bool>>) -> bool {
    cancel.as_ref().is_some_and(|signal| *signal.borrow())
}

fn abort_failure(abort: FetchAbort) -> ReceiveFailure {
    ReceiveFailure::Aborted {
        code: abort.code,
        files: abort.files_sent,
        bytes: abort.bytes_sent,
    }
}

async fn wait_for_cancel(cancel: &mut Option<watch::Receiver<bool>>) {
    if let Some(signal) = cancel.as_mut() {
        let _ = signal.changed().await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn read_v2_cancellable(
    stream: &mut TcpStream,
    duration: Duration,
    cancel: &mut Option<watch::Receiver<bool>>,
    files: u32,
    bytes: u64,
) -> Result<V2Message, ReceiveFailure> {
    if cancel_requested(cancel) {
        return Err(ReceiveFailure::LocalCancelled { files, bytes });
    }
    if cancel.is_none() {
        return read_v2_timeout(stream, duration, files, bytes).await;
    }
    tokio::select! {
        biased;
        result = read_v2_timeout(stream, duration, files, bytes) => result,
        () = wait_for_cancel(cancel) => {
            if cancel_requested(cancel) {
                Err(ReceiveFailure::LocalCancelled { files, bytes })
            } else {
                read_v2_timeout(stream, duration, files, bytes).await
            }
        }
    }
}

async fn read_exact_cancellable(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    duration: Duration,
    cancel: &mut Option<watch::Receiver<bool>>,
    files: u32,
    bytes: u64,
) -> Result<(), ReceiveFailure> {
    if cancel_requested(cancel) {
        return Err(ReceiveFailure::LocalCancelled { files, bytes });
    }
    if cancel.is_none() {
        return read_exact_timeout(stream, buffer, duration).await;
    }
    tokio::select! {
        biased;
        result = read_exact_timeout(stream, buffer, duration) => result,
        () = wait_for_cancel(cancel) => {
            if cancel_requested(cancel) {
                Err(ReceiveFailure::LocalCancelled { files, bytes })
            } else {
                read_exact_timeout(stream, buffer, duration).await
            }
        }
    }
}

async fn read_chunk_cancellable(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    duration: Duration,
    cancel: &mut Option<watch::Receiver<bool>>,
    files: u32,
    bytes: u64,
) -> Result<usize, ReceiveFailure> {
    if cancel_requested(cancel) {
        return Err(ReceiveFailure::LocalCancelled { files, bytes });
    }
    let read = if cancel.is_none() {
        timeout(duration, stream.read(buffer))
            .await
            .map_err(|_| ReceiveFailure::Io(NetError::Timeout("read file payload")))?
            .map_err(|error| ReceiveFailure::Io(NetError::Io(error)))?
    } else {
        tokio::select! {
            biased;
            result = timeout(duration, stream.read(&mut *buffer)) => {
                result
                    .map_err(|_| ReceiveFailure::Io(NetError::Timeout("read file payload")))?
                    .map_err(|error| ReceiveFailure::Io(NetError::Io(error)))?
            }
            () = wait_for_cancel(cancel) => {
                if cancel_requested(cancel) {
                    return Err(ReceiveFailure::LocalCancelled { files, bytes });
                }
                timeout(duration, stream.read(buffer))
                    .await
                    .map_err(|_| ReceiveFailure::Io(NetError::Timeout("read file payload")))?
                    .map_err(|error| ReceiveFailure::Io(NetError::Io(error)))?
            }
        }
    };
    Ok(read)
}

struct StagingGuard {
    store: Option<Arc<RedbV2Store>>,
    staging_root: Option<PathBuf>,
    activation_id: Option<ActivationId>,
    cleanup_blocked: Arc<AtomicBool>,
    disarmed: bool,
    keep: bool,
}

impl StagingGuard {
    fn inactive(cleanup_blocked: Arc<AtomicBool>) -> Self {
        Self {
            store: None,
            staging_root: None,
            activation_id: None,
            cleanup_blocked,
            disarmed: true,
            keep: false,
        }
    }

    fn arm(&mut self, store: Arc<RedbV2Store>, staging_root: PathBuf, activation_id: ActivationId) {
        self.store = Some(store);
        self.staging_root = Some(staging_root);
        self.activation_id = Some(activation_id);
        self.disarmed = false;
        self.keep = false;
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.disarmed || self.keep {
            return;
        }
        let Some(staging_root) = self.staging_root.as_ref() else {
            return;
        };
        let staging_failed = match remove_owned_tree(staging_root) {
            Ok(()) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => true,
        };
        let journal_failed = match (self.store.as_ref(), self.activation_id) {
            (Some(store), Some(activation_id)) => {
                store.remove_activation_journal(activation_id).is_err()
            }
            _ => false,
        };
        if staging_failed || journal_failed {
            self.cleanup_blocked.store(true, Ordering::Release);
        }
    }
}

fn manifest_invalid() -> ReceiveFailure {
    ReceiveFailure::Verification {
        files: 0,
        bytes: 0,
        detail: "invalid manifest".to_owned(),
    }
}

async fn read_manifest_frame(
    stream: &mut TcpStream,
    duration: Duration,
    cancel: &mut Option<watch::Receiver<bool>>,
) -> Result<V2Message, ReceiveFailure> {
    read_v2_cancellable(stream, duration, cancel, 0, 0).await
}

async fn read_exact_timeout(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    duration: Duration,
) -> Result<(), ReceiveFailure> {
    let _ = timeout(duration, stream.read_exact(buffer))
        .await
        .map_err(|_| ReceiveFailure::Io(NetError::Timeout("read payload")))?
        .map_err(NetError::Io)
        .map_err(ReceiveFailure::Io)?;
    Ok(())
}

async fn cleanup_staging(path: &Path) -> Result<(), std::io::Error> {
    remove_owned_tree(path)?;
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let metadata = match fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    reject_reparse_point(parent)?;
    if !metadata.is_dir() {
        return Ok(());
    }
    match fs::remove_dir(parent) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn close_staged_handles(plan: &mut ReceivePlan) {
    for staged in &mut plan.staged_files {
        drop(staged.file.take());
    }
}

async fn cleanup_activation(
    plan: &mut ReceivePlan,
    staging_root: &Path,
) -> Result<(), std::io::Error> {
    close_staged_handles(plan);
    cleanup_staging(staging_root).await
}

fn remove_published_cache_object(path: &Path) -> Result<(), std::io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    reject_reparse_point(path)?;
    if metadata.is_dir() {
        remove_owned_tree(path)
    } else {
        fs::remove_file(path)
    }
}

fn safe_detail(detail: &str) -> String {
    let mut detail = detail.replace(['\n', '\r'], " ");
    detail.truncate(256);
    detail
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use meshelf_core::{
        ActivationJournalEntry, ActivationMode, ActivationState, CardAvailability,
        ClipboardCacheRecord, ClipboardCacheState, ClipboardError, ClipboardSink, DeviceId,
        OfferAttemptCode, OfferCardInput, OfferDescriptor, OfferId,
    };
    use meshelf_protocol::{
        FetchAbort, FetchAbortCode, FetchAdmissionCode, FetchComplete, FetchHeader,
        FetchReceiptCode, FileEnd, FileEntryKind, FileStart, ManifestChunk, ManifestEnd, TextEnd,
        V2Message, read_v2_frame_async, write_v2_frame_async,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::*;

    const TEST_IO_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn nonempty_text_does_not_require_a_filesystem_reservation() {
        assert!(!needs_filesystem_reservation(ContentKind::Text, 442));
        assert!(needs_filesystem_reservation(ContentKind::File, 442));
    }

    #[derive(Debug, Default)]
    struct TestClipboard {
        files: Mutex<Vec<PathBuf>>,
        texts: Mutex<Vec<String>>,
        text_calls: Mutex<u32>,
        file_calls: Mutex<u32>,
        fail_text: Mutex<Option<ClipboardError>>,
        fail_text_after_recording: Mutex<Option<ClipboardError>>,
        fail_text_native: Mutex<bool>,
        fail_files: Mutex<bool>,
        fail_files_error: Mutex<Option<ClipboardError>>,
        fail_file_list_after_clear: Mutex<bool>,
        cleared: Mutex<bool>,
        observe_existing: Mutex<Option<PathBuf>>,
        existed_at_call: Mutex<Option<bool>>,
        durable_marker: Mutex<Option<PathBuf>>,
    }

    struct TestNative<'a> {
        clipboard: &'a TestClipboard,
    }

    impl meshelf_platform::NativeClipboard for TestNative<'_> {
        fn set_text(&mut self, text: &str) -> Result<(), String> {
            if *self
                .clipboard
                .fail_text_native
                .lock()
                .expect("native text failure lock")
            {
                return Err("NSPasteboard#writeObjects: returned false".to_owned());
            }
            self.clipboard
                .texts
                .lock()
                .expect("clipboard texts lock")
                .push(text.to_owned());
            Ok(())
        }

        fn get_text(&mut self) -> Result<String, String> {
            if let Some(error) = self
                .clipboard
                .fail_text_after_recording
                .lock()
                .expect("clipboard verify lock")
                .clone()
            {
                return Err(error.message().to_owned());
            }
            self.clipboard
                .texts
                .lock()
                .expect("clipboard texts lock")
                .last()
                .cloned()
                .ok_or_else(|| "clipboard has no text".to_owned())
        }

        fn clear(&mut self) -> Result<(), String> {
            *self
                .clipboard
                .cleared
                .lock()
                .expect("clipboard cleared lock") = true;
            self.clipboard
                .files
                .lock()
                .expect("clipboard files lock")
                .clear();
            Ok(())
        }

        fn set_file_list(&mut self, paths: &[PathBuf]) -> Result<(), String> {
            if *self
                .clipboard
                .fail_file_list_after_clear
                .lock()
                .expect("clipboard clear-then-list lock")
            {
                return Err("native file_list failed after clear".to_owned());
            }
            self.clipboard
                .files
                .lock()
                .expect("clipboard files lock")
                .extend(paths.iter().cloned());
            Ok(())
        }

        fn get_file_list(&mut self) -> Result<Vec<PathBuf>, String> {
            Ok(self
                .clipboard
                .files
                .lock()
                .expect("clipboard files lock")
                .clone())
        }
    }

    impl ClipboardSink for TestClipboard {
        fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
            *self.text_calls.lock().expect("clipboard text lock") += 1;
            if let Some(error) = self
                .fail_text
                .lock()
                .expect("clipboard text failure lock")
                .clone()
            {
                return Err(error);
            }
            meshelf_platform::write_text_on(&mut TestNative { clipboard: self }, text)
        }
    }

    impl FetchClipboard for TestClipboard {
        fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
            *self.file_calls.lock().expect("clipboard file lock") += 1;
            if let Some(path) = self
                .observe_existing
                .lock()
                .expect("clipboard observe lock")
                .as_ref()
            {
                *self.existed_at_call.lock().expect("clipboard result lock") = Some(path.exists());
            }
            if let Some(error) = self
                .fail_files_error
                .lock()
                .expect("clipboard file error lock")
                .clone()
            {
                return Err(error);
            }
            if *self.fail_files.lock().expect("clipboard failure lock") {
                return Err(ClipboardError::new("test clipboard failure"));
            }
            meshelf_platform::write_files_on(&mut TestNative { clipboard: self }, paths)?;
            if let Some(marker) = self
                .durable_marker
                .lock()
                .expect("clipboard marker lock")
                .as_ref()
            {
                fs::write(marker, b"clipboard side effect durable")
                    .expect("write side effect marker");
            }
            Ok(())
        }
    }

    struct FileActivation {
        activation: FetchActivation,
        descriptor: OfferDescriptor,
        chunk: ManifestChunk,
        manifest_sha256: Vec<u8>,
        manifest_encoded_bytes: u64,
    }

    struct TextActivation {
        activation: FetchActivation,
        descriptor: OfferDescriptor,
        text: String,
        digest: Vec<u8>,
    }

    struct ReceiverFixture {
        _directory: tempfile::TempDir,
        state_root: PathBuf,
        store: Arc<RedbV2Store>,
        clipboard: Arc<TestClipboard>,
        source_device: DeviceId,
        destination: PathBuf,
    }

    impl ReceiverFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary receiver directory");
            let state_root = fs::canonicalize(directory.path()).expect("canonical state root");
            let store = Arc::new(
                RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
            );
            Self {
                destination: state_root.join("save-destination"),
                state_root,
                store,
                clipboard: Arc::new(TestClipboard::default()),
                source_device: DeviceId::new(),
                _directory: directory,
            }
        }

        fn file_activation(
            &self,
            mode: ActivationMode,
            destination: Option<PathBuf>,
        ) -> FileActivation {
            let offer_id = OfferId::new();
            let request_id = ActivationId::new();
            let descriptor = OfferDescriptor::File {
                root_name: "payload.txt".to_owned(),
                total_bytes: 3,
            };
            self.store
                .insert_offer_card(OfferCardInput::new(
                    self.source_device,
                    offer_id,
                    descriptor.clone(),
                    CardAvailability::Available,
                ))
                .expect("insert offer card");
            let entry = ManifestEntry {
                relative_path: String::new(),
                kind: FileEntryKind::File,
                byte_len: 3,
            };
            let manifest_sha256 = Sha256::digest(
                serde_json::to_vec(std::slice::from_ref(&entry)).expect("manifest json"),
            )
            .to_vec();
            let chunk = ManifestChunk::new(request_id, 0, vec![entry]).expect("manifest chunk");
            let manifest_encoded_bytes =
                meshelf_protocol::encoded_manifest_bytes(std::slice::from_ref(&chunk))
                    .expect("manifest size") as u64;
            FileActivation {
                activation: FetchActivation::new(
                    request_id,
                    self.source_device,
                    offer_id,
                    mode,
                    destination,
                ),
                descriptor,
                chunk,
                manifest_sha256,
                manifest_encoded_bytes,
            }
        }

        fn text_activation(&self, text: &str) -> TextActivation {
            let offer_id = OfferId::new();
            let request_id = ActivationId::new();
            let descriptor = OfferDescriptor::text(text).expect("text descriptor");
            self.store
                .insert_offer_card(OfferCardInput::new(
                    self.source_device,
                    offer_id,
                    descriptor.clone(),
                    CardAvailability::Available,
                ))
                .expect("insert text offer card");
            TextActivation {
                activation: FetchActivation::new(
                    request_id,
                    self.source_device,
                    offer_id,
                    ActivationMode::Clipboard,
                    None,
                ),
                descriptor,
                text: text.to_owned(),
                digest: Sha256::digest(text.as_bytes()).to_vec(),
            }
        }

        fn receiver(&self) -> Arc<FetchReceiver<TestClipboard>> {
            Arc::new(FetchReceiver::with_ledger(
                DeviceId::new(),
                self.store.clone(),
                self.clipboard.clone(),
                self.state_root.clone(),
                ReservationLedger::default(),
            ))
        }

        async fn start(
            &self,
            activation: &FileActivation,
        ) -> (
            TcpStream,
            tokio::task::JoinHandle<Result<ActivationOutcome, NetError>>,
            FetchAdmission,
        ) {
            self.start_with(self.receiver(), activation).await
        }

        async fn start_with(
            &self,
            receiver: Arc<FetchReceiver<TestClipboard>>,
            activation: &FileActivation,
        ) -> (
            TcpStream,
            tokio::task::JoinHandle<Result<ActivationOutcome, NetError>>,
            FetchAdmission,
        ) {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind receiver test listener");
            let address = listener.local_addr().expect("receiver test address");
            let source_device = activation.activation.source_device;
            let receiver_activation = activation.activation.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept receiver test");
                receiver
                    .receive(
                        source_device,
                        receiver_activation,
                        &mut stream,
                        TEST_IO_TIMEOUT,
                    )
                    .await
            });
            let mut client = TcpStream::connect(address)
                .await
                .expect("connect receiver test");
            write_v2_frame_async(
                &mut client,
                &V2Message::FetchHeader(FetchHeader {
                    request_id: activation.activation.request_id,
                    offer_id: activation.activation.offer_id,
                    descriptor: activation.descriptor.clone(),
                    manifest_entries: 1,
                    manifest_encoded_bytes: activation.manifest_encoded_bytes,
                    text_sha256: None,
                    manifest_sha256: Some(activation.manifest_sha256.clone()),
                }),
            )
            .await
            .expect("write fetch header");
            write_v2_frame_async(
                &mut client,
                &V2Message::ManifestChunk(activation.chunk.clone()),
            )
            .await
            .expect("write manifest chunk");
            write_v2_frame_async(
                &mut client,
                &V2Message::ManifestEnd(ManifestEnd {
                    request_id: activation.activation.request_id,
                    entry_count: 1,
                    file_count: 1,
                    total_bytes: 3,
                    manifest_sha256: activation.manifest_sha256.clone(),
                }),
            )
            .await
            .expect("write manifest end");
            let response = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(&mut client))
                .await
                .expect("read admission timeout")
                .expect("read admission");
            let V2Message::FetchAdmission(admission) = response else {
                panic!("expected fetch admission");
            };
            (client, server, admission)
        }

        async fn start_text(
            &self,
            activation: &TextActivation,
        ) -> (
            TcpStream,
            tokio::task::JoinHandle<Result<ActivationOutcome, NetError>>,
            FetchAdmission,
        ) {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind text receiver test listener");
            let address = listener.local_addr().expect("text receiver test address");
            let source_device = activation.activation.source_device;
            let receiver_activation = activation.activation.clone();
            let receiver = self.receiver();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept text receiver test");
                receiver
                    .receive(
                        source_device,
                        receiver_activation,
                        &mut stream,
                        TEST_IO_TIMEOUT,
                    )
                    .await
            });
            let mut client = TcpStream::connect(address)
                .await
                .expect("connect text receiver test");
            write_v2_frame_async(
                &mut client,
                &V2Message::FetchHeader(FetchHeader {
                    request_id: activation.activation.request_id,
                    offer_id: activation.activation.offer_id,
                    descriptor: activation.descriptor.clone(),
                    manifest_entries: 0,
                    manifest_encoded_bytes: 0,
                    text_sha256: Some(activation.digest.clone()),
                    manifest_sha256: None,
                }),
            )
            .await
            .expect("write text fetch header");
            let response = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(&mut client))
                .await
                .expect("read text admission timeout")
                .expect("read text admission");
            let V2Message::FetchAdmission(admission) = response else {
                panic!("expected text fetch admission");
            };
            (client, server, admission)
        }
    }

    fn assert_no_payload_artifacts(root: &Path) {
        fn walk(path: &Path, bytes: &mut u64) {
            for entry in fs::read_dir(path).expect("read test filesystem") {
                let entry = entry.expect("test directory entry");
                let child = entry.path();
                let metadata = fs::symlink_metadata(&child).expect("test metadata");
                let name = child
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                assert!(!name.starts_with("staging") && !name.starts_with("candidate-"));
                if metadata.is_dir() {
                    walk(&child, bytes);
                } else if name != "offers.redb" {
                    *bytes = bytes.saturating_add(metadata.len());
                }
            }
        }
        let mut bytes = 0;
        walk(root, &mut bytes);
        assert_eq!(bytes, 0, "payload bytes survived cleanup under {root:?}");
    }

    fn fail_preallocation(_file: &File, _length: u64) -> std::io::Result<()> {
        Err(std::io::Error::other("injected preallocation failure"))
    }

    async fn send_file_and_complete(
        client: &mut TcpStream,
        activation: &FileActivation,
        bytes: &[u8],
        file_digest: Vec<u8>,
    ) -> meshelf_protocol::FetchReceipt {
        write_v2_frame_async(
            client,
            &V2Message::FileStart(FileStart {
                request_id: activation.activation.request_id,
                entry_index: 0,
                byte_len: 3,
            }),
        )
        .await
        .expect("write file start");
        client.write_all(bytes).await.expect("write file bytes");
        write_v2_frame_async(
            client,
            &V2Message::FileEnd(FileEnd {
                request_id: activation.activation.request_id,
                entry_index: 0,
                sha256: file_digest.clone(),
            }),
        )
        .await
        .expect("write file end");
        let mut content_set = Sha256::new();
        content_set.update(&activation.manifest_sha256);
        content_set.update(&file_digest);
        write_v2_frame_async(
            client,
            &V2Message::FetchComplete(FetchComplete {
                request_id: activation.activation.request_id,
                files_sent: 1,
                bytes_sent: 3,
                content_set_sha256: content_set.finalize().to_vec(),
            }),
        )
        .await
        .expect("write fetch complete");
        let response = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(client))
            .await
            .expect("read receipt timeout")
            .expect("read receipt");
        let V2Message::FetchReceipt(receipt) = response else {
            panic!("expected fetch receipt");
        };
        receipt
    }

    async fn send_text_and_complete(
        client: &mut TcpStream,
        activation: &TextActivation,
    ) -> meshelf_protocol::FetchReceipt {
        client
            .write_all(activation.text.as_bytes())
            .await
            .expect("write text bytes");
        write_v2_frame_async(
            client,
            &V2Message::TextEnd(TextEnd {
                request_id: activation.activation.request_id,
                sha256: activation.digest.clone(),
            }),
        )
        .await
        .expect("write text end");
        write_v2_frame_async(
            client,
            &V2Message::FetchComplete(FetchComplete {
                request_id: activation.activation.request_id,
                files_sent: 0,
                bytes_sent: activation.text.len() as u64,
                content_set_sha256: activation.digest.clone(),
            }),
        )
        .await
        .expect("write text complete");
        let message = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(client))
            .await
            .expect("read text receipt timeout")
            .expect("read text receipt");
        let V2Message::FetchReceipt(receipt) = message else {
            panic!("expected text fetch receipt");
        };
        receipt
    }

    #[tokio::test]
    async fn completed_text_activation_performed_the_exact_clipboard_write() {
        let fixture = ReceiverFixture::new();
        let text = format!("HEAD-{}-TAIL", "x".repeat(428));
        assert_eq!(text.len(), 438);
        let activation = fixture.text_activation(&text);
        let (mut client, server, admission) = fixture.start_text(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);

        let receipt = send_text_and_complete(&mut client, &activation).await;
        assert_eq!(receipt.code, FetchReceiptCode::Completed);
        assert_eq!(receipt.files_received, 0);
        assert_eq!(receipt.bytes_received, text.len() as u64);
        server
            .await
            .expect("text receiver task")
            .expect("completed text activation");
        assert_eq!(
            fixture
                .clipboard
                .texts
                .lock()
                .expect("clipboard texts")
                .as_slice(),
            [text]
        );
    }

    #[tokio::test]
    async fn failed_text_clipboard_write_is_counted_clipboard_failed_not_completed() {
        let fixture = ReceiverFixture::new();
        let text = format!("HEAD-{}-TAIL", "x".repeat(430));
        let activation = fixture.text_activation(&text);
        *fixture
            .clipboard
            .fail_text
            .lock()
            .expect("clipboard text failure lock") =
            Some(ClipboardError::new("injected text clipboard failure"));
        let (mut client, server, admission) = fixture.start_text(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);

        let receipt = send_text_and_complete(&mut client, &activation).await;
        assert_eq!(receipt.code, FetchReceiptCode::ClipboardFailed);
        assert_eq!(receipt.files_received, 0);
        assert_eq!(receipt.bytes_received, text.len() as u64);
        assert!(
            receipt
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("injected text clipboard failure"))
        );
        assert_eq!(
            server
                .await
                .expect("text receiver task")
                .expect("typed result"),
            ActivationOutcome::Failed(crate::ActivationFailCode::ClipboardFailed)
        );
        assert!(
            fixture
                .clipboard
                .texts
                .lock()
                .expect("clipboard texts")
                .is_empty()
        );
    }

    #[test]
    fn clipboard_worker_crash_is_uncertain_not_terminal() {
        assert!(matches!(
            classify_clipboard_failure(ClipboardError::uncertain("worker stopped")),
            SideEffectFailure::Uncertain(_)
        ));
        assert!(matches!(
            classify_clipboard_failure(ClipboardError::new("platform rejected write")),
            SideEffectFailure::Terminal(_)
        ));
    }

    #[test]
    fn two_same_filesystem_reservations_cannot_overcommit() {
        let directory =
            std::env::temp_dir().join(format!("meshelf-ledger-{}", ActivationId::new()));
        fs::create_dir(&directory).expect("create ledger test directory");
        let key = filesystem_key(&directory).expect("filesystem key");
        let ledger = ReservationLedger::default();
        let total = 100_u64 * 1024 * 1024 * 1024;
        let available = 5_u64 * 1024 * 1024 * 1024 + 1536;
        let first = ledger
            .reserve_with_capacity(key.clone(), available, total, 1024)
            .expect("first reservation");
        assert!(matches!(
            ledger.reserve_with_capacity(key, available, total, 1024),
            Err(ReservationError::InsufficientSpace { .. })
        ));
        drop(first);
        fs::remove_dir(&directory).expect("remove ledger test directory");
    }

    #[cfg(unix)]
    #[test]
    fn different_filesystems_have_independent_reservations() {
        let directory = std::env::temp_dir().join(format!(
            "meshelf-ledger-independent-{}",
            ActivationId::new()
        ));
        fs::create_dir(&directory).expect("create ledger test directory");
        let first_key = filesystem_key(&directory).expect("temporary filesystem key");
        let second_key = filesystem_key(Path::new("/dev")).expect("device filesystem key");
        assert_ne!(first_key, second_key);

        let ledger = ReservationLedger::default();
        let available = 6_u64 * 1024 * 1024 * 1024;
        let total = 100_u64 * 1024 * 1024 * 1024;
        let first = ledger
            .reserve_with_capacity(first_key, available, total, 1024)
            .expect("first reservation");
        let second = ledger
            .reserve_with_capacity(second_key, available, total, 1024)
            .expect("independent reservation");
        drop((first, second));
        fs::remove_dir(&directory).expect("remove ledger test directory");
    }

    #[tokio::test]
    async fn receiver_admits_only_after_manifest_validation_and_preallocation() {
        let directory = tempfile::tempdir().expect("temporary receiver directory");
        let state_root = fs::canonicalize(directory.path()).expect("canonical state root");
        let store = Arc::new(
            RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
        );
        let source_device = DeviceId::new();
        let offer_id = OfferId::new();
        let request_id = ActivationId::new();
        let descriptor = OfferDescriptor::File {
            root_name: "payload.txt".to_owned(),
            total_bytes: 3,
        };
        store
            .insert_offer_card(OfferCardInput::new(
                source_device,
                offer_id,
                descriptor.clone(),
                CardAvailability::Available,
            ))
            .expect("insert offer card");
        let entry = ManifestEntry {
            relative_path: String::new(),
            kind: FileEntryKind::File,
            byte_len: 3,
        };
        let entries = vec![entry.clone()];
        let manifest_sha256 = Sha256::digest(serde_json::to_vec(&entries).expect("manifest json"));
        let chunk = ManifestChunk::new(request_id, 0, entries).expect("manifest chunk");
        let manifest_encoded_bytes =
            meshelf_protocol::encoded_manifest_bytes(std::slice::from_ref(&chunk))
                .expect("manifest size");
        let activation = FetchActivation::new(
            request_id,
            source_device,
            offer_id,
            ActivationMode::Clipboard,
            None,
        );
        let clipboard = Arc::new(TestClipboard::default());
        let receiver = Arc::new(FetchReceiver::with_ledger(
            DeviceId::new(),
            store,
            clipboard.clone(),
            state_root.clone(),
            ReservationLedger::default(),
        ));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind receiver test listener");
        let address = listener.local_addr().expect("receiver test address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept receiver test");
            receiver
                .receive(source_device, activation, &mut stream, TEST_IO_TIMEOUT)
                .await
                .expect("receive file activation");
        });
        let mut client = TcpStream::connect(address)
            .await
            .expect("connect receiver test");
        write_v2_frame_async(
            &mut client,
            &V2Message::FetchHeader(FetchHeader {
                request_id,
                offer_id,
                descriptor,
                manifest_entries: 1,
                manifest_encoded_bytes: manifest_encoded_bytes as u64,
                text_sha256: None,
                manifest_sha256: Some(manifest_sha256.to_vec()),
            }),
        )
        .await
        .expect("write fetch header");
        write_v2_frame_async(&mut client, &V2Message::ManifestChunk(chunk))
            .await
            .expect("write manifest chunk");
        write_v2_frame_async(
            &mut client,
            &V2Message::ManifestEnd(ManifestEnd {
                request_id,
                entry_count: 1,
                file_count: 1,
                total_bytes: 3,
                manifest_sha256: manifest_sha256.to_vec(),
            }),
        )
        .await
        .expect("write manifest end");
        let admission = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(&mut client))
            .await
            .expect("read admission timeout")
            .expect("read admission");
        let V2Message::FetchAdmission(admission) = admission else {
            panic!("expected fetch admission");
        };
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        assert_eq!(admission.entries_reserved, 1);
        assert_eq!(admission.bytes_reserved, 3);
        let staged_file = state_root
            .join("staging")
            .join(request_id.to_string())
            .join("payload");
        assert_eq!(fs::metadata(&staged_file).expect("staged file").len(), 3);

        let bytes = b"abc";
        let file_digest = Sha256::digest(bytes).to_vec();
        write_v2_frame_async(
            &mut client,
            &V2Message::FileStart(FileStart {
                request_id,
                entry_index: 0,
                byte_len: 3,
            }),
        )
        .await
        .expect("write file start");
        client.write_all(bytes).await.expect("write file bytes");
        write_v2_frame_async(
            &mut client,
            &V2Message::FileEnd(FileEnd {
                request_id,
                entry_index: 0,
                sha256: file_digest.clone(),
            }),
        )
        .await
        .expect("write file end");
        let mut content_set = Sha256::new();
        content_set.update(manifest_sha256);
        content_set.update(file_digest);
        write_v2_frame_async(
            &mut client,
            &V2Message::FetchComplete(FetchComplete {
                request_id,
                files_sent: 1,
                bytes_sent: 3,
                content_set_sha256: content_set.finalize().to_vec(),
            }),
        )
        .await
        .expect("write fetch complete");
        let receipt = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(&mut client))
            .await
            .expect("read receipt timeout")
            .expect("read receipt");
        let V2Message::FetchReceipt(receipt) = receipt else {
            panic!("expected fetch receipt");
        };
        assert_eq!(receipt.code, FetchReceiptCode::Completed);
        assert_eq!(
            clipboard.files.lock().expect("clipboard files lock").len(),
            1
        );
        server.await.expect("receiver task");
    }

    #[tokio::test]
    async fn allocation_failure_cleans_before_admission() {
        let fixture = ReceiverFixture::new();
        let activation =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let receiver = Arc::new(FetchReceiver::with_preallocator_for_test(
            DeviceId::new(),
            fixture.store.clone(),
            fixture.clipboard.clone(),
            fixture.state_root.clone(),
            ReservationLedger::default(),
            fail_preallocation,
        ));
        let (client, server, admission) = fixture.start_with(receiver, &activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::AllocationFailed);
        assert_eq!(admission.entries_reserved, 0);
        assert_eq!(admission.bytes_reserved, 0);
        drop(client);
        assert_eq!(
            server.await.expect("receiver task").expect("typed result"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::AllocationFailed)
        );
        assert_no_payload_artifacts(&fixture.state_root);
    }

    #[tokio::test]
    async fn receipt_is_not_sent_before_durable_side_effect() {
        let fixture = ReceiverFixture::new();
        let marker = fixture.state_root.join("clipboard-side-effect-marker");
        *fixture
            .clipboard
            .durable_marker
            .lock()
            .expect("clipboard marker lock") = Some(marker.clone());
        let activation = fixture.file_activation(ActivationMode::Clipboard, None);
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let bytes = b"abc";
        let digest = Sha256::digest(bytes).to_vec();
        let receipt = send_file_and_complete(&mut client, &activation, bytes, digest).await;
        assert_eq!(receipt.code, FetchReceiptCode::Completed);
        assert!(
            marker.exists(),
            "receipt arrived before the durable side-effect marker"
        );
        assert_eq!(fixture.clipboard.files.lock().expect("file calls").len(), 1);
        server
            .await
            .expect("receiver task")
            .expect("clipboard receipt");
    }

    #[tokio::test]
    async fn hash_mismatch_removes_staging_before_failure_status() {
        let fixture = ReceiverFixture::new();
        let activation =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        write_v2_frame_async(
            &mut client,
            &V2Message::FileStart(FileStart {
                request_id: activation.activation.request_id,
                entry_index: 0,
                byte_len: 3,
            }),
        )
        .await
        .expect("write file start");
        client.write_all(b"abc").await.expect("write file bytes");
        write_v2_frame_async(
            &mut client,
            &V2Message::FileEnd(FileEnd {
                request_id: activation.activation.request_id,
                entry_index: 0,
                sha256: vec![0; 32],
            }),
        )
        .await
        .expect("write wrong file digest");
        let response = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(&mut client))
            .await
            .expect("read verification receipt timeout")
            .expect("read verification receipt");
        let V2Message::FetchReceipt(receipt) = response else {
            panic!("expected verification receipt");
        };
        assert_eq!(receipt.code, FetchReceiptCode::VerificationFailed);
        assert_eq!(receipt.files_received, 0);
        assert_eq!(receipt.bytes_received, 3);
        assert_eq!(
            server.await.expect("receiver task").expect("typed result"),
            ActivationOutcome::Failed(crate::ActivationFailCode::VerificationFailed)
        );
        assert_no_payload_artifacts(&fixture.state_root);
        let attempt = fixture
            .store
            .get_offer_card(
                activation.activation.source_device,
                activation.activation.offer_id,
            )
            .expect("read card")
            .expect("card")
            .last_attempt
            .expect("verification attempt");
        assert_eq!(attempt.code, OfferAttemptCode::VerificationFailed);
        assert_eq!(attempt.files_processed, 0);
        assert_eq!(attempt.bytes_processed, 3);
    }

    #[tokio::test]
    async fn disconnect_mid_file_removes_staging_and_reports_counts() {
        let fixture = ReceiverFixture::new();
        let activation =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        write_v2_frame_async(
            &mut client,
            &V2Message::FileStart(FileStart {
                request_id: activation.activation.request_id,
                entry_index: 0,
                byte_len: 3,
            }),
        )
        .await
        .expect("write file start");
        client.write_all(b"a").await.expect("write partial payload");
        drop(client);
        assert_eq!(
            server.await.expect("receiver task").expect("typed result"),
            ActivationOutcome::Failed(crate::ActivationFailCode::ConnectionLost)
        );
        assert_no_payload_artifacts(&fixture.state_root);
        let attempt = fixture
            .store
            .get_offer_card(
                activation.activation.source_device,
                activation.activation.offer_id,
            )
            .expect("read card")
            .expect("card")
            .last_attempt
            .expect("disconnect attempt");
        assert_eq!(attempt.code, OfferAttemptCode::Failed);
        assert_eq!(attempt.files_processed, 0);
        assert_eq!(attempt.bytes_processed, 1);
    }

    #[tokio::test]
    async fn cancel_closes_socket_and_removes_staging() {
        let fixture = ReceiverFixture::new();
        let activation =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        write_v2_frame_async(
            &mut client,
            &V2Message::FetchAbort(FetchAbort {
                request_id: activation.activation.request_id,
                code: FetchAbortCode::Cancelled,
                files_sent: 0,
                bytes_sent: 0,
                detail: None,
            }),
        )
        .await
        .expect("write cancellation");
        let response = timeout(TEST_IO_TIMEOUT, read_v2_frame_async(&mut client))
            .await
            .expect("read cancellation receipt timeout")
            .expect("read cancellation receipt");
        let V2Message::FetchReceipt(receipt) = response else {
            panic!("expected cancellation receipt");
        };
        assert_eq!(receipt.code, FetchReceiptCode::Cancelled);
        assert_eq!(receipt.files_received, 0);
        assert_eq!(receipt.bytes_received, 0);
        let mut eof = [0_u8; 1];
        assert_eq!(
            timeout(TEST_IO_TIMEOUT, client.read(&mut eof))
                .await
                .expect("socket close timeout")
                .expect("socket close"),
            0
        );
        assert_eq!(
            server.await.expect("receiver task").expect("typed result"),
            ActivationOutcome::Cancelled
        );
        assert_no_payload_artifacts(&fixture.state_root);
        let attempt = fixture
            .store
            .get_offer_card(
                activation.activation.source_device,
                activation.activation.offer_id,
            )
            .expect("read card")
            .expect("card")
            .last_attempt
            .expect("cancel attempt");
        assert_eq!(attempt.code, OfferAttemptCode::Cancelled);
    }

    #[tokio::test]
    async fn save_mode_publishes_no_replace_to_configured_destination() {
        let fixture = ReceiverFixture::new();
        let first =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let (mut first_client, first_server, first_admission) = fixture.start(&first).await;
        assert_eq!(first_admission.code, FetchAdmissionCode::Accepted);
        let bytes = b"abc";
        let digest = Sha256::digest(bytes).to_vec();
        let receipt =
            send_file_and_complete(&mut first_client, &first, bytes, digest.clone()).await;
        assert_eq!(receipt.code, FetchReceiptCode::Completed);
        first_server
            .await
            .expect("first receiver task")
            .expect("first save");
        assert_eq!(
            fs::read(fixture.destination.join("payload.txt")).expect("first payload"),
            bytes
        );

        let second =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let (mut second_client, second_server, second_admission) = fixture.start(&second).await;
        assert_eq!(second_admission.code, FetchAdmissionCode::Accepted);
        let receipt = send_file_and_complete(&mut second_client, &second, bytes, digest).await;
        assert_eq!(receipt.code, FetchReceiptCode::Completed);
        second_server
            .await
            .expect("second receiver task")
            .expect("second save");
        assert_eq!(
            fs::read(fixture.destination.join("payload.txt")).expect("original payload"),
            bytes
        );
        assert_eq!(
            fs::read(fixture.destination.join("payload (2).txt")).expect("collision payload"),
            bytes
        );
    }

    #[test]
    fn clipboard_mode_keeps_one_completed_and_one_inflight() {
        let fixture = ReceiverFixture::new();
        let cache_root = fixture.state_root.join("clipboard-cache");
        fs::create_dir_all(&cache_root).expect("cache root");
        let completed_path = cache_root.join("candidate-completed");
        let inflight_path = cache_root.join("candidate-inflight");
        fs::write(&completed_path, b"old").expect("completed cache");
        fs::write(&inflight_path, b"new").expect("inflight cache");
        fixture
            .store
            .set_clipboard_cache(&ClipboardCacheRecord {
                activation_id: ActivationId::new(),
                state: ClipboardCacheState::Completed,
                payload_path: completed_path.clone(),
            })
            .expect("completed index");
        fixture
            .store
            .set_clipboard_cache(&ClipboardCacheRecord {
                activation_id: ActivationId::new(),
                state: ClipboardCacheState::InFlight,
                payload_path: inflight_path.clone(),
            })
            .expect("inflight index");
        assert_eq!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::Completed)
                .expect("completed lookup")
                .expect("completed")
                .payload_path,
            completed_path
        );
        assert_eq!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::InFlight)
                .expect("inflight lookup")
                .expect("inflight")
                .payload_path,
            inflight_path
        );
        assert_eq!(fs::read_dir(cache_root).expect("cache entries").count(), 2);
    }

    #[tokio::test]
    async fn failed_new_clipboard_pull_preserves_previous_cache() {
        let fixture = ReceiverFixture::new();
        let first = fixture.file_activation(ActivationMode::Clipboard, None);
        let (mut first_client, first_server, first_admission) = fixture.start(&first).await;
        assert_eq!(first_admission.code, FetchAdmissionCode::Accepted);
        let bytes = b"abc";
        let digest = Sha256::digest(bytes).to_vec();
        assert_eq!(
            send_file_and_complete(&mut first_client, &first, bytes, digest.clone())
                .await
                .code,
            FetchReceiptCode::Completed
        );
        first_server
            .await
            .expect("first receiver task")
            .expect("first clipboard");
        let old = fixture
            .store
            .get_clipboard_cache(ClipboardCacheState::Completed)
            .expect("old lookup")
            .expect("old cache");
        assert!(old.payload_path.exists());

        *fixture
            .clipboard
            .fail_files
            .lock()
            .expect("clipboard failure lock") = true;
        let second = fixture.file_activation(ActivationMode::Clipboard, None);
        let (mut second_client, second_server, second_admission) = fixture.start(&second).await;
        assert_eq!(second_admission.code, FetchAdmissionCode::Accepted);
        let receipt = send_file_and_complete(&mut second_client, &second, bytes, digest).await;
        assert_eq!(receipt.code, FetchReceiptCode::ClipboardFailed);
        assert_eq!(
            second_server
                .await
                .expect("second receiver task")
                .expect("typed result"),
            ActivationOutcome::Failed(crate::ActivationFailCode::ClipboardFailed)
        );
        assert!(old.payload_path.exists());
        assert!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::InFlight)
                .expect("inflight lookup")
                .is_none()
        );
        assert_eq!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::Completed)
                .expect("completed lookup")
                .expect("completed cache")
                .payload_path,
            old.payload_path
        );
    }

    #[tokio::test]
    async fn successful_new_clipboard_pull_deletes_previous_cache_after_the_write() {
        let fixture = ReceiverFixture::new();
        let first = fixture.file_activation(ActivationMode::Clipboard, None);
        let (mut first_client, first_server, first_admission) = fixture.start(&first).await;
        assert_eq!(first_admission.code, FetchAdmissionCode::Accepted);
        let bytes = b"abc";
        let digest = Sha256::digest(bytes).to_vec();
        assert_eq!(
            send_file_and_complete(&mut first_client, &first, bytes, digest.clone())
                .await
                .code,
            FetchReceiptCode::Completed
        );
        first_server
            .await
            .expect("first receiver task")
            .expect("first clipboard");
        let old = fixture
            .store
            .get_clipboard_cache(ClipboardCacheState::Completed)
            .expect("old lookup")
            .expect("old cache");
        *fixture
            .clipboard
            .observe_existing
            .lock()
            .expect("clipboard observe lock") = Some(old.payload_path.clone());

        let second = fixture.file_activation(ActivationMode::Clipboard, None);
        let (mut second_client, second_server, second_admission) = fixture.start(&second).await;
        assert_eq!(second_admission.code, FetchAdmissionCode::Accepted);
        assert_eq!(
            send_file_and_complete(&mut second_client, &second, bytes, digest)
                .await
                .code,
            FetchReceiptCode::Completed
        );
        second_server
            .await
            .expect("second receiver task")
            .expect("second clipboard");
        assert_eq!(
            *fixture
                .clipboard
                .existed_at_call
                .lock()
                .expect("clipboard result lock"),
            Some(true)
        );
        assert!(
            !old.payload_path.exists(),
            "old cache must be evicted after clipboard write"
        );
        let current = fixture
            .store
            .get_clipboard_cache(ClipboardCacheState::Completed)
            .expect("current lookup")
            .expect("current cache");
        assert_ne!(current.payload_path, old.payload_path);
        assert!(current.payload_path.exists());
    }

    #[test]
    fn uncertain_candidate_survives_recovery_without_replay() {
        let fixture = ReceiverFixture::new();
        let cache_root = fixture.state_root.join("clipboard-cache");
        fs::create_dir_all(&cache_root).expect("cache root");
        let candidate = cache_root.join("candidate-uncertain");
        fs::write(&candidate, b"candidate").expect("uncertain candidate");
        let activation_id = ActivationId::new();
        fixture
            .store
            .set_clipboard_cache(&ClipboardCacheRecord {
                activation_id,
                state: ClipboardCacheState::InFlight,
                payload_path: candidate.clone(),
            })
            .expect("uncertain cache index");
        fixture
            .store
            .journal_activation(&ActivationJournalEntry {
                activation_id,
                source_device: fixture.source_device,
                offer_id: OfferId::new(),
                mode: ActivationMode::Clipboard,
                staging_root: fixture
                    .state_root
                    .join("staging")
                    .join(activation_id.to_string()),
                state: ActivationState::ApplyingClipboard,
                reserved_entries: 1,
                reserved_bytes: 7,
            })
            .expect("uncertain journal");
        let receiver = fixture.receiver();
        receiver.startup_cleanup().expect("startup recovery");
        assert!(candidate.exists());
        assert_eq!(*fixture.clipboard.text_calls.lock().expect("text calls"), 0);
        assert!(
            fixture
                .clipboard
                .files
                .lock()
                .expect("file calls")
                .is_empty()
        );
        assert!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::InFlight)
                .expect("inflight lookup")
                .is_some()
        );
    }

    #[tokio::test]
    async fn unresolved_uncertainty_refuses_another_file_clipboard_pull() {
        let fixture = ReceiverFixture::new();
        let cache_root = fixture.state_root.join("clipboard-cache");
        fs::create_dir_all(&cache_root).expect("cache root");
        let candidate = cache_root.join("candidate-uncertain");
        fs::write(&candidate, b"candidate").expect("uncertain candidate");
        fixture
            .store
            .set_clipboard_cache(&ClipboardCacheRecord {
                activation_id: ActivationId::new(),
                state: ClipboardCacheState::InFlight,
                payload_path: candidate.clone(),
            })
            .expect("uncertain cache index");
        let receiver = fixture.receiver();
        receiver.startup_cleanup().expect("startup recovery");
        let activation = fixture.file_activation(ActivationMode::Clipboard, None);
        let (client, server, admission) = fixture.start_with(receiver, &activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::RefusedBusy);
        assert_eq!(admission.entries_reserved, 0);
        assert_eq!(admission.bytes_reserved, 0);
        drop(client);
        assert_eq!(
            server.await.expect("receiver task").expect("typed result"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::Busy)
        );
        assert!(candidate.exists());
        assert!(
            fixture
                .clipboard
                .files
                .lock()
                .expect("file calls")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn uncertain_file_clipboard_survives_recovery_and_refuses_replay() {
        let fixture = ReceiverFixture::new();
        *fixture
            .clipboard
            .fail_files_error
            .lock()
            .expect("uncertain files") = Some(ClipboardError::uncertain("native clipboard raced"));
        let activation = fixture.file_activation(ActivationMode::Clipboard, None);
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let bytes = b"abc";
        let digest = Sha256::digest(bytes).to_vec();
        let receipt = send_file_and_complete(&mut client, &activation, bytes, digest).await;
        assert_eq!(receipt.code, FetchReceiptCode::UncertainNoReplay);
        assert_eq!(
            server.await.expect("receiver task").expect("typed result"),
            ActivationOutcome::UncertainNoReplay
        );
        assert!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::InFlight)
                .expect("inflight")
                .is_some()
        );
        let journal = fixture
            .store
            .get_activation_journal(activation.activation.request_id)
            .expect("journal")
            .expect("uncertain journal");
        assert_eq!(journal.state, ActivationState::UncertainNoReplay);
        let service = crate::ActivationService::new(
            DeviceId::new(),
            fixture.store.clone(),
            fixture.clipboard.clone(),
            fixture.state_root.clone(),
        );
        service.recover().expect("startup recovery");
        assert!(
            fixture
                .store
                .get_activation_journal(activation.activation.request_id)
                .expect("journal after recovery")
                .is_some(),
            "uncertain marker must survive startup cleanup"
        );
        assert!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::InFlight)
                .expect("inflight after recovery")
                .is_some()
        );
        let replay = fixture.file_activation(ActivationMode::Clipboard, None);
        let (client, replay_server, replay_admission) =
            fixture.start_with(fixture.receiver(), &replay).await;
        assert_eq!(replay_admission.code, FetchAdmissionCode::RefusedBusy);
        drop(client);
        assert_eq!(
            replay_server
                .await
                .expect("replay task")
                .expect("typed replay"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::Busy)
        );
        assert!(
            fixture
                .clipboard
                .files
                .lock()
                .expect("file calls")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn uncertain_text_clipboard_survives_recovery_and_refuses_replay() {
        let fixture = ReceiverFixture::new();
        let text = "uncertain text body";
        let activation = fixture.text_activation(text);
        *fixture.clipboard.fail_text.lock().expect("uncertain text") =
            Some(ClipboardError::uncertain("text clipboard raced"));
        let (mut client, server, admission) = fixture.start_text(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let receipt = send_text_and_complete(&mut client, &activation).await;
        assert_eq!(receipt.code, FetchReceiptCode::UncertainNoReplay);
        assert_eq!(
            server.await.expect("text task").expect("typed result"),
            ActivationOutcome::UncertainNoReplay
        );
        assert_eq!(*fixture.clipboard.text_calls.lock().expect("text calls"), 1);
        assert!(
            fixture
                .store
                .get_activation_journal(activation.activation.request_id)
                .expect("journal")
                .is_some()
        );
        let service = crate::ActivationService::new(
            DeviceId::new(),
            fixture.store.clone(),
            fixture.clipboard.clone(),
            fixture.state_root.clone(),
        );
        service.recover().expect("startup recovery");
        assert!(
            fixture
                .store
                .get_activation_journal(activation.activation.request_id)
                .expect("journal after recovery")
                .is_some()
        );
        let replay = fixture.text_activation("replay text");
        let (client, replay_server, replay_admission) = fixture.start_text(&replay).await;
        assert_eq!(replay_admission.code, FetchAdmissionCode::RefusedBusy);
        drop(client);
        assert_eq!(
            replay_server
                .await
                .expect("replay task")
                .expect("typed replay"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::Busy)
        );
        assert_eq!(*fixture.clipboard.text_calls.lock().expect("text calls"), 1);
        assert!(fixture.clipboard.texts.lock().expect("texts").is_empty());
    }

    #[tokio::test]
    async fn text_write_then_failed_verification_is_uncertain_and_not_replayed() {
        let fixture = ReceiverFixture::new();
        let text = "offered text that reached the clipboard";
        let activation = fixture.text_activation(text);
        *fixture
            .clipboard
            .fail_text_after_recording
            .lock()
            .expect("verify after write") = Some(ClipboardError::uncertain(
            "clipboard text verification failed: wrote 39 UTF-8 bytes but read back 4",
        ));
        let (mut client, server, admission) = fixture.start_text(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let receipt = send_text_and_complete(&mut client, &activation).await;
        assert_eq!(receipt.code, FetchReceiptCode::UncertainNoReplay);
        assert_eq!(
            server.await.expect("text task").expect("typed result"),
            ActivationOutcome::UncertainNoReplay
        );
        assert_eq!(
            fixture
                .clipboard
                .texts
                .lock()
                .expect("recorded text")
                .as_slice(),
            [text]
        );
        assert_eq!(*fixture.clipboard.text_calls.lock().expect("text calls"), 1);
        assert!(
            fixture
                .store
                .get_activation_journal(activation.activation.request_id)
                .expect("journal")
                .is_some()
        );
        let service = crate::ActivationService::new(
            DeviceId::new(),
            fixture.store.clone(),
            fixture.clipboard.clone(),
            fixture.state_root.clone(),
        );
        service.recover().expect("startup recovery");
        *fixture
            .clipboard
            .fail_text_after_recording
            .lock()
            .expect("clear verify") = None;
        let replay = fixture.text_activation("a later activation must not reapply");
        let (client, replay_server, replay_admission) = fixture.start_text(&replay).await;
        assert_eq!(replay_admission.code, FetchAdmissionCode::RefusedBusy);
        drop(client);
        assert_eq!(
            replay_server
                .await
                .expect("replay task")
                .expect("typed replay"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::Busy)
        );
        assert_eq!(
            fixture
                .clipboard
                .texts
                .lock()
                .expect("recorded text after replay")
                .as_slice(),
            [text],
            "a later activation must not write the clipboard again"
        );
        assert_eq!(*fixture.clipboard.text_calls.lock().expect("text calls"), 1);
    }

    #[tokio::test]
    async fn text_native_write_failure_is_uncertain_and_not_replayed() {
        let fixture = ReceiverFixture::new();
        *fixture
            .clipboard
            .fail_text_native
            .lock()
            .expect("native text failure") = true;
        let activation = fixture.text_activation("offered text");
        let (mut client, server, admission) = fixture.start_text(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let receipt = send_text_and_complete(&mut client, &activation).await;
        assert_eq!(receipt.code, FetchReceiptCode::UncertainNoReplay);
        assert_eq!(
            server.await.expect("text task").expect("typed result"),
            ActivationOutcome::UncertainNoReplay
        );
        assert!(
            fixture.clipboard.texts.lock().expect("texts").is_empty(),
            "writeObjects/SetClipboardData failed after the library cleared"
        );
        assert_eq!(*fixture.clipboard.text_calls.lock().expect("text calls"), 1);
        assert!(
            fixture
                .store
                .get_activation_journal(activation.activation.request_id)
                .expect("journal")
                .is_some()
        );
        let service = crate::ActivationService::new(
            DeviceId::new(),
            fixture.store.clone(),
            fixture.clipboard.clone(),
            fixture.state_root.clone(),
        );
        service.recover().expect("startup recovery");
        *fixture
            .clipboard
            .fail_text_native
            .lock()
            .expect("clear native failure") = false;
        let replay = fixture.text_activation("a later activation must not reapply");
        let (client, replay_server, replay_admission) = fixture.start_text(&replay).await;
        assert_eq!(replay_admission.code, FetchAdmissionCode::RefusedBusy);
        drop(client);
        assert_eq!(
            replay_server
                .await
                .expect("replay task")
                .expect("typed replay"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::Busy)
        );
        assert_eq!(*fixture.clipboard.text_calls.lock().expect("text calls"), 1);
        assert!(fixture.clipboard.texts.lock().expect("texts").is_empty());
    }

    #[tokio::test]
    async fn file_clear_then_failed_list_is_uncertain_and_not_replayed() {
        let fixture = ReceiverFixture::new();
        *fixture
            .clipboard
            .fail_file_list_after_clear
            .lock()
            .expect("fail after clear") = true;
        let activation = fixture.file_activation(ActivationMode::Clipboard, None);
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let bytes = b"abc";
        let digest = Sha256::digest(bytes).to_vec();
        let receipt = send_file_and_complete(&mut client, &activation, bytes, digest).await;
        assert_eq!(receipt.code, FetchReceiptCode::UncertainNoReplay);
        assert_eq!(
            server.await.expect("file task").expect("typed result"),
            ActivationOutcome::UncertainNoReplay
        );
        assert!(
            *fixture.clipboard.cleared.lock().expect("cleared"),
            "clear() already mutated the clipboard before file_list failed"
        );
        assert!(
            fixture.clipboard.files.lock().expect("files").is_empty(),
            "file_list failed, so no file list was recorded"
        );
        assert_eq!(*fixture.clipboard.file_calls.lock().expect("file calls"), 1);
        assert!(
            fixture
                .store
                .get_activation_journal(activation.activation.request_id)
                .expect("journal")
                .is_some()
        );
        assert!(
            fixture
                .store
                .get_clipboard_cache(ClipboardCacheState::InFlight)
                .expect("inflight")
                .is_some()
        );
        let service = crate::ActivationService::new(
            DeviceId::new(),
            fixture.store.clone(),
            fixture.clipboard.clone(),
            fixture.state_root.clone(),
        );
        service.recover().expect("startup recovery");
        *fixture
            .clipboard
            .fail_file_list_after_clear
            .lock()
            .expect("clear fail-after-clear") = false;
        let replay = fixture.file_activation(ActivationMode::Clipboard, None);
        let (client, replay_server, replay_admission) =
            fixture.start_with(fixture.receiver(), &replay).await;
        assert_eq!(replay_admission.code, FetchAdmissionCode::RefusedBusy);
        drop(client);
        assert_eq!(
            replay_server
                .await
                .expect("replay task")
                .expect("typed replay"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::Busy)
        );
        assert_eq!(
            *fixture.clipboard.file_calls.lock().expect("file calls"),
            1,
            "a later activation must not place files on the clipboard again"
        );
        assert!(
            fixture
                .clipboard
                .files
                .lock()
                .expect("files after replay")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn malformed_frame_after_admission_is_protocol_not_connection_lost() {
        let fixture = ReceiverFixture::new();
        let activation =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        let payload = b"this is not a v2 control frame";
        let mut frame = u32::try_from(payload.len())
            .expect("frame length")
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(payload);
        client
            .write_all(&frame)
            .await
            .expect("write malformed frame");
        let outcome = server.await.expect("receiver task").expect("typed result");
        assert_eq!(
            outcome,
            ActivationOutcome::Failed(crate::ActivationFailCode::Protocol)
        );
        let status = outcome.desktop_status().to_ascii_lowercase();
        assert!(status.contains("protocol"), "{status}");
        assert!(!status.contains("connection lost"), "{status}");
        assert_no_payload_artifacts(&fixture.state_root);
    }

    #[tokio::test]
    async fn local_publish_failure_is_local_io_not_connection_lost() {
        let fixture = ReceiverFixture::new();
        let activation =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let (mut client, server, admission) = fixture.start(&activation).await;
        assert_eq!(admission.code, FetchAdmissionCode::Accepted);
        fs::remove_dir_all(&fixture.destination).expect("remove destination directory");
        fs::write(&fixture.destination, b"not a directory").expect("block publication");
        let bytes = b"abc";
        let digest = Sha256::digest(bytes).to_vec();
        write_v2_frame_async(
            &mut client,
            &V2Message::FileStart(FileStart {
                request_id: activation.activation.request_id,
                entry_index: 0,
                byte_len: 3,
            }),
        )
        .await
        .expect("write file start");
        client.write_all(bytes).await.expect("write file bytes");
        write_v2_frame_async(
            &mut client,
            &V2Message::FileEnd(FileEnd {
                request_id: activation.activation.request_id,
                entry_index: 0,
                sha256: digest.clone(),
            }),
        )
        .await
        .expect("write file end");
        let mut content_set = Sha256::new();
        content_set.update(&activation.manifest_sha256);
        content_set.update(&digest);
        write_v2_frame_async(
            &mut client,
            &V2Message::FetchComplete(FetchComplete {
                request_id: activation.activation.request_id,
                files_sent: 1,
                bytes_sent: 3,
                content_set_sha256: content_set.finalize().to_vec(),
            }),
        )
        .await
        .expect("write fetch complete");
        let outcome = server.await.expect("receiver task").expect("typed result");
        assert_eq!(
            outcome,
            ActivationOutcome::Failed(crate::ActivationFailCode::LocalIo)
        );
        let status = outcome.desktop_status().to_ascii_lowercase();
        assert!(status.contains("local storage"), "{status}");
        assert!(!status.contains("connection lost"), "{status}");
    }

    #[tokio::test]
    async fn second_store_handle_inherits_cleanup_block() {
        let fixture = ReceiverFixture::new();
        let store_path = fixture.store.path().to_path_buf();
        crate::activation::shared_owner(&store_path)
            .cleanup_blocked
            .store(true, Ordering::Release);
        let second_store = Arc::new(RedbV2Store::open(&store_path).expect("open second store"));
        assert_ne!(
            Arc::as_ptr(&fixture.store),
            Arc::as_ptr(&second_store),
            "the two handles must be distinct allocations"
        );
        let activation =
            fixture.file_activation(ActivationMode::Save, Some(fixture.destination.clone()));
        let receiver = FetchReceiver::with_ledger(
            DeviceId::new(),
            second_store,
            fixture.clipboard.clone(),
            fixture.state_root.clone(),
            ReservationLedger::default(),
        );
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let source_device = activation.activation.source_device;
        let receiver_activation = activation.activation.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            receiver
                .receive(
                    source_device,
                    receiver_activation,
                    &mut stream,
                    TEST_IO_TIMEOUT,
                )
                .await
        });
        let _client = TcpStream::connect(address).await.expect("connect");
        assert_eq!(
            server.await.expect("receiver task").expect("typed result"),
            ActivationOutcome::Refused(crate::ActivationRefuseCode::Busy),
            "a second store handle must inherit the first handle's cleanup block"
        );
        crate::activation::shared_owner(&store_path)
            .cleanup_blocked
            .store(false, Ordering::Release);
    }
}
