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
    FetchAdmission, FetchAdmissionCode, FetchComplete, FetchHeader, FetchReceipt, FetchReceiptCode,
    FileEntryKind, ManifestEnd, ManifestEntry, V2_MAX_FILE_BYTES, V2_MAX_MANIFEST_BYTES,
    V2_MAX_RELATIVE_PATH_BYTES, V2_MAX_TRANSFER_BYTES, V2Message, validate_v2_message,
    write_v2_frame_async,
};
use meshelf_store::RedbV2Store;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::{NetError, io_timeout};

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
        meshelf_platform::ClipboardWorker::set_files(self, paths)
            .map_err(|error| ClipboardError::new(error.to_string()))
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
    ) -> Result<(), NetError>;
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
    cleanup_blocked: AtomicBool,
    uncertain_clipboard: AtomicBool,
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
        Self {
            local_device,
            store,
            clipboard,
            state_root,
            ledger: ReservationLedger::global(),
            cleanup_blocked: AtomicBool::new(false),
            uncertain_clipboard: AtomicBool::new(false),
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
        Self {
            local_device,
            store,
            clipboard,
            state_root,
            ledger,
            cleanup_blocked: AtomicBool::new(false),
            uncertain_clipboard: AtomicBool::new(false),
            #[cfg(test)]
            preallocate_override: None,
        }
    }

    #[cfg(test)]
    fn with_preallocator_for_test(
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

    /// Remove journal-owned partial staging before this process accepts another activation.
    pub fn startup_cleanup(&self) -> Result<(), NetError> {
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
            .get_clipboard_cache(ClipboardCacheState::InFlight)
            .map_err(|error| NetError::FetchServiceOwned(error.to_string()))?
            .is_some()
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
    ) -> Result<(), NetError> {
        self.receive_one(
            authenticated_source,
            activation,
            stream,
            io_timeout_duration,
        )
        .await
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
    ) -> Result<(), NetError> {
        if self.cleanup_blocked.load(Ordering::Acquire) {
            return Err(NetError::Rejected(
                "receiver cleanup is unresolved; listener admission is blocked".to_owned(),
            ));
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

        let header = self.read_header(stream, io_timeout_duration).await?;
        let mut plan = match validate_header(&header, &card, &activation) {
            Ok(plan) => plan,
            Err(code) => {
                self.write_admission(
                    stream,
                    activation.request_id,
                    code,
                    0,
                    0,
                    None,
                    io_timeout_duration,
                )
                .await?;
                return Ok(());
            }
        };

        if let Err(code) = self
            .read_manifest(stream, &header, &mut plan, io_timeout_duration)
            .await
        {
            self.write_admission(
                stream,
                activation.request_id,
                code,
                0,
                0,
                None,
                io_timeout_duration,
            )
            .await?;
            return Ok(());
        }
        if let Err(code) = validate_manifest(&header, &card.descriptor, &plan) {
            self.write_admission(
                stream,
                activation.request_id,
                code,
                0,
                0,
                None,
                io_timeout_duration,
            )
            .await?;
            return Ok(());
        }

        let destination = self.destination_for(&activation, &header.descriptor)?;
        if activation.mode == ActivationMode::Clipboard
            && !header.descriptor.is_text()
            && self.uncertain_clipboard.load(Ordering::Acquire)
        {
            self.write_admission(
                stream,
                activation.request_id,
                FetchAdmissionCode::RefusedBusy,
                0,
                0,
                Some("clipboard file activation is uncertain after recovery".to_owned()),
                io_timeout_duration,
            )
            .await?;
            return Ok(());
        }
        if let Some(destination) = &destination {
            if let Err(error) = ensure_directory_tree(destination) {
                self.write_admission(
                    stream,
                    activation.request_id,
                    FetchAdmissionCode::DestinationUnavailable,
                    0,
                    0,
                    Some(safe_detail(&error.to_string())),
                    io_timeout_duration,
                )
                .await?;
                return Ok(());
            }
            require_directory(destination)?;
        }

        let payload_bytes = plan.total_bytes;
        let permit = if payload_bytes == 0 {
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
                    self.write_admission(
                        stream,
                        activation.request_id,
                        FetchAdmissionCode::InsufficientSpace,
                        0,
                        0,
                        None,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
                Err(error) => {
                    self.write_admission(
                        stream,
                        activation.request_id,
                        FetchAdmissionCode::DestinationUnavailable,
                        0,
                        0,
                        Some(safe_detail(&error.to_string())),
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
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
        if let Err(error) = self.prepare_staging(&staging_root, &mut plan).await {
            let cleanup_result = self
                .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                .await;
            if let Err(cleanup_error) = cleanup_result {
                self.cleanup_blocked.store(true, Ordering::Release);
                drop(permit);
                return Err(NetError::FetchServiceOwned(format!(
                    "allocation failed: {error}; {cleanup_error}"
                )));
            }
            drop(permit);
            self.write_admission(
                stream,
                activation.request_id,
                FetchAdmissionCode::AllocationFailed,
                0,
                0,
                Some(safe_detail(&error.to_string())),
                io_timeout_duration,
            )
            .await?;
            return Ok(());
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

        let receive = self
            .receive_payload(
                stream,
                &activation,
                &mut plan,
                &staging_root,
                io_timeout_duration,
            )
            .await;
        match receive {
            Ok(()) => {
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
                            return Err(NetError::FetchServiceOwned(format!(
                                "publication failed: {error}; {cleanup_error}"
                            )));
                        }
                        self.send_receipt(
                            stream,
                            FetchReceiptCode::InternalError,
                            plan.file_count,
                            plan.total_bytes,
                            Some(safe_detail(&error.to_string())),
                            &activation,
                            io_timeout_duration,
                        )
                        .await?;
                        return Ok(());
                    }
                };
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
                            return Err(NetError::FetchServiceOwned(format!(
                                "side effect failed: {error}; {cleanup_error}"
                            )));
                        }
                        self.send_receipt(
                            stream,
                            FetchReceiptCode::ClipboardFailed,
                            plan.file_count,
                            plan.total_bytes,
                            Some(safe_detail(&error.to_string())),
                            &activation,
                            io_timeout_duration,
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(SideEffectFailure::Uncertain(error)) => {
                        self.cleanup_blocked.store(true, Ordering::Release);
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
                    drop(permit);
                    return Err(cleanup_error);
                }
                drop(permit);
                let _ = self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::Failed,
                    files,
                    bytes,
                    Some(format!(
                        "connection lost after {files} files and {bytes} bytes"
                    )),
                );
                Ok(())
            }
            Err(ReceiveFailure::Cancelled { files, bytes }) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    return Err(cleanup_error);
                }
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::Cancelled,
                    files,
                    bytes,
                    None,
                )?;
                self.send_receipt(
                    stream,
                    FetchReceiptCode::Cancelled,
                    files,
                    bytes,
                    None,
                    &activation,
                    io_timeout_duration,
                )
                .await
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
                    return Err(cleanup_error);
                }
                self.record_attempt_with_counts(
                    &activation,
                    OfferAttemptCode::VerificationFailed,
                    files,
                    bytes,
                    Some(detail.clone()),
                )?;
                self.send_receipt(
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
            Err(ReceiveFailure::Io(error)) => {
                let cleanup_result = self
                    .cleanup_activation_state(&mut plan, &staging_root, activation.request_id)
                    .await;
                drop(permit);
                if let Err(cleanup_error) = cleanup_result {
                    self.cleanup_blocked.store(true, Ordering::Release);
                    return Err(cleanup_error);
                }
                Err(error)
            }
        }
    }

    async fn read_header(
        &self,
        stream: &mut TcpStream,
        io_timeout_duration: Duration,
    ) -> Result<FetchHeader, NetError> {
        let message = io_timeout(
            io_timeout_duration,
            meshelf_protocol::read_v2_frame_async(stream),
            "read fetch header",
        )
        .await?;
        validate_v2_message(&message)?;
        let V2Message::FetchHeader(header) = message else {
            return Err(NetError::UnexpectedMessage("expected fetch header"));
        };
        Ok(header)
    }

    async fn read_manifest(
        &self,
        stream: &mut TcpStream,
        header: &FetchHeader,
        plan: &mut ReceivePlan,
        io_timeout_duration: Duration,
    ) -> Result<(), FetchAdmissionCode> {
        if header.manifest_entries == 0 {
            return Ok(());
        }
        let mut expected_index = 0_u32;
        while expected_index < header.manifest_entries {
            let message = timeout(
                io_timeout_duration,
                meshelf_protocol::read_v2_frame_async(stream),
            )
            .await
            .map_err(|_| FetchAdmissionCode::InvalidManifest)?
            .map_err(|_| FetchAdmissionCode::InvalidManifest)?;
            validate_v2_message(&message).map_err(|_| FetchAdmissionCode::InvalidManifest)?;
            let V2Message::ManifestChunk(chunk) = message else {
                return Err(FetchAdmissionCode::InvalidManifest);
            };
            if chunk.request_id != header.request_id
                || chunk.first_index != expected_index
                || chunk.entries.is_empty()
            {
                return Err(FetchAdmissionCode::InvalidManifest);
            }
            expected_index = expected_index
                .checked_add(
                    u32::try_from(chunk.entries.len())
                        .map_err(|_| FetchAdmissionCode::InvalidManifest)?,
                )
                .ok_or(FetchAdmissionCode::InvalidManifest)?;
            if expected_index > header.manifest_entries {
                return Err(FetchAdmissionCode::InvalidManifest);
            }
            plan.manifest_encoded_bytes = plan
                .manifest_encoded_bytes
                .checked_add(
                    serde_json::to_vec(&V2Message::ManifestChunk(chunk.clone()))
                        .map_err(|_| FetchAdmissionCode::InvalidManifest)?
                        .len(),
                )
                .ok_or(FetchAdmissionCode::InvalidManifest)?;
            plan.entries.extend(chunk.entries);
        }
        let message = timeout(
            io_timeout_duration,
            meshelf_protocol::read_v2_frame_async(stream),
        )
        .await
        .map_err(|_| FetchAdmissionCode::InvalidManifest)?
        .map_err(|_| FetchAdmissionCode::InvalidManifest)?;
        validate_v2_message(&message).map_err(|_| FetchAdmissionCode::InvalidManifest)?;
        let V2Message::ManifestEnd(end) = message else {
            return Err(FetchAdmissionCode::InvalidManifest);
        };
        if end.request_id != header.request_id {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
        plan.manifest_end = Some(end);
        if plan.manifest_encoded_bytes > V2_MAX_MANIFEST_BYTES
            || plan.manifest_encoded_bytes
                != usize::try_from(header.manifest_encoded_bytes).unwrap_or(usize::MAX)
        {
            return Err(FetchAdmissionCode::InvalidManifest);
        }
        Ok(())
    }

    fn destination_for(
        &self,
        activation: &FetchActivation,
        descriptor: &OfferDescriptor,
    ) -> Result<Option<PathBuf>, NetError> {
        if descriptor.is_text() {
            return Ok(None);
        }
        let path = match activation.mode {
            ActivationMode::Save => activation.destination.clone().ok_or_else(|| {
                NetError::Rejected("save activation has no configured destination".to_owned())
            })?,
            ActivationMode::Clipboard => self.state_root.join("clipboard-cache"),
        };
        if !path.is_absolute() {
            return Err(NetError::Rejected(
                "activation destination must be absolute".to_owned(),
            ));
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
                let path = payload_root.join(meshelf_core::relative_path(&entry.relative_path));
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
                payload_root.join(meshelf_core::relative_path(&entry.relative_path))
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
    ) -> Result<(), ReceiveFailure> {
        if plan.content_kind == ContentKind::Text {
            let expected = plan.total_bytes as usize;
            let mut bytes = vec![0_u8; expected];
            read_exact_timeout(stream, &mut bytes, io_timeout_duration).await?;
            let digest = Sha256::digest(&bytes).to_vec();
            let message = read_v2_timeout(stream, io_timeout_duration).await?;
            let V2Message::TextEnd(end) = message else {
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
            let complete = read_complete(stream, io_timeout_duration).await?;
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
            let message = read_v2_timeout(stream, io_timeout_duration).await?;
            if let V2Message::FetchAbort(abort) = &message
                && abort.request_id == activation.request_id
            {
                return Err(ReceiveFailure::Cancelled {
                    files: abort.files_sent,
                    bytes: abort.bytes_sent,
                });
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
                let wanted =
                    usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                let read = timeout(io_timeout_duration, stream.read(&mut buffer[..wanted]))
                    .await
                    .map_err(|_| ReceiveFailure::Io(NetError::Timeout("read file payload")))??;
                if read == 0 {
                    return Err(ReceiveFailure::Disconnected {
                        files: files_received,
                        bytes: bytes_received,
                    });
                }
                hasher.update(&buffer[..read]);
                file.write_all(&buffer[..read])
                    .await
                    .map_err(|error| ReceiveFailure::Io(NetError::Io(error)))?;
                remaining -= read as u64;
                bytes_received = bytes_received.saturating_add(read as u64);
            }
            file.sync_all()
                .await
                .map_err(|error| ReceiveFailure::Io(NetError::Io(error)))?;
            let digest = hasher.finalize().to_vec();
            let message = read_v2_timeout(stream, io_timeout_duration).await?;
            if let V2Message::FetchAbort(abort) = &message
                && abort.request_id == activation.request_id
            {
                return Err(ReceiveFailure::Cancelled {
                    files: files_received,
                    bytes: bytes_received,
                });
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
        let complete = read_complete(stream, io_timeout_duration).await?;
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
        sync_directory(staging_root)
            .map_err(NetError::Io)
            .map_err(ReceiveFailure::Io)
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
            (OfferDescriptor::Text { .. }, ActivationMode::Clipboard, None) => text
                .ok_or_else(|| {
                    SideEffectFailure::Terminal(NetError::FetchServiceOwned(
                        "text payload was not retained".to_owned(),
                    ))
                })
                .and_then(|text| {
                    self.clipboard.set_text(text).map_err(|error| {
                        SideEffectFailure::Terminal(NetError::FetchServiceOwned(
                            error.message().to_owned(),
                        ))
                    })
                }),
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
        let _ = self
            .store
            .update_activation_state(activation.request_id, ActivationState::UncertainNoReplay);
        let _ = self.record_attempt(
            activation,
            OfferAttemptCode::UncertainNoReplay,
            plan,
            Some(detail.clone()),
        );
        self.send_receipt(
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
    ) -> Result<(), NetError> {
        self.receive_one(
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
    Cancelled {
        files: u32,
        bytes: u64,
    },
    Verification {
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

async fn read_v2_timeout(
    stream: &mut TcpStream,
    duration: Duration,
) -> Result<V2Message, ReceiveFailure> {
    let message = timeout(duration, meshelf_protocol::read_v2_frame_async(stream))
        .await
        .map_err(|_| ReceiveFailure::Io(NetError::Timeout("read fetch control")))?
        .map_err(NetError::Protocol)
        .map_err(ReceiveFailure::Io)?;
    validate_v2_message(&message)
        .map_err(NetError::Protocol)
        .map_err(ReceiveFailure::Io)?;
    Ok(message)
}

async fn read_complete(
    stream: &mut TcpStream,
    duration: Duration,
) -> Result<FetchComplete, ReceiveFailure> {
    let message = read_v2_timeout(stream, duration).await?;
    match message {
        V2Message::FetchComplete(complete) => Ok(complete),
        V2Message::FetchAbort(abort) => Err(ReceiveFailure::Cancelled {
            files: abort.files_sent,
            bytes: abort.bytes_sent,
        }),
        _ => Err(ReceiveFailure::Verification {
            files: 0,
            bytes: 0,
            detail: "expected fetch_complete".to_owned(),
        }),
    }
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
        FetchReceiptCode, FileEnd, FileEntryKind, FileStart, ManifestChunk, ManifestEnd, V2Message,
        read_v2_frame_async, write_v2_frame_async,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::*;

    const TEST_IO_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Debug, Default)]
    struct TestClipboard {
        files: Mutex<Vec<PathBuf>>,
        text_calls: Mutex<u32>,
        fail_files: Mutex<bool>,
        observe_existing: Mutex<Option<PathBuf>>,
        existed_at_call: Mutex<Option<bool>>,
        durable_marker: Mutex<Option<PathBuf>>,
    }

    impl ClipboardSink for TestClipboard {
        fn set_text(&self, _text: &str) -> Result<(), ClipboardError> {
            *self.text_calls.lock().expect("clipboard text lock") += 1;
            Ok(())
        }
    }

    impl FetchClipboard for TestClipboard {
        fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
            if let Some(path) = self
                .observe_existing
                .lock()
                .expect("clipboard observe lock")
                .as_ref()
            {
                *self.existed_at_call.lock().expect("clipboard result lock") = Some(path.exists());
            }
            if *self.fail_files.lock().expect("clipboard failure lock") {
                return Err(ClipboardError::new("test clipboard failure"));
            }
            if let Some(marker) = self
                .durable_marker
                .lock()
                .expect("clipboard marker lock")
                .as_ref()
            {
                fs::write(marker, b"clipboard side effect durable")
                    .expect("write side effect marker");
            }
            self.files
                .lock()
                .expect("clipboard files lock")
                .extend(paths.iter().cloned());
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
            tokio::task::JoinHandle<Result<(), NetError>>,
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
            tokio::task::JoinHandle<Result<(), NetError>>,
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
        server
            .await
            .expect("receiver task")
            .expect("allocation refusal");
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
        server
            .await
            .expect("receiver task")
            .expect("verification result");
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
        server
            .await
            .expect("receiver task")
            .expect("disconnect result");
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
        server.await.expect("receiver task").expect("cancel result");
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
        second_server
            .await
            .expect("second receiver task")
            .expect("second clipboard failure");
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
        server.await.expect("receiver task").expect("busy refusal");
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
}
