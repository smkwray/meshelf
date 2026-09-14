//! Origin-side v2 fetch service.
//!
//! This module deliberately contains no receiver admission, staging, or publication logic. It
//! authenticates a request through the surrounding connection handler, rebuilds a live-source
//! plan, waits for the receiver's admission frame, and streams one authorized payload.

use std::{
    fs::{self, Metadata},
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};

use meshelf_core::{
    ActivationId, CaptureSourcePhase, CaptureSourceRecord, CapturedPhoto, DeviceId,
    DocumentLeaseId, MAX_OFFER_FILE_BYTES, MAX_OFFER_MANIFEST_ENTRIES, MAX_OFFER_TRANSFER_BYTES,
    OfferDescriptor, OfferId, OfferSource, OfferSourceRecord, OfferSourceStore, StoreError,
};
use meshelf_protocol::{
    FetchAbort, FetchAbortCode, FetchAdmission, FetchAdmissionCode, FetchComplete, FetchHeader,
    FetchReceipt, FetchRefusal, FetchRefusalCode, FetchRequest, FileEnd, FileEntryKind, FileStart,
    ManifestChunk, ManifestEnd, ManifestEntry, TextEnd, V2_MAX_ACTIVE_PAYLOAD_STREAMS,
    V2_MAX_MANIFEST_BYTES, V2_MAX_MANIFEST_ENTRIES, V2_MAX_RELATIVE_PATH_BYTES,
    V2_STREAM_BUFFER_BYTES, V2Message, chunk_manifest, encoded_manifest_bytes, validate_v2_message,
    write_v2_frame_async,
};
use meshelf_store::CaptureSourceClaim;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError},
    time::timeout,
};

use super::{NetError, io_timeout};

#[async_trait::async_trait]
pub trait V2FetchSender: Send + Sync + 'static {
    async fn handle_fetch(
        &self,
        authenticated_requester: DeviceId,
        request: FetchRequest,
        stream: &mut TcpStream,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError>;
}

/// A source a fetch may be served from. Byte transfer, revalidation, manifest and hash
/// generation, bounded streaming, and receipt validation are the same for both; they differ in
/// who is eligible and in what the origin records once the fetch ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchableSource {
    /// A shelf offer: eligible for every device it was announced to, and servable repeatedly.
    Shelf(OfferSourceRecord),
    /// A captured photo: eligible only for the device that requested it, only while announced,
    /// and served at most once.
    Capture(Box<CaptureSourceRecord>),
}

/// Where an origin finds the source behind a fetched offer id, and where it records the end of
/// serving a captured photo. Capture methods are called only for sources this resolver returned
/// as [`FetchableSource::Capture`]; a shelf-only resolver keeps the refusing defaults.
pub trait FetchSourceResolver: Send + Sync + 'static {
    fn resolve(&self, offer_id: OfferId) -> Result<Option<FetchableSource>, StoreError>;

    /// `Announced -> Claimed` in one transaction, before the first byte of the fetch header.
    fn claim_capture(
        &self,
        _offer_id: OfferId,
        _requester: DeviceId,
        _activation_id: ActivationId,
    ) -> Result<CaptureSourceClaim, StoreError> {
        Err(no_capture_sources())
    }

    /// Records a validated completed receipt and only then announces the delivery, which is what
    /// allows the photo to be deleted. Returns false when the store refused the receipt.
    fn capture_delivered(
        &self,
        _claimed: &CaptureSourceRecord,
        _activation_id: ActivationId,
        _files_received: u32,
        _bytes_received: u64,
    ) -> Result<bool, StoreError> {
        Err(no_capture_sources())
    }

    /// The fetch provably delivered nothing: it ended before `FetchComplete`, or the receipt
    /// affirms the requester published nothing. The photo is withdrawn as `failed`.
    fn capture_failed(&self, _claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        Err(no_capture_sources())
    }

    /// `FetchComplete` was sent but no receipt proves or disproves delivery (none arrived, it
    /// reported `UncertainNoReplay`, or its counts were wrong): the requester may hold the photo.
    /// It is kept until its deadline, never served again, and never reported delivered.
    fn capture_uncertain(&self, _claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        Err(no_capture_sources())
    }
}

fn no_capture_sources() -> StoreError {
    StoreError::new("this origin serves no capture photos")
}

/// Opens a platform document lease as a readable stream (typically a detached FD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentOpenError {
    Unavailable,
    Changed,
    Unsupported,
}

pub trait DocumentSourceProvider: Send + Sync + 'static {
    fn open(
        &self,
        lease_id: DocumentLeaseId,
        expected_bytes: u64,
    ) -> Result<tokio::fs::File, DocumentOpenError>;

    /// Best-effort platform release when the durable lease refcount reaches zero.
    fn release(&self, _lease_id: DocumentLeaseId) {}
}

/// Non-Android default: documents cannot be served.
#[derive(Debug, Default)]
pub struct UnsupportedDocumentSources;

impl DocumentSourceProvider for UnsupportedDocumentSources {
    fn open(
        &self,
        _lease_id: DocumentLeaseId,
        _expected_bytes: u64,
    ) -> Result<tokio::fs::File, DocumentOpenError> {
        Err(DocumentOpenError::Unsupported)
    }
}

/// The shelf's offer sources; announced-to eligibility, no capture photos.
pub struct ShelfSourceResolver {
    store: Arc<dyn OfferSourceStore>,
}

impl ShelfSourceResolver {
    #[must_use]
    pub fn new(store: Arc<dyn OfferSourceStore>) -> Self {
        Self { store }
    }
}

impl FetchSourceResolver for ShelfSourceResolver {
    fn resolve(&self, offer_id: OfferId) -> Result<Option<FetchableSource>, StoreError> {
        Ok(self
            .store
            .get_offer_source(offer_id)?
            .map(FetchableSource::Shelf))
    }
}

/// Capture photos first, then ordinary shelf sources. Capture claim/delivery methods always
/// delegate to the capture half so a shelf miss never swallows a capture transition.
pub struct ComposedFetchSourceResolver {
    capture: Arc<dyn FetchSourceResolver>,
    shelf: Arc<dyn FetchSourceResolver>,
}

impl ComposedFetchSourceResolver {
    #[must_use]
    pub fn new(capture: Arc<dyn FetchSourceResolver>, shelf: Arc<dyn FetchSourceResolver>) -> Self {
        Self { capture, shelf }
    }
}

impl FetchSourceResolver for ComposedFetchSourceResolver {
    fn resolve(&self, offer_id: OfferId) -> Result<Option<FetchableSource>, StoreError> {
        if let Some(source) = self.capture.resolve(offer_id)? {
            return Ok(Some(source));
        }
        self.shelf.resolve(offer_id)
    }

    fn claim_capture(
        &self,
        offer_id: OfferId,
        requester: DeviceId,
        activation_id: ActivationId,
    ) -> Result<CaptureSourceClaim, StoreError> {
        self.capture
            .claim_capture(offer_id, requester, activation_id)
    }

    fn capture_delivered(
        &self,
        claimed: &CaptureSourceRecord,
        activation_id: ActivationId,
        files_received: u32,
        bytes_received: u64,
    ) -> Result<bool, StoreError> {
        self.capture
            .capture_delivered(claimed, activation_id, files_received, bytes_received)
    }

    fn capture_failed(&self, claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        self.capture.capture_failed(claimed)
    }

    fn capture_uncertain(&self, claimed: &CaptureSourceRecord) -> Result<(), StoreError> {
        self.capture.capture_uncertain(claimed)
    }
}

pub struct OfferFetchHandler {
    origin_device: DeviceId,
    resolver: Arc<dyn FetchSourceResolver>,
    documents: Arc<dyn DocumentSourceProvider>,
    active_streams: Arc<Semaphore>,
}

impl OfferFetchHandler {
    /// An origin that serves its shelf offer sources.
    #[must_use]
    pub fn new(origin_device: DeviceId, store: Arc<dyn OfferSourceStore>) -> Self {
        Self::with_resolver(origin_device, Arc::new(ShelfSourceResolver::new(store)))
    }

    #[must_use]
    pub fn with_resolver(origin_device: DeviceId, resolver: Arc<dyn FetchSourceResolver>) -> Self {
        Self {
            origin_device,
            resolver,
            documents: Arc::new(UnsupportedDocumentSources),
            active_streams: Arc::new(Semaphore::new(
                usize::try_from(V2_MAX_ACTIVE_PAYLOAD_STREAMS).expect("stream limit fits usize"),
            )),
        }
    }

    #[must_use]
    pub fn with_document_provider(mut self, documents: Arc<dyn DocumentSourceProvider>) -> Self {
        self.documents = documents;
        self
    }

    fn active_counts(&self) -> (u32, u32) {
        let available = u32::try_from(self.active_streams.available_permits()).unwrap_or(0);
        (
            V2_MAX_ACTIVE_PAYLOAD_STREAMS.saturating_sub(available),
            V2_MAX_ACTIVE_PAYLOAD_STREAMS,
        )
    }
}

#[async_trait::async_trait]
impl V2FetchSender for OfferFetchHandler {
    async fn handle_fetch(
        &self,
        authenticated_requester: DeviceId,
        request: FetchRequest,
        stream: &mut TcpStream,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        // This ordering is the authorization boundary. In particular, no source path is read
        // until the authenticated requester has passed every persisted eligibility check.
        if request.source_device != self.origin_device {
            return self
                .send_refusal(
                    stream,
                    &request,
                    FetchRefusalCode::Malformed,
                    None,
                    Some("source device does not match this origin"),
                    io_timeout_duration,
                )
                .await;
        }
        if request.requester_device != authenticated_requester {
            return self
                .send_refusal(
                    stream,
                    &request,
                    FetchRefusalCode::Malformed,
                    None,
                    Some("requester device does not match the authenticated peer"),
                    io_timeout_duration,
                )
                .await;
        }
        let Some(source) = self
            .resolver
            .resolve(request.offer_id)
            .map_err(|error| NetError::OfferStorage(error.to_string()))?
        else {
            return self
                .send_refusal(
                    stream,
                    &request,
                    FetchRefusalCode::UnknownOffer,
                    None,
                    None,
                    io_timeout_duration,
                )
                .await;
        };
        let eligible = match source {
            FetchableSource::Shelf(record) => {
                if !record.announced_to.contains(&authenticated_requester) {
                    return self
                        .send_refusal(
                            stream,
                            &request,
                            FetchRefusalCode::NotAnnouncedToRequester,
                            None,
                            None,
                            io_timeout_duration,
                        )
                        .await;
                }
                if record.source.validate_for(&record.descriptor).is_err() {
                    return self
                        .send_refusal(
                            stream,
                            &request,
                            FetchRefusalCode::Malformed,
                            None,
                            Some("stored offer source does not match its descriptor"),
                            io_timeout_duration,
                        )
                        .await;
                }
                Eligible::Shelf(PlanInput {
                    descriptor: record.descriptor,
                    source: record.source,
                    expected_sha256: None,
                })
            }
            // A photo is eligible only for the device that asked for it, and only while it is
            // announced; once a fetch has claimed it, it is never served again.
            FetchableSource::Capture(record) => {
                let refusal = if record.requester != authenticated_requester {
                    Some((FetchRefusalCode::NotAnnouncedToRequester, None))
                } else {
                    match &record.phase {
                        CaptureSourcePhase::Announced { .. } => None,
                        CaptureSourcePhase::Claimed { .. } => Some((
                            FetchRefusalCode::SourceUnavailable,
                            Some("capture photo was already served"),
                        )),
                        _ => Some((FetchRefusalCode::NotAnnouncedToRequester, None)),
                    }
                };
                if let Some((code, detail)) = refusal {
                    return self
                        .send_refusal(stream, &request, code, None, detail, io_timeout_duration)
                        .await;
                }
                Eligible::Capture
            }
        };

        let permit = match self.active_streams.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                let (active_streams, max_active_streams) = self.active_counts();
                return self
                    .send_refusal_with_counts(
                        stream,
                        &request,
                        FetchRefusalCode::Busy,
                        (active_streams, max_active_streams),
                        Some("origin payload capacity is full"),
                        io_timeout_duration,
                    )
                    .await;
            }
            Err(TryAcquireError::Closed) => {
                return Err(NetError::FetchService("payload stream limit is closed"));
            }
        };
        let mut permit = Some(permit);

        match eligible {
            Eligible::Shelf(input) => {
                let end = self
                    .serve_input(
                        stream,
                        &request,
                        Ok(input),
                        &mut permit,
                        io_timeout_duration,
                    )
                    .await?;
                let result = match end {
                    PlanEnd::CompleteSent => {
                        self.await_completed_receipt(
                            stream,
                            request.request_id,
                            Some(request.offer_id),
                            io_timeout_duration,
                        )
                        .await
                    }
                    PlanEnd::Stopped => Ok(()),
                };
                drop(permit);
                result
            }
            Eligible::Capture => {
                // Claimed in one transaction after the stream permit and before the header, so
                // a racing second fetch finds the photo already served.
                let claim = self
                    .resolver
                    .claim_capture(
                        request.offer_id,
                        authenticated_requester,
                        request.request_id,
                    )
                    .map_err(|error| NetError::OfferStorage(error.to_string()))?;
                let (code, detail) = match claim {
                    CaptureSourceClaim::Claimed(claimed) => {
                        let result = self
                            .serve_claimed_capture(
                                stream,
                                &request,
                                &claimed,
                                &mut permit,
                                io_timeout_duration,
                            )
                            .await;
                        drop(permit);
                        return result;
                    }
                    CaptureSourceClaim::AlreadyClaimed => (
                        FetchRefusalCode::SourceUnavailable,
                        Some("capture photo was already served"),
                    ),
                    CaptureSourceClaim::NotAnnounced | CaptureSourceClaim::WrongRequester => {
                        (FetchRefusalCode::NotAnnouncedToRequester, None)
                    }
                    CaptureSourceClaim::Unknown => (FetchRefusalCode::UnknownOffer, None),
                };
                drop(permit);
                self.send_refusal(stream, &request, code, None, detail, io_timeout_duration)
                    .await
            }
        }
    }
}

/// What a fetch may be served from once eligibility has passed.
enum Eligible {
    Shelf(PlanInput),
    /// The photo is read again from the claimed row, which is the authority once claimed.
    Capture,
}

/// Whether the origin finished the stream with `FetchComplete`. That frame is the delivery
/// boundary for a captured photo: the requester publishes only after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanEnd {
    CompleteSent,
    /// A refusal, an abort, or a mid-stream close ended the fetch before `FetchComplete`.
    Stopped,
}

/// The descriptor and source a plan is built from, and rebuilt from for revalidation.
#[derive(Debug)]
struct PlanInput {
    descriptor: OfferDescriptor,
    source: OfferSource,
    /// The digest the streamed file must have; set for a captured photo, whose bytes were
    /// hashed when the person took it.
    expected_sha256: Option<[u8; 32]>,
}

/// The plan input for a captured photo. Its metadata commitment is taken now, from the live
/// file, so every later revalidation compares against the file as it was when serving began.
fn capture_plan_input(photo: &CapturedPhoto) -> Result<PlanInput, SourceFailure> {
    let OfferDescriptor::File { root_name, .. } = &photo.descriptor else {
        return Err(SourceFailure::Malformed);
    };
    let metadata = source_metadata(&photo.path)?;
    let mut commitment = Sha256::new();
    hash_metadata(&mut commitment, "root", root_name, &metadata)?;
    Ok(PlanInput {
        descriptor: photo.descriptor.clone(),
        source: OfferSource::File {
            canonical_path: photo.path.clone(),
            metadata_commitment: commitment.finalize().to_vec(),
        },
        expected_sha256: Some(photo.sha256),
    })
}

/// Whether a receipt after `FetchComplete` affirms that the requester published nothing, so the
/// photo may be deleted at once. The capture receiver sends these failure codes only before it
/// publishes. `UncertainNoReplay` means the photo may already be published, and `Completed` is
/// delivery (or, with the wrong counts, uncertainty); neither disproves delivery. The match is
/// exhaustive so a new receipt code cannot delete a photo without a decision here.
fn receipt_disproves_delivery(code: &meshelf_protocol::FetchReceiptCode) -> bool {
    use meshelf_protocol::FetchReceiptCode as Code;
    match code {
        Code::Completed | Code::UncertainNoReplay => false,
        Code::ConnectionLost
        | Code::Cancelled
        | Code::VerificationFailed
        | Code::ClipboardFailed
        | Code::InternalError => true,
    }
}

fn claimed_photo(record: &CaptureSourceRecord) -> Option<(&CapturedPhoto, u64)> {
    match &record.phase {
        CaptureSourcePhase::Claimed { photo, .. } => match photo.descriptor {
            OfferDescriptor::File { total_bytes, .. } => Some((photo, total_bytes)),
            _ => None,
        },
        _ => None,
    }
}

impl OfferFetchHandler {
    async fn serve_input(
        &self,
        stream: &mut TcpStream,
        request: &FetchRequest,
        input: Result<PlanInput, SourceFailure>,
        permit: &mut Option<OwnedSemaphorePermit>,
        io_timeout_duration: std::time::Duration,
    ) -> Result<PlanEnd, NetError> {
        let built = input.and_then(|input| {
            build_source_plan(&input, request.request_id).map(|plan| (input, plan))
        });
        let (input, plan) = match built {
            Ok(built) => built,
            Err(failure) => {
                let (code, detail) = match failure {
                    SourceFailure::Unavailable => (FetchRefusalCode::SourceUnavailable, None),
                    SourceFailure::Changed => (FetchRefusalCode::SourceChanged, None),
                    SourceFailure::Malformed => (
                        FetchRefusalCode::Malformed,
                        Some("source cannot be represented by the v2 manifest"),
                    ),
                };
                drop(permit.take());
                self.send_refusal(stream, request, code, None, detail, io_timeout_duration)
                    .await?;
                return Ok(PlanEnd::Stopped);
            }
        };
        self.send_plan(stream, request, &input, plan, io_timeout_duration)
            .await
    }

    /// Serves a photo this fetch has claimed and records how serving ended. Deletion is allowed
    /// only by a validated completed receipt, or by a failure before `FetchComplete`, which
    /// provably delivered nothing.
    async fn serve_claimed_capture(
        &self,
        stream: &mut TcpStream,
        request: &FetchRequest,
        claimed: &CaptureSourceRecord,
        permit: &mut Option<OwnedSemaphorePermit>,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        let storage = |error: StoreError| NetError::OfferStorage(error.to_string());
        let Some((photo, photo_bytes)) = claimed_photo(claimed) else {
            self.resolver.capture_failed(claimed).map_err(storage)?;
            return Err(NetError::FetchService(
                "claimed capture row holds no single-file photo",
            ));
        };
        let end = self
            .serve_input(
                stream,
                request,
                capture_plan_input(photo),
                permit,
                io_timeout_duration,
            )
            .await;
        match end {
            Err(error) => {
                self.resolver.capture_failed(claimed).map_err(storage)?;
                Err(error)
            }
            Ok(PlanEnd::Stopped) => {
                self.resolver.capture_failed(claimed).map_err(storage)?;
                Ok(())
            }
            Ok(PlanEnd::CompleteSent) => {
                let receipt = self
                    .await_receipt(
                        stream,
                        request.request_id,
                        Some(request.offer_id),
                        io_timeout_duration,
                    )
                    .await;
                match receipt {
                    Ok(receipt)
                        if receipt.code == meshelf_protocol::FetchReceiptCode::Completed
                            && receipt.files_received == 1
                            && receipt.bytes_received == photo_bytes =>
                    {
                        if self
                            .resolver
                            .capture_delivered(
                                claimed,
                                request.request_id,
                                receipt.files_received,
                                receipt.bytes_received,
                            )
                            .map_err(storage)?
                        {
                            Ok(())
                        } else {
                            self.resolver.capture_uncertain(claimed).map_err(storage)?;
                            Err(NetError::Rejected(
                                "capture delivery receipt was not accepted".to_owned(),
                            ))
                        }
                    }
                    Ok(receipt) if receipt_disproves_delivery(&receipt.code) => {
                        self.resolver.capture_failed(claimed).map_err(storage)?;
                        require_completed_receipt(&receipt)
                    }
                    Ok(receipt) => {
                        // The requester may hold the photo: it reported `UncertainNoReplay`, or
                        // `Completed` for something other than this photo's one file and byte
                        // count. The photo is neither delivered nor deleted early.
                        self.resolver.capture_uncertain(claimed).map_err(storage)?;
                        if receipt.code == meshelf_protocol::FetchReceiptCode::Completed {
                            Err(NetError::IdentityMismatch(format!(
                                "completed capture receipt reports {} files and {} bytes; expected 1 and {photo_bytes}",
                                receipt.files_received, receipt.bytes_received
                            )))
                        } else {
                            require_completed_receipt(&receipt)
                        }
                    }
                    Err(error) => {
                        self.resolver.capture_uncertain(claimed).map_err(storage)?;
                        Err(error)
                    }
                }
            }
        }
    }

    async fn send_refusal(
        &self,
        stream: &mut TcpStream,
        request: &FetchRequest,
        code: FetchRefusalCode,
        counts: Option<(u32, u32)>,
        detail: Option<&'static str>,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        let (active_streams, max_active_streams) = counts.unwrap_or_else(|| self.active_counts());
        self.send_refusal_with_counts(
            stream,
            request,
            code,
            (active_streams, max_active_streams),
            detail,
            io_timeout_duration,
        )
        .await
    }

    async fn send_refusal_with_counts(
        &self,
        stream: &mut TcpStream,
        request: &FetchRequest,
        code: FetchRefusalCode,
        counts: (u32, u32),
        detail: Option<&'static str>,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        let (active_streams, max_active_streams) = counts;
        let refusal = FetchRefusal {
            request_id: request.request_id,
            offer_id: request.offer_id,
            code,
            active_streams,
            max_active_streams,
            detail: detail.map(str::to_owned),
        };
        io_timeout(
            io_timeout_duration,
            write_v2_frame_async(stream, &V2Message::FetchRefusal(refusal)),
            "write fetch refusal",
        )
        .await
    }

    /// Streams one plan. Returns [`PlanEnd::CompleteSent`] once `FetchComplete` is written; the
    /// caller then awaits the receipt.
    async fn send_plan(
        &self,
        stream: &mut TcpStream,
        request: &FetchRequest,
        input: &PlanInput,
        plan: SourcePlan,
        io_timeout_duration: std::time::Duration,
    ) -> Result<PlanEnd, NetError> {
        let header = FetchHeader {
            request_id: request.request_id,
            offer_id: request.offer_id,
            descriptor: plan.descriptor.clone(),
            manifest_entries: u32::try_from(plan.manifest.len()).unwrap_or(u32::MAX),
            manifest_encoded_bytes: u64::try_from(plan.manifest_encoded_bytes).unwrap_or(u64::MAX),
            text_sha256: plan
                .text
                .as_ref()
                .map(|text| Sha256::digest(text.as_bytes()).to_vec()),
            manifest_sha256: plan.manifest_sha256.as_ref().map(|digest| digest.to_vec()),
        };
        self.write_control(stream, V2Message::FetchHeader(header), io_timeout_duration)
            .await?;
        for chunk in &plan.manifest_chunks {
            self.write_control(
                stream,
                V2Message::ManifestChunk(chunk.clone()),
                io_timeout_duration,
            )
            .await?;
        }
        if !plan.manifest.is_empty() {
            let manifest_end = ManifestEnd {
                request_id: request.request_id,
                entry_count: u32::try_from(plan.manifest.len()).unwrap_or(u32::MAX),
                file_count: u32::try_from(plan.files.len()).unwrap_or(u32::MAX),
                total_bytes: plan.total_bytes,
                manifest_sha256: plan.manifest_sha256.clone().unwrap_or_default(),
            };
            self.write_control(
                stream,
                V2Message::ManifestEnd(manifest_end),
                io_timeout_duration,
            )
            .await?;
        }

        let admission = io_timeout(
            io_timeout_duration,
            meshelf_protocol::read_v2_frame_async(stream),
            "read fetch admission",
        )
        .await?;
        validate_v2_message(&admission)?;
        let V2Message::FetchAdmission(admission) = admission else {
            return Err(NetError::UnexpectedMessage("expected fetch_admission"));
        };
        require_accepted_admission(admission, request.request_id)?;

        if plan.text.is_none() {
            match build_source_plan(input, request.request_id) {
                Ok(current) if current.same_source(&plan) => {}
                Ok(_) | Err(SourceFailure::Changed) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        request.offer_id,
                        FetchAbortCode::SourceChanged,
                        0,
                        0,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(PlanEnd::Stopped);
                }
                Err(SourceFailure::Unavailable) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        request.offer_id,
                        FetchAbortCode::SourceUnavailable,
                        0,
                        0,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(PlanEnd::Stopped);
                }
                Err(SourceFailure::Malformed) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        request.offer_id,
                        FetchAbortCode::InternalError,
                        0,
                        0,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(PlanEnd::Stopped);
                }
            }
        }

        if let Some(text) = plan.text {
            self.stream_text(stream, request.request_id, text, io_timeout_duration)
                .await?;
            return Ok(PlanEnd::CompleteSent);
        }

        let mut content_set = Sha256::new();
        content_set.update(plan.manifest_sha256.as_deref().unwrap_or_default());
        let mut files_sent = 0_u32;
        let mut bytes_sent = 0_u64;
        for file in &plan.files {
            match self
                .stream_file(stream, request.request_id, file, io_timeout_duration)
                .await
            {
                Ok(file_digest) => {
                    content_set.update(&file_digest);
                    files_sent = files_sent.saturating_add(1);
                    bytes_sent = bytes_sent.saturating_add(file.byte_len);
                }
                Err(FileStreamFailure::MidStream) => {
                    // Raw bytes may already have crossed the wire. Closing is the only honest
                    // framing after a part-way source mutation.
                    return Ok(PlanEnd::Stopped);
                }
                Err(FileStreamFailure::Unavailable) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        request.offer_id,
                        FetchAbortCode::SourceUnavailable,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(PlanEnd::Stopped);
                }
                Err(FileStreamFailure::Changed) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        request.offer_id,
                        FetchAbortCode::SourceChanged,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(PlanEnd::Stopped);
                }
                Err(FileStreamFailure::AfterFileUnavailable(file_digest)) => {
                    content_set.update(&file_digest);
                    files_sent = files_sent.saturating_add(1);
                    bytes_sent = bytes_sent.saturating_add(file.byte_len);
                    self.send_abort(
                        stream,
                        request.request_id,
                        request.offer_id,
                        FetchAbortCode::SourceUnavailable,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(PlanEnd::Stopped);
                }
                Err(FileStreamFailure::AfterFileChanged(file_digest)) => {
                    content_set.update(&file_digest);
                    files_sent = files_sent.saturating_add(1);
                    bytes_sent = bytes_sent.saturating_add(file.byte_len);
                    self.send_abort(
                        stream,
                        request.request_id,
                        request.offer_id,
                        FetchAbortCode::SourceChanged,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(PlanEnd::Stopped);
                }
                Err(FileStreamFailure::Io(error)) => return Err(error),
            }
        }

        match build_source_plan(input, request.request_id) {
            Ok(current) if current.same_source(&plan) => {}
            Ok(_) | Err(SourceFailure::Changed) => {
                self.send_abort(
                    stream,
                    request.request_id,
                    request.offer_id,
                    FetchAbortCode::SourceChanged,
                    files_sent,
                    bytes_sent,
                    io_timeout_duration,
                )
                .await?;
                return Ok(PlanEnd::Stopped);
            }
            Err(SourceFailure::Unavailable) => {
                self.send_abort(
                    stream,
                    request.request_id,
                    request.offer_id,
                    FetchAbortCode::SourceUnavailable,
                    files_sent,
                    bytes_sent,
                    io_timeout_duration,
                )
                .await?;
                return Ok(PlanEnd::Stopped);
            }
            Err(SourceFailure::Malformed) => {
                self.send_abort(
                    stream,
                    request.request_id,
                    request.offer_id,
                    FetchAbortCode::InternalError,
                    files_sent,
                    bytes_sent,
                    io_timeout_duration,
                )
                .await?;
                return Ok(PlanEnd::Stopped);
            }
        }

        let complete = FetchComplete {
            request_id: request.request_id,
            files_sent,
            bytes_sent,
            content_set_sha256: content_set.finalize().to_vec(),
        };
        self.write_control(
            stream,
            V2Message::FetchComplete(complete),
            io_timeout_duration,
        )
        .await?;
        Ok(PlanEnd::CompleteSent)
    }

    async fn await_completed_receipt(
        &self,
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
        expected_offer_id: Option<meshelf_core::OfferId>,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        let receipt = self
            .await_receipt(stream, request_id, expected_offer_id, io_timeout_duration)
            .await?;
        require_completed_receipt(&receipt)
    }

    async fn stream_text(
        &self,
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
        text: String,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        let bytes = text.as_bytes();
        let mut hasher = Sha256::new();
        for chunk in bytes.chunks(V2_STREAM_BUFFER_BYTES) {
            hasher.update(chunk);
            timeout(io_timeout_duration, stream.write_all(chunk))
                .await
                .map_err(|_| NetError::Timeout("write text payload"))??;
        }
        let digest = hasher.finalize().to_vec();
        self.write_control(
            stream,
            V2Message::TextEnd(TextEnd {
                request_id,
                sha256: digest.clone(),
            }),
            io_timeout_duration,
        )
        .await?;
        self.write_control(
            stream,
            V2Message::FetchComplete(FetchComplete {
                request_id,
                files_sent: 0,
                bytes_sent: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                content_set_sha256: digest,
            }),
            io_timeout_duration,
        )
        .await
    }

    async fn stream_file(
        &self,
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
        file: &LiveFile,
        io_timeout_duration: std::time::Duration,
    ) -> Result<Vec<u8>, FileStreamFailure> {
        let mut source = open_live_file(file, self.documents.as_ref()).await?;
        self.write_control(
            stream,
            V2Message::FileStart(FileStart {
                request_id,
                entry_index: file.entry_index,
                byte_len: file.byte_len,
            }),
            io_timeout_duration,
        )
        .await
        .map_err(FileStreamFailure::Io)?;

        let mut remaining = file.byte_len;
        let mut buffer = vec![0_u8; V2_STREAM_BUFFER_BYTES];
        let mut hasher = Sha256::new();
        while remaining > 0 {
            let wanted =
                usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = source
                .read(&mut buffer[..wanted])
                .await
                .map_err(|_| FileStreamFailure::MidStream)?;
            if read == 0 {
                return Err(FileStreamFailure::MidStream);
            }
            hasher.update(&buffer[..read]);
            timeout(io_timeout_duration, stream.write_all(&buffer[..read]))
                .await
                .map_err(|_| FileStreamFailure::Io(NetError::Timeout("write file payload")))?
                .map_err(|error| FileStreamFailure::Io(NetError::Io(error)))?;
            remaining = remaining.saturating_sub(read as u64);
        }

        confirm_read_complete(file, &mut source).await?;
        let digest = hasher.finalize().to_vec();
        if file
            .expected_sha256
            .is_some_and(|expected| expected[..] != digest[..])
        {
            // These are not the bytes the person photographed and approved. Closing without a
            // file end leaves the requester nothing it can verify or publish.
            return Err(FileStreamFailure::MidStream);
        }
        self.write_control(
            stream,
            V2Message::FileEnd(FileEnd {
                request_id,
                entry_index: file.entry_index,
                sha256: digest.clone(),
            }),
            io_timeout_duration,
        )
        .await
        .map_err(FileStreamFailure::Io)?;

        match verify_path_metadata(file) {
            Ok(()) => Ok(digest),
            Err(FileStreamFailure::Unavailable) => {
                Err(FileStreamFailure::AfterFileUnavailable(digest))
            }
            Err(FileStreamFailure::Changed) => Err(FileStreamFailure::AfterFileChanged(digest)),
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_abort(
        &self,
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
        offer_id: meshelf_core::OfferId,
        code: FetchAbortCode,
        files_sent: u32,
        bytes_sent: u64,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        self.write_control(
            stream,
            V2Message::FetchAbort(FetchAbort {
                request_id,
                code,
                files_sent,
                bytes_sent,
                detail: None,
            }),
            io_timeout_duration,
        )
        .await?;
        let _receipt = self
            .await_receipt(stream, request_id, Some(offer_id), io_timeout_duration)
            .await?;
        Ok(())
    }

    async fn await_receipt(
        &self,
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
        expected_offer_id: Option<meshelf_core::OfferId>,
        io_timeout_duration: std::time::Duration,
    ) -> Result<FetchReceipt, NetError> {
        let response = io_timeout(
            io_timeout_duration,
            meshelf_protocol::read_v2_frame_async(stream),
            "read fetch receipt",
        )
        .await?;
        validate_v2_message(&response)?;
        let V2Message::FetchReceipt(receipt) = response else {
            return Err(NetError::UnexpectedMessage("expected fetch receipt"));
        };
        validate_receipt_identity(&receipt, request_id, expected_offer_id)?;
        Ok(receipt)
    }

    async fn write_control(
        &self,
        stream: &mut TcpStream,
        message: V2Message,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
        io_timeout(
            io_timeout_duration,
            write_v2_frame_async(stream, &message),
            "write fetch control frame",
        )
        .await
    }
}

#[derive(Debug)]
struct SourcePlan {
    descriptor: OfferDescriptor,
    text: Option<String>,
    manifest: Vec<ManifestEntry>,
    manifest_chunks: Vec<ManifestChunk>,
    manifest_encoded_bytes: usize,
    manifest_sha256: Option<Vec<u8>>,
    files: Vec<LiveFile>,
    total_bytes: u64,
    source_commitment: Option<Vec<u8>>,
}

impl SourcePlan {
    fn same_source(&self, other: &Self) -> bool {
        self.descriptor == other.descriptor
            && self.manifest == other.manifest
            && self.manifest_sha256 == other.manifest_sha256
            && self.source_commitment == other.source_commitment
    }
}

#[derive(Debug)]
struct LiveFile {
    entry_index: u32,
    metadata_kind: &'static str,
    relative_name: String,
    origin: LiveFileOrigin,
    byte_len: u64,
    metadata_digest: Vec<u8>,
    expected_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
enum LiveFileOrigin {
    Path(PathBuf),
    Document { lease_id: DocumentLeaseId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceFailure {
    Unavailable,
    Changed,
    Malformed,
}

#[derive(Debug)]
enum FileStreamFailure {
    Unavailable,
    Changed,
    MidStream,
    AfterFileUnavailable(Vec<u8>),
    AfterFileChanged(Vec<u8>),
    Io(NetError),
}

fn validate_receipt_identity(
    receipt: &FetchReceipt,
    request_id: meshelf_core::ActivationId,
    expected_offer_id: Option<meshelf_core::OfferId>,
) -> Result<(), NetError> {
    if receipt.request_id != request_id {
        return Err(NetError::IdentityMismatch(
            "fetch receipt request ID does not match".to_owned(),
        ));
    }
    if let Some(expected_offer_id) = expected_offer_id
        && receipt.offer_id != expected_offer_id
    {
        return Err(NetError::IdentityMismatch(
            "fetch receipt offer ID does not match".to_owned(),
        ));
    }
    Ok(())
}

fn require_completed_receipt(receipt: &FetchReceipt) -> Result<(), NetError> {
    if receipt.code == meshelf_protocol::FetchReceiptCode::Completed {
        Ok(())
    } else {
        Err(NetError::FetchTerminal {
            code: receipt.code.clone(),
            files_processed: receipt.files_received,
            bytes_processed: receipt.bytes_received,
            detail: receipt.detail.clone(),
        })
    }
}

fn require_accepted_admission(
    admission: FetchAdmission,
    request_id: meshelf_core::ActivationId,
) -> Result<(), NetError> {
    if admission.request_id != request_id {
        return Err(NetError::IdentityMismatch(
            "fetch admission request ID does not match".to_owned(),
        ));
    }
    if admission.code == FetchAdmissionCode::Accepted {
        Ok(())
    } else {
        Err(NetError::FetchAdmissionRefused {
            code: admission.code,
            entries_reserved: admission.entries_reserved,
            bytes_reserved: admission.bytes_reserved,
            detail: admission.detail,
        })
    }
}

fn build_source_plan(
    input: &PlanInput,
    request_id: meshelf_core::ActivationId,
) -> Result<SourcePlan, SourceFailure> {
    match (&input.descriptor, &input.source) {
        (OfferDescriptor::Text { .. }, OfferSource::Text { text }) => Ok(SourcePlan {
            descriptor: input.descriptor.clone(),
            text: Some(text.clone()),
            manifest: Vec::new(),
            manifest_chunks: Vec::new(),
            manifest_encoded_bytes: 0,
            manifest_sha256: None,
            files: Vec::new(),
            total_bytes: u64::try_from(text.len()).unwrap_or(u64::MAX),
            source_commitment: None,
        }),
        (
            OfferDescriptor::File {
                root_name,
                total_bytes,
                ..
            },
            OfferSource::File {
                canonical_path,
                metadata_commitment,
            },
        ) => build_file_plan(
            input.descriptor.clone(),
            root_name,
            *total_bytes,
            canonical_path,
            metadata_commitment,
            request_id,
            input.expected_sha256,
        ),
        (
            OfferDescriptor::Folder {
                root_name,
                total_bytes,
                entry_count,
                file_count,
                directory_count,
            },
            OfferSource::Folder {
                canonical_path,
                metadata_commitment,
            },
        ) => build_folder_plan(
            input.descriptor.clone(),
            FolderSpec {
                root_name,
                total_bytes: *total_bytes,
                entry_count: *entry_count,
                file_count: *file_count,
                directory_count: *directory_count,
            },
            canonical_path,
            metadata_commitment,
            request_id,
        ),
        (
            OfferDescriptor::File {
                root_name,
                total_bytes,
                ..
            },
            OfferSource::Document {
                lease_id,
                metadata_commitment,
            },
        ) => build_document_plan(
            input.descriptor.clone(),
            root_name,
            *total_bytes,
            *lease_id,
            metadata_commitment,
            request_id,
            input.expected_sha256,
        ),
        _ => Err(SourceFailure::Malformed),
    }
}

fn build_file_plan(
    descriptor: OfferDescriptor,
    root_name: &str,
    total_bytes: u64,
    path: &Path,
    stored_commitment: &[u8],
    request_id: meshelf_core::ActivationId,
    expected_sha256: Option<[u8; 32]>,
) -> Result<SourcePlan, SourceFailure> {
    let metadata = source_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || path_basename(path) != Some(root_name)
    {
        return Err(SourceFailure::Changed);
    }
    if metadata.len() != total_bytes || metadata.len() > MAX_OFFER_FILE_BYTES {
        return Err(SourceFailure::Changed);
    }
    let mut commitment = Sha256::new();
    hash_metadata(&mut commitment, "root", root_name, &metadata)?;
    let commitment = commitment.finalize().to_vec();
    if commitment != stored_commitment {
        return Err(SourceFailure::Changed);
    }
    let metadata_digest = metadata_digest("root", root_name, &metadata)?;
    let manifest = vec![ManifestEntry {
        relative_path: String::new(),
        kind: FileEntryKind::File,
        byte_len: total_bytes,
    }];
    let manifest_chunks =
        chunk_manifest(request_id, manifest.clone()).map_err(|_| SourceFailure::Malformed)?;
    let manifest_encoded_bytes =
        encoded_manifest_bytes(&manifest_chunks).map_err(|_| SourceFailure::Malformed)?;
    let manifest_sha256 = manifest_digest(&manifest)?;
    Ok(SourcePlan {
        descriptor,
        text: None,
        manifest,
        manifest_chunks,
        manifest_encoded_bytes,
        manifest_sha256: Some(manifest_sha256),
        files: vec![LiveFile {
            entry_index: 0,
            metadata_kind: "root",
            relative_name: root_name.to_owned(),
            origin: LiveFileOrigin::Path(path.to_owned()),
            byte_len: total_bytes,
            metadata_digest,
            expected_sha256,
        }],
        total_bytes,
        source_commitment: Some(commitment),
    })
}

fn build_document_plan(
    descriptor: OfferDescriptor,
    root_name: &str,
    total_bytes: u64,
    lease_id: DocumentLeaseId,
    stored_commitment: &[u8],
    request_id: meshelf_core::ActivationId,
    expected_sha256: Option<[u8; 32]>,
) -> Result<SourcePlan, SourceFailure> {
    if total_bytes == 0 || total_bytes > MAX_OFFER_FILE_BYTES || root_name.is_empty() {
        return Err(SourceFailure::Malformed);
    }
    let commitment = document_metadata_commitment(lease_id, root_name, total_bytes);
    if commitment != stored_commitment {
        return Err(SourceFailure::Changed);
    }
    let manifest = vec![ManifestEntry {
        relative_path: String::new(),
        kind: FileEntryKind::File,
        byte_len: total_bytes,
    }];
    let manifest_chunks =
        chunk_manifest(request_id, manifest.clone()).map_err(|_| SourceFailure::Malformed)?;
    let manifest_encoded_bytes =
        encoded_manifest_bytes(&manifest_chunks).map_err(|_| SourceFailure::Malformed)?;
    let manifest_sha256 = manifest_digest(&manifest)?;
    Ok(SourcePlan {
        descriptor,
        text: None,
        manifest,
        manifest_chunks,
        manifest_encoded_bytes,
        manifest_sha256: Some(manifest_sha256),
        files: vec![LiveFile {
            entry_index: 0,
            metadata_kind: "document",
            relative_name: root_name.to_owned(),
            origin: LiveFileOrigin::Document { lease_id },
            byte_len: total_bytes,
            metadata_digest: commitment.clone(),
            expected_sha256,
        }],
        total_bytes,
        source_commitment: Some(commitment),
    })
}

/// Bound commitment for a document lease (no filesystem metadata).
pub fn document_metadata_commitment(
    lease_id: DocumentLeaseId,
    root_name: &str,
    total_bytes: u64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"document\0");
    hasher.update(lease_id.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(root_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(total_bytes.to_le_bytes());
    hasher.finalize().to_vec()
}

fn build_folder_plan(
    descriptor: OfferDescriptor,
    spec: FolderSpec<'_>,
    path: &Path,
    stored_commitment: &[u8],
    request_id: meshelf_core::ActivationId,
) -> Result<SourcePlan, SourceFailure> {
    let FolderSpec {
        root_name,
        total_bytes,
        entry_count,
        file_count,
        directory_count,
    } = spec;
    let metadata = source_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || path_basename(path) != Some(root_name)
    {
        return Err(SourceFailure::Changed);
    }
    let mut commitment = Sha256::new();
    hash_metadata(&mut commitment, "root", root_name, &metadata)?;
    let mut stats = FolderStats::default();
    let mut manifest = Vec::new();
    let mut files = Vec::new();
    walk_folder(
        path,
        "",
        &mut commitment,
        &mut stats,
        &mut manifest,
        &mut files,
    )?;
    if stats.total_bytes != total_bytes
        || stats.entry_count != entry_count
        || stats.file_count != file_count
        || stats.directory_count != directory_count
        || stats.total_bytes > MAX_OFFER_TRANSFER_BYTES
        || stats.entry_count > MAX_OFFER_MANIFEST_ENTRIES
    {
        return Err(SourceFailure::Changed);
    }
    let commitment = commitment.finalize().to_vec();
    if commitment != stored_commitment {
        return Err(SourceFailure::Changed);
    }
    let manifest_chunks =
        chunk_manifest(request_id, manifest.clone()).map_err(|_| SourceFailure::Malformed)?;
    let manifest_encoded_bytes =
        encoded_manifest_bytes(&manifest_chunks).map_err(|_| SourceFailure::Malformed)?;
    if manifest_encoded_bytes > V2_MAX_MANIFEST_BYTES {
        return Err(SourceFailure::Malformed);
    }
    let manifest_sha256 = manifest_digest(&manifest)?;
    Ok(SourcePlan {
        descriptor,
        text: None,
        manifest,
        manifest_chunks,
        manifest_encoded_bytes,
        manifest_sha256: Some(manifest_sha256),
        files,
        total_bytes,
        source_commitment: Some(commitment),
    })
}

struct FolderSpec<'a> {
    root_name: &'a str,
    total_bytes: u64,
    entry_count: u32,
    file_count: u32,
    directory_count: u32,
}

#[derive(Debug, Default)]
struct FolderStats {
    total_bytes: u64,
    entry_count: u32,
    file_count: u32,
    directory_count: u32,
}

fn walk_folder(
    directory: &Path,
    relative_directory: &str,
    commitment: &mut Sha256,
    stats: &mut FolderStats,
    manifest: &mut Vec<ManifestEntry>,
    files: &mut Vec<LiveFile>,
) -> Result<(), SourceFailure> {
    let mut children = fs::read_dir(directory)
        .map_err(|_| SourceFailure::Unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SourceFailure::Unavailable)?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let name = child
            .file_name()
            .to_str()
            .map(str::to_owned)
            .ok_or(SourceFailure::Changed)?;
        validate_source_component(&name)?;
        let relative_name = if relative_directory.is_empty() {
            name.clone()
        } else {
            format!("{relative_directory}/{name}")
        };
        if relative_name.len() > V2_MAX_RELATIVE_PATH_BYTES {
            return Err(SourceFailure::Changed);
        }
        let child_path = child.path();
        let metadata = source_metadata(&child_path)?;
        if metadata.file_type().is_symlink() {
            return Err(SourceFailure::Changed);
        }
        stats.entry_count = stats
            .entry_count
            .checked_add(1)
            .ok_or(SourceFailure::Changed)?;
        if stats.entry_count > V2_MAX_MANIFEST_ENTRIES {
            return Err(SourceFailure::Changed);
        }
        hash_metadata(commitment, "entry", &relative_name, &metadata)?;
        let entry_index = u32::try_from(manifest.len()).map_err(|_| SourceFailure::Changed)?;
        if metadata.is_file() {
            if metadata.len() > MAX_OFFER_FILE_BYTES {
                return Err(SourceFailure::Changed);
            }
            stats.file_count = stats
                .file_count
                .checked_add(1)
                .ok_or(SourceFailure::Changed)?;
            stats.total_bytes = stats
                .total_bytes
                .checked_add(metadata.len())
                .ok_or(SourceFailure::Changed)?;
            if stats.total_bytes > MAX_OFFER_TRANSFER_BYTES {
                return Err(SourceFailure::Changed);
            }
            manifest.push(ManifestEntry {
                relative_path: relative_name.clone(),
                kind: FileEntryKind::File,
                byte_len: metadata.len(),
            });
            files.push(LiveFile {
                entry_index,
                metadata_kind: "entry",
                relative_name: relative_name.clone(),
                origin: LiveFileOrigin::Path(child_path),
                byte_len: metadata.len(),
                metadata_digest: metadata_digest("entry", &relative_name, &metadata)?,
                expected_sha256: None,
            });
        } else if metadata.is_dir() {
            stats.directory_count = stats
                .directory_count
                .checked_add(1)
                .ok_or(SourceFailure::Changed)?;
            manifest.push(ManifestEntry {
                relative_path: relative_name.clone(),
                kind: FileEntryKind::Directory,
                byte_len: 0,
            });
            walk_folder(
                &child_path,
                &relative_name,
                commitment,
                stats,
                manifest,
                files,
            )?;
        } else {
            return Err(SourceFailure::Changed);
        }
    }
    Ok(())
}

async fn open_and_verify_file(file: &LiveFile) -> Result<tokio::fs::File, FileStreamFailure> {
    let LiveFileOrigin::Path(path) = &file.origin else {
        return Err(FileStreamFailure::Unavailable);
    };
    verify_path_metadata(file)?;
    let source = tokio::fs::File::open(path)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => FileStreamFailure::Unavailable,
            _ => FileStreamFailure::Unavailable,
        })?;
    let metadata = source
        .metadata()
        .await
        .map_err(|_| FileStreamFailure::Unavailable)?;
    if metadata_digest(file.metadata_kind, &file.relative_name, &metadata)
        .map_err(|_| FileStreamFailure::Changed)?
        != file.metadata_digest
    {
        return Err(FileStreamFailure::Changed);
    }
    Ok(source)
}

async fn open_live_file(
    file: &LiveFile,
    documents: &dyn DocumentSourceProvider,
) -> Result<tokio::fs::File, FileStreamFailure> {
    match &file.origin {
        LiveFileOrigin::Path(_) => open_and_verify_file(file).await,
        LiveFileOrigin::Document { lease_id } => match documents.open(*lease_id, file.byte_len) {
            Ok(source) => Ok(source),
            Err(DocumentOpenError::Unavailable) => Err(FileStreamFailure::Unavailable),
            Err(DocumentOpenError::Changed) => Err(FileStreamFailure::Changed),
            Err(DocumentOpenError::Unsupported) => Err(FileStreamFailure::Unavailable),
        },
    }
}

/// After exactly the declared bytes were read: a path source must still carry the metadata it
/// was planned with, and a document (not stat-stable) must be at end of file.
async fn confirm_read_complete(
    file: &LiveFile,
    source: &mut tokio::fs::File,
) -> Result<(), FileStreamFailure> {
    match &file.origin {
        LiveFileOrigin::Path(_) => {
            let opened_metadata = source
                .metadata()
                .await
                .map_err(|_| FileStreamFailure::MidStream)?;
            if metadata_digest(file.metadata_kind, &file.relative_name, &opened_metadata)
                .map_err(|_| FileStreamFailure::MidStream)?
                != file.metadata_digest
            {
                return Err(FileStreamFailure::MidStream);
            }
        }
        LiveFileOrigin::Document { .. } => {
            let mut probe = [0_u8; 1];
            let extra = source
                .read(&mut probe)
                .await
                .map_err(|_| FileStreamFailure::MidStream)?;
            if extra != 0 {
                return Err(FileStreamFailure::MidStream);
            }
        }
    }
    Ok(())
}

/// A source this device retains, opened for its own card's activation. It is planned, checked
/// against its stored metadata commitment, opened and rechecked by exactly the rules an origin
/// applies before and while serving a peer's pull, so an own card can never read something a
/// peer's pull of the same offer would be refused.
pub(crate) enum LocalOfferSource {
    Text(String),
    File(Box<LocalFileSource>),
}

pub(crate) struct LocalFileSource {
    file: LiveFile,
    source: tokio::fs::File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalSourceFailure {
    Unavailable,
    Changed,
    Malformed,
}

pub(crate) enum LocalCopyFailure {
    Source(LocalSourceFailure),
    Write(std::io::Error),
}

pub(crate) async fn open_local_source(
    record: &OfferSourceRecord,
    documents: &dyn DocumentSourceProvider,
    request_id: meshelf_core::ActivationId,
) -> Result<LocalOfferSource, LocalSourceFailure> {
    if record.source.validate_for(&record.descriptor).is_err() {
        return Err(LocalSourceFailure::Malformed);
    }
    let input = PlanInput {
        descriptor: record.descriptor.clone(),
        source: record.source.clone(),
        expected_sha256: None,
    };
    let plan = build_source_plan(&input, request_id).map_err(|failure| match failure {
        SourceFailure::Unavailable => LocalSourceFailure::Unavailable,
        SourceFailure::Changed => LocalSourceFailure::Changed,
        SourceFailure::Malformed => LocalSourceFailure::Malformed,
    })?;
    if let Some(text) = plan.text {
        return Ok(LocalOfferSource::Text(text));
    }
    if !matches!(record.descriptor, OfferDescriptor::File { .. }) {
        // A tree has no single platform export yet; the caller refuses folders before this.
        return Err(LocalSourceFailure::Malformed);
    }
    let file = <[LiveFile; 1]>::try_from(plan.files)
        .map(|[file]| file)
        .map_err(|_| LocalSourceFailure::Malformed)?;
    let source = open_live_file(&file, documents)
        .await
        .map_err(stream_failure_to_local)?;
    Ok(LocalOfferSource::File(Box::new(LocalFileSource {
        file,
        source,
    })))
}

fn stream_failure_to_local(failure: FileStreamFailure) -> LocalSourceFailure {
    match failure {
        FileStreamFailure::Unavailable | FileStreamFailure::AfterFileUnavailable(_) => {
            LocalSourceFailure::Unavailable
        }
        FileStreamFailure::Changed
        | FileStreamFailure::MidStream
        | FileStreamFailure::AfterFileChanged(_)
        | FileStreamFailure::Io(_) => LocalSourceFailure::Changed,
    }
}

impl LocalFileSource {
    pub(crate) fn byte_len(&self) -> u64 {
        self.file.byte_len
    }

    /// Copies exactly the declared bytes into `sink`, syncs it, and applies the same end-of-read
    /// and after-file rechecks as serving a pull. Returns the digest of the copied bytes.
    pub(crate) async fn copy_into(
        mut self,
        sink: &mut tokio::fs::File,
    ) -> Result<Vec<u8>, LocalCopyFailure> {
        use tokio::io::AsyncWriteExt;
        let changed = LocalCopyFailure::Source(LocalSourceFailure::Changed);
        let mut remaining = self.file.byte_len;
        let mut buffer = vec![0_u8; V2_STREAM_BUFFER_BYTES];
        let mut hasher = Sha256::new();
        while remaining > 0 {
            let wanted =
                usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = match self.source.read(&mut buffer[..wanted]).await {
                Ok(0) | Err(_) => return Err(changed),
                Ok(read) => read,
            };
            hasher.update(&buffer[..read]);
            sink.write_all(&buffer[..read])
                .await
                .map_err(LocalCopyFailure::Write)?;
            remaining = remaining.saturating_sub(read as u64);
        }
        confirm_read_complete(&self.file, &mut self.source)
            .await
            .map_err(|failure| LocalCopyFailure::Source(stream_failure_to_local(failure)))?;
        sink.flush().await.map_err(LocalCopyFailure::Write)?;
        sink.sync_all().await.map_err(LocalCopyFailure::Write)?;
        verify_path_metadata(&self.file)
            .map_err(|failure| LocalCopyFailure::Source(stream_failure_to_local(failure)))?;
        Ok(hasher.finalize().to_vec())
    }
}

fn verify_path_metadata(file: &LiveFile) -> Result<(), FileStreamFailure> {
    match &file.origin {
        LiveFileOrigin::Document { .. } => {
            // Document sources already passed the EOF probe; there is no filesystem metadata.
            Ok(())
        }
        LiveFileOrigin::Path(path) => {
            let metadata = source_metadata(path).map_err(|error| match error {
                SourceFailure::Unavailable => FileStreamFailure::Unavailable,
                SourceFailure::Changed | SourceFailure::Malformed => FileStreamFailure::Changed,
            })?;
            if metadata_digest(file.metadata_kind, &file.relative_name, &metadata)
                .map_err(|_| FileStreamFailure::Changed)?
                != file.metadata_digest
            {
                return Err(FileStreamFailure::Changed);
            }
            Ok(())
        }
    }
}

fn source_metadata(path: &Path) -> Result<Metadata, SourceFailure> {
    fs::symlink_metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => SourceFailure::Unavailable,
        _ => SourceFailure::Unavailable,
    })
}

fn path_basename(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

fn manifest_digest<T: Serialize>(entries: &T) -> Result<Vec<u8>, SourceFailure> {
    let encoded = serde_json::to_vec(entries).map_err(|_| SourceFailure::Malformed)?;
    Ok(Sha256::digest(encoded).to_vec())
}

fn metadata_digest(
    kind: &str,
    relative_name: &str,
    metadata: &Metadata,
) -> Result<Vec<u8>, SourceFailure> {
    let mut hasher = Sha256::new();
    hash_metadata(&mut hasher, kind, relative_name, metadata)?;
    Ok(hasher.finalize().to_vec())
}

fn hash_metadata(
    hasher: &mut Sha256,
    kind: &str,
    relative_name: &str,
    metadata: &Metadata,
) -> Result<(), SourceFailure> {
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(relative_name.as_bytes());
    hasher.update([0]);
    hash_metadata_identity(hasher, metadata);
    hasher.update(metadata.len().to_le_bytes());
    hasher.update([u8::from(metadata.is_file()), u8::from(metadata.is_dir())]);
    hasher.update([u8::from(metadata.permissions().readonly())]);
    let modified = metadata
        .modified()
        .map_err(|_| SourceFailure::Unavailable)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SourceFailure::Unavailable)?;
    hasher.update(modified.as_secs().to_le_bytes());
    hasher.update(modified.subsec_nanos().to_le_bytes());
    Ok(())
}

fn hash_metadata_identity(hasher: &mut Sha256, metadata: &Metadata) {
    hasher.update(meshelf_platform::source_identity_bytes(metadata));
}

fn validate_source_component(component: &str) -> Result<(), SourceFailure> {
    let device_stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let numbered_device_suffix = device_stem
        .strip_prefix("COM")
        .or_else(|| device_stem.strip_prefix("LPT"));
    let reserved = matches!(device_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || numbered_device_suffix.is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if component.is_empty()
        || component.len() > meshelf_protocol::V2_MAX_PORTABLE_COMPONENT_BYTES
        || component == "."
        || component == ".."
        || component.ends_with(' ')
        || component.ends_with('.')
        || component.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
        })
        || reserved
    {
        return Err(SourceFailure::Changed);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn metadata_commitment_for_test(
    path: &Path,
    descriptor: &OfferDescriptor,
) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let mut commitment = Sha256::new();
    let root_name = match descriptor {
        OfferDescriptor::File { root_name, .. } | OfferDescriptor::Folder { root_name, .. } => {
            root_name
        }
        OfferDescriptor::Text { .. } => return None,
    };
    hash_metadata(&mut commitment, "root", root_name, &metadata).ok()?;
    if let OfferDescriptor::Folder { .. } = descriptor {
        let mut stats = FolderStats::default();
        let mut manifest = Vec::new();
        let mut files = Vec::new();
        walk_folder(
            path,
            "",
            &mut commitment,
            &mut stats,
            &mut manifest,
            &mut files,
        )
        .ok()?;
    }
    Some(commitment.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_admission_is_not_a_successful_transfer() {
        let request_id = meshelf_core::ActivationId::new();
        let result = require_accepted_admission(
            FetchAdmission {
                request_id,
                code: FetchAdmissionCode::InvalidManifest,
                entries_reserved: 0,
                bytes_reserved: 0,
                detail: Some("descriptor mismatch".to_owned()),
            },
            request_id,
        );
        assert!(matches!(
            result,
            Err(NetError::FetchAdmissionRefused {
                code: FetchAdmissionCode::InvalidManifest,
                entries_reserved: 0,
                bytes_reserved: 0,
                ..
            })
        ));
    }
}
