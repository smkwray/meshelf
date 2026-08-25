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
    DeviceId, MAX_OFFER_FILE_BYTES, MAX_OFFER_MANIFEST_ENTRIES, MAX_OFFER_TRANSFER_BYTES,
    OfferDescriptor, OfferSource, OfferSourceRecord, OfferSourceStore,
};
use meshelf_protocol::{
    FetchAbort, FetchAbortCode, FetchAdmissionCode, FetchComplete, FetchHeader, FetchRefusal,
    FetchRefusalCode, FetchRequest, FileEnd, FileEntryKind, FileStart, ManifestChunk, ManifestEnd,
    ManifestEntry, TextEnd, V2_MAX_ACTIVE_PAYLOAD_STREAMS, V2_MAX_MANIFEST_BYTES,
    V2_MAX_MANIFEST_ENTRIES, V2_MAX_RELATIVE_PATH_BYTES, V2_STREAM_BUFFER_BYTES, V2Message,
    chunk_manifest, encoded_manifest_bytes, validate_v2_message, write_v2_frame_async,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Semaphore, TryAcquireError},
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

pub struct OfferFetchHandler {
    origin_device: DeviceId,
    store: Arc<dyn OfferSourceStore>,
    active_streams: Arc<Semaphore>,
}

impl OfferFetchHandler {
    #[must_use]
    pub fn new(origin_device: DeviceId, store: Arc<dyn OfferSourceStore>) -> Self {
        Self {
            origin_device,
            store,
            active_streams: Arc::new(Semaphore::new(
                usize::try_from(V2_MAX_ACTIVE_PAYLOAD_STREAMS).expect("stream limit fits usize"),
            )),
        }
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
        let Some(record) = self
            .store
            .get_offer_source(request.offer_id)
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

        let plan = match build_source_plan(&record, request.request_id) {
            Ok(plan) => plan,
            Err(SourceFailure::Unavailable) => {
                drop(permit);
                return self
                    .send_refusal(
                        stream,
                        &request,
                        FetchRefusalCode::SourceUnavailable,
                        None,
                        None,
                        io_timeout_duration,
                    )
                    .await;
            }
            Err(SourceFailure::Changed) => {
                drop(permit);
                return self
                    .send_refusal(
                        stream,
                        &request,
                        FetchRefusalCode::SourceChanged,
                        None,
                        None,
                        io_timeout_duration,
                    )
                    .await;
            }
            Err(SourceFailure::Malformed) => {
                drop(permit);
                return self
                    .send_refusal(
                        stream,
                        &request,
                        FetchRefusalCode::Malformed,
                        None,
                        Some("source cannot be represented by the v2 manifest"),
                        io_timeout_duration,
                    )
                    .await;
            }
        };

        self.send_plan(stream, &request, &record, plan, io_timeout_duration)
            .await?;
        drop(permit);
        Ok(())
    }
}

impl OfferFetchHandler {
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

    async fn send_plan(
        &self,
        stream: &mut TcpStream,
        request: &FetchRequest,
        record: &OfferSourceRecord,
        plan: SourcePlan,
        io_timeout_duration: std::time::Duration,
    ) -> Result<(), NetError> {
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
        if admission.request_id != request.request_id {
            return Err(NetError::IdentityMismatch(
                "fetch admission request ID does not match".to_owned(),
            ));
        }
        if admission.code != FetchAdmissionCode::Accepted {
            return Ok(());
        }

        if plan.text.is_none() {
            match build_source_plan(record, request.request_id) {
                Ok(current) if current.same_source(&plan) => {}
                Ok(_) | Err(SourceFailure::Changed) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        FetchAbortCode::SourceChanged,
                        0,
                        0,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
                Err(SourceFailure::Unavailable) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        FetchAbortCode::SourceUnavailable,
                        0,
                        0,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
                Err(SourceFailure::Malformed) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        FetchAbortCode::InternalError,
                        0,
                        0,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }

        if let Some(text) = plan.text {
            return self
                .stream_text(stream, request.request_id, text, io_timeout_duration)
                .await;
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
                    return Ok(());
                }
                Err(FileStreamFailure::Unavailable) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        FetchAbortCode::SourceUnavailable,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
                Err(FileStreamFailure::Changed) => {
                    self.send_abort(
                        stream,
                        request.request_id,
                        FetchAbortCode::SourceChanged,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
                Err(FileStreamFailure::AfterFileUnavailable(file_digest)) => {
                    content_set.update(&file_digest);
                    files_sent = files_sent.saturating_add(1);
                    bytes_sent = bytes_sent.saturating_add(file.byte_len);
                    self.send_abort(
                        stream,
                        request.request_id,
                        FetchAbortCode::SourceUnavailable,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
                Err(FileStreamFailure::AfterFileChanged(file_digest)) => {
                    content_set.update(&file_digest);
                    files_sent = files_sent.saturating_add(1);
                    bytes_sent = bytes_sent.saturating_add(file.byte_len);
                    self.send_abort(
                        stream,
                        request.request_id,
                        FetchAbortCode::SourceChanged,
                        files_sent,
                        bytes_sent,
                        io_timeout_duration,
                    )
                    .await?;
                    return Ok(());
                }
                Err(FileStreamFailure::Io(error)) => return Err(error),
            }
        }

        match build_source_plan(record, request.request_id) {
            Ok(current) if current.same_source(&plan) => {}
            Ok(_) | Err(SourceFailure::Changed) => {
                self.send_abort(
                    stream,
                    request.request_id,
                    FetchAbortCode::SourceChanged,
                    files_sent,
                    bytes_sent,
                    io_timeout_duration,
                )
                .await?;
                return Ok(());
            }
            Err(SourceFailure::Unavailable) => {
                self.send_abort(
                    stream,
                    request.request_id,
                    FetchAbortCode::SourceUnavailable,
                    files_sent,
                    bytes_sent,
                    io_timeout_duration,
                )
                .await?;
                return Ok(());
            }
            Err(SourceFailure::Malformed) => {
                self.send_abort(
                    stream,
                    request.request_id,
                    FetchAbortCode::InternalError,
                    files_sent,
                    bytes_sent,
                    io_timeout_duration,
                )
                .await?;
                return Ok(());
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
        .await
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
        let mut source = match open_and_verify_file(file).await {
            Ok(source) => source,
            Err(error) => return Err(error),
        };
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
        let digest = hasher.finalize().to_vec();
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

    async fn send_abort(
        &self,
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
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
        .await
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
    path: PathBuf,
    byte_len: u64,
    metadata_digest: Vec<u8>,
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

fn build_source_plan(
    record: &OfferSourceRecord,
    request_id: meshelf_core::ActivationId,
) -> Result<SourcePlan, SourceFailure> {
    match (&record.descriptor, &record.source) {
        (OfferDescriptor::Text { .. }, OfferSource::Text { text }) => Ok(SourcePlan {
            descriptor: record.descriptor.clone(),
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
            },
            OfferSource::File {
                canonical_path,
                metadata_commitment,
            },
        ) => build_file_plan(
            record.descriptor.clone(),
            root_name,
            *total_bytes,
            canonical_path,
            metadata_commitment,
            request_id,
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
            record.descriptor.clone(),
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
            path: path.to_owned(),
            byte_len: total_bytes,
            metadata_digest,
        }],
        total_bytes,
        source_commitment: Some(commitment),
    })
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
                path: child_path,
                byte_len: metadata.len(),
                metadata_digest: metadata_digest("entry", &relative_name, &metadata)?,
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
    verify_path_metadata(file)?;
    let source = tokio::fs::File::open(&file.path)
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

fn verify_path_metadata(file: &LiveFile) -> Result<(), FileStreamFailure> {
    let metadata = source_metadata(&file.path).map_err(|error| match error {
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
