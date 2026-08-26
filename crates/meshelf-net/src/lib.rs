//! Direct protocol-2 transport for metadata announcements and user-initiated fetches.

mod destination;
mod fetch_receiver;
mod fetch_sender;

pub use fetch_receiver::{
    FetchActivation, FetchClipboard, FetchReceiver, OfferFetchReceiver, ReservationError,
    ReservationLedger, ReservationPermit, V2FetchReceiver,
};
pub use fetch_sender::{OfferFetchHandler, V2FetchSender};

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr, TcpListener as StdTcpListener},
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use meshelf_core::{
    CardAvailability, DeviceId, OfferCardInput, OfferCardInsert, OfferCardRecord, OfferId,
    StoreError, V2_MAX_LIVE_ENTRIES,
};
use meshelf_identity::InstallationIdentity;
use meshelf_protocol::{
    CAP_OFFER_PULL_V2, ClientHello, OfferAck, OfferAckCode, OfferAnnouncement, ProtocolError,
    ServerHello, V2_MAX_INBOUND_HANDLERS, V2_PROTOCOL_VERSION, V2Message, WireMessage,
    read_client_hello_async, read_frame_async, read_v2_frame_async, validate_v2_message,
    write_frame_async, write_v2_frame_async,
};
use meshelf_store::RedbV2Store;
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, TryAcquireError, watch},
    time::timeout,
};

#[derive(Debug, Clone)]
pub struct ServerIdentity {
    pub signing_identity: InstallationIdentity,
    pub device_name: String,
}

#[cfg(test)]
mod restored_v2_tests {
    use std::{
        collections::HashSet,
        fs,
        path::{Path, PathBuf},
        sync::Arc,
    };

    use meshelf_core::{
        ActivationId, OfferAttemptCode, OfferDescriptor, OfferSource, OfferSourceInput,
    };
    use meshelf_protocol::{
        ClientHello, FetchAbortCode, FetchReceipt, FetchRefusal, FetchRefusalCode, FetchRequest,
        ManifestEntry, V2_MAX_INBOUND_HANDLERS, V2_MAX_MANIFEST_BYTES,
    };
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::watch,
    };

    use super::*;
    use crate::fetch_sender;

    const TEST_IO_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Debug, Default)]
    struct NoopFetchClipboard;

    impl meshelf_core::ClipboardSink for NoopFetchClipboard {
        fn set_text(&self, _text: &str) -> Result<(), meshelf_core::ClipboardError> {
            Ok(())
        }
    }

    impl FetchClipboard for NoopFetchClipboard {
        fn set_files(&self, _paths: &[PathBuf]) -> Result<(), meshelf_core::ClipboardError> {
            Ok(())
        }
    }

    async fn start_offer_server(
        allowed_devices: impl IntoIterator<Item = DeviceId>,
    ) -> (
        tempfile::TempDir,
        SocketAddr,
        meshelf_identity::InstallationIdentity,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), NetError>>,
        Arc<RedbV2Store>,
    ) {
        start_offer_server_with_identity(
            allowed_devices,
            meshelf_identity::InstallationIdentity::generate(),
            "BZOT",
        )
        .await
    }

    async fn start_offer_server_with_identity(
        allowed_devices: impl IntoIterator<Item = DeviceId>,
        target_identity: meshelf_identity::InstallationIdentity,
        device_name: &str,
    ) -> (
        tempfile::TempDir,
        SocketAddr,
        meshelf_identity::InstallationIdentity,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), NetError>>,
        Arc<RedbV2Store>,
    ) {
        let directory = tempfile::tempdir().expect("temporary offer directory");
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("offers.redb")).expect("open store"));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_v2_with_offers_and_fetch(
            listener,
            ServerIdentity {
                signing_identity: target_identity.clone(),
                device_name: device_name.to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new(allowed_devices)),
            V2OfferServices {
                announcement_receiver: Arc::new(OfferAnnouncementHandler::new(store.clone())),
                fetch_sender: Arc::new(OfferFetchHandler::new(
                    target_identity.device_id,
                    store.clone(),
                )),
            },
            TEST_IO_TIMEOUT,
            shutdown_rx,
        ));
        (
            directory,
            address,
            target_identity,
            shutdown_tx,
            server,
            store,
        )
    }

    async fn start_fetch_server(
        allowed_devices: impl IntoIterator<Item = DeviceId>,
    ) -> (
        tempfile::TempDir,
        SocketAddr,
        meshelf_identity::InstallationIdentity,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), NetError>>,
        Arc<RedbV2Store>,
    ) {
        start_offer_server(allowed_devices).await
    }

    fn now_unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_millis() as u64
    }
    async fn stop_offer_server(
        shutdown_tx: watch::Sender<bool>,
        server: tokio::task::JoinHandle<Result<(), NetError>>,
    ) {
        shutdown_tx.send(true).expect("request shutdown");
        server.await.expect("server task").expect("clean server");
    }

    fn insert_text_source(
        store: &RedbV2Store,
        requester: DeviceId,
        offer_id: OfferId,
        text: &str,
    ) -> OfferDescriptor {
        let descriptor = OfferDescriptor::text(text).expect("text descriptor");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor.clone(),
                HashSet::from([requester]),
                OfferSource::Text {
                    text: text.to_owned(),
                },
            ))
            .expect("insert text source");
        descriptor
    }

    fn insert_file_source(
        store: &RedbV2Store,
        requester: DeviceId,
        offer_id: OfferId,
        path: &Path,
    ) -> OfferDescriptor {
        insert_file_source_for_requesters(store, HashSet::from([requester]), offer_id, path)
    }

    fn insert_file_source_for_requesters(
        store: &RedbV2Store,
        requesters: HashSet<DeviceId>,
        offer_id: OfferId,
        path: &Path,
    ) -> OfferDescriptor {
        let root_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("file root name")
            .to_owned();
        let total_bytes = fs::metadata(path).expect("file metadata").len();
        let descriptor = OfferDescriptor::File {
            root_name: root_name.clone(),
            total_bytes,
        };
        let commitment =
            fetch_sender::metadata_commitment_for_test(path, &descriptor).expect("file commitment");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor.clone(),
                requesters,
                OfferSource::File {
                    canonical_path: fs::canonicalize(path).expect("canonical file"),
                    metadata_commitment: commitment,
                },
            ))
            .expect("insert file source");
        descriptor
    }

    fn insert_folder_source(
        store: &RedbV2Store,
        requester: DeviceId,
        offer_id: OfferId,
        path: &Path,
    ) -> OfferDescriptor {
        let root_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("folder root name")
            .to_owned();
        let mut total_bytes = 0_u64;
        let mut entry_count = 0_u32;
        let mut file_count = 0_u32;
        let mut directory_count = 0_u32;
        let mut pending = vec![path.to_owned()];
        while let Some(directory) = pending.pop() {
            for child in fs::read_dir(directory).expect("read folder") {
                let child = child.expect("folder entry");
                let metadata = child.metadata().expect("folder metadata");
                entry_count = entry_count.saturating_add(1);
                if metadata.is_dir() {
                    directory_count = directory_count.saturating_add(1);
                    pending.push(child.path());
                } else {
                    file_count = file_count.saturating_add(1);
                    total_bytes = total_bytes.saturating_add(metadata.len());
                }
            }
        }
        let descriptor = OfferDescriptor::Folder {
            root_name: root_name.clone(),
            total_bytes,
            entry_count,
            file_count,
            directory_count,
        };
        let commitment = fetch_sender::metadata_commitment_for_test(path, &descriptor)
            .expect("folder commitment");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor.clone(),
                HashSet::from([requester]),
                OfferSource::Folder {
                    canonical_path: fs::canonicalize(path).expect("canonical folder"),
                    metadata_commitment: commitment,
                },
            ))
            .expect("insert folder source");
        descriptor
    }

    async fn connect_fetch(
        address: SocketAddr,
        requester_identity: &meshelf_identity::InstallationIdentity,
        origin_identity: &meshelf_identity::InstallationIdentity,
        request: FetchRequest,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.expect("connect fetch");
        stream.set_nodelay(true).expect("nodelay");
        let hello = ClientHello::signed(
            requester_identity.device_id,
            "BZOT",
            DeviceId::new().to_string(),
            requester_identity,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write fetch hello",
        )
        .await
        .expect("write fetch hello");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read fetch server hello",
        )
        .await
        .expect("read fetch server hello");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected fetch server hello");
        };
        assert!(server_hello.accepted);
        assert_eq!(server_hello.device_id, origin_identity.device_id);
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(&mut stream, &V2Message::FetchRequest(request)),
            "write fetch request",
        )
        .await
        .expect("write fetch request");
        stream
    }

    async fn read_fetch_header_and_manifest(
        stream: &mut TcpStream,
    ) -> (meshelf_protocol::FetchHeader, Vec<ManifestEntry>, usize) {
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_v2_frame_async(stream),
            "read fetch header",
        )
        .await
        .expect("read fetch header");
        let V2Message::FetchHeader(header) = response else {
            panic!("expected fetch header");
        };
        let mut entries = Vec::new();
        let mut chunk_count = 0;
        while entries.len() < usize::try_from(header.manifest_entries).expect("entry count") {
            let response = io_timeout(
                TEST_IO_TIMEOUT,
                read_v2_frame_async(stream),
                "read manifest frame",
            )
            .await
            .expect("read manifest frame");
            match response {
                V2Message::ManifestChunk(chunk) => {
                    chunk_count += 1;
                    entries.extend(chunk.entries);
                }
                V2Message::ManifestEnd(end) => {
                    assert_eq!(end.entry_count, header.manifest_entries);
                }
                other => panic!("unexpected manifest response: {other:?}"),
            }
        }
        if header.manifest_entries > 0 {
            let response = io_timeout(
                TEST_IO_TIMEOUT,
                read_v2_frame_async(stream),
                "read manifest end",
            )
            .await
            .expect("read manifest end");
            assert!(matches!(response, V2Message::ManifestEnd(_)));
        }
        (header, entries, chunk_count)
    }

    async fn admit_fetch(stream: &mut TcpStream, request_id: meshelf_core::ActivationId) {
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(
                stream,
                &V2Message::FetchAdmission(meshelf_protocol::FetchAdmission {
                    request_id,
                    code: meshelf_protocol::FetchAdmissionCode::Accepted,
                    entries_reserved: 0,
                    bytes_reserved: 0,
                    detail: None,
                }),
            ),
            "write fetch admission",
        )
        .await
        .expect("write fetch admission");
    }

    async fn read_v2_test(stream: &mut TcpStream, operation: &'static str) -> V2Message {
        io_timeout(TEST_IO_TIMEOUT, read_v2_frame_async(stream), operation)
            .await
            .expect("read v2 frame")
    }

    async fn write_fetch_receipt(
        stream: &mut TcpStream,
        request_id: meshelf_core::ActivationId,
        offer_id: OfferId,
    ) {
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(
                stream,
                &V2Message::FetchReceipt(meshelf_protocol::FetchReceipt {
                    request_id,
                    offer_id,
                    code: meshelf_protocol::FetchReceiptCode::Completed,
                    files_received: 0,
                    bytes_received: 0,
                    detail: None,
                }),
            ),
            "write fetch receipt",
        )
        .await
        .expect("write fetch receipt");
    }

    async fn read_exact_test(stream: &mut TcpStream, bytes: &mut [u8], operation: &'static str) {
        timeout(TEST_IO_TIMEOUT, stream.read_exact(bytes))
            .await
            .expect("read payload timeout")
            .expect(operation);
    }

    fn text_announcement(
        source: DeviceId,
        target: DeviceId,
        offer_id: OfferId,
        text: &str,
    ) -> OfferAnnouncement {
        OfferAnnouncement::new(
            offer_id,
            source,
            target,
            now_unix_ms(),
            meshelf_core::OfferDescriptor::text(text).expect("text descriptor"),
        )
    }

    async fn send_announcement(
        address: SocketAddr,
        source_identity: &meshelf_identity::InstallationIdentity,
        target_identity: &meshelf_identity::InstallationIdentity,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError> {
        PeerClient::with_timeouts(TEST_IO_TIMEOUT, TEST_IO_TIMEOUT)
            .announce_offer_v2(
                address,
                ClientHello::signed(
                    source_identity.device_id,
                    "BMST",
                    DeviceId::new().to_string(),
                    source_identity,
                ),
                announcement,
                &target_identity.public_key(),
            )
            .await
    }

    async fn send_raw_announcement(
        address: SocketAddr,
        source_identity: &meshelf_identity::InstallationIdentity,
        target_identity: &meshelf_identity::InstallationIdentity,
        announcement: OfferAnnouncement,
    ) -> OfferAck {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect announcement");
        stream.set_nodelay(true).expect("nodelay");
        let hello = ClientHello::signed(
            source_identity.device_id,
            "BMST",
            DeviceId::new().to_string(),
            source_identity,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write raw client hello",
        )
        .await
        .expect("write hello");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read raw server hello",
        )
        .await
        .expect("read hello");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected server hello");
        };
        assert!(server_hello.accepted);
        assert_eq!(server_hello.device_id, target_identity.device_id);

        let payload = serde_json::to_vec(&V2Message::OfferAnnouncement(announcement))
            .expect("serialize raw announcement");
        let payload_len = u32::try_from(payload.len()).expect("raw announcement length");
        stream
            .write_all(&payload_len.to_be_bytes())
            .await
            .expect("write raw announcement length");
        stream
            .write_all(&payload)
            .await
            .expect("write raw announcement");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_v2_frame_async(&mut stream),
            "read raw acknowledgement",
        )
        .await
        .expect("read raw acknowledgement");
        let V2Message::OfferAck(ack) = response else {
            panic!("expected offer ack");
        };
        ack
    }

    fn filesystem_entries(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut entries = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).expect("read test directory") {
                let entry = entry.expect("read directory entry");
                let path = entry.path();
                let metadata = entry.metadata().expect("read entry metadata");
                if metadata.is_dir() {
                    pending.push(path);
                } else {
                    entries.push((path, metadata.len()));
                }
            }
        }
        entries
    }

    fn assert_no_payload_artifacts(root: &Path) {
        let entries = filesystem_entries(root);
        let forbidden = entries
            .iter()
            .filter(|(path, _)| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.contains("staging")
                            || name.contains("cache")
                            || name.contains("payload")
                    })
            })
            .collect::<Vec<_>>();
        assert!(
            forbidden.is_empty(),
            "unexpected payload artifacts: {forbidden:?}"
        );
        assert!(
            entries
                .iter()
                .any(|(path, _)| path.ends_with("offers.redb")),
            "metadata store was not created"
        );
        let non_store_bytes: u64 = entries
            .iter()
            .filter(|(path, _)| !path.ends_with("offers.redb"))
            .map(|(_, bytes)| *bytes)
            .sum();
        assert_eq!(non_store_bytes, 0, "non-store payload bytes were written");
    }
    #[test]
    fn production_listener_attaches_to_its_long_lived_runtime() {
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = bind_discovered_tailscale_std_listener(
            address,
            &[std::net::Ipv4Addr::LOCALHOST.into()],
        )
        .expect("bind validated standard listener");
        let bound_address = listener.local_addr().expect("bound address");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("server runtime");
            let listener = runtime
                .block_on(async move { TcpListener::from_std(listener) })
                .expect("attach listener to runtime");
            ready_tx.send(()).expect("signal listener ready");
            runtime
                .block_on(async { timeout(TEST_IO_TIMEOUT, listener.accept()).await })
                .expect("listener accepted before timeout")
                .expect("accept connection");
        });

        ready_rx.recv().expect("listener attached");
        std::net::TcpStream::connect(bound_address).expect("connect to moved listener");
        worker.join().expect("server worker");
    }

    #[tokio::test]
    async fn announcement_persists_only_metadata() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "metadata must be bounded",
        );
        let ack = send_announcement(
            address,
            &source_identity,
            &target_identity,
            announcement.clone(),
        )
        .await
        .expect("metadata announcement");
        assert_eq!(ack.code, OfferAckCode::Stored);
        let card = store
            .get_offer_card(source_identity.device_id, announcement.offer_id)
            .expect("read card")
            .expect("stored card");
        assert_eq!(card.descriptor, announcement.descriptor);
        assert_eq!(card.availability, CardAvailability::Available);
        assert!(card.last_attempt.is_none());
        assert!(
            store
                .read_offer_sources()
                .expect("read source table")
                .is_empty()
        );
        stop_offer_server(shutdown_tx, server).await;
        assert_no_payload_artifacts(directory.path());
    }

    #[tokio::test]
    async fn announcement_creates_no_staging_cache_or_payload_file_on_disk() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (directory, address, target_identity, shutdown_tx, server, _store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "metadata only",
        );
        let ack = send_announcement(address, &source_identity, &target_identity, announcement)
            .await
            .expect("announce");
        assert_eq!(ack.code, OfferAckCode::Stored);
        stop_offer_server(shutdown_tx, server).await;
        assert_no_payload_artifacts(directory.path());
    }

    #[tokio::test]
    async fn announcement_without_activation_writes_zero_payload_bytes() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let source_directory = tempfile::tempdir().expect("source directory");
        let source_file = source_directory.path().join("secret.txt");
        fs::write(&source_file, b"payload remains on the source").expect("write source file");
        let (receiver_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            source_identity.device_id,
            target_identity.device_id,
            now_unix_ms(),
            meshelf_core::OfferDescriptor::File {
                root_name: "secret.txt".to_owned(),
                total_bytes: 31,
            },
        );
        let ack = send_announcement(address, &source_identity, &target_identity, announcement)
            .await
            .expect("announce file metadata");
        assert_eq!(ack.code, OfferAckCode::Stored);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
        assert_no_payload_artifacts(receiver_directory.path());
        assert_eq!(
            fs::read(&source_file).expect("source remains"),
            b"payload remains on the source"
        );
    }

    #[tokio::test]
    async fn third_peer_that_never_activates_receives_zero_payload_bytes() {
        let origin_identity = meshelf_identity::InstallationIdentity::generate();
        let activating_identity = meshelf_identity::InstallationIdentity::generate();
        let dormant_identity = meshelf_identity::InstallationIdentity::generate();
        assert_ne!(origin_identity.device_id, activating_identity.device_id);
        assert_ne!(origin_identity.device_id, dormant_identity.device_id);
        assert_ne!(activating_identity.device_id, dormant_identity.device_id);

        let source_directory = tempfile::tempdir().expect("source directory");
        let source_file = source_directory.path().join("secret.txt");
        let source_bytes = b"payload remains on the source";
        fs::write(&source_file, source_bytes).expect("write source file");

        let (
            origin_directory,
            origin_address,
            origin,
            origin_shutdown,
            origin_server,
            origin_store,
        ) = start_offer_server_with_identity(
            [activating_identity.device_id],
            origin_identity,
            "BMST",
        )
        .await;
        let (
            activating_directory,
            activating_address,
            activating,
            activating_shutdown,
            activating_server,
            activating_store,
        ) = start_offer_server_with_identity([origin.device_id], activating_identity, "ACTIVE")
            .await;
        let (
            dormant_directory,
            dormant_address,
            dormant,
            dormant_shutdown,
            dormant_server,
            dormant_store,
        ) = start_offer_server_with_identity([origin.device_id], dormant_identity, "DORMANT").await;

        let offer_id = OfferId::new();
        let descriptor = insert_file_source_for_requesters(
            &origin_store,
            HashSet::from([activating.device_id, dormant.device_id]),
            offer_id,
            &source_file,
        );
        let activating_announcement = OfferAnnouncement::new(
            offer_id,
            origin.device_id,
            activating.device_id,
            now_unix_ms(),
            descriptor.clone(),
        );
        let dormant_announcement = OfferAnnouncement::new(
            offer_id,
            origin.device_id,
            dormant.device_id,
            now_unix_ms(),
            descriptor,
        );
        assert_eq!(
            send_announcement(
                activating_address,
                &origin,
                &activating,
                activating_announcement,
            )
            .await
            .expect("announce to activating peer")
            .code,
            OfferAckCode::Stored
        );
        assert_eq!(
            send_announcement(dormant_address, &origin, &dormant, dormant_announcement)
                .await
                .expect("announce to dormant peer")
                .code,
            OfferAckCode::Stored
        );
        assert!(
            activating_store
                .get_offer_card(origin.device_id, offer_id)
                .expect("read activating card")
                .is_some()
        );
        assert!(
            dormant_store
                .get_offer_card(origin.device_id, offer_id)
                .expect("read dormant card")
                .is_some()
        );

        let request = FetchRequest::new(offer_id, origin.device_id, activating.device_id);
        // macOS exposes the temporary directory through `/var`, which is a symlink to
        // `/private/var`. The production receiver correctly rejects every symlink ancestor, so
        // exercise it with the resolved directory just like the focused receiver fixtures do.
        let activating_root =
            fs::canonicalize(activating_directory.path()).expect("canonical activating directory");
        let destination = activating_root.join("received");
        let activation = FetchActivation::new(
            request.request_id,
            origin.device_id,
            offer_id,
            meshelf_core::ActivationMode::Save,
            Some(destination.clone()),
        );
        let receiver = FetchReceiver::new(
            activating.device_id,
            activating_store,
            Arc::new(NoopFetchClipboard),
            activating_root,
        );
        receiver
            .startup_cleanup()
            .expect("activating peer startup cleanup");
        PeerClient::with_timeouts(TEST_IO_TIMEOUT, TEST_IO_TIMEOUT)
            .fetch_v2(
                origin_address,
                ClientHello::signed_v2(
                    activating.device_id,
                    "ACTIVE",
                    DeviceId::new().to_string(),
                    &activating,
                ),
                request,
                activation,
                &origin.public_key(),
                &receiver,
            )
            .await
            .expect("activating peer fetch");

        let activation_card = receiver
            .store()
            .get_offer_card(origin.device_id, offer_id)
            .expect("read activated card")
            .expect("activated card");
        let attempt = activation_card
            .last_attempt
            .expect("activated offer attempt");
        assert_eq!(attempt.code, OfferAttemptCode::Completed);
        assert_eq!(attempt.files_processed, 1);
        assert_eq!(attempt.bytes_processed, source_bytes.len() as u64);

        let published_path = destination.join("secret.txt");
        assert_eq!(
            fs::read(&published_path).expect("read activated payload"),
            source_bytes
        );
        stop_offer_server(dormant_shutdown, dormant_server).await;
        stop_offer_server(activating_shutdown, activating_server).await;
        stop_offer_server(origin_shutdown, origin_server).await;

        assert_no_payload_artifacts(dormant_directory.path());
        assert_eq!(
            fs::read(&source_file).expect("source remains"),
            source_bytes
        );
        assert!(origin_directory.path().join("offers.redb").is_file());
    }

    #[tokio::test]
    async fn announcement_from_unpaired_peer_is_refused_before_storage() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let unpaired_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([unpaired_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "must not store",
        );
        let error = send_announcement(address, &source_identity, &target_identity, announcement)
            .await
            .expect_err("unpaired announcement");
        assert!(matches!(error, NetError::Rejected(_)));
        assert!(store.read_offer_shelf().expect("read shelf").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn announcement_with_wrong_target_device_is_refused() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            DeviceId::new(),
            OfferId::new(),
            "wrong target",
        );
        let ack =
            send_raw_announcement(address, &source_identity, &target_identity, announcement).await;
        assert_eq!(ack.code, OfferAckCode::RefusedInvalid);
        assert_eq!(ack.live_entries, 0);
        assert_eq!(ack.max_live_entries, V2_MAX_LIVE_ENTRIES);
        assert!(store.read_offer_shelf().expect("read shelf").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn announcement_with_oversized_preview_is_refused_invalid() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            source_identity.device_id,
            target_identity.device_id,
            now_unix_ms(),
            meshelf_core::OfferDescriptor::Text {
                utf8_bytes: 1,
                line_count: 1,
                preview: "x".repeat(meshelf_core::MAX_OFFER_PREVIEW_BYTES + 1),
            },
        );
        let ack =
            send_raw_announcement(address, &source_identity, &target_identity, announcement).await;
        assert_eq!(ack.code, OfferAckCode::RefusedInvalid);
        assert_eq!(ack.live_entries, 0);
        assert_eq!(ack.max_live_entries, V2_MAX_LIVE_ENTRIES);
        assert!(store.read_offer_shelf().expect("read shelf").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn identical_reannouncement_returns_duplicate_and_does_not_duplicate_the_card() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "same descriptor",
        );
        let first = send_announcement(
            address,
            &source_identity,
            &target_identity,
            announcement.clone(),
        )
        .await
        .expect("first announcement");
        let duplicate =
            send_announcement(address, &source_identity, &target_identity, announcement)
                .await
                .expect("duplicate announcement");
        assert_eq!(first.code, OfferAckCode::Stored);
        assert_eq!(duplicate.code, OfferAckCode::Duplicate);
        assert_eq!(duplicate.live_entries, 1);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn same_offer_id_with_different_descriptor_returns_conflict() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let offer_id = OfferId::new();
        let first = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            offer_id,
            "first",
        );
        let second = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            offer_id,
            "different",
        );
        assert_eq!(
            send_announcement(address, &source_identity, &target_identity, first)
                .await
                .expect("first announcement")
                .code,
            OfferAckCode::Stored
        );
        let conflict = send_announcement(address, &source_identity, &target_identity, second)
            .await
            .expect("conflicting announcement");
        assert_eq!(conflict.code, OfferAckCode::RefusedConflict);
        assert_eq!(conflict.live_entries, 1);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn eleventh_card_returns_capacity_with_ten_of_ten_counts() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        for index in 0..V2_MAX_LIVE_ENTRIES {
            let ack = send_announcement(
                address,
                &source_identity,
                &target_identity,
                text_announcement(
                    source_identity.device_id,
                    target_identity.device_id,
                    OfferId::new(),
                    &format!("card {index}"),
                ),
            )
            .await
            .expect("announcement within capacity");
            assert_eq!(ack.code, OfferAckCode::Stored);
        }
        let eleventh = send_announcement(
            address,
            &source_identity,
            &target_identity,
            text_announcement(
                source_identity.device_id,
                target_identity.device_id,
                OfferId::new(),
                "eleventh",
            ),
        )
        .await
        .expect("capacity acknowledgement");
        assert_eq!(eleventh.code, OfferAckCode::RefusedCapacity);
        assert_eq!(eleventh.live_entries, V2_MAX_LIVE_ENTRIES);
        assert_eq!(eleventh.max_live_entries, V2_MAX_LIVE_ENTRIES);
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 10);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn offline_announcement_is_reported_and_not_retried() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let target_identity = meshelf_identity::InstallationIdentity::generate();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        drop(listener);
        let started = std::time::Instant::now();
        let error = send_announcement(
            address,
            &source_identity,
            &target_identity,
            text_announcement(
                source_identity.device_id,
                target_identity.device_id,
                OfferId::new(),
                "offline",
            ),
        )
        .await
        .expect_err("offline peer");
        assert!(matches!(error, NetError::Unavailable(_) | NetError::Io(_)));
        assert!(started.elapsed() < TEST_IO_TIMEOUT);
    }

    #[tokio::test]
    async fn one_connection_cannot_announce_twice() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, target_identity, shutdown_tx, server, store) =
            start_offer_server([source_identity.device_id]).await;
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect announcement");
        stream.set_nodelay(true).expect("nodelay");
        let hello = ClientHello::signed(
            source_identity.device_id,
            "BMST",
            "single-operation",
            &source_identity,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write client hello",
        )
        .await
        .expect("write hello");
        let _ = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read server hello",
        )
        .await
        .expect("read hello");
        let announcement = text_announcement(
            source_identity.device_id,
            target_identity.device_id,
            OfferId::new(),
            "one operation",
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(
                &mut stream,
                &V2Message::OfferAnnouncement(announcement.clone()),
            ),
            "write first announcement",
        )
        .await
        .expect("write first announcement");
        let first = io_timeout(
            TEST_IO_TIMEOUT,
            read_v2_frame_async(&mut stream),
            "read first acknowledgement",
        )
        .await
        .expect("read first acknowledgement");
        assert!(matches!(first, V2Message::OfferAck(_)));

        let second_write = io_timeout(
            TEST_IO_TIMEOUT,
            write_v2_frame_async(&mut stream, &V2Message::OfferAnnouncement(announcement)),
            "write second announcement",
        )
        .await;
        if second_write.is_ok() {
            let second_read = io_timeout(
                TEST_IO_TIMEOUT,
                read_v2_frame_async(&mut stream),
                "read second acknowledgement",
            )
            .await;
            assert!(
                second_read.is_err(),
                "one connection returned two acknowledgements"
            );
        }
        assert_eq!(store.read_offer_shelf().expect("read shelf").len(), 1);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn handler_limit_refuses_excess_connections_without_unbounded_task_growth() {
        let source_identity = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, _target_identity, shutdown_tx, server, _store) =
            start_offer_server([source_identity.device_id]).await;
        let mut held = Vec::new();
        for index in 0..V2_MAX_INBOUND_HANDLERS {
            let mut stream = TcpStream::connect(address)
                .await
                .expect("connect held handler");
            stream.set_nodelay(true).expect("nodelay");
            let hello = ClientHello::signed(
                source_identity.device_id,
                "BMST",
                format!("held-{index}"),
                &source_identity,
            );
            io_timeout(
                TEST_IO_TIMEOUT,
                write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
                "write held hello",
            )
            .await
            .expect("write held hello");
            let response = io_timeout(
                TEST_IO_TIMEOUT,
                read_frame_async(&mut stream),
                "read held server hello",
            )
            .await
            .expect("read held server hello");
            let WireMessage::ServerHello(server_hello) = response else {
                panic!("expected held server hello");
            };
            assert!(server_hello.accepted);
            held.push(stream);
        }

        let mut excess = TcpStream::connect(address)
            .await
            .expect("connect excess handler");
        excess.set_nodelay(true).expect("nodelay");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut excess),
            "read capacity refusal",
        )
        .await
        .expect("read capacity refusal");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected capacity refusal server hello");
        };
        let reason = server_hello.reason.expect("capacity refusal detail");
        assert!(!server_hello.accepted);
        assert!(reason.contains("active=16"));
        assert!(reason.contains("maximum=16"));
        drop(excess);
        drop(held);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn unannounced_peer_cannot_fetch_known_offer_id() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let other = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        let descriptor = OfferDescriptor::text("known but not announced").expect("descriptor");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor,
                HashSet::from([other.device_id]),
                OfferSource::Text {
                    text: "known but not announced".to_owned(),
                },
            ))
            .expect("insert source");
        let mut stream = connect_fetch(
            address,
            &requester,
            &origin,
            FetchRequest::new(offer_id, origin.device_id, requester.device_id),
        )
        .await;
        let response = read_v2_test(&mut stream, "read refusal").await;
        let V2Message::FetchRefusal(refusal) = response else {
            panic!("expected fetch refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::NotAnnouncedToRequester);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn unpaired_peer_cannot_fetch_even_if_announced() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([]).await;
        let offer_id = OfferId::new();
        let descriptor =
            OfferDescriptor::text("announced to an unpaired peer").expect("descriptor");
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                descriptor,
                HashSet::from([requester.device_id]),
                OfferSource::Text {
                    text: "announced to an unpaired peer".to_owned(),
                },
            ))
            .expect("insert source");
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect unpaired peer");
        let hello = ClientHello::signed(
            requester.device_id,
            "BZOT",
            DeviceId::new().to_string(),
            &requester,
        );
        io_timeout(
            TEST_IO_TIMEOUT,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write unpaired hello",
        )
        .await
        .expect("write hello");
        let response = io_timeout(
            TEST_IO_TIMEOUT,
            read_frame_async(&mut stream),
            "read unpaired hello",
        )
        .await
        .expect("read hello");
        let WireMessage::ServerHello(server_hello) = response else {
            panic!("expected server hello");
        };
        assert!(!server_hello.accepted);
        assert!(
            store
                .get_offer_source(offer_id)
                .expect("read source")
                .is_some()
        );
        assert_eq!(origin.device_id, server_hello.device_id);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn wrong_source_device_in_request_is_refused() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        insert_text_source(&store, requester.device_id, offer_id, "wrong source");
        let mut stream = connect_fetch(
            address,
            &requester,
            &origin,
            FetchRequest::new(offer_id, DeviceId::new(), requester.device_id),
        )
        .await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::Malformed);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn unknown_offer_id_is_refused_without_touching_the_source() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let unknown = OfferId::new();
        let mut stream = connect_fetch(
            address,
            &requester,
            &origin,
            FetchRequest::new(unknown, origin.device_id, requester.device_id),
        )
        .await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::UnknownOffer);
        assert!(store.read_offer_sources().expect("read sources").is_empty());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn text_fetch_serves_the_stored_body_exactly() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let body = "stored text\nwith unicode: β🙂";
        let offer_id = OfferId::new();
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (header, entries, chunks) = read_fetch_header_and_manifest(&mut stream).await;
        assert_eq!(header.manifest_entries, 0);
        assert_eq!(entries.len(), 0);
        assert_eq!(chunks, 0);
        assert_eq!(
            header.text_sha256,
            Some(Sha256::digest(body.as_bytes()).to_vec())
        );
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read text body").await;
        assert_eq!(received, body.as_bytes());
        assert!(matches!(
            read_v2_test(&mut stream, "read text end").await,
            V2Message::TextEnd(_)
        ));
        assert!(matches!(
            read_v2_test(&mut stream, "read fetch complete").await,
            V2Message::FetchComplete(_)
        ));
        write_fetch_receipt(&mut stream, request_id, offer_id).await;
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn origin_waits_for_and_validates_fetch_receipt() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let directory = tempfile::tempdir().expect("temporary fetch directory");
        let store = Arc::new(
            RedbV2Store::open(directory.path().join("offers.redb")).expect("open offer store"),
        );
        let origin = meshelf_identity::InstallationIdentity::generate();
        let body = "receipt-gated text";
        let offer_id = OfferId::new();
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let sender = Arc::new(OfferFetchHandler::new(origin.device_id, store));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fetch");
            sender
                .handle_fetch(requester.device_id, request, &mut stream, TEST_IO_TIMEOUT)
                .await
        });
        let mut stream = TcpStream::connect(address).await.expect("connect fetch");
        let _ = read_fetch_header_and_manifest(&mut stream).await;
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read text body").await;
        assert_eq!(received, body.as_bytes());
        let _ = read_v2_test(&mut stream, "read text end").await;
        let _ = read_v2_test(&mut stream, "read fetch complete").await;

        let mut probe = [0_u8; 1];
        assert!(
            timeout(TEST_IO_TIMEOUT / 10, stream.read(&mut probe))
                .await
                .is_err(),
            "origin returned before the receiver supplied a receipt"
        );
        write_v2_frame_async(
            &mut stream,
            &V2Message::FetchReceipt(FetchReceipt {
                request_id: ActivationId::new(),
                offer_id,
                code: meshelf_protocol::FetchReceiptCode::Completed,
                files_received: 0,
                bytes_received: body.len() as u64,
                detail: None,
            }),
        )
        .await
        .expect("write mismatched receipt");
        assert_eq!(
            timeout(TEST_IO_TIMEOUT, stream.read(&mut probe))
                .await
                .expect("read close timeout")
                .expect("read close"),
            0
        );
        let result = server.await.expect("sender task");
        assert!(matches!(result, Err(NetError::IdentityMismatch(_))));
    }

    #[tokio::test]
    async fn text_fetch_cannot_return_source_changed() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        let body = "text is durable";
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (header, _, _) = read_fetch_header_and_manifest(&mut stream).await;
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read text body").await;
        assert_eq!(received, body.as_bytes());
        assert_eq!(header.manifest_entries, 0);
        let response = read_v2_test(&mut stream, "read text end").await;
        assert!(!matches!(
            response,
            V2Message::FetchRefusal(FetchRefusal {
                code: FetchRefusalCode::SourceChanged,
                ..
            })
        ));
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn deleted_file_source_returns_source_unavailable_and_sends_no_payload() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let path = source_directory.path().join("deleted.txt");
        fs::write(&path, b"body").expect("write source");
        let offer_id = OfferId::new();
        insert_file_source(&store, requester.device_id, offer_id, &path);
        fs::remove_file(&path).expect("delete source");
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected source refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::SourceUnavailable);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn modified_file_source_returns_source_changed_and_sends_no_payload() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let path = source_directory.path().join("modified.txt");
        fs::write(&path, b"body").expect("write source");
        let offer_id = OfferId::new();
        insert_file_source(&store, requester.device_id, offer_id, &path);
        fs::write(&path, b"changed body").expect("modify source");
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut stream, "read refusal").await
        else {
            panic!("expected source refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::SourceChanged);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn folder_manifest_is_chunked_within_the_control_frame() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let root = source_directory.path().join("many-files");
        fs::create_dir(&root).expect("create root");
        for index in 0..1500 {
            fs::write(root.join(format!("file-{index:04}.txt")), []).expect("write file");
        }
        let offer_id = OfferId::new();
        insert_folder_source(&store, requester.device_id, offer_id, &root);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (header, entries, chunk_count) = read_fetch_header_and_manifest(&mut stream).await;
        assert_eq!(header.manifest_entries, 1500);
        assert_eq!(entries.len(), 1500);
        assert!(chunk_count > 1);
        assert!(header.manifest_encoded_bytes <= V2_MAX_MANIFEST_BYTES as u64);
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn manifest_contains_no_sender_absolute_path() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let root = source_directory.path().join("folder");
        fs::create_dir(&root).expect("create root");
        fs::write(root.join("item.txt"), b"body").expect("write file");
        let offer_id = OfferId::new();
        insert_folder_source(&store, requester.device_id, offer_id, &root);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let (_, entries, _) = read_fetch_header_and_manifest(&mut stream).await;
        let encoded = serde_json::to_string(&entries).expect("encode manifest");
        assert!(!encoded.contains(source_directory.path().to_str().expect("temp path")));
        assert!(
            entries
                .iter()
                .all(|entry| !Path::new(&entry.relative_path).is_absolute())
        );
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn two_peers_can_fetch_the_same_offer_concurrently() {
        let first = meshelf_identity::InstallationIdentity::generate();
        let second = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([first.device_id, second.device_id]).await;
        let offer_id = OfferId::new();
        let body = "same offer twice";
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                OfferDescriptor::text(body).expect("descriptor"),
                HashSet::from([first.device_id, second.device_id]),
                OfferSource::Text {
                    text: body.to_owned(),
                },
            ))
            .expect("insert source");
        let request_one = FetchRequest::new(offer_id, origin.device_id, first.device_id);
        let request_two = FetchRequest::new(offer_id, origin.device_id, second.device_id);
        let request_one_id = request_one.request_id;
        let request_two_id = request_two.request_id;
        let mut stream_one = connect_fetch(address, &first, &origin, request_one).await;
        let mut stream_two = connect_fetch(address, &second, &origin, request_two).await;
        let (_, _, _) = read_fetch_header_and_manifest(&mut stream_one).await;
        let (_, _, _) = read_fetch_header_and_manifest(&mut stream_two).await;
        admit_fetch(&mut stream_one, request_one_id).await;
        admit_fetch(&mut stream_two, request_two_id).await;
        let mut one = vec![0_u8; body.len()];
        let mut two = vec![0_u8; body.len()];
        read_exact_test(&mut stream_one, &mut one, "read first body").await;
        read_exact_test(&mut stream_two, &mut two, "read second body").await;
        assert_eq!(one, body.as_bytes());
        assert_eq!(two, body.as_bytes());
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn third_concurrent_fetch_is_refused_busy_with_two_of_two_and_no_queue() {
        let first = meshelf_identity::InstallationIdentity::generate();
        let second = meshelf_identity::InstallationIdentity::generate();
        let third = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([first.device_id, second.device_id, third.device_id]).await;
        let offer_id = OfferId::new();
        let body = "held until admission";
        store
            .insert_offer_source(OfferSourceInput::new(
                offer_id,
                OfferDescriptor::text(body).expect("descriptor"),
                HashSet::from([first.device_id, second.device_id, third.device_id]),
                OfferSource::Text {
                    text: body.to_owned(),
                },
            ))
            .expect("insert source");
        let request_one = FetchRequest::new(offer_id, origin.device_id, first.device_id);
        let request_two = FetchRequest::new(offer_id, origin.device_id, second.device_id);
        let mut one = connect_fetch(address, &first, &origin, request_one).await;
        let mut two = connect_fetch(address, &second, &origin, request_two).await;
        let _ = read_fetch_header_and_manifest(&mut one).await;
        let _ = read_fetch_header_and_manifest(&mut two).await;
        let request_three = FetchRequest::new(offer_id, origin.device_id, third.device_id);
        let mut three = connect_fetch(address, &third, &origin, request_three).await;
        let V2Message::FetchRefusal(refusal) = read_v2_test(&mut three, "read busy refusal").await
        else {
            panic!("expected busy refusal");
        };
        assert_eq!(refusal.code, FetchRefusalCode::Busy);
        assert_eq!((refusal.active_streams, refusal.max_active_streams), (2, 2));
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn successful_fetch_does_not_consume_the_offer() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let offer_id = OfferId::new();
        let body = "still available";
        insert_text_source(&store, requester.device_id, offer_id, body);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let _ = read_fetch_header_and_manifest(&mut stream).await;
        admit_fetch(&mut stream, request_id).await;
        let mut received = vec![0_u8; body.len()];
        read_exact_test(&mut stream, &mut received, "read body").await;
        assert!(
            store
                .get_offer_source(offer_id)
                .expect("read source")
                .is_some()
        );
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn source_change_mid_transfer_aborts_and_sends_no_further_bytes() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let root = source_directory.path().join("changing-folder");
        fs::create_dir(&root).expect("create root");
        fs::write(root.join("one.txt"), b"one").expect("write first file");
        fs::write(root.join("two.txt"), b"two").expect("write second file");
        let offer_id = OfferId::new();
        insert_folder_source(&store, requester.device_id, offer_id, &root);
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let request_id = request.request_id;
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let _ = read_fetch_header_and_manifest(&mut stream).await;
        fs::write(root.join("two.txt"), b"changed after manifest").expect("change source");
        admit_fetch(&mut stream, request_id).await;
        let response = read_v2_test(&mut stream, "read abort").await;
        let V2Message::FetchAbort(abort) = response else {
            panic!("expected fetch abort");
        };
        assert_eq!(abort.code, FetchAbortCode::SourceChanged);
        assert_eq!(abort.files_sent, 0);
        assert_eq!(abort.bytes_sent, 0);
        write_fetch_receipt(&mut stream, request_id, offer_id).await;
        stop_offer_server(shutdown_tx, server).await;
    }

    #[tokio::test]
    async fn refusal_never_contains_an_absolute_source_path() {
        let requester = meshelf_identity::InstallationIdentity::generate();
        let (_directory, address, origin, shutdown_tx, server, store) =
            start_fetch_server([requester.device_id]).await;
        let source_directory = tempfile::tempdir().expect("source directory");
        let path = source_directory.path().join("private.txt");
        fs::write(&path, b"body").expect("write source");
        let offer_id = OfferId::new();
        insert_file_source(&store, requester.device_id, offer_id, &path);
        fs::write(&path, b"changed").expect("change source");
        let request = FetchRequest::new(offer_id, origin.device_id, requester.device_id);
        let mut stream = connect_fetch(address, &requester, &origin, request).await;
        let response = read_v2_test(&mut stream, "read refusal").await;
        let V2Message::FetchRefusal(refusal) = response else {
            panic!("expected refusal");
        };
        let encoded = serde_json::to_string(&refusal).expect("encode refusal");
        assert!(!encoded.contains(source_directory.path().to_str().expect("temp path")));
        assert!(refusal.detail.is_none());
        stop_offer_server(shutdown_tx, server).await;
    }
}

impl ServerIdentity {
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.signing_identity.device_id
    }

    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_identity.public_key().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    Allow,
    Deny(String),
}

pub trait TrustGate: Send + Sync + 'static {
    fn authorize(&self, remote: SocketAddr, hello: &ClientHello) -> TrustDecision;
}

#[derive(Debug, Default)]
pub struct DenyAll;

impl TrustGate for DenyAll {
    fn authorize(&self, _remote: SocketAddr, _hello: &ClientHello) -> TrustDecision {
        TrustDecision::Deny("secure pairing is not configured".to_owned())
    }
}

#[derive(Debug, Clone)]
pub struct ExactDeviceAllowList {
    allowed: HashSet<DeviceId>,
}

impl ExactDeviceAllowList {
    #[must_use]
    pub fn new(allowed: impl IntoIterator<Item = DeviceId>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }
}

impl TrustGate for ExactDeviceAllowList {
    fn authorize(&self, _remote: SocketAddr, hello: &ClientHello) -> TrustDecision {
        if self.allowed.contains(&hello.device_id) {
            TrustDecision::Allow
        } else {
            TrustDecision::Deny("claimed device ID is not in the development allowlist".to_owned())
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TailnetPeerAllowList {
    allowed: Arc<RwLock<HashMap<DeviceId, HashSet<IpAddr>>>>,
}

impl TailnetPeerAllowList {
    #[must_use]
    pub fn new(
        peers: impl IntoIterator<Item = (DeviceId, impl IntoIterator<Item = IpAddr>)>,
    ) -> Self {
        Self {
            allowed: Arc::new(RwLock::new(
                peers
                    .into_iter()
                    .map(|(id, addresses)| (id, addresses.into_iter().collect()))
                    .collect(),
            )),
        }
    }
}

impl TrustGate for TailnetPeerAllowList {
    fn authorize(&self, remote: SocketAddr, hello: &ClientHello) -> TrustDecision {
        let Ok(allowed) = self.allowed.read() else {
            return TrustDecision::Deny("tailnet peer registry is unavailable".to_owned());
        };
        match allowed.get(&hello.device_id) {
            Some(addresses) if addresses.contains(&remote.ip()) => TrustDecision::Allow,
            Some(_) => TrustDecision::Deny(
                "accepted meshelf identity arrived from an unrecognized Tailscale address"
                    .to_owned(),
            ),
            None => TrustDecision::Deny("meshelf device has not been accepted".to_owned()),
        }
    }
}

pub trait OfferCardStore: Send + Sync + 'static {
    fn get_offer_card(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
    ) -> Result<Option<OfferCardRecord>, StoreError>;
    fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError>;
    fn insert_offer_card(&self, input: OfferCardInput) -> Result<OfferCardInsert, StoreError>;
}

impl OfferCardStore for RedbV2Store {
    fn get_offer_card(
        &self,
        source_device: DeviceId,
        offer_id: OfferId,
    ) -> Result<Option<OfferCardRecord>, StoreError> {
        RedbV2Store::get_offer_card(self, source_device, offer_id)
    }
    fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError> {
        RedbV2Store::read_offer_shelf(self)
    }
    fn insert_offer_card(&self, input: OfferCardInput) -> Result<OfferCardInsert, StoreError> {
        RedbV2Store::insert_offer_card(self, input)
    }
}

pub struct OfferAnnouncementHandler {
    store: Arc<dyn OfferCardStore>,
    mutation_lock: std::sync::Mutex<()>,
}

impl OfferAnnouncementHandler {
    #[must_use]
    pub fn new(store: Arc<dyn OfferCardStore>) -> Self {
        Self {
            store,
            mutation_lock: std::sync::Mutex::new(()),
        }
    }

    fn live_count(&self) -> Result<u32, NetError> {
        u32::try_from(
            self.store
                .read_offer_shelf()
                .map_err(|error| NetError::OfferStorage(error.to_string()))?
                .len(),
        )
        .map_err(|_| NetError::OfferStorage("offer card count exceeds u32".to_owned()))
    }

    fn ack(
        offer_id: OfferId,
        code: OfferAckCode,
        live_entries: u32,
        pruned_entries: u32,
        detail: Option<String>,
    ) -> OfferAck {
        OfferAck {
            offer_id,
            code,
            live_entries,
            max_live_entries: V2_MAX_LIVE_ENTRIES,
            pruned_entries,
            detail,
        }
    }

    pub fn handle_sync(
        &self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError> {
        let offer_id = announcement.offer_id;
        let live_entries = self.live_count()?;
        if announcement.source_device != authenticated_source {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedInvalid,
                live_entries,
                0,
                Some("source device does not match authenticated client".to_owned()),
            ));
        }
        if announcement.target_device != listener_device {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedInvalid,
                live_entries,
                0,
                Some("target device does not match listener".to_owned()),
            ));
        }
        if let Err(error) = announcement.validate() {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedInvalid,
                live_entries,
                0,
                Some(format!("invalid offer announcement: {error}")),
            ));
        }
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| NetError::OfferStorage("offer card lock is poisoned".to_owned()))?;
        let live_entries = self.live_count()?;
        if let Some(existing) = self
            .store
            .get_offer_card(authenticated_source, offer_id)
            .map_err(|error| NetError::OfferStorage(error.to_string()))?
        {
            let (code, detail) = if existing.descriptor == announcement.descriptor {
                (OfferAckCode::Duplicate, None)
            } else {
                (
                    OfferAckCode::RefusedConflict,
                    Some("offer ID is already stored with a different descriptor".to_owned()),
                )
            };
            return Ok(Self::ack(offer_id, code, live_entries, 0, detail));
        }
        if live_entries >= V2_MAX_LIVE_ENTRIES {
            return Ok(Self::ack(
                offer_id,
                OfferAckCode::RefusedCapacity,
                live_entries,
                0,
                Some("receiver offer-card capacity is full".to_owned()),
            ));
        }
        let inserted = self
            .store
            .insert_offer_card(OfferCardInput::new(
                authenticated_source,
                offer_id,
                announcement.descriptor,
                CardAvailability::Available,
            ))
            .map_err(|error| NetError::OfferStorage(error.to_string()))?;
        let code = if inserted.inserted {
            OfferAckCode::Stored
        } else {
            OfferAckCode::Duplicate
        };
        Ok(Self::ack(
            offer_id,
            code,
            self.live_count()?,
            inserted.purged,
            None,
        ))
    }
}

#[async_trait]
pub trait V2AnnouncementReceiver: Send + Sync + 'static {
    async fn handle_announcement(
        &self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError>;
}

#[async_trait]
impl V2AnnouncementReceiver for OfferAnnouncementHandler {
    async fn handle_announcement(
        &self,
        authenticated_source: DeviceId,
        listener_device: DeviceId,
        announcement: OfferAnnouncement,
    ) -> Result<OfferAck, NetError> {
        self.handle_sync(authenticated_source, listener_device, announcement)
    }
}

#[derive(Debug, Clone)]
pub struct PeerClient {
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl Default for PeerClient {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
        }
    }
}

impl PeerClient {
    #[must_use]
    pub const fn with_timeouts(connect_timeout: Duration, io_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            io_timeout,
        }
    }

    pub async fn probe(&self, address: SocketAddr) -> Result<ServerHello, NetError> {
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| NetError::Timeout("probe connect"))??;
        let probe_device = DeviceId::new();
        let hello = ClientHello::v2(probe_device, "meshelf-discovery", probe_device.to_string());
        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write probe hello",
        )
        .await?;
        match io_timeout(
            self.io_timeout,
            read_frame_async(&mut stream),
            "read probe response",
        )
        .await?
        {
            WireMessage::ServerHello(server) => Ok(server),
            WireMessage::ClientHello(_) => {
                Err(NetError::UnexpectedMessage("expected server_hello"))
            }
        }
    }

    pub async fn announce_offer_v2(
        &self,
        address: SocketAddr,
        hello: ClientHello,
        announcement: OfferAnnouncement,
        expected_server_public_key: &[u8],
    ) -> Result<OfferAck, NetError> {
        announcement.validate()?;
        if hello.device_id != announcement.source_device {
            return Err(NetError::IdentityMismatch(
                "client hello and offer announcement source differ".to_owned(),
            ));
        }
        require_v2_client_hello(&hello, "v2 announcement")?;
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| NetError::Unavailable("announce connect timed out".to_owned()))??;
        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write v2 announce client hello",
        )
        .await?;
        let server = read_server_hello(
            &mut stream,
            self.io_timeout,
            expected_server_public_key,
            announcement.target_device,
            "announcement",
        )
        .await?;
        require_v2_server_hello(&server, true, "announcement")?;
        io_timeout(
            self.io_timeout,
            write_v2_frame_async(
                &mut stream,
                &V2Message::OfferAnnouncement(announcement.clone()),
            ),
            "write v2 offer announcement",
        )
        .await?;
        let response = io_timeout(
            self.io_timeout,
            read_v2_frame_async(&mut stream),
            "read offer acknowledgement",
        )
        .await?;
        validate_v2_message(&response)?;
        let V2Message::OfferAck(ack) = response else {
            return Err(NetError::UnexpectedMessage("expected offer_ack"));
        };
        if ack.offer_id != announcement.offer_id {
            return Err(NetError::IdentityMismatch(
                "offer acknowledgement ID does not match announcement".to_owned(),
            ));
        }
        Ok(ack)
    }

    pub async fn fetch_v2<C>(
        &self,
        address: SocketAddr,
        hello: ClientHello,
        request: meshelf_protocol::FetchRequest,
        activation: FetchActivation,
        expected_server_public_key: &[u8],
        receiver: &FetchReceiver<C>,
    ) -> Result<(), NetError>
    where
        C: FetchClipboard,
    {
        if hello.device_id != request.requester_device
            || activation.request_id != request.request_id
            || activation.source_device != request.source_device
            || activation.offer_id != request.offer_id
        {
            return Err(NetError::IdentityMismatch(
                "fetch request, activation, and client identity differ".to_owned(),
            ));
        }
        require_v2_client_hello(&hello, "v2 fetch")?;
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| NetError::Timeout("fetch v2 connect"))??;
        io_timeout(
            self.io_timeout,
            write_frame_async(&mut stream, &WireMessage::ClientHello(hello)),
            "write v2 fetch client hello",
        )
        .await?;
        let server = read_server_hello(
            &mut stream,
            self.io_timeout,
            expected_server_public_key,
            request.source_device,
            "fetch",
        )
        .await?;
        require_v2_server_hello(&server, true, "fetch")?;
        io_timeout(
            self.io_timeout,
            write_v2_frame_async(&mut stream, &V2Message::FetchRequest(request)),
            "write v2 fetch request",
        )
        .await?;
        receiver
            .receive(server.device_id, activation, &mut stream, self.io_timeout)
            .await
    }
}

fn require_v2_client_hello(hello: &ClientHello, operation: &str) -> Result<(), NetError> {
    if hello.protocol_version != V2_PROTOCOL_VERSION
        || !hello
            .capabilities
            .iter()
            .any(|capability| capability == CAP_OFFER_PULL_V2)
    {
        return Err(NetError::Rejected(format!(
            "{operation} requires protocol 2 and offer-pull-v2"
        )));
    }
    Ok(())
}

async fn read_server_hello(
    stream: &mut TcpStream,
    io_timeout_duration: Duration,
    expected_key: &[u8],
    expected_device: DeviceId,
    operation: &'static str,
) -> Result<ServerHello, NetError> {
    let response = io_timeout(
        io_timeout_duration,
        read_frame_async(stream),
        "read server hello",
    )
    .await?;
    let WireMessage::ServerHello(server) = response else {
        return Err(NetError::UnexpectedMessage("expected server_hello"));
    };
    if !server.has_valid_signature()
        || (!expected_key.is_empty() && server.public_key != expected_key)
    {
        return Err(NetError::IdentityMismatch(format!(
            "{operation} server hello signature or public key is invalid"
        )));
    }
    if server.device_id != expected_device {
        return Err(NetError::IdentityMismatch(format!(
            "{operation} server hello device does not match request"
        )));
    }
    Ok(server)
}

fn require_v2_server_hello(
    server: &ServerHello,
    require_accepted: bool,
    operation: &str,
) -> Result<(), NetError> {
    if server.protocol_version != V2_PROTOCOL_VERSION {
        return Err(NetError::Rejected(format!(
            "{operation} server uses an unsupported protocol version"
        )));
    }
    if !server
        .capabilities
        .iter()
        .any(|capability| capability == CAP_OFFER_PULL_V2)
    {
        return Err(NetError::Rejected(format!(
            "{operation} server does not advertise offer-pull-v2"
        )));
    }
    if require_accepted && !server.accepted {
        return Err(NetError::Rejected(server.reason.clone().unwrap_or_else(
            || format!("{operation} server rejected connection"),
        )));
    }
    Ok(())
}

pub struct V2OfferServices {
    pub announcement_receiver: Arc<dyn V2AnnouncementReceiver>,
    pub fetch_sender: Arc<dyn V2FetchSender>,
}

pub async fn serve_v2_with_offers_and_fetch<G>(
    listener: TcpListener,
    identity: ServerIdentity,
    gate: Arc<G>,
    services: V2OfferServices,
    io_timeout_duration: Duration,
    shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
{
    serve_inner(
        listener,
        ServerContext {
            identity,
            gate,
            services,
            io_timeout_duration,
        },
        shutdown,
    )
    .await
}

struct ServerContext<G> {
    identity: ServerIdentity,
    gate: Arc<G>,
    services: V2OfferServices,
    io_timeout_duration: Duration,
}

impl<G> Clone for ServerContext<G>
where
    G: TrustGate,
{
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            gate: self.gate.clone(),
            services: V2OfferServices {
                announcement_receiver: self.services.announcement_receiver.clone(),
                fetch_sender: self.services.fetch_sender.clone(),
            },
            io_timeout_duration: self.io_timeout_duration,
        }
    }
}

async fn serve_inner<G>(
    listener: TcpListener,
    context: ServerContext<G>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), NetError>
where
    G: TrustGate,
{
    let handler_limit = Arc::new(Semaphore::new(
        usize::try_from(V2_MAX_INBOUND_HANDLERS).expect("handler limit fits usize"),
    ));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed { Ok(()) if *shutdown.borrow() => return Ok(()), Ok(()) => continue, Err(_) => return Ok(()) }
            }
            accepted = listener.accept() => {
                let (stream, remote) = accepted?;
                let permit = match handler_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(TryAcquireError::NoPermits) => { refuse_excess_connection(stream, context.identity.clone(), context.io_timeout_duration).await?; continue; }
                    Err(TryAcquireError::Closed) => return Err(NetError::HandlerLimitClosed),
                };
                let context = context.clone();
                tokio::spawn(async move { let _permit = permit; if let Err(error) = handle_v2_connection(stream, remote, context).await { tracing::warn!(%remote, error = %error, "meshelf peer connection failed"); } });
            }
        }
    }
}

async fn refuse_excess_connection(
    mut stream: TcpStream,
    identity: ServerIdentity,
    io_timeout_duration: Duration,
) -> Result<(), NetError> {
    let device_id = identity.device_id();
    let hello = WireMessage::ServerHello(ServerHello::signed(
        V2_PROTOCOL_VERSION,
        device_id,
        identity.device_name.clone(),
        false,
        Some(format!(
            "inbound handler capacity exhausted: active={V2_MAX_INBOUND_HANDLERS}, maximum={V2_MAX_INBOUND_HANDLERS}; update peer {device_id} to meshelf protocol 2"
        )),
        vec![CAP_OFFER_PULL_V2.to_owned()],
        &identity.signing_identity,
    ));
    io_timeout(
        io_timeout_duration,
        write_frame_async(&mut stream, &hello),
        "write handler-capacity refusal",
    )
    .await
}

async fn handle_v2_connection<G>(
    mut stream: TcpStream,
    remote: SocketAddr,
    context: ServerContext<G>,
) -> Result<(), NetError>
where
    G: TrustGate,
{
    let hello = io_timeout(
        context.io_timeout_duration,
        read_client_hello_async(&mut stream),
        "read v2 client hello",
    )
    .await?;
    if hello.protocol_version != V2_PROTOCOL_VERSION {
        let reason = format!(
            "Peer {} ({}) uses protocol version {}; update it to meshelf protocol 2",
            hello.device_name, hello.device_id, hello.protocol_version
        );
        let refusal = WireMessage::ServerHello(ServerHello::signed(
            V2_PROTOCOL_VERSION,
            context.identity.device_id(),
            context.identity.device_name.clone(),
            false,
            Some(reason),
            vec![CAP_OFFER_PULL_V2.to_owned()],
            &context.identity.signing_identity,
        ));
        io_timeout(
            context.io_timeout_duration,
            write_frame_async(&mut stream, &refusal),
            "write v1 refusal",
        )
        .await?;
        stream.shutdown().await?;
        return Ok(());
    }
    let trust = if !hello.has_valid_signature() {
        TrustDecision::Deny("client hello signature is invalid".to_owned())
    } else if !hello
        .capabilities
        .iter()
        .any(|capability| capability == CAP_OFFER_PULL_V2)
    {
        TrustDecision::Deny("client hello does not advertise offer-pull-v2".to_owned())
    } else {
        context.gate.authorize(remote, &hello)
    };
    let (accepted, reason) = match trust {
        TrustDecision::Allow => (true, None),
        TrustDecision::Deny(reason) => (false, Some(reason)),
    };
    let server_hello = WireMessage::ServerHello(ServerHello::signed(
        V2_PROTOCOL_VERSION,
        context.identity.device_id(),
        context.identity.device_name.clone(),
        accepted,
        reason,
        vec![CAP_OFFER_PULL_V2.to_owned()],
        &context.identity.signing_identity,
    ));
    io_timeout(
        context.io_timeout_duration,
        write_frame_async(&mut stream, &server_hello),
        "write v2 server hello",
    )
    .await?;
    if !accepted {
        stream.shutdown().await?;
        return Ok(());
    }
    let message = io_timeout(
        context.io_timeout_duration,
        read_v2_frame_async(&mut stream),
        "read v2 operation",
    )
    .await?;
    match message {
        V2Message::OfferAnnouncement(announcement) => {
            let ack = context
                .services
                .announcement_receiver
                .handle_announcement(hello.device_id, context.identity.device_id(), announcement)
                .await?;
            io_timeout(
                context.io_timeout_duration,
                write_v2_frame_async(&mut stream, &V2Message::OfferAck(ack)),
                "write v2 offer acknowledgement",
            )
            .await?;
        }
        V2Message::FetchRequest(request) => {
            validate_v2_message(&V2Message::FetchRequest(request.clone()))?;
            context
                .services
                .fetch_sender
                .handle_fetch(
                    hello.device_id,
                    request,
                    &mut stream,
                    context.io_timeout_duration,
                )
                .await?
        }
        _ => {
            return Err(NetError::UnexpectedMessage(
                "unsupported v2 operation; announcement and fetch request are enabled",
            ));
        }
    }
    Ok(())
}

pub async fn bind_discovered_tailscale_address(
    address: SocketAddr,
    discovered_local_addresses: &[IpAddr],
) -> Result<TcpListener, NetError> {
    Ok(TcpListener::from_std(
        bind_discovered_tailscale_std_listener(address, discovered_local_addresses)?,
    )?)
}

pub fn bind_discovered_tailscale_std_listener(
    address: SocketAddr,
    discovered_local_addresses: &[IpAddr],
) -> Result<StdTcpListener, NetError> {
    if address.ip().is_unspecified() {
        return Err(NetError::UnsafeBind(
            "unspecified listener addresses are forbidden".to_owned(),
        ));
    }
    if !discovered_local_addresses.contains(&address.ip()) {
        return Err(NetError::UnsafeBind(
            "listener address is not one of the currently discovered local Tailscale addresses"
                .to_owned(),
        ));
    }
    let listener = StdTcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

async fn io_timeout<T>(
    duration: Duration,
    future: impl Future<Output = Result<T, ProtocolError>>,
    operation: &'static str,
) -> Result<T, NetError> {
    timeout(duration, future)
        .await
        .map_err(|_| NetError::Timeout(operation))?
        .map_err(NetError::Protocol)
}

#[derive(Debug, Error)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("operation timed out during {0}")]
    Timeout(&'static str),
    #[error("peer rejected connection: {0}")]
    Rejected(String),
    #[error("peer unavailable: {0}")]
    Unavailable(String),
    #[error("unexpected wire message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("identity mismatch: {0}")]
    IdentityMismatch(String),
    #[error("unsafe bind refused: {0}")]
    UnsafeBind(String),
    #[error("file transfer failed: {0}")]
    FileTransfer(String),
    #[error("offer card storage failed: {0}")]
    OfferStorage(String),
    #[error("fetch service failed: {0}")]
    FetchService(&'static str),
    #[error("fetch service failed: {0}")]
    FetchServiceOwned(String),
    #[error("inbound handler limit was closed")]
    HandlerLimitClosed,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use meshelf_core::OfferDescriptor;
    use meshelf_core::{ActivationMode, ClipboardError, ClipboardSink};
    use meshelf_protocol::FetchRequest;
    use tempfile::tempdir;

    #[derive(Debug, Default)]
    struct TestClipboard;

    impl ClipboardSink for TestClipboard {
        fn set_text(&self, _text: &str) -> Result<(), ClipboardError> {
            Ok(())
        }
    }

    impl FetchClipboard for TestClipboard {
        fn set_files(&self, _paths: &[PathBuf]) -> Result<(), ClipboardError> {
            Ok(())
        }
    }

    fn v1_hello(identity: &InstallationIdentity, name: &str) -> ClientHello {
        ClientHello {
            protocol_version: 1,
            device_id: identity.device_id,
            device_name: name.to_owned(),
            nonce: "legacy".to_owned(),
            capabilities: vec!["text-shelf-v1".to_owned()],
            public_key: identity.public_key().to_vec(),
            signature: identity.sign(&[]),
        }
    }

    async fn start_test_server(
        server_identity: InstallationIdentity,
        card_store: Arc<RedbV2Store>,
        source_store: Arc<RedbV2Store>,
        allowed: DeviceId,
    ) -> (
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), NetError>>,
    ) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_v2_with_offers_and_fetch(
            listener,
            ServerIdentity {
                signing_identity: server_identity,
                device_name: "server".to_owned(),
            },
            Arc::new(ExactDeviceAllowList::new([allowed])),
            V2OfferServices {
                announcement_receiver: Arc::new(OfferAnnouncementHandler::new(card_store)),
                fetch_sender: Arc::new(OfferFetchHandler::new(allowed, source_store)),
            },
            Duration::from_secs(1),
            shutdown_rx,
        ));
        (address, shutdown, server)
    }

    #[test]
    fn production_hello_advertises_only_offer_pull_v2() {
        let identity = InstallationIdentity::generate();
        let hello = ClientHello::new(identity.device_id, "BMST", "nonce");
        assert_eq!(hello.protocol_version, V2_PROTOCOL_VERSION);
        assert_eq!(hello.capabilities, vec![CAP_OFFER_PULL_V2]);
    }

    #[tokio::test]
    async fn production_listener_refuses_v1_before_reading_a_second_frame() {
        let peer = InstallationIdentity::generate();
        let server_identity = InstallationIdentity::generate();
        let directory = tempdir().expect("tempdir");
        let store =
            Arc::new(RedbV2Store::open(directory.path().join("cards.redb")).expect("store"));
        let source =
            Arc::new(RedbV2Store::open(directory.path().join("source.redb")).expect("source"));
        let (address, shutdown, server) = start_test_server(
            server_identity.clone(),
            store.clone(),
            source,
            peer.device_id,
        )
        .await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        write_frame_async(
            &mut stream,
            &WireMessage::ClientHello(v1_hello(&peer, "BZOT")),
        )
        .await
        .expect("hello");
        let response = read_frame_async(&mut stream).await.expect("refusal");
        let WireMessage::ServerHello(response) = response else {
            panic!("server hello")
        };
        assert!(!response.accepted);
        assert_eq!(response.protocol_version, V2_PROTOCOL_VERSION);
        assert_eq!(response.capabilities, vec![CAP_OFFER_PULL_V2]);
        let announcement = V2Message::OfferAnnouncement(OfferAnnouncement::new(
            OfferId::new(),
            peer.device_id,
            server_identity.device_id,
            1,
            OfferDescriptor::text("payload").expect("descriptor"),
        ));
        let _ = write_v2_frame_async(&mut stream, &announcement).await;
        let _ = shutdown.send(true);
        server.await.expect("server join").expect("server result");
        assert!(store.read_offer_shelf().expect("shelf").is_empty());
    }

    #[tokio::test]
    async fn v1_refusal_reason_names_the_peer_and_says_to_update() {
        let peer = InstallationIdentity::generate();
        let server_identity = InstallationIdentity::generate();
        let directory = tempdir().expect("tempdir");
        let cards =
            Arc::new(RedbV2Store::open(directory.path().join("cards.redb")).expect("cards"));
        let source =
            Arc::new(RedbV2Store::open(directory.path().join("source.redb")).expect("source"));
        let (address, shutdown, server) =
            start_test_server(server_identity.clone(), cards, source, peer.device_id).await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        write_frame_async(
            &mut stream,
            &WireMessage::ClientHello(v1_hello(&peer, "old-peer")),
        )
        .await
        .expect("hello");
        let WireMessage::ServerHello(response) =
            read_frame_async(&mut stream).await.expect("response")
        else {
            panic!("server hello")
        };
        let reason = response.reason.expect("refusal reason");
        assert!(reason.contains("old-peer"));
        assert!(reason.contains("update"));
        let _ = shutdown.send(true);
        server.await.expect("server join").expect("server result");
    }

    #[tokio::test]
    async fn v1_peer_cannot_deliver_any_payload_byte_to_a_v2_listener() {
        let peer = InstallationIdentity::generate();
        let server_identity = InstallationIdentity::generate();
        let directory = tempdir().expect("tempdir");
        let cards =
            Arc::new(RedbV2Store::open(directory.path().join("cards.redb")).expect("cards"));
        let source =
            Arc::new(RedbV2Store::open(directory.path().join("source.redb")).expect("source"));
        let (address, shutdown, server) = start_test_server(
            server_identity.clone(),
            cards.clone(),
            source,
            peer.device_id,
        )
        .await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        write_frame_async(
            &mut stream,
            &WireMessage::ClientHello(v1_hello(&peer, "old-peer")),
        )
        .await
        .expect("hello");
        let _ = read_frame_async(&mut stream).await.expect("refusal");
        let payload = serde_json::to_vec(&V2Message::OfferAnnouncement(OfferAnnouncement::new(
            OfferId::new(),
            peer.device_id,
            server_identity.device_id,
            1,
            OfferDescriptor::text("must not arrive").expect("descriptor"),
        )))
        .expect("payload");
        let _ = stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await;
        let _ = stream.write_all(&payload).await;
        let _ = shutdown.send(true);
        server.await.expect("server join").expect("server result");
        assert!(cards.read_offer_shelf().expect("shelf").is_empty());
    }

    #[tokio::test]
    async fn announcement_client_refuses_a_server_without_the_capability() {
        let client_identity = InstallationIdentity::generate();
        let server_identity = InstallationIdentity::generate();
        let response_identity = server_identity.clone();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = read_frame_async(&mut stream).await.expect("hello");
            let response = WireMessage::ServerHello(ServerHello::signed(
                V2_PROTOCOL_VERSION,
                server_identity.device_id,
                "server".to_owned(),
                true,
                None,
                Vec::new(),
                &response_identity,
            ));
            write_frame_async(&mut stream, &response)
                .await
                .expect("response");
        });
        let announcement = OfferAnnouncement::new(
            OfferId::new(),
            client_identity.device_id,
            server_identity.device_id,
            1,
            OfferDescriptor::text("announcement").expect("descriptor"),
        );
        let result = PeerClient::default()
            .announce_offer_v2(
                address,
                ClientHello::signed_v2(
                    client_identity.device_id,
                    "client",
                    "nonce",
                    &client_identity,
                ),
                announcement,
                &server_identity.public_key(),
            )
            .await;
        assert!(
            matches!(result, Err(NetError::Rejected(reason)) if reason.contains("offer-pull-v2"))
        );
        server.await.expect("server join");
    }

    #[tokio::test]
    async fn fetch_client_refuses_a_server_without_the_capability() {
        let client_identity = InstallationIdentity::generate();
        let server_identity = InstallationIdentity::generate();
        let response_identity = server_identity.clone();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = read_frame_async(&mut stream).await.expect("hello");
            let response = WireMessage::ServerHello(ServerHello::signed(
                V2_PROTOCOL_VERSION,
                response_identity.device_id,
                "server".to_owned(),
                true,
                None,
                Vec::new(),
                &response_identity,
            ));
            write_frame_async(&mut stream, &response)
                .await
                .expect("response");
        });
        let directory = tempdir().expect("tempdir");
        let receiver_store = Arc::new(
            RedbV2Store::open(directory.path().join("receiver.redb")).expect("receiver store"),
        );
        let request = FetchRequest::new(
            OfferId::new(),
            server_identity.device_id,
            client_identity.device_id,
        );
        let request_id = request.request_id;
        let activation = FetchActivation::new(
            request_id,
            server_identity.device_id,
            request.offer_id,
            ActivationMode::Clipboard,
            None,
        );
        let receiver = FetchReceiver::new(
            client_identity.device_id,
            receiver_store,
            Arc::new(TestClipboard),
            directory.path().to_owned(),
        );
        let result = PeerClient::default()
            .fetch_v2(
                address,
                ClientHello::signed_v2(
                    client_identity.device_id,
                    "client",
                    "nonce",
                    &client_identity,
                ),
                request,
                activation,
                &server_identity.public_key(),
                &receiver,
            )
            .await;
        assert!(
            matches!(result, Err(NetError::Rejected(reason)) if reason.contains("offer-pull-v2"))
        );
        server.await.expect("server join");
    }
}
