//! Protocol-v2 offer, cleanup, and clipboard-cache indexes.
//!
//! Opening [`RedbV2Store`] does not itself read or migrate the v1 receive
//! ledger; startup calls [`RedbV2Store::migrate_legacy_state`] before the
//! listener binds.

use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

use meshelf_core::{
    ActivationId, ActivationJournalEntry, ActivationMode, CleanupReport, ClipboardCacheRecord,
    ClipboardCacheState, MigrationReport, OfferCardInput, OfferCardInsert, OfferCardRecord,
    OfferEligibilityUpdate, OfferSourceInput, OfferSourceInsert, OfferSourceRecord,
    OfferSourceStore, StoreError, V2_MAX_LIVE_ENTRIES,
};
use meshelf_platform::{ensure_directory_tree, reject_reparse_point, remove_owned_tree};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{RECEIVE_LEDGER, map_redb_error};

macro_rules! encode_json {
    ($value:expr) => {
        serde_json::to_vec($value).map_err(|error| StoreError::new(error.to_string()))
    };
}

macro_rules! decode_json {
    ($bytes:expr) => {
        serde_json::from_slice($bytes).map_err(|error| StoreError::new(error.to_string()))
    };
}

const OFFER_SOURCES_V2: TableDefinition<&str, &[u8]> = TableDefinition::new("offer_sources_v2");
const OFFER_CARDS_V2: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("offer_cards_v2");
const ACTIVATION_JOURNAL_V2: TableDefinition<&str, &[u8]> =
    TableDefinition::new("activation_journal_v2");
const CLIPBOARD_CACHE_V2: TableDefinition<&str, &[u8]> = TableDefinition::new("clipboard_cache_v2");

const CACHE_IN_FLIGHT: &str = "in_flight";
const CACHE_COMPLETED: &str = "completed";

#[derive(Debug)]
pub struct RedbV2Store {
    database: Arc<Database>,
    path: PathBuf,
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    let _ = out.pop();
                }
                Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                Some(Component::ParentDir) | Some(Component::CurDir) | None => {
                    if !out.has_root() {
                        out.push(component);
                    }
                }
            },
            component => out.push(component),
        }
    }
    out
}

/// Logical identity of an offer-store file. Equivalent spellings of the same
/// location share one key; a path that cannot be named fails instead of keeping
/// the caller's unresolved spelling.
pub fn store_identity(path: &Path) -> Result<PathBuf, StoreError> {
    let normalized = normalize_path(path.to_path_buf());
    if normalized.file_name().is_none() {
        return Err(StoreError::new(
            "offer store path has no file name and cannot be used as a store identity",
        ));
    }
    resolve_store_identity(&normalized).or_else(|_| {
        let absolute = std::path::absolute(&normalized).map_err(|error| {
            StoreError::new(format!("offer store path could not be resolved: {error}"))
        })?;
        resolve_store_identity(&normalize_path(absolute))
    })
}

fn resolve_store_identity(path: &Path) -> Result<PathBuf, StoreError> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }
    let Some(name) = path.file_name() else {
        return Err(StoreError::new(
            "offer store path has no file name and cannot be used as a store identity",
        ));
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && let Ok(parent) = fs::canonicalize(parent)
    {
        return Ok(parent.join(name));
    }
    Err(StoreError::new(
        "offer store path could not be resolved to a store identity",
    ))
}

fn open_shared_database(path: &Path) -> Result<(Arc<Database>, PathBuf), StoreError> {
    static OPEN: OnceLock<Mutex<HashMap<PathBuf, Weak<Database>>>> = OnceLock::new();
    let registry = OPEN.get_or_init(|| Mutex::new(HashMap::new()));
    for _ in 0..64 {
        let identity = store_identity(path)?;
        {
            let map = registry.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(existing) = map.get(&identity).and_then(Weak::upgrade) {
                return Ok((existing, identity));
            }
        }
        match Database::create(path) {
            Ok(database) => {
                let identity = store_identity(path)?;
                let database = Arc::new(database);
                let mut map = registry.lock().unwrap_or_else(|error| error.into_inner());
                if let Some(existing) = map.get(&identity).and_then(Weak::upgrade) {
                    return Ok((existing, identity));
                }
                map.insert(identity.clone(), Arc::downgrade(&database));
                return Ok((database, identity));
            }
            Err(error) => {
                let message = error.to_string();
                if message.contains("already open") {
                    std::thread::yield_now();
                    continue;
                }
                return Err(map_redb_error(error));
            }
        }
    }
    Err(StoreError::new(
        "offer store is already open and could not be attached",
    ))
}

impl RedbV2Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let (database, path) = open_shared_database(path.as_ref())?;
        let write = database.begin_write().map_err(map_redb_error)?;
        {
            write.open_table(OFFER_SOURCES_V2).map_err(map_redb_error)?;
            write.open_table(OFFER_CARDS_V2).map_err(map_redb_error)?;
            write
                .open_table(ACTIVATION_JOURNAL_V2)
                .map_err(map_redb_error)?;
            write
                .open_table(CLIPBOARD_CACHE_V2)
                .map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)?;
        Ok(Self { database, path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn insert_offer_source(
        &self,
        input: OfferSourceInput,
    ) -> Result<OfferSourceInsert, StoreError> {
        input.validate()?;
        let key = input.offer_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let result = {
            let mut table = write.open_table(OFFER_SOURCES_V2).map_err(map_redb_error)?;
            let existing: Option<OfferSourceRecord> = table
                .get(key.as_str())
                .map_err(map_redb_error)?
                .map(|guard| decode_json!(guard.value()))
                .transpose()?;

            if let Some(record) = existing {
                if record.descriptor != input.descriptor {
                    return Err(StoreError::new(
                        "offer source conflicts with an existing descriptor",
                    ));
                }
                Ok(OfferSourceInsert {
                    record,
                    inserted: false,
                    purged: 0,
                })
            } else {
                let purged = purge_oldest_sources(&mut table)?;
                let creation_sequence = next_source_sequence(&table)?;
                let record = OfferSourceRecord {
                    offer_id: input.offer_id,
                    descriptor: input.descriptor,
                    creation_sequence,
                    announced_to: input.announced_to,
                    source: input.source,
                };
                let encoded = encode_json!(&record)?;
                table
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(map_redb_error)?;
                Ok(OfferSourceInsert {
                    record,
                    inserted: true,
                    purged,
                })
            }
        };
        let result = result?;
        write.commit().map_err(map_redb_error)?;
        Ok(result)
    }

    pub fn get_offer_source(
        &self,
        offer_id: meshelf_core::OfferId,
    ) -> Result<Option<OfferSourceRecord>, StoreError> {
        let key = offer_id.to_string();
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read.open_table(OFFER_SOURCES_V2).map_err(map_redb_error)?;
        table
            .get(key.as_str())
            .map_err(map_redb_error)?
            .map(|guard| decode_json!(guard.value()))
            .transpose()
    }

    /// Remove one recipient only after the user explicitly refused the offer.
    /// The source row is removed in the same redb transaction when no eligible
    /// recipients remain. Transport failures and lost acknowledgements never
    /// call this method and therefore preserve eligibility.
    pub fn remove_explicit_refusal(
        &self,
        offer_id: meshelf_core::OfferId,
        recipient: meshelf_core::DeviceId,
    ) -> Result<OfferEligibilityUpdate, StoreError> {
        let key = offer_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let result: Result<OfferEligibilityUpdate, StoreError> = {
            let mut table = write.open_table(OFFER_SOURCES_V2).map_err(map_redb_error)?;
            let Some(bytes) = table
                .get(key.as_str())
                .map_err(map_redb_error)?
                .map(|guard| guard.value().to_vec())
            else {
                return Err(StoreError::new("offer source does not exist"));
            };
            let mut record: OfferSourceRecord = decode_json!(&bytes)?;
            let recipient_was_eligible = record.announced_to.remove(&recipient);
            if !recipient_was_eligible {
                Ok(OfferEligibilityUpdate {
                    recipient_was_eligible: false,
                    offer_deleted: false,
                    remaining_recipients: u32::try_from(record.announced_to.len())
                        .map_err(|_| StoreError::new("too many eligible recipients"))?,
                })
            } else if record.announced_to.is_empty() {
                table.remove(key.as_str()).map_err(map_redb_error)?;
                Ok(OfferEligibilityUpdate {
                    recipient_was_eligible: true,
                    offer_deleted: true,
                    remaining_recipients: 0,
                })
            } else {
                let remaining_recipients = u32::try_from(record.announced_to.len())
                    .map_err(|_| StoreError::new("too many eligible recipients"))?;
                let encoded = encode_json!(&record)?;
                table
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(map_redb_error)?;
                Ok(OfferEligibilityUpdate {
                    recipient_was_eligible: true,
                    offer_deleted: false,
                    remaining_recipients,
                })
            }
        };
        let result = result?;
        write.commit().map_err(map_redb_error)?;
        Ok(result)
    }

    /// Descriptive alias for callers whose domain language is eligibility.
    pub fn remove_eligible_recipient(
        &self,
        offer_id: meshelf_core::OfferId,
        recipient: meshelf_core::DeviceId,
    ) -> Result<OfferEligibilityUpdate, StoreError> {
        self.remove_explicit_refusal(offer_id, recipient)
    }

    pub fn read_offer_sources(&self) -> Result<Vec<OfferSourceRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read.open_table(OFFER_SOURCES_V2).map_err(map_redb_error)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(map_redb_error)? {
            let (_, value) = entry.map_err(map_redb_error)?;
            records.push(decode_json!(value.value())?);
        }
        records
            .sort_by_key(|record: &OfferSourceRecord| std::cmp::Reverse(record.creation_sequence));
        Ok(records)
    }

    pub fn insert_offer_card(&self, input: OfferCardInput) -> Result<OfferCardInsert, StoreError> {
        input.validate()?;
        let source_key = input.source_device.to_string();
        let offer_key = input.offer_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let result = {
            let mut table = write.open_table(OFFER_CARDS_V2).map_err(map_redb_error)?;
            let existing: Option<OfferCardRecord> = table
                .get((source_key.as_str(), offer_key.as_str()))
                .map_err(map_redb_error)?
                .map(|guard| decode_json!(guard.value()))
                .transpose()?;

            if let Some(record) = existing {
                if record.descriptor != input.descriptor {
                    return Err(StoreError::new(
                        "offer card conflicts with an existing descriptor",
                    ));
                }
                Ok(OfferCardInsert {
                    record,
                    inserted: false,
                    purged: 0,
                })
            } else {
                let purged = purge_oldest_cards(&mut table)?;
                let received_sequence = next_card_sequence(&table)?;
                let record = OfferCardRecord {
                    source_device: input.source_device,
                    offer_id: input.offer_id,
                    descriptor: input.descriptor,
                    received_sequence,
                    availability: input.availability,
                    last_attempt: None,
                };
                let encoded = encode_json!(&record)?;
                table
                    .insert(
                        (source_key.as_str(), offer_key.as_str()),
                        encoded.as_slice(),
                    )
                    .map_err(map_redb_error)?;
                Ok(OfferCardInsert {
                    record,
                    inserted: true,
                    purged,
                })
            }
        };
        let result = result?;
        write.commit().map_err(map_redb_error)?;
        Ok(result)
    }

    pub fn get_offer_card(
        &self,
        source_device: meshelf_core::DeviceId,
        offer_id: meshelf_core::OfferId,
    ) -> Result<Option<OfferCardRecord>, StoreError> {
        let source_key = source_device.to_string();
        let offer_key = offer_id.to_string();
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read.open_table(OFFER_CARDS_V2).map_err(map_redb_error)?;
        table
            .get((source_key.as_str(), offer_key.as_str()))
            .map_err(map_redb_error)?
            .map(|guard| decode_json!(guard.value()))
            .transpose()
    }

    /// Read-only shelf access. This does not prune, rewrite, or otherwise
    /// mutate the card table.
    pub fn read_offer_shelf(&self) -> Result<Vec<OfferCardRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read.open_table(OFFER_CARDS_V2).map_err(map_redb_error)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(map_redb_error)? {
            let (_, value) = entry.map_err(map_redb_error)?;
            records.push(decode_json!(value.value())?);
        }
        records.sort_by_key(|record: &OfferCardRecord| std::cmp::Reverse(record.received_sequence));
        Ok(records)
    }

    pub fn record_offer_attempt(
        &self,
        source_device: meshelf_core::DeviceId,
        offer_id: meshelf_core::OfferId,
        status: meshelf_core::OfferAttemptStatus,
    ) -> Result<(), StoreError> {
        if status
            .detail
            .as_ref()
            .is_some_and(|detail| detail.len() > meshelf_core::MAX_OFFER_ATTEMPT_DETAIL_BYTES)
        {
            return Err(StoreError::new("offer attempt detail is too large"));
        }
        let source_key = source_device.to_string();
        let offer_key = offer_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        {
            let mut table = write.open_table(OFFER_CARDS_V2).map_err(map_redb_error)?;
            let Some(bytes) = table
                .get((source_key.as_str(), offer_key.as_str()))
                .map_err(map_redb_error)?
                .map(|guard| guard.value().to_vec())
            else {
                return Err(StoreError::new("offer card does not exist"));
            };
            let mut record: OfferCardRecord = decode_json!(&bytes)?;
            record.availability = match status.code {
                meshelf_core::OfferAttemptCode::SourceUnavailable => {
                    meshelf_core::CardAvailability::SourceUnavailable
                }
                meshelf_core::OfferAttemptCode::SourceChanged => {
                    meshelf_core::CardAvailability::SourceChanged
                }
                _ => record.availability,
            };
            record.last_attempt = Some(status);
            let encoded = encode_json!(&record)?;
            table
                .insert(
                    (source_key.as_str(), offer_key.as_str()),
                    encoded.as_slice(),
                )
                .map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)
    }

    pub fn journal_activation(&self, entry: &ActivationJournalEntry) -> Result<(), StoreError> {
        entry.validate()?;
        let key = entry.activation_id.to_string();
        let encoded = encode_json!(entry)?;
        let write = self.database.begin_write().map_err(map_redb_error)?;
        {
            let mut table = write
                .open_table(ACTIVATION_JOURNAL_V2)
                .map_err(map_redb_error)?;
            table
                .insert(key.as_str(), encoded.as_slice())
                .map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)
    }

    pub fn get_activation_journal(
        &self,
        activation_id: ActivationId,
    ) -> Result<Option<ActivationJournalEntry>, StoreError> {
        let key = activation_id.to_string();
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(ACTIVATION_JOURNAL_V2)
            .map_err(map_redb_error)?;
        table
            .get(key.as_str())
            .map_err(map_redb_error)?
            .map(|guard| decode_json!(guard.value()))
            .transpose()
    }

    /// The journal transaction is committed before the staging directory is
    /// created. The caller must have checked the directory ancestry; this
    /// method creates only the final activation directory.
    pub fn prepare_staging(&self, entry: &ActivationJournalEntry) -> Result<(), StoreError> {
        let parent = entry
            .staging_root
            .parent()
            .ok_or_else(|| StoreError::new("staging root has no parent"))?;
        ensure_directory_tree(parent)
            .map_err(|error| StoreError::new(format!("staging ancestry failed: {error}")))?;
        self.journal_activation(entry)?;
        fs::create_dir(&entry.staging_root)
            .map_err(|error| StoreError::new(format!("staging creation failed: {error}")))
    }

    /// Durably advance the cleanup journal without adding payload or replay state to it.
    pub fn update_activation_state(
        &self,
        activation_id: ActivationId,
        state: meshelf_core::ActivationState,
    ) -> Result<(), StoreError> {
        let key = activation_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        {
            let mut table = write
                .open_table(ACTIVATION_JOURNAL_V2)
                .map_err(map_redb_error)?;
            let Some(bytes) = table
                .get(key.as_str())
                .map_err(map_redb_error)?
                .map(|guard| guard.value().to_vec())
            else {
                return Err(StoreError::new("activation journal entry does not exist"));
            };
            let mut entry: ActivationJournalEntry = decode_json!(&bytes)?;
            entry.state = state;
            let encoded = encode_json!(&entry)?;
            table
                .insert(key.as_str(), encoded.as_slice())
                .map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)
    }

    pub fn remove_activation_journal(&self, activation_id: ActivationId) -> Result<(), StoreError> {
        let key = activation_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        {
            let mut table = write
                .open_table(ACTIVATION_JOURNAL_V2)
                .map_err(map_redb_error)?;
            table.remove(key.as_str()).map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)
    }

    /// Deletes abandoned journaled staging. A journal that records an uncertain
    /// clipboard side effect is preserved so a later activation cannot replay it.
    pub fn startup_cleanup(&self) -> Result<CleanupReport, StoreError> {
        let entries = self.activation_journal_entries()?;
        let journaled_entries = u32::try_from(entries.len())
            .map_err(|_| StoreError::new("too many activation journal entries"))?;
        let mut removed = Vec::new();
        let mut failures = Vec::new();
        let mut record_uncertain = Vec::new();

        for entry in &entries {
            if entry.state.is_uncertain_side_effect() {
                let _ = remove_owned_tree(&entry.staging_root);
                if entry.state != meshelf_core::ActivationState::UncertainNoReplay {
                    record_uncertain.push(entry.activation_id);
                }
                continue;
            }
            match remove_owned_tree(&entry.staging_root) {
                Ok(()) => removed.push(entry.activation_id),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    removed.push(entry.activation_id)
                }
                Err(_) => failures.push(entry.activation_id),
            }
        }

        if !removed.is_empty() {
            let write = self.database.begin_write().map_err(map_redb_error)?;
            {
                let mut table = write
                    .open_table(ACTIVATION_JOURNAL_V2)
                    .map_err(map_redb_error)?;
                for activation_id in &removed {
                    let key = activation_id.to_string();
                    table.remove(key.as_str()).map_err(map_redb_error)?;
                }
            }
            write.commit().map_err(map_redb_error)?;
        }

        for activation_id in &record_uncertain {
            self.update_activation_state(
                *activation_id,
                meshelf_core::ActivationState::UncertainNoReplay,
            )?;
        }

        if !failures.is_empty() {
            let failed_ids = failures
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            return Err(StoreError::new(format!(
                "cleanup failed for {} activation journal entr{}: {failed_ids}",
                failures.len(),
                if failures.len() == 1 { "y" } else { "ies" }
            )));
        }

        Ok(CleanupReport {
            journaled_entries,
            removed_entries: u32::try_from(removed.len())
                .map_err(|_| StoreError::new("too many cleaned activation entries"))?,
        })
    }

    pub fn has_uncertain_side_effect(&self) -> Result<bool, StoreError> {
        Ok(self.activation_journal_entries()?.iter().any(|entry| {
            entry.mode == ActivationMode::Clipboard && entry.state.is_uncertain_side_effect()
        }) || self
            .get_clipboard_cache(ClipboardCacheState::InFlight)?
            .is_some())
    }

    pub fn set_clipboard_cache(&self, record: &ClipboardCacheRecord) -> Result<(), StoreError> {
        record.validate()?;
        let key = cache_key(record.state);
        let encoded = encode_json!(record)?;
        let write = self.database.begin_write().map_err(map_redb_error)?;
        {
            let mut table = write
                .open_table(CLIPBOARD_CACHE_V2)
                .map_err(map_redb_error)?;
            table
                .insert(key, encoded.as_slice())
                .map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)
    }

    pub fn get_clipboard_cache(
        &self,
        state: ClipboardCacheState,
    ) -> Result<Option<ClipboardCacheRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(CLIPBOARD_CACHE_V2)
            .map_err(map_redb_error)?;
        table
            .get(cache_key(state))
            .map_err(map_redb_error)?
            .map(|guard| decode_json!(guard.value()))
            .transpose()
    }

    pub fn clear_clipboard_cache(&self, state: ClipboardCacheState) -> Result<(), StoreError> {
        let write = self.database.begin_write().map_err(map_redb_error)?;
        {
            let mut table = write
                .open_table(CLIPBOARD_CACHE_V2)
                .map_err(map_redb_error)?;
            table.remove(cache_key(state)).map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)
    }

    /// Atomically promote the in-flight cache index to the completed slot. The returned record,
    /// when present, is the previous completed object and may be deleted only after this commit.
    pub fn promote_clipboard_cache(
        &self,
        candidate: &ClipboardCacheRecord,
    ) -> Result<Option<ClipboardCacheRecord>, StoreError> {
        if candidate.state != ClipboardCacheState::InFlight {
            return Err(StoreError::new("clipboard candidate must be in flight"));
        }
        candidate.validate()?;
        let encoded_candidate = encode_json!(&ClipboardCacheRecord {
            activation_id: candidate.activation_id,
            state: ClipboardCacheState::Completed,
            payload_path: candidate.payload_path.clone(),
        })?;
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let previous = {
            let mut table = write
                .open_table(CLIPBOARD_CACHE_V2)
                .map_err(map_redb_error)?;
            let previous = table
                .get(CACHE_COMPLETED)
                .map_err(map_redb_error)?
                .map(|guard| decode_json!(guard.value()))
                .transpose()?;
            table
                .insert(CACHE_COMPLETED, encoded_candidate.as_slice())
                .map_err(map_redb_error)?;
            table.remove(CACHE_IN_FLIGHT).map_err(map_redb_error)?;
            previous
        };
        write.commit().map_err(map_redb_error)?;
        Ok(previous)
    }

    /// Delete remaining v1 receive-ledger rows. Opening a v2 store does not
    /// call this function; [`Self::migrate_legacy_state`] does. Published user
    /// files are outside the v1 ledger and are not inspected or removed.
    pub fn migrate_v1_body_records(&self) -> Result<MigrationReport, StoreError> {
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let report = {
            let mut table = write.open_table(RECEIVE_LEDGER).map_err(map_redb_error)?;
            let mut keys = Vec::new();
            for entry in table.iter().map_err(map_redb_error)? {
                let (key, _) = entry.map_err(map_redb_error)?;
                keys.push(key.value().to_owned());
            }
            for key in &keys {
                table.remove(key.as_str()).map_err(map_redb_error)?;
            }
            MigrationReport {
                v1_body_records_removed: u64::try_from(keys.len())
                    .map_err(|_| StoreError::new("too many v1 body records"))?,
                partials_directory_removed: false,
                completion_markers_removed: 0,
            }
        };
        write.commit().map_err(map_redb_error)?;
        Ok(report)
    }

    /// Perform the irreversible legacy cleanup before the v2 listener is bound.
    ///
    /// The redb deletion is one transaction. Files in the user's incoming directory are never
    /// inspected as transfer authority: only the app-owned partial directory and completion
    /// marker files are removed.
    pub fn migrate_legacy_state(
        &self,
        incoming_directory: &Path,
    ) -> Result<MigrationReport, StoreError> {
        let mut report = self.migrate_v1_body_records()?;
        let partials = incoming_directory.join(".meshelf-partials");
        match remove_owned_tree(&partials) {
            Ok(()) => report.partials_directory_removed = path_exists(&partials),
            Err(error) => {
                return Err(StoreError::new(format!(
                    "legacy partial cleanup failed: {error}"
                )));
            }
        }
        report.partials_directory_removed = !path_exists(&partials);

        let completed = incoming_directory.join(".meshelf-completed");
        report.completion_markers_removed = remove_completion_markers(&completed)?;
        Ok(report)
    }

    fn activation_journal_entries(&self) -> Result<Vec<ActivationJournalEntry>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(ACTIVATION_JOURNAL_V2)
            .map_err(map_redb_error)?;
        let mut entries = Vec::new();
        for entry in table.iter().map_err(map_redb_error)? {
            let (_, value) = entry.map_err(map_redb_error)?;
            entries.push(decode_json!(value.value())?);
        }
        Ok(entries)
    }
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn remove_completion_markers(directory: &Path) -> Result<u64, StoreError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(StoreError::new(error.to_string())),
    };
    reject_reparse_point(directory).map_err(|error| StoreError::new(error.to_string()))?;
    if !metadata.is_dir() {
        return Err(StoreError::new(
            "legacy completion marker path is not a directory",
        ));
    }
    let mut removed = 0_u64;
    for entry in fs::read_dir(directory).map_err(|error| StoreError::new(error.to_string()))? {
        let entry = entry.map_err(|error| StoreError::new(error.to_string()))?;
        let path = entry.path();
        let child_metadata =
            fs::symlink_metadata(&path).map_err(|error| StoreError::new(error.to_string()))?;
        if child_metadata.is_dir() {
            return Err(StoreError::new(format!(
                "legacy completion marker is a directory: {}",
                path.display()
            )));
        }
        fs::remove_file(&path).map_err(|error| StoreError::new(error.to_string()))?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

impl OfferSourceStore for RedbV2Store {
    fn insert_offer_source(
        &self,
        input: OfferSourceInput,
    ) -> Result<OfferSourceInsert, StoreError> {
        Self::insert_offer_source(self, input)
    }

    fn remove_explicit_refusal(
        &self,
        offer_id: meshelf_core::OfferId,
        recipient: meshelf_core::DeviceId,
    ) -> Result<OfferEligibilityUpdate, StoreError> {
        Self::remove_explicit_refusal(self, offer_id, recipient)
    }

    fn get_offer_source(
        &self,
        offer_id: meshelf_core::OfferId,
    ) -> Result<Option<OfferSourceRecord>, StoreError> {
        Self::get_offer_source(self, offer_id)
    }
}

fn purge_oldest_sources(
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
) -> Result<u32, StoreError> {
    let mut rows = Vec::new();
    for entry in table.iter().map_err(map_redb_error)? {
        let (key, value) = entry.map_err(map_redb_error)?;
        let record: OfferSourceRecord = decode_json!(value.value())?;
        rows.push((record.creation_sequence, key.value().to_owned()));
    }
    let target = rows
        .len()
        .saturating_sub(usize::try_from(V2_MAX_LIVE_ENTRIES - 1).unwrap_or(0));
    rows.sort_by_key(|(sequence, key)| (*sequence, key.clone()));
    for (_, key) in rows.iter().take(target) {
        table.remove(key.as_str()).map_err(map_redb_error)?;
    }
    u32::try_from(target).map_err(|_| StoreError::new("too many purged offer sources"))
}

fn next_source_sequence(
    table: &redb::Table<'_, &'static str, &'static [u8]>,
) -> Result<u64, StoreError> {
    let mut maximum = 0;
    for entry in table.iter().map_err(map_redb_error)? {
        let (_, value) = entry.map_err(map_redb_error)?;
        let record: OfferSourceRecord = decode_json!(value.value())?;
        maximum = maximum.max(record.creation_sequence);
    }
    maximum
        .checked_add(1)
        .ok_or_else(|| StoreError::new("offer source sequence overflow"))
}

fn purge_oldest_cards(
    table: &mut redb::Table<'_, (&'static str, &'static str), &'static [u8]>,
) -> Result<u32, StoreError> {
    let mut rows = Vec::new();
    for entry in table.iter().map_err(map_redb_error)? {
        let (key, value) = entry.map_err(map_redb_error)?;
        let record: OfferCardRecord = decode_json!(value.value())?;
        let (source_device, offer_id) = key.value();
        rows.push((
            record.received_sequence,
            source_device.to_owned(),
            offer_id.to_owned(),
        ));
    }
    let target = rows
        .len()
        .saturating_sub(usize::try_from(V2_MAX_LIVE_ENTRIES - 1).unwrap_or(0));
    rows.sort_by_key(|(sequence, source, offer)| (*sequence, source.clone(), offer.clone()));
    for (_, source, offer) in rows.iter().take(target) {
        table
            .remove((source.as_str(), offer.as_str()))
            .map_err(map_redb_error)?;
    }
    u32::try_from(target).map_err(|_| StoreError::new("too many purged offer cards"))
}

fn next_card_sequence(
    table: &redb::Table<'_, (&'static str, &'static str), &'static [u8]>,
) -> Result<u64, StoreError> {
    let mut maximum = 0;
    for entry in table.iter().map_err(map_redb_error)? {
        let (_, value) = entry.map_err(map_redb_error)?;
        let record: OfferCardRecord = decode_json!(value.value())?;
        maximum = maximum.max(record.received_sequence);
    }
    maximum
        .checked_add(1)
        .ok_or_else(|| StoreError::new("offer card sequence overflow"))
}

fn cache_key(state: ClipboardCacheState) -> &'static str {
    match state {
        ClipboardCacheState::InFlight => CACHE_IN_FLIGHT,
        ClipboardCacheState::Completed => CACHE_COMPLETED,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fs,
        path::{Path, PathBuf},
    };

    use meshelf_core::{
        ActivationId, ActivationJournalEntry, ActivationMode, ActivationState, CardAvailability,
        ClipboardCacheRecord, ClipboardCacheState, DeviceId, OfferAttemptCode, OfferAttemptStatus,
        OfferCardInput, OfferDescriptor, OfferId, OfferSource, OfferSourceInput,
        V2_MAX_LIVE_ENTRIES,
    };
    use redb::{Database, ReadableDatabase, ReadableTable};
    use tempfile::tempdir;

    use super::RedbV2Store;
    use crate::RECEIVE_LEDGER;

    fn insert_legacy_rows(path: &PathBuf, keys: &[&str]) {
        let database = Database::create(path).expect("legacy database");
        let write = database.begin_write().expect("legacy write");
        {
            let mut table = write.open_table(RECEIVE_LEDGER).expect("legacy table");
            for key in keys {
                table
                    .insert(*key, b"legacy payload".as_slice())
                    .expect("legacy row");
            }
        }
        write.commit().expect("legacy commit");
    }

    fn legacy_row_count(path: &PathBuf) -> usize {
        let database = Database::create(path).expect("legacy reopen");
        let read = database.begin_read().expect("legacy read");
        let table = read.open_table(RECEIVE_LEDGER).expect("legacy table");
        table.iter().expect("legacy rows").count()
    }

    fn store() -> (tempfile::TempDir, RedbV2Store) {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("meshelf.redb");
        let store = RedbV2Store::open(path).expect("open v2 store");
        (directory, store)
    }

    fn text_input(text: &str) -> OfferSourceInput {
        let descriptor = OfferDescriptor::text(text).expect("descriptor");
        OfferSourceInput::new(
            OfferId::new(),
            descriptor,
            HashSet::from([DeviceId::new()]),
            OfferSource::Text {
                text: text.to_owned(),
            },
        )
    }

    #[test]
    fn normalize_path_keeps_repeated_leading_parent_dirs() {
        assert_eq!(
            super::normalize_path(PathBuf::from("../../offers.redb")),
            PathBuf::from("../../offers.redb")
        );
        assert_eq!(
            super::normalize_path(PathBuf::from("../../../offers.redb")),
            PathBuf::from("../../../offers.redb")
        );
        assert_eq!(
            super::normalize_path(PathBuf::from("../foo/../../offers.redb")),
            PathBuf::from("../../offers.redb")
        );
        assert_eq!(
            super::normalize_path(PathBuf::from("/../../offers.redb")),
            PathBuf::from("/offers.redb")
        );
    }

    #[test]
    fn equivalent_store_spellings_share_identity_before_the_file_exists() {
        let directory = tempdir().expect("temporary directory");
        let base = directory.path().join("offers.redb");
        let dotted = directory.path().join(".").join("offers.redb");
        let via_parent = directory
            .path()
            .join("subdir")
            .join("..")
            .join("offers.redb");
        let first = super::store_identity(&base).expect("base identity");
        assert_eq!(
            first,
            super::store_identity(&dotted).expect("dotted identity")
        );
        assert_eq!(
            first,
            super::store_identity(&via_parent).expect("parent-dotdot identity")
        );
    }

    #[test]
    fn unresolvable_store_path_fails_explicitly() {
        let error = super::store_identity(Path::new("")).expect_err("empty path has no file name");
        assert!(error.message().contains("no file name"));
    }

    #[test]
    fn two_opens_of_the_same_path_share_store_identity() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("offers.redb");
        let first = RedbV2Store::open(&path).expect("open first handle");
        let second = RedbV2Store::open(&path).expect("open second handle");
        assert_eq!(first.path(), second.path());
        let input = text_input("shared identity");
        let id = input.offer_id;
        first
            .insert_offer_source(input)
            .expect("insert on first handle");
        assert!(
            second
                .get_offer_source(id)
                .expect("read second handle")
                .is_some(),
            "a second open of the same path must observe the first handle's writes"
        );
    }

    #[test]
    fn source_and_eligibility_survive_restart() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("offers.redb");
        let first = DeviceId::new();
        let second = DeviceId::new();
        let mut input = text_input("restart eligibility");
        input.announced_to = HashSet::from([first, second]);
        let offer_id = input.offer_id;
        {
            let store = RedbV2Store::open(&path).expect("open");
            store.insert_offer_source(input).expect("insert");
        }
        let reopened = RedbV2Store::open(path).expect("reopen");
        assert_eq!(
            reopened
                .get_offer_source(offer_id)
                .expect("read")
                .expect("source")
                .announced_to,
            HashSet::from([first, second])
        );
    }

    #[test]
    fn explicit_refusal_removes_only_that_recipient() {
        let (_directory, store) = store();
        let first = DeviceId::new();
        let second = DeviceId::new();
        let mut input = text_input("refusal");
        input.announced_to = HashSet::from([first, second]);
        let offer_id = input.offer_id;
        store.insert_offer_source(input).expect("insert");
        let result = store
            .remove_explicit_refusal(offer_id, first)
            .expect("refusal");
        assert_eq!(
            result,
            meshelf_core::OfferEligibilityUpdate {
                recipient_was_eligible: true,
                offer_deleted: false,
                remaining_recipients: 1,
            }
        );
        assert_eq!(
            store
                .get_offer_source(offer_id)
                .expect("read")
                .expect("source")
                .announced_to,
            HashSet::from([second])
        );
    }

    #[test]
    fn last_explicit_refusal_deletes_source() {
        let (_directory, store) = store();
        let recipient = DeviceId::new();
        let mut input = text_input("last refusal");
        input.announced_to = HashSet::from([recipient]);
        let offer_id = input.offer_id;
        store.insert_offer_source(input).expect("insert");
        let result = store
            .remove_explicit_refusal(offer_id, recipient)
            .expect("refusal");
        assert!(result.offer_deleted);
        assert!(store.get_offer_source(offer_id).expect("read").is_none());
    }

    #[test]
    fn lost_ack_keeps_attempted_recipient() {
        let (_directory, store) = store();
        let recipient = DeviceId::new();
        let mut input = text_input("lost acknowledgement");
        input.announced_to = HashSet::from([recipient]);
        let offer_id = input.offer_id;
        store.insert_offer_source(input).expect("insert");
        assert!(
            store
                .get_offer_source(offer_id)
                .expect("read")
                .expect("source")
                .announced_to
                .contains(&recipient)
        );
    }

    #[test]
    fn eleventh_source_purges_oldest_text_and_eligibility() {
        let (_directory, store) = store();
        let recipient = DeviceId::new();
        let mut oldest = text_input("oldest");
        oldest.announced_to = HashSet::from([recipient]);
        let oldest_id = oldest.offer_id;
        store.insert_offer_source(oldest).expect("oldest");
        for index in 0..V2_MAX_LIVE_ENTRIES {
            store
                .insert_offer_source(text_input(&format!("new {index}")))
                .expect("new source");
        }
        assert!(store.get_offer_source(oldest_id).expect("read").is_none());
        assert_eq!(store.read_offer_sources().expect("read sources").len(), 10);
    }

    #[test]
    fn no_offer_record_contains_time_expiry() {
        let (_directory, store) = store();
        let input = text_input("persistent");
        let offer_id = input.offer_id;
        store.insert_offer_source(input).expect("insert");
        let encoded = serde_json::to_string(
            &store
                .get_offer_source(offer_id)
                .expect("read")
                .expect("source"),
        )
        .expect("encode");
        assert!(!encoded.contains("expiry"));
        assert!(!encoded.contains("expires"));
        assert!(!encoded.contains("deadline"));
    }

    fn card_input(source_device: DeviceId, text: &str) -> OfferCardInput {
        OfferCardInput::new(
            source_device,
            OfferId::new(),
            OfferDescriptor::text(text).expect("descriptor"),
            CardAvailability::Available,
        )
    }

    #[test]
    fn offer_source_stores_text_body_and_purges_it_with_the_entry() {
        let (_directory, store) = store();
        let first = text_input("body that must be durable");
        let first_id = first.offer_id;
        store.insert_offer_source(first).expect("insert");
        assert!(matches!(
            store.get_offer_source(first_id).expect("read"),
            Some(record) if matches!(&record.source, OfferSource::Text { text } if text == "body that must be durable")
        ));
        for index in 0..V2_MAX_LIVE_ENTRIES {
            store
                .insert_offer_source(text_input(&format!("new {index}")))
                .expect("insert newer offer");
        }
        assert!(
            store
                .get_offer_source(first_id)
                .expect("read purged")
                .is_none()
        );
    }

    #[test]
    fn offer_source_for_file_stores_path_and_never_bytes() {
        let (_directory, store) = store();
        let input = OfferSourceInput::new(
            OfferId::new(),
            OfferDescriptor::File {
                root_name: "file.bin".to_owned(),
                total_bytes: 3,
            },
            HashSet::new(),
            OfferSource::File {
                canonical_path: absolute_test_path("file.bin"),
                metadata_commitment: vec![7; 32],
            },
        );
        let id = input.offer_id;
        store.insert_offer_source(input).expect("insert");
        let record = store
            .get_offer_source(id)
            .expect("read")
            .expect("file source");
        assert!(matches!(
            &record.source,
            OfferSource::File {
                canonical_path,
                metadata_commitment
            } if canonical_path.as_path() == absolute_test_path("file.bin").as_path()
                && metadata_commitment == &vec![7; 32]
        ));
        let encoded = serde_json::to_string(&record).expect("serialize");
        assert!(!encoded.contains("body"));
        assert!(!encoded.contains("text"));
    }

    #[test]
    fn eleventh_offer_purges_the_oldest_and_leaves_ten() {
        let (_directory, store) = store();
        let mut ids = Vec::new();
        for index in 0..=V2_MAX_LIVE_ENTRIES {
            let input = text_input(&format!("offer {index}"));
            ids.push(input.offer_id);
            store.insert_offer_source(input).expect("insert");
        }
        assert_eq!(store.read_offer_sources().expect("read").len(), 10);
        assert!(store.get_offer_source(ids[0]).expect("oldest").is_none());
        assert!(
            store
                .get_offer_source(*ids.last().expect("newest"))
                .expect("newest")
                .is_some()
        );
    }

    #[test]
    fn purge_is_by_creation_order_not_insertion_hash_order() {
        let (_directory, store) = store();
        let mut ids = Vec::new();
        for index in 0..=V2_MAX_LIVE_ENTRIES {
            let input = text_input(&format!("ordered {index}"));
            ids.push(input.offer_id);
            store.insert_offer_source(input).expect("insert");
        }
        assert!(store.get_offer_source(ids[0]).expect("oldest").is_none());
        for id in ids.iter().skip(1) {
            assert!(store.get_offer_source(*id).expect("retained").is_some());
        }
    }

    #[test]
    fn offer_card_records_metadata_and_preview_but_no_body() {
        let (_directory, store) = store();
        let input = card_input(DeviceId::new(), "visible preview");
        let source = input.source_device;
        let offer = input.offer_id;
        store.insert_offer_card(input).expect("insert");
        let card = store
            .get_offer_card(source, offer)
            .expect("read")
            .expect("card");
        assert_eq!(
            card.descriptor,
            OfferDescriptor::text("visible preview").unwrap()
        );
        assert!(card.last_attempt.is_none());
        let encoded = serde_json::to_string(&card).expect("serialize");
        assert!(encoded.contains("preview"));
        assert!(!encoded.contains("payload"));
        assert!(!encoded.contains("last_body"));
    }

    #[test]
    fn duplicate_identical_offer_is_a_noop_success() {
        let (_directory, store) = store();
        let input = text_input("same offer");
        let first = store
            .insert_offer_source(input.clone())
            .expect("first insert");
        let second = store.insert_offer_source(input).expect("duplicate");
        assert!(first.inserted);
        assert!(!second.inserted);
        assert_eq!(first.record, second.record);
        assert_eq!(store.read_offer_sources().expect("read").len(), 1);
    }

    #[test]
    fn same_offer_id_with_different_descriptor_is_a_conflict() {
        let (_directory, store) = store();
        let first = text_input("first");
        let conflicting = OfferSourceInput {
            offer_id: first.offer_id,
            descriptor: OfferDescriptor::text("different").expect("descriptor"),
            announced_to: first.announced_to.clone(),
            source: OfferSource::Text {
                text: "different".to_owned(),
            },
        };
        store.insert_offer_source(first).expect("first insert");
        let error = store
            .insert_offer_source(conflicting)
            .expect_err("conflict");
        assert!(error.message().contains("conflicts"));
    }

    #[test]
    fn shelf_read_is_newest_first_and_does_not_mutate() {
        let (_directory, store) = store();
        let source = DeviceId::new();
        let first = card_input(source, "first");
        let second = card_input(source, "second");
        store.insert_offer_card(first).expect("first");
        store.insert_offer_card(second).expect("second");
        let before = store.read_offer_shelf().expect("before");
        let again = store.read_offer_shelf().expect("again");
        assert_eq!(before.len(), 2);
        assert_eq!(before, again);
        assert_eq!(
            before[0].descriptor,
            OfferDescriptor::text("second").expect("descriptor")
        );
        assert_eq!(store.read_offer_shelf().expect("count").len(), 2);
    }

    #[test]
    fn stored_offers_survive_a_close_and_reopen() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("meshelf.redb");
        let input = text_input("survives restart");
        let offer_id = input.offer_id;
        let card = card_input(DeviceId::new(), "card survives");
        let card_key = (card.source_device, card.offer_id);
        {
            let store = RedbV2Store::open(&path).expect("open");
            store.insert_offer_source(input).expect("source");
            store.insert_offer_card(card).expect("card");
        }
        let reopened = RedbV2Store::open(path).expect("reopen");
        assert!(
            reopened
                .get_offer_source(offer_id)
                .expect("source")
                .is_some()
        );
        assert!(
            reopened
                .get_offer_card(card_key.0, card_key.1)
                .expect("card")
                .is_some()
        );
    }

    /// An absolute path that is valid on every supported platform. A literal `/private/tmp/...`
    /// is absolute on Unix but merely root-relative on Windows, which made two tests pass on
    /// macOS and fail on Windows against the same correct production check.
    fn absolute_test_path(tail: &str) -> PathBuf {
        std::env::temp_dir().join(tail)
    }

    fn journal_entry(root: PathBuf) -> ActivationJournalEntry {
        ActivationJournalEntry {
            activation_id: ActivationId::new(),
            source_device: DeviceId::new(),
            offer_id: OfferId::new(),
            mode: ActivationMode::Save,
            staging_root: root,
            state: ActivationState::Staging,
            reserved_entries: 2,
            reserved_bytes: 12,
        }
    }

    #[test]
    fn cleanup_journal_commit_precedes_staging_creation() {
        let (directory, store) = store();
        let entry = journal_entry(
            fs::canonicalize(directory.path())
                .expect("canonical temporary directory")
                .join("staging"),
        );
        store.prepare_staging(&entry).expect("prepare");
        assert!(entry.staging_root.is_dir());
        assert_eq!(
            store
                .get_activation_journal(entry.activation_id)
                .expect("journal")
                .expect("journal entry"),
            entry
        );
    }

    #[test]
    fn uncertain_journal_survives_startup_cleanup() {
        let (directory, store) = store();
        let root = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let abandoned = journal_entry(root.join("abandoned"));
        let mut uncertain = journal_entry(root.join("uncertain"));
        uncertain.mode = ActivationMode::Clipboard;
        uncertain.state = ActivationState::UncertainNoReplay;
        store.prepare_staging(&abandoned).expect("abandoned");
        store.prepare_staging(&uncertain).expect("uncertain");
        let report = store.startup_cleanup().expect("cleanup");
        assert_eq!(report.removed_entries, 1);
        assert!(!abandoned.staging_root.exists());
        assert!(
            store
                .get_activation_journal(abandoned.activation_id)
                .expect("abandoned journal")
                .is_none()
        );
        let kept = store
            .get_activation_journal(uncertain.activation_id)
            .expect("uncertain journal")
            .expect("preserved");
        assert_eq!(kept.state, ActivationState::UncertainNoReplay);
        assert!(store.has_uncertain_side_effect().expect("uncertain marker"));
    }

    #[test]
    fn applying_clipboard_journal_is_recorded_uncertain_and_kept() {
        let (directory, store) = store();
        let root = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let mut applying = journal_entry(root.join("applying"));
        applying.mode = ActivationMode::Clipboard;
        applying.state = ActivationState::ApplyingClipboard;
        store.prepare_staging(&applying).expect("applying");
        store.startup_cleanup().expect("cleanup");
        let kept = store
            .get_activation_journal(applying.activation_id)
            .expect("journal")
            .expect("preserved");
        assert_eq!(kept.state, ActivationState::UncertainNoReplay);
        assert!(store.has_uncertain_side_effect().expect("uncertain marker"));
    }

    #[test]
    fn save_uncertainty_does_not_mark_clipboard_uncertain() {
        let (directory, store) = store();
        let root = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let mut uncertain = journal_entry(root.join("save-uncertain"));
        uncertain.state = ActivationState::UncertainNoReplay;
        store.prepare_staging(&uncertain).expect("save uncertain");
        assert!(
            !store
                .has_uncertain_side_effect()
                .expect("clipboard uncertainty marker")
        );
    }

    #[test]
    fn journal_commit_precedes_staging() {
        let (directory, store) = store();
        let root = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let staging_root = root.join("staging-file");
        fs::write(&staging_root, b"pre-existing non-staging object").expect("blocking object");
        let entry = journal_entry(staging_root.clone());

        let error = store
            .prepare_staging(&entry)
            .expect_err("staging creation must fail on a pre-existing file");
        assert!(error.message().contains("staging creation failed"));
        assert_eq!(
            store
                .get_activation_journal(entry.activation_id)
                .expect("journal lookup")
                .expect("journal committed before staging")
                .staging_root,
            staging_root
        );

        store
            .remove_activation_journal(entry.activation_id)
            .expect("remove test journal");
        fs::remove_file(entry.staging_root).expect("remove blocking object");
    }

    #[test]
    fn startup_cleanup_deletes_every_journaled_partial() {
        let (directory, store) = store();
        let root = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let first = journal_entry(root.join("first"));
        let second = journal_entry(root.join("second"));
        store.prepare_staging(&first).expect("first");
        store.prepare_staging(&second).expect("second");
        let report = store.startup_cleanup().expect("cleanup");
        assert_eq!(report.journaled_entries, 2);
        assert_eq!(report.removed_entries, 2);
        assert!(!first.staging_root.exists());
        assert!(!second.staging_root.exists());
        assert!(
            store
                .get_activation_journal(first.activation_id)
                .expect("first journal")
                .is_none()
        );
    }

    #[test]
    fn restart_cleans_partial_without_resume() {
        let directory = tempdir().expect("temporary directory");
        let database_path = directory.path().join("offers.redb");
        let root = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        let entry = journal_entry(root.join("partial-staging"));
        {
            let store = RedbV2Store::open(&database_path).expect("open store");
            store.journal_activation(&entry).expect("journal partial");
            fs::create_dir_all(entry.staging_root.join("nested")).expect("partial directory");
            fs::write(entry.staging_root.join("nested/payload"), b"partial").expect("payload");
        }

        let reopened = RedbV2Store::open(&database_path).expect("reopen store");
        let report = reopened.startup_cleanup().expect("startup cleanup");
        assert_eq!(report.journaled_entries, 1);
        assert_eq!(report.removed_entries, 1);
        assert!(!entry.staging_root.exists());
        assert!(
            reopened
                .get_activation_journal(entry.activation_id)
                .expect("journal lookup")
                .is_none()
        );
    }

    #[test]
    fn cleanup_failure_is_reported_not_swallowed() {
        let (directory, store) = store();
        let path = directory.path().join("not-a-directory");
        fs::write(&path, b"published content").expect("file");
        let entry = journal_entry(path.clone());
        store.journal_activation(&entry).expect("journal");
        let error = store.startup_cleanup().expect_err("cleanup failure");
        assert!(error.message().contains("cleanup failed"));
        assert!(path.exists());
        assert!(
            store
                .get_activation_journal(entry.activation_id)
                .expect("journal")
                .is_some()
        );
    }

    #[test]
    fn migration_removes_every_v1_ledger_row_and_reports_the_count() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("meshelf.redb");
        insert_legacy_rows(&path, &["first", "second"]);
        let v2 = RedbV2Store::open(&path).expect("v2 open");
        let report = v2.migrate_v1_body_records().expect("migration");
        assert_eq!(report.v1_body_records_removed, 2);
        drop(v2);
        assert_eq!(legacy_row_count(&path), 0);
    }

    #[test]
    fn migration_never_deletes_a_published_user_file() {
        let directory = tempdir().expect("temp directory");
        let published = directory.path().join("published.txt");
        fs::write(&published, b"published").expect("published file");
        let path = directory.path().join("meshelf.redb");
        insert_legacy_rows(&path, &["published"]);
        let v2 = RedbV2Store::open(&path).expect("v2 open");
        v2.migrate_legacy_state(&directory.path().join("missing incoming"))
            .expect("migration");
        assert_eq!(fs::read(&published).expect("read published"), b"published");
    }

    #[test]
    fn migration_counts_and_removes_v1_body_records() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("meshelf.redb");
        insert_legacy_rows(&path, &["first", "second"]);
        let v2 = RedbV2Store::open(&path).expect("v2 open");
        let report = v2.migrate_v1_body_records().expect("migration");
        assert_eq!(report.v1_body_records_removed, 2);
        drop(v2);
        assert_eq!(legacy_row_count(&path), 0);
    }

    #[test]
    fn migration_preserves_published_user_files() {
        let directory = tempdir().expect("temp directory");
        let published = directory.path().join("published.txt");
        fs::write(&published, b"published").expect("published file");
        let path = directory.path().join("meshelf.redb");
        insert_legacy_rows(&path, &["published"]);
        let v2 = RedbV2Store::open(&path).expect("v2 open");
        v2.migrate_legacy_state(&directory.path().join("missing incoming"))
            .expect("migration");
        assert_eq!(fs::read(&published).expect("read published"), b"published");
    }

    #[test]
    fn migration_removes_partials_and_completion_markers_only() {
        let directory = tempdir().expect("temporary directory");
        let incoming = directory.path().join("Meshelf Incoming");
        fs::create_dir_all(incoming.join(".meshelf-partials/old")).expect("partials directory");
        fs::write(incoming.join(".meshelf-partials/old/payload"), b"partial")
            .expect("partial payload");
        fs::create_dir_all(incoming.join(".meshelf-completed")).expect("completed directory");
        fs::write(
            incoming.join(".meshelf-completed/old-transfer.json"),
            br#"{"final_path":"user-output.txt"}"#,
        )
        .expect("completion marker");
        let published = incoming.join("user-output.txt");
        fs::write(&published, b"published user data").expect("published file");

        let store = RedbV2Store::open(directory.path().join("meshelf.redb")).expect("open store");
        let report = store.migrate_legacy_state(&incoming).expect("migration");

        assert!(report.partials_directory_removed);
        assert_eq!(report.completion_markers_removed, 1);
        assert!(!incoming.join(".meshelf-partials").exists());
        assert!(
            !incoming
                .join(".meshelf-completed/old-transfer.json")
                .exists()
        );
        assert_eq!(
            fs::read(&published).expect("published file"),
            b"published user data"
        );
        assert!(incoming.exists());
    }

    #[test]
    fn migration_is_idempotent() {
        let directory = tempdir().expect("temporary directory");
        let incoming = directory.path().join("Meshelf Incoming");
        fs::create_dir_all(incoming.join(".meshelf-partials/old")).expect("partials directory");
        fs::create_dir_all(incoming.join(".meshelf-completed")).expect("completed directory");
        fs::write(incoming.join(".meshelf-completed/old.json"), b"marker").expect("marker");
        let store = RedbV2Store::open(directory.path().join("meshelf.redb")).expect("open store");

        let first = store
            .migrate_legacy_state(&incoming)
            .expect("first migration");
        let second = store
            .migrate_legacy_state(&incoming)
            .expect("second migration");

        assert_eq!(first.v1_body_records_removed, 0);
        assert_eq!(first.completion_markers_removed, 1);
        assert_eq!(second.v1_body_records_removed, 0);
        assert_eq!(second.completion_markers_removed, 0);
        assert!(second.partials_directory_removed);
    }

    #[cfg(unix)]
    #[test]
    fn startup_blocks_when_cleanup_fails() {
        let directory = tempdir().expect("temporary directory");
        let incoming = directory.path().join("Meshelf Incoming");
        fs::create_dir_all(&incoming).expect("incoming directory");
        let outside = directory.path().join("outside");
        fs::create_dir_all(&outside).expect("outside directory");
        std::os::unix::fs::symlink(&outside, incoming.join(".meshelf-partials"))
            .expect("partial symlink");
        let store = RedbV2Store::open(directory.path().join("meshelf.redb")).expect("open store");

        let error = store
            .migrate_legacy_state(&incoming)
            .expect_err("reparse cleanup must block startup");
        assert!(error.message().contains("legacy partial cleanup failed"));
        assert!(incoming.join(".meshelf-partials").exists());
        assert!(outside.exists());
    }

    #[cfg(windows)]
    #[test]
    fn startup_blocks_when_cleanup_fails() {
        use std::os::windows::fs::OpenOptionsExt;

        let directory = tempdir().expect("temporary directory");
        let incoming = directory.path().join("Meshelf Incoming");
        let partials = incoming.join(".meshelf-partials");
        fs::create_dir_all(&partials).expect("partials directory");
        let held = partials.join("held.bin");
        fs::write(&held, b"held").expect("held file");
        // Share mode 0 denies FILE_SHARE_DELETE, so an open handle blocks
        // removing the leftover tree on Windows without elevation.
        let _blocked = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&held)
            .expect("open blocking handle");
        let store = RedbV2Store::open(directory.path().join("meshelf.redb")).expect("open store");

        let error = store
            .migrate_legacy_state(&incoming)
            .expect_err("blocked leftover cleanup must refuse startup");
        assert!(error.message().contains("legacy partial cleanup failed"));
        assert!(partials.exists());
    }

    #[test]
    fn v2_store_types_carry_no_expiry_or_deadline_field() {
        let source = text_input("no timing");
        let card = card_input(DeviceId::new(), "no timing");
        let source_record = meshelf_core::OfferSourceRecord {
            offer_id: source.offer_id,
            descriptor: source.descriptor.clone(),
            creation_sequence: 1,
            announced_to: source.announced_to.clone(),
            source: source.source.clone(),
        };
        let card_record = meshelf_core::OfferCardRecord {
            source_device: card.source_device,
            offer_id: card.offer_id,
            descriptor: card.descriptor.clone(),
            received_sequence: 1,
            availability: card.availability,
            last_attempt: None,
        };
        let journal = journal_entry(absolute_test_path("staging"));
        let cache = ClipboardCacheRecord {
            activation_id: ActivationId::new(),
            state: ClipboardCacheState::Completed,
            payload_path: absolute_test_path("payload"),
        };
        for encoded in [
            serde_json::to_string(&source_record).expect("source"),
            serde_json::to_string(&card_record).expect("card"),
            serde_json::to_string(&journal).expect("journal"),
            serde_json::to_string(&cache).expect("cache"),
        ] {
            assert!(!encoded.contains("expiry"));
            assert!(!encoded.contains("expires"));
            assert!(!encoded.contains("deadline"));
        }
    }

    #[test]
    fn clipboard_cache_has_one_completed_and_one_in_flight_entry() {
        let (_directory, store) = store();
        for state in [
            ClipboardCacheState::Completed,
            ClipboardCacheState::InFlight,
        ] {
            let record = ClipboardCacheRecord {
                activation_id: ActivationId::new(),
                state,
                payload_path: absolute_test_path(&format!("{state:?}")),
            };
            store.set_clipboard_cache(&record).expect("cache");
        }
        let completed = store
            .get_clipboard_cache(ClipboardCacheState::Completed)
            .expect("completed")
            .expect("completed record");
        assert_eq!(completed.state, ClipboardCacheState::Completed);
        assert!(
            store
                .get_clipboard_cache(ClipboardCacheState::InFlight)
                .expect("in flight")
                .is_some()
        );
        let status =
            OfferAttemptStatus::new(OfferAttemptCode::Completed, 1, 0, 0, None).expect("status");
        let _ = status;
    }
}
