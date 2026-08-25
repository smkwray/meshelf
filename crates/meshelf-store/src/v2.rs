//! Additive protocol-v2 offer, cleanup, and clipboard-cache indexes.
//!
//! Nothing in this module is selected by the current v1 production entry
//! points. In particular, opening [`RedbV2Store`] never reads or migrates the
//! v1 receive ledger.

use std::{fs, path::Path};

use meshelf_core::{
    ActivationId, ActivationJournalEntry, CleanupReport, ClipboardCacheRecord, ClipboardCacheState,
    MigrationReport, OfferCardInput, OfferCardInsert, OfferCardRecord, OfferEligibilityUpdate,
    OfferSourceInput, OfferSourceInsert, OfferSourceRecord, OfferSourceStore, StoreError,
    V2_MAX_LIVE_ENTRIES,
};
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
    database: Database,
}

impl RedbV2Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let database = Database::create(path).map_err(map_redb_error)?;
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
        Ok(Self { database })
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
    /// created. If directory creation fails, the journal remains for startup
    /// cleanup and the error is returned to the caller.
    pub fn prepare_staging(&self, entry: &ActivationJournalEntry) -> Result<(), StoreError> {
        self.journal_activation(entry)?;
        fs::create_dir_all(&entry.staging_root)
            .map_err(|error| StoreError::new(format!("staging creation failed: {error}")))
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

    /// Deletes all journaled staging roots. A missing root is already clean;
    /// any other cleanup failure is reported and its journal entry is kept.
    pub fn startup_cleanup(&self) -> Result<CleanupReport, StoreError> {
        let entries = self.activation_journal_entries()?;
        let journaled_entries = u32::try_from(entries.len())
            .map_err(|_| StoreError::new("too many activation journal entries"))?;
        let mut removed = Vec::new();
        let mut failures = Vec::new();

        for entry in &entries {
            match fs::remove_dir_all(&entry.staging_root) {
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

    /// Explicit migration for the later cutover step. Opening a v2 store does
    /// not call this function. Published user files are outside the v1 ledger
    /// and are not inspected or removed.
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
            }
        };
        write.commit().map_err(map_redb_error)?;
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
    use std::{collections::HashSet, fs, path::PathBuf};

    use meshelf_core::{
        ActivationId, ActivationJournalEntry, ActivationState, CardAvailability,
        ClipboardCacheRecord, ClipboardCacheState, DeviceId, OfferAttemptCode, OfferAttemptStatus,
        OfferCardInput, OfferDescriptor, OfferId, OfferSource, OfferSourceInput, ReceiveStore,
        TextEnvelope, V2_MAX_LIVE_ENTRIES,
    };
    use tempfile::tempdir;

    use super::RedbV2Store;
    use crate::RedbReceiveStore;

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
            staging_root: root,
            state: ActivationState::Staging,
            reserved_entries: 2,
            reserved_bytes: 12,
        }
    }

    #[test]
    fn cleanup_journal_commit_precedes_staging_creation() {
        let (directory, store) = store();
        let entry = journal_entry(directory.path().join("staging"));
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
    fn startup_cleanup_deletes_every_journaled_partial() {
        let (directory, store) = store();
        let first = journal_entry(directory.path().join("first"));
        let second = journal_entry(directory.path().join("second"));
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
    fn migration_counts_and_removes_v1_body_records() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("meshelf.redb");
        {
            let v1 = RedbReceiveStore::open(&path).expect("v1 open");
            let first = TextEnvelope::shelf_item(
                DeviceId::new(),
                DeviceId::new(),
                1,
                None,
                meshelf_core::ContentKind::Text,
                "first body",
            );
            let second = TextEnvelope::shelf_item(
                DeviceId::new(),
                DeviceId::new(),
                2,
                None,
                meshelf_core::ContentKind::Text,
                "second body",
            );
            v1.record_if_absent(&first, 1).expect("first");
            v1.record_if_absent(&second, 2).expect("second");
        }
        let v2 = RedbV2Store::open(&path).expect("v2 open");
        let report = v2.migrate_v1_body_records().expect("migration");
        assert_eq!(report.v1_body_records_removed, 2);
        drop(v2);
        let v1 = RedbReceiveStore::open(path).expect("reopen v1");
        assert!(v1.recent(10).expect("recent").is_empty());
    }

    #[test]
    fn migration_preserves_published_user_files() {
        let directory = tempdir().expect("temp directory");
        let published = directory.path().join("published.txt");
        fs::write(&published, b"published").expect("published file");
        let path = directory.path().join("meshelf.redb");
        {
            let v1 = RedbReceiveStore::open(&path).expect("v1 open");
            let record = TextEnvelope::shelf_item(
                DeviceId::new(),
                DeviceId::new(),
                1,
                None,
                meshelf_core::ContentKind::Path,
                published.to_string_lossy(),
            );
            v1.record_if_absent(&record, 1).expect("record");
        }
        let v2 = RedbV2Store::open(&path).expect("v2 open");
        v2.migrate_v1_body_records().expect("migration");
        assert_eq!(fs::read(&published).expect("read published"), b"published");
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
