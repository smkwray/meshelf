//! Durable redb-backed receive ledger.

use std::path::Path;

use meshelf_core::{
    MessageId, ReceivePhase, ReceiveRecord, ReceiveState, ReceiveStore, StoreError, TextEnvelope,
    TransitionOutcome,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const RECEIVE_LEDGER: TableDefinition<&str, &[u8]> = TableDefinition::new("receive_ledger_v1");

#[derive(Debug)]
pub struct RedbReceiveStore {
    database: Database,
}

impl RedbReceiveStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let database = Database::create(path).map_err(map_redb_error)?;
        // Materialize the table at startup so the first receive cannot discover a schema error.
        let write = database.begin_write().map_err(map_redb_error)?;
        {
            write.open_table(RECEIVE_LEDGER).map_err(map_redb_error)?;
        }
        write.commit().map_err(map_redb_error)?;
        Ok(Self { database })
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<ReceiveRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read.open_table(RECEIVE_LEDGER).map_err(map_redb_error)?;
        let mut records = Vec::new();
        for entry in table.iter().map_err(map_redb_error)? {
            let (_, value) = entry.map_err(map_redb_error)?;
            records.push(decode_record(value.value())?);
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.first_seen_unix_ms));
        records.truncate(limit);
        Ok(records)
    }
}

impl ReceiveStore for RedbReceiveStore {
    fn record_if_absent(
        &self,
        envelope: &TextEnvelope,
        now_unix_ms: u64,
    ) -> Result<ReceiveRecord, StoreError> {
        let key = envelope.message_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let result = {
            let mut table = write.open_table(RECEIVE_LEDGER).map_err(map_redb_error)?;
            let existing = table
                .get(key.as_str())
                .map_err(map_redb_error)?
                .map(|guard| guard.value().to_vec());
            if let Some(bytes) = existing {
                decode_record(&bytes)?
            } else {
                let record = ReceiveRecord {
                    envelope: envelope.clone(),
                    state: ReceiveState::recorded(),
                    first_seen_unix_ms: now_unix_ms,
                    updated_at_unix_ms: now_unix_ms,
                };
                let encoded = encode_record(&record)?;
                table
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(map_redb_error)?;
                record
            }
        };
        write.commit().map_err(map_redb_error)?;
        Ok(result)
    }

    fn get(&self, message_id: MessageId) -> Result<Option<ReceiveRecord>, StoreError> {
        let key = message_id.to_string();
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read.open_table(RECEIVE_LEDGER).map_err(map_redb_error)?;
        let bytes = table
            .get(key.as_str())
            .map_err(map_redb_error)?
            .map(|guard| guard.value().to_vec());
        bytes.map(|value| decode_record(&value)).transpose()
    }

    fn transition(
        &self,
        message_id: MessageId,
        expected: ReceivePhase,
        next: ReceiveState,
        now_unix_ms: u64,
    ) -> Result<TransitionOutcome, StoreError> {
        let key = message_id.to_string();
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let outcome = {
            let mut table = write.open_table(RECEIVE_LEDGER).map_err(map_redb_error)?;
            let bytes = table
                .get(key.as_str())
                .map_err(map_redb_error)?
                .map(|guard| guard.value().to_vec());
            let Some(bytes) = bytes else {
                return Ok(TransitionOutcome::Missing);
            };
            let mut record = decode_record(&bytes)?;
            if record.state.phase != expected {
                TransitionOutcome::Mismatch(record)
            } else {
                record.state = next;
                record.updated_at_unix_ms = now_unix_ms;
                let encoded = encode_record(&record)?;
                table
                    .insert(key.as_str(), encoded.as_slice())
                    .map_err(map_redb_error)?;
                TransitionOutcome::Changed(record)
            }
        };
        write.commit().map_err(map_redb_error)?;
        Ok(outcome)
    }
}

fn encode_record(record: &ReceiveRecord) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(record).map_err(|error| StoreError::new(error.to_string()))
}

fn decode_record(bytes: &[u8]) -> Result<ReceiveRecord, StoreError> {
    serde_json::from_slice(bytes).map_err(|error| StoreError::new(error.to_string()))
}

fn map_redb_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use meshelf_core::{DeviceId, ReceiveStore, TextEnvelope};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn persists_across_reopen_and_transitions_atomically() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("meshelf.redb");
        let source = DeviceId::new();
        let target = DeviceId::new();
        let envelope = TextEnvelope::clipboard_push(source, target, 100, None, "persistent");

        {
            let store = RedbReceiveStore::open(&path).expect("open store");
            let record = store
                .record_if_absent(&envelope, 100)
                .expect("record message");
            assert_eq!(record.state.phase, ReceivePhase::Recorded);
            let transition = store
                .transition(
                    envelope.message_id,
                    ReceivePhase::Recorded,
                    ReceiveState::applying(),
                    101,
                )
                .expect("claim");
            assert!(matches!(transition, TransitionOutcome::Changed(_)));
        }

        let reopened = RedbReceiveStore::open(&path).expect("reopen store");
        let record = reopened
            .get(envelope.message_id)
            .expect("read")
            .expect("record exists");
        assert_eq!(record.state.phase, ReceivePhase::Applying);
    }

    #[test]
    fn check_and_insert_preserves_first_payload_for_duplicate_id() {
        let directory = tempdir().expect("temp directory");
        let store =
            RedbReceiveStore::open(directory.path().join("meshelf.redb")).expect("open store");
        let first =
            TextEnvelope::clipboard_push(DeviceId::new(), DeviceId::new(), 100, None, "first");
        let id = first.message_id;
        let mut second = first.clone();
        second.text = "second".to_owned();
        second.message_id = id;

        store.record_if_absent(&first, 100).expect("insert first");
        let existing = store.record_if_absent(&second, 101).expect("read existing");
        assert_eq!(existing.envelope.text, "first");
    }

    #[test]
    fn recent_returns_newest_records_first() {
        let directory = tempdir().expect("temp directory");
        let store =
            RedbReceiveStore::open(directory.path().join("meshelf.redb")).expect("open store");
        let first = TextEnvelope::shelf_item(
            DeviceId::new(),
            DeviceId::new(),
            100,
            None,
            meshelf_core::ContentKind::Text,
            "first",
        );
        let second = TextEnvelope::shelf_item(
            DeviceId::new(),
            DeviceId::new(),
            200,
            None,
            meshelf_core::ContentKind::Path,
            "/tmp/second",
        );
        store.record_if_absent(&first, 100).expect("insert first");
        store.record_if_absent(&second, 200).expect("insert second");

        let records = store.recent(2).expect("read recent");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].envelope.text, "/tmp/second");
        assert_eq!(records[1].envelope.text, "first");
    }
}
