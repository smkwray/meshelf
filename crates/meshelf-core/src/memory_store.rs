use std::{collections::HashMap, sync::Mutex};

use crate::{
    MessageId, ReceivePhase, ReceiveRecord, ReceiveState, ReceiveStore, StoreError, TextEnvelope,
    TransitionOutcome,
};

#[derive(Debug, Default)]
pub struct MemoryReceiveStore {
    records: Mutex<HashMap<MessageId, ReceiveRecord>>,
}

impl MemoryReceiveStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReceiveStore for MemoryReceiveStore {
    fn record_if_absent(
        &self,
        envelope: &TextEnvelope,
        now_unix_ms: u64,
    ) -> Result<ReceiveRecord, StoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| StoreError::new("memory store mutex poisoned"))?;
        let record = records
            .entry(envelope.message_id)
            .or_insert_with(|| ReceiveRecord {
                envelope: envelope.clone(),
                state: ReceiveState::recorded(),
                first_seen_unix_ms: now_unix_ms,
                updated_at_unix_ms: now_unix_ms,
            });
        Ok(record.clone())
    }

    fn get(&self, message_id: MessageId) -> Result<Option<ReceiveRecord>, StoreError> {
        let records = self
            .records
            .lock()
            .map_err(|_| StoreError::new("memory store mutex poisoned"))?;
        Ok(records.get(&message_id).cloned())
    }

    fn transition(
        &self,
        message_id: MessageId,
        expected: ReceivePhase,
        next: ReceiveState,
        now_unix_ms: u64,
    ) -> Result<TransitionOutcome, StoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| StoreError::new("memory store mutex poisoned"))?;
        let Some(record) = records.get_mut(&message_id) else {
            return Ok(TransitionOutcome::Missing);
        };
        if record.state.phase != expected {
            return Ok(TransitionOutcome::Mismatch(record.clone()));
        }
        record.state = next;
        record.updated_at_unix_ms = now_unix_ms;
        Ok(TransitionOutcome::Changed(record.clone()))
    }
}
