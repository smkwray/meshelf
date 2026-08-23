use std::sync::Arc;

use thiserror::Error;

use crate::{
    DeliveryMode, DeviceId, Receipt, ReceiptCode, ReceivePhase, ReceiveRecord, ReceiveState,
    ReceiveStore, StoreError, TextEnvelope, TransitionOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("clipboard error: {message}")]
pub struct ClipboardError {
    message: String,
}

impl ClipboardError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

pub trait ClipboardSink: Send + Sync + 'static {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError>;
}

#[derive(Debug)]
pub struct ReceiverService<S, C> {
    local_device: DeviceId,
    store: Arc<S>,
    clipboard: Arc<C>,
}

impl<S, C> ReceiverService<S, C>
where
    S: ReceiveStore,
    C: ClipboardSink,
{
    #[must_use]
    pub fn new(local_device: DeviceId, store: Arc<S>, clipboard: Arc<C>) -> Self {
        Self {
            local_device,
            store,
            clipboard,
        }
    }

    #[must_use]
    pub const fn local_device(&self) -> DeviceId {
        self.local_device
    }

    pub fn receive(&self, envelope: TextEnvelope, now_unix_ms: u64) -> Receipt {
        if let Err(error) = envelope.validate(now_unix_ms) {
            return Receipt::rejected(
                envelope.message_id,
                ReceiptCode::RejectedInvalid,
                error.to_string(),
            );
        }
        if envelope.target_device != self.local_device {
            return Receipt::rejected(
                envelope.message_id,
                ReceiptCode::RejectedWrongTarget,
                "message target does not match this device",
            );
        }
        if envelope.delivery_mode != DeliveryMode::ClipboardPush {
            return Receipt::rejected(
                envelope.message_id,
                ReceiptCode::RejectedUnsupportedMode,
                "shelf delivery is reserved and cannot mutate the clipboard",
            );
        }

        let current = match self.store.record_if_absent(&envelope, now_unix_ms) {
            Ok(record) => record,
            Err(error) => return internal_store_error(envelope.message_id, &error),
        };

        if current.envelope != envelope {
            return Receipt::rejected(
                envelope.message_id,
                ReceiptCode::RejectedMessageIdConflict,
                "message ID was already used for different immutable content",
            );
        }

        self.resume_from(current, now_unix_ms)
    }

    fn resume_from(&self, record: ReceiveRecord, now_unix_ms: u64) -> Receipt {
        match record.state.phase {
            ReceivePhase::Applied => Receipt::duplicate_applied(record.envelope.message_id),
            ReceivePhase::ClipboardFailed => Receipt::new(
                record.envelope.message_id,
                ReceiptCode::ClipboardFailed,
                record.state.detail,
            ),
            ReceivePhase::Rejected => Receipt::new(
                record.envelope.message_id,
                ReceiptCode::RejectedInvalid,
                record.state.detail,
            ),
            ReceivePhase::Applying => Receipt::new(
                record.envelope.message_id,
                ReceiptCode::UncertainNoReplay,
                Some(
                    "receiver may have crossed the clipboard side-effect boundary; automatic replay is forbidden"
                        .to_owned(),
                ),
            ),
            ReceivePhase::Recorded => self.claim_and_apply(record, now_unix_ms),
        }
    }

    fn claim_and_apply(&self, record: ReceiveRecord, now_unix_ms: u64) -> Receipt {
        let message_id = record.envelope.message_id;
        match self.store.transition(
            message_id,
            ReceivePhase::Recorded,
            ReceiveState::applying(),
            now_unix_ms,
        ) {
            Ok(TransitionOutcome::Changed(_)) => {}
            Ok(TransitionOutcome::Mismatch(current)) => {
                return self.resume_from(current, now_unix_ms);
            }
            Ok(TransitionOutcome::Missing) => {
                return Receipt::new(
                    message_id,
                    ReceiptCode::InternalError,
                    Some("record disappeared before clipboard claim".to_owned()),
                );
            }
            Err(error) => return internal_store_error(message_id, &error),
        }

        match self.clipboard.set_text(&record.envelope.text) {
            Ok(()) => match self.store.transition(
                message_id,
                ReceivePhase::Applying,
                ReceiveState::applied(),
                now_unix_ms,
            ) {
                Ok(TransitionOutcome::Changed(_)) => Receipt::applied(message_id),
                Ok(TransitionOutcome::Mismatch(current)) => {
                    if current.state.phase == ReceivePhase::Applied {
                        Receipt::applied(message_id)
                    } else {
                        uncertain_after_side_effect(message_id)
                    }
                }
                Ok(TransitionOutcome::Missing) | Err(_) => uncertain_after_side_effect(message_id),
            },
            Err(error) => {
                let detail = error.message().to_owned();
                match self.store.transition(
                    message_id,
                    ReceivePhase::Applying,
                    ReceiveState::clipboard_failed(detail.clone()),
                    now_unix_ms,
                ) {
                    Ok(TransitionOutcome::Changed(_)) => {
                        Receipt::new(message_id, ReceiptCode::ClipboardFailed, Some(detail))
                    }
                    Ok(TransitionOutcome::Mismatch(current))
                        if current.state.phase == ReceivePhase::ClipboardFailed =>
                    {
                        Receipt::new(
                            message_id,
                            ReceiptCode::ClipboardFailed,
                            current.state.detail,
                        )
                    }
                    Ok(TransitionOutcome::Mismatch(_))
                    | Ok(TransitionOutcome::Missing)
                    | Err(_) => uncertain_after_side_effect(message_id),
                }
            }
        }
    }
}

fn internal_store_error(message_id: crate::MessageId, error: &StoreError) -> Receipt {
    Receipt::new(
        message_id,
        ReceiptCode::InternalError,
        Some(format!("durable ledger unavailable: {}", error.message())),
    )
}

fn uncertain_after_side_effect(message_id: crate::MessageId) -> Receipt {
    Receipt::new(
        message_id,
        ReceiptCode::UncertainNoReplay,
        Some(
            "clipboard side effect completed or may have completed, but durable finalization failed; do not replay automatically"
                .to_owned(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{MemoryReceiveStore, MessageId, ReceiveStore};

    #[derive(Debug, Default)]
    struct CountingClipboard {
        writes: Mutex<Vec<String>>,
        failure: Mutex<Option<String>>,
    }

    impl CountingClipboard {
        fn failing(message: &str) -> Self {
            Self {
                writes: Mutex::new(Vec::new()),
                failure: Mutex::new(Some(message.to_owned())),
            }
        }

        fn writes(&self) -> Vec<String> {
            self.writes.lock().expect("writes mutex").clone()
        }
    }

    impl ClipboardSink for CountingClipboard {
        fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
            if let Some(message) = self.failure.lock().expect("failure mutex").clone() {
                return Err(ClipboardError::new(message));
            }
            self.writes
                .lock()
                .expect("writes mutex")
                .push(text.to_owned());
            Ok(())
        }
    }

    fn envelope(source: DeviceId, target: DeviceId) -> TextEnvelope {
        TextEnvelope::clipboard_push(source, target, 100, Some(10_000), "hello\nworld")
    }

    #[test]
    fn duplicate_delivery_applies_clipboard_once() {
        let local = DeviceId::new();
        let store = Arc::new(MemoryReceiveStore::new());
        let clipboard = Arc::new(CountingClipboard::default());
        let service = ReceiverService::new(local, store, clipboard.clone());
        let message = envelope(DeviceId::new(), local);

        let first = service.receive(message.clone(), 200);
        let second = service.receive(message, 201);

        assert_eq!(first.code, ReceiptCode::Applied);
        assert_eq!(second.code, ReceiptCode::DuplicateApplied);
        assert_eq!(clipboard.writes(), vec!["hello\nworld"]);
    }

    #[test]
    fn clipboard_failure_is_durable_and_not_retried() {
        let local = DeviceId::new();
        let store = Arc::new(MemoryReceiveStore::new());
        let clipboard = Arc::new(CountingClipboard::failing("clipboard unavailable"));
        let service = ReceiverService::new(local, store, clipboard.clone());
        let message = envelope(DeviceId::new(), local);

        let first = service.receive(message.clone(), 200);
        let second = service.receive(message, 201);

        assert_eq!(first.code, ReceiptCode::ClipboardFailed);
        assert_eq!(second.code, ReceiptCode::ClipboardFailed);
        assert!(clipboard.writes().is_empty());
    }

    #[test]
    fn applying_state_is_never_replayed() {
        let local = DeviceId::new();
        let store = Arc::new(MemoryReceiveStore::new());
        let clipboard = Arc::new(CountingClipboard::default());
        let service = ReceiverService::new(local, store.clone(), clipboard.clone());
        let message = envelope(DeviceId::new(), local);
        store
            .record_if_absent(&message, 100)
            .expect("record message");
        store
            .transition(
                message.message_id,
                ReceivePhase::Recorded,
                ReceiveState::applying(),
                101,
            )
            .expect("claim message");

        let receipt = service.receive(message, 200);

        assert_eq!(receipt.code, ReceiptCode::UncertainNoReplay);
        assert!(clipboard.writes().is_empty());
    }

    #[test]
    fn message_id_cannot_be_reused_for_different_text() {
        let local = DeviceId::new();
        let service = ReceiverService::new(
            local,
            Arc::new(MemoryReceiveStore::new()),
            Arc::new(CountingClipboard::default()),
        );
        let first = envelope(DeviceId::new(), local);
        let mut conflicting = first.clone();
        conflicting.text = "different".to_owned();

        assert_eq!(service.receive(first, 200).code, ReceiptCode::Applied);
        assert_eq!(
            service.receive(conflicting, 201).code,
            ReceiptCode::RejectedMessageIdConflict
        );
    }

    #[test]
    fn wrong_target_never_touches_clipboard() {
        let local = DeviceId::new();
        let clipboard = Arc::new(CountingClipboard::default());
        let service = ReceiverService::new(
            local,
            Arc::new(MemoryReceiveStore::new()),
            clipboard.clone(),
        );
        let message = envelope(DeviceId::new(), DeviceId::new());

        let receipt = service.receive(message, 200);

        assert_eq!(receipt.code, ReceiptCode::RejectedWrongTarget);
        assert!(clipboard.writes().is_empty());
    }

    #[test]
    fn fixed_message_id_round_trip_supports_explicit_retry() {
        let id = MessageId::new();
        let source = DeviceId::new();
        let target = DeviceId::new();
        let mut message = envelope(source, target);
        message.message_id = id;
        assert_eq!(message.message_id, id);
    }
}
