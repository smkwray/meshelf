//! Rust-to-Kotlin events: the bounded queue the resident emits into, and the one JVM-attached
//! thread that drains it and invokes the Kotlin callbacks.

use std::{
    fmt, io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use jni::{
    Env, JValue,
    objects::{JObject, JString},
    refs::Global,
    vm::JavaVM,
};
use meshelf_core::{
    CaptureRequestId, MAX_TEXT_BYTES, validate_capture_label, validate_capture_purpose,
};
use meshelf_protocol::pairing::{PairingAbortCode, PairingId, Sas, TranscriptHash};
use serde::Serialize;
use thiserror::Error;

use crate::{
    ErrorLog,
    abi::{self, JniMethod},
    args::validate_device_name,
    invoke, lock,
};

/// Events waiting for the callback thread. A full queue refuses; it never grows.
pub const EVENT_QUEUE_CAPACITY: usize = 32;
const LOCAL_FRAME_CAPACITY: usize = 16;

/// One Kotlin callback, in typed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KotlinEvent {
    CaptureRequested {
        request_id: CaptureRequestId,
        requester_name: String,
        purpose: String,
        expires_at_unix_ms: u64,
    },
    CaptureWithdrawn {
        request_id: CaptureRequestId,
        reason: String,
    },
    CaptureDelivered {
        request_id: CaptureRequestId,
    },
    PeerAdmitted {
        device_name: String,
    },
    PairingCandidate {
        pairing_id: PairingId,
        device_name: String,
        code: Sas,
        transcript_hash: TranscriptHash,
        expires_at_unix_ms: u64,
    },
    PairingFinished {
        pairing_id: PairingId,
        outcome: PairingOutcome,
    },
    ShelfChanged,
    PlatformDispatchPrepared {
        dispatch_id: String,
        text: String,
        gesture_token: String,
    },
    /// Verified file ready for Save (SAF) or Share (FileProvider). Path is app-private.
    PlatformFileExportPrepared {
        dispatch_id: String,
        absolute_path: String,
        display_name: String,
        mime_hint: String,
        gesture_token: String,
        export_kind: String,
    },
}

/// The `onPairingFinished` result, pinned by plan amendment A11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingOutcome {
    Paired,
    Aborted(PairingAbortCode),
    /// Any internal error.
    Failed,
}

impl PairingOutcome {
    /// The only words Rust may send. Aborts use the protocol's snake_case abort-code names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Paired => "paired",
            Self::Failed => "failed",
            Self::Aborted(code) => match code {
                PairingAbortCode::WindowClosed => "window_closed",
                PairingAbortCode::Busy => "busy",
                PairingAbortCode::RateLimited => "rate_limited",
                PairingAbortCode::Timeout => "timeout",
                PairingAbortCode::Invalid => "invalid",
                PairingAbortCode::Declined => "declined",
                PairingAbortCode::IdentityChanged => "identity_changed",
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallArg {
    Text(String),
    Long(i64),
}

/// A validated callback ready for JNI: the method and its arguments in descriptor order.
#[derive(Debug)]
pub(crate) struct Invocation {
    pub(crate) method: JniMethod,
    pub(crate) args: Vec<CallArg>,
}

impl KotlinEvent {
    /// Converts to JNI arguments, refusing text Kotlin would reject and times a Java long cannot
    /// hold, so a malformed event is refused at the emitter instead of failing on the phone.
    pub(crate) fn invocation(&self) -> Result<Invocation, String> {
        use CallArg::{Long, Text};
        let (method, args) = match self {
            Self::CaptureRequested {
                request_id,
                requester_name,
                purpose,
                expires_at_unix_ms,
            } => {
                validate_capture_label(requester_name)
                    .map_err(|error| format!("requester name {error}"))?;
                validate_capture_purpose(purpose).map_err(|error| format!("purpose {error}"))?;
                (
                    abi::ON_CAPTURE_REQUESTED,
                    vec![
                        Text(request_id.to_string()),
                        Text(requester_name.clone()),
                        Text(purpose.clone()),
                        Long(java_time(*expires_at_unix_ms)?),
                    ],
                )
            }
            Self::CaptureWithdrawn { request_id, reason } => {
                validate_capture_label(reason).map_err(|error| format!("reason {error}"))?;
                (
                    abi::ON_CAPTURE_WITHDRAWN,
                    vec![Text(request_id.to_string()), Text(reason.clone())],
                )
            }
            Self::CaptureDelivered { request_id } => (
                abi::ON_CAPTURE_DELIVERED,
                vec![Text(request_id.to_string())],
            ),
            Self::PeerAdmitted { device_name } => {
                validate_device_name(device_name)?;
                (abi::ON_PEER_ADMITTED, vec![Text(device_name.clone())])
            }
            Self::PairingCandidate {
                pairing_id,
                device_name,
                code,
                transcript_hash,
                expires_at_unix_ms,
            } => {
                validate_device_name(device_name)?;
                (
                    abi::ON_PAIRING_CANDIDATE,
                    vec![
                        Text(protocol_hex(pairing_id)?),
                        Text(device_name.clone()),
                        Text(code.as_str().to_owned()),
                        Text(protocol_hex(transcript_hash)?),
                        Long(java_time(*expires_at_unix_ms)?),
                    ],
                )
            }
            Self::PairingFinished {
                pairing_id,
                outcome,
            } => (
                abi::ON_PAIRING_FINISHED,
                vec![
                    Text(protocol_hex(pairing_id)?),
                    Text(outcome.as_str().to_owned()),
                ],
            ),
            Self::ShelfChanged => (abi::ON_SHELF_CHANGED, vec![]),
            Self::PlatformDispatchPrepared {
                dispatch_id,
                text,
                gesture_token,
            } => {
                if dispatch_id.is_empty() {
                    return Err("dispatch id is empty".to_owned());
                }
                if gesture_token.is_empty() {
                    return Err("gesture token is empty".to_owned());
                }
                if text.len() > MAX_TEXT_BYTES {
                    return Err(format!(
                        "clipboard text is {} bytes; maximum is {MAX_TEXT_BYTES}",
                        text.len()
                    ));
                }
                (
                    abi::ON_PLATFORM_DISPATCH_PREPARED,
                    vec![
                        Text(dispatch_id.clone()),
                        Text(text.clone()),
                        Text(gesture_token.clone()),
                    ],
                )
            }
            Self::PlatformFileExportPrepared {
                dispatch_id,
                absolute_path,
                display_name,
                mime_hint,
                gesture_token,
                export_kind,
            } => {
                if dispatch_id.is_empty() {
                    return Err("dispatch id is empty".to_owned());
                }
                if absolute_path.is_empty() {
                    return Err("export path is empty".to_owned());
                }
                if display_name.is_empty() {
                    return Err("export display name is empty".to_owned());
                }
                if mime_hint.is_empty() {
                    return Err("export mime hint is empty".to_owned());
                }
                if gesture_token.is_empty() {
                    return Err("gesture token is empty".to_owned());
                }
                if export_kind != "SAVE" && export_kind != "SHARE" {
                    return Err("export kind must be SAVE or SHARE".to_owned());
                }
                (
                    abi::ON_PLATFORM_FILE_EXPORT_PREPARED,
                    vec![
                        Text(dispatch_id.clone()),
                        Text(absolute_path.clone()),
                        Text(display_name.clone()),
                        Text(mime_hint.clone()),
                        Text(gesture_token.clone()),
                        Text(export_kind.clone()),
                    ],
                )
            }
        };
        Ok(Invocation { method, args })
    }
}

fn java_time(unix_ms: u64) -> Result<i64, String> {
    i64::try_from(unix_ms).map_err(|_| "time does not fit a Java long".to_owned())
}

/// Renders a pairing value with the protocol's own wire encoding (lowercase hex).
fn protocol_hex(value: &impl Serialize) -> Result<String, String> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => Ok(text),
        _ => Err("pairing value did not render as hexadecimal text".to_owned()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EventRefused {
    #[error("the Kotlin event queue is full")]
    QueueFull,
    #[error("the native bridge is stopped")]
    Stopped,
    #[error("event refused: {0}")]
    Invalid(String),
}

/// The resident's handle for emitting Kotlin callbacks. Cloneable; every clone refuses once the
/// bridge stops, however many clones remain.
#[derive(Debug, Clone)]
pub struct EventSink {
    shared: Arc<EventChannel>,
}

#[derive(Debug)]
struct EventChannel {
    sender: Mutex<Option<SyncSender<Invocation>>>,
    errors: ErrorLog,
}

impl EventSink {
    pub(crate) fn channel(capacity: usize, errors: ErrorLog) -> (Self, Receiver<Invocation>) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let shared = Arc::new(EventChannel {
            sender: Mutex::new(Some(sender)),
            errors,
        });
        (Self { shared }, receiver)
    }

    /// Queues one callback without blocking. A refusal is returned to the caller, who must act on
    /// it (for example by not acknowledging a presentation), and a full queue is also recorded as
    /// the bridge's last error.
    pub fn emit(&self, event: KotlinEvent) -> Result<(), EventRefused> {
        let invocation = event.invocation().map_err(EventRefused::Invalid)?;
        let sender = lock(&self.shared.sender);
        let Some(sender) = sender.as_ref() else {
            return Err(EventRefused::Stopped);
        };
        match sender.try_send(invocation) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(invocation)) => {
                self.record_error(format!(
                    "Kotlin event queue full; {} refused",
                    invocation.method.name
                ));
                Err(EventRefused::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => Err(EventRefused::Stopped),
        }
    }

    /// Drops the only sender, so the callback thread's receive loop ends.
    pub(crate) fn close(&self) {
        lock(&self.shared.sender).take();
    }

    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.shared.sender).is_none()
    }

    pub(crate) fn record_error(&self, message: String) {
        self.shared.errors.record(message);
    }
}

/// Delivers queued callbacks in order until the channel closes. Anything still queued once the
/// bridge has stopped is discarded, and the count is recorded rather than dropped silently.
pub(crate) fn drain(
    receiver: &Receiver<Invocation>,
    events: &EventSink,
    mut deliver: impl FnMut(&Invocation) -> Result<(), String>,
) {
    let mut discarded = 0_usize;
    for invocation in receiver.iter() {
        if events.is_closed() {
            discarded += 1;
            continue;
        }
        match catch_unwind(AssertUnwindSafe(|| deliver(&invocation))) {
            Ok(Ok(())) => {}
            Ok(Err(problem)) => events.record_error(problem),
            Err(_) => events.record_error(format!("{} panicked", invocation.method.name)),
        }
    }
    if discarded > 0 {
        events.record_error(format!(
            "{discarded} Kotlin callbacks discarded because the bridge stopped"
        ));
    }
}

/// The single callback thread, with a join that gives up after a bound.
pub(crate) struct CallbackThread {
    handle: JoinHandle<()>,
    done: Receiver<()>,
}

impl fmt::Debug for CallbackThread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackThread")
    }
}

impl CallbackThread {
    pub(crate) fn spawn(body: impl FnOnce() + Send + 'static) -> io::Result<Self> {
        let (done_sender, done) = mpsc::channel::<()>();
        let handle = thread::Builder::new()
            .name("meshelf-callbacks".to_owned())
            .spawn(move || {
                // Dropped when the body returns or unwinds, which is what `join` waits for.
                let _done = done_sender;
                body();
            })?;
        Ok(Self { handle, done })
    }

    pub(crate) fn join(self, bound: Duration) -> Result<(), String> {
        match self.done.recv_timeout(bound) {
            Err(RecvTimeoutError::Timeout) => Err(format!(
                "callback thread did not stop within {} ms",
                bound.as_millis()
            )),
            Ok(()) | Err(RecvTimeoutError::Disconnected) => self
                .handle
                .join()
                .map_err(|_| "callback thread panicked".to_owned()),
        }
    }
}

/// Starts the callback thread: attached to the JVM for its whole life, it owns the one global
/// reference to the Kotlin object and deletes it on that attached thread when the channel closes.
pub(crate) fn spawn_jni_callbacks(
    vm: JavaVM,
    target: Global<JObject<'static>>,
    receiver: Receiver<Invocation>,
    events: EventSink,
) -> io::Result<CallbackThread> {
    CallbackThread::spawn(move || {
        let errors = events.clone();
        let attached = vm.attach_current_thread(move |env| -> jni::errors::Result<()> {
            drain(&receiver, &events, |invocation| {
                deliver(env, &target, invocation)
            });
            drop(target);
            Ok(())
        });
        if let Err(error) = attached {
            errors.record_error(format!(
                "callback thread could not attach to the JVM: {error}"
            ));
        }
    })
}

enum Prepared<'local> {
    Text(JString<'local>),
    Long(i64),
}

/// Invokes one callback inside its own local frame and clears any exception Kotlin threw, so one
/// failing callback never poisons the next.
fn deliver(
    env: &mut Env<'_>,
    target: &Global<JObject<'static>>,
    invocation: &Invocation,
) -> Result<(), String> {
    let method = invocation.method;
    let outcome = env.with_local_frame(LOCAL_FRAME_CAPACITY, |env| -> jni::errors::Result<()> {
        let prepared = invocation
            .args
            .iter()
            .map(|arg| match arg {
                CallArg::Text(text) => env.new_string(text).map(Prepared::Text),
                CallArg::Long(value) => Ok(Prepared::Long(*value)),
            })
            .collect::<jni::errors::Result<Vec<_>>>()?;
        let values: Vec<JValue<'_>> = prepared
            .iter()
            .map(|value| match value {
                Prepared::Text(text) => JValue::Object(text),
                Prepared::Long(value) => JValue::Long(*value),
            })
            .collect();
        invoke(env, target.as_obj(), method, &values)?;
        Ok(())
    });
    outcome.map_err(|error| match env.exception_catch() {
        Err(jni::errors::Error::CaughtJavaException { name, .. }) => {
            format!("{} threw {name}", method.name)
        }
        _ => format!("{} failed: {error}", method.name),
    })
}

#[cfg(test)]
mod tests {
    use jni::signature::RuntimeMethodSignature;
    use meshelf_protocol::pairing::sas;

    use super::*;

    fn samples() -> Vec<KotlinEvent> {
        let request_id = CaptureRequestId::new();
        let pairing_id = PairingId::from_bytes([0x11; 16]);
        let transcript_hash = TranscriptHash::from_bytes([0x22; 32]);
        vec![
            KotlinEvent::CaptureRequested {
                request_id,
                requester_name: "CEDAR".to_owned(),
                purpose: "Photograph the router label".to_owned(),
                expires_at_unix_ms: 1_700_000_180_000,
            },
            KotlinEvent::CaptureWithdrawn {
                request_id,
                reason: "cancelled".to_owned(),
            },
            KotlinEvent::CaptureDelivered { request_id },
            KotlinEvent::PeerAdmitted {
                device_name: "CEDAR".to_owned(),
            },
            KotlinEvent::PairingCandidate {
                pairing_id,
                device_name: "CEDAR".to_owned(),
                code: sas(&transcript_hash),
                transcript_hash,
                expires_at_unix_ms: 1_700_000_120_000,
            },
            KotlinEvent::PairingFinished {
                pairing_id,
                outcome: PairingOutcome::Paired,
            },
            KotlinEvent::ShelfChanged,
            KotlinEvent::PlatformDispatchPrepared {
                dispatch_id: "0f8fad5b-d9cb-469f-a165-70867728950e".to_owned(),
                text: "hello shelf".to_owned(),
                gesture_token: "gesture-1".to_owned(),
            },
            KotlinEvent::PlatformFileExportPrepared {
                dispatch_id: "1a2b3c4d-e5f6-7890-abcd-ef1234567890".to_owned(),
                absolute_path: "/data/user/0/com.meshelf.android/no_backup/meshelf/v2/state/clipboard-cache/candidate-x".to_owned(),
                display_name: "photo.jpg".to_owned(),
                mime_hint: "image/jpeg".to_owned(),
                gesture_token: "gesture-2".to_owned(),
                export_kind: "SAVE".to_owned(),
            },
        ]
    }

    /// The arguments Rust builds for each callback must have exactly the kinds its descriptor
    /// declares; JNI does not convert, so a mismatch is a runtime failure on the phone.
    #[test]
    fn every_event_callback_gets_arguments_matching_its_descriptor() {
        let mut covered = Vec::new();
        for event in samples() {
            let invocation = event.invocation().expect("valid sample");
            // `invoke` parses the descriptor at call time; it must parse to the same arity.
            let signature =
                RuntimeMethodSignature::from_str(invocation.method.descriptor).expect("descriptor");
            assert_eq!(
                signature.method_signature().args().len(),
                invocation.args.len()
            );
            let built: String = invocation
                .args
                .iter()
                .map(|arg| match arg {
                    CallArg::Text(_) => "Ljava/lang/String;",
                    CallArg::Long(_) => "J",
                })
                .collect();
            assert_eq!(format!("({built})V"), invocation.method.descriptor);
            covered.push(invocation.method.name);
        }
        covered.sort_unstable();
        let mut callbacks: Vec<&str> = abi::CALLBACK_METHODS
            .iter()
            .map(|method| method.name)
            .filter(|name| name.starts_with("on"))
            .collect();
        callbacks.sort_unstable();
        assert_eq!(covered, callbacks, "every on* callback has an event");
    }

    #[test]
    fn pairing_values_render_as_kotlin_expects() {
        let invocation = samples()[4].invocation().expect("candidate");
        assert_eq!(
            invocation.args[0],
            CallArg::Text("11".repeat(16)),
            "32 lowercase hex"
        );
        assert_eq!(invocation.args[3], CallArg::Text("22".repeat(32)));
        let CallArg::Text(code) = &invocation.args[2] else {
            panic!("code is text");
        };
        assert!(code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn pairing_results_are_exactly_the_a11_words() {
        use PairingAbortCode::*;
        let codes = [
            WindowClosed,
            Busy,
            RateLimited,
            Timeout,
            Invalid,
            Declined,
            IdentityChanged,
        ];
        for code in codes {
            let wire = serde_json::to_value(code).expect("abort code");
            assert_eq!(wire.as_str(), Some(PairingOutcome::Aborted(code).as_str()));
        }
        let mut words: Vec<&str> = codes
            .into_iter()
            .map(PairingOutcome::Aborted)
            .chain([PairingOutcome::Paired, PairingOutcome::Failed])
            .map(PairingOutcome::as_str)
            .collect();
        words.sort_unstable();
        let mut a11 = vec![
            "paired",
            "declined",
            "window_closed",
            "timeout",
            "busy",
            "rate_limited",
            "invalid",
            "identity_changed",
            "failed",
        ];
        a11.sort_unstable();
        assert_eq!(words, a11);
    }

    #[test]
    fn queue_is_bounded_and_refuses_rather_than_grows() {
        let errors = ErrorLog::default();
        let (events, receiver) = EventSink::channel(EVENT_QUEUE_CAPACITY, errors.clone());
        let delivered = KotlinEvent::CaptureDelivered {
            request_id: CaptureRequestId::new(),
        };
        for _ in 0..EVENT_QUEUE_CAPACITY {
            events.emit(delivered.clone()).expect("room in the queue");
        }
        assert_eq!(events.emit(delivered.clone()), Err(EventRefused::QueueFull));
        assert!(errors.latest().expect("recorded").contains("queue full"));
        assert_eq!(receiver.try_iter().count(), EVENT_QUEUE_CAPACITY);
        events.close();
        assert_eq!(events.emit(delivered), Err(EventRefused::Stopped));
    }

    #[test]
    fn events_kotlin_would_reject_are_refused_before_queueing() {
        let (events, receiver) = EventSink::channel(EVENT_QUEUE_CAPACITY, ErrorLog::default());
        let request_id = CaptureRequestId::new();
        let refused = [
            KotlinEvent::CaptureRequested {
                request_id,
                requester_name: "CEDAR".to_owned(),
                purpose: "look \u{202e}here".to_owned(),
                expires_at_unix_ms: 1,
            },
            KotlinEvent::CaptureRequested {
                request_id,
                requester_name: "CEDAR".to_owned(),
                purpose: "ok".to_owned(),
                expires_at_unix_ms: u64::MAX,
            },
            KotlinEvent::PeerAdmitted {
                device_name: "x".repeat(81),
            },
        ];
        for event in refused {
            assert!(matches!(events.emit(event), Err(EventRefused::Invalid(_))));
        }
        assert_eq!(receiver.try_iter().count(), 0);
    }

    #[test]
    fn drain_delivers_in_order_then_counts_what_it_discards_after_stop() {
        let errors = ErrorLog::default();
        let (events, receiver) = EventSink::channel(4, errors.clone());
        for request_id in [CaptureRequestId::new(), CaptureRequestId::new()] {
            events
                .emit(KotlinEvent::CaptureDelivered { request_id })
                .expect("queued");
        }
        let mut seen = 0;
        let sink = events.clone();
        let consumer = thread::spawn(move || {
            drain(&receiver, &sink, |invocation| {
                seen += 1;
                if seen == 2 {
                    return Err(format!("{} threw java.lang.X", invocation.method.name));
                }
                Ok(())
            });
            seen
        });
        // Wait for both deliveries, then queue two more and stop before they can be delivered.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while errors.latest().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "second delivery never failed"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            errors.latest().as_deref(),
            Some("onCaptureDelivered threw java.lang.X")
        );
        let stopped_sender = lock(&events.shared.sender).clone().expect("open");
        events.close();
        for _ in 0..2 {
            stopped_sender
                .try_send(
                    KotlinEvent::CaptureDelivered {
                        request_id: CaptureRequestId::new(),
                    }
                    .invocation()
                    .expect("valid"),
                )
                .expect("queued after close");
        }
        drop(stopped_sender);
        assert_eq!(
            consumer.join().expect("consumer"),
            2,
            "no delivery after stop"
        );
        assert_eq!(
            errors.latest().as_deref(),
            Some("2 Kotlin callbacks discarded because the bridge stopped")
        );
    }
}
