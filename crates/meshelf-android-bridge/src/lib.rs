//! Rust half of the Android JNI ABI-8 bridge.
//!
//! This crate owns the JNI mechanics (the instance-method exports, the global references to
//! the Kotlin object, the callback thread), the lifecycle, the identity hooks, and VPN socket
//! binding, and it starts the phone resident behind [`host::PhoneHost`]. A native that needs the
//! resident before one is attached throws `IllegalStateException("phone resident not wired")` after
//! validating its arguments.
//!
//! Bad arguments and wrong state reach Kotlin as thrown exceptions (`IllegalArgumentException`,
//! `IllegalStateException`), never as return codes, because Kotlin reads a normal return as
//! success. Shelf activation outcomes are returned as result objects. Every export runs inside `EnvUnowned::with_env`, which catches panics,
//! so nothing unwinds across the FFI boundary.

pub mod abi;
pub mod args;
pub mod binder;
pub mod events;
pub mod host;
pub mod platform_clipboard;
pub mod platform_documents;

use std::{
    io,
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, mpsc::Receiver},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jni::{
    Env, EnvUnowned, JValue, JValueOwned,
    errors::ErrorPolicy,
    jni_str,
    objects::{JByteArray, JObject, JString},
    signature::RuntimeMethodSignature,
    strings::{JNIStr, JNIString},
    sys::{jint, jlong},
};
use meshelf_identity::InstallationIdentity;
use serde_json::json;
use thiserror::Error;

pub use abi::ANDROID_ABI_VERSION;
use abi::JniMethod;
use args::{
    CapturedFile, DeclineReason, StartArgs, pairing_window_deadline, parse_pairing_id,
    parse_request_id, parse_transcript_hash,
};
use binder::platform_binder;
use events::{CallbackThread, EVENT_QUEUE_CAPACITY, EventSink, Invocation};
use host::{PhoneHost, PhoneHostContext, start_phone_host};
use platform_clipboard::PlatformClipboard;
use platform_documents::PlatformDocuments;

/// The message of every forwarding native while no resident is plugged in.
pub const RESIDENT_NOT_WIRED: &str = "phone resident not wired";
const NOT_STARTED: &str = "meshelf native is not started";
const ALREADY_STARTED: &str = "meshelf native is already started";
const WORKER_THREADS: usize = 2;
const STOP_BOUNDS: StopBounds = StopBounds {
    runtime: Duration::from_secs(2),
    callbacks: Duration::from_secs(2),
};

/// A failure the export turns into a Java exception.
#[derive(Debug, Error)]
pub enum NativeError {
    /// Thrown as `IllegalArgumentException`.
    #[error("{0}")]
    InvalidArgument(String),
    /// Thrown as `IllegalStateException`.
    #[error("{0}")]
    IllegalState(String),
    /// A pending Java exception propagates unchanged; otherwise `IllegalStateException`.
    #[error("JNI failure: {0}")]
    Jni(#[from] jni::errors::Error),
}

pub(crate) fn invalid(message: impl Into<String>) -> NativeError {
    NativeError::InvalidArgument(message.into())
}

pub(crate) fn state(message: impl Into<String>) -> NativeError {
    NativeError::IllegalState(message.into())
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The latest failure that has no caller to throw to (callback delivery, a full queue, a bounded
/// stop), reported as `last_error` by `nativeStatus`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ErrorLog(Arc<Mutex<Option<String>>>);

impl ErrorLog {
    pub(crate) fn record(&self, message: String) {
        *lock(&self.0) = Some(message);
    }

    pub(crate) fn latest(&self) -> Option<String> {
        lock(&self.0).clone()
    }
}

/// The one process-wide slot for the running state.
#[derive(Default)]
struct Bridge {
    running: Mutex<Option<Running>>,
    errors: ErrorLog,
}

static BRIDGE: LazyLock<Bridge> = LazyLock::new(Bridge::default);

struct Running {
    runtime: tokio::runtime::Runtime,
    events: EventSink,
    callbacks: CallbackThread,
    clipboard: Arc<PlatformClipboard>,
    host: Option<Arc<dyn PhoneHost>>,
}

#[derive(Debug, Clone, Copy)]
struct StopBounds {
    runtime: Duration,
    callbacks: Duration,
}

impl Running {
    fn launch(
        args: StartArgs,
        identity: InstallationIdentity,
        errors: ErrorLog,
        spawn_callbacks: impl FnOnce(Receiver<Invocation>, EventSink) -> io::Result<CallbackThread>,
        start_host: impl FnOnce(PhoneHostContext) -> Result<Option<Arc<dyn PhoneHost>>, NativeError>,
    ) -> Result<Self, NativeError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .thread_name("meshelf-runtime")
            .enable_all()
            .build()
            .map_err(|error| state(format!("could not start the async runtime: {error}")))?;
        let (events, receiver) = EventSink::channel(EVENT_QUEUE_CAPACITY, errors.clone());
        let clipboard = PlatformClipboard::new(events.clone());
        let callbacks = spawn_callbacks(receiver, events.clone())
            .map_err(|error| state(format!("could not start the callback thread: {error}")))?;
        let context = PhoneHostContext {
            identity,
            state_dir: args.state_dir,
            local_address: args.local_address,
            device_name: args.device_name,
            binder: platform_binder(args.network),
            events: events.clone(),
            runtime: runtime.handle().clone(),
            documents: None,
        };
        let mut running = Self {
            runtime,
            events,
            callbacks,
            clipboard,
            host: None,
        };
        match start_host(context) {
            Ok(host) => {
                running.host = host;
                Ok(running)
            }
            Err(error) => {
                if let Err(problem) = running.stop(STOP_BOUNDS) {
                    errors.record(problem);
                }
                Err(error)
            }
        }
    }

    /// Resident first, then the runtime with a bound, then the event channel, then a bounded join
    /// of the callback thread, which deletes the global reference on its own attached thread.
    fn stop(self, bounds: StopBounds) -> Result<(), String> {
        let Self {
            runtime,
            events,
            callbacks,
            clipboard: _clipboard,
            host,
        } = self;
        if let Some(host) = host {
            host.shutdown();
        }
        runtime.shutdown_timeout(bounds.runtime);
        events.close();
        callbacks.join(bounds.callbacks)
    }
}

impl Bridge {
    fn install(
        &self,
        launch: impl FnOnce() -> Result<Running, NativeError>,
    ) -> Result<(), NativeError> {
        let mut slot = lock(&self.running);
        if slot.is_some() {
            return Err(state(ALREADY_STARTED));
        }
        *slot = Some(launch()?);
        Ok(())
    }

    /// Idempotent. The slot is released before teardown so `nativeStatus` never waits on it.
    fn stop(&self, bounds: StopBounds) {
        let running = lock(&self.running).take();
        if let Some(running) = running
            && let Err(problem) = running.stop(bounds)
        {
            self.errors.record(problem);
        }
    }

    fn host(&self) -> Result<Arc<dyn PhoneHost>, NativeError> {
        let slot = lock(&self.running);
        let running = slot.as_ref().ok_or_else(|| state(NOT_STARTED))?;
        running
            .host
            .clone()
            .ok_or_else(|| state(RESIDENT_NOT_WIRED))
    }

    fn capture_captured(
        &self,
        request_id: &str,
        path: &str,
        sha256: &str,
        width: i32,
        height: i32,
    ) -> Result<(), NativeError> {
        let capture = CapturedFile::parse(request_id, path, sha256, width, height)?;
        self.host()?.capture_captured(capture)
    }

    fn capture_declined(&self, request_id: &str, reason: &str) -> Result<(), NativeError> {
        let request_id = parse_request_id(request_id)?;
        let reason = DeclineReason::parse(reason)?;
        self.host()?.capture_declined(request_id, reason)
    }

    fn open_pairing_window(&self, now_unix_ms: u64, expires_at_ms: i64) -> Result<(), NativeError> {
        let deadline = pairing_window_deadline(now_unix_ms, expires_at_ms)?;
        self.host()?.open_pairing_window(deadline)
    }

    /// A13: closing a closed or expired window is a no-op. Without a resident no window can have
    /// opened, so this succeeds whether or not the bridge is running.
    fn close_pairing_window(&self) {
        let host = lock(&self.running)
            .as_ref()
            .and_then(|running| running.host.clone());
        if let Some(host) = host {
            host.close_pairing_window();
        }
    }

    fn confirm_pairing(&self, pairing_id: &str, transcript_hash: &str) -> Result<(), NativeError> {
        let pairing_id = parse_pairing_id(pairing_id)?;
        let transcript_hash = parse_transcript_hash(transcript_hash)?;
        self.host()?.confirm_pairing(pairing_id, transcript_hash)
    }

    fn reject_pairing(&self, pairing_id: &str) -> Result<(), NativeError> {
        let pairing_id = parse_pairing_id(pairing_id)?;
        self.host()?.reject_pairing(pairing_id)
    }

    fn shelf_snapshot(&self) -> Result<String, NativeError> {
        self.host()?.shelf_snapshot()
    }

    fn refresh_origin_catalogs(&self, open_epoch: i64) -> Result<String, NativeError> {
        self.host()?.refresh_origin_catalogs(open_epoch)
    }

    fn announce_text(&self, text: &str, action_id: &str) -> Result<String, NativeError> {
        self.host()?.announce_text(text, action_id)
    }

    fn announce_document(
        &self,
        lease_id: &str,
        root_name: &str,
        byte_length: u64,
        action_id: &str,
    ) -> Result<String, NativeError> {
        self.host()?
            .announce_document(lease_id, root_name, byte_length, action_id)
    }

    fn reserve_ordinary_photo(&self, action_id: &str) -> Result<String, NativeError> {
        self.host()?.reserve_ordinary_photo(action_id)
    }

    fn commit_ordinary_photo(
        &self,
        lease_id: &str,
        sha256_hex: &str,
        width: i32,
        height: i32,
    ) -> Result<String, NativeError> {
        self.host()?
            .commit_ordinary_photo(lease_id, sha256_hex, width, height)
    }

    fn abandon_photo(&self, lease_id: &str) -> Result<(), NativeError> {
        self.host()?.abandon_photo(lease_id)
    }

    fn activate(
        &self,
        source_device: &str,
        offer_id: &str,
        action: &str,
        gesture_token: &str,
    ) -> Result<String, NativeError> {
        let clipboard = self.clipboard()?;
        self.host()?
            .activate(source_device, offer_id, action, gesture_token, clipboard)
    }

    fn invalidate_platform_actions(&self) -> Result<(), NativeError> {
        self.clipboard()?.invalidate();
        Ok(())
    }

    fn report_platform_outcome(&self, dispatch_id: &str, outcome: &str) -> Result<(), NativeError> {
        self.clipboard()?.report_outcome(dispatch_id, outcome)
    }

    fn clipboard(&self) -> Result<Arc<PlatformClipboard>, NativeError> {
        let slot = lock(&self.running);
        let running = slot.as_ref().ok_or_else(|| state(NOT_STARTED))?;
        Ok(Arc::clone(&running.clipboard))
    }

    /// Fixed keys; never a key, the identity record, or the network handle.
    fn status_json(&self) -> String {
        let (running, host) = match lock(&self.running).as_ref() {
            None => (false, None),
            Some(running) => (true, running.host.clone()),
        };
        let status = host.map(|host| host.status()).unwrap_or_default();
        let capture = if !running {
            json!({ "state": "unknown" })
        } else {
            match status.live_request {
                Ok(request_id) => json!({
                    "state": "known",
                    "live_request": request_id.map(|id| id.to_string()),
                }),
                Err(detail) => json!({ "state": "error", "detail": detail }),
            }
        };
        let trust = if !running {
            json!({ "state": "unknown" })
        } else {
            match status.paired_peers {
                Ok(paired_peers) => json!({
                    "state": "known",
                    "paired_peers": paired_peers,
                }),
                Err(detail) => json!({ "state": "error", "detail": detail }),
            }
        };
        let last_failure = status
            .last_failure
            .map(|(detail, at_unix_ms)| json!({ "detail": detail, "at_unix_ms": at_unix_ms }));
        json!({
            "abi": ANDROID_ABI_VERSION,
            "running": running,
            "listening": status.listening,
            "pairing_window": status
                .pairing_window_expires_at_ms
                .map(|expires_at_ms| json!({ "expires_at_ms": expires_at_ms })),
            "capture": capture,
            "trust": trust,
            "failures": {
                "count": status.failure_count,
                "last": last_failure,
            },
            "last_error": self.errors.latest(),
        })
        .to_string()
    }
}

fn now_unix_ms() -> Result<u64, NativeError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| state("the system clock is before 1970"))?;
    u64::try_from(elapsed.as_millis()).map_err(|_| state("the system clock is out of range"))
}

/// Calls one Kotlin method by its table name and descriptor.
pub(crate) fn invoke<'local>(
    env: &mut Env<'local>,
    target: &JObject<'_>,
    method: JniMethod,
    args: &[JValue<'_>],
) -> jni::errors::Result<JValueOwned<'local>> {
    let signature = RuntimeMethodSignature::from_str(method.descriptor)?;
    env.call_method(
        target,
        JNIString::new(method.name),
        signature.method_signature(),
        args,
    )
}

fn start(env: &mut Env<'_>, this: &JObject<'_>, args: StartArgs) -> Result<(), NativeError> {
    BRIDGE.install(|| {
        let vm = env.get_java_vm()?;
        let target = env.new_global_ref(this)?;
        let documents_target = env.new_global_ref(this)?;
        let documents = Arc::new(PlatformDocuments::new(vm.clone(), documents_target));
        let identity = load_identity(env, this)?;
        Running::launch(
            args,
            identity,
            BRIDGE.errors.clone(),
            |receiver, sink| events::spawn_jni_callbacks(vm, target, receiver, sink),
            move |mut context| {
                context.documents = Some(documents as Arc<dyn meshelf_net::DocumentSourceProvider>);
                start_phone_host(context)
            },
        )
    })
}

/// `loadInstallationIdentity()` returns the stored record or null; on null a new identity is
/// generated and handed to `storeInstallationIdentity` before use. A Kotlin exception from either
/// hook propagates to the `nativeStart` caller unchanged.
fn load_identity(
    env: &mut Env<'_>,
    this: &JObject<'_>,
) -> Result<InstallationIdentity, NativeError> {
    let loaded = invoke(env, this, abi::LOAD_INSTALLATION_IDENTITY, &[])?.l()?;
    if loaded.is_null() {
        let identity = InstallationIdentity::generate();
        let record = env.byte_array_from_slice(&identity.to_record())?;
        invoke(
            env,
            this,
            abi::STORE_INSTALLATION_IDENTITY,
            &[JValue::Object(&record)],
        )?;
        return Ok(identity);
    }
    let record = JByteArray::cast_local(env, loaded)?;
    let bytes = env.convert_byte_array(&record)?;
    // The parse error could quote part of the secret record, so it is never passed on.
    InstallationIdentity::from_record(&bytes)
        .map_err(|_| state("the stored installation identity record is unreadable"))
}

fn text(env: &Env<'_>, value: &JString<'_>, label: &str) -> Result<String, NativeError> {
    if value.is_null() {
        return Err(invalid(format!("{label} is null")));
    }
    Ok(value.try_to_string(env)?)
}

/// Throws `IllegalArgumentException` or `IllegalStateException` for a [`NativeError`], and
/// `IllegalStateException` for a caught panic. A Java exception already pending (thrown by a
/// Kotlin hook) is the most specific failure and propagates unchanged.
struct ThrowJavaException;

impl<T: Default> ErrorPolicy<T, NativeError> for ThrowJavaException {
    type Captures<'unowned_env_local: 'native_method, 'native_method> = ();

    fn on_error<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        error: NativeError,
    ) -> jni::errors::Result<T> {
        let class = match error {
            NativeError::InvalidArgument(_) => jni_str!("java/lang/IllegalArgumentException"),
            NativeError::IllegalState(_) | NativeError::Jni(_) => {
                jni_str!("java/lang/IllegalStateException")
            }
        };
        throw(env, class, &error.to_string());
        Ok(T::default())
    }

    fn on_panic<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        payload: Box<dyn std::any::Any + Send + 'static>,
    ) -> jni::errors::Result<T> {
        let detail = payload
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_owned());
        throw(
            env,
            jni_str!("java/lang/IllegalStateException"),
            &format!("meshelf native panicked: {detail}"),
        );
        Ok(T::default())
    }
}

/// Never returns normally without a pending exception: if the typed exception cannot be thrown,
/// a `RuntimeException` is, because Kotlin would read a bare return as success.
fn throw(env: &mut Env<'_>, class: &JNIStr, message: &str) {
    if env.exception_check() {
        return;
    }
    let _ = env.throw_new(class, JNIString::new(message));
    if !env.exception_check() {
        let _ = env.throw(message.to_owned());
    }
}

/// Kotlin: `private external fun nativeAbiVersion(): Int`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAbiVersion<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
) -> jint {
    unowned_env
        .with_env(|_env| Ok::<_, NativeError>(ANDROID_ABI_VERSION))
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeStart(stateDir: String, localAddress: String,
/// networkHandle: Long, deviceName: String)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeStart<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    this: JObject<'caller>,
    state_dir: JString<'caller>,
    local_address: JString<'caller>,
    network_handle: jlong,
    device_name: JString<'caller>,
) {
    unowned_env
        .with_env(|env| -> Result<(), NativeError> {
            let args = StartArgs::parse(
                &text(env, &state_dir, "state directory")?,
                &text(env, &local_address, "local address")?,
                network_handle,
                &text(env, &device_name, "device name")?,
            )?;
            start(env, &this, args)
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeStop()`. Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeStop<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
) {
    unowned_env
        .with_env(|_env| -> Result<(), NativeError> {
            BRIDGE.stop(STOP_BOUNDS);
            Ok(())
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeCaptureCaptured(requestId: String, path: String,
/// sha256: String, width: Int, height: Int)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeCaptureCaptured<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    request_id: JString<'caller>,
    path: JString<'caller>,
    sha256: JString<'caller>,
    width: jint,
    height: jint,
) {
    unowned_env
        .with_env(|env| -> Result<(), NativeError> {
            BRIDGE.capture_captured(
                &text(env, &request_id, "request id")?,
                &text(env, &path, "path")?,
                &text(env, &sha256, "sha256")?,
                width,
                height,
            )
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeCaptureDeclined(requestId: String, reason: String)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeCaptureDeclined<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    request_id: JString<'caller>,
    reason: JString<'caller>,
) {
    unowned_env
        .with_env(|env| -> Result<(), NativeError> {
            BRIDGE.capture_declined(
                &text(env, &request_id, "request id")?,
                &text(env, &reason, "reason")?,
            )
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeStatus(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeStatus<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            Ok(env.new_string(BRIDGE.status_json())?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeOpenPairingWindow(expiresAtMs: Long)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeOpenPairingWindow<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    expires_at_ms: jlong,
) {
    unowned_env
        .with_env(|_env| -> Result<(), NativeError> {
            BRIDGE.open_pairing_window(now_unix_ms()?, expires_at_ms)
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeClosePairingWindow()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeClosePairingWindow<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
) {
    unowned_env
        .with_env(|_env| -> Result<(), NativeError> {
            BRIDGE.close_pairing_window();
            Ok(())
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeConfirmPairing(pairingId: String, transcriptHash: String)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeConfirmPairing<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    pairing_id: JString<'caller>,
    transcript_hash: JString<'caller>,
) {
    unowned_env
        .with_env(|env| -> Result<(), NativeError> {
            BRIDGE.confirm_pairing(
                &text(env, &pairing_id, "pairing id")?,
                &text(env, &transcript_hash, "transcript hash")?,
            )
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeRejectPairing(pairingId: String)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeRejectPairing<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    pairing_id: JString<'caller>,
) {
    unowned_env
        .with_env(|env| -> Result<(), NativeError> {
            BRIDGE.reject_pairing(&text(env, &pairing_id, "pairing id")?)
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeShelfSnapshot(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeShelfSnapshot<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            Ok(env.new_string(BRIDGE.shelf_snapshot()?)?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeRefreshOriginCatalogs(openEpoch: Long): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeRefreshOriginCatalogs<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    open_epoch: jlong,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            Ok(env.new_string(BRIDGE.refresh_origin_catalogs(open_epoch)?)?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeAnnounceText(text: String, actionId: String): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAnnounceText<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    body: JString<'caller>,
    action_id: JString<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            Ok(env.new_string(BRIDGE.announce_text(
                &text(env, &body, "text")?,
                &text(env, &action_id, "action id")?,
            )?)?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeAnnounceDocument(leaseId: String, rootName: String,
/// byteLength: Long, actionId: String): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAnnounceDocument<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    lease_id: JString<'caller>,
    root_name: JString<'caller>,
    byte_length: jlong,
    action_id: JString<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            if byte_length <= 0 {
                return Err(invalid("document byte length must be positive"));
            }
            let byte_length = u64::try_from(byte_length)
                .map_err(|_| invalid("document byte length out of range"))?;
            Ok(env.new_string(BRIDGE.announce_document(
                &text(env, &lease_id, "lease id")?,
                &text(env, &root_name, "root name")?,
                byte_length,
                &text(env, &action_id, "action id")?,
            )?)?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeReserveOrdinaryPhoto(actionId: String): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeReserveOrdinaryPhoto<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    action_id: JString<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            Ok(env.new_string(BRIDGE.reserve_ordinary_photo(&text(
                env,
                &action_id,
                "action id",
            )?)?)?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeCommitOrdinaryPhoto(leaseId: String, sha256: String,
/// width: Int, height: Int): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeCommitOrdinaryPhoto<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    lease_id: JString<'caller>,
    sha256: JString<'caller>,
    width: jint,
    height: jint,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            Ok(env.new_string(BRIDGE.commit_ordinary_photo(
                &text(env, &lease_id, "lease id")?,
                &text(env, &sha256, "sha256")?,
                width,
                height,
            )?)?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeAbandonPhoto(leaseId: String)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAbandonPhoto<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    lease_id: JString<'caller>,
) {
    unowned_env
        .with_env(|env| -> Result<(), NativeError> {
            BRIDGE.abandon_photo(&text(env, &lease_id, "lease id")?)
        })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeActivate(sourceDevice: String, offerId: String, action:
/// String, gestureToken: String): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeActivate<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    source_device: JString<'caller>,
    offer_id: JString<'caller>,
    action: JString<'caller>,
    gesture_token: JString<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<JString<'caller>, NativeError> {
            Ok(env.new_string(BRIDGE.activate(
                &text(env, &source_device, "source device")?,
                &text(env, &offer_id, "offer id")?,
                &text(env, &action, "action")?,
                &text(env, &gesture_token, "gesture token")?,
            )?)?)
        })
        .resolve::<ThrowJavaException>()
}

/// Kotlin: `private external fun nativeInvalidatePlatformActions()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeInvalidatePlatformActions<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
) {
    unowned_env
        .with_env(|_env| -> Result<(), NativeError> { BRIDGE.invalidate_platform_actions() })
        .resolve::<ThrowJavaException>();
}

/// Kotlin: `private external fun nativeReportPlatformOutcome(dispatchId: String, outcome: String)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeReportPlatformOutcome<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _this: JObject<'caller>,
    dispatch_id: JString<'caller>,
    outcome: JString<'caller>,
) {
    unowned_env
        .with_env(|env| -> Result<(), NativeError> {
            BRIDGE.report_platform_outcome(
                &text(env, &dispatch_id, "dispatch id")?,
                &text(env, &outcome, "outcome")?,
            )
        })
        .resolve::<ThrowJavaException>();
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Instant};

    use meshelf_core::CaptureRequestId;
    use meshelf_protocol::pairing::{PairingId, TranscriptHash};

    use super::*;
    use crate::{
        events::{EventRefused, KotlinEvent},
        host::HostStatus,
    };

    const ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const PAIRING: &str = "00112233445566778899aabbccddeeff";
    const NOW: u64 = 1_700_000_000_000;
    const HANDLE: i64 = 0x5eed_1234_abcd_0042;
    const QUICK: StopBounds = StopBounds {
        runtime: Duration::from_millis(500),
        callbacks: Duration::from_millis(500),
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum HostCall {
        Captured(CapturedFile),
        Declined(CaptureRequestId, DeclineReason),
        Open(u64),
        Close,
        Confirm(PairingId, TranscriptHash),
        Reject(PairingId),
        ShelfSnapshot,
        RefreshCatalogs(i64),
        AnnounceText(String, String),
        AnnounceDocument(String, String, u64, String),
        ReserveOrdinaryPhoto(String),
        CommitOrdinaryPhoto(String, String, i32, i32),
        AbandonPhoto(String),
        Activate(String, String, String, String),
        Shutdown,
    }

    #[derive(Default)]
    struct FakeHost {
        calls: Mutex<Vec<HostCall>>,
        events: Mutex<Option<EventSink>>,
    }

    impl FakeHost {
        fn record(&self, call: HostCall) -> Result<(), NativeError> {
            lock(&self.calls).push(call);
            Ok(())
        }
    }

    impl PhoneHost for FakeHost {
        fn capture_captured(&self, capture: CapturedFile) -> Result<(), NativeError> {
            self.record(HostCall::Captured(capture))
        }
        fn capture_declined(
            &self,
            request_id: CaptureRequestId,
            reason: DeclineReason,
        ) -> Result<(), NativeError> {
            self.record(HostCall::Declined(request_id, reason))
        }
        fn open_pairing_window(&self, expires_at_unix_ms: u64) -> Result<(), NativeError> {
            self.record(HostCall::Open(expires_at_unix_ms))
        }
        fn close_pairing_window(&self) {
            let _ = self.record(HostCall::Close);
        }
        fn confirm_pairing(
            &self,
            pairing_id: PairingId,
            transcript_hash: TranscriptHash,
        ) -> Result<(), NativeError> {
            self.record(HostCall::Confirm(pairing_id, transcript_hash))
        }
        fn reject_pairing(&self, pairing_id: PairingId) -> Result<(), NativeError> {
            self.record(HostCall::Reject(pairing_id))
        }
        fn shelf_snapshot(&self) -> Result<String, NativeError> {
            self.record(HostCall::ShelfSnapshot)?;
            Ok("{}".to_owned())
        }
        fn refresh_origin_catalogs(&self, open_epoch: i64) -> Result<String, NativeError> {
            self.record(HostCall::RefreshCatalogs(open_epoch))?;
            Ok("{}".to_owned())
        }
        fn announce_text(&self, text: &str, action_id: &str) -> Result<String, NativeError> {
            self.record(HostCall::AnnounceText(
                text.to_owned(),
                action_id.to_owned(),
            ))?;
            Ok("offer-id".to_owned())
        }
        fn announce_document(
            &self,
            lease_id: &str,
            root_name: &str,
            byte_length: u64,
            action_id: &str,
        ) -> Result<String, NativeError> {
            self.record(HostCall::AnnounceDocument(
                lease_id.to_owned(),
                root_name.to_owned(),
                byte_length,
                action_id.to_owned(),
            ))?;
            Ok("offer-id".to_owned())
        }
        fn reserve_ordinary_photo(&self, action_id: &str) -> Result<String, NativeError> {
            self.record(HostCall::ReserveOrdinaryPhoto(action_id.to_owned()))?;
            Ok(r#"{"leaseId":"lease","rawPath":"/raw","finalPath":"/final"}"#.to_owned())
        }
        fn commit_ordinary_photo(
            &self,
            lease_id: &str,
            sha256_hex: &str,
            width: i32,
            height: i32,
        ) -> Result<String, NativeError> {
            self.record(HostCall::CommitOrdinaryPhoto(
                lease_id.to_owned(),
                sha256_hex.to_owned(),
                width,
                height,
            ))?;
            Ok("offer-id".to_owned())
        }
        fn abandon_photo(&self, lease_id: &str) -> Result<(), NativeError> {
            self.record(HostCall::AbandonPhoto(lease_id.to_owned()))
        }
        fn activate(
            &self,
            source_device: &str,
            offer_id: &str,
            action: &str,
            gesture_token: &str,
            _clipboard: Arc<PlatformClipboard>,
        ) -> Result<String, NativeError> {
            self.record(HostCall::Activate(
                source_device.to_owned(),
                offer_id.to_owned(),
                action.to_owned(),
                gesture_token.to_owned(),
            ))?;
            Ok("activation-id".to_owned())
        }
        fn status(&self) -> HostStatus {
            HostStatus {
                listening: true,
                pairing_window_expires_at_ms: Some(NOW + 60_000),
                live_request: Ok(None),
                paired_peers: Ok(1),
                failure_count: 0,
                last_failure: None,
            }
        }
        fn shutdown(&self) {
            let _ = self.record(HostCall::Shutdown);
        }
    }

    fn start_args() -> StartArgs {
        StartArgs::parse(
            env!("CARGO_MANIFEST_DIR"),
            "100.64.1.50",
            HANDLE,
            "Pixel",
        )
        .expect("valid")
    }

    /// Installs a bridge through the production `launch`, with a plain thread in place of the JVM
    /// callback thread that forwards each invocation to the returned receiver.
    fn launch(
        bridge: &Bridge,
        identity: InstallationIdentity,
        host: Option<Arc<FakeHost>>,
    ) -> mpsc::Receiver<Invocation> {
        let (delivered, received) = mpsc::channel();
        let errors = bridge.errors.clone();
        bridge
            .install(|| {
                Running::launch(
                    start_args(),
                    identity,
                    errors,
                    |receiver, _sink| {
                        CallbackThread::spawn(move || {
                            for invocation in receiver.iter() {
                                let _ = delivered.send(invocation);
                            }
                        })
                    },
                    |context| {
                        Ok(host.map(|host| {
                            *lock(&host.events) = Some(context.events);
                            host as Arc<dyn PhoneHost>
                        }))
                    },
                )
            })
            .expect("start");
        received
    }

    fn is_state(result: Result<(), NativeError>, message: &str) -> bool {
        matches!(result, Err(NativeError::IllegalState(text)) if text == message)
    }

    fn forwarding_calls(bridge: &Bridge) -> Vec<Result<(), NativeError>> {
        vec![
            bridge.capture_captured(ID, CAPTURED_JPEG, SHA, 10, 10),
            bridge.capture_declined(ID, "user-declined"),
            bridge.open_pairing_window(NOW, (NOW + 1_000).cast_signed()),
            bridge.confirm_pairing(PAIRING, SHA),
            bridge.reject_pairing(PAIRING),
        ]
    }

    fn shelf_calls(bridge: &Bridge) -> Vec<Result<String, NativeError>> {
        vec![
            bridge.shelf_snapshot(),
            bridge.refresh_origin_catalogs(1),
            bridge.announce_text("hello", "action-1"),
            bridge.announce_document(
                "0f8fad5b-d9cb-469f-a165-70867728950e",
                "photo.jpg",
                12,
                "action-doc-1",
            ),
            bridge.activate(
                "0f8fad5b-d9cb-469f-a165-70867728950e",
                "0f8fad5b-d9cb-469f-a165-70867728950f",
                "COPY_TEXT",
                "gesture-1",
            ),
        ]
    }

    /// Absolute on the host running the tests; `/data/...` is not absolute on Windows.
    const CAPTURED_JPEG: &str = if cfg!(windows) {
        r"C:\data\a.jpg"
    } else {
        "/data/a.jpg"
    };

    #[test]
    fn before_start_arguments_are_checked_then_state_is_refused() {
        let bridge = Bridge::default();
        assert!(matches!(
            bridge.capture_declined(ID, "nope"),
            Err(NativeError::InvalidArgument(_))
        ));
        assert!(matches!(
            bridge.open_pairing_window(NOW, (NOW + 120_001).cast_signed()),
            Err(NativeError::InvalidArgument(_))
        ));
        for result in forwarding_calls(&bridge) {
            assert!(is_state(result, NOT_STARTED));
        }
        for result in shelf_calls(&bridge) {
            assert!(is_state(result.map(|_| ()), NOT_STARTED));
        }
        assert!(is_state(bridge.invalidate_platform_actions(), NOT_STARTED));
        bridge.close_pairing_window();
        bridge.stop(QUICK);
        let status: serde_json::Value =
            serde_json::from_str(&bridge.status_json()).expect("status json");
        assert_eq!(status["running"], false);
        assert_eq!(status["capture"]["state"], "unknown");
        assert_eq!(status["trust"]["state"], "unknown");
    }

    /// Kotlin reads a normal return as success, so the shell must refuse rather than pretend.
    #[test]
    fn shell_without_a_resident_refuses_honestly() {
        let bridge = Bridge::default();
        let _events = launch(&bridge, InstallationIdentity::generate(), None);
        for result in forwarding_calls(&bridge) {
            assert!(is_state(result, RESIDENT_NOT_WIRED));
        }
        for result in shelf_calls(&bridge) {
            assert!(is_state(result.map(|_| ()), RESIDENT_NOT_WIRED));
        }
        bridge.invalidate_platform_actions().expect("clipboard");
        assert!(matches!(
            bridge.confirm_pairing(PAIRING, "short"),
            Err(NativeError::InvalidArgument(_))
        ));
        // A13: no window can have opened, so closing is a no-op, not an error.
        bridge.close_pairing_window();
        let status: serde_json::Value =
            serde_json::from_str(&bridge.status_json()).expect("status json");
        assert_eq!(status["running"], true);
        assert_eq!(status["listening"], false);
        assert!(status["pairing_window"].is_null());
        bridge.stop(QUICK);
    }

    #[test]
    fn a_second_start_is_refused_without_launching() {
        let bridge = Bridge::default();
        let _events = launch(&bridge, InstallationIdentity::generate(), None);
        let mut launched = false;
        let result = bridge.install(|| {
            launched = true;
            Err(state("unreachable"))
        });
        assert!(is_state(result, ALREADY_STARTED));
        assert!(!launched);
        bridge.stop(QUICK);
    }

    #[test]
    fn stop_is_idempotent_closes_the_queue_and_shuts_the_resident_down() {
        let bridge = Bridge::default();
        let host = Arc::new(FakeHost::default());
        let _events = launch(
            &bridge,
            InstallationIdentity::generate(),
            Some(host.clone()),
        );
        let sink = lock(&host.events).clone().expect("sink");
        bridge.stop(QUICK);
        bridge.stop(QUICK);
        assert_eq!(*lock(&host.calls), vec![HostCall::Shutdown]);
        let delivered = KotlinEvent::CaptureDelivered {
            request_id: CaptureRequestId::new(),
        };
        assert_eq!(sink.emit(delivered), Err(EventRefused::Stopped));
        assert!(
            bridge.errors.latest().is_none(),
            "clean stop records nothing"
        );
        let status: serde_json::Value =
            serde_json::from_str(&bridge.status_json()).expect("status json");
        assert_eq!(status["running"], false);
        // A stopped bridge starts again.
        let _events = launch(&bridge, InstallationIdentity::generate(), None);
        bridge.stop(QUICK);
    }

    #[test]
    fn a_stuck_callback_thread_bounds_stop_and_is_reported() {
        let bridge = Bridge::default();
        let errors = bridge.errors.clone();
        bridge
            .install(|| {
                Running::launch(
                    start_args(),
                    InstallationIdentity::generate(),
                    errors,
                    |receiver, _sink| {
                        CallbackThread::spawn(move || {
                            thread::sleep(Duration::from_millis(800));
                            drop(receiver);
                        })
                    },
                    |_context| Ok(None),
                )
            })
            .expect("start");
        let started = Instant::now();
        bridge.stop(StopBounds {
            runtime: Duration::from_millis(50),
            callbacks: Duration::from_millis(50),
        });
        assert!(started.elapsed() < Duration::from_millis(600));
        assert_eq!(
            bridge.errors.latest().as_deref(),
            Some("callback thread did not stop within 50 ms")
        );
    }

    #[test]
    fn the_resident_gets_typed_arguments_and_its_events_reach_the_callback_thread() {
        let bridge = Bridge::default();
        let host = Arc::new(FakeHost::default());
        let delivered = launch(
            &bridge,
            InstallationIdentity::generate(),
            Some(host.clone()),
        );
        bridge
            .capture_captured(ID, CAPTURED_JPEG, SHA, 4032, 3024)
            .expect("captured");
        bridge
            .capture_declined(ID, "camera-permission-denied")
            .expect("declined");
        bridge
            .open_pairing_window(NOW, (NOW + 120_000).cast_signed())
            .expect("open");
        bridge.close_pairing_window();
        bridge.confirm_pairing(PAIRING, SHA).expect("confirm");
        bridge.reject_pairing(PAIRING).expect("reject");
        let request_id = parse_request_id(ID).expect("id");
        let pairing_id = parse_pairing_id(PAIRING).expect("pairing id");
        assert_eq!(
            *lock(&host.calls),
            vec![
                HostCall::Captured(
                    CapturedFile::parse(ID, CAPTURED_JPEG, SHA, 4032, 3024).expect("file")
                ),
                HostCall::Declined(request_id, DeclineReason::CameraPermissionDenied),
                HostCall::Open(NOW + 120_000),
                HostCall::Close,
                HostCall::Confirm(pairing_id, parse_transcript_hash(SHA).expect("hash")),
                HostCall::Reject(pairing_id),
            ]
        );
        let sink = lock(&host.events).clone().expect("sink");
        sink.emit(KotlinEvent::CaptureDelivered { request_id })
            .expect("emitted");
        let invocation = delivered
            .recv_timeout(Duration::from_secs(5))
            .expect("delivered to the callback thread");
        assert_eq!(invocation.method, abi::ON_CAPTURE_DELIVERED);
        bridge.stop(QUICK);
    }

    #[test]
    fn status_has_fixed_keys_and_never_key_material_or_the_handle() {
        let bridge = Bridge::default();
        let identity = InstallationIdentity::generate();
        let record: serde_json::Value =
            serde_json::from_slice(&identity.to_record()).expect("record json");
        let public_key: String = identity
            .public_key()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let _events = launch(&bridge, identity, Some(Arc::new(FakeHost::default())));
        let text = bridge.status_json();
        let status: serde_json::Value = serde_json::from_str(&text).expect("status json");
        let keys: Vec<&str> = status
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "abi",
                "capture",
                "failures",
                "last_error",
                "listening",
                "pairing_window",
                "running",
                "trust"
            ]
        );
        assert_eq!(status["abi"], 8);
        assert_eq!(status["listening"], true);
        assert_eq!(status["pairing_window"]["expires_at_ms"], NOW + 60_000);
        assert_eq!(status["capture"]["state"], "known");
        assert_eq!(status["trust"]["paired_peers"], 1);
        assert!(!text.contains(&record["secret_key"].to_string()));
        assert!(!text.contains(&public_key));
        assert!(!text.contains(&HANDLE.to_string()));
        assert!(!text.contains(&HANDLE.cast_unsigned().to_string()));
        assert!(!text.contains(&format!("{HANDLE:x}")));
        bridge.stop(QUICK);
    }
}
