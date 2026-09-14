//! Loopback-only, event-driven wait service for long local waits.
//!
//! The local-control channel in `activation.rs` is serial and its client gives up after five
//! seconds, so a wait that lasts minutes (a person taking a photograph) cannot live there. This is
//! a separate small listener: the resident registers a key and hands the caller a request-scoped
//! token over the control channel; the caller connects here and sleeps until the registration
//! completes, its deadline passes, the service shuts down, or the caller goes away.
//!
//! Nothing here wakes on an interval. Each attached waiter blocks on its own channel with a
//! timeout equal to the exact time left before its deadline, and a companion thread blocks
//! reading the client socket so a departing client is noticed by EOF rather than by probing.
//! Expired registrations and undelivered outcomes are pruned only when `register`, `complete`, or
//! an attach already holds the map lock. No lock is held while a waiter sleeps.
//!
//! Wire format, one wait per connection:
//! 1. The client writes its token: exactly 36 ASCII bytes (a hyphenated UUIDv4). It then keeps
//!    its write side open and sends nothing more; EOF or any further byte withdraws the waiter.
//! 2. The server writes exactly one response frame and closes: a one-byte tag, a `u32`
//!    big-endian payload length, then the payload (at most `MAX_WAIT_OUTCOME_BYTES`).
//!
//! | Tag    | Meaning   | Payload                                                          |
//! |--------|-----------|------------------------------------------------------------------|
//! | `0x01` | completed | the exact outcome bytes passed to `complete`                     |
//! | `0x02` | timed out | empty; the registration deadline passed and it was removed       |
//! | `0x03` | shutdown  | empty; the service stopped                                       |
//! | `0x04` | refused   | UTF-8 reason; nothing was attached or queued for this connection |

use std::{
    collections::HashMap,
    fmt,
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use meshelf_core::MessageId;
use thiserror::Error;

/// Largest outcome `complete` accepts and the largest response payload a client reads.
pub const MAX_WAIT_OUTCOME_BYTES: usize = 64 * 1024;
/// Hard cap on live registrations, so the map is bounded even if nothing ever attaches.
const MAX_WAIT_REGISTRATIONS: usize = 64;
/// A hyphenated UUIDv4, as produced by `MessageId`'s `Display`.
const WAIT_TOKEN_LEN: usize = 36;

const TAG_COMPLETED: u8 = 0x01;
const TAG_TIMED_OUT: u8 = 0x02;
const TAG_SHUTDOWN: u8 = 0x03;
const TAG_REFUSED: u8 = 0x04;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
/// How long the accept thread waits for a token; the client writes it as soon as it connects.
const TOKEN_READ_TIMEOUT: Duration = Duration::from_secs(1);
/// Bounds every server write, so a client that stops reading cannot pin a thread.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// Extra client patience, so the server's own deadline frame arrives before the client gives up.
const CLIENT_MARGIN: Duration = Duration::from_millis(500);

const REFUSED_MALFORMED: &str = "malformed wait token";
const REFUSED_UNKNOWN: &str = "unknown or expired wait token";
const REFUSED_ATTACHED: &str = "a waiter is already attached to this request";
const REFUSED_CAPACITY: &str = "too many waiters are attached";
const REFUSED_UNWATCHABLE: &str = "cannot watch the waiter connection";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WaitError {
    #[error("a wait registration already exists for this key")]
    DuplicateKey,
    #[error("wait registrations are at their limit of {0}")]
    RegistrationLimit(usize),
    #[error("the wait deadline has already passed")]
    DeadlineElapsed,
    #[error("no live wait registration exists for this key")]
    UnknownKey,
    #[error("this wait registration already has an outcome")]
    AlreadyCompleted,
    #[error("wait outcome is {0} bytes; maximum is {MAX_WAIT_OUTCOME_BYTES}")]
    OutcomeTooLarge(usize),
    #[error("malformed wait token")]
    MalformedToken,
    #[error("the wait service is shut down")]
    ShutDown,
}

/// Unguessable, request-scoped proof that a caller may wait on one registration.
#[derive(Clone, PartialEq, Eq)]
pub struct WaitToken(String);

impl WaitToken {
    fn generate() -> Self {
        Self(MessageId::new().to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for WaitToken {
    type Err = WaitError;

    /// Accepts only the canonical form the service issues, so a token that parses here is
    /// byte-for-byte what the server compares against.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let canonical = value
            .parse::<MessageId>()
            .map_err(|_| WaitError::MalformedToken)?
            .to_string();
        if canonical == value {
            Ok(Self(canonical))
        } else {
            Err(WaitError::MalformedToken)
        }
    }
}

impl fmt::Debug for WaitToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WaitToken(<redacted>)")
    }
}

/// How one wait ended. The server encodes exactly one of these per connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitOutcome {
    Completed(Vec<u8>),
    /// The registration deadline passed, or the client's own timeout elapsed first.
    TimedOut,
    Shutdown,
    Refused(String),
}

impl WaitOutcome {
    fn encode(&self) -> (u8, &[u8]) {
        match self {
            Self::Completed(outcome) => (TAG_COMPLETED, outcome),
            Self::TimedOut => (TAG_TIMED_OUT, &[]),
            Self::Shutdown => (TAG_SHUTDOWN, &[]),
            Self::Refused(reason) => (TAG_REFUSED, reason.as_bytes()),
        }
    }

    fn decode(tag: u8, payload: Vec<u8>) -> io::Result<Self> {
        match tag {
            TAG_COMPLETED => Ok(Self::Completed(payload)),
            TAG_TIMED_OUT if payload.is_empty() => Ok(Self::TimedOut),
            TAG_SHUTDOWN if payload.is_empty() => Ok(Self::Shutdown),
            TAG_REFUSED => String::from_utf8(payload)
                .map(Self::Refused)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "wait refusal is not UTF-8")),
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "malformed wait response: tag {tag:#04x} with {} payload bytes",
                    payload.len()
                ),
            )),
        }
    }
}

enum WaiterEvent {
    /// The registration changed (completed) or the service stopped; re-read the map.
    Wake,
    /// The client closed, errored, or broke protocol by sending more bytes.
    Disconnected,
}

struct Registration {
    token: WaitToken,
    deadline: Instant,
    outcome: Option<Vec<u8>>,
    /// Present exactly while one waiter is attached.
    waiter: Option<Sender<WaiterEvent>>,
}

struct State {
    registrations: HashMap<String, Registration>,
    attached: usize,
    shut_down: bool,
}

impl State {
    /// An attached waiter wakes at its own deadline and removes its registration itself, so only
    /// unattended registrations are pruned here.
    fn prune(&mut self, now: Instant) {
        self.registrations
            .retain(|_, registration| registration.waiter.is_some() || registration.deadline > now);
    }
}

struct Shared {
    state: Mutex<State>,
    max_waiters: usize,
}

struct Waiter {
    key: String,
    token: WaitToken,
    events: Receiver<WaiterEvent>,
    sender: Sender<WaiterEvent>,
}

enum Attach {
    Attached(Waiter),
    Answer(WaitOutcome),
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Critical sections never panic; recover rather than wedge every future waiter.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stop(&self) {
        let mut state = self.lock();
        if state.shut_down {
            return;
        }
        state.shut_down = true;
        for registration in state.registrations.values() {
            if let Some(waiter) = &registration.waiter {
                let _ = waiter.send(WaiterEvent::Wake);
            }
        }
        state.registrations.clear();
    }

    fn attach(&self, presented: &[u8]) -> Attach {
        let now = Instant::now();
        let mut guard = self.lock();
        if guard.shut_down {
            return Attach::Answer(WaitOutcome::Shutdown);
        }
        guard.prune(now);
        let State {
            registrations,
            attached,
            ..
        } = &mut *guard;
        let Some((key, registration)) = registrations
            .iter_mut()
            .find(|(_, registration)| registration.token.0.as_bytes() == presented)
        else {
            return Attach::Answer(WaitOutcome::Refused(REFUSED_UNKNOWN.to_owned()));
        };
        if registration.waiter.is_some() {
            return Attach::Answer(WaitOutcome::Refused(REFUSED_ATTACHED.to_owned()));
        }
        if *attached >= self.max_waiters {
            return Attach::Answer(WaitOutcome::Refused(REFUSED_CAPACITY.to_owned()));
        }
        let (sender, events) = mpsc::channel();
        registration.waiter = Some(sender.clone());
        *attached += 1;
        Attach::Attached(Waiter {
            key: key.clone(),
            token: registration.token.clone(),
            events,
            sender,
        })
    }

    /// Sleep, without the map lock, until the registration resolves or the client leaves.
    /// `None` means the client left; the registration and any outcome stay for a later waiter.
    fn resolve(
        &self,
        key: &str,
        token: &WaitToken,
        events: &Receiver<WaiterEvent>,
    ) -> Option<WaitOutcome> {
        loop {
            let remaining = {
                let now = Instant::now();
                let mut state = self.lock();
                if state.shut_down {
                    return Some(WaitOutcome::Shutdown);
                }
                let Some(registration) = state
                    .registrations
                    .get(key)
                    .filter(|registration| registration.token == *token)
                else {
                    // Only this waiter removes an attached registration, so this is unexpected;
                    // answer honestly rather than sleep on nothing.
                    return Some(WaitOutcome::Refused(REFUSED_UNKNOWN.to_owned()));
                };
                if let Some(outcome) = &registration.outcome {
                    return Some(WaitOutcome::Completed(outcome.clone()));
                }
                if registration.deadline <= now {
                    state.registrations.remove(key);
                    return Some(WaitOutcome::TimedOut);
                }
                registration.deadline - now
            };
            match events.recv_timeout(remaining) {
                // A wake or the deadline: re-read the map to learn which.
                Ok(WaiterEvent::Wake) | Err(RecvTimeoutError::Timeout) => {}
                Ok(WaiterEvent::Disconnected) | Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Free the waiter slot. A delivered outcome ends the registration; anything else leaves it
    /// (with any outcome) for a later waiter until its deadline.
    fn release(&self, key: &str, token: &WaitToken, delivered: bool) {
        let mut state = self.lock();
        debug_assert!(
            state.attached > 0,
            "released a waiter that was never attached"
        );
        state.attached = state.attached.saturating_sub(1);
        let matches = state
            .registrations
            .get(key)
            .is_some_and(|registration| registration.token == *token);
        if !matches {
            return;
        }
        if delivered {
            state.registrations.remove(key);
        } else if let Some(registration) = state.registrations.get_mut(key) {
            registration.waiter = None;
        }
    }

    /// End a registration before its completed outcome is written. Without this, a client that
    /// reconnects the instant it reads the outcome could still find the registration attached,
    /// because `release` runs only after the outcome is written and the socket is shut down. The
    /// attached count is untouched until `release`.
    fn take_for_delivery(&self, key: &str, token: &WaitToken) -> Option<Registration> {
        let mut state = self.lock();
        let matches = state
            .registrations
            .get(key)
            .is_some_and(|registration| registration.token == *token);
        if matches {
            state.registrations.remove(key)
        } else {
            None
        }
    }

    /// Put back a registration whose completed outcome could not be written, so a later waiter can
    /// still receive it. A key registered again meanwhile is left alone, and the registration cap
    /// still holds; the durable request row stays the authority either way.
    fn restore_undelivered(&self, key: String, mut registration: Registration) {
        let mut state = self.lock();
        if state.shut_down
            || registration.deadline <= Instant::now()
            || (!state.registrations.contains_key(&key)
                && state.registrations.len() >= MAX_WAIT_REGISTRATIONS)
        {
            return;
        }
        registration.waiter = None;
        state.registrations.entry(key).or_insert(registration);
    }
}

/// Server side: a loopback listener plus the registration map it answers from.
pub struct WaitService {
    shared: Arc<Shared>,
    port: u16,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

impl WaitService {
    /// Bind `127.0.0.1:0` and start the accept thread. `max_waiters` bounds simultaneously
    /// attached waiters; further waiters are refused, never queued.
    pub fn start(max_waiters: usize) -> io::Result<Self> {
        if max_waiters == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "wait service needs room for at least one waiter",
            ));
        }
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                registrations: HashMap::new(),
                attached: 0,
                shut_down: false,
            }),
            max_waiters,
        });
        let accept_shared = Arc::clone(&shared);
        let accept_thread = thread::Builder::new()
            .name("meshelf-wait-accept".to_owned())
            .spawn(move || accept_loop(&listener, &accept_shared))?;
        Ok(Self {
            shared,
            port,
            accept_thread: Mutex::new(Some(accept_thread)),
        })
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Register one wait per key, live until `deadline`, and return its token.
    pub fn register(&self, key: &str, deadline: Instant) -> Result<WaitToken, WaitError> {
        let now = Instant::now();
        let mut state = self.shared.lock();
        if state.shut_down {
            return Err(WaitError::ShutDown);
        }
        state.prune(now);
        if deadline <= now {
            return Err(WaitError::DeadlineElapsed);
        }
        if state.registrations.contains_key(key) {
            return Err(WaitError::DuplicateKey);
        }
        if state.registrations.len() >= MAX_WAIT_REGISTRATIONS {
            return Err(WaitError::RegistrationLimit(MAX_WAIT_REGISTRATIONS));
        }
        let token = WaitToken::generate();
        state.registrations.insert(
            key.to_owned(),
            Registration {
                token: token.clone(),
                deadline,
                outcome: None,
                waiter: None,
            },
        );
        Ok(token)
    }

    /// Record the outcome and wake an attached waiter at once; with none attached, the outcome
    /// is retained until a waiter attaches or the registration's deadline passes.
    pub fn complete(&self, key: &str, outcome: Vec<u8>) -> Result<(), WaitError> {
        if outcome.len() > MAX_WAIT_OUTCOME_BYTES {
            return Err(WaitError::OutcomeTooLarge(outcome.len()));
        }
        let now = Instant::now();
        let mut state = self.shared.lock();
        if state.shut_down {
            return Err(WaitError::ShutDown);
        }
        state.prune(now);
        let registration = state
            .registrations
            .get_mut(key)
            .ok_or(WaitError::UnknownKey)?;
        if registration.outcome.is_some() {
            return Err(WaitError::AlreadyCompleted);
        }
        registration.outcome = Some(outcome);
        if let Some(waiter) = &registration.waiter {
            let _ = waiter.send(WaiterEvent::Wake);
        }
        Ok(())
    }

    /// Wake every attached waiter with `Shutdown`, drop all registrations, and stop accepting.
    /// Returns once the listener is closed; an error means the accept thread could not be woken.
    pub fn shutdown(&self) -> io::Result<()> {
        self.shared.stop();
        let handle = self
            .accept_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(handle) = handle else {
            return Ok(());
        };
        if !handle.is_finished() {
            // The accept thread is blocked in accept(); one connection lets it see the flag.
            TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], self.port)),
                CONNECT_TIMEOUT,
            )?;
        }
        handle
            .join()
            .map_err(|_| io::Error::other("wait accept thread panicked"))
    }

    #[cfg(test)]
    fn attached_waiters(&self) -> usize {
        self.shared.lock().attached
    }
}

impl Drop for WaitService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    for connection in listener.incoming() {
        if shared.lock().shut_down {
            return;
        }
        match connection {
            Ok(stream) => handle_connection(shared, stream),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionAborted | ErrorKind::Interrupted
                ) => {}
            Err(_) => {
                // Retrying a persistent accept error would spin. Stop loudly instead: attached
                // waiters get `Shutdown` and later registrations fail.
                shared.stop();
                return;
            }
        }
    }
}

fn handle_connection(shared: &Arc<Shared>, mut stream: TcpStream) {
    if stream.set_read_timeout(Some(TOKEN_READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return;
    }
    let mut presented = [0_u8; WAIT_TOKEN_LEN];
    if stream.read_exact(&mut presented).is_err() {
        let _ = write_outcome(
            &mut stream,
            &WaitOutcome::Refused(REFUSED_MALFORMED.to_owned()),
        );
        return;
    }
    let waiter = match shared.attach(&presented) {
        Attach::Answer(outcome) => {
            let _ = write_outcome(&mut stream, &outcome);
            return;
        }
        Attach::Attached(waiter) => waiter,
    };
    let (key, token) = (waiter.key.clone(), waiter.token.clone());
    let waiter_shared = Arc::clone(shared);
    if thread::Builder::new()
        .name("meshelf-wait".to_owned())
        .spawn(move || run_waiter(&waiter_shared, stream, waiter))
        .is_err()
    {
        // The unrun closure dropped the stream, so the client sees EOF rather than a hang.
        shared.release(&key, &token, false);
    }
}

fn run_waiter(shared: &Shared, mut stream: TcpStream, waiter: Waiter) {
    let Waiter {
        key,
        token,
        events,
        sender,
    } = waiter;
    // The read timeout is per socket, so clear it before the companion's blocking read or that
    // read would end on a timer instead of on the client leaving.
    let companion = stream
        .set_read_timeout(None)
        .and_then(|()| stream.try_clone())
        .and_then(|mut watched| {
            thread::Builder::new()
                .name("meshelf-wait-watch".to_owned())
                .spawn(move || {
                    // The client sends nothing after its token, so this read returns only on EOF,
                    // an error, a protocol violation, or the server shutting the socket down.
                    let mut byte = [0_u8; 1];
                    let _ = watched.read(&mut byte);
                    let _ = sender.send(WaiterEvent::Disconnected);
                })
        });
    let (outcome, companion) = match companion {
        Ok(handle) => (shared.resolve(&key, &token, &events), Some(handle)),
        Err(_) => (
            Some(WaitOutcome::Refused(REFUSED_UNWATCHABLE.to_owned())),
            None,
        ),
    };
    // A completed outcome ends its registration before the client can read it (see
    // `take_for_delivery`), so "the client has the outcome" always happens after "the registration
    // is gone". If the frame cannot be written, the registration and its outcome are restored.
    let taken = match &outcome {
        Some(WaitOutcome::Completed(_)) => shared.take_for_delivery(&key, &token),
        _ => None,
    };
    let written = outcome
        .as_ref()
        .is_some_and(|outcome| write_outcome(&mut stream, outcome).is_ok());
    let delivered = match taken {
        Some(registration) if !written => {
            shared.restore_undelivered(key.clone(), registration);
            false
        }
        Some(_) => true,
        None => false,
    };
    // Ends the companion's read on Unix. Windows does not wake a read already blocked on a cloned
    // socket, so there the companion ends only when the client closes. The slot is released
    // first, so a client that keeps its socket open cannot hold the only slot either way.
    let _ = stream.shutdown(Shutdown::Both);
    shared.release(&key, &token, delivered);
    if let Some(handle) = companion {
        let _ = handle.join();
    }
}

fn write_outcome(stream: &mut TcpStream, outcome: &WaitOutcome) -> io::Result<()> {
    let (tag, payload) = outcome.encode();
    if payload.len() > MAX_WAIT_OUTCOME_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "wait response is {} bytes; maximum is {MAX_WAIT_OUTCOME_BYTES}",
                payload.len()
            ),
        ));
    }
    let mut frame = Vec::with_capacity(1 + 4 + payload.len());
    frame.push(tag);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()
}

/// Client side: attach to a wait and block, for at most `timeout` plus a small margin, until it
/// resolves. The client's own timeout elapsing is reported as `TimedOut`; the registration then
/// survives until its deadline, so the caller may attach again.
pub fn wait(port: u16, token: &WaitToken, timeout: Duration) -> io::Result<WaitOutcome> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_read_timeout(Some(timeout.saturating_add(CLIENT_MARGIN)))?;
    stream.write_all(token.as_str().as_bytes())?;
    stream.flush()?;
    read_outcome(&mut stream)
}

fn read_outcome(stream: &mut TcpStream) -> io::Result<WaitOutcome> {
    let mut tag = [0_u8; 1];
    if let Err(error) = stream.read_exact(&mut tag) {
        // Only a timeout before any response byte is the wait itself running out.
        return if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            Ok(WaitOutcome::TimedOut)
        } else {
            Err(error)
        };
    }
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_WAIT_OUTCOME_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("wait response is {length} bytes; maximum is {MAX_WAIT_OUTCOME_BYTES}"),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    WaitOutcome::decode(tag[0], payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: Duration = Duration::from_secs(5);

    fn in_(duration: Duration) -> Instant {
        Instant::now() + duration
    }

    /// Test-side bounded wait for the server to reach a state; the service itself never polls.
    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let limit = Instant::now() + Duration::from_secs(2);
        while !condition() {
            assert!(Instant::now() < limit, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn spawn_wait(port: u16, token: &WaitToken) -> JoinHandle<io::Result<WaitOutcome>> {
        let token = token.clone();
        thread::spawn(move || wait(port, &token, LONG))
    }

    fn attach_raw(port: u16, presented: &[u8]) -> TcpStream {
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).expect("connect to the wait service");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound the test read");
        stream.write_all(presented).expect("write the token");
        stream
    }

    fn refused(outcome: &WaitOutcome, reason: &str) -> bool {
        matches!(outcome, WaitOutcome::Refused(actual) if actual == reason)
    }

    #[test]
    fn a_waiter_attached_before_completion_receives_the_exact_outcome() {
        let service = WaitService::start(8).expect("start wait service");
        let token = service.register("photo", in_(LONG)).expect("register");
        assert_eq!(token.as_str().len(), WAIT_TOKEN_LEN);
        let waiter = spawn_wait(service.port(), &token);
        wait_until("the waiter to attach", || service.attached_waiters() == 1);

        // Full-size binary outcome: the bound is inclusive and bytes are not reinterpreted.
        let outcome: Vec<u8> = (0..MAX_WAIT_OUTCOME_BYTES)
            .map(|i| (i % 251) as u8)
            .collect();
        service
            .complete("photo", outcome.clone())
            .expect("complete");

        let received = waiter.join().expect("waiter thread").expect("wait");
        assert_eq!(received, WaitOutcome::Completed(outcome));
    }

    #[test]
    fn a_waiter_attaching_after_completion_gets_the_retained_outcome_once() {
        let service = WaitService::start(8).expect("start wait service");
        let token = service.register("photo", in_(LONG)).expect("register");
        service
            .complete("photo", b"done".to_vec())
            .expect("complete");

        let started = Instant::now();
        let received = wait(service.port(), &token, LONG).expect("wait");
        assert_eq!(received, WaitOutcome::Completed(b"done".to_vec()));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "retained outcome must arrive at once"
        );

        // Delivery ends the registration: the durable row, not this service, is the record.
        let again = wait(service.port(), &token, LONG).expect("second wait");
        assert!(refused(&again, REFUSED_UNKNOWN), "got {again:?}");
    }

    #[test]
    fn a_deadline_with_no_completion_times_out_at_the_deadline_not_an_interval() {
        let service = WaitService::start(8).expect("start wait service");
        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        let token = service.register("photo", deadline).expect("register");

        // The client would wait five seconds, so a prompt TimedOut is the server's deadline.
        let received = wait(service.port(), &token, LONG).expect("wait");
        let elapsed = started.elapsed();
        assert_eq!(received, WaitOutcome::TimedOut);
        assert!(
            elapsed >= Duration::from_millis(300),
            "woke early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(550),
            "woke late: {elapsed:?}"
        );

        let again = wait(service.port(), &token, LONG).expect("second wait");
        assert!(
            refused(&again, REFUSED_UNKNOWN),
            "expired registration must be gone: {again:?}"
        );
    }

    #[test]
    fn a_second_concurrent_waiter_for_the_same_key_is_refused_not_queued() {
        let service = WaitService::start(8).expect("start wait service");
        let token = service.register("photo", in_(LONG)).expect("register");
        let first = spawn_wait(service.port(), &token);
        wait_until("the first waiter to attach", || {
            service.attached_waiters() == 1
        });

        let started = Instant::now();
        let second = wait(service.port(), &token, LONG).expect("second wait");
        assert!(refused(&second, REFUSED_ATTACHED), "got {second:?}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refusal must not wait"
        );
        assert_eq!(service.attached_waiters(), 1);

        service
            .complete("photo", b"done".to_vec())
            .expect("complete");
        let received = first.join().expect("waiter thread").expect("wait");
        assert_eq!(received, WaitOutcome::Completed(b"done".to_vec()));
    }

    #[test]
    fn a_killed_waiter_frees_its_slot_so_a_rerun_can_attach_and_complete() {
        let service = WaitService::start(8).expect("start wait service");
        let token = service.register("photo", in_(LONG)).expect("register");
        let killed = attach_raw(service.port(), token.as_str().as_bytes());
        wait_until("the first waiter to attach", || {
            service.attached_waiters() == 1
        });

        drop(killed);
        wait_until("the disconnect to free the slot", || {
            service.attached_waiters() == 0
        });

        // The registration survived the disconnect, so the rerun attaches to the same wait.
        let rerun = spawn_wait(service.port(), &token);
        wait_until("the rerun to attach", || service.attached_waiters() == 1);
        service
            .complete("photo", b"done".to_vec())
            .expect("complete");
        let received = rerun.join().expect("waiter thread").expect("wait");
        assert_eq!(received, WaitOutcome::Completed(b"done".to_vec()));
    }

    #[test]
    fn the_waiter_cap_refuses_the_next_waiter_and_queues_nothing() {
        let service = WaitService::start(2).expect("start wait service");
        let a = service.register("a", in_(LONG)).expect("register a");
        let b = service.register("b", in_(LONG)).expect("register b");
        let c = service.register("c", in_(LONG)).expect("register c");
        let waiting_a = spawn_wait(service.port(), &a);
        let waiting_b = spawn_wait(service.port(), &b);
        wait_until("two waiters to attach", || service.attached_waiters() == 2);

        let over = wait(service.port(), &c, LONG).expect("third wait");
        assert!(refused(&over, REFUSED_CAPACITY), "got {over:?}");
        assert_eq!(
            service.attached_waiters(),
            2,
            "the refused waiter must not be held"
        );

        // The refused attempt left no waiter behind: c's outcome is retained, not delivered.
        service.complete("c", b"c".to_vec()).expect("complete c");
        service.complete("a", b"a".to_vec()).expect("complete a");
        assert_eq!(
            waiting_a.join().expect("a").expect("wait a"),
            WaitOutcome::Completed(b"a".to_vec())
        );
        wait_until("a's slot to free", || service.attached_waiters() == 1);
        assert_eq!(
            wait(service.port(), &c, LONG).expect("wait c"),
            WaitOutcome::Completed(b"c".to_vec())
        );

        service.complete("b", b"b".to_vec()).expect("complete b");
        assert_eq!(
            waiting_b.join().expect("b").expect("wait b"),
            WaitOutcome::Completed(b"b".to_vec())
        );
    }

    #[test]
    fn wrong_unknown_and_malformed_tokens_are_refused() {
        let service = WaitService::start(8).expect("start wait service");
        let token = service.register("photo", in_(LONG)).expect("register");

        let mut wrong = attach_raw(service.port(), &[b'x'; WAIT_TOKEN_LEN]);
        let answer = read_outcome(&mut wrong).expect("wrong-token answer");
        assert!(refused(&answer, REFUSED_UNKNOWN), "got {answer:?}");

        let unknown = WaitToken::generate();
        let answer = wait(service.port(), &unknown, LONG).expect("unknown-token wait");
        assert!(refused(&answer, REFUSED_UNKNOWN), "got {answer:?}");

        let mut short = attach_raw(service.port(), b"too-short");
        short
            .shutdown(Shutdown::Write)
            .expect("finish the short token");
        let answer = read_outcome(&mut short).expect("short-token answer");
        assert!(refused(&answer, REFUSED_MALFORMED), "got {answer:?}");

        assert_eq!(service.attached_waiters(), 0);
        service
            .complete("photo", b"done".to_vec())
            .expect("complete");
        assert_eq!(
            wait(service.port(), &token, LONG).expect("real wait"),
            WaitOutcome::Completed(b"done".to_vec()),
            "refusals must not disturb the real registration"
        );

        // The client-side parser accepts exactly the form the server issues.
        let issued = WaitToken::generate();
        assert_eq!(issued.as_str().parse::<WaitToken>(), Ok(issued.clone()));
        assert_eq!(
            issued.as_str().to_uppercase().parse::<WaitToken>(),
            Err(WaitError::MalformedToken)
        );
        assert_eq!(
            "not-a-token".parse::<WaitToken>(),
            Err(WaitError::MalformedToken)
        );
    }

    #[test]
    fn shutdown_wakes_every_attached_waiter_and_stops_accepting() {
        let service = WaitService::start(8).expect("start wait service");
        let a = service.register("a", in_(LONG)).expect("register a");
        let b = service.register("b", in_(LONG)).expect("register b");
        let waiting_a = spawn_wait(service.port(), &a);
        let waiting_b = spawn_wait(service.port(), &b);
        wait_until("two waiters to attach", || service.attached_waiters() == 2);

        let started = Instant::now();
        service.shutdown().expect("shutdown");
        assert_eq!(
            waiting_a.join().expect("a").expect("wait a"),
            WaitOutcome::Shutdown
        );
        assert_eq!(
            waiting_b.join().expect("b").expect("wait b"),
            WaitOutcome::Shutdown
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "shutdown must wake, not wait out"
        );

        assert_eq!(service.register("c", in_(LONG)), Err(WaitError::ShutDown));
        assert_eq!(service.complete("a", Vec::new()), Err(WaitError::ShutDown));
        // A closed listener refuses a new client instead of leaving it queued. The port number can
        // be taken for an instant (another test's listener, or a Linux TCP self-connect), so a few
        // spaced attempts are allowed. A listener left open accepts every one of them: they stay
        // well under its backlog, and retrying without a cap would end only once that backlog fills.
        let refused = (0..50).any(|_| {
            let refused = TcpStream::connect(("127.0.0.1", service.port())).is_err();
            if !refused {
                thread::sleep(Duration::from_millis(20));
            }
            refused
        });
        assert!(
            refused,
            "a shut-down service must not keep accepting connections"
        );
    }

    #[test]
    fn register_and_complete_stay_prompt_while_a_waiter_sleeps() {
        let service = WaitService::start(8).expect("start wait service");
        let token = service.register("asleep", in_(LONG)).expect("register");
        let waiter = spawn_wait(service.port(), &token);
        wait_until("the waiter to attach", || service.attached_waiters() == 1);
        thread::sleep(Duration::from_millis(20));

        // If the sleeping waiter held the map lock these would block for its five-second deadline.
        let started = Instant::now();
        service
            .register("other", in_(LONG))
            .expect("register other");
        service
            .complete("other", b"x".to_vec())
            .expect("complete other");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "map lock held while sleeping: {elapsed:?}"
        );

        service
            .complete("asleep", b"done".to_vec())
            .expect("complete");
        assert_eq!(
            waiter.join().expect("waiter").expect("wait"),
            WaitOutcome::Completed(b"done".to_vec())
        );
    }

    #[test]
    fn expired_registrations_are_pruned_on_touch_and_the_cap_refuses_growth() {
        let service = WaitService::start(8).expect("start wait service");
        let stale = service
            .register("old", in_(Duration::from_millis(50)))
            .expect("register old");
        service
            .complete("old", b"undelivered".to_vec())
            .expect("complete old");
        thread::sleep(Duration::from_millis(100));

        // The next touch prunes the expired registration together with its undelivered outcome.
        let fresh = service.register("old", in_(LONG)).expect("re-register old");
        assert_ne!(fresh, stale);
        service
            .complete("old", b"fresh".to_vec())
            .expect("the pruned outcome must not linger as AlreadyCompleted");
        let answer = wait(service.port(), &stale, LONG).expect("stale wait");
        assert!(refused(&answer, REFUSED_UNKNOWN), "got {answer:?}");

        for index in 1..MAX_WAIT_REGISTRATIONS - 1 {
            service
                .register(&format!("live-{index}"), in_(LONG))
                .expect("register live");
        }
        service
            .register("short", in_(Duration::from_millis(50)))
            .expect("register short");
        assert_eq!(
            service.register("over", in_(LONG)),
            Err(WaitError::RegistrationLimit(MAX_WAIT_REGISTRATIONS))
        );
        thread::sleep(Duration::from_millis(100));
        service
            .register("over", in_(LONG))
            .expect("the expired registration frees room on the next touch");
    }

    #[test]
    fn invalid_registrations_and_completions_fail_loudly() {
        let service = WaitService::start(8).expect("start wait service");
        service.register("photo", in_(LONG)).expect("register");
        assert_eq!(
            service.register("photo", in_(LONG)),
            Err(WaitError::DuplicateKey)
        );
        assert_eq!(
            service.register("past", Instant::now()),
            Err(WaitError::DeadlineElapsed)
        );
        assert_eq!(
            service.complete("photo", vec![0; MAX_WAIT_OUTCOME_BYTES + 1]),
            Err(WaitError::OutcomeTooLarge(MAX_WAIT_OUTCOME_BYTES + 1))
        );
        assert_eq!(
            service.complete("missing", Vec::new()),
            Err(WaitError::UnknownKey)
        );
        service
            .complete("photo", b"first".to_vec())
            .expect("complete");
        assert_eq!(
            service.complete("photo", b"second".to_vec()),
            Err(WaitError::AlreadyCompleted),
            "a terminal outcome is never overwritten"
        );
        assert!(WaitService::start(0).is_err());
    }

    #[test]
    fn a_client_timeout_before_the_deadline_keeps_the_registration() {
        let service = WaitService::start(8).expect("start wait service");
        let token = service.register("photo", in_(LONG)).expect("register");

        let started = Instant::now();
        let received = wait(service.port(), &token, Duration::from_millis(100)).expect("wait");
        assert_eq!(received, WaitOutcome::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));

        wait_until("the abandoned slot to free", || {
            service.attached_waiters() == 0
        });
        service
            .complete("photo", b"done".to_vec())
            .expect("complete");
        assert_eq!(
            wait(service.port(), &token, LONG).expect("second wait"),
            WaitOutcome::Completed(b"done".to_vec())
        );
    }

    #[test]
    fn the_slot_frees_after_delivery_even_if_the_client_keeps_its_socket_open() {
        let service = WaitService::start(1).expect("start wait service");
        let a = service.register("a", in_(LONG)).expect("register a");
        let b = service.register("b", in_(LONG)).expect("register b");
        let mut lingering = attach_raw(service.port(), a.as_str().as_bytes());
        wait_until("the waiter to attach", || service.attached_waiters() == 1);
        service.complete("a", b"a".to_vec()).expect("complete a");
        assert_eq!(
            read_outcome(&mut lingering).expect("outcome"),
            WaitOutcome::Completed(b"a".to_vec())
        );

        // The server shuts the socket down to end its watcher, so an idle client cannot pin
        // the watcher thread or the only slot.
        wait_until("the delivered slot to free", || {
            service.attached_waiters() == 0
        });
        let waiting_b = spawn_wait(service.port(), &b);
        wait_until("the next waiter to attach", || {
            service.attached_waiters() == 1
        });
        service.complete("b", b"b".to_vec()).expect("complete b");
        assert_eq!(
            waiting_b.join().expect("b").expect("wait b"),
            WaitOutcome::Completed(b"b".to_vec())
        );
        drop(lingering);
    }
}
