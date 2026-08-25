//! Local, loopback-only activation for the resident desktop process.
//!
//! This channel carries only a per-process token. It is separate from the production
//! Tailscale listener and never carries clipboard or peer data.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::process::Command;

use fs2::FileExt;
use meshelf_core::{MAX_CONTROL_REQUEST_BYTES as CORE_MAX_CONTROL_REQUEST_BYTES, MessageId};

const ACTIVATION_FILE: &str = "activation";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_CONTROL_REQUEST_BYTES: usize = CORE_MAX_CONTROL_REQUEST_BYTES;
pub const MAX_CONTROL_RESPONSE_BYTES: usize = 64 * 1024;

/// The one process-wide resident lock shared by the desktop and headless
/// `serve` entry points. Ordinary CLI requests do not acquire it.
#[derive(Debug)]
pub struct ResidentLock {
    file: File,
}

pub fn acquire_resident_lock(data_dir: &Path) -> io::Result<Option<ResidentLock>> {
    fs::create_dir_all(data_dir)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(data_dir.join("resident.lock"))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(ResidentLock { file })),
        Err(error) if is_lock_contention(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Another live instance holds the lock, as opposed to the lock being unusable.
///
/// Unix reports contention as `WouldBlock`. Windows reports `ERROR_SHARING_VIOLATION` (32) or
/// `ERROR_LOCK_VIOLATION` (33), which Rust maps to `ErrorKind::Uncategorized`, so matching on
/// `WouldBlock` alone silently turns "already running" into a hard error there. That would have
/// made a second launch fail outright on Windows instead of signalling the resident instance and
/// exiting quietly, regressing the behaviour that made relaunching show the window again.
fn is_lock_contention(error: &io::Error) -> bool {
    if error.kind() == ErrorKind::WouldBlock {
        return true;
    }
    cfg!(windows) && matches!(error.raw_os_error(), Some(32) | Some(33))
}

impl Drop for ResidentLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Start the loopback activation listener and publish its address and token.
pub fn listen(data_dir: &Path, on_activate: impl Fn() + Send + 'static) -> io::Result<()> {
    listen_with_control(data_dir, on_activate, |_request| {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "legacy activation listener does not handle control requests",
        ))
    })
}

/// Start the loopback listener with a bounded request/response transport.
///
/// A connection first proves possession of the token in the activation file. A clean EOF after
/// that token is the legacy raise-the-window signal. Otherwise the connection carries one
/// length-prefixed request and one length-prefixed response. The request handler owns command
/// semantics; this module only supplies authenticated local transport.
pub fn listen_with_control(
    data_dir: &Path,
    on_activate: impl Fn() + Send + 'static,
    on_request: impl Fn(&[u8]) -> io::Result<Vec<u8>> + Send + 'static,
) -> io::Result<()> {
    fs::create_dir_all(data_dir)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let token = MessageId::new().to_string();
    let activation_path = data_dir.join(ACTIVATION_FILE);
    write_activation(&activation_path, port, &token)?;

    let thread_activation_path = activation_path.clone();
    if let Err(error) = thread::Builder::new()
        .name("meshelf-activation".to_owned())
        .spawn(move || {
            for connection in listener.incoming() {
                let Ok(stream) = connection else {
                    break;
                };
                let _ = handle_connection(stream, &token, &on_activate, &on_request);
            }
            let _ = fs::remove_file(thread_activation_path);
        })
    {
        let _ = fs::remove_file(activation_path);
        return Err(error);
    }

    Ok(())
}

/// Signal the resident desktop process, returning whether the token was sent.
pub fn signal(data_dir: &Path) -> bool {
    let Ok((port, token)) = read_activation(&data_dir.join(ACTIVATION_FILE)) else {
        return false;
    };
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
        return false;
    };
    if stream.set_write_timeout(Some(CONNECT_TIMEOUT)).is_err()
        || stream.write_all(token.as_bytes()).is_err()
        || stream.shutdown(Shutdown::Write).is_err()
    {
        return false;
    }
    true
}

/// Send one bounded local-control request and return its bounded response.
pub fn request(data_dir: &Path, request: &[u8]) -> io::Result<Vec<u8>> {
    if request.len() > MAX_CONTROL_REQUEST_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "control request is {} bytes; maximum is {MAX_CONTROL_REQUEST_BYTES}",
                request.len()
            ),
        ));
    }

    let (port, token) = read_activation(&data_dir.join(ACTIVATION_FILE))?;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.write_all(token.as_bytes())?;
    write_frame(&mut stream, request, MAX_CONTROL_REQUEST_BYTES)?;
    stream.flush()?;
    read_frame(&mut stream, MAX_CONTROL_RESPONSE_BYTES, "response")
}

fn write_activation(path: &Path, port: u16, token: &str) -> io::Result<()> {
    let temporary_path = path.with_file_name(format!(".activation-{token}.tmp"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)?;
        write_activation_contents(&mut file, port, token)?;
        file.sync_all()?;
        make_owner_only(&temporary_path)?;

        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::rename(&temporary_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary_path);
    }
    result
}

fn write_activation_contents(file: &mut File, port: u16, token: &str) -> io::Result<()> {
    writeln!(file, "{port} {token}")
}

pub(crate) fn make_owner_only(path: &Path) -> io::Result<()> {
    // Rust's standard library has no portable owner-only ACL API. On Unix platforms
    // with chmod, apply the restrictive mode; Windows uses the ACL of its config directory.
    #[cfg(unix)]
    {
        let mode = if path.metadata()?.is_dir() {
            "700"
        } else {
            "600"
        };
        let status = Command::new("chmod")
            .args([mode, &path_to_arg(path)])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "chmod {mode} for {} exited with {status}",
                path.display()
            )))
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(unix)]
fn path_to_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn read_activation(path: &Path) -> io::Result<(u16, String)> {
    let contents = fs::read_to_string(path)?;
    let mut fields = contents.split_whitespace();
    let port = fields
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "activation file has no port"))?
        .parse()
        .map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("activation file has an invalid port: {error}"),
            )
        })?;
    let token = fields
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "activation file has no token"))?
        .to_owned();
    if fields.next().is_some() || token.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "activation file has malformed fields",
        ));
    }
    Ok((port, token))
}

fn handle_connection(
    mut stream: TcpStream,
    expected_token: &str,
    on_activate: &impl Fn(),
    on_request: &impl Fn(&[u8]) -> io::Result<Vec<u8>>,
) -> io::Result<()> {
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err() {
        return Ok(());
    }
    if stream.set_write_timeout(Some(READ_TIMEOUT)).is_err() {
        return Ok(());
    }

    let mut received_token = vec![0_u8; expected_token.len()];
    if stream.read_exact(&mut received_token).is_err()
        || received_token != expected_token.as_bytes()
    {
        return Ok(());
    }

    let mut first_frame_byte = [0_u8; 1];
    match stream.read(&mut first_frame_byte) {
        Ok(0) => {
            on_activate();
            Ok(())
        }
        Ok(1) => {
            let mut length = [0_u8; 4];
            length[0] = first_frame_byte[0];
            stream.read_exact(&mut length[1..])?;
            let request_length = u32::from_be_bytes(length) as usize;
            if request_length > MAX_CONTROL_REQUEST_BYTES {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "control request is {request_length} bytes; maximum is {MAX_CONTROL_REQUEST_BYTES}"
                    ),
                ));
            }
            let mut request = vec![0_u8; request_length];
            stream.read_exact(&mut request)?;
            let response = on_request(&request)?;
            write_frame(&mut stream, &response, MAX_CONTROL_RESPONSE_BYTES)
        }
        Ok(_) => unreachable!("a one-byte read cannot return more than one byte"),
        Err(error) => Err(error),
    }
}

fn write_frame(stream: &mut TcpStream, payload: &[u8], maximum: usize) -> io::Result<()> {
    if payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "control frame is {} bytes; maximum is {maximum}",
                payload.len()
            ),
        ));
    }
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)
}

fn read_frame(stream: &mut TcpStream, maximum: usize, label: &str) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > maximum {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("control {label} is {length} bytes; maximum is {maximum}"),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::mpsc,
        time::{Duration, Instant},
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("meshelf-activation-test-{}", MessageId::new()));
            fs::create_dir(&path).expect("create unique temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn local_control_still_raises_the_window_for_a_legacy_activation_signal() {
        let directory = TestDirectory::new();
        let (activated, received) = mpsc::channel();
        listen(directory.path(), move || {
            activated.send(()).expect("activation receiver is alive");
        })
        .expect("start activation listener");

        assert!(signal(directory.path()));
        received
            .recv_timeout(Duration::from_secs(1))
            .expect("activation callback");
        assert!(received.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn signal_without_activation_file_returns_false() {
        let directory = TestDirectory::new();
        assert!(!signal(directory.path()));
    }

    #[test]
    fn wrong_token_does_not_run_callback() {
        let directory = TestDirectory::new();
        let (activated, received) = mpsc::channel();
        listen(directory.path(), move || {
            activated.send(()).expect("activation receiver is alive");
        })
        .expect("start activation listener");
        let (port, _) = read_activation(&directory.path().join(ACTIVATION_FILE))
            .expect("activation file contents");
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
            .expect("connect activation listener");
        stream
            .write_all(b"wrong-token")
            .expect("write wrong activation token");
        stream
            .shutdown(Shutdown::Write)
            .expect("finish wrong activation token");

        assert!(received.recv_timeout(Duration::from_millis(400)).is_err());
    }

    #[test]
    fn stale_activation_file_returns_false_without_blocking() {
        let directory = TestDirectory::new();
        fs::write(
            directory.path().join(ACTIVATION_FILE),
            "0 00000000-0000-0000-0000-000000000000\n",
        )
        .expect("write stale activation file");

        let started = Instant::now();
        assert!(!signal(directory.path()));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn local_control_round_trips_a_bounded_request_and_response() {
        let directory = TestDirectory::new();
        listen_with_control(
            directory.path(),
            || {},
            |request| {
                let mut response = b"response:".to_vec();
                response.extend_from_slice(request);
                Ok(response)
            },
        )
        .expect("start local control listener");

        let response = request(directory.path(), b"bounded request")
            .expect("bounded request/response round trip");
        assert_eq!(response, b"response:bounded request");
    }

    #[test]
    fn one_mib_worst_case_text_crosses_control_channel() {
        let directory = TestDirectory::new();
        listen_with_control(
            directory.path(),
            || {},
            |request| {
                assert_eq!(request.len(), meshelf_core::MAX_TEXT_BYTES * 6);
                Ok(Vec::new())
            },
        )
        .expect("start local control listener");
        let worst_case_encoded = vec![b'\\'; meshelf_core::MAX_TEXT_BYTES * 6];
        assert!(request(directory.path(), &worst_case_encoded).is_ok());
    }

    #[test]
    fn local_listener_is_ipv4_loopback_only() {
        let directory = TestDirectory::new();
        listen_with_control(directory.path(), || {}, |_| Ok(Vec::new()))
            .expect("start local control listener");
        let (port, _) = read_activation(&directory.path().join(ACTIVATION_FILE))
            .expect("activation file contents");
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        assert!(TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).is_ok());
    }

    #[test]
    fn desktop_and_serve_cannot_both_own_resident_lock() {
        let directory = TestDirectory::new();
        let first = acquire_resident_lock(directory.path())
            .expect("first lock")
            .expect("first owner");
        assert!(
            acquire_resident_lock(directory.path())
                .expect("second lock")
                .is_none()
        );
        drop(first);
        assert!(
            acquire_resident_lock(directory.path())
                .expect("lock after release")
                .is_some()
        );
    }

    #[test]
    fn local_control_rejects_a_wrong_token_before_reading_a_request() {
        let directory = TestDirectory::new();
        let (handled, received) = mpsc::channel();
        listen_with_control(
            directory.path(),
            || {},
            move |_request| {
                handled.send(()).expect("handler receiver is alive");
                Ok(Vec::new())
            },
        )
        .expect("start local control listener");

        let (port, token) = read_activation(&directory.path().join(ACTIVATION_FILE))
            .expect("activation file contents");
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
            .expect("connect local control listener");
        let wrong_token = vec![b'x'; token.len()];
        stream
            .write_all(&wrong_token)
            .and_then(|()| stream.write_all(&[0, 0, 0, 1, b'x']))
            .expect("write wrong token and request");
        stream
            .shutdown(Shutdown::Write)
            .expect("finish wrong-token request");

        assert!(received.recv_timeout(Duration::from_millis(500)).is_err());
    }

    #[test]
    fn local_control_rejects_an_oversized_request_without_allocating_it() {
        let directory = TestDirectory::new();
        let (handled, received) = mpsc::channel();
        listen_with_control(
            directory.path(),
            || {},
            move |_request| {
                handled.send(()).expect("handler receiver is alive");
                Ok(Vec::new())
            },
        )
        .expect("start local control listener");

        let (port, token) = read_activation(&directory.path().join(ACTIVATION_FILE))
            .expect("activation file contents");
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
            .expect("connect local control listener");
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set bounded test timeout");
        stream.write_all(token.as_bytes()).expect("write token");
        stream
            .write_all(&((MAX_CONTROL_REQUEST_BYTES as u32) + 1).to_be_bytes())
            .expect("write oversized request length");

        let mut byte = [0_u8; 1];
        let result = stream.read(&mut byte);
        assert!(matches!(result, Ok(0) | Err(_)));
        assert!(received.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn stale_control_file_returns_an_error_rather_than_blocking() {
        let directory = TestDirectory::new();
        fs::write(
            directory.path().join(ACTIVATION_FILE),
            "0 00000000-0000-0000-0000-000000000000\n",
        )
        .expect("write stale control file");

        let started = Instant::now();
        let result = request(directory.path(), b"request");
        assert!(result.is_err(), "stale control file must return an error");
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
