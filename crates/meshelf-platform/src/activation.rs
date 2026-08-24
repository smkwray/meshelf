//! Local, loopback-only activation for the resident desktop process.
//!
//! This channel carries only a per-process token. It is separate from the production
//! Tailscale listener and never carries clipboard or peer data.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use meshelf_core::MessageId;

const ACTIVATION_FILE: &str = "activation";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const READ_TIMEOUT: Duration = Duration::from_millis(250);

/// Start the loopback activation listener and publish its address and token.
pub fn listen(data_dir: &Path, on_activate: impl Fn() + Send + 'static) -> io::Result<()> {
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
                if authenticates(stream, &token) {
                    on_activate();
                }
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
    let Some((port, token)) = read_activation(&data_dir.join(ACTIVATION_FILE)) else {
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

fn write_activation(path: &Path, port: u16, token: &str) -> io::Result<()> {
    let temporary_path = path.with_file_name(format!(".activation-{token}.tmp"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)?;
        write_activation_contents(&mut file, port, token)?;
        file.sync_all()?;
        make_owner_only(&temporary_path);

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

fn make_owner_only(path: &Path) {
    // Rust's standard library has no portable owner-only ACL API. On Unix platforms
    // with chmod, apply the restrictive mode; Windows uses the ACL of its config directory.
    let _ = Command::new("chmod")
        .args(["600", &path_to_arg(path)])
        .status();
}

fn path_to_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn read_activation(path: &Path) -> Option<(u16, String)> {
    let contents = fs::read_to_string(path).ok()?;
    let mut fields = contents.split_whitespace();
    let port = fields.next()?.parse().ok()?;
    let token = fields.next()?.to_owned();
    if fields.next().is_some() || token.is_empty() {
        return None;
    }
    Some((port, token))
}

fn authenticates(mut stream: TcpStream, expected_token: &str) -> bool {
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err() {
        return false;
    }

    let expected = expected_token.as_bytes();
    let mut received = Vec::with_capacity(expected.len() + 1);
    let mut buffer = [0_u8; 64];
    loop {
        let read_limit = (expected.len() + 1).saturating_sub(received.len());
        if read_limit == 0 {
            return false;
        }
        let buffer_limit = read_limit.min(buffer.len());
        let Ok(bytes_read) = stream.read(&mut buffer[..buffer_limit]) else {
            return false;
        };
        if bytes_read == 0 {
            return received == expected;
        }
        received.extend_from_slice(&buffer[..bytes_read]);
    }
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
    fn listener_is_signalled_and_callback_runs_once() {
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
}
