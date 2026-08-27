use std::path::PathBuf;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::path::Path;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::{
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
};

use meshelf_core::ClipboardError;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use meshelf_core::ClipboardSink;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardItem {
    Text(String),
    Files(Vec<PathBuf>),
}

pub trait ClipboardSource: Send + Sync + 'static {
    fn read_item(&self) -> Result<ClipboardItem, PlatformClipboardError>;

    fn read_text(&self) -> Result<String, PlatformClipboardError> {
        match self.read_item()? {
            ClipboardItem::Text(text) => Ok(text),
            ClipboardItem::Files(paths) => Err(PlatformClipboardError::new(format!(
                "clipboard contains {} file item(s), not text",
                paths.len()
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("platform clipboard error: {message}")]
pub struct PlatformClipboardError {
    message: String,
    uncertain: bool,
}

impl PlatformClipboardError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uncertain: false,
        }
    }

    #[must_use]
    fn uncertain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uncertain: true,
        }
    }

    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        self.uncertain
    }
}

impl From<PlatformClipboardError> for ClipboardError {
    fn from(error: PlatformClipboardError) -> Self {
        if error.is_uncertain() {
            Self::uncertain(error.to_string())
        } else {
            Self::new(error.to_string())
        }
    }
}

struct NativeWriteError {
    message: String,
    native_write_succeeded: bool,
}

impl NativeWriteError {
    fn before_mutation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            native_write_succeeded: false,
        }
    }

    fn after_mutation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            native_write_succeeded: true,
        }
    }
}

impl From<NativeWriteError> for PlatformClipboardError {
    fn from(error: NativeWriteError) -> Self {
        if error.native_write_succeeded {
            Self::uncertain(error.message)
        } else {
            Self::new(error.message)
        }
    }
}

impl From<NativeWriteError> for ClipboardError {
    fn from(error: NativeWriteError) -> Self {
        PlatformClipboardError::from(error).into()
    }
}

/// Native clipboard operations used by the worker. Tests supply a scripted
/// backend so classification runs on the same path as production.
pub trait NativeClipboard {
    fn set_text(&mut self, text: &str) -> Result<(), String>;
    fn get_text(&mut self) -> Result<String, String>;
    fn clear(&mut self) -> Result<(), String>;
    fn set_file_list(&mut self, paths: &[PathBuf]) -> Result<(), String>;
    fn get_file_list(&mut self) -> Result<Vec<PathBuf>, String>;
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl NativeClipboard for arboard::Clipboard {
    fn set_text(&mut self, text: &str) -> Result<(), String> {
        arboard::Clipboard::set_text(self, text).map_err(|error| error.to_string())
    }

    fn get_text(&mut self) -> Result<String, String> {
        arboard::Clipboard::get_text(self).map_err(|error| error.to_string())
    }

    fn clear(&mut self) -> Result<(), String> {
        arboard::Clipboard::clear(self).map_err(|error| error.to_string())
    }

    fn set_file_list(&mut self, paths: &[PathBuf]) -> Result<(), String> {
        self.set()
            .file_list(paths)
            .map_err(|error| error.to_string())
    }

    fn get_file_list(&mut self) -> Result<Vec<PathBuf>, String> {
        self.get().file_list().map_err(|error| error.to_string())
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
enum ClipboardCommand {
    Read(Sender<Result<ClipboardItem, String>>),
    Write(String, Sender<Result<(), NativeWriteError>>),
    WriteFiles(Vec<PathBuf>, Sender<Result<(), NativeWriteError>>),
    Shutdown,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug)]
struct ClipboardWorkerInner {
    commands: SyncSender<ClipboardCommand>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for ClipboardWorkerInner {
    fn drop(&mut self) {
        let _ = self.commands.send(ClipboardCommand::Shutdown);
        if let Ok(worker) = self.worker.get_mut()
            && let Some(handle) = worker.take()
        {
            let _ = handle.join();
        }
    }
}

/// A clonable handle to one native clipboard worker thread.
///
/// Keeping the native clipboard object alive on one thread avoids concurrent access on Windows
/// and preserves clipboard ownership semantics used by Linux backends.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Clone)]
pub struct ClipboardWorker {
    inner: Arc<ClipboardWorkerInner>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl ClipboardWorker {
    pub fn new() -> Result<Self, PlatformClipboardError> {
        let (command_tx, command_rx) = mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("meshelf-clipboard".to_owned())
            .spawn(move || clipboard_thread(command_rx, ready_tx))
            .map_err(|error| PlatformClipboardError::new(error.to_string()))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                inner: Arc::new(ClipboardWorkerInner {
                    commands: command_tx,
                    worker: Mutex::new(Some(worker)),
                }),
            }),
            Ok(Err(message)) => {
                let _ = worker.join();
                Err(PlatformClipboardError::new(message))
            }
            Err(error) => {
                let _ = worker.join();
                Err(PlatformClipboardError::new(error.to_string()))
            }
        }
    }

    fn request<T>(
        &self,
        make_command: impl FnOnce(Sender<Result<T, String>>) -> ClipboardCommand,
    ) -> Result<T, PlatformClipboardError> {
        let (response_tx, response_rx) = mpsc::channel();
        self.inner
            .commands
            .try_send(make_command(response_tx))
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    PlatformClipboardError::new("another clipboard operation is already queued")
                }
                TrySendError::Disconnected(_) => {
                    PlatformClipboardError::new("clipboard worker is unavailable")
                }
            })?;
        response_rx
            .recv()
            .map_err(|error| {
                PlatformClipboardError::uncertain(format!(
                    "clipboard worker stopped after accepting the operation: {error}"
                ))
            })?
            .map_err(PlatformClipboardError::new)
    }

    pub fn set_files(&self, paths: &[impl AsRef<Path>]) -> Result<(), PlatformClipboardError> {
        let paths = paths
            .iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect();
        let (response_tx, response_rx) = mpsc::channel();
        self.inner
            .commands
            .try_send(ClipboardCommand::WriteFiles(paths, response_tx))
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    PlatformClipboardError::new("another clipboard operation is already queued")
                }
                TrySendError::Disconnected(_) => {
                    PlatformClipboardError::new("clipboard worker is unavailable")
                }
            })?;
        match response_rx.recv() {
            Err(error) => Err(PlatformClipboardError::uncertain(format!(
                "clipboard worker stopped after accepting the operation: {error}"
            ))),
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl ClipboardSource for ClipboardWorker {
    fn read_item(&self) -> Result<ClipboardItem, PlatformClipboardError> {
        self.request(ClipboardCommand::Read)
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl ClipboardSink for ClipboardWorker {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        let (response_tx, response_rx) = mpsc::channel();
        self.inner
            .commands
            .try_send(ClipboardCommand::Write(text.to_owned(), response_tx))
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    ClipboardError::new("another clipboard operation is already queued")
                }
                TrySendError::Disconnected(_) => {
                    ClipboardError::new("clipboard worker is unavailable")
                }
            })?;
        match response_rx.recv() {
            Err(error) => Err(ClipboardError::uncertain(format!(
                "clipboard worker stopped after accepting the operation: {error}"
            ))),
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(if error.native_write_succeeded {
                ClipboardError::uncertain(error.message)
            } else {
                ClipboardError::new(error.message)
            }),
        }
    }
}

fn require_exact_text(expected: &str, observed: &str) -> Result<(), String> {
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "clipboard text verification failed: wrote {} UTF-8 bytes but read back {}",
            expected.len(),
            observed.len()
        ))
    }
}

/// After the native write returns success, a readback failure or mismatch is
/// uncertain: the clipboard may already hold the offered text.
fn confirm_text_write(
    readback: Result<String, String>,
    expected: &str,
) -> Result<(), NativeWriteError> {
    match readback {
        Err(error) => Err(NativeWriteError::after_mutation(format!(
            "clipboard text verification read failed: {error}"
        ))),
        Ok(observed) => {
            require_exact_text(expected, &observed).map_err(NativeWriteError::after_mutation)
        }
    }
}

/// Place text through the same decision path the worker thread uses.
///
/// `arboard::Clipboard::set_text` is not a single untouched-or-written step on
/// the platforms we ship, so a returned error is classified uncertain. Verified
/// against the pinned sources:
/// - macOS `arboard-3.6.1/src/platform/osx.rs:285` calls `clear()` (pasteboard
///   `clearContents`) before `writeObjects` at `:290`, which may then fail with
///   the clipboard already emptied.
/// - Windows `arboard-3.6.1/src/platform/windows.rs:677` calls
///   `clipboard_win::raw::set_string`, which reaches `set_string_inner` at
///   `clipboard-win-5.4.1/src/raw.rs:556` and clears before writing.
///
/// One Windows path does fail untouched — opening the clipboard at
/// `windows.rs:675` errors before any clear — but the caller cannot distinguish
/// it from the post-clear failures above, so the conservative classification is
/// the only sound one. Do not narrow this to "definite" without a pinned-source
/// path proving the clipboard was never entered.
pub fn write_text_on(
    clipboard: &mut impl NativeClipboard,
    text: &str,
) -> Result<(), ClipboardError> {
    write_text_on_native(clipboard, text).map_err(Into::into)
}

fn write_text_on_native(
    clipboard: &mut impl NativeClipboard,
    text: &str,
) -> Result<(), NativeWriteError> {
    match clipboard.set_text(text) {
        Err(error) => Err(NativeWriteError::after_mutation(format!(
            "clipboard text write failed: {error}"
        ))),
        Ok(()) => confirm_text_write(clipboard.get_text(), text),
    }
}

/// Place a file list through the same decision path the worker thread uses.
/// Empty input does not touch the clipboard. `clear` runs before `file_list`;
/// a failed `clear` is definite, a failed `file_list` after `clear` is uncertain.
pub fn write_files_on(
    clipboard: &mut impl NativeClipboard,
    paths: &[PathBuf],
) -> Result<(), ClipboardError> {
    write_files_on_native(clipboard, paths).map_err(Into::into)
}

fn write_files_on_native(
    clipboard: &mut impl NativeClipboard,
    paths: &[PathBuf],
) -> Result<(), NativeWriteError> {
    if paths.is_empty() {
        return Err(NativeWriteError::before_mutation(
            "cannot place an empty file list on the clipboard",
        ));
    }
    match clipboard.clear() {
        Err(error) => Err(NativeWriteError::before_mutation(format!(
            "clipboard file clear failed: {error}"
        ))),
        Ok(()) => match clipboard.set_file_list(paths) {
            Ok(()) => Ok(()),
            Err(error) => Err(NativeWriteError::after_mutation(format!(
                "clipboard file list write failed: {error}"
            ))),
        },
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn handle_command(clipboard: &mut impl NativeClipboard, command: ClipboardCommand) -> bool {
    match command {
        ClipboardCommand::Read(response) => {
            let result = match clipboard.get_file_list() {
                Ok(paths) if !paths.is_empty() => Ok(ClipboardItem::Files(paths)),
                Ok(_) | Err(_) => clipboard.get_text().map(ClipboardItem::Text),
            };
            let _ = response.send(result);
            false
        }
        ClipboardCommand::Write(text, response) => {
            let _ = response.send(write_text_on_native(clipboard, &text));
            false
        }
        ClipboardCommand::WriteFiles(paths, response) => {
            let _ = response.send(write_files_on_native(clipboard, &paths));
            false
        }
        ClipboardCommand::Shutdown => true,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn clipboard_thread(
    commands: Receiver<ClipboardCommand>,
    ready: mpsc::SyncSender<Result<(), String>>,
) {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(clipboard) => {
            let _ = ready.send(Ok(()));
            clipboard
        }
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return;
        }
    };

    while let Ok(command) = commands.recv() {
        match command {
            ClipboardCommand::Read(response) => {
                let result = match clipboard.get().file_list() {
                    Ok(paths) if !paths.is_empty() => Ok(ClipboardItem::Files(paths)),
                    Ok(_) | Err(_) => clipboard
                        .get_text()
                        .map(ClipboardItem::Text)
                        .map_err(|error| error.to_string()),
                };
                let _ = response.send(result);
            }
            command => {
                if handle_command(&mut clipboard, command) {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct ScriptedClipboard {
        texts: Vec<String>,
        files: Vec<PathBuf>,
        set_text_error: Option<String>,
        get_text: Option<Result<String, String>>,
        clear_error: Option<String>,
        clear_calls: u32,
        file_list_error: Option<String>,
    }

    impl NativeClipboard for ScriptedClipboard {
        fn set_text(&mut self, text: &str) -> Result<(), String> {
            if let Some(error) = &self.set_text_error {
                return Err(error.clone());
            }
            self.texts.push(text.to_owned());
            Ok(())
        }

        fn get_text(&mut self) -> Result<String, String> {
            if let Some(result) = &self.get_text {
                return result.clone();
            }
            self.texts
                .last()
                .cloned()
                .ok_or_else(|| "clipboard has no text".to_owned())
        }

        fn clear(&mut self) -> Result<(), String> {
            self.clear_calls += 1;
            if let Some(error) = &self.clear_error {
                return Err(error.clone());
            }
            self.texts.clear();
            self.files.clear();
            Ok(())
        }

        fn set_file_list(&mut self, paths: &[PathBuf]) -> Result<(), String> {
            if let Some(error) = &self.file_list_error {
                return Err(error.clone());
            }
            self.files = paths.to_vec();
            Ok(())
        }

        fn get_file_list(&mut self) -> Result<Vec<PathBuf>, String> {
            Ok(self.files.clone())
        }
    }

    fn send_write(clipboard: &mut ScriptedClipboard, text: &str) -> Result<(), NativeWriteError> {
        write_text_on_native(clipboard, text)
    }

    fn send_write_files(
        clipboard: &mut ScriptedClipboard,
        paths: Vec<PathBuf>,
    ) -> Result<(), NativeWriteError> {
        write_files_on_native(clipboard, &paths)
    }

    #[test]
    fn exact_text_verification_rejects_a_stale_clipboard() {
        assert!(require_exact_text("offered text", "offered text").is_ok());
        let error = require_exact_text("offered text", "stale clipboard")
            .expect_err("stale clipboard must not verify");
        assert!(error.contains("wrote 12 UTF-8 bytes but read back 15"));
        assert!(!error.contains("offered text"));
        assert!(!error.contains("stale clipboard"));
    }

    #[test]
    fn set_text_error_is_uncertain_because_arboard_clears_first() {
        let mut clipboard = ScriptedClipboard {
            set_text_error: Some("NSPasteboard#writeObjects: returned false".to_owned()),
            ..ScriptedClipboard::default()
        };
        let error = send_write(&mut clipboard, "offered text").expect_err("native set_text error");
        assert!(
            error.native_write_succeeded,
            "arboard already cleared the pasteboard before writeObjects/SetClipboardData"
        );
        assert!(ClipboardError::from(error).is_uncertain());
    }

    #[test]
    fn readback_failure_after_successful_write_is_uncertain() {
        let mut clipboard = ScriptedClipboard {
            get_text: Some(Err("clipboard locked".to_owned())),
            ..ScriptedClipboard::default()
        };
        let error = send_write(&mut clipboard, "offered text").expect_err("readback failure");
        assert!(error.native_write_succeeded);
        assert!(error.message.contains("verification read failed"));
        assert!(ClipboardError::from(error).is_uncertain());
        assert_eq!(clipboard.texts.as_slice(), ["offered text"]);
    }

    #[test]
    fn mismatch_after_successful_write_is_uncertain() {
        let mut clipboard = ScriptedClipboard {
            get_text: Some(Ok("stale clipboard".to_owned())),
            ..ScriptedClipboard::default()
        };
        let error = send_write(&mut clipboard, "offered text").expect_err("mismatch");
        assert!(error.native_write_succeeded);
        assert!(error.message.contains("verification failed"));
        assert!(ClipboardError::from(error).is_uncertain());
    }

    #[test]
    fn empty_file_list_is_definite_and_does_not_clear() {
        let mut clipboard = ScriptedClipboard::default();
        let error = send_write_files(&mut clipboard, Vec::new()).expect_err("empty list");
        assert!(!error.native_write_succeeded);
        assert_eq!(clipboard.clear_calls, 0);
        assert!(ClipboardError::from(error).message().contains("empty"));
    }

    #[test]
    fn failed_clear_is_definite() {
        let mut clipboard = ScriptedClipboard {
            clear_error: Some("access denied".to_owned()),
            ..ScriptedClipboard::default()
        };
        let error = send_write_files(&mut clipboard, vec![PathBuf::from("payload.txt")])
            .expect_err("clear failure");
        assert_eq!(clipboard.clear_calls, 1);
        assert!(!error.native_write_succeeded);
        assert!(!ClipboardError::from(error).is_uncertain());
    }

    #[test]
    fn file_list_failure_after_successful_clear_is_uncertain() {
        let mut clipboard = ScriptedClipboard {
            file_list_error: Some("backend locked".to_owned()),
            ..ScriptedClipboard::default()
        };
        let error = send_write_files(&mut clipboard, vec![PathBuf::from("payload.txt")])
            .expect_err("file_list failure after clear");
        assert_eq!(
            clipboard.clear_calls, 1,
            "the worker must call clear before file_list"
        );
        assert!(error.native_write_succeeded);
        let clipboard_error = ClipboardError::from(error);
        assert!(clipboard_error.is_uncertain());
        assert!(clipboard_error.message().contains("file list write failed"));
        assert!(clipboard.files.is_empty());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn full_clipboard_queue_is_definite_before_native_write() {
        let (commands, receiver) = mpsc::sync_channel(1);
        commands
            .send(ClipboardCommand::Shutdown)
            .expect("fill clipboard queue");
        let (release_sender, release_receiver) = mpsc::channel();
        let worker_thread = std::thread::spawn(move || {
            release_receiver.recv().expect("release worker");
            let _ = receiver.recv();
        });
        let worker = ClipboardWorker {
            inner: Arc::new(ClipboardWorkerInner {
                commands,
                worker: Mutex::new(Some(worker_thread)),
            }),
        };

        let error = worker
            .set_text("must not reach the native backend")
            .expect_err("a full queue must refuse immediately");
        assert!(!error.is_uncertain());
        assert!(error.message().contains("already queued"));

        release_sender.send(()).expect("release queued command");
        drop(worker);
    }
}
