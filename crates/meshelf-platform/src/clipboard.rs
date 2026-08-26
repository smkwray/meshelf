use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
};

use meshelf_core::{ClipboardError, ClipboardSink};
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

enum ClipboardCommand {
    Read(Sender<Result<ClipboardItem, String>>),
    Write(String, Sender<Result<(), String>>),
    WriteFiles(Vec<PathBuf>, Sender<Result<(), String>>),
    Shutdown,
}

#[derive(Debug)]
struct ClipboardWorkerInner {
    commands: SyncSender<ClipboardCommand>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

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
#[derive(Debug, Clone)]
pub struct ClipboardWorker {
    inner: Arc<ClipboardWorkerInner>,
}

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
        self.request(|response| ClipboardCommand::WriteFiles(paths, response))
    }
}

impl ClipboardSource for ClipboardWorker {
    fn read_item(&self) -> Result<ClipboardItem, PlatformClipboardError> {
        self.request(ClipboardCommand::Read)
    }
}

impl ClipboardSink for ClipboardWorker {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        self.request(|response| ClipboardCommand::Write(text.to_owned(), response))
            .map_err(ClipboardError::from)
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
            ClipboardCommand::Write(text, response) => {
                let result = clipboard
                    .set_text(&text)
                    .map_err(|error| format!("clipboard text write failed: {error}"))
                    .and_then(|()| {
                        clipboard.get_text().map_err(|error| {
                            format!("clipboard text verification read failed: {error}")
                        })
                    })
                    .and_then(|observed| require_exact_text(&text, &observed));
                let _ = response.send(result);
            }
            ClipboardCommand::WriteFiles(paths, response) => {
                let result = if paths.is_empty() {
                    Err("cannot place an empty file list on the clipboard".to_owned())
                } else {
                    clipboard
                        .clear()
                        .and_then(|()| clipboard.set().file_list(&paths))
                        .map_err(|error| error.to_string())
                };
                let _ = response.send(result);
            }
            ClipboardCommand::Shutdown => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_text_verification_rejects_a_stale_clipboard() {
        assert!(require_exact_text("offered text", "offered text").is_ok());
        let error = require_exact_text("offered text", "stale clipboard")
            .expect_err("stale clipboard must not verify");
        assert!(error.contains("wrote 12 UTF-8 bytes but read back 15"));
        assert!(!error.contains("offered text"));
        assert!(!error.contains("stale clipboard"));
    }
}
