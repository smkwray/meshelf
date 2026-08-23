use std::{
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
};

use meshelf_core::{ClipboardError, ClipboardSink};
use thiserror::Error;

pub trait ClipboardSource: Send + Sync + 'static {
    fn read_text(&self) -> Result<String, PlatformClipboardError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("platform clipboard error: {message}")]
pub struct PlatformClipboardError {
    message: String,
}

impl PlatformClipboardError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

enum ClipboardCommand {
    Read(Sender<Result<String, String>>),
    Write(String, Sender<Result<(), String>>),
    Shutdown,
}

#[derive(Debug)]
struct ClipboardWorkerInner {
    commands: Sender<ClipboardCommand>,
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
        let (command_tx, command_rx) = mpsc::channel();
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
            .send(make_command(response_tx))
            .map_err(|error| PlatformClipboardError::new(error.to_string()))?;
        response_rx
            .recv()
            .map_err(|error| PlatformClipboardError::new(error.to_string()))?
            .map_err(PlatformClipboardError::new)
    }
}

impl ClipboardSource for ClipboardWorker {
    fn read_text(&self) -> Result<String, PlatformClipboardError> {
        self.request(ClipboardCommand::Read)
    }
}

impl ClipboardSink for ClipboardWorker {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        self.request(|response| ClipboardCommand::Write(text.to_owned(), response))
            .map_err(|error| ClipboardError::new(error.to_string()))
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
                let result = clipboard.get_text().map_err(|error| error.to_string());
                let _ = response.send(result);
            }
            ClipboardCommand::Write(text, response) => {
                let result = clipboard.set_text(text).map_err(|error| error.to_string());
                let _ = response.send(result);
            }
            ClipboardCommand::Shutdown => break,
        }
    }
}
