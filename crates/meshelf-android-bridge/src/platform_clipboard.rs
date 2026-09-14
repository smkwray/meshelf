//! Deferred Android clipboard and file-export writes: native prepares a dispatch, Kotlin performs
//! the platform write on the main thread, then reports the outcome back through JNI.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        mpsc::{self, RecvTimeoutError, SyncSender},
    },
    time::Duration,
};

use meshelf_core::{ClipboardError, ClipboardSink, MAX_TEXT_BYTES};
use meshelf_net::FetchClipboard;

use crate::{
    NativeError,
    events::{EventRefused, EventSink, KotlinEvent},
    invalid, lock,
};

const WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const OUTCOME_APPLIED: &str = "APPLIED";
const OUTCOME_FOREGROUND_LOST: &str = "FOREGROUND_LOST";
const OUTCOME_PLATFORM_FAILED: &str = "PLATFORM_FAILED";
/// Recent per-gesture failures kept for the activation that owns the gesture to collect.
const MAX_RECORDED_FAILURES: usize = 8;

/// Why a gesture's platform action did not apply. The activation result needs the difference:
/// a lost or superseded foreground is not a platform failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformFailure {
    ForegroundLost,
    PlatformFailed,
}

/// Platform side-effect kind for a verified file publish on Android.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileExportKind {
    Save,
    Share,
}

impl FileExportKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Save => "SAVE",
            Self::Share => "SHARE",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, NativeError> {
        match raw {
            "SAVE" | "SAVE_FILE" => Ok(Self::Save),
            "SHARE" | "SHARE_FILE" => Ok(Self::Share),
            _ => Err(invalid("file export kind must be SAVE or SHARE")),
        }
    }
}

#[derive(Debug)]
pub struct PlatformClipboard {
    events: EventSink,
    gesture_token: Mutex<Option<String>>,
    file_export: Mutex<Option<PreparedExport>>,
    pending: Mutex<HashMap<String, SyncSender<String>>>,
    failures: Mutex<Vec<(String, PlatformFailure)>>,
}

/// One activation's file export: how Android hands the file over, and the card's own name for it.
#[derive(Debug)]
struct PreparedExport {
    kind: FileExportKind,
    card_name: Option<String>,
}

impl PlatformClipboard {
    pub fn new(events: EventSink) -> Arc<Self> {
        Arc::new(Self {
            events,
            gesture_token: Mutex::new(None),
            file_export: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            failures: Mutex::new(Vec::new()),
        })
    }

    /// A newer gesture supersedes an unconsumed older one, which is recorded as foreground lost.
    pub fn prepare_gesture(&self, gesture_token: String) {
        let previous = lock(&self.gesture_token).replace(gesture_token.clone());
        if let Some(previous) = previous
            && previous != gesture_token
        {
            self.record_failure(&previous, PlatformFailure::ForegroundLost);
        }
    }

    /// Ends one activation's use of its gesture: an unconsumed token is withdrawn so nothing
    /// later can spend it, and the recorded reason its platform action did not apply, if any, is
    /// returned once.
    pub fn finish_gesture(&self, gesture_token: &str) -> Option<PlatformFailure> {
        {
            let mut slot = lock(&self.gesture_token);
            if slot.as_deref() == Some(gesture_token) {
                *slot = None;
                *lock(&self.file_export) = None;
            }
        }
        let mut failures = lock(&self.failures);
        let index = failures
            .iter()
            .position(|(token, _)| token == gesture_token)?;
        Some(failures.remove(index).1)
    }

    fn record_failure(&self, gesture_token: &str, failure: PlatformFailure) {
        let mut failures = lock(&self.failures);
        if failures.len() >= MAX_RECORDED_FAILURES {
            failures.remove(0);
        }
        failures.push((gesture_token.to_owned(), failure));
    }

    /// `card_name` is the card's file name. The receiver's verified copy is a `candidate-<id>`
    /// cache object, so without it Android saved and shared files under that cache name.
    pub fn prepare_file_export(&self, kind: FileExportKind, card_name: Option<String>) {
        *lock(&self.file_export) = Some(PreparedExport { kind, card_name });
    }

    pub fn invalidate(&self) {
        if let Some(token) = lock(&self.gesture_token).take() {
            self.record_failure(&token, PlatformFailure::ForegroundLost);
        }
        *lock(&self.file_export) = None;
        for (_, sender) in lock(&self.pending).drain() {
            let _ = sender.send(OUTCOME_FOREGROUND_LOST.to_owned());
        }
    }

    pub fn report_outcome(&self, dispatch_id: &str, outcome: &str) -> Result<(), NativeError> {
        if dispatch_id.is_empty() {
            return Err(invalid("dispatch id is empty"));
        }
        match outcome {
            OUTCOME_APPLIED | OUTCOME_FOREGROUND_LOST | OUTCOME_PLATFORM_FAILED => {}
            _ => {
                return Err(invalid(
                    "platform outcome must be APPLIED, FOREGROUND_LOST, or PLATFORM_FAILED",
                ));
            }
        }
        let sender = lock(&self.pending)
            .remove(dispatch_id)
            .ok_or_else(|| invalid("unknown dispatch id"))?;
        if sender.send(outcome.to_owned()).is_err() {
            return Err(invalid("platform clipboard dispatch is no longer waiting"));
        }
        Ok(())
    }

    fn take_gesture_token(&self) -> Result<String, ClipboardError> {
        lock(&self.gesture_token)
            .take()
            .ok_or_else(|| ClipboardError::new("clipboard gesture was not prepared"))
    }

    fn take_file_export(&self) -> Result<PreparedExport, ClipboardError> {
        lock(&self.file_export)
            .take()
            .ok_or_else(|| ClipboardError::new("file export kind was not prepared"))
    }

    fn wait_for_outcome(
        &self,
        gesture_token: &str,
        dispatch_id: &str,
        receiver: mpsc::Receiver<String>,
        lost_detail: &str,
        failed_detail: &str,
    ) -> Result<(), ClipboardError> {
        let outcome = receiver
            .recv_timeout(WAIT_TIMEOUT)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => {
                    lock(&self.pending).remove(dispatch_id);
                    ClipboardError::uncertain("platform clipboard outcome was not reported")
                }
                RecvTimeoutError::Disconnected => {
                    ClipboardError::uncertain("platform clipboard outcome channel closed")
                }
            })?;
        match outcome.as_str() {
            OUTCOME_APPLIED => Ok(()),
            OUTCOME_FOREGROUND_LOST => {
                self.record_failure(gesture_token, PlatformFailure::ForegroundLost);
                Err(ClipboardError::new(lost_detail.to_owned()))
            }
            OUTCOME_PLATFORM_FAILED => {
                self.record_failure(gesture_token, PlatformFailure::PlatformFailed);
                Err(ClipboardError::new(failed_detail.to_owned()))
            }
            _ => Err(ClipboardError::new(format!(
                "unexpected platform clipboard outcome: {outcome}"
            ))),
        }
    }
}

impl ClipboardSink for PlatformClipboard {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(ClipboardError::new(format!(
                "clipboard text is {} bytes; maximum is {MAX_TEXT_BYTES}",
                text.len()
            )));
        }
        let gesture_token = self.take_gesture_token()?;
        let dispatch_id = meshelf_core::OfferId::new().to_string();
        let (sender, receiver) = mpsc::sync_channel(1);
        lock(&self.pending).insert(dispatch_id.clone(), sender);
        match self.events.emit(KotlinEvent::PlatformDispatchPrepared {
            dispatch_id: dispatch_id.clone(),
            text: text.to_owned(),
            gesture_token: gesture_token.clone(),
        }) {
            Ok(()) => self.wait_for_outcome(
                &gesture_token,
                &dispatch_id,
                receiver,
                "foreground was lost before clipboard could be written",
                "platform clipboard write failed",
            ),
            Err(error) => {
                lock(&self.pending).remove(&dispatch_id);
                Err(clipboard_refused(error))
            }
        }
    }
}

impl FetchClipboard for PlatformClipboard {
    fn set_files(&self, paths: &[PathBuf]) -> Result<(), ClipboardError> {
        if paths.len() != 1 {
            return Err(ClipboardError::new(
                "Android file export accepts exactly one verified file path",
            ));
        }
        let path = &paths[0];
        if !path.is_absolute() {
            return Err(ClipboardError::new("file export path must be absolute"));
        }
        let meta = std::fs::metadata(path).map_err(|error| {
            ClipboardError::new(format!("verified export file is unreadable: {error}"))
        })?;
        if !meta.is_file() {
            return Err(ClipboardError::new("verified export path is not a file"));
        }
        let PreparedExport { kind, card_name } = self.take_file_export()?;
        let gesture_token = self.take_gesture_token()?;
        let display_name = export_display_name(card_name.as_deref(), path);
        let mime_hint = mime_hint_for(Path::new(&display_name));
        let dispatch_id = meshelf_core::OfferId::new().to_string();
        let (sender, receiver) = mpsc::sync_channel(1);
        lock(&self.pending).insert(dispatch_id.clone(), sender);
        match self.events.emit(KotlinEvent::PlatformFileExportPrepared {
            dispatch_id: dispatch_id.clone(),
            absolute_path: path.display().to_string(),
            display_name,
            mime_hint,
            gesture_token: gesture_token.clone(),
            export_kind: kind.as_str().to_owned(),
        }) {
            Ok(()) => self.wait_for_outcome(
                &gesture_token,
                &dispatch_id,
                receiver,
                "foreground was lost before file export could complete",
                "platform file export failed",
            ),
            Err(error) => {
                lock(&self.pending).remove(&dispatch_id);
                Err(clipboard_refused(error))
            }
        }
    }
}

fn export_display_name(card_name: Option<&str>, path: &Path) -> String {
    card_name
        .or_else(|| path.file_name().and_then(|name| name.to_str()))
        .filter(|name| !name.is_empty())
        .unwrap_or("meshelf-file")
        .replace(['\\', '/'], "_")
}

fn mime_hint_for(path: &Path) -> String {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("jpg" | "jpeg") => "image/jpeg".to_owned(),
        Some("png") => "image/png".to_owned(),
        Some("gif") => "image/gif".to_owned(),
        Some("webp") => "image/webp".to_owned(),
        Some("txt") => "text/plain".to_owned(),
        Some("pdf") => "application/pdf".to_owned(),
        _ => "application/octet-stream".to_owned(),
    }
}

fn clipboard_refused(error: EventRefused) -> ClipboardError {
    ClipboardError::new(format!(
        "platform clipboard dispatch could not be queued: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorLog;
    use crate::events::{EVENT_QUEUE_CAPACITY, EventSink};
    use std::thread;
    use std::time::Duration;

    fn clipboard_with_sink() -> (
        Arc<PlatformClipboard>,
        EventSink,
        std::sync::mpsc::Receiver<crate::events::Invocation>,
    ) {
        let (events, receiver) = EventSink::channel(EVENT_QUEUE_CAPACITY, ErrorLog::default());
        (PlatformClipboard::new(events.clone()), events, receiver)
    }

    #[test]
    fn invalidate_unblocks_waiter_as_foreground_lost() {
        let (clipboard, _events, _receiver) = clipboard_with_sink();
        clipboard.prepare_gesture("g1".into());
        let clip = Arc::clone(&clipboard);
        let worker = thread::spawn(move || clip.set_text("hello"));
        for _ in 0..50 {
            if !lock(&clipboard.pending).is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!lock(&clipboard.pending).is_empty());
        clipboard.invalidate();
        let err = worker.join().expect("join").expect_err("must refuse");
        assert!(err.to_string().contains("foreground was lost"), "got {err}");
        assert!(lock(&clipboard.pending).is_empty());
        assert!(lock(&clipboard.gesture_token).is_none());
    }

    /// A lost foreground is reported against the gesture that lost it, once, so the activation
    /// can say FOREGROUND_LOST rather than a platform failure.
    #[test]
    fn a_lost_foreground_is_recorded_against_its_gesture_and_collected_once() {
        let (clipboard, _events, receiver) = clipboard_with_sink();
        clipboard.prepare_gesture("g-lost".into());
        let clip = Arc::clone(&clipboard);
        let worker = thread::spawn(move || clip.set_text("hello"));
        let invocation = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("dispatch event");
        let crate::events::CallArg::Text(dispatch_id) = &invocation.args[0] else {
            panic!("dispatch id");
        };
        clipboard
            .report_outcome(dispatch_id, OUTCOME_FOREGROUND_LOST)
            .expect("report");
        worker.join().expect("join").expect_err("not applied");
        assert_eq!(
            clipboard.finish_gesture("g-lost"),
            Some(PlatformFailure::ForegroundLost)
        );
        assert_eq!(clipboard.finish_gesture("g-lost"), None);
    }

    /// A gesture superseded or invalidated before its dispatch is foreground lost, and finishing
    /// an unconsumed gesture withdraws it so no later write can spend it.
    #[test]
    fn a_superseded_or_withdrawn_gesture_cannot_be_spent_later() {
        let (clipboard, _events, _receiver) = clipboard_with_sink();
        clipboard.prepare_gesture("g-old".into());
        clipboard.prepare_gesture("g-new".into());
        assert_eq!(
            clipboard.finish_gesture("g-old"),
            Some(PlatformFailure::ForegroundLost)
        );
        clipboard.invalidate();
        assert_eq!(
            clipboard.finish_gesture("g-new"),
            Some(PlatformFailure::ForegroundLost)
        );
        clipboard.prepare_gesture("g-unused".into());
        assert_eq!(clipboard.finish_gesture("g-unused"), None);
        let err = clipboard
            .set_text("hello")
            .expect_err("token was withdrawn");
        assert!(err.to_string().contains("gesture was not prepared"));
    }

    #[test]
    fn set_text_without_gesture_refuses_without_side_effect_wait() {
        let (clipboard, _events, _receiver) = clipboard_with_sink();
        let err = clipboard.set_text("hello").expect_err("gesture required");
        assert!(err.to_string().contains("gesture was not prepared"));
    }

    #[test]
    fn applied_outcome_completes() {
        let (clipboard, _events, receiver) = clipboard_with_sink();
        clipboard.prepare_gesture("g1".into());
        let clip = Arc::clone(&clipboard);
        let worker = thread::spawn(move || clip.set_text("hello"));
        let invocation = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("dispatch event");
        assert_eq!(invocation.method.name, "onPlatformDispatchPrepared");
        let dispatch_id = match &invocation.args[0] {
            crate::events::CallArg::Text(id) => id.clone(),
            _ => panic!("dispatch id"),
        };
        clipboard
            .report_outcome(&dispatch_id, OUTCOME_APPLIED)
            .expect("report");
        worker.join().expect("join").expect("applied");
    }

    #[test]
    fn set_files_without_export_kind_refuses() {
        let (clipboard, _events, _receiver) = clipboard_with_sink();
        clipboard.prepare_gesture("g1".into());
        let path = std::env::temp_dir().join("meshelf-export-missing-kind.bin");
        std::fs::write(&path, b"payload").expect("fixture");
        let err = clipboard
            .set_files(&[path])
            .expect_err("export kind required");
        assert!(
            err.to_string()
                .contains("file export kind was not prepared")
        );
    }

    #[test]
    fn set_files_save_waits_for_applied_outcome() {
        let (clipboard, _events, receiver) = clipboard_with_sink();
        clipboard.prepare_gesture("g1".into());
        clipboard.prepare_file_export(FileExportKind::Save, Some("report 2026.pdf".to_owned()));
        let path = std::env::temp_dir().join("meshelf-export-save.bin");
        std::fs::write(&path, b"verified-bytes").expect("fixture");
        let clip = Arc::clone(&clipboard);
        let export_path = path.clone();
        let worker = thread::spawn(move || clip.set_files(&[export_path]));
        let invocation = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("export event");
        assert_eq!(invocation.method.name, "onPlatformFileExportPrepared");
        let dispatch_id = match &invocation.args[0] {
            crate::events::CallArg::Text(id) => id.clone(),
            _ => panic!("dispatch id"),
        };
        let kind = match &invocation.args[5] {
            crate::events::CallArg::Text(kind) => kind.clone(),
            _ => panic!("kind"),
        };
        assert_eq!(kind, "SAVE");
        // Android names the saved file from these, not from the cache object's own name.
        assert_eq!(
            invocation.args[2],
            crate::events::CallArg::Text("report 2026.pdf".to_owned())
        );
        assert_eq!(
            invocation.args[3],
            crate::events::CallArg::Text("application/pdf".to_owned())
        );
        // Kotlin accepts only `[A-Za-z0-9-]{1,64}` as a dispatch id.
        assert!(
            (1..=64).contains(&dispatch_id.len())
                && dispatch_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "{dispatch_id}"
        );
        clipboard
            .report_outcome(&dispatch_id, OUTCOME_APPLIED)
            .expect("report");
        worker.join().expect("join").expect("applied");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn set_files_invalidate_is_foreground_lost() {
        let (clipboard, _events, _receiver) = clipboard_with_sink();
        clipboard.prepare_gesture("g1".into());
        clipboard.prepare_file_export(FileExportKind::Share, None);
        let path = std::env::temp_dir().join("meshelf-export-share.bin");
        std::fs::write(&path, b"share-bytes").expect("fixture");
        let clip = Arc::clone(&clipboard);
        let export_path = path.clone();
        let worker = thread::spawn(move || clip.set_files(&[export_path]));
        for _ in 0..50 {
            if !lock(&clipboard.pending).is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        clipboard.invalidate();
        let err = worker.join().expect("join").expect_err("must refuse");
        assert!(err.to_string().contains("foreground was lost"), "got {err}");
        let _ = std::fs::remove_file(path);
    }
}
