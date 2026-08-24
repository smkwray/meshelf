//! Platform boundary for explicit clipboard access.
//!
//! There is no clipboard watcher in this crate. A dedicated worker owns the native clipboard
//! object and performs a read or write only in response to an explicit command.

mod clipboard;

pub use clipboard::{ClipboardItem, ClipboardSource, ClipboardWorker, PlatformClipboardError};

pub trait Notifier: Send + Sync + 'static {
    fn received_clipboard(&self, source_name: &str) -> Result<(), String>;
    fn send_failed(&self, target_name: &str, reason: &str) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct NoopNotifier;

impl Notifier for NoopNotifier {
    fn received_clipboard(&self, _source_name: &str) -> Result<(), String> {
        Ok(())
    }

    fn send_failed(&self, _target_name: &str, _reason: &str) -> Result<(), String> {
        Ok(())
    }
}

pub trait AutostartManager: Send + Sync + 'static {
    fn is_enabled(&self) -> Result<bool, String>;
    fn set_enabled(&self, enabled: bool) -> Result<(), String>;
}

/// Deliberately refuses until a platform-specific implementation is added and audited.
#[derive(Debug, Default)]
pub struct UnsupportedAutostart;

impl AutostartManager for UnsupportedAutostart {
    fn is_enabled(&self) -> Result<bool, String> {
        Ok(false)
    }

    fn set_enabled(&self, _enabled: bool) -> Result<(), String> {
        Err("start-at-login is not integrated in the seed".to_owned())
    }
}
