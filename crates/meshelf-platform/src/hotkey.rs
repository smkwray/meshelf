use std::{
    env,
    sync::mpsc::{self, Receiver},
    thread,
};

use global_hotkey::{
    GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
    hotkey::{Code, HotKey, Modifiers},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotkeyAction {
    SendToDefault,
    OpenTargetChooser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortcutAvailability {
    Native,
    WaylandPortalRequired,
}

#[must_use]
pub fn shortcut_availability() -> ShortcutAvailability {
    if cfg!(target_os = "linux") {
        let session_type = env::var("XDG_SESSION_TYPE").unwrap_or_default();
        let wayland_display = env::var_os("WAYLAND_DISPLAY").is_some();
        if session_type.eq_ignore_ascii_case("wayland") || wayland_display {
            return ShortcutAvailability::WaylandPortalRequired;
        }
    }
    ShortcutAvailability::Native
}

#[derive(Debug, Error)]
pub enum HotkeyError {
    #[error("Wayland requires the XDG Global Shortcuts portal; native registration is disabled")]
    WaylandPortalRequired,
    #[error("global hotkey manager failed: {0}")]
    Manager(String),
}

/// Owns native shortcut registrations and exposes an event-driven standard receiver.
///
/// The listener blocks on the library event channel; it does not poll the clipboard or network.
pub struct HotkeyService {
    manager: GlobalHotKeyManager,
    send_hotkey: HotKey,
    chooser_hotkey: HotKey,
    actions: Receiver<HotkeyAction>,
}

impl std::fmt::Debug for HotkeyService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HotkeyService")
            .field("send_hotkey", &self.send_hotkey)
            .field("chooser_hotkey", &self.chooser_hotkey)
            .finish_non_exhaustive()
    }
}

impl HotkeyService {
    pub fn register_defaults() -> Result<Self, HotkeyError> {
        if shortcut_availability() == ShortcutAvailability::WaylandPortalRequired {
            return Err(HotkeyError::WaylandPortalRequired);
        }

        let manager =
            GlobalHotKeyManager::new().map_err(|error| HotkeyError::Manager(error.to_string()))?;
        let base_modifiers = Modifiers::CONTROL | Modifiers::ALT;
        let send_hotkey = HotKey::new(Some(base_modifiers), Code::KeyV);
        let chooser_hotkey = HotKey::new(Some(base_modifiers | Modifiers::SHIFT), Code::KeyV);
        manager
            .register_all(&[send_hotkey, chooser_hotkey])
            .map_err(|error| HotkeyError::Manager(error.to_string()))?;

        let send_id = send_hotkey.id();
        let chooser_id = chooser_hotkey.id();
        let (action_tx, actions) = mpsc::channel();
        thread::Builder::new()
            .name("meshelf-hotkeys".to_owned())
            .spawn(move || {
                while let Ok(event) = GlobalHotKeyEvent::receiver().recv() {
                    if event.state != HotKeyState::Pressed {
                        continue;
                    }
                    let action = if event.id == send_id {
                        Some(HotkeyAction::SendToDefault)
                    } else if event.id == chooser_id {
                        Some(HotkeyAction::OpenTargetChooser)
                    } else {
                        None
                    };
                    if let Some(action) = action
                        && action_tx.send(action).is_err()
                    {
                        break;
                    }
                }
            })
            .map_err(|error| HotkeyError::Manager(error.to_string()))?;

        Ok(Self {
            manager,
            send_hotkey,
            chooser_hotkey,
            actions,
        })
    }

    #[must_use]
    pub fn actions(&self) -> &Receiver<HotkeyAction> {
        &self.actions
    }
}

impl Drop for HotkeyService {
    fn drop(&mut self) {
        let _ = self
            .manager
            .unregister_all(&[self.send_hotkey, self.chooser_hotkey]);
    }
}
