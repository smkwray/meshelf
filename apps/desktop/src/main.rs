use std::env;

use anyhow::Result;
use meshelf_platform::{ClipboardSource, ClipboardWorker};
use slint::ComponentHandle;
use tracing_subscriber::EnvFilter;

slint::include_modules!();

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .without_time()
        .init();

    let window = MainWindow::new()?;
    let tray = MeshelfTray::new()?;
    let device_name = env::var("MESHELF_DEVICE_NAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "This device".to_owned());
    window.set_device_name(device_name.clone().into());
    tray.set_tooltip_text(format!("meshelf — {device_name}").into());

    let clipboard = match ClipboardWorker::new() {
        Ok(clipboard) => Some(clipboard),
        Err(error) => {
            window.set_status_text(format!("Clipboard unavailable: {error}").into());
            None
        }
    };

    {
        let window_weak = window.as_weak();
        let clipboard = clipboard.clone();
        window.on_paste_clipboard(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let Some(clipboard) = clipboard.as_ref() else {
                window.set_status_text("Clipboard adapter is unavailable".into());
                return;
            };
            match clipboard.read_text() {
                Ok(text) => {
                    window.set_draft_text(text.into());
                    window
                        .set_status_text("Clipboard loaded locally; nothing has been sent".into());
                }
                Err(error) => {
                    window.set_status_text(format!("Could not read clipboard: {error}").into());
                }
            }
        });
    }

    {
        let window_weak = window.as_weak();
        window.on_send_default(move |draft| {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            if draft.trim().is_empty() {
                window.set_status_text("Nothing to send".into());
            } else {
                window.set_status_text(
                    "Send is intentionally blocked in the seed until signed pairing is integrated"
                        .into(),
                );
            }
        });
    }

    {
        let window_weak = window.as_weak();
        window.on_refresh_peers(move || {
            if let Some(window) = window_weak.upgrade() {
                window.set_status_text(
                    "Peer refresh adapter is seeded; authenticated probing remains a bounded work order"
                        .into(),
                );
            }
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_open_window(move || {
            if let Some(window) = window_weak.upgrade() {
                let _ = window.show();
            }
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_send_default(move || {
            if let Some(window) = window_weak.upgrade() {
                window.set_status_text(
                    "Tray send is blocked until signed pairing and integration gates close".into(),
                );
                let _ = window.show();
            }
        });
    }

    {
        let window_weak = window.as_weak();
        tray.on_choose_target(move || {
            if let Some(window) = window_weak.upgrade() {
                window.set_status_text(
                    "Target chooser integration is assigned to Work Order 05".into(),
                );
                let _ = window.show();
            }
        });
    }

    tray.on_quit(|| {
        let _ = slint::quit_event_loop();
    });

    window.show()?;
    tray.show()?;
    slint::run_event_loop()?;
    Ok(())
}
