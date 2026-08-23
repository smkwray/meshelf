# Work Order 04 — clipboard, global shortcuts, notifications, autostart

## Ownership

`crates/meshelf-platform/**`.

## Objective

Finish native platform adapters without moving product rules into platform code.

## Required properties

- serialized explicit clipboard reads/writes;
- no watcher or polling;
- default and chooser shortcuts;
- event-driven hotkey delivery;
- X11 plus Wayland portal path;
- bounded clipboard-busy handling;
- notifications without clipboard body by default;
- reversible per-user start at login;
- no elevation;
- graceful hotkey conflict fallback to tray/buttons.

## Acceptance

Exact platform receipts on Windows, macOS, Linux X11, and selected Wayland desktop. Ordinary copy produces no meshelf callback or network action.
