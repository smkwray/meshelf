# Work Order 04 — clipboard, notifications, autostart

## Ownership

`crates/meshelf-platform/**`.

## Objective

Finish native platform adapters without moving product rules into platform code.

## Required properties

- serialized explicit clipboard reads/writes;
- no watcher or polling;
- active-window button and tray-open path;
- bounded clipboard-busy handling;
- notifications without clipboard body by default;
- reversible per-user start at login;
- no elevation;
- no global input registration or shortcut conflict surface.

## Acceptance

Exact platform receipts on Windows, macOS, Linux X11, and selected Wayland desktop. Ordinary copy produces no meshelf callback or network action.
