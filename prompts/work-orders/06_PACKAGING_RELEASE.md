# Work Order 06 — packaging and release evidence

## Ownership

`scripts/**`, `.github/**`, packaging metadata, and `docs/06_BUILD_AND_RELEASE.md`.

## Objective

Produce deterministic private packages and exact validation receipts for Windows, macOS, and Linux.

## Required outputs

- committed `Cargo.lock`;
- dependency/license/advisory receipts;
- Windows installer and portable ZIP;
- macOS app bundle for Apple silicon;
- Linux package after X11/Wayland gate;
- source ZIP with internal manifest;
- package SHA-256 values;
- listener binding proof;
- idle CPU/memory/network measurements;
- uninstall/autostart cleanup test;
- honest signing status.

## Acceptance

Every package maps to one exact source object and passes the release gates on its native platform.
