# Changelog

## 0.1.0-candidate.1 — 2026-08-27

- Published the source under the MIT License as an early functional candidate.
- Added Apple-silicon macOS and Windows x64 candidate packaging with explicit unsigned/ad-hoc build
  warnings and SHA-256 checksums.
- Fixed save activation bookkeeping so save-mode transfers cannot be recovered as clipboard
  uncertainty.
- This candidate is not notarized, Authenticode-signed, or production-ready.

## 0.1.0-seed — 2026-08-23

- Established the symmetric peer-to-peer product contract.
- Seeded Rust 2024 workspace, Slint desktop/tray shell, core receive state machine, protocol, redb store, Tailscale status adapter, platform adapters, and loopback simulator.
- Added agent work orders, validation gates, packaging scripts, and audit handoffs.
- Kept signed pairing, production trust verification, notifications, autostart, and installers explicitly open; global hotkeys are intentionally excluded from meshelf.
