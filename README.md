# meshelf

**meshelf** is a small, symmetric, peer-to-peer clipboard courier and lightweight shared shelf for devices already connected through Tailscale.

The primary interaction is deliberately minimal:

```text
copy normally -> press one global hotkey -> switch devices -> paste normally
```

No machine is a controller, server, primary, leader, or canonical store. Every installation has the same role. A normal copy operation never causes network activity. Only an explicit meshelf action reads or sends clipboard content.

This repository is an **agent-ready implementation seed**, not a production release. It contains the locked product contract, architecture, protocol/state-machine foundations, cross-platform UI shell, platform adapters, local simulation, bounded work orders, test plan, release scaffolding, and audit materials needed for local agents to continue implementation without reopening settled architecture.

## Locked v1 behavior

- Windows, macOS, and desktop Linux.
- Same binary role on every device.
- Tailscale provides reachability; meshelf does not create another VPN.
- Plain Unicode text only in v1.
- `Ctrl+Alt+V` / `Control+Option+V`: send current clipboard to the configured default peer.
- `Ctrl+Alt+Shift+V` / `Control+Option+Shift+V`: open the keyboard-first target chooser.
- Direct clipboard push is immediate and online-only.
- Offline failure is visible and is never replayed later into the destination clipboard.
- Received text is durably recorded before the application attempts the clipboard side effect.
- Message IDs make retries duplicate-safe.
- The main window may be closed while a tray/menu-bar process remains available.
- No automatic clipboard watcher, periodic clipboard polling, remote command execution, rich text, images, or file transfer in v1.

File transfer is reserved in the architecture but intentionally not implemented in the first tranche.

## Start here

1. Read [`START_HERE.md`](START_HERE.md).
2. Read [`AGENTS.md`](AGENTS.md); its invariants are binding.
3. Read [`docs/00_PRODUCT_CONTRACT.md`](docs/00_PRODUCT_CONTRACT.md) and [`docs/01_ARCHITECTURE.md`](docs/01_ARCHITECTURE.md).
4. Read [`status/PROJECT_STATE.md`](status/PROJECT_STATE.md) before changing code.
5. Use one bounded work order from [`prompts/work-orders/`](prompts/work-orders/).

## Repository map

```text
apps/desktop/          Slint desktop UI and tray shell
crates/meshelf-core/   Domain model, policy, idempotent receive state machine
crates/meshelf-net/    One-shot peer listener/client and trust-gate abstraction
crates/meshelf-platform/ Clipboard and hotkey adapters
crates/meshelf-protocol/ Framing and versioned wire messages
crates/meshelf-store/  redb-backed receive ledger
crates/meshelf-tailscale/ Tailscale status discovery adapter
tools/meshelf-sim/     Loopback two-peer simulation
config/                Example local configuration and Tailscale policy
docs/                  Binding design, security, protocol, and test documents
prompts/                Launch prompt and bounded agent work orders
scripts/                Bootstrap, validation, and source-package helpers
status/                 Current implementation and validation ledger
```

## Build commands

macOS/Linux:

```bash
./scripts/bootstrap.sh
./scripts/check.sh
./scripts/dev.sh
```

Windows PowerShell or Command Prompt:

```bat
scripts\bootstrap.bat
scripts\check.bat
scripts\dev.bat
```

The pinned toolchain is in `rust-toolchain.toml`. Linux desktop builds may require the native packages listed in [`docs/06_BUILD_AND_RELEASE.md`](docs/06_BUILD_AND_RELEASE.md).

## What is already seeded

- Versioned text envelope and receipt types.
- 1 MiB text policy and validation.
- At-most-once clipboard application state machine.
- Durable receive-ledger interface and redb implementation.
- Length-prefixed JSON wire codec.
- Direct one-message TCP client/listener with timeouts.
- Deny-by-default trust gate.
- Tailscale `status --json` parser and binary locator.
- Cross-platform explicit clipboard adapter using `arboard`.
- Global-hotkey adapter for Windows, macOS, and Linux X11.
- Slint 1.17 desktop window and system-tray shell.
- Loopback simulation and unit-test scaffolding.
- CI, packaging scripts, source manifest, and agent/audit handoffs.

## Deliberately unfinished

The project is not safe for everyday clipboard use until the release gate in [`docs/05_TEST_PLAN.md`](docs/05_TEST_PLAN.md) passes. The largest open items are application-level key generation and signed pairing, wiring the hotkeys/tray to the network engine, secure peer discovery/probing, native notifications, start-at-login, Linux Wayland portal shortcuts, installers/signing, and real three-platform testing.

See [`status/PROJECT_STATE.md`](status/PROJECT_STATE.md) for the exact boundary.
