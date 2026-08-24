# meshelf

**meshelf** is a small, symmetric, peer-to-peer clipboard courier and lightweight shared shelf for devices already connected through Tailscale.

The primary interaction is deliberately minimal:

```text
sender: open meshelf -> press Cmd/Ctrl+V once
receiver: open meshelf -> click an item or press Cmd/Ctrl+1–5
```

No machine is a controller, server, primary, leader, or canonical store. Every installation has the same role. A normal copy operation never causes network activity. Only an explicit meshelf action reads or sends clipboard content.

This repository is an **agent-ready implementation seed**, not a production release. It contains the locked product contract, architecture, protocol/state-machine foundations, a cross-platform UI shell, on-demand Tailscale discovery of untrusted meshelf candidates, platform adapters, local simulation, bounded work orders, test plan, release scaffolding, and audit materials needed for local agents to continue implementation without reopening settled architecture.

## Locked v1 behavior

- Windows, macOS, and desktop Linux.
- Same binary role on every device.
- Tailscale provides reachability; meshelf does not create another VPN.
- Plain Unicode text plus direct file/folder transfer from native Finder/Explorer file copies or an existing textual path.
- Cmd/Ctrl+V in the focused meshelf window reads the clipboard once and fans the item out to every paired online peer.
- Received items are stored on the local shelf and never replace the receiver clipboard automatically.
- Clicking a card or pressing Cmd/Ctrl+1–5 explicitly copies that shelf item on the receiving device.
- Offline failure is visible and is never replayed later.
- Message IDs make retries duplicate-safe.
- The main window may be closed while a tray/menu-bar process remains available.
- No automatic clipboard watcher, periodic clipboard polling, remote command execution, rich text, or images.
- File/folder senders and receivers must be online together; transfer is streamed directly and is not queued.

## Start here

1. Read [`START_HERE.md`](START_HERE.md).
2. Read [`AGENTS.md`](AGENTS.md); its invariants are binding.
3. Read [`docs/00_PRODUCT_CONTRACT.md`](docs/00_PRODUCT_CONTRACT.md) and [`docs/01_ARCHITECTURE.md`](docs/01_ARCHITECTURE.md).
4. Read [`docs/05_TEST_PLAN.md`](docs/05_TEST_PLAN.md) before changing code; in a synced development workspace, also inspect the private `do/state.md` note.
5. Use one bounded work order from [`prompts/work-orders/`](prompts/work-orders/).

## Repository map

```text
apps/desktop/          Slint desktop UI and tray shell
crates/meshelf-core/   Domain model, policy, idempotent receive state machine
crates/meshelf-net/    One-shot peer listener/client and trust-gate abstraction
crates/meshelf-platform/ Explicit clipboard adapter
crates/meshelf-protocol/ Framing and versioned wire messages
crates/meshelf-store/  redb-backed receive ledger
crates/meshelf-tailscale/ Tailscale status discovery adapter
tools/meshelf-sim/     Loopback two-peer simulation
config/                Example local configuration and Tailscale policy
docs/                  Binding design, security, protocol, and test documents
prompts/                Launch prompt and bounded agent work orders
scripts/                Bootstrap, validation, and source-package helpers
do/                     Private local state, audit dispatches, and operator notes (not committed)
```

## Build commands

macOS/Linux:

```bash
./scripts/bootstrap.sh
./scripts/check.sh
./scripts/dev.sh
```

On macOS, `./scripts/package-macos.sh --install` creates and registers
`~/Applications/meshelf.app`, making the app available to Raycast and `open -a meshelf`.

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
- Bounded direct file/folder streaming with manifests, free-space admission, SHA-256 verification,
  partial staging, atomic finalization, and no-overwrite naming.
- Native file-list clipboard reads and writes: copy in Finder/Explorer, paste once into Meshelf,
  then activate the received card to paste the actual file from that device's clipboard.
- Deny-by-default trust gate.
- Tailscale `status --json` parser and binary locator.
- On-demand Tailscale peer probes and a listener bound only to a discovered Tailscale address.
- Protected per-installation Ed25519 identity, signed hellos, and durable peer-key bindings.
- Signed Meshelf peers on the same Tailscale network pair automatically during discovery; private
  builds also recover automatically after an app reinstall on the same Tailscale node.
- Cross-platform explicit clipboard adapter using `arboard`.
- Window-local explicit send controls; meshelf does not register global hotkeys.
- `meshelfctl` equivalents for status/refresh, clipboard read, and mesh-wide text/stdin/clipboard
  sends.
- High-contrast black-and-white tray icon wiring, rounded application artwork, Windows
  executable icon resources, and a private macOS application-bundle path.
- Slint 1.17 desktop window and system-tray shell.
- Loopback simulation and unit-test scaffolding.
- CI, packaging scripts, source manifest, and agent/audit handoffs.

## Deliberately unfinished

The app is in functional private testing, not a hardened public release. The largest open items are
interrupted-transfer resume/cleanup, notifications/start-at-login, signing/notarization, Linux
packaging, and a final security hardening pass. Automatic pairing
currently treats a valid signed Meshelf installation on the owner's Tailscale network as eligible;
tightening that policy is intentionally deferred until the core workflow is settled.

See the private `do/state.md` note in a synced development workspace for the exact boundary.
