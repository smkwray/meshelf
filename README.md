# meshelf

<p align="center">
  <img src="assets/meshelf-256.png" alt="meshelf logo" width="160">
</p>

meshelf is a small, symmetric, peer-to-peer offer shelf for devices connected through Tailscale.
There is no controller, server, primary, leader, canonical store, or mandatory relay.

The current production composition speaks protocol 2 only:

```text
sender:   focus meshelf -> press Cmd/Ctrl+V once
receiver: open the shelf -> activate a card or press Cmd/Ctrl+1–5
```

The sender stores text captured at the explicit paste and announces bounded metadata to its paired
peers. File and folder offers store a canonical path and metadata commitment, never a sender payload
copy. Every receiver may store a metadata card; payload bytes move only when that receiver activates
the card and pulls them directly from the origin. A failed direct operation is not queued or resumed.

The shelf retains ten live entries per device; the eleventh purges the oldest and there is no
time-based expiry. Text cards show a bounded 256-byte UTF-8 preview. File/folder cards can activate
to the local native clipboard or to Downloads/the configured absolute save destination. The status
line reports peers that answered the latest reachability probe, not every paired device.

Clipboard reads are explicit only: an active-window control or a foreground command the user typed.
Copy events, idle polling, discovery timers, network heartbeats, global hotkeys, notifications, and
start-at-login are not part of the contract.

This is an early functional candidate, not a production-ready release. The local source gates pass,
and the repaired two-device smoke path has been exercised on macOS and Windows. Full native
failure-mode proof, recovery/resource hardening, Linux, security/release, and mobile-device proofs
remain open. No trusted signed or notarized release artifacts are provided; any candidate build must
be treated as unsigned/ad-hoc and used only with those limitations understood. Do not use this
candidate for sensitive material; see `SECURITY.md`.

## Start here

1. Read [`START_HERE.md`](START_HERE.md), [`SECURITY.md`](SECURITY.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md).
2. Read the crate source and tests for the area you intend to change.
3. Run the platform-appropriate bootstrap and check command before submitting a change.

## Repository map

```text
apps/desktop/             Slint desktop UI and tray shell
apps/android/             Native Android shell (currently ABI-only seed)
apps/meshelfctl/          Headless resident and explicit CLI operations
crates/meshelf-core/      Domain, offer, activation, and destination semantics
crates/meshelf-control/   Offer planning, local control, and composition
crates/meshelf-net/       Protocol-2 announcement/fetch transport
crates/meshelf-platform/  Clipboard and filesystem adapters
crates/meshelf-protocol/  Version-2 messages and bounded framing
crates/meshelf-store/     redb v2 offer/card/activation storage
crates/meshelf-tailscale/ On-demand discovery and peer state
crates/meshelf-android-bridge/  Android JNI ABI bridge (currently ABI-only)
tools/meshelf-sim/        Local simulation
config/                   Example state shape and Tailscale policy
scripts/                  Bootstrap, validation, packaging, and source-archive helpers
```

## Build commands

macOS/Linux:

```bash
./scripts/bootstrap.sh
./scripts/check.sh
./scripts/dev.sh
```

Windows:

```bat
scripts\bootstrap.bat
scripts\check.bat
scripts\dev.bat
```

The pinned toolchain is in `rust-toolchain.toml`. Linux desktop builds may require additional
native packages from the platform package manager.

## Current implementation boundary

The source includes bounded text and native file/folder offers, signed protocol-2 hellos, Tailscale-
only listener binding, metadata announcements, receiver-initiated fetch, descriptor/manifest/hash
validation, atomic no-replace publication, startup migration/cleanup, explicit clipboard/save
activation, and local simulation/tests.

The Android tree is currently an ABI-only seed: it proves the Rust/JNI build boundary and exposes
explicit platform-adapter placeholders, but it has no network session, background service, mobile
file transfer, APK, signing, or device-tested claim.

The candidate still needs the complete native failure and recovery proof, broader security and release
review, Linux evidence, and mobile-device work. Do not infer those from a local green source gate or
from one successful smoke transfer.
