# meshelf

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

This is a private functional candidate, not a production release. The cutover source/tests are at
`3002cb7` and the current runtime evidence is BMST/macOS. BZOT/Windows was unreachable, so no
Windows or cross-platform verification is claimed.

## Start here

1. Read [`AGENTS.md`](AGENTS.md) and [`START_HERE.md`](START_HERE.md).
2. Read the current product, architecture, protocol, security, and test documents in [`docs/`](docs/).
3. Read the private [`do/state.md`](do/state.md) in a synced development workspace.
4. Use one bounded work order from [`prompts/work-orders/`](prompts/work-orders/).

## Repository map

```text
apps/desktop/             Slint desktop UI and tray shell
apps/meshelfctl/          Headless resident and explicit CLI operations
crates/meshelf-core/      Domain, offer, activation, and destination semantics
crates/meshelf-control/   Offer planning, local control, and composition
crates/meshelf-net/       Protocol-2 announcement/fetch transport
crates/meshelf-platform/  Clipboard and filesystem adapters
crates/meshelf-protocol/  Version-2 messages and bounded framing
crates/meshelf-store/     redb v2 offer/card/activation storage
crates/meshelf-tailscale/ On-demand discovery and peer state
tools/meshelf-sim/        Local simulation
config/                   Example state shape and Tailscale policy
docs/                     Product, architecture, security, protocol, and gate documents
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

The pinned toolchain is in `rust-toolchain.toml`. Linux desktop builds may require the native
packages listed in [`docs/06_BUILD_AND_RELEASE.md`](docs/06_BUILD_AND_RELEASE.md).

## Current implementation boundary

The source includes bounded text and native file/folder offers, signed protocol-2 hellos, Tailscale-
only listener binding, metadata announcements, receiver-initiated fetch, descriptor/manifest/hash
validation, atomic no-replace publication, startup migration/cleanup, explicit clipboard/save
activation, and local simulation/tests.

The private candidate still needs permitted-host listener proof, Windows platform proof, and final
security/package release evidence. Do not infer those from a local green source gate or from the
BMST host.
