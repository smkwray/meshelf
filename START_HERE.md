# Start here

This ZIP is intended to be unpacked into a normal local development directory and handed to coding agents. It is not a completed binary distribution.

## The non-negotiable architecture

meshelf is **symmetric peer-to-peer software**. Do not introduce a hosted database, Spark controller, elected leader, preferred server, authoritative mailbox, cloud account, or canonical replica.

Any two configured devices must be able to exchange a direct clipboard push while every third device is powered off.

## Read order

1. `AGENTS.md`
2. `docs/00_PRODUCT_CONTRACT.md`
3. `docs/01_ARCHITECTURE.md`
4. `docs/02_PROTOCOL.md`
5. `docs/03_SECURITY.md`
6. The private `do/state.md` note when working in a synced development workspace.
7. the assigned file under `prompts/work-orders/`

## First local commands

macOS/Linux:

```bash
./scripts/bootstrap.sh
./scripts/check.sh
cargo run -p meshelf-sim
```

Windows:

```bat
scripts\bootstrap.bat
scripts\check.bat
cargo run -p meshelf-sim
```

Then run the desktop shell:

```bash
cargo run -p meshelf-desktop
```

## Expected first-run state

The desktop shell is intentionally conservative. It renders the window, tray, draft editor, status surfaces, explicit local clipboard-read/send actions, and on-demand Tailscale discovery. `meshelfctl` supports the same operational actions without the UI. Global hotkeys are deliberately absent. The intended first approval is one local **Trust both ways using SSH** action; the remote side does not need a physical click, and later sends use signed direct TCP. Real two-device proof, native credential-store evidence, listener lifecycle, notifications, and release packaging/icon verification remain open. Do not “make it work” by changing the trust gate to allow all tailnet nodes.

## Recommended local agent sequence

1. Run Work Order 01 and close any core/storage compilation defects.
2. Run Work Order 02 to harden signed identity and one-sided SSH pairing.
3. Run Work Order 03 to complete peer discovery, Tailscale source verification, and secure direct transfer.
4. Run Work Order 04 to finish clipboard, notifications, and autostart without adding global hotkeys.
5. Run Work Order 05 to finish the active-window UI and runtime integration.
6. Run Work Order 06 for packaging and release evidence.
7. Give the final tree to a read-only audit agent using Work Order 07.

Parallel work is allowed only where the ownership table in `AGENTS.md` says files do not overlap.
