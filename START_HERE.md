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
6. `status/PROJECT_STATE.md`
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

The desktop shell is intentionally conservative. It renders the window, tray, draft editor, status surfaces, and an explicit local clipboard-read action. Peer rows, recent-history persistence, hotkey composition, and production networking remain disabled until their bounded work orders and signed trust path are integrated. Do not “make it work” by changing the default trust gate to allow all tailnet nodes.

## Recommended local agent sequence

1. Run Work Order 01 and close any core/storage compilation defects.
2. Run Work Order 02 to implement signed identity and pairing.
3. Run Work Order 03 to complete peer discovery and secure direct transfer.
4. Run Work Order 04 to wire platform hotkeys, clipboard, notifications, and autostart.
5. Run Work Order 05 to finish the UI and exact one-hotkey path.
6. Run Work Order 06 for packaging and release evidence.
7. Give the final tree to a read-only audit agent using Work Order 07.

Parallel work is allowed only where the ownership table in `AGENTS.md` says files do not overlap.
