# Start here

This repository is an early public-source candidate. It is not a completed or trusted binary
distribution.

## The non-negotiable architecture

meshelf is **symmetric peer-to-peer software**. Do not introduce a hosted database, central controller, elected leader, preferred server, authoritative mailbox, cloud account, or canonical replica.

Any two configured devices must be able to exchange a direct clipboard push while every third device is powered off.

## Read order

1. `README.md`
2. `SECURITY.md` and `CONTRIBUTING.md`
3. The relevant crate source, tests, and configuration examples

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

The desktop shell is intentionally conservative. It renders the window, tray, draft editor, status surfaces, explicit local clipboard-read/send actions, refresh, and on-demand Tailscale discovery. `meshelfctl` supports the same operational actions without the UI. There are no global hotkeys, clipboard watchers, or ambient reads. Admission is an interim functional-testing policy: valid signed meshelf installations on the same Tailscale network, including the Android app, are admitted automatically on refresh, and the six-digit pairing flow is deferred. The complete native failure/recovery proof and release hardening remain open. No candidate binaries are published, and any local build is unsigned. Do not “make it work” by changing the trust gate to allow all tailnet nodes.

## Recommended local sequence

1. Run the platform-appropriate bootstrap command.
2. Run the platform-appropriate check command.
3. Make a focused change with a focused test.
4. Re-run the full check command and inspect the resulting diff.
