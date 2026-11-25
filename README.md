# meshelf

<p align="center">
  <img src="assets/meshelf-256.png" alt="meshelf logo" width="160">
</p>

meshelf shares text, files and folders between your own devices over [Tailscale](https://tailscale.com), and photos from an Android phone. Paste an item into the meshelf window on one device and a card for it appears on your other devices; the data moves directly from the sending device when you open the card on another. There is no server, and meshelf reads your clipboard only when you paste into its window or run a command.

meshelf is an early test version. There are no published binaries, so you build it from source, and those builds are unsigned. Desktop transfers have been tested between macOS and Windows, Linux desktop builds are untested, and the Android app has been tested on one phone. Do not use it for passwords, keys or other sensitive material.

Any meshelf installation on your tailnet with a valid signed identity joins your shelf automatically when you refresh, without a pairing code, so use meshelf only on a tailnet whose devices you control. meshelf listens only on the device's Tailscale address, on TCP port 45832. See [SECURITY.md](SECURITY.md).

## Use

```text
sender:   focus meshelf -> press Cmd/Ctrl+V once
receiver: open the shelf -> activate a card or press Cmd/Ctrl+1–5
```

| Keys | Action |
|---|---|
| Cmd/Ctrl+V | Offer the clipboard's text, files or folders to your other devices |
| Cmd/Ctrl+1 to 5 | Copy that card's item to the local clipboard |
| Alt/Option+1 to 5 | Save that card's file or folder to the save destination (Downloads unless you choose another folder) |
| Cmd/Ctrl+R | Refresh the list of reachable devices |

Each device keeps its ten most recent items, and an eleventh replaces the oldest. Text can be up to 1 MiB, a file up to 8 GiB, and a folder up to 4,096 entries and 16 GiB. A file or folder is offered from where it sits on disk, not copied, so keep it in place and unchanged until the other device has opened it, and keep the sending device running until then.

The Android app puts typed or pasted text, camera photos and gallery picks on the shelf, and copies, saves or shares an item when you tap it. It cannot save folders; zip the folder first. It is reachable only while open, unless you turn on background availability, which switches off whenever the app restarts. A computer can ask the phone for a photo with `meshelfctl capture photo --peer PHONE --purpose TEXT --output PATH`; the phone opens its camera and sends nothing until you press the shutter.

## Build and install

You need [rustup](https://rustup.rs) (the bootstrap script installs the toolchain pinned in `rust-toolchain.toml`), Python 3, and Tailscale running on every device.

On macOS, this builds `meshelf.app` and installs it in `~/Applications`:

```bash
./scripts/bootstrap.sh
./scripts/package-macos.sh --install
```

On Windows, this installs meshelf in `%LOCALAPPDATA%\Programs\meshelf`, adds desktop and Start menu shortcuts, and puts `meshelfctl` on your `PATH`. `uninstall-windows.ps1` in that folder removes it.

```bat
scripts\bootstrap.bat
powershell -ExecutionPolicy Bypass -File scripts\package-windows.ps1 -Install
```

To run from the checkout instead, use `./scripts/dev.sh` (`scripts\dev.bat` on Windows). `./scripts/check.sh` (`scripts\check.bat`) runs formatting, lint and tests. Linux desktop builds may need extra native packages from your distribution. The Android app builds on Linux; see [apps/android/README.md](apps/android/README.md).

`meshelfctl` is a command-line client for the same actions; run it without arguments to see its commands.

## Repository map

```text
apps/desktop/        Desktop window and tray app (Slint)
apps/android/        Android app
apps/meshelfctl/     Command-line client and headless resident
crates/              Shared Rust libraries: offers, storage, network protocol, Tailscale discovery, clipboard and file adapters
tools/meshelf-sim/   Local simulation
config/              Example state file and an optional Tailscale access rule
scripts/             Bootstrap, checks, packaging and install scripts
```

## License

MIT. See [LICENSE.md](LICENSE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
