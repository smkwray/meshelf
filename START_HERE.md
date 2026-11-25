# Run from a checkout

Install the prerequisites listed in the [README](README.md#build-and-install). Run the checks and the local simulator from the repository root.

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
