#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: Cargo is not installed. Install rustup, then rerun this script." >&2
  exit 1
fi
if ! command -v rustup >/dev/null 2>&1; then
  echo "ERROR: rustup is required because rust-toolchain.toml pins the project toolchain." >&2
  exit 1
fi

rustup toolchain install 1.92.0 --profile minimal --component rustfmt --component clippy
cargo fetch
python3 scripts/verify-repo.py --allow-stale-manifest

echo "Bootstrap complete. Run ./scripts/check.sh next."
