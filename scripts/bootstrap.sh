#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v rustup >/dev/null 2>&1; then
  echo "ERROR: rustup is required because rust-toolchain.toml pins the project toolchain." >&2
  exit 1
fi

rustup toolchain install 1.92.0 --profile minimal --component rustfmt --component clippy
source scripts/rust-env.sh
cargo fetch
python3 scripts/verify-repo.py --allow-stale-manifest

echo "Bootstrap complete. Run ./scripts/check.sh next."
