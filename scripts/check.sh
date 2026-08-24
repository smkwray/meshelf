#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

source scripts/rust-env.sh

python3 scripts/verify-repo.py --allow-stale-manifest
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

after_tests=0
cargo test --workspace --all-targets && after_tests=1
if [[ "$after_tests" -ne 1 ]]; then
  echo "ERROR: workspace tests failed" >&2
  exit 1
fi
cargo run -p meshelf-sim

echo "All source gates passed on this host. Record the exact receipt in status/."
