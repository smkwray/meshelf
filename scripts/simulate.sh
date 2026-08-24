#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/rust-env.sh
exec cargo run -p meshelf-sim
