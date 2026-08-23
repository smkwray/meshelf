#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RUST_LOG="${RUST_LOG:-meshelf=debug,info}"
exec cargo run -p meshelf-desktop
