#!/usr/bin/env bash

meshelf_toolchain_bin="$(dirname "$(rustup which --toolchain 1.92.0 cargo)")"
export PATH="$meshelf_toolchain_bin:$PATH"

if [[ "$(uname -s)" == "Darwin" ]]; then
  meshelf_logical_cores="$(sysctl -n hw.logicalcpu)"
else
  meshelf_logical_cores="$(getconf _NPROCESSORS_ONLN)"
fi
export CARGO_BUILD_JOBS="$((meshelf_logical_cores / 2))"
if ((CARGO_BUILD_JOBS < 1)); then
  export CARGO_BUILD_JOBS=1
fi

echo "Rust build jobs: $CARGO_BUILD_JOBS of $meshelf_logical_cores logical cores"

export CARGO_INCREMENTAL=0

# Test fixtures reserve payload plus a 2 GiB safety headroom on the temp filesystem (production
# admission behaviour). A small or quota-limited tmpfs /tmp refuses those reservations, so an unset or
# system-default TMPDIR moves beside the build output. Any other TMPDIR the caller chose is kept.
if [[ -z "${TMPDIR:-}" || "${TMPDIR}" == /tmp* || "${TMPDIR}" == /var/folders/* ]]; then
  meshelf_tmp="${CARGO_TARGET_DIR:-$(pwd)/target}/tmp"
  mkdir -p "$meshelf_tmp"
  export TMPDIR="$meshelf_tmp"
fi
