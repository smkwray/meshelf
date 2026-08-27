#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
API_LEVEL="${MESHELF_ANDROID_MIN_API:-26}"

if [[ -z "$NDK_ROOT" || ! -d "$NDK_ROOT/toolchains/llvm/prebuilt" ]]; then
  echo "ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) must name NDK 28.2.13676358" >&2
  exit 2
fi

case "$(uname -s)" in
  Darwin) HOST_TAG="darwin-x86_64" ;;
  Linux) HOST_TAG="linux-x86_64" ;;
  *) echo "unsupported host for this seed script; use an equivalent reviewed PowerShell script" >&2; exit 2 ;;
esac

TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG/bin"
LINKER="$TOOLCHAIN/aarch64-linux-android${API_LEVEL}-clang"
if [[ ! -x "$LINKER" ]]; then
  echo "NDK linker not found: $LINKER" >&2
  exit 2
fi

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$LINKER"
export CC_aarch64_linux_android="$LINKER"
export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"

cargo +1.92.0 build \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  --locked \
  --release \
  --target aarch64-linux-android \
  -p meshelf-android-bridge

SOURCE="$REPO_ROOT/target/aarch64-linux-android/release/libmeshelf_android_bridge.so"
DESTINATION="$REPO_ROOT/apps/android/app/src/main/jniLibs/arm64-v8a"
install -d "$DESTINATION"
install -m 0755 "$SOURCE" "$DESTINATION/libmeshelf_android_bridge.so"
sha256sum "$DESTINATION/libmeshelf_android_bridge.so"
