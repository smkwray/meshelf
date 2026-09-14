#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v gradle >/dev/null || {
  echo "Gradle 9.5.0 must be installed on PATH; this repository intentionally does not track wrapper files." >&2
  exit 2
}
version="$(gradle --version | awk '/^Gradle / { print $2; exit }')"
[[ "$version" == "9.5.0" ]] || {
  echo "Gradle 9.5.0 required, found ${version:-unknown}" >&2
  exit 2
}
[[ "$(java -version 2>&1 | sed -n '1s/.*version "\([0-9][0-9]*\).*/\1/p')" == "17" ]] || {
  echo "JDK 17 is required." >&2
  exit 2
}
: "${ANDROID_SDK_ROOT:?ANDROID_SDK_ROOT must point to the Android SDK containing platform 37 and build-tools 37.0.0}"
[[ -d "$ANDROID_SDK_ROOT/platforms/android-37" ]] || { echo "platform android-37 missing" >&2; exit 2; }
[[ -d "$ANDROID_SDK_ROOT/build-tools/37.0.0" ]] || { echo "build-tools 37.0.0 missing" >&2; exit 2; }
NDK_ROOT="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/28.2.13676358}"
[[ -d "$NDK_ROOT" ]] || { echo "NDK 28.2.13676358 missing" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*28\.2\.13676358$' "$NDK_ROOT/source.properties" || {
  echo "NDK path is not revision 28.2.13676358: $NDK_ROOT" >&2
  exit 2
}
mode="${1:-online}"
case "$mode" in
  online) gradle --no-daemon --refresh-dependencies testDebugUnitTest assembleDebug ;;
  offline) gradle --no-daemon --offline testDebugUnitTest assembleDebug ;;
  *) echo "usage: $0 [online|offline]" >&2; exit 2 ;;
esac
