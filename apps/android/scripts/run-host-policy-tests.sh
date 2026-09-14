#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${TMPDIR:-/tmp}/meshelf-android-policy-$$"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT"
SOURCES=(
  app/src/main/java/com/meshelf/android/capture/RequestText.kt
  app/src/main/java/com/meshelf/android/capture/CaptureModels.kt
  app/src/main/java/com/meshelf/android/capture/CaptureFiles.kt
  app/src/main/java/com/meshelf/android/capture/JpegSanitizer.kt
  app/src/main/java/com/meshelf/android/tailscale/TailscaleRouteSelector.kt
  app/src/main/java/com/meshelf/android/service/NotificationContent.kt
  scripts/host-policy/PolicyHarness.kt
)
kotlinc -jvm-target 17 "${SOURCES[@]}" -include-runtime -d "$OUT/policy.jar"
java -jar "$OUT/policy.jar" app/src/test/resources/fixtures/gps-orientation-6.jpg
