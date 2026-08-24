#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "package-macos.sh must run on macOS" >&2
  exit 1
fi

source scripts/rust-env.sh

output_directory="release/macos"
install=false
while (($#)); do
  case "$1" in
    --install)
      install=true
      shift
      ;;
    --output)
      if (($# < 2)); then
        echo "--output requires a directory" >&2
        exit 1
      fi
      output_directory="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
architecture="$(uname -m)"
if [[ -z "$version" ]]; then
  echo "workspace version is missing from Cargo.toml" >&2
  exit 1
fi
bundle="$output_directory/meshelf.app"
contents="$bundle/Contents"
macos="$contents/MacOS"
resources="$contents/Resources"

cargo build --locked --release -p meshelf-desktop -p meshelfctl

if [[ -e "$bundle" ]]; then
  rm -rf -- "$bundle"
fi
mkdir -p "$macos" "$resources"
cp target/release/meshelf-desktop "$macos/meshelf"
cp target/release/meshelfctl "$macos/meshelfctl"
cp assets/meshelf.icns "$resources/meshelf.icns"

cat > "$contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>meshelf</string>
  <key>CFBundleExecutable</key>
  <string>meshelf</string>
  <key>CFBundleIconFile</key>
  <string>meshelf</string>
  <key>CFBundleIdentifier</key>
  <string>app.meshelf.desktop</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>meshelf</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$version</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

plutil -lint "$contents/Info.plist" >/dev/null
codesign --force --sign - "$bundle"

zip_path="$output_directory/meshelf-$version-macos-$architecture.zip"
if [[ -e "$zip_path" ]]; then
  rm -f -- "$zip_path"
fi
ditto -c -k --keepParent "$bundle" "$zip_path"
shasum -a 256 "$zip_path" > "$zip_path.sha256"

if [[ "$install" == true ]]; then
  install_root="$HOME/Applications"
  installed_bundle="$install_root/meshelf.app"
  mkdir -p "$install_root"
  if [[ -e "$installed_bundle" ]]; then
    rm -rf -- "$installed_bundle"
  fi
  ditto "$bundle" "$installed_bundle"
  launch_services="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  if [[ -x "$launch_services" ]]; then
    "$launch_services" -f "$installed_bundle"
  fi
  echo "$installed_bundle"
fi

echo "$bundle"
echo "$zip_path"
