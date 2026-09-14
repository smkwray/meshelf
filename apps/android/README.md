# meshelf Android app

This directory uses AGP 9.3.2's built-in Kotlin support; it does not apply the legacy
`org.jetbrains.kotlin.android` plugin. Toolchain pins are compile/target SDK 37, build-tools
37.0.0, minSdk 26, NDK 28.2.13676358, Gradle 9.5.0, and JDK 17.

The Gradle wrapper is intentionally not tracked. On a Linux build host, install/use Gradle 9.5.0 and run:

```bash
scripts/build-rust-arm64.sh
scripts/build-app.sh online   # first dependency fetch
scripts/build-app.sh offline  # proves the subsequent offline build path
```

The app is a shelf peer. It puts typed or pasted text, camera photos, and gallery picks on the
shelf, lists offers from the other meshelf devices on the tailnet, and copies, saves, or shares one
only when the user taps it. Folders are not saved on the phone; zip the folder on the computer and send
the zip. A photo request from a desktop command opens the camera, and the shutter is the user's
consent.

Background availability is opt-in and off after every process start. The foreground service uses only
the active default VPN with one `100.64.0.0/10` IPv4 address, and it never creates a VPN or persists a
network handle. The shelf works in the foreground without it.

Admission follows the interim functional-testing policy in `SECURITY.md`: a valid signed meshelf
installation on the same tailnet is admitted automatically. The six-digit pairing screen is implemented
but not reachable from the interface while that policy stands.

`MeshelfNative` implements JNI ABI 8, pinned by `MeshelfNativeAbiTest`. The app fails closed at startup
unless the bundled Rust bridge reports the same ABI.
