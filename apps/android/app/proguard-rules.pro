# Rust stores a global JNI reference to one MeshelfNative instance while running.
# Keep native declarations and Rust-to-Kotlin callback names stable if R8 is enabled later.
-keep class com.meshelf.android.nativebridge.MeshelfNative { *; }
-keep class com.meshelf.android.nativebridge.NativeEventListener { *; }
