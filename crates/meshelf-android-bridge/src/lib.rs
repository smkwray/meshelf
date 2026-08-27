//! Minimal JNI ABI seed for the Android shell.
//!
//! This crate intentionally exposes no operational Meshelf API yet. The first
//! red/green slice proves only that Kotlin can load one Rust `cdylib` built for
//! `aarch64-linux-android` and obtain the exact ABI version.

use jni::{EnvUnowned, errors::ThrowRuntimeExAndDefault, objects::JClass, sys::jint};

pub const ANDROID_ABI_VERSION: jint = 1;

/// Kotlin declaration:
/// `private external fun nativeAbiVersion(): Int`
/// on `com.meshelf.android.nativebridge.MeshelfNative`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAbiVersion<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> jint {
    unowned_env
        .with_env(|_env| Ok::<jint, jni::errors::Error>(ANDROID_ABI_VERSION))
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use super::ANDROID_ABI_VERSION;

    #[test]
    fn abi_version_is_exactly_one() {
        assert_eq!(ANDROID_ABI_VERSION, 1);
    }
}
