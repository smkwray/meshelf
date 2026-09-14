//! The JNI contract with `com.meshelf.android.nativebridge.MeshelfNative`, ABI-8.
//!
//! ABI-8 keeps ABI-7's method set and descriptors; the shelf JSON the natives return changed
//! (`handoffs/ANDROID_SHELF_ABI.md`), so the version moves with it.
//!
//! No compiler checks this boundary. A native whose name or descriptor drifts from Kotlin still builds
//! on both sides and then fails on the phone: an unresolved export throws `UnsatisfiedLinkError`, a
//! callback looked up with the wrong descriptor fails at runtime, and a wrong return type (an `int`
//! where Kotlin expects a `String`) is an invalid object reference that aborts the process. These
//! tables are the Rust authority; the tests pin them to Kotlin's own table and to the Rust exports.

use jni::sys::jint;

/// Kotlin's `MeshelfNative.ABI_VERSION`, compared for exact equality before any other native call.
pub const ANDROID_ABI_VERSION: jint = 8;

/// JVM binary name of the class that declares the natives and the callbacks.
pub const JNI_CLASS: &str = "com/meshelf/android/nativebridge/MeshelfNative";

/// One method on the Kotlin class, by name and exact JVM descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JniMethod {
    pub name: &'static str,
    pub descriptor: &'static str,
}

const fn method(name: &'static str, descriptor: &'static str) -> JniMethod {
    JniMethod { name, descriptor }
}

/// Every `external fun` Kotlin declares; each is exported below as an instance method.
pub const NATIVE_METHODS: [JniMethod; 20] = [
    method("nativeAbiVersion", "()I"),
    method(
        "nativeStart",
        "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)V",
    ),
    method("nativeStop", "()V"),
    method(
        "nativeCaptureCaptured",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V",
    ),
    method(
        "nativeCaptureDeclined",
        "(Ljava/lang/String;Ljava/lang/String;)V",
    ),
    method("nativeStatus", "()Ljava/lang/String;"),
    method("nativeOpenPairingWindow", "(J)V"),
    method("nativeClosePairingWindow", "()V"),
    method(
        "nativeConfirmPairing",
        "(Ljava/lang/String;Ljava/lang/String;)V",
    ),
    method("nativeRejectPairing", "(Ljava/lang/String;)V"),
    method("nativeShelfSnapshot", "()Ljava/lang/String;"),
    method("nativeRefreshOriginCatalogs", "(J)Ljava/lang/String;"),
    method(
        "nativeAnnounceText",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    ),
    method(
        "nativeAnnounceDocument",
        "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)Ljava/lang/String;",
    ),
    method(
        "nativeReserveOrdinaryPhoto",
        "(Ljava/lang/String;)Ljava/lang/String;",
    ),
    method(
        "nativeCommitOrdinaryPhoto",
        "(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;",
    ),
    method("nativeAbandonPhoto", "(Ljava/lang/String;)V"),
    method(
        "nativeActivate",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    ),
    method("nativeInvalidatePlatformActions", "()V"),
    method(
        "nativeReportPlatformOutcome",
        "(Ljava/lang/String;Ljava/lang/String;)V",
    ),
];

pub const ON_CAPTURE_REQUESTED: JniMethod = method(
    "onCaptureRequested",
    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V",
);
pub const ON_CAPTURE_WITHDRAWN: JniMethod = method(
    "onCaptureWithdrawn",
    "(Ljava/lang/String;Ljava/lang/String;)V",
);
pub const ON_CAPTURE_DELIVERED: JniMethod = method("onCaptureDelivered", "(Ljava/lang/String;)V");
pub const ON_PEER_ADMITTED: JniMethod = method("onPeerAdmitted", "(Ljava/lang/String;)V");
/// Five arguments per plan amendment A5: Kotlin echoes the transcript hash on confirmation.
pub const ON_PAIRING_CANDIDATE: JniMethod = method(
    "onPairingCandidate",
    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V",
);
pub const ON_PAIRING_FINISHED: JniMethod = method(
    "onPairingFinished",
    "(Ljava/lang/String;Ljava/lang/String;)V",
);
/// Returns the stored identity record, or `null` when none exists yet.
pub const LOAD_INSTALLATION_IDENTITY: JniMethod = method("loadInstallationIdentity", "()[B");
pub const STORE_INSTALLATION_IDENTITY: JniMethod = method("storeInstallationIdentity", "([B)V");
pub const ON_SHELF_CHANGED: JniMethod = method("onShelfChanged", "()V");
pub const ON_PLATFORM_DISPATCH_PREPARED: JniMethod = method(
    "onPlatformDispatchPrepared",
    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
);
pub const ON_PLATFORM_FILE_EXPORT_PREPARED: JniMethod = method(
    "onPlatformFileExportPrepared",
    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
);
/// Detached FD (>=0) or DocumentGrantStore codes (-1 unavailable, -2 changed, -3 unsupported).
pub const OPEN_DOCUMENT_SOURCE: JniMethod = method("openDocumentSource", "(Ljava/lang/String;J)I");
pub const RELEASE_DOCUMENT_LEASE: JniMethod =
    method("releaseDocumentLease", "(Ljava/lang/String;)V");

/// Every method Rust invokes on the retained `MeshelfNative` object.
pub const CALLBACK_METHODS: [JniMethod; 13] = [
    ON_CAPTURE_REQUESTED,
    ON_CAPTURE_WITHDRAWN,
    ON_CAPTURE_DELIVERED,
    ON_PEER_ADMITTED,
    ON_PAIRING_CANDIDATE,
    ON_PAIRING_FINISHED,
    LOAD_INSTALLATION_IDENTITY,
    STORE_INSTALLATION_IDENTITY,
    ON_SHELF_CHANGED,
    ON_PLATFORM_DISPATCH_PREPARED,
    ON_PLATFORM_FILE_EXPORT_PREPARED,
    OPEN_DOCUMENT_SOURCE,
    RELEASE_DOCUMENT_LEASE,
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use jni::{
        EnvUnowned,
        objects::{JObject, JString},
        sys::{jint, jlong},
    };

    use super::*;

    /// Copied from MeshelfNativeAbiTest.kt for ABI-8.
    const KOTLIN_NATIVES: [(&str, &str); 20] = [
        ("nativeAbiVersion", "()I"),
        (
            "nativeStart",
            "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)V",
        ),
        ("nativeStop", "()V"),
        (
            "nativeCaptureCaptured",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V",
        ),
        (
            "nativeCaptureDeclined",
            "(Ljava/lang/String;Ljava/lang/String;)V",
        ),
        ("nativeStatus", "()Ljava/lang/String;"),
        ("nativeOpenPairingWindow", "(J)V"),
        ("nativeClosePairingWindow", "()V"),
        (
            "nativeConfirmPairing",
            "(Ljava/lang/String;Ljava/lang/String;)V",
        ),
        ("nativeRejectPairing", "(Ljava/lang/String;)V"),
        ("nativeShelfSnapshot", "()Ljava/lang/String;"),
        ("nativeRefreshOriginCatalogs", "(J)Ljava/lang/String;"),
        (
            "nativeAnnounceText",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        ),
        (
            "nativeAnnounceDocument",
            "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;)Ljava/lang/String;",
        ),
        (
            "nativeReserveOrdinaryPhoto",
            "(Ljava/lang/String;)Ljava/lang/String;",
        ),
        (
            "nativeCommitOrdinaryPhoto",
            "(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;",
        ),
        ("nativeAbandonPhoto", "(Ljava/lang/String;)V"),
        (
            "nativeActivate",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        ),
        ("nativeInvalidatePlatformActions", "()V"),
        (
            "nativeReportPlatformOutcome",
            "(Ljava/lang/String;Ljava/lang/String;)V",
        ),
    ];
    const KOTLIN_CALLBACKS: [(&str, &str); 13] = [
        (
            "onCaptureRequested",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V",
        ),
        (
            "onCaptureWithdrawn",
            "(Ljava/lang/String;Ljava/lang/String;)V",
        ),
        ("onCaptureDelivered", "(Ljava/lang/String;)V"),
        ("onPeerAdmitted", "(Ljava/lang/String;)V"),
        (
            "onPairingCandidate",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V",
        ),
        (
            "onPairingFinished",
            "(Ljava/lang/String;Ljava/lang/String;)V",
        ),
        ("loadInstallationIdentity", "()[B"),
        ("storeInstallationIdentity", "([B)V"),
        ("onShelfChanged", "()V"),
        (
            "onPlatformDispatchPrepared",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        ),
        (
            "onPlatformFileExportPrepared",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        ),
        ("openDocumentSource", "(Ljava/lang/String;J)I"),
        ("releaseDocumentLease", "(Ljava/lang/String;)V"),
    ];

    fn table(rows: &[JniMethod]) -> BTreeMap<&'static str, &'static str> {
        let table: BTreeMap<_, _> = rows.iter().map(|row| (row.name, row.descriptor)).collect();
        assert_eq!(table.len(), rows.len(), "a method name is duplicated");
        table
    }

    #[test]
    fn natives_match_the_kotlin_abi8_table() {
        assert_eq!(ANDROID_ABI_VERSION, 8);
        assert_eq!(table(&NATIVE_METHODS), KOTLIN_NATIVES.into_iter().collect());
    }

    #[test]
    fn callbacks_match_the_kotlin_abi8_table() {
        assert_eq!(
            table(&CALLBACK_METHODS),
            KOTLIN_CALLBACKS.into_iter().collect()
        );
    }

    macro_rules! jni_type {
        ($l:lifetime, S) => { JString<$l> };
        ($l:lifetime, J) => { jlong };
        ($l:lifetime, I) => { jint };
        ($l:lifetime, V) => { () };
    }

    macro_rules! jni_code {
        (S) => {
            "Ljava/lang/String;"
        };
        (J) => {
            "J"
        };
        (I) => {
            "I"
        };
        (V) => {
            "V"
        };
    }

    /// Coerces an export to the instance-method shape spelled by the codes (this fails to compile
    /// if the Rust signature differs, including a static `JClass` receiver) and returns the export's
    /// symbol with the descriptor those same codes spell.
    macro_rules! pin_export {
        ($function:ident, ($($arg:ident),*) -> $ret:ident) => {{
            let _: for<'a> extern "system" fn(
                EnvUnowned<'a>,
                JObject<'a>
                $(, jni_type!('a, $arg))*
            ) -> jni_type!('a, $ret) = crate::$function;
            let descriptor: String = ["(", $(jni_code!($arg),)* ")", jni_code!($ret)].concat();
            (stringify!($function), descriptor)
        }};
    }

    #[test]
    fn exports_have_the_table_names_and_signatures() {
        let exports = [
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAbiVersion, () -> I),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeStart, (S, S, J, S) -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeStop, () -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeCaptureCaptured, (S, S, S, I, I) -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeCaptureDeclined, (S, S) -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeStatus, () -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeOpenPairingWindow, (J) -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeClosePairingWindow, () -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeConfirmPairing, (S, S) -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeRejectPairing, (S) -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeShelfSnapshot, () -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeRefreshOriginCatalogs, (J) -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAnnounceText, (S, S) -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAnnounceDocument, (S, S, J, S) -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeReserveOrdinaryPhoto, (S) -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeCommitOrdinaryPhoto, (S, S, I, I) -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeAbandonPhoto, (S) -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeActivate, (S, S, S, S) -> S),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeInvalidatePlatformActions, () -> V),
            pin_export!(Java_com_meshelf_android_nativebridge_MeshelfNative_nativeReportPlatformOutcome, (S, S) -> V),
        ];
        let prefix = format!("Java_{}_", JNI_CLASS.replace('/', "_"));
        let exported: BTreeMap<&str, String> = exports
            .iter()
            .map(|(symbol, descriptor)| {
                let name = symbol
                    .strip_prefix(prefix.as_str())
                    .expect("JNI symbol prefix");
                (name, descriptor.clone())
            })
            .collect();
        let expected: BTreeMap<&str, String> = NATIVE_METHODS
            .iter()
            .map(|row| (row.name, row.descriptor.to_owned()))
            .collect();
        assert_eq!(exported, expected);
    }
}
