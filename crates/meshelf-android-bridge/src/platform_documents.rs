//! Android document leases: Rust asks Kotlin to open a detached FD for a selected URI grant.
//! Bytes are never copied into app storage; the FD is the only read path.

use jni::{
    objects::{JObject, JValue},
    refs::Global,
    sys::jlong,
    vm::JavaVM,
};
use meshelf_core::DocumentLeaseId;
use meshelf_net::{DocumentOpenError, DocumentSourceProvider};

use crate::{abi, invoke};

/// JNI-backed [`DocumentSourceProvider`] for ordinary gallery/document offers.
pub struct PlatformDocuments {
    vm: JavaVM,
    target: Global<JObject<'static>>,
}

impl PlatformDocuments {
    #[must_use]
    pub fn new(vm: JavaVM, target: Global<JObject<'static>>) -> Self {
        Self { vm, target }
    }

    fn call_open(&self, lease_id: &str, expected_bytes: u64) -> Result<i32, DocumentOpenError> {
        self.vm
            .attach_current_thread(|env| -> jni::errors::Result<i32> {
                env.with_local_frame(8, |env| {
                    let lease = env.new_string(lease_id)?;
                    let expected = jlong::try_from(expected_bytes).unwrap_or(jlong::MAX);
                    let result = invoke(
                        env,
                        self.target.as_obj(),
                        abi::OPEN_DOCUMENT_SOURCE,
                        &[JValue::Object(&lease), JValue::Long(expected)],
                    )?;
                    result.i()
                })
            })
            .map_err(|error| {
                // Surface JNI attach/call failures for adb logcat without clipboard bodies.
                eprintln!("meshelf document open JNI failed for {lease_id}: {error}");
                DocumentOpenError::Unavailable
            })
    }

    fn call_release(&self, lease_id: &str) {
        let _ = self
            .vm
            .attach_current_thread(|env| -> jni::errors::Result<()> {
                let lease = env.new_string(lease_id)?;
                invoke(
                    env,
                    self.target.as_obj(),
                    abi::RELEASE_DOCUMENT_LEASE,
                    &[JValue::Object(&lease)],
                )?;
                Ok(())
            });
    }
}

impl DocumentSourceProvider for PlatformDocuments {
    fn open(
        &self,
        lease_id: DocumentLeaseId,
        expected_bytes: u64,
    ) -> Result<tokio::fs::File, DocumentOpenError> {
        let code = self.call_open(&lease_id.to_string(), expected_bytes)?;
        match code {
            fd if fd >= 0 => file_from_detached_fd(fd),
            -1 => Err(DocumentOpenError::Unavailable),
            -2 => Err(DocumentOpenError::Changed),
            _ => Err(DocumentOpenError::Unsupported),
        }
    }

    fn release(&self, lease_id: DocumentLeaseId) {
        self.call_release(&lease_id.to_string());
    }
}

/// Takes ownership of a descriptor Kotlin detached from a `ParcelFileDescriptor`.
#[cfg(unix)]
fn file_from_detached_fd(fd: i32) -> Result<tokio::fs::File, DocumentOpenError> {
    use std::os::fd::FromRawFd;
    // SAFETY: Kotlin detached a ParcelFileDescriptor FD and handed its ownership to this call.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    Ok(tokio::fs::File::from_std(file))
}

/// Document leases are raw unix descriptors; a non-unix host has no way to adopt one, so the
/// open is refused explicitly rather than reported as a readable source.
#[cfg(not(unix))]
fn file_from_detached_fd(_fd: i32) -> Result<tokio::fs::File, DocumentOpenError> {
    crate::host::log_android("document sources require a unix file descriptor");
    Err(DocumentOpenError::Unsupported)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{io::Write, os::fd::IntoRawFd};

    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn a_detached_descriptor_becomes_the_readable_source_it_names() {
        let mut file = tempfile::tempfile().expect("temporary file");
        file.write_all(b"leased bytes").expect("write");
        std::io::Seek::rewind(&mut file).expect("rewind");
        let mut source = file_from_detached_fd(file.into_raw_fd()).expect("adopted");
        let mut read = Vec::new();
        source.read_to_end(&mut read).await.expect("read");
        assert_eq!(read, b"leased bytes");
    }
}
