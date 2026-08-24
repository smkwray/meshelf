//! Per-installation signing identity.
//!
//! The private key is kept in a per-user platform store. Windows uses DPAPI, Linux uses its
//! credential store, and unsigned macOS development builds use an owner-only file so replacing an
//! ad-hoc-signed bundle does not invalidate Keychain access. Public app state never contains it.

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(target_os = "linux")]
use keyring::Entry;
use meshelf_core::DeviceId;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(target_os = "linux")]
const KEYRING_SERVICE: &str = "meshelf";
#[cfg(target_os = "linux")]
const KEYRING_USER: &str = "installation-signing-key-v1";
const SIGNING_DOMAIN: &[u8] = b"meshelf/installation-signature/v1\0";
#[cfg(target_os = "windows")]
const WINDOWS_DPAPI_ENTROPY: &[u8] = b"meshelf/installation-identity/v1";
#[cfg(target_os = "windows")]
const WINDOWS_IDENTITY_FILE: &str = "installation-identity-v1.dpapi";
#[cfg(target_os = "macos")]
const MACOS_IDENTITY_FILE: &str = "installation-identity-v1.json";

#[derive(Debug, Clone)]
pub struct InstallationIdentity {
    pub device_id: DeviceId,
    signing_key: SigningKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredIdentity {
    device_id: DeviceId,
    secret_key: Vec<u8>,
}

impl InstallationIdentity {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            device_id: DeviceId::new(),
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn load_or_create() -> Result<Self, IdentityError> {
        load_or_create_windows()
    }

    #[cfg(target_os = "macos")]
    pub fn load_or_create() -> Result<Self, IdentityError> {
        load_or_create_macos()
    }

    #[cfg(target_os = "linux")]
    pub fn load_or_create() -> Result<Self, IdentityError> {
        let entry = Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(IdentityError::Keyring)?;
        match entry.get_secret() {
            Ok(bytes) => Self::from_stored(&bytes),
            Err(keyring::Error::NoEntry) => {
                let identity = Self::generate();
                let stored = identity.to_stored()?;
                entry.set_secret(&stored).map_err(IdentityError::Keyring)?;
                Ok(identity)
            }
            Err(error) => Err(IdentityError::Keyring(error)),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut transcript = Vec::with_capacity(SIGNING_DOMAIN.len() + message.len());
        transcript.extend_from_slice(SIGNING_DOMAIN);
        transcript.extend_from_slice(message);
        self.signing_key.sign(&transcript).to_bytes().to_vec()
    }

    #[must_use]
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(public_key) = <[u8; 32]>::try_from(public_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
            return false;
        };
        let mut transcript = Vec::with_capacity(SIGNING_DOMAIN.len() + message.len());
        transcript.extend_from_slice(SIGNING_DOMAIN);
        transcript.extend_from_slice(message);
        verifying_key.verify(&transcript, &signature).is_ok()
    }

    fn to_stored(&self) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(&StoredIdentity {
            device_id: self.device_id,
            secret_key: self.signing_key.to_bytes().to_vec(),
        })
        .map_err(IdentityError::Json)
    }

    fn from_stored(bytes: &[u8]) -> Result<Self, IdentityError> {
        let stored: StoredIdentity = serde_json::from_slice(bytes).map_err(IdentityError::Json)?;
        let secret_key = <[u8; 32]>::try_from(stored.secret_key.as_slice())
            .map_err(|_| IdentityError::InvalidSecretKey)?;
        Ok(Self {
            device_id: stored.device_id,
            signing_key: SigningKey::from_bytes(&secret_key),
        })
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[cfg(target_os = "linux")]
    #[error("credential store error: {0}")]
    Keyring(#[source] keyring::Error),
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[error("could not determine the user configuration directory")]
    ConfigDirectoryUnavailable,
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[error("identity-store I/O error: {0}")]
    Io(#[source] std::io::Error),
    #[cfg(target_os = "windows")]
    #[error("Windows DPAPI identity protection failed: {0}")]
    Dpapi(String),
    #[error("credential store record is not valid JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("credential store record does not contain a 32-byte signing key")]
    InvalidSecretKey,
}

#[cfg(target_os = "macos")]
fn load_or_create_macos() -> Result<InstallationIdentity, IdentityError> {
    let directory = dirs::config_dir()
        .ok_or(IdentityError::ConfigDirectoryUnavailable)?
        .join("meshelf");
    fs::create_dir_all(&directory).map_err(IdentityError::Io)?;
    let path = directory.join(MACOS_IDENTITY_FILE);
    match fs::read(&path) {
        Ok(stored) => InstallationIdentity::from_stored(&stored),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_macos_identity(&path),
        Err(error) => Err(IdentityError::Io(error)),
    }
}

#[cfg(target_os = "macos")]
fn create_macos_identity(path: &Path) -> Result<InstallationIdentity, IdentityError> {
    let identity = InstallationIdentity::generate();
    let stored = identity.to_stored()?;
    let temporary = path.with_extension(format!("json.{}.tmp", identity.device_id));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(IdentityError::Io)?;
    file.write_all(&stored).map_err(IdentityError::Io)?;
    file.sync_all().map_err(IdentityError::Io)?;
    drop(file);
    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary).map_err(IdentityError::Io)?;
            Ok(identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            let stored = fs::read(path).map_err(IdentityError::Io)?;
            InstallationIdentity::from_stored(&stored)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(IdentityError::Io(error))
        }
    }
}

#[cfg(target_os = "windows")]
fn load_or_create_windows() -> Result<InstallationIdentity, IdentityError> {
    let directory = dirs::config_dir()
        .ok_or(IdentityError::ConfigDirectoryUnavailable)?
        .join("meshelf");
    fs::create_dir_all(&directory).map_err(IdentityError::Io)?;
    let path = directory.join(WINDOWS_IDENTITY_FILE);
    match load_windows_identity(&path) {
        Ok(identity) => Ok(identity),
        Err(IdentityError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            create_windows_identity(&path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "windows")]
fn load_windows_identity(path: &Path) -> Result<InstallationIdentity, IdentityError> {
    let protected = fs::read(path).map_err(IdentityError::Io)?;
    let stored = windows_dpapi::decrypt_data(
        &protected,
        windows_dpapi::Scope::User,
        Some(WINDOWS_DPAPI_ENTROPY),
    )
    .map_err(|error| IdentityError::Dpapi(error.to_string()))?;
    InstallationIdentity::from_stored(&stored)
}

#[cfg(target_os = "windows")]
fn create_windows_identity(path: &Path) -> Result<InstallationIdentity, IdentityError> {
    let identity = InstallationIdentity::generate();
    let stored = identity.to_stored()?;
    let protected = windows_dpapi::encrypt_data(
        &stored,
        windows_dpapi::Scope::User,
        Some(WINDOWS_DPAPI_ENTROPY),
    )
    .map_err(|error| IdentityError::Dpapi(error.to_string()))?;
    let temporary = temporary_identity_path(path, identity.device_id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(IdentityError::Io)?;
    file.write_all(&protected).map_err(IdentityError::Io)?;
    file.sync_all().map_err(IdentityError::Io)?;
    drop(file);

    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary).map_err(IdentityError::Io)?;
            Ok(identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            load_windows_identity(path)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(IdentityError::Io(error))
        }
    }
}

#[cfg(target_os = "windows")]
fn temporary_identity_path(path: &Path, device_id: DeviceId) -> PathBuf {
    path.with_extension(format!("dpapi.{device_id}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_signs_and_rejects_mutations() {
        let identity = InstallationIdentity::generate();
        let message = b"pairing transcript";
        let signature = identity.sign(message);
        assert!(InstallationIdentity::verify(
            &identity.public_key(),
            message,
            &signature
        ));
        assert!(!InstallationIdentity::verify(
            &identity.public_key(),
            b"mutated transcript",
            &signature
        ));
    }

    #[test]
    fn stored_identity_round_trip_keeps_device_and_key() {
        let identity = InstallationIdentity::generate();
        let stored = identity.to_stored().expect("serialize");
        let reopened = InstallationIdentity::from_stored(&stored).expect("deserialize");
        assert_eq!(reopened.device_id, identity.device_id);
        assert_eq!(reopened.public_key(), identity.public_key());
    }
}
