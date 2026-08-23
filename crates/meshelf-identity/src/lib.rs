//! Per-installation signing identity.
//!
//! The private key is deliberately kept behind the platform credential-store crate. The
//! application state file may contain the public key and peer bindings, but never the private
//! signing material.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use keyring::Entry;
use meshelf_core::DeviceId;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const KEYRING_SERVICE: &str = "meshelf";
const KEYRING_USER: &str = "installation-signing-key-v1";
const SIGNING_DOMAIN: &[u8] = b"meshelf/installation-signature/v1\0";

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
    #[error("credential store error: {0}")]
    Keyring(#[source] keyring::Error),
    #[error("credential store record is not valid JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("credential store record does not contain a 32-byte signing key")]
    InvalidSecretKey,
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
