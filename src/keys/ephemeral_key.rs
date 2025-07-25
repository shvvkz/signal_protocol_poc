use std::fmt::Display;

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Represents a single-use (ephemeral) X25519 key pair used for ECDH-based key exchange.
///
/// Ephemeral keys are used once per session or message to ensure forward secrecy.
/// This struct exposes the public key for sharing and allows access to the private
/// key only for internal use.
///
/// # Fields
/// - `private`: A 32-byte private scalar (kept internal).
/// - `public`: A 32-byte public key, safe to transmit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralKey {
    private: [u8; 32],
    pub public: [u8; 32],
}

impl EphemeralKey {
    /// Generates a fresh `EphemeralKey` using secure random entropy.
    ///
    /// # Returns
    /// A new `EphemeralKey` with an X25519 key pair.
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(&mut OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        Self {
            private: private_key.to_bytes(),
            public: *public_key.as_bytes(),
        }
    }

    /// Returns the private key bytes associated with this `EphemeralKey`.
    ///
    /// # Returns
    /// A 32-byte array representing the X25519 private key.
    ///
    /// > ⚠️ This function exposes sensitive material. Handle with care.
    pub(crate) fn get_private(&self) -> [u8; 32] {
        self.private
    }
}

impl Display for EphemeralKey {
    /// Displays both public and private keys in hexadecimal format.
    /// Intended for debugging or inspection (not recommended in production logs).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "public: {}, private: {}",
            hex::encode(self.public),
            hex::encode(self.private)
        )
    }
}
