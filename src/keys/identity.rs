use std::fmt::Display;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Represents a user's long-term identity key pair.
///
/// This struct combines both an X25519 key pair (for ECDH) and an Ed25519 key pair (for signatures).
///
/// # Fields
/// - `dh_private`: X25519 private scalar (32 bytes) used for ECDH.
/// - `dh_public`: Corresponding X25519 public key.
/// - `sign_private`: Ed25519 private seed (32 bytes) used for signing.
/// - `sign_public`: Corresponding Ed25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKey {
    dh_private: [u8; 32], // X25519
    pub dh_public: [u8; 32],
    sign_private: [u8; 32], // Ed25519
    sign_public: [u8; 32],
}

impl IdentityKey {
    /// Generates a fresh `IdentityKey` with secure randomness.
    ///
    /// # Returns
    /// A new `IdentityKey` instance containing both X25519 and Ed25519 key pairs.
    pub fn new() -> Self {
        let dh_private = StaticSecret::random_from_rng(&mut OsRng);
        let dh_public = X25519PublicKey::from(&dh_private);

        let mut signing_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut signing_bytes);
        let sign_private = SigningKey::from_bytes(&signing_bytes);
        let sign_public = sign_private.verifying_key();

        Self {
            dh_private: dh_private.to_bytes(),
            dh_public: *dh_public.as_bytes(),
            sign_private: signing_bytes,
            sign_public: sign_public.to_bytes(),
        }
    }

    /// Returns the X25519 private key bytes.
    ///
    /// # Returns
    /// A 32-byte array used in ECDH key agreement.
    ///
    /// > ⚠️ This function exposes sensitive material. Handle with care.
    pub(crate) fn get_private(&self) -> [u8; 32] {
        self.dh_private
    }

    /// Returns the Ed25519 signing key.
    ///
    /// # Returns
    /// A `SigningKey` usable for signing data (e.g., pre-keys or identity attestations).
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.sign_private)
    }
}

impl Display for IdentityKey {
    /// Displays the public components of the identity key in hex format.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dh_public: {}, sign_public: {}",
            hex::encode(self.dh_public),
            hex::encode(self.sign_public)
        )
    }
}
