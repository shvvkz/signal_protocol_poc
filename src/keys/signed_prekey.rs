use std::fmt::Display;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Represents a signed X25519 pre-key used in ephemeral key exchange protocols.
///
/// # Fields
/// - `id`: A UUID string uniquely identifying this pre-key instance.
/// - `private`: The secret 32-byte X25519 private key. Not serialized.
/// - `public`: The corresponding public key derived from `private`.
/// - `signature`: An Ed25519 signature of the `public` key, generated using the long-term identity key.
/// - `created_at`: UTC timestamp marking when this pre-key was generated.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedPreKey {
    id: String,
    private: [u8; 32],
    pub public: [u8; 32],
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl SignedPreKey {
    /// Constructs a new `SignedPreKey` from an Ed25519 identity key.
    ///
    /// # Arguments
    /// - `identity_signing_key`: Reference to a long-term Ed25519 identity key that will sign the generated public key.
    ///
    /// # Returns
    /// A fully initialized `SignedPreKey` with a fresh X25519 key pair, signed public key, and timestamp.
    pub(crate) fn new(identity_signing_key: &SigningKey) -> Self {
        let private_key = StaticSecret::random_from_rng(&mut OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        let signature = identity_signing_key.sign(public_key.as_bytes());

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            private: private_key.to_bytes(),
            public: *public_key.as_bytes(),
            signature: signature.to_vec(),
            created_at: Utc::now(),
        }
    }

    /// Returns the private key associated with this signed pre-key.
    ///
    /// # Returns
    /// A copy of the 32-byte private key as `[u8; 32]`.
    ///
    /// > ⚠️ This function exposes sensitive material. Handle with care.
    pub(crate) fn get_private(&self) -> [u8; 32] {
        self.private
    }
}

impl Display for SignedPreKey {
    /// Formats the `SignedPreKey` for human-readable output.
    ///
    /// Displays the ID, public key (hex-encoded), and creation timestamp.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, public: {}, created_at: {}",
            self.id,
            hex::encode(self.public),
            self.created_at
        )
    }
}
