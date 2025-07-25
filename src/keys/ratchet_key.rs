use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// Represents an ephemeral X25519 key pair used in Double Ratchet exchanges.
///
/// The `RatchetKey` struct encapsulates a 32-byte private key and its associated
/// public key, both serialized for use in secure messaging state.
///
/// # Fields
/// - `private`: A 32-byte X25519 private scalar (kept private).
/// - `public`: A 32-byte X25519 public key (shared with the peer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RatchetKey {
    private: [u8; 32],
    pub public: [u8; 32],
}

impl RatchetKey {
    /// Generates a new random `RatchetKey` using secure RNG.
    ///
    /// Internally uses `OsRng` to produce a cryptographically secure X25519 key pair.
    ///
    /// # Returns
    /// A newly generated `RatchetKey` instance.
    pub(crate) fn new() -> Self {
        let private = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&private);

        Self {
            private: private.to_bytes(),
            public: *public.as_bytes(),
        }
    }

    /// Constructs a `RatchetKey` from pre-existing key material.
    ///
    /// This is typically used when restoring state from serialized or externally derived keys.
    ///
    /// # Parameters
    /// - `private`: A 32-byte private key.
    /// - `public`: A 32-byte public key corresponding to `private`.
    ///
    /// # Returns
    /// A `RatchetKey` instance wrapping the provided material.
    pub(crate) fn from_keys(private: [u8; 32], public: [u8; 32]) -> Self {
        Self { private, public }
    }

    /// Returns the private key bytes associated with this `RatchetKey`.
    ///
    /// # Returns
    /// A 32-byte array representing the X25519 private key.
    ///
    /// > ⚠️ This function exposes sensitive material. Handle with care.
    pub(crate) fn get_private(&self) -> [u8; 32] {
        self.private
    }
}
