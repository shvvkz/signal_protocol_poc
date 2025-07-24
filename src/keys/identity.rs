use std::fmt::Display;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKey {
    dh_private: [u8; 32], // X25519
    pub dh_public: [u8; 32],
    sign_private: [u8; 32], // Ed25519
    sign_public: [u8; 32],
}

impl IdentityKey {
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

    pub(crate) fn private(&self) -> [u8; 32] {
        self.dh_private
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.sign_private)
    }
}

impl Display for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dh_public: {}, sign_public: {}",
            hex::encode(self.dh_public),
            hex::encode(self.sign_public)
        )
    }
}
