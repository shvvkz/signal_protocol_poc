use std::fmt::Display;

use serde::{Serialize, Deserialize};
use rand_core::OsRng;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralKey {
    private: [u8; 32],
    pub public: [u8; 32],
}

impl EphemeralKey {
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(&mut OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        Self {
            private: private_key.to_bytes(),
            public: *public_key.as_bytes(),
        }
    }

    pub(crate) fn private(&self) -> [u8; 32] {
        self.private
    }
}

impl Display for EphemeralKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "public: {}, private: {}", hex::encode(self.public), hex::encode(self.private))
    }
}

