use std::fmt::Display;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedPreKey {
    id: String,
    pub private: [u8; 32],
    pub public: [u8; 32],
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl SignedPreKey {
    pub fn new(identity_signing_key: &SigningKey) -> Self {
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

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

impl Display for SignedPreKey {
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