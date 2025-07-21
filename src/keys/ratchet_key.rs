use serde::{Serialize, Deserialize};
use rand_core::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetKey {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl RatchetKey {
    pub fn new() -> Self {
        let private = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&private);

        Self {
            private: private.to_bytes(),
            public: *public.as_bytes(),
        }
    }

    pub fn from_bytes(private: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(private);
        let public_key = PublicKey::from(&private_key);
        Self {
            private,
            public: *public_key.as_bytes(),
        }
    }

    
}
