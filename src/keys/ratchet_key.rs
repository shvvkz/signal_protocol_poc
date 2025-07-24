use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RatchetKey {
    private: [u8; 32],
    pub public: [u8; 32],
}

impl RatchetKey {
    pub(crate) fn new() -> Self {
        let private = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&private);

        Self {
            private: private.to_bytes(),
            public: *public.as_bytes(),
        }
    }

    pub(crate) fn from_keys(private: [u8; 32], public: [u8; 32]) -> Self {
        Self { private, public }
    }

    pub(crate) fn get_private(&self) -> [u8; 32] {
        self.private
    }
}
