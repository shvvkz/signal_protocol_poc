use std::fmt::Display;

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// A single one-time pre-key (OTPK) containing an X25519 key pair and a unique ID.
///
/// This key is intended to be used exactly once during X3DH session establishment.
/// After being used, it should be discarded.
///
/// # Fields
/// - `id`: UUID string uniquely identifying this key.
/// - `private`: 32-byte X25519 secret scalar (not serialized).
/// - `public`: Corresponding public key to be published and used by the sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: String,
    private: [u8; 32],
    pub public: [u8; 32],
}

impl OneTimePreKey {
    /// Generates a new one-time pre-key with random key material.
    ///
    /// # Returns
    /// A `OneTimePreKey` with fresh ID and X25519 key pair.
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(&mut OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            private: private_key.to_bytes(),
            public: *public_key.as_bytes(),
        }
    }

    /// Retrieves the private key associated with this OTPK.
    ///
    /// # Returns
    /// A 32-byte private key.
    pub fn get_private(&self) -> [u8; 32] {
        self.private
    }
}

impl Display for OneTimePreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "public: {}, private: {}",
            hex::encode(self.public),
            hex::encode(self.private)
        )
    }
}

/// A batch of one-time pre-keys owned by a user.
///
/// This is used to supply the X3DH protocol with a pool of forward-secret keys,
/// where each is expected to be used at most once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyGroup {
    keys: Vec<OneTimePreKey>,
}

impl OneTimePreKeyGroup {
    /// Creates a new group of one-time pre-keys of specified size.
    ///
    /// # Arguments
    /// - `size`: The number of pre-keys to generate.
    ///
    /// # Returns
    /// A `OneTimePreKeyGroup` containing `size` freshly generated keys.
    pub(crate) fn new(size: usize) -> Self {
        let keys = (0..size).map(|_| OneTimePreKey::new()).collect();
        Self { keys }
    }

    /// Retrieves a one-time pre-key by its public key (for matching in session negotiation).
    ///
    /// # Arguments
    /// - `pubkey`: The 32-byte public key to match.
    ///
    /// # Returns
    /// An optional matching [`OneTimePreKey`] if found.
    pub(crate) fn get_by_public_key(&self, pubkey: [u8; 32]) -> Option<OneTimePreKey> {
        self.keys.iter().find(|k| k.public == pubkey).cloned()
    }

    /// Returns the number of available keys in the group.
    pub(crate) fn len(&self) -> usize {
        self.keys.len()
    }

    /// Converts this private group into a public-only representation for export or advertisement.
    ///
    /// # Returns
    /// A `OneTimePreKeyGroupPublic` containing only public fields.
    pub(crate) fn public_group(&self) -> OneTimePreKeyGroupPublic {
        OneTimePreKeyGroupPublic {
            keys: self
                .keys
                .iter()
                .map(|k| OneTimePreKeyPublic {
                    id: k.id.clone(),
                    public: k.public,
                })
                .collect(),
        }
    }
}

impl Display for OneTimePreKeyGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "OneTimePreKeyGroup with {} keys:", self.len())?;
        for (i, key) in self.keys.iter().enumerate() {
            writeln!(f, "Key {}: {}", i, key)?;
        }
        Ok(())
    }
}

/// A public-only version of a one-time pre-key, suitable for transmission or publication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyPublic {
    pub id: String,
    pub public: [u8; 32],
}

/// A group of public one-time pre-keys used in X3DH session establishment.
///
/// This is typically published by a user and consumed by a sender to select a pre-key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyGroupPublic {
    pub keys: Vec<OneTimePreKeyPublic>,
}

impl OneTimePreKeyGroupPublic {
    /// Selects a usable one-time pre-key from the group (non-consuming).
    ///
    /// This method simulates a one-time selection from the server side.
    /// In a production system, the selected key would be deleted server-side.
    ///
    /// # Returns
    /// An available `OneTimePreKeyPublic`, or `None` if the group is empty.
    pub fn use_key(&self) -> Option<OneTimePreKeyPublic> {
        if !self.keys.is_empty() {
            // let used_key = self.keys.remove(0);
            // this will ask the api to get a key from the row of the User and delete the first key he founds and return it
            let used_key = self.keys[0].clone();
            // self.keys.push(OneTimePreKey::new());
            Some(used_key)
        } else {
            None
        }
    }
}
