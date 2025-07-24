use std::fmt::Display;

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: String,
    private: [u8; 32],
    pub public: [u8; 32],
}

impl OneTimePreKey {
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(&mut OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            private: private_key.to_bytes(),
            public: *public_key.as_bytes(),
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyGroup {
    keys: Vec<OneTimePreKey>,
}

impl OneTimePreKeyGroup {
    pub(crate) fn new(size: usize) -> Self {
        let keys = (0..size).map(|_| OneTimePreKey::new()).collect();
        Self { keys }
    }

    pub(crate) fn get_keys(&self) -> &Vec<OneTimePreKey> {
        &self.keys
    }

    pub(crate) fn use_key(&mut self) -> Option<OneTimePreKey> {
        if !self.keys.is_empty() {
            // let used_key = self.keys.remove(0);
            println!("Delete the first key from the group in database");
            let used_key = self.keys[0].clone();
            // self.keys.push(OneTimePreKey::new());
            Some(used_key)
        } else {
            None
        }
    }

    pub(crate) fn get_private_by_public_key(&self, pubkey: [u8; 32]) -> Option<[u8; 32]> {
        let opk_used = self.keys.iter().find(|k| k.public == pubkey).cloned();
        if opk_used.is_some() {
            Some(opk_used.unwrap().private)
        } else {
            None
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.keys.len()
    }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyPublic {
    pub id: String,
    pub public: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyGroupPublic {
    pub keys: Vec<OneTimePreKeyPublic>,
}

impl OneTimePreKeyGroupPublic {
    pub fn use_key(&mut self) -> Option<OneTimePreKeyPublic> {
        if !self.keys.is_empty() {
            // let used_key = self.keys.remove(0);
            println!("Delete the first key from the group in database");
            // this will ask the api to get a key from the row of the User and delete the first key he founds and return it
            let used_key = self.keys[0].clone();
            // self.keys.push(OneTimePreKey::new());
            Some(used_key)
        } else {
            None
        }
    }
}
