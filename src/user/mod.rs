use std::fmt::Display;

use serde::{Serialize, Deserialize};

use crate::keys::{identity::IdentityKey, one_time_prekey::OneTimePreKeyGroup, signed_prekey::SignedPreKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub ik: IdentityKey,
    pub spk: SignedPreKey,
    pub opk: OneTimePreKeyGroup,
}

impl User {
    pub fn new(name: String)
        -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let ik = IdentityKey::new();
        let spk = SignedPreKey::new(&ik.signing_key());
        let opk = OneTimePreKeyGroup::new(100);

        User {
            id,
            name,
            ik,
            spk,
            opk,
        }
    }
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}\nname: {},\nik: {},\nspk: {},\nopk_count: {}",
            self.id,
            self.name,
            self.ik,
            self.spk,
            self.opk
        )
    }
}