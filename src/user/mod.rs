pub mod public_info;

use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::keys::{
    encrypted_message::EncryptedMessage, identity::IdentityKey,
    one_time_prekey::OneTimePreKeyGroup, ratchet_key::RatchetKey, signed_prekey::SignedPreKey,
};

use std::collections::HashMap;

use crate::{
    crypto_utils::hkdf::derive_root_key,
    double_ratchet::state::RatchetState,
    keys::ephemeral_key::EphemeralKey,
    user::public_info::UserPublicInfo,
    x3dh::session::{create_session_key, receive_session_key},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub ik: IdentityKey,
    pub spk: SignedPreKey,
    pub opk: OneTimePreKeyGroup,
    sessions: HashMap<String, RatchetState>,
}

impl User {
    pub fn new(name: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let ik = IdentityKey::new();
        let spk = SignedPreKey::new(&ik.signing_key());
        let opk = OneTimePreKeyGroup::new(100);

        Self {
            id,
            name,
            ik,
            spk,
            opk,
            sessions: HashMap::new(),
        }
    }

    pub fn public_info(&self) -> UserPublicInfo {
        UserPublicInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            ik: self.ik.dh_public,
            spk: self.spk.public,
        }
    }

    pub fn send_message(&mut self, to: &mut User, plaintext: &str) -> EncryptedMessage {
        let receiver_id = to.id.clone();

        // We'll store the OPK used (if any) here
        let mut used_opk: Option<[u8; 32]> = None;
        let mut used_ek: Option<[u8; 32]> = None;

        let ratchet = self.sessions.entry(receiver_id.clone()).or_insert_with(|| {
            let ek = EphemeralKey::new();
            // Try to use an OPK from the recipient
            let opk = to.opk.use_key();
            if let Some(ref opk_val) = opk {
                used_opk = Some(opk_val.public);
            }
            used_ek = Some(ek.public);
            let session = create_session_key(
                self.name.clone(),
                to.name.clone(),
                &self.ik,
                &ek,
                &to.spk,
                &to.ik,
                opk.as_ref(),
            );
            let rk = derive_root_key(&session.get_bytes());
            let dhs = RatchetKey::new();

            RatchetState::new(rk, dhs, Some(to.spk.public), true)
        });
        ratchet.encrypt(
            plaintext,
            self.name.clone(),
            to.name.clone(),
            used_opk,
            used_ek,
        )
    }

    pub fn receive_message(&mut self, from: &User, msg: &EncryptedMessage) -> Option<String> {
        let sender_id = from.id.clone();

        let ratchet = self.sessions.entry(sender_id.clone()).or_insert_with(|| {
            let opk_private = msg.opk_used.and_then(|opk| {
                self.opk.get_private_by_public_key(opk)
            });
            let opk_private = opk_private.unwrap_or([0u8; 32]);
            let ek = msg.ek_used.unwrap_or([0u8; 32]);
            let session = receive_session_key(
                self.name.clone(),
                from.name.clone(),
                &self.ik,
                &self.spk,
                opk_private,
                &from.ik,
                ek,
            );
            let rk = derive_root_key(&session.get_bytes());
            // Accessing the private field directly is not possible if it's private.
            // You need to provide a public method in SignedPreKey to get the private key if needed.
            // For example, add this to SignedPreKey:
            // pub fn private_key(&self) -> [u8; 32] { self.private }
            let dhs = RatchetKey::from_keys(self.spk.get_private(), self.spk.public);
            RatchetState::new(rk, dhs, None, false)
        });

        ratchet.decrypt(msg)
    }
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}\nname: {}\nik: {}\nspk: {}\nopk_count: {}\nsessions:\n{}\n",
            self.id,
            self.name,
            self.ik,
            self.spk,
            self.opk.len(),
            self.sessions.iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}
