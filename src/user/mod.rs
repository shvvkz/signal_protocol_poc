pub mod public_info;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;

use crate::keys::{
    encrypted_message::EncryptedMessage, identity::IdentityKey,
    one_time_prekey::OneTimePreKeyGroup, ratchet_key::RatchetKey, signed_prekey::SignedPreKey,
};
use crate::{
    crypto_utils::hkdf::derive_root_key,
    double_ratchet::state::RatchetState,
    keys::ephemeral_key::EphemeralKey,
    user::public_info::UserPublicInfo,
    x3dh::session::{create_session_key, receive_session_key},
};

/// Represents a user in the Signal messaging protocol, with cryptographic identity, key material,
/// and session state management.
///
/// # Fields
/// - `id`: A unique UUID representing the user.
/// - `name`: A human-readable identifier.
/// - `ik`: The user's long-term identity key.
/// - `spk`: A signed pre-key used in X3DH session establishment.
/// - `opk`: A pool of one-time pre-keys providing forward secrecy.
/// - `sessions`: A mapping from remote user IDs to ratchet session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    ik: IdentityKey,
    spk: SignedPreKey,
    opk: OneTimePreKeyGroup,
    sessions: HashMap<String, RatchetState>,
}

impl User {
    /// Initializes a new user with a fresh identity key, signed pre-key, and a batch of one-time pre-keys.
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

    /// Returns the public-facing cryptographic material and metadata required for X3DH session establishment.
    pub fn public_info(&self) -> UserPublicInfo {
        UserPublicInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            ik: self.ik.dh_public,
            spk: self.spk.public,
            opk: self.opk.public_group(),
        }
    }

    /// Sends a message to the target user using their [`UserPublicInfo`].
    ///
    /// If no session exists, initializes a new one using the X3DH protocol, followed by
    /// Double Ratchet encryption of the plaintext.
    ///
    /// # Arguments
    /// - `to`: Public info of the recipient user.
    /// - `plaintext`: Message content to encrypt.
    ///
    /// # Returns
    /// An [`EncryptedMessage`] ready for transmission.
    pub fn send_message(&mut self, to: &UserPublicInfo, plaintext: &str) -> EncryptedMessage {
        let receiver_id = to.id.clone();

        let mut used_opk: Option<[u8; 32]> = None;
        let mut used_ek: Option<[u8; 32]> = None;

        let ratchet = self.sessions.entry(receiver_id.clone()).or_insert_with(|| {
            let ek = EphemeralKey::new();
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
                to.spk,
                to.ik,
                opk.as_ref(),
            );

            let rk = derive_root_key(&session.get_bytes());
            let dhs = RatchetKey::new();

            RatchetState::new(rk, dhs, Some(to.spk), true)
        });

        ratchet.encrypt(
            plaintext,
            self.name.clone(),
            to.name.clone(),
            used_opk,
            used_ek,
        )
    }

    /// Receives and decrypts a message from another user using their [`UserPublicInfo`].
    ///
    /// If no session exists, attempts to reconstruct it using the sender's identity key,
    /// the local one-time pre-key, and the ephemeral key used in the message.
    ///
    /// # Arguments
    /// - `from`: Sender's public key bundle.
    /// - `msg`: The [`EncryptedMessage`] to be decrypted.
    ///
    /// # Returns
    /// The decrypted plaintext message, or `None` if decryption fails.
    pub fn receive_message(
        &mut self,
        from: &UserPublicInfo,
        msg: &EncryptedMessage,
    ) -> Option<String> {
        let sender_id = from.id.clone();

        let ratchet = self.sessions.entry(sender_id.clone()).or_insert_with(|| {
            let opk = msg
                .opk_used
                .and_then(|opk| self.opk.get_by_public_key(opk))
                .unwrap();

            let ek = msg.ek_used.unwrap_or([0u8; 32]);
            let session = receive_session_key(
                self.name.clone(),
                from.name.clone(),
                &self.ik,
                &self.spk,
                opk,
                from.ik,
                ek,
            );
            let rk = derive_root_key(&session.get_bytes());
            let dhs = RatchetKey::from_keys(self.spk.get_private(), self.spk.public);
            RatchetState::new(rk, dhs, None, false)
        });

        ratchet.decrypt(msg)
    }
}

impl Display for User {
    /// Prints a human-readable summary of the user's identity and session state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}\nname: {}\nik: {}\nspk: {}\nopk_count: {}\nsessions:\n{}\n",
            self.id,
            self.name,
            self.ik,
            self.spk,
            self.opk.len(),
            self.sessions
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}
