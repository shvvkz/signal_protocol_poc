use std::{collections::HashMap, fmt::Display};

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    crypto_utils::{
        dh::diffie_hellman,
        encryption::{decrypt_chacha20, encrypt_chacha20},
    },
    keys::{
        chain_key::ChainKey, encrypted_message::EncryptedMessage, message_key::MessageKey,
        ratchet_key::RatchetKey, root_key::RootKey,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RatchetState {
    root_key: RootKey,
    sending_chain: ChainKey,
    receiving_chain: ChainKey,
    dhs: RatchetKey,
    dhr: Option<[u8; 32]>,
    last_dhr: Option<[u8; 32]>,
    skipped_message_keys: HashMap<(Vec<u8>, u32), MessageKey>,
}

impl RatchetState {
    pub(crate) fn new(
        root_key: RootKey,
        dhs: RatchetKey,
        dhr: Option<[u8; 32]>,
        is_initiator: bool,
    ) -> Self {
        let (sending_chain, receiving_chain) = if is_initiator {
            crate::crypto_utils::hkdf::derive_initial_chain_keys(&root_key)
        } else {
            let (recv, send) = crate::crypto_utils::hkdf::derive_initial_chain_keys(&root_key);
            (send, recv)
        };
        Self {
            root_key,
            sending_chain,
            receiving_chain,
            dhs,
            dhr,
            last_dhr: None,
            skipped_message_keys: HashMap::new(),
        }
    }

    pub(crate) fn encrypt(
        &mut self,
        plaintext: &str,
        sender: String,
        receiver: String,
        opk_used: Option<[u8; 32]>,
        ek_used: Option<[u8; 32]>,
    ) -> EncryptedMessage {
        let should_ratchet = self.last_dhr.map_or(true, |prev| {
            self.dhr.map_or(true, |current| current != prev)
        });

        if should_ratchet {
            self.last_dhr = self.dhr;

            self.dhs = RatchetKey::new();

            let dh_output = diffie_hellman(&self.dhs.get_private(), self.dhr.as_ref().unwrap());

            let root_hkdf = Hkdf::<Sha256>::new(Some(self.root_key.get_bytes()), &dh_output);

            let mut rk = [0u8; 32];
            let mut ck_send = [0u8; 32];
            root_hkdf.expand(b"double-ratchet-rk", &mut rk).unwrap();
            root_hkdf.expand(b"ratchet-ck-send", &mut ck_send).unwrap();

            self.root_key = RootKey::new(rk);
            self.sending_chain = ChainKey::new(ck_send, 0);
        }

        let (next_ck, message_key) = self.sending_chain.derive_next();
        self.sending_chain = next_ck;

        let (ciphertext, nonce) = encrypt_chacha20(&message_key.get_key(), plaintext.as_bytes());

        EncryptedMessage {
            sender,
            receiver,
            ratchet_pub: self.dhs.public,
            message_index: message_key.get_index(),
            nonce,
            ciphertext: ciphertext.to_vec(),
            opk_used,
            ek_used,
        }
    }

    pub(crate) fn decrypt(&mut self, msg: &EncryptedMessage) -> Option<String> {
        let key_id = (msg.ratchet_pub.to_vec(), msg.message_index);

        // 1️⃣ Check for skipped messages
        if let Some(message_key) = self.skipped_message_keys.remove(&key_id) {
            return decrypt_chacha20(&message_key.get_key(), &msg.nonce, &msg.ciphertext)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok());
        }

        // 2️⃣ DH ratchet if needed
        let is_new_dhr = self.dhr.map_or(true, |prev| prev != msg.ratchet_pub);

        if is_new_dhr {
            self.dhr = Some(msg.ratchet_pub);

            let dh_output = diffie_hellman(&self.dhs.get_private(), &msg.ratchet_pub);

            let root_hkdf = Hkdf::<Sha256>::new(Some(self.root_key.get_bytes()), &dh_output);

            let mut rk = [0u8; 32];
            let mut ck_recv = [0u8; 32];
            root_hkdf.expand(b"double-ratchet-rk", &mut rk).unwrap();
            root_hkdf.expand(b"ratchet-ck-send", &mut ck_recv).unwrap();

            self.root_key = RootKey::new(rk);
            self.receiving_chain = ChainKey::new(ck_recv, 0);
        }

        // 3️⃣ Advance receiving chain to message index
        while self.receiving_chain.get_index() < msg.message_index {
            let (next_ck, skipped_key) = self.receiving_chain.derive_next();
            let key = (msg.ratchet_pub.to_vec(), self.receiving_chain.get_index());
            self.skipped_message_keys.insert(key, skipped_key);
            self.receiving_chain = next_ck;
        }

        // 4️⃣ Decrypt the message
        let (next_ck, message_key) = self.receiving_chain.derive_next();
        self.receiving_chain = next_ck;

        decrypt_chacha20(&message_key.get_key(), &msg.nonce, &msg.ciphertext)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }
}

impl Display for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "root_key: {}\nsending_chain: {:?}\nreceiving_chain: {:?}\ndhs.pub: {}\ndhs.priv: {}\ndhr: {}\nlast_dhr: {}\nskipped_message_keys: {}",
            self.root_key,
            self.sending_chain,
            self.receiving_chain,
            hex::encode(self.dhs.public),
            hex::encode(self.dhs.get_private()),
            match &self.dhr {
                Some(dhr_bytes) => hex::encode(dhr_bytes),
                None => String::from("None"),
            },
            match &self.last_dhr {
                Some(last_dhs_bytes) => hex::encode(last_dhs_bytes),
                None => String::from("None"),
            },
            {
                let mut skipped = String::new();
                for ((ratchet_pub, idx), msg_key) in &self.skipped_message_keys {
                    skipped.push_str(&format!(
                        "\n  pub: {}, idx: {}, key: {}",
                        hex::encode(ratchet_pub),
                        idx,
                        hex::encode(&msg_key.get_key())
                    ));
                }
                skipped
            }
        )
    }
}
