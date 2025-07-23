use std::fmt::Display;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    crypto_utils::{
        dh::diffie_hellman,
        encryption::{decrypt_chacha20, encrypt_chacha20},
    },
    keys::{
        chain_key::ChainKey, encrypted_message::EncryptedMessage, ratchet_key::RatchetKey,
        root_key::RootKey,
    },
};

#[derive(Debug, Clone)]
pub struct RatchetState {
    pub root_key: RootKey,
    pub sending_chain: ChainKey,
    pub receiving_chain: ChainKey,
    pub dhs: RatchetKey,
    pub dhr: Option<[u8; 32]>,
    pub last_dhs_private_used: Option<[u8; 32]>,
}

impl RatchetState {
    pub fn new(
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
            last_dhs_private_used: None,
        }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &str,
        sender: String,
        receiver: String,
    ) -> EncryptedMessage {
        let dh_output = diffie_hellman(&self.dhs.private, self.dhr.as_ref().unwrap());

        let root_hkdf = Hkdf::<Sha256>::new(Some(&self.root_key.bytes), &dh_output);

        let mut rk = [0u8; 32];
        let mut ck_send = [0u8; 32];
        root_hkdf.expand(b"double-ratchet-rk", &mut rk).unwrap();
        root_hkdf.expand(b"ratchet-ck-send", &mut ck_send).unwrap();

        self.root_key = RootKey { bytes: rk };
        self.sending_chain = ChainKey {
            key: ck_send,
            index: 0,
        };

        let (next_ck, message_key) = self.sending_chain.derive_next();
        let index = self.sending_chain.index;
        self.sending_chain = next_ck;

        let (ciphertext, nonce) = encrypt_chacha20(&message_key.key, plaintext.as_bytes());

        EncryptedMessage {
            sender,
            receiver,
            ratchet_pub: self.dhs.public,
            message_index: index,
            nonce,
            ciphertext: ciphertext.to_vec(),
        }
    }

    pub fn decrypt(&mut self, msg: &EncryptedMessage) -> Option<String> {
        let is_new_dhr = self.dhr.map_or(true, |prev| prev != msg.ratchet_pub);

        if is_new_dhr {
            // 🔄 On va effectuer un DH ratchet réception
            self.dhr = Some(msg.ratchet_pub);
            self.last_dhs_private_used = Some(self.dhs.private); // On garde celle qu’on vient d’utiliser
            self.dhs = RatchetKey::new(); // Nouvelle paire locale

            // 🔐 On utilise l’ancienne clé privée si elle existe
            let dh_private = self.last_dhs_private_used.unwrap_or(self.dhs.private);

            let dh_output = diffie_hellman(&dh_private, &msg.ratchet_pub);

            let root_hkdf = Hkdf::<Sha256>::new(Some(&self.root_key.bytes), &dh_output);

            let mut rk = [0u8; 32];
            let mut ck_recv = [0u8; 32];
            root_hkdf.expand(b"double-ratchet-rk", &mut rk).unwrap();
            root_hkdf.expand(b"ratchet-ck-send", &mut ck_recv).unwrap();

            self.root_key = RootKey { bytes: rk };
            self.receiving_chain = ChainKey {
                key: ck_recv,
                index: msg.message_index,
            };

            // 🧠 On prépare le prochain DH ratchet envoi

            let (next_ck, message_key) = self.receiving_chain.derive_next();
            self.receiving_chain = next_ck;

            match decrypt_chacha20(&message_key.key, &msg.nonce, &msg.ciphertext) {
                Ok(plaintext_bytes) => String::from_utf8(plaintext_bytes).ok(),
                Err(_) => {
                    println!("❌ Échec de déchiffrement après ratchet");
                    None
                }
            }
        } else {
            // 📦 Message avec même ratchet_pub, juste avance dans la chaîne symétrique
            let dh_private = self.last_dhs_private_used.unwrap_or(self.dhs.private);

            let dh_output = diffie_hellman(&dh_private, &msg.ratchet_pub);

            let root_hkdf = Hkdf::<Sha256>::new(Some(&self.root_key.bytes), &dh_output);

            let mut rk = [0u8; 32];
            let mut ck_recv = [0u8; 32];
            root_hkdf.expand(b"double-ratchet-rk", &mut rk).unwrap();
            root_hkdf.expand(b"ratchet-ck-send", &mut ck_recv).unwrap();

            self.root_key = RootKey { bytes: rk };
            self.receiving_chain = ChainKey {
                key: ck_recv,
                index: msg.message_index,
            };
            while self.receiving_chain.index < msg.message_index {
                let (next_ck, _) = self.receiving_chain.derive_next();
                self.receiving_chain = next_ck;
            }

            let (next_ck, message_key) = self.receiving_chain.derive_next();
            self.receiving_chain = next_ck;

            match decrypt_chacha20(&message_key.key, &msg.nonce, &msg.ciphertext) {
                Ok(plaintext_bytes) => String::from_utf8(plaintext_bytes).ok(),
                Err(_) => {
                    println!("❌ Échec de déchiffrement (pas de ratchet)");
                    None
                }
            }
        }
    }
}

impl Display for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "root_key: {}\nsending_chain: {:?}\nreceiving_chain: {:?}\ndhs.pub: {}\ndhs.priv: {}\ndhr: {}\nlast_dhs_private_used: {}",
            self.root_key,
            self.sending_chain,
            self.receiving_chain,
            hex::encode(self.dhs.public),
            hex::encode(self.dhs.private),
            match &self.dhr {
                Some(dhr_bytes) => hex::encode(dhr_bytes),
                None => String::from("None"),
            },
            match &self.last_dhs_private_used {
                Some(last_dhs_bytes) => hex::encode(last_dhs_bytes),
                None => String::from("None"),
            }
        )
    }
}
