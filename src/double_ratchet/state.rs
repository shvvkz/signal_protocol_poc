use std::fmt::Display;

use hkdf::Hkdf;
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

#[derive(Debug, Clone)]
pub struct RatchetState {
    pub root_key: RootKey,
    pub sending_chain: ChainKey,
    pub receiving_chain: ChainKey,
    pub dhs: RatchetKey,
    pub dhr: [u8; 32],
}

impl RatchetState {
    pub fn new(root_key: RootKey, dhs: RatchetKey, dhr: [u8; 32], is_initiator: bool) -> Self {
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
        }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &str,
        their_dh_public: &[u8; 32],
        sender: String,
        receiver: String,
    ) -> EncryptedMessage {
        // 🔁 Forcer la rotation DH à chaque message
        self.dhr = *their_dh_public;
        self.dhs = RatchetKey::new(); // nouvelle paire locale

        let dh_output = diffie_hellman(&self.dhs.private, &self.dhr);

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

        println!(
            "🔗 [encrypt] Nouvelle sending_chain: {}",
            hex::encode(ck_send)
        );

        let (next_ck, message_key) = self.sending_chain.derive_next();
        let index = self.sending_chain.index;
        self.sending_chain = next_ck;
        println!("🔐 Alice message_key: {}", hex::encode(&message_key.key));

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

    pub fn decrypt(
        &mut self,
        msg: &EncryptedMessage,
        their_dh_public: &[u8; 32],
    ) -> Option<String> {
        if self.dhr != *their_dh_public {
            self.dhr = *their_dh_public;

            let dh_output = diffie_hellman(&self.dhs.private, &msg.ratchet_pub);
            println!("[decrypt] DH output: {}", hex::encode(dh_output));

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
            let (next_ck, message_key) = self.receiving_chain.derive_next();
            self.receiving_chain = next_ck;

            println!(
                "🔗 [decrypt] Nouvelle receiving_chain: {}",
                hex::encode(ck_recv)
            );
            println!("🔐 Bob message_key: {}", hex::encode(&message_key.key));
            match decrypt_chacha20(&message_key.key, &msg.nonce, &msg.ciphertext) {
                Ok(plaintext_bytes) => {
                    let text = String::from_utf8(plaintext_bytes).ok();
                    return text;
                }
                Err(_) => {
                    println!("❌ Échec de déchiffrement après rotation DH");
                    return None;
                }
            }
        }

        while self.receiving_chain.index < msg.message_index {
            let (next_ck, _) = self.receiving_chain.derive_next();
            println!(
                "⏭️ [decrypt] Skip index {} (non stocké)",
                self.receiving_chain.index
            );
            self.receiving_chain = next_ck;
        }

        let (next_ck, message_key) = self.receiving_chain.derive_next();
        self.receiving_chain = next_ck;

        match decrypt_chacha20(&message_key.key, &msg.nonce, &msg.ciphertext) {
            Ok(plaintext_bytes) => {
                let text = String::from_utf8(plaintext_bytes).ok();
                println!("📥 Message déchiffré: {:?}", text);
                text
            }
            Err(_) => {
                println!("❌ Échec de déchiffrement");
                None
            }
        }
    }
}

impl Display for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "root_key: {}\nsending_chain: {:?}\nreceiving_chain: {:?}\ndhs.pub: {}\ndhs.priv: {}\ndhr: {}",
            self.root_key,
            self.sending_chain,
            self.receiving_chain,
            hex::encode(self.dhs.public),
            hex::encode(self.dhs.private),
            hex::encode(self.dhr)
        )
    }
}
