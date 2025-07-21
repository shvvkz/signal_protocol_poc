use std::fmt::Display;

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender: String,
    pub receiver: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub ratchet_pub: [u8; 32], // DH public key utilisée
    pub message_index: u32,    // Index du message dans la chaîne (CKs.index)
}

impl Display for EncryptedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EncryptedMessage {{ sender: {}, receiver: {}, nonce: {}, ciphertext: {}, ratchet_pub: {}, message_index: {} }}",
            self.sender,
            self.receiver,
            hex::encode(self.nonce),
            hex::encode(self.ciphertext.clone()),
            hex::encode(self.ratchet_pub),
            self.message_index
        )
    }
}