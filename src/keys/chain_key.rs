use crate::keys::message_key::MessageKey;
use hkdf::{hmac::{Hmac, Mac}};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainKey {
    pub key: [u8; 32],
    pub index: u32,
}

impl ChainKey {
    pub fn derive_next(&self) -> (ChainKey, MessageKey) {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();

        // 🔑 Derive message key with constant
        hmac.update(b"msg_key");
        let result = hmac.finalize().into_bytes();
        let message_key = MessageKey { key: result.into(), index: self.index };

        // 🔁 Derive next chain key
        let mut hmac_ck = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        hmac_ck.update(b"ck");
        let next_ck = hmac_ck.finalize().into_bytes();

        let next_chain_key = ChainKey {
            key: next_ck.into(),
            index: self.index + 1,
        };

        (next_chain_key, message_key)
    }
}

