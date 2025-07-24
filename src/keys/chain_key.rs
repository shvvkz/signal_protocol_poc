use crate::keys::message_key::MessageKey;
use hkdf::hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    pub(crate) fn derive_next(&self) -> (ChainKey, MessageKey) {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();

        // 🔑 Derive message key with constant
        hmac.update(b"msg_key");
        let result = hmac.finalize().into_bytes();
        let message_key = MessageKey::new(result.into(), self.index);

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

    pub(crate) fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    pub(crate) fn get_index(&self) -> u32 {
        self.index
    }
}
