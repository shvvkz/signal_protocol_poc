use crate::keys::message_key::MessageKey;
use hkdf::hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Represents a Chain Key in the Double Ratchet protocol.
///
/// The chain key is used to deterministically derive per-message [`MessageKey`]s
/// and to advance to the next chain key. It is based on HMAC-SHA256 derivation
/// and guarantees forward secrecy.
///
/// # Fields
/// - `key`: 32-byte HMAC input key.
/// - `index`: The message index in the current sending or receiving chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    /// Derives the next `ChainKey` and a corresponding `MessageKey`.
    ///
    /// - `MessageKey` is derived using HMAC(chain_key, "msg_key")
    /// - `ChainKey` is updated using HMAC(chain_key, "ck") and index += 1
    ///
    /// # Returns
    /// A tuple `(next_chain_key, message_key)`
    pub(crate) fn derive_next(&self) -> (ChainKey, MessageKey) {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();

        // 🔑 Derive message key with fixed context string
        hmac.update(b"msg_key");
        let result = hmac.finalize().into_bytes();
        let message_key = MessageKey::new(result.into(), self.index);

        // 🔁 Derive next chain key using different fixed context string
        let mut hmac_ck = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        hmac_ck.update(b"ck");
        let next_ck = hmac_ck.finalize().into_bytes();

        let next_chain_key = ChainKey {
            key: next_ck.into(),
            index: self.index + 1,
        };

        (next_chain_key, message_key)
    }

    /// Creates a new `ChainKey` from a given key and index.
    ///
    /// # Arguments
    /// - `key`: Initial 32-byte key (from root key or previous chain step).
    /// - `index`: Initial message index.
    ///
    /// # Returns
    /// A new `ChainKey`.
    pub(crate) fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    /// Returns the current message index.
    ///
    /// # Returns
    /// A `u32` representing the number of derivations from this chain.
    pub(crate) fn get_index(&self) -> u32 {
        self.index
    }
}
