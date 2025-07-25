use serde::{Deserialize, Serialize};

/// Represents a per-message encryption key in the Double Ratchet protocol.
///
/// This key is derived from a chain key using a KDF and used exactly once.
/// It includes a 32-byte symmetric key and its associated position (index) in the chain.
///
/// # Fields
/// - `key`: A 32-byte key for symmetric encryption (AES, ChaCha20, etc.).
/// - `index`: The position in the ratchet chain this key was derived from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageKey {
    key: [u8; 32], // For symmetric encryption with AES or ChaCha20
    index: u32,    // Position in the chain this key belongs to
}

impl MessageKey {
    /// Creates a new `MessageKey` with the given bytes and index.
    ///
    /// # Arguments
    /// - `key`: A 32-byte symmetric key.
    /// - `index`: The index within the chain key sequence.
    ///
    /// # Returns
    /// A new `MessageKey` instance.
    pub fn new(key: [u8; 32], index: u32) -> Self {
        MessageKey { key, index }
    }

    /// Returns a reference to the key bytes.
    ///
    /// # Returns
    /// A reference to the 32-byte symmetric key.
    pub fn get_key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Returns the index associated with this message key.
    ///
    /// # Returns
    /// A `u32` index value.
    pub fn get_index(&self) -> u32 {
        self.index
    }
}
