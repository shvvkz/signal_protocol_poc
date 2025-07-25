use serde::{Deserialize, Serialize};

/// Represents a symmetric session key exchanged between two parties.
///
/// # Fields
/// - `bytes`: A 32-byte fixed-length array that holds the raw session key material.
/// - `sender`: The identifier (e.g., username, node ID) of the entity who initiated the session.
/// - `receiver`: The identifier of the intended recipient of the session.
///
/// # Serialization
/// This struct implements `Serialize` and `Deserialize` from Serde, making it suitable for
/// encoding as JSON, binary formats, or network protocols.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionKey {
    bytes: [u8; 32],
    pub sender: String,
    pub receiver: String,
}

impl SessionKey {
    /// Creates a new `SessionKey` instance from raw key material and endpoint identifiers.
    ///
    /// # Arguments
    /// - `bytes`: A `[u8; 32]` array representing the session key.
    /// - `sender`: The identity of the key originator.
    /// - `receiver`: The identity of the key recipient.
    ///
    /// # Returns
    /// A `SessionKey` instance with the provided data.
    pub(crate) fn new(bytes: [u8; 32], sender: String, receiver: String) -> Self {
        Self {
            bytes,
            sender,
            receiver,
        }
    }

    /// Returns a reference to the raw 32-byte key material.
    ///
    /// # Returns
    /// A reference to `[u8; 32]` containing the session key.
    pub(crate) fn get_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}
