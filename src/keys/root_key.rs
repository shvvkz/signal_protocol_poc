use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Represents a 32-byte root key used in the Double Ratchet protocol.
///
/// The root key is a critical piece of state updated through HKDF during
/// ratchet steps. It should be kept secret and handled securely.
///
/// # Fields
/// - `bytes`: A fixed-size array `[u8; 32]` containing the raw key material.
///
/// # Serialization
/// This struct supports `Serialize` and `Deserialize` for transport or storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RootKey {
    bytes: [u8; 32],
}

impl RootKey {
    /// Creates a new `RootKey` from the given byte array.
    ///
    /// # Arguments
    /// - `bytes`: A 32-byte array used to initialize the root key.
    ///
    /// # Returns
    /// A new [`RootKey`] instance.
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns a reference to the underlying byte array of the root key.
    ///
    /// # Returns
    /// A reference to `[u8; 32]`.
    pub(crate) fn get_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Display for RootKey {
    /// Formats the root key as a hexadecimal string for display.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}
