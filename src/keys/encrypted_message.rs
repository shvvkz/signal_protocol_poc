use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Represents a ratcheted, AEAD-encrypted message exchanged between users.
///
/// This structure is designed to hold all necessary metadata for decryption
/// within a Double Ratchet or X3DH-based session.
///
/// # Fields
/// - `sender`: Sender's identity (used for display/logging).
/// - `receiver`: Receiver's identity (used for routing).
/// - `nonce`: A 12-byte nonce for AEAD encryption.
/// - `ciphertext`: The encrypted payload.
/// - `ratchet_pub`: Sender's public ratchet key used for DH ratchet.
/// - `message_index`: Index within the sender's message chain.
/// - `opk_used`: One-time pre-key (if any) used to establish the session.
/// - `ek_used`: Ephemeral key used during session negotiation (if applicable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender: String,
    pub receiver: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub ratchet_pub: [u8; 32], // DH public key used in ratchet step
    pub message_index: u32,    // Index in chain key (CKs.index)
    pub opk_used: Option<[u8; 32]>,
    pub ek_used: Option<[u8; 32]>,
}

impl Display for EncryptedMessage {
    /// Formats the `EncryptedMessage` for human-readable display.
    ///
    /// Shows sender/receiver, nonce, ciphertext, ratchet public key, and message index
    /// as hex-encoded values for clarity.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EncryptedMessage {{ sender: {}, receiver: {}, nonce: {}, ciphertext: {}, ratchet_pub: {}, message_index: {} }}",
            self.sender,
            self.receiver,
            hex::encode(self.nonce),
            hex::encode(&self.ciphertext),
            hex::encode(self.ratchet_pub),
            self.message_index
        )
    }
}
