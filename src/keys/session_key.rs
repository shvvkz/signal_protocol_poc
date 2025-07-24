use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionKey {
    bytes: [u8; 32],
    pub sender: String,
    pub receiver: String,
}

impl SessionKey {
    pub(crate) fn new(bytes: [u8; 32], sender: String, receiver: String) -> Self {
        Self {
            bytes,
            sender,
            receiver,
        }
    }

    pub(crate) fn get_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}
