use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageKey {
    key: [u8; 32], // Pour chiffrer avec AES ou ChaCha20
    index: u32,    // Indice associé à la CK utilisée
}

impl MessageKey {
    pub fn new(key: [u8; 32], index: u32) -> Self {
        MessageKey { key, index }
    }

    pub fn get_key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn get_index(&self) -> u32 {
        self.index
    }
}