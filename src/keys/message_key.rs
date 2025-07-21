use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageKey {
    pub key: [u8; 32], // Pour chiffrer avec AES ou ChaCha20
    pub index: u32,    // Indice associé à la CK utilisée
}
