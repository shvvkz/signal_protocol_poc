use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    pub bytes: [u8; 32],
    pub sender: String,
    pub receiver: String,
}
