use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RootKey {
    bytes: [u8; 32],
}

impl RootKey {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub(crate) fn get_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Display for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}
