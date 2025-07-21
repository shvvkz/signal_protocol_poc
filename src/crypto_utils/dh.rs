use x25519_dalek::{StaticSecret, PublicKey};

pub fn diffie_hellman(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*private);
    let pk = PublicKey::from(*public);
    let shared = sk.diffie_hellman(&pk);
    *shared.as_bytes()
}
