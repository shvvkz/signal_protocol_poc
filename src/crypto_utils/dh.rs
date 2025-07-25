use x25519_dalek::{PublicKey, StaticSecret};

/// Computes a shared secret using X25519 Diffie-Hellman key exchange.
///
/// This function performs a scalar multiplication between the caller’s private key
/// and the peer’s public key. The result is a 32-byte shared secret used as input to a KDF.
///
/// # Parameters
/// - `private`: The caller's X25519 private scalar (`[u8; 32]`)
/// - `public`: The peer's X25519 public key (`[u8; 32]`)
///
/// # Returns
/// A 32-byte shared secret (`[u8; 32]`)
///
/// # Security
/// - The returned secret should not be used directly; pass it through HKDF or a KDF chain.
/// - Inputs should be validated upstream to avoid trivial keys.
///
/// # Panics
/// This function does not panic.
pub(crate) fn diffie_hellman(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*private);
    let pk = PublicKey::from(*public);
    let shared = sk.diffie_hellman(&pk);
    *shared.as_bytes()
}
