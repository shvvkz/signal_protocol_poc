use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use rand_core::RngCore;

/// Encrypts a message using ChaCha20-Poly1305 with a random nonce.
///
/// # Parameters
/// - `key_bytes`: A 32-byte symmetric encryption key.
/// - `plaintext`: The message to encrypt.
///
/// # Returns
/// A tuple `(ciphertext, nonce)`:
/// - `ciphertext`: The encrypted and authenticated output.
/// - `nonce`: The randomly generated 12-byte nonce used for encryption.
///
/// # Panics
/// Panics if encryption fails (should never occur with valid input sizes).
pub(crate) fn encrypt_chacha20(key_bytes: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    (ciphertext, nonce_bytes)
}

/// Decrypts a ciphertext using ChaCha20-Poly1305.
///
/// # Parameters
/// - `key_bytes`: A 32-byte symmetric encryption key.
/// - `nonce_bytes`: The 12-byte nonce used during encryption.
/// - `ciphertext`: The encrypted and authenticated message.
///
/// # Returns
/// - `Ok(plaintext)` if decryption and authentication succeed.
/// - `Err(_)` if decryption fails (e.g., incorrect key, nonce, or tampered ciphertext).
pub(crate) fn decrypt_chacha20(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
}
