use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::RngCore;

/// Retourne `(ciphertext, nonce)`
pub fn encrypt_chacha20(key_bytes: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("encryption failure!");

    (ciphertext, nonce_bytes)
}

/// Déchiffre le message à partir de la clé de 32 octets et du nonce de 12 octets.
/// Retourne le texte clair si tout est valide, sinon retourne une erreur.
pub fn decrypt_chacha20(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
}
