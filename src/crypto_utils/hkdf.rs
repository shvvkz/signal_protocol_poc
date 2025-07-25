use hkdf::Hkdf;
use sha2::Sha256;

use crate::keys::chain_key::ChainKey;
use crate::keys::root_key::RootKey;

/// Derives a 32-byte session key from concatenated DH results (X3DH phase).
///
/// # Parameters
/// - `dh_results`: Concatenated byte slices of shared secrets (DH1 || DH2 || DH3 ...).
///
/// # Returns
/// A 32-byte symmetric key suitable for initializing a Double Ratchet session.
///
/// # Panics
/// Panics if HKDF expansion fails (should not happen with 32-byte output).
pub(crate) fn derive_session_key(dh_results: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, dh_results);
    let mut okm = [0u8; 32];
    hk.expand(b"x3dh-session", &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// Derives a new root key from a session key using HKDF.
///
/// This is the first step in initializing or updating the root key in a Double Ratchet state.
///
/// # Parameters
/// - `session_key`: A 32-byte symmetric key produced from X3DH.
///
/// # Returns
/// A new [`RootKey`] derived using HKDF-SHA256.
///
/// # Panics
/// Panics if HKDF expansion fails.
pub(crate) fn derive_root_key(session_key: &[u8; 32]) -> RootKey {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut rk = [0u8; 32];
    hk.expand(b"double-ratchet-root", &mut rk)
        .expect("HKDF expand failed");
    RootKey::new(rk)
}

/// Derives initial send and receive chain keys from a root key.
///
/// Used when a new Double Ratchet session is initialized after X3DH completes.
///
/// # Parameters
/// - `root_key`: The shared [`RootKey`] to branch from.
///
/// # Returns
/// A tuple of `(sending_chain_key, receiving_chain_key)` as [`ChainKey`]s, both initialized at index 0.
///
/// # Panics
/// Panics if HKDF expansion fails.
pub(crate) fn derive_initial_chain_keys(root_key: &RootKey) -> (ChainKey, ChainKey) {
    let hk = Hkdf::<Sha256>::new(None, root_key.get_bytes());

    let mut cks_bytes = [0u8; 32];
    let mut ckr_bytes = [0u8; 32];

    hk.expand(b"ratchet-ck-send", &mut cks_bytes).unwrap();
    hk.expand(b"ratchet-ck-recv", &mut ckr_bytes).unwrap();

    (ChainKey::new(cks_bytes, 0), ChainKey::new(ckr_bytes, 0))
}
