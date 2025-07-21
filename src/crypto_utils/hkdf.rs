use hkdf::Hkdf;
use sha2::Sha256;

use crate::keys::chain_key::ChainKey;
use crate::keys::root_key::RootKey;

pub fn derive_session_key(dh_results: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, dh_results);
    let mut okm = [0u8; 32];
    hk.expand(b"x3dh-session", &mut okm).expect("HKDF expand failed");
    okm
}

pub fn derive_root_key(session_key: &[u8; 32]) -> RootKey {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut rk = [0u8; 32];
    hk.expand(b"double-ratchet-root", &mut rk).expect("HKDF expand failed");
    RootKey { bytes: rk }
}

pub fn derive_initial_chain_keys(root_key: &RootKey) -> (ChainKey, ChainKey) {
    let hk = Hkdf::<Sha256>::new(None, &root_key.bytes);

    let mut cks_bytes = [0u8; 32];
    let mut ckr_bytes = [0u8; 32];

    hk.expand(b"ratchet-ck-send", &mut cks_bytes).unwrap();
    hk.expand(b"ratchet-ck-recv", &mut ckr_bytes).unwrap();

    (
        ChainKey { key: cks_bytes, index: 0 },
        ChainKey { key: ckr_bytes, index: 0 },
    )
}