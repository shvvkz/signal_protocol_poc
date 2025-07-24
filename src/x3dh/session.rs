use crate::keys::{identity::IdentityKey, signed_prekey::SignedPreKey, one_time_prekey::OneTimePreKey, ephemeral_key::EphemeralKey, session_key::SessionKey};
use crate::crypto_utils::{dh::diffie_hellman, hkdf::derive_session_key};

pub fn create_session_key(
    sender_name: String,
    receiver_name: String,
    ik_initiator: &IdentityKey,
    ek_initiator: &EphemeralKey,
    spk_receiver: &SignedPreKey,
    ik_receiver: &IdentityKey,
    opk_receiver: Option<&OneTimePreKey>,
) -> SessionKey {
    let dh1 = diffie_hellman(&ik_initiator.private(), &spk_receiver.public); // IK_A <-> SPK_B
    let dh2 = diffie_hellman(&ek_initiator.private(), &ik_receiver.dh_public);  // EK_A <-> IK_B
    let dh3 = diffie_hellman(&ek_initiator.private(), &spk_receiver.public);    // EK_A <-> SPK_B

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk) = opk_receiver {
        let dh4 = diffie_hellman(&ek_initiator.private(), &opk.public);         // EK_A <-> OPK_B
        ikm.extend_from_slice(&dh4);
    }

    let sk_bytes = derive_session_key(&ikm);

    SessionKey {
        bytes: sk_bytes,
        sender: sender_name,
        receiver: receiver_name,
    }
}

pub fn receive_session_key(
    receiver_name: String,
    sender_name: String,
    receiver_ik: &IdentityKey,
    receiver_spk: &SignedPreKey,
    receiver_opk_private: [u8; 32],
    sender_ik: &IdentityKey,
    sender_ek_public: [u8; 32],
) -> SessionKey {
    // Même ordre que Alice : DH1, DH2, DH3, DH4
    let dh1 = diffie_hellman(&receiver_spk.private(), &sender_ik.dh_public);
    let dh2 = diffie_hellman(&receiver_ik.private(), &sender_ek_public);
    let dh3 = diffie_hellman(&receiver_spk.private(), &sender_ek_public);
    let dh4 = diffie_hellman(&receiver_opk_private, &sender_ek_public);

    let ikm = [dh1, dh2, dh3, dh4].concat();
    let sk_bytes = derive_session_key(&ikm);

    SessionKey {
        bytes: sk_bytes,
        sender: sender_name,
        receiver: receiver_name,
    }
}