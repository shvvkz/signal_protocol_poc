use crate::crypto_utils::{dh::diffie_hellman, hkdf::derive_session_key};
use crate::keys::one_time_prekey::OneTimePreKey;
use crate::keys::{
    ephemeral_key::EphemeralKey, identity::IdentityKey, one_time_prekey::OneTimePreKeyPublic,
    session_key::SessionKey, signed_prekey::SignedPreKey,
};

/// Creates a new session key for the initiator (sender) in the X3DH protocol.
///
/// Performs the required Diffie-Hellman (DH) operations between the initiator's identity
/// and ephemeral keys and the receiver's signed prekey, identity key, and optionally,
/// one-time prekey. These shared secrets are combined and passed through HKDF to derive the session key.
///
/// # Parameters:
/// - `sender_name`: Name or ID of the sender (initiator).
/// - `receiver_name`: Name or ID of the receiver.
/// - `ik_initiator`: Initiator's identity key.
/// - `ek_initiator`: Initiator's ephemeral key.
/// - `spk_receiver`: Receiver's signed pre-key (public).
/// - `ik_receiver`: Receiver's identity key (public).
/// - `opk_receiver`: Optional one-time pre-key (public).
///
/// # Returns
/// A [`SessionKey`] object containing the derived shared secret and participant metadata.
///
/// # X3DH DH Computations:
/// - DH1: IK_initiator <-> SPK_receiver
/// - DH2: EK_initiator <-> IK_receiver
/// - DH3: EK_initiator <-> SPK_receiver
/// - DH4: EK_initiator <-> OPK_receiver (if present)
///
/// # Panics
/// May panic if any cryptographic primitive fails unexpectedly.
pub(crate) fn create_session_key(
    sender_name: String,
    receiver_name: String,
    ik_initiator: &IdentityKey,
    ek_initiator: &EphemeralKey,
    spk_receiver: [u8; 32],
    ik_receiver: [u8; 32],
    opk_receiver: Option<&OneTimePreKeyPublic>,
) -> SessionKey {
    let dh1 = diffie_hellman(&ik_initiator.get_private(), &spk_receiver);
    let dh2 = diffie_hellman(&ek_initiator.get_private(), &ik_receiver);
    let dh3 = diffie_hellman(&ek_initiator.get_private(), &spk_receiver);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk) = opk_receiver {
        let dh4 = diffie_hellman(&ek_initiator.get_private(), &opk.public);
        ikm.extend_from_slice(&dh4);
    }

    let sk_bytes = derive_session_key(&ikm);

    SessionKey::new(sk_bytes, sender_name, receiver_name)
}

/// Derives a session key for the receiver (responder) in the X3DH protocol.
///
/// Performs the required Diffie-Hellman (DH) operations using the receiver’s identity,
/// signed pre-key, and one-time pre-key, in combination with the sender’s identity
/// and ephemeral public keys. The output is a shared `SessionKey` derived via HKDF.
///
/// # Parameters:
/// - `receiver_name`: Receiver's ID or name.
/// - `sender_name`: Sender's ID or name.
/// - `receiver_ik`: Receiver’s identity key (private).
/// - `receiver_spk`: Receiver’s signed pre-key (private).
/// - `receiver_opk`: Receiver’s one-time pre-key (private).
/// - `sender_ik_public`: Sender's identity key (public).
/// - `sender_ek_public`: Sender's ephemeral key (public).
///
/// # Returns
/// A [`SessionKey`] derived from the DH shared secrets.
///
/// # X3DH DH Computations:
/// - DH1: SPK_receiver <-> IK_sender
/// - DH2: IK_receiver <-> EK_sender
/// - DH3: SPK_receiver <-> EK_sender
/// - DH4: OPK_receiver <-> EK_sender
///
/// # Panics
/// May panic if any of the internal cryptographic functions fail unexpectedly.
pub(crate) fn receive_session_key(
    receiver_name: String,
    sender_name: String,
    receiver_ik: &IdentityKey,
    receiver_spk: &SignedPreKey,
    receiver_opk: OneTimePreKey,
    sender_ik_public: [u8; 32],
    sender_ek_public: [u8; 32],
) -> SessionKey {
    let dh1 = diffie_hellman(&receiver_spk.get_private(), &sender_ik_public);
    let dh2 = diffie_hellman(&receiver_ik.get_private(), &sender_ek_public);
    let dh3 = diffie_hellman(&receiver_spk.get_private(), &sender_ek_public);
    let dh4 = diffie_hellman(&receiver_opk.get_private(), &sender_ek_public);

    let ikm = [dh1, dh2, dh3, dh4].concat();
    let sk_bytes = derive_session_key(&ikm);

    SessionKey::new(sk_bytes, sender_name, receiver_name)
}
