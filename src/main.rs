use signal_protocol_poc::{
    User,
    crypto_utils::hkdf::derive_root_key,
    double_ratchet::state::RatchetState,
    keys::{
        ephemeral_key::EphemeralKey,
        ratchet_key::RatchetKey,
    },
    x3dh::session::{create_session_key, receive_session_key},
};

fn main() {
    let alice = User::new("Alice".to_string());
    let mut bob = User::new("Bob".to_string());

    let ek_alice = EphemeralKey::new();
    let opk_bob = bob.opk.use_key().unwrap();
    let session_alice = create_session_key(
        alice.name.clone(),
        bob.name.clone(),
        &alice.ik,
        &ek_alice,
        &bob.spk,
        &bob.ik,
        Some(&opk_bob),
    );

    // 3️⃣ Bob reçoit la session (sans interaction réseau dans ce PoC)
    let session_bob = receive_session_key(
        bob.name.clone(),
        alice.name.clone(),
        &bob.ik,
        &bob.spk,
        &opk_bob,
        &alice.ik,
        &ek_alice,
    );

    // 4️⃣ Les deux côtés dérivent leur root key
    let root_key_alice = derive_root_key(&session_alice.bytes);
    let root_key_bob = derive_root_key(&session_bob.bytes);

    let ratchet_key_alice = RatchetKey::new();
    let ratchet_key_bob = RatchetKey::new();

    let mut alice = RatchetState::new(
        root_key_alice,
        ratchet_key_alice.clone(),
        Some(ratchet_key_bob.public.clone()),
        true,
    );
    let mut bob = RatchetState::new(
        root_key_bob,
        ratchet_key_bob,
        None,
        false,
    );
    let msg0 = alice.encrypt(
        "Bonjour Bob !",
        "Alice".into(),
        "Bob".into(),
    );
    let decrypted_msg0 = bob.decrypt(&msg0);
    println!("Message 0 déchiffré : {:?}", decrypted_msg0);

    let msg2 = bob.encrypt(
        "Tu as reçu mes messages ?",
        "Alice".into(),
        "Bob".into(),
    );
    let decrypted_msg2 = alice.decrypt(&msg2);
    println!("Message 2 déchiffré : {:?}", decrypted_msg2);
    let msg3 = bob.encrypt("Je l'espere en tout cas", "Bob".into(), "Alice".into());
    let decrypted_msg3 = alice.decrypt(&msg3);
    println!("Message 3 déchiffré : {:?}", decrypted_msg3);

}