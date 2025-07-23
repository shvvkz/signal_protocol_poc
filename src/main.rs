use signal_protocol_poc::{
    User,
    crypto_utils::hkdf::derive_root_key,
    double_ratchet::state::RatchetState,
    keys::{ephemeral_key::EphemeralKey, ratchet_key::RatchetKey},
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
        ratchet_key_alice,
        Some(ratchet_key_bob.public.clone()),
        true,
    );
    let mut bob = RatchetState::new(root_key_bob, ratchet_key_bob, None, false);

    let msg0 = alice.encrypt("Bonjour Bob !", "Alice".into(), "Bob".into());
    let decrypted_msg0 = bob.decrypt(&msg0);
    println!("Alice : {:?}", decrypted_msg0);

    let msg2 = bob.encrypt("Tu as reçu mes messages ?", "Alice".into(), "Bob".into());
    let decrypted_msg2 = alice.decrypt(&msg2);
    println!("Bob : {:?}", decrypted_msg2);

    let msg3 = bob.encrypt("Je l'espere en tout cas", "Bob".into(), "Alice".into());
    let decrypted_msg3 = alice.decrypt(&msg3);
    println!("Bob : {:?}", decrypted_msg3);

    let msg4 = alice.encrypt("Oui, tout est bon !", "Alice".into(), "Bob".into());
    let decrypted_msg4 = bob.decrypt(&msg4);
    println!("Alice : {:?}", decrypted_msg4);

    let msg5 = bob.encrypt("Super, on continue ?", "Bob".into(), "Alice".into());
    let decrypted_msg5 = alice.decrypt(&msg5);
    println!("Bob : {:?}", decrypted_msg5);

    let msg6 = alice.encrypt("Oui, allons-y !", "Alice".into(), "Bob".into());
    let decrypted_msg6 = bob.decrypt(&msg6);
    println!("Alice : {:?}", decrypted_msg6);

    let msg7 = bob.encrypt("Tu travailles sur quoi ?", "Bob".into(), "Alice".into());
    let decrypted_msg7 = alice.decrypt(&msg7);
    println!("Bob : {:?}", decrypted_msg7);

    let msg8 = alice.encrypt("Sur un protocole sécurisé.", "Alice".into(), "Bob".into());
    let decrypted_msg8 = bob.decrypt(&msg8);
    println!("Alice : {:?}", decrypted_msg8);

    let msg9 = bob.encrypt("Intéressant ! Tu m'expliques ?", "Bob".into(), "Alice".into());
    let decrypted_msg9 = alice.decrypt(&msg9);
    println!("Bob : {:?}", decrypted_msg9);

    let msg10 = alice.encrypt("Bien sûr, c'est basé sur Double Ratchet.", "Alice".into(), "Bob".into());
    let decrypted_msg10 = bob.decrypt(&msg10);
    println!("Alice : {:?}", decrypted_msg10);

    let msg11 = bob.encrypt("Ça a l'air complexe.", "Bob".into(), "Alice".into());
    let decrypted_msg11 = alice.decrypt(&msg11);
    println!("Bob : {:?}", decrypted_msg11);

    let msg12 = alice.encrypt("Un peu, mais c'est très sécurisé.", "Alice".into(), "Bob".into());
    let decrypted_msg12 = bob.decrypt(&msg12);
    println!("Alice : {:?}", decrypted_msg12);

    let msg13 = alice.encrypt("d'ailleurs on l'utilise en ce moment!", "Bob".into(), "Alice".into());
    let decrypted_msg13 = bob.decrypt(&msg13);
    println!("Alice : {:?}", decrypted_msg13);
}
