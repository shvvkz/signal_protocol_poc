use signal_protocol_poc::{
    crypto_utils::hkdf::{derive_root_key},
    double_ratchet::state::RatchetState,
    keys::{ephemeral_key::EphemeralKey, ratchet_key::RatchetKey},
    user::User,
    x3dh::session::{create_session_key, receive_session_key},
};

fn main() {
    // 1️⃣ Création des utilisateurs
    let alice = User::new("Alice".to_string());
    let mut bob = User::new("Bob".to_string());

    println!("🔐 Utilisateurs créés.\nAlice:\n{}\n\nBob:\n{}\n", alice, bob);

    // 2️⃣ Alice génère EK + crée la session
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
    println!("Root key: alice::{} = bob::{} ", root_key_alice, root_key_bob);

    // 5️⃣ Initialisation Double Ratchet
    let mut ratchet_alice = RatchetState::new(root_key_alice, RatchetKey::new(), bob.spk.public, true);
    let mut ratchet_bob = RatchetState::new(root_key_bob, RatchetKey::new(), alice.spk.public, false);

    println!("🔄 Double Ratchet initialisé.\n");

    // 💬 1er message : Alice → Bob
    let alice_pub = ratchet_alice.dhs.public;
    let msg1 = ratchet_alice.encrypt("Salut Bob, c’est Alice !", &alice_pub, "Alice".into(), "Bob".into());
    println!("📤 Alice envoie");
    let clear1 = ratchet_bob.decrypt(&msg1, &msg1.ratchet_pub);
    println!("📥 Bob reçoit : {:?}", clear1);

    // 💬 2e message : Bob → Alice
    let bob_pub = ratchet_bob.dhs.public;
    let msg2 = ratchet_bob.encrypt("Salut Alice, bien reçu !", &bob_pub, "Bob".into(), "Alice".into());
    let clear2 = ratchet_alice.decrypt(&msg2, &msg2.ratchet_pub);
    println!("📥 Alice reçoit : {:?}", clear2);

    // 💬 3e message : Alice → Bob (nouvelle rotation DH)
    let alice_pub_2 = ratchet_alice.dhs.public;
    let msg3 = ratchet_alice.encrypt("On peut maintenant discuter en toute sécurité 🔐", &alice_pub_2, "Alice".into(), "Bob".into());
    let clear3 = ratchet_bob.decrypt(&msg3, &msg3.ratchet_pub);
    println!("📥 Bob reçoit : {:?}", clear3);
}
