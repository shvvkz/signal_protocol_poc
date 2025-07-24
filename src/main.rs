use signal_protocol_poc::user::User;

fn main() {
    let mut alice = User::new("Alice".to_string());
    let mut bob = User::new("Bob".to_string());
    let mut charlie = User::new("Charlie".to_string());

    println!("🔐 Utilisateurs créés !");
    println!("Alice: {}\n", alice);
    println!("Bob: {}\n", bob);
    println!("Charlie: {}\n", charlie);

    let msg1 = alice.send_message(&mut bob, "Salut Bob !");
    let msg1_1 = charlie.send_message(&mut alice, "Salut Alice, c'est Charlie !");
    let msg1_2 = bob.send_message(&mut charlie, "Yo Charlie, ça dit quoi?");
    if let Some(plain1_2) = charlie.receive_message(&bob, &msg1_2) {
        println!("Bob -> Charlie: {}", plain1_2);
    }
    if let Some(plain1_1) = alice.receive_message(&charlie, &msg1_1) {
        println!("Charlie -> Alice: {}", plain1_1);
    }
    if let Some(plain1) = bob.receive_message(&alice, &msg1) {
        println!("Alice -> Bob: {}", plain1);
    }

    let msg2 = bob.send_message(&mut alice, "Salut Alice, bien reçu !");
    let msg2_2 = alice.send_message(&mut charlie, "Salut Charlie, quoi de neuf ?");
    if let Some(plain2_2) = charlie.receive_message(&alice, &msg2_2) {
        println!("Alice -> Charlie: {}", plain2_2);
    }
    if let Some(plain2) = alice.receive_message(&bob, &msg2) {
        println!("Bob -> Alice: {}", plain2);
    }

    // 💬 Bob envoie 2 messages désynchronisés
    let msg3 = bob.send_message(&mut alice, "Voici un autre message.");
    let msg3_3 = charlie.send_message(&mut alice, "Pas grand chose!");
    let msg4 = bob.send_message(&mut alice, "Et un dernier pour la route !");
    let msg4_4 = charlie.send_message(&mut alice, "Et toi?");

    // 📥 Alice reçoit d'abord le message 4, puis le 3
    if let Some(plain4) = alice.receive_message(&bob, &msg4) {
        println!("Bob -> Alice: {}", plain4);
    }
    if let Some(plain4_4) = alice.receive_message(&charlie, &msg4_4) {
        println!("Charlie -> Alice: {}", plain4_4);
    }
    if let Some(plain3) = alice.receive_message(&bob, &msg3) {
        println!("Bob -> Alice: {}", plain3);
    }
    if let Some(plain3_3) = alice.receive_message(&charlie, &msg3_3) {
        println!("Charlie -> Alice: {}", plain3_3);
    }
}
