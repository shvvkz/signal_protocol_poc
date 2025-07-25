use signal_protocol_poc::user::User;

fn main() {
    let mut alice = User::new("Alice".to_string());
    let mut bob = User::new("Bob".to_string());
    let mut charlie = User::new("Charlie".to_string());

    let msg1 = alice.send_message(&bob.public_info(), "Salut Bob !");
    let msg1_1 = charlie.send_message(&alice.public_info(), "Salut Alice, c'est Charlie !");
    let msg1_2 = bob.send_message(&charlie.public_info(), "Yo Charlie, ça dit quoi?");
    if let Some(plain1_2) = charlie.receive_message(&bob.public_info(), &msg1_2) {
        println!("Bob -> Charlie: {}", plain1_2);
    }
    if let Some(plain1_1) = alice.receive_message(&charlie.public_info(), &msg1_1) {
        println!("Charlie -> Alice: {}", plain1_1);
    }
    if let Some(plain1) = bob.receive_message(&alice.public_info(), &msg1) {
        println!("Alice -> Bob: {}", plain1);
    }

    let msg2 = bob.send_message(&alice.public_info(), "Salut Alice, bien reçu !");
    let msg2_2 = alice.send_message(&charlie.public_info(), "Salut Charlie, quoi de neuf ?");
    if let Some(plain2_2) = charlie.receive_message(&alice.public_info(), &msg2_2) {
        println!("Alice -> Charlie: {}", plain2_2);
    }
    if let Some(plain2) = alice.receive_message(&bob.public_info(), &msg2) {
        println!("Bob -> Alice: {}", plain2);
    }

    let msg3 = bob.send_message(&alice.public_info(), "Voici un autre message.");
    let msg3_3 = charlie.send_message(&alice.public_info(), "Pas grand chose!");
    let msg4 = bob.send_message(&alice.public_info(), "Et un dernier pour la route !");
    let msg4_4 = charlie.send_message(&alice.public_info(), "Et toi?");

    if let Some(plain4) = alice.receive_message(&bob.public_info(), &msg4) {
        println!("Bob -> Alice: {}", plain4);
    }
    if let Some(plain4_4) = alice.receive_message(&charlie.public_info(), &msg4_4) {
        println!("Charlie -> Alice: {}", plain4_4);
    }
    if let Some(plain3) = alice.receive_message(&bob.public_info(), &msg3) {
        println!("Bob -> Alice: {}", plain3);
    }
    if let Some(plain3_3) = alice.receive_message(&charlie.public_info(), &msg3_3) {
        println!("Charlie -> Alice: {}", plain3_3);
    }
}
