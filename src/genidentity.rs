extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::{Keypair, Signature, Signer};
use keyex_rand_core::OsRng;
use serde::{Deserialize, Serialize};
//use crate::encrypt;

#[derive(Serialize, Deserialize)]
struct Keyfile {
    keypair: String,
    id: String,
    id_signature: String
}

pub fn main() {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    println!("[Exocryption] Hello!");
    println!("[Exocryption] User ID?");
    let mut iostring = String::new();
    std::io::stdin()
        .read_line(&mut iostring)
        .ok()
        .expect("Couldn't read line");
    let iostring = iostring.trim();
    let message = iostring.as_bytes();
    let signature: Signature = keypair.sign(message);
    let keyfile = Keyfile {keypair: base64::encode(keypair.to_bytes()), id: iostring.to_string(), id_signature: base64::encode(signature.to_bytes())};
    let keyfile = serde_json::to_string_pretty(&keyfile).unwrap();
    println!("[Exocryption] Protect with a password? (y/n)");
    let mut iostring = String::new();
    std::io::stdin()
        .read_line(&mut iostring)
        .ok()
        .expect("Couldn't read line");
    let iostring = iostring.trim();
    let finalfile;
    if iostring == "y" {
       finalfile = keyfile;
        // encrypt::main(password: String, filename: String, ciphertouse: String, outputfile: String)
    } else {
        finalfile = keyfile;
    }
    std::fs::write("keyfile.json", finalfile).expect("Failed to write");
}