use aes_gcm_siv::aead::{Aead as AesAead, NewAead as AesNewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce};
use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
use integer_encoding::VarInt;
use std::convert::TryFrom; // Or `Aes128GcmSiv`
                           //use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce}; // Or `XChaCha20Poly1305`
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    method: String,
    nonce: String,
    ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct DecryptedFile {
    filename: String,
    filecontents: String,
}
pub fn main(password: String, filename: String, ciphertouse: String) -> Vec<u8> {
    let params = argon2::Params {
        m_cost: 37000,
        t_cost: 2,
        p_cost: 1,
        output_size: 32,
        version: argon2::Version::default(),
    };
    let argon2 = Argon2::default();
    let password = password.trim();
    let filename = filename.trim();
    let mut nonce = [0; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let noncebytes = nonce.clone();
    let mut file = File::open(&filename).unwrap();
    let filelen: usize = file.metadata().unwrap().len().try_into().unwrap();
    let mut buffer = vec![0; filelen];
    file.read(&mut buffer[0..filelen])
        .expect("Unable to read file!");

    let password = password.as_bytes();
    println!("[Exocryption] The random salt: {}", base64::encode(&nonce));
    let salt = SaltString::new(&base64::encode(nonce)).unwrap();
    println!("[Exocryption] Hashing your password, please wait..");
    let hash = argon2
        .hash_password(
            password,
            None,
            params,
            Salt::try_from(salt.as_ref()).unwrap(),
        )
        .unwrap();
    let b64 = hash.hash.unwrap();
    let mut finalencryptedfile = vec![];
    println!("[Exocryption] We are using {} as the cipher.", ciphertouse);
    if ciphertouse.to_lowercase() == "XChaCha20-Poly1305".to_lowercase() {
        let key = Key::from_slice(b64.as_bytes());
        let noncebytes = noncebytes.clone();
        let nonce = XNonce::from_slice(&noncebytes);
        let aead = XChaCha20Poly1305::new(key);
        let decryptedfile = serializedecexo(filename.to_string(), buffer);
        let attemptciphertext = aead.encrypt(nonce, decryptedfile.as_ref());
        if attemptciphertext.is_err() {
            println!("[Exocryption] Failed to encrypt.");
            std::process::exit(1);
        }
        let ciphertext = attemptciphertext.unwrap();
        let encryptedfile = EncryptedFile {
            method: "XChaCha20Poly1305-Argon2".to_string(),
            nonce: base64::encode(nonce),
            ciphertext: ciphertext,
        };
        finalencryptedfile = serializeexo(encryptedfile);
    } else if ciphertouse.to_lowercase() == "AES-256-GCM-SIV".to_lowercase() {
        let key = AesKey::from_slice(b64.as_bytes());
        let originalnonce = noncebytes.clone();
        let noncebytes = &noncebytes.clone()[0..12];
        let nonce = Nonce::from_slice(&noncebytes);
        let aead = Aes256GcmSiv::new(key);
        let decryptedfile = serializedecexo(filename.to_string(), buffer);
        let attemptciphertext = aead.encrypt(nonce, decryptedfile.as_ref());
        if attemptciphertext.is_err() {
            println!("[Exocryption] Failed to encrypt.");
            std::process::exit(1);
        }
        let ciphertext = attemptciphertext.unwrap();
        let encryptedfile = EncryptedFile {
            method: "AES256GCMSIV-Argon2".to_string(),
            nonce: base64::encode(originalnonce),
            ciphertext: ciphertext,
        };
        finalencryptedfile = serializeexo(encryptedfile);
    }
    return finalencryptedfile;
}

fn makevarint(number: usize) -> Vec<u8> {
    let mut packetconstruct = vec![];
    let mut varint1 = vec![0; 32];
    number.encode_var(&mut varint1);
    for i in 0..varint1.len() {
        if varint1[i] != 0 {
            packetconstruct.push(varint1[i]);
        }
    }
    return packetconstruct;
}

fn serializeexo(mut file: EncryptedFile) -> Vec<u8> {
    let mut bytevec = vec![];
    println!("Nonts: {}", file.nonce);
    bytevec.append(&mut "\x00\x00\x0fExocryption".as_bytes().to_vec());
    bytevec.append(&mut makevarint(file.method.as_bytes().len()));
    bytevec.append(&mut file.method.as_bytes().to_vec());
    bytevec.append(&mut makevarint(base64::decode(&file.nonce).unwrap().len()));
    bytevec.append(&mut base64::decode(file.nonce).unwrap());
    bytevec.append(&mut file.ciphertext);
    return bytevec;
}

fn serializedecexo(filename: String, mut filecontents: Vec<u8>) -> Vec<u8> {
    let mut bytevec = vec![];
    bytevec.append(&mut makevarint(filename.as_bytes().len()));
    bytevec.append(&mut filename.as_bytes().to_vec());
    bytevec.append(&mut filecontents);
    return bytevec;
}
