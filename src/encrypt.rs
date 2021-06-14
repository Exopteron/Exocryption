use aes_gcm_siv::aead::{Aead as AesAead, NewAead as AesNewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce};
use aes_gcm::{Aes256Gcm, Key as GCMKey, Nonce as GCMNonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};
use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
use integer_encoding::VarInt;
use std::convert::TryFrom;
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
#[path = "weirdrng.rs"]
mod weirdrng;
#[path = "varint.rs"]
mod varint;
use varint::VarInt as NewVint;

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
    let nonce = weirdrng::get_random_bytes(24);
    let noncebytes = nonce.clone();
    let mut file = File::open(&filename).unwrap();
    let file2: Vec<&str>;
    if cfg!(windows) {
        file2 = filename.split(r#"\"#).collect();
    } else {
        file2 = filename.split("/").collect();
    }
    let filename = file2.last().unwrap();
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
        finalencryptedfile =
            encheaderexo(encryptedfile, String::from_utf8(password.to_vec()).unwrap());
    } else if ciphertouse.to_lowercase() == "AES-256-GCM".to_lowercase() {
        let key = GCMKey::from_slice(b64.as_bytes());
        let originalnonce = noncebytes.clone();
        let noncebytes = &noncebytes.clone()[0..12];
        let nonce = GCMNonce::from_slice(&noncebytes);
        let aead = Aes256Gcm::new(key);
        let decryptedfile = serializedecexo(filename.to_string(), buffer);
        let attemptciphertext = aead.encrypt(nonce, decryptedfile.as_ref());
        if attemptciphertext.is_err() {
            println!("[Exocryption] Failed to encrypt.");
            std::process::exit(1);
        }
        let ciphertext = attemptciphertext.unwrap();
        let encryptedfile = EncryptedFile {
            method: "AES256GCM-Argon2".to_string(),
            nonce: base64::encode(originalnonce),
            ciphertext: ciphertext,
        };
        finalencryptedfile =
            encheaderexo(encryptedfile, String::from_utf8(password.to_vec()).unwrap());
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
        finalencryptedfile =
            encheaderexo(encryptedfile, String::from_utf8(password.to_vec()).unwrap());
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
fn encheaderexo(mut file: EncryptedFile, password: String) -> Vec<u8> {
    use aes::Aes256;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};
    use hmac::{Hmac, Mac, NewMac};
    use sha3::Sha3_256;
    type HmacSha3_256 = Hmac<Sha3_256>;
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let iv = weirdrng::get_random_bytes(16);
    let params = argon2::Params {
        m_cost: 37000,
        t_cost: 2,
        p_cost: 1,
        output_size: 32,
        version: argon2::Version::default(),
    };
    let argon2 = Argon2::default();
    let password = password.trim().as_bytes();
    let mut hashiv = sha3_256(iv.clone());
    hashiv.truncate(24);
    let salt = SaltString::new(&base64::encode(&hashiv)).unwrap();
    //println!("[Exocryption] Hashing your password, please wait..");
    let hash = argon2
        .hash_password(
            password,
            None,
            params,
            Salt::try_from(salt.as_ref()).unwrap(),
        )
        .unwrap();
    let b64 = hash.hash.unwrap();
    let key = b64.as_bytes();
    let mut bytevec = vec![];
    //println!("Nonts: {}", file.nonce);
    //println!("Key: {:?} IV: {:?}",&key,&iv);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let mut buffer = vec![0];
    buffer.append(&mut NewVint::new_as_bytes(file.method.as_bytes().to_vec().len() as u32));
    buffer.append(&mut file.method.as_bytes().to_vec());
    buffer.append(&mut NewVint::new_as_bytes(base64::decode(&file.nonce).unwrap().len() as u32));
    buffer.append(&mut base64::decode(file.nonce).unwrap());
    let methodandnonceenc = &cipher.encrypt_vec(&mut buffer);
    let mut hmac = HmacSha3_256::new_from_slice(&sha3_256(key.to_vec())).unwrap();
    bytevec.append(&mut "\x00\x00\x0fExocryption2".as_bytes().to_vec());
    let mut superbytevec = vec![];
    superbytevec.append(&mut NewVint::new_as_bytes(methodandnonceenc.len() as u32));
    superbytevec.append(&mut methodandnonceenc.to_vec());
    superbytevec.append(&mut file.ciphertext);
    hmac.update(&superbytevec);
    //println!("Updating with: {:?}", &superbytevec);
    let hmac = hmac.finalize();
    let hmac = hmac.into_bytes();
    bytevec.append(&mut hmac.to_vec());
    bytevec.append(&mut iv.to_vec());
    bytevec.append(&mut superbytevec);
    return bytevec;
}

fn serializedecexo(filename: String, mut filecontents: Vec<u8>) -> Vec<u8> {
    let mut bytevec = vec![];
    bytevec.append(&mut makevarint(filename.as_bytes().len()));
    bytevec.append(&mut filename.as_bytes().to_vec());
    bytevec.append(&mut filecontents);
    return bytevec;
}

fn sha3_256(input: Vec<u8>) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    return hasher.finalize().to_vec();
}
