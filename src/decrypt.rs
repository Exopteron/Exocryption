use aes_gcm_siv::aead::{Aead as AesAead, NewAead as AesNewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce}; // Or `Aes128GcmSiv`
use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
//use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce}; // Or `XChaCha20Poly1305`
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fs::{self, File};
use std::io;
use std::io::Read;

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    method: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct DecryptedFile {
    filename: String,
    filecontents: Vec<u8>,
}

pub fn main(password: String, filename: String, mut ciphertouse: String) {
    let params = argon2::Params {
        m_cost: 37000,
        t_cost: 2,
        p_cost: 1,
        output_size: 32,
        version: argon2::Version::default(),
    };
    //let key = b"h";
    //let argon2 = Argon2::new(Some(key), 2, 3700, 2, argon2::Version::default()).unwrap();
    let argon2 = Argon2::default();
    //let nonce = "7j5TpVANzNjzaXebe3pUfN2fWdI33A3c";
    let mut file = File::open(&filename).unwrap();
    //let filelen: usize = file.metadata().unwrap().len().try_into().unwrap();
    let mut buffer = vec![];
    file.read_to_end(&mut buffer)
        .expect("Unable to read file"); //(&mut buffer[0..filelen]).expect("Unable to read file!");
    //let encryptedfile: EncryptedFile = serde_json::from_str(&buffer).unwrap();
    let encryptedfile = deserializeexo(buffer);
    let nonce = encryptedfile.nonce;
    if encryptedfile.method.contains("AES256GCMSIV") {
        println!("[Exocryption] Automatically detected as AES-256-GCM-SIV");
        ciphertouse = "AES-256-GCM-SIV".to_string();
    } else if encryptedfile.method.contains("XChaCha20Poly1305") {
        println!("[Exocryption] Automatically detected as XChaCha20-Poly1305");
        ciphertouse = "XChaCha20-Poly1305".to_string();
    }
    //println!("Nonce: {}",nonce);
    /*
    let nonce = base64::decode(nonce);
    if nonce.is_err() {
        println!("[Exocryption] Nonce is invalid base64.");
        std::process::exit(1);
    }
    let nonce = nonce.unwrap();
    */
    let noncebytes = nonce.clone();
    let buffer = encryptedfile.ciphertext;
    //println!("Encrypted file: {}",buffer);
    let buffer = buffer;
    //let buffer = base64::decode(buffer.trim()).unwrap();
    //println!("Pazzworde: {}",password);
    let password = password.trim().as_bytes();
    //let argon2 = Argon2::new(Some(key), 0x0FFFFFFF, 3, 2,argon2::Version::default()).unwrap();
    //let h: argon2::password_hash::Ident.new();
    //let salt = argon2::password_hash::Salt::new("aaaa").unwrap();
    println!("[Exocryption] The random salt: {}", base64::encode(&nonce));
    let salt = SaltString::new(&base64::encode(nonce)).unwrap();
    //let salt = "abcsda".to_string();
    //let salt = Salt::try_from(salt).unwrap();
    //let version = argon2::password_hash::Ident::new("argon2id");
    println!("[Exocryption] Hashing your password, please wait..");
    let hash = argon2
        .hash_password(
            password,
            None,
            params,
            Salt::try_from(salt.as_ref()).unwrap(),
        )
        .unwrap(); //(b"ggggh",&salt);
                   //println!("Hash: {}",hash.hash.unwrap());
    let b64 = hash.hash.unwrap();
    let mut finaldecryptedfile = vec![];
    let mut finalfilename = "".to_owned();
    println!("[Exocryption] We are using {} as the cipher.", ciphertouse);
    if ciphertouse.to_lowercase() == "XChaCha20-Poly1305".to_lowercase() {
        let key = Key::from_slice(b64.as_bytes());
        let noncebytes = noncebytes.clone();
        let nonce = XNonce::from_slice(&noncebytes);
        let aead = XChaCha20Poly1305::new(key);
        let attemptplaintext = aead.decrypt(nonce, buffer.as_ref());
        let plaintext;  
        if attemptplaintext.is_err() {
            println!("[Exocryption] Could not decrypt. Incorrect password/message tampering?");
            std::process::exit(1);
        } else {
            plaintext = attemptplaintext.unwrap();
        }
        let plaintext = String::from_utf8_lossy(&plaintext);
        let decryptedfile: DecryptedFile = serde_json::from_str(&plaintext).unwrap();
        let decryptedfilecontents = decryptedfile.filecontents;
        let filefinal = decryptedfile.filename;
        finalfilename = filefinal;
        finaldecryptedfile = decryptedfilecontents;
    } else if ciphertouse.to_lowercase() == "AES-256-GCM-SIV".to_lowercase() {
        //println!("Key!! {}",b64);
        let key = AesKey::from_slice(b64.as_bytes());
        let noncebytes = &noncebytes.clone()[0..12];
        //println!("Nonce!! {:?}",noncebytes);
        let nonce = Nonce::from_slice(&noncebytes);
        let aead = Aes256GcmSiv::new(key);
        //let decryptedfile = serde_json::to_string(&decryptedfile).unwrap();
        let attemptplaintext = aead.decrypt(nonce, buffer.as_ref());
        let plaintext;
        if attemptplaintext.is_err() {
            println!("[Exocryption] Could not decrypt. Incorrect password/message tampering?");
            std::process::exit(1);
        } else {
            plaintext = attemptplaintext.unwrap();
        }
        let (filename, filecontents) = deserializedecexo(plaintext);
        let decryptedfile = DecryptedFile {filename: filename, filecontents: filecontents};
        let decryptedfilecontents = decryptedfile.filecontents;
        let filefinal = decryptedfile.filename;
        finalfilename = filefinal;
        finaldecryptedfile = decryptedfilecontents;
    }
    let mut filefinal = "".to_owned();
    filefinal.push_str(&finalfilename);
    println!(
        "[Exocryption] Done! Would you like to save to {}? (Blank if yes, filename if no.)",
        filefinal
    );
    let mut iostring = String::new();
    io::stdin()
        .read_line(&mut iostring)
        .ok()
        .expect("Couldn't read line");
    let iostring = iostring.trim();
    if iostring != "" {
        filefinal = iostring.to_string();
    }
    println!("[Exocryption] Writing decrypted file to {}", filefinal);
    let fswrite = fs::write(&filefinal, finaldecryptedfile);
    if fswrite.is_err() {
        println!("[Exocryption] Couldn't write to {}!", filefinal);
    }
    /*
    let key = Key::from_slice(b64.as_bytes());
    let mut noncebytes = noncebytes.clone();
    let nonce = XNonce::from_slice(&noncebytes);
    let aead = XChaCha20Poly1305::new(key);

    let ciphertext = aead.decrypt(nonce, buffer.as_ref()).expect("Failed to decrypt");
    let ciphertext: DecryptedFile = serde_json::from_str(&String::from_utf8_lossy(&ciphertext)).unwrap();
    let decryptedfile = ciphertext.filecontents;
    let mut filefinal = ciphertext.filename;
    println!("Writing to {}",filefinal);
    fs::write(filename,decryptedfile).expect("Unable to write file!");
    */
}

fn deserializeexo(mut file: Vec<u8>) -> EncryptedFile {
    use std::convert::TryInto;
    let mut header = vec![];
    for _ in 0..14 {
        header.push(file.remove(0));
    }
    let header = String::from_utf8_lossy(&header).to_string();
    if header != format!("\x00\x00\x0fExocryption") {
        println!("[Exocryption] Invalid or corrupted file.");
        std::process::exit(1);
    }
    //println!("{}",header);
    let mut fullbyte: Vec<String> = vec![];
    let mut current = 0;
    let mut bytesstepped = 0;
    let mut largebytestepped = 0;
    for _ in 0..5 {
        bytesstepped += 1;
        let currentbyte = format!("{:b}", file[current]);
        let mut var = currentbyte.chars().rev().collect::<String>();
        for _g in 0..9 - var.chars().count() {
            if var.chars().count() < 8 {
                var.push_str("0");
            }
        }
        let currentbyte = var.chars().rev().collect::<String>();
        //println!("current byte: {}",currentbyte);
        if currentbyte.chars().nth(0).unwrap() == '1' {
            if currentbyte.len() > 1 {
                //println!("Pushing: {}",&currentbyte[1..currentbyte.len()]);
                fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                current += 1;
            } else {
                fullbyte.push(currentbyte);
                current += 1;
            }
        } else {
            //println!("Pushing B: {}",&currentbyte[1..currentbyte.len()]);
            fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
            break;
        }
    }
    fullbyte.reverse();
    let mut fullbyte2 = "".to_owned();
    //println!("Full byte: {:?}",fullbyte);
    for i in 0..fullbyte.len() {
        fullbyte2.push_str(&fullbyte[i]);
    }

    let finalen: usize = isize::from_str_radix(&fullbyte2, 2)
        .unwrap()
        .try_into()
        .unwrap();
    largebytestepped+=bytesstepped;
    let method = String::from_utf8_lossy(&file[largebytestepped..largebytestepped + finalen]).to_string();
    largebytestepped+=finalen;
    let mut fullbyte: Vec<String> = vec![];
    let mut current = largebytestepped;
    let mut bytesstepped = 0;
    for _ in 0..5 {
        bytesstepped += 1;
        let currentbyte = format!("{:b}", file[current]);
        let mut var = currentbyte.chars().rev().collect::<String>();
        for _g in 0..9 - var.chars().count() {
            if var.chars().count() < 8 {
                var.push_str("0");
            }
        }
        let currentbyte = var.chars().rev().collect::<String>();
        //println!("current byte: {}",currentbyte);
        if currentbyte.chars().nth(0).unwrap() == '1' {
            if currentbyte.len() > 1 {
                //println!("Pushing: {}",&currentbyte[1..currentbyte.len()]);
                fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                current += 1;
            } else {
                fullbyte.push(currentbyte);
                current += 1;
            }
        } else {
            //println!("Pushing B: {}",&currentbyte[1..currentbyte.len()]);
            fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
            break;
        }
    }
    fullbyte.reverse();
    let mut fullbyte2 = "".to_owned();
    //println!("Full byte: {:?}",fullbyte);
    for i in 0..fullbyte.len() {
        fullbyte2.push_str(&fullbyte[i]);
    }

    let finalen: usize = isize::from_str_radix(&fullbyte2, 2)
        .unwrap()
        .try_into()
        .unwrap();
    //println!("We skipped over {} bytes",bytesstepped);
    //let noncelen = finalen.clone();
    largebytestepped += bytesstepped;
    let nonce = &file[largebytestepped..largebytestepped + finalen].to_vec();
    let nonce = nonce.to_vec();
    largebytestepped+=finalen;
    let ciphertext = &file[largebytestepped..file.len()].to_vec();
    let ciphertext = ciphertext.to_vec();
    let finalfile = EncryptedFile {method: method, nonce: nonce, ciphertext: ciphertext};
    return finalfile;
    /*
    let mut bytevec = vec![];
    bytevec.append(&mut makevarint(file.method.as_bytes().len()));
    bytevec.append(&mut file.method.as_bytes().to_vec());
    bytevec.append(&mut makevarint(base64::decode(&file.nonce).unwrap().len()));
    bytevec.append(&mut base64::decode(file.nonce).    let nonce = base64::decode(nonce);
    if nonce.is_err() {
        println!("[Exocryption] Nonce is invalid base64.");
        std::process::exit(1);
    }
    let nonce = nonce.unwrap();unwrap());
    bytevec.append(&mut makevarint(file.ciphertext.len()));
    bytevec.append(&mut file.ciphertext);
    return bytevec;*/
}

fn deserializedecexo(file: Vec<u8>) -> (String, Vec<u8>) {
    use std::convert::TryInto;
    let mut fullbyte: Vec<String> = vec![];
    let mut current = 0;
    let mut bytesstepped = 0;
    let mut largebytestepped = 0;
    for _ in 0..5 {
        bytesstepped += 1;
        let currentbyte = format!("{:b}", file[current]);
        let mut var = currentbyte.chars().rev().collect::<String>();
        for _g in 0..9 - var.chars().count() {
            if var.chars().count() < 8 {
                var.push_str("0");
            }
        }
        let currentbyte = var.chars().rev().collect::<String>();
        //println!("current byte: {}",currentbyte);
        if currentbyte.chars().nth(0).unwrap() == '1' {
            if currentbyte.len() > 1 {
                //println!("Pushing: {}",&currentbyte[1..currentbyte.len()]);
                fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                current += 1;
            } else {
                fullbyte.push(currentbyte);
                current += 1;
            }
        } else {
            //println!("Pushing B: {}",&currentbyte[1..currentbyte.len()]);
            fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
            break;
        }
    }
    fullbyte.reverse();
    let mut fullbyte2 = "".to_owned();
    //println!("Full byte: {:?}",fullbyte);
    for i in 0..fullbyte.len() {
        fullbyte2.push_str(&fullbyte[i]);
    }

    let finalen: usize = isize::from_str_radix(&fullbyte2, 2)
        .unwrap()
        .try_into()
        .unwrap();
    largebytestepped+=bytesstepped;
    let filename = String::from_utf8_lossy(&file[largebytestepped..largebytestepped + finalen]).to_string();
    largebytestepped+=finalen;
    let file = &file[largebytestepped..file.len()].to_vec();
    let file = file.to_vec();
    return (filename, file);
    /*
    let mut bytevec = vec![];
    bytevec.append(&mut makevarint(filename.as_bytes().len()));
    bytevec.append(&mut filename.as_bytes().to_vec());
    bytevec.append(&mut filecontents);
    return bytevec;
    */
}