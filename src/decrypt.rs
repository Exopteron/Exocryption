use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key as GCMKey, Nonce as GCMNonce}; // Or `Aes128Gcm`
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce}; // Or `Aes128GcmSiv`
use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
//use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce}; // Or `XChaCha20Poly1305`
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
#[path = "varint.rs"]
mod varint;
use varint::VarInt as NewVint;
#[derive(Serialize, Deserialize, Debug)]
struct EncryptedFile {
    method: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize, Debug)]
struct DecryptedFile {
    filename: String,
    filecontents: Vec<u8>,
}

pub fn main(password: String, filename: String, mut ciphertouse: String) -> (Vec<u8>, String) {
    let params = argon2::Params {
        m_cost: 37000,
        t_cost: 2,
        p_cost: 1,
        output_size: 32,
        version: argon2::Version::default(),
    };
    let argon2 = Argon2::default();
    let mut file = File::open(&filename).unwrap();
    let mut buffer = vec![];
    file.read_to_end(&mut buffer).expect("Unable to read file");
    let mut encryptedfile = EncryptedFile {
        method: "G".to_string(),
        nonce: [2].to_vec(),
        ciphertext: [5].to_vec(),
    };
    if String::from_utf8_lossy(&buffer[0..15])
        .to_string()
        .contains(&format!("\x00\x00\x0fExocryption2"))
    {
        println!("[Exocryption] Detected as Exocryptionv2 format!");
        encryptedfile = deserializeencheaderexo(buffer, password.clone());
    } else if String::from_utf8_lossy(&buffer[0..14])
        .to_string()
        .contains(&format!("\x00\x00\x0fExocryption"))
    {
        println!("[Exocryption] Detected as Exocryption Legacy format.");
        encryptedfile = deserializeexo(buffer);
    } else {
        println!("[Exocryption] Unknown format.");
    }
    let nonce = encryptedfile.nonce;
    if encryptedfile.method.contains("AES256GCMSIV") {
        println!("[Exocryption] Automatically detected as AES-256-GCM-SIV!");
        ciphertouse = "AES-256-GCM-SIV".to_string();
    } else if encryptedfile.method.contains("AES256GCM") {
        println!("[Exocryption] Automatically detected as AES-256-GCM!");
        ciphertouse = "AES-256-GCM".to_string();
    } else if encryptedfile.method.contains("XChaCha20Poly1305") {
        println!("[Exocryption] Automatically detected as XChaCha20-Poly1305!");
        ciphertouse = "XChaCha20-Poly1305".to_string();
    } else {
        println!("Wtf: {}", encryptedfile.method);
    }
    let noncebytes = nonce.clone();
    let buffer = encryptedfile.ciphertext;
    let buffer = buffer;
    let password = password.trim().as_bytes();
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
        let (filename, filecontents) = deserializedecexo(plaintext);
        let decryptedfile = DecryptedFile {
            filename: filename,
            filecontents: filecontents,
        };
        let decryptedfilecontents = decryptedfile.filecontents;
        let filefinal = decryptedfile.filename;
        finalfilename = filefinal;
        finaldecryptedfile = decryptedfilecontents;
    } else if ciphertouse.to_lowercase() == "AES-256-GCM-SIV".to_lowercase() {
        let key = AesKey::from_slice(b64.as_bytes());
        let noncebytes = &noncebytes.clone()[0..12];
        let nonce = Nonce::from_slice(&noncebytes);
        let aead = Aes256GcmSiv::new(key);
        let attemptplaintext = aead.decrypt(nonce, buffer.as_ref());
        let plaintext;
        if attemptplaintext.is_err() {
            println!("[Exocryption] Could not decrypt. Incorrect password/message tampering?");
            std::process::exit(1);
        } else {
            plaintext = attemptplaintext.unwrap();
        }
        let (filename, filecontents) = deserializedecexo(plaintext);
        let decryptedfile = DecryptedFile {
            filename: filename,
            filecontents: filecontents,
        };
        let decryptedfilecontents = decryptedfile.filecontents;
        let filefinal = decryptedfile.filename;
        finalfilename = filefinal;
        finaldecryptedfile = decryptedfilecontents;
    }
    else if ciphertouse.to_lowercase() == "AES-256-GCM".to_lowercase() {
        let key = GCMKey::from_slice(b64.as_bytes());
        let noncebytes = &noncebytes.clone()[0..12];
        let nonce = GCMNonce::from_slice(&noncebytes);
        let aead = Aes256Gcm::new(key);
        let attemptplaintext = aead.decrypt(nonce, buffer.as_ref());
        let plaintext;
        if attemptplaintext.is_err() {
            println!("[Exocryption] Could not decrypt. Incorrect password/message tampering?");
            std::process::exit(1);
        } else {
            plaintext = attemptplaintext.unwrap();
        }
        let (filename, filecontents) = deserializedecexo(plaintext);
        let decryptedfile = DecryptedFile {
            filename: filename,
            filecontents: filecontents,
        };
        let decryptedfilecontents = decryptedfile.filecontents;
        let filefinal = decryptedfile.filename;
        finalfilename = filefinal;
        finaldecryptedfile = decryptedfilecontents;
    }
    return (finaldecryptedfile, finalfilename);
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
    largebytestepped += bytesstepped;
    let method =
        String::from_utf8_lossy(&file[largebytestepped..largebytestepped + finalen]).to_string();
    largebytestepped += finalen;
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
    largebytestepped += finalen;
    let ciphertext = &file[largebytestepped..file.len()].to_vec();
    let ciphertext = ciphertext.to_vec();
    let finalfile = EncryptedFile {
        method: method,
        nonce: nonce,
        ciphertext: ciphertext,
    };
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
fn deserializeencheaderexo(mut file: Vec<u8>, password: String) -> EncryptedFile {
    use aes::Aes256;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let mut header = vec![];
    for _ in 0..15 {
        header.push(file.remove(0));
    }
    let mut fullfile = vec![];
    fullfile.append(&mut file.clone());
    fullfile.reverse();
    header.reverse();
    fullfile.append(&mut header.clone());
    header.reverse();
    fullfile.reverse();
    let header = String::from_utf8_lossy(&header).to_string();
    if !header.contains(&format!("\x00\x00\x0fExocryption2")) {
        println!(
            "[Exocryption] Invalid or corrupted file. Header: {}",
            header
        );
        std::process::exit(1);
    }
    let theirhmac = &file[0..32];
    let iv = &file[32..48];
    use hmac::{Hmac, Mac, NewMac};
    use sha3::Sha3_256;
    type HmacSha3_256 = Hmac<Sha3_256>;
    let params = argon2::Params {
        m_cost: 37000,
        t_cost: 2,
        p_cost: 1,
        output_size: 32,
        version: argon2::Version::default(),
    };
    let argon2 = Argon2::default();
    let password = password.trim().as_bytes();
    let mut hashiv = sha3_256(iv.clone().to_vec());
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
    let key = b64.as_bytes().to_vec();
    let mut hmac = HmacSha3_256::new_from_slice(&sha3_256(key.clone())).unwrap();
    let mut file = (&file[48..]).to_vec();
    //println!("Updating with: {:?}", file);
    hmac.update(&file);
    let hmac = hmac.finalize();
    let hmac = hmac.into_bytes();
    //println!("Our HMAC: {:?}\nTheir HMAC: {:?}", hmac, theirhmac);
    if theirhmac.to_vec() != hmac.to_vec() {
        println!("[Exocryption] Header HMAC mismatch.");
        std::process::exit(1);
    }
    //println!("{}",header);
    let finalen = NewVint::u32_from_bytes(&mut file);
    let mut largebytestepped = 0 as usize;
    let methodandnonceenc = &file[largebytestepped..largebytestepped + finalen as usize];
    let mut methodandnonceenc = methodandnonceenc.to_vec();
    largebytestepped += finalen as usize;
    let ciphertext = &file[largebytestepped..].to_vec();
    let ciphertext = ciphertext.to_vec();
    //println!("Key: {:?} IV: {:?}",&key,&iv);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let mut methodandnonceenc = cipher.decrypt(&mut methodandnonceenc).unwrap().to_vec();
    let mut largebytestepped = 0;
    let g = NewVint::u32_from_bytes(&mut methodandnonceenc);
    largebytestepped += g as usize;
    for _ in 0..largebytestepped {
        methodandnonceenc.remove(0);
    }
    let finalen = NewVint::u32_from_bytes(&mut methodandnonceenc) as usize;
    let method = &methodandnonceenc[..finalen].to_vec();
    let method = method.to_vec();
    largebytestepped += finalen;
    for _ in 0..largebytestepped {
        methodandnonceenc.remove(0);
    }
    let finalen = NewVint::u32_from_bytes(&mut methodandnonceenc) as usize;
    let nonce = &methodandnonceenc[..finalen].to_vec();
    let nonce = nonce.to_vec();
    let method = String::from_utf8_lossy(&method).to_string();
    let finalfile = EncryptedFile {
        method: method,
        nonce: nonce,
        ciphertext: ciphertext,
    };
    //println!("Finalfile: {:?}",finalfile);
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
fn sha3_256(input: Vec<u8>) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    return hasher.finalize().to_vec();
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
    largebytestepped += bytesstepped;
    let filename =
        String::from_utf8_lossy(&file[largebytestepped..largebytestepped + finalen]).to_string();
    largebytestepped += finalen;
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
