#[path = "varint.rs"]
mod varint;
use crate::encryption::aes::cbc;
use crate::mac::hmac;
use crate::ciphers;
use std::io::Read;
pub fn serialize_hmac_cbc(ciphertext: Vec<u8>, iv: Vec<u8>, mac: Vec<u8>, header_key: Vec<u8>, header_mac_key: Vec<u8>, header_iv: Vec<u8>) -> Vec<u8> {
    let mut packet = vec![];
    packet.append(&mut b"Exocryptionv3\x01\x00\x01".to_vec());
    let mut packettoencrypt = vec![];
    packettoencrypt.append(&mut varint::VarInt::write_string("Argon2-AES-256-CBC-HMAC-SHA256".to_string()));
    //packettoencrypt.append(&mut iv.clone());
    let packettoencrypt = cbc::cbc_encrypt(packettoencrypt, header_key, header_iv.clone());
    //println!("Header: {:?} Mac key: {:?}", packettoencrypt, header_mac_key);
    let mut headermac = hmac::perform_hmac_sha256(header_mac_key, packettoencrypt.clone());
    //println!("MAC: {:?}", headermac);
    packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(header_iv.clone()));
    packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(headermac));
    packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(packettoencrypt));
    packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(mac));
    packet.append(&mut varint::VarInt::write_varint_prefixed_bytearray(iv.clone()));
    packet.append(&mut ciphertext.clone());
    return packet;
}
pub fn deserialize(serialized: Vec<u8>, message_key: Vec<u8>, mac_key: Vec<u8>, header_key: Vec<u8>, header_mac_key: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut serialized = std::io::Cursor::new(serialized);
    let mut checkbyte = vec![0; b"Exocryptionv3\x01\x00\x01".len()];
    serialized.read_exact(&mut checkbyte);
    if checkbyte != b"Exocryptionv3\x01\x00\x01".to_vec() {
        return Err("Invalid.".to_string());
    }
    let mut header_iv = varint::VarInt::read_varint_prefixed_bytearray(&mut serialized);
    let mut header_mac = varint::VarInt::read_varint_prefixed_bytearray(&mut serialized);
    let mut header_enc = varint::VarInt::read_varint_prefixed_bytearray(&mut serialized);
    let mut mac = varint::VarInt::read_varint_prefixed_bytearray(&mut serialized);
    let mut iv = varint::VarInt::read_varint_prefixed_bytearray(&mut serialized);
    let mut ciphertext = vec![];
    serialized.read_to_end(&mut ciphertext);
    //println!("Header: {:?} Mac key: {:?}", header_enc, header_mac_key);
    let mut ourmac = hmac::perform_hmac_sha256(header_mac_key, header_enc.clone());
    //println!("Our mac: {:?}", ourmac);
    if ourmac != header_mac {
        return Err("Header MAC mismatch.".to_string());
    }
    let mut ourmac = hmac::perform_hmac_sha256(mac_key, ciphertext.clone());
    if ourmac != mac {
        return Err("MAC mismatch.".to_string());
    }
    let mut header = cbc::cbc_decrypt(header_enc, header_key, header_iv);
    let mut header = std::io::Cursor::new(header);
    let mut method = varint::VarInt::read_string(&mut header);
    //let mut iv = varint::VarInt::read_varint_prefixed_bytearray(&mut header);
    if method == "Argon2-AES-256-CBC-HMAC-SHA256" {
        let decrypted = ciphers::aes_256_cbc_hmac_sha256_decrypt(message_key, ciphertext, iv);
        return Ok(decrypted);
    }
    return Err("Invalid cipher suite.".to_string());
    //return Ok((method, iv, ciphertext));
}