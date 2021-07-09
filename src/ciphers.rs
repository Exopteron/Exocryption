use crate::keyderivation;
use crate::mac;
use crate::encryption;
use crate::serializer;
//use keyderivation::argon2;
//use std::io::Read;
use rand::RngCore;
use hmac::Mac;
pub fn aes_256_cbc_hmac_sha256_encrypt(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    let (headerkey, headermackey, messagekey, messagemackey) = keyderivation::hkdf::rk_to_mk_hk(key);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let mut iv = vec![0; 16];
    rng.fill_bytes(&mut iv);
    let msg = encryption::aes::cbc::cbc_encrypt(message, messagekey, iv.clone());
    let mac = mac::hmac::perform_hmac_sha256(messagemackey, msg.clone());
    let mut headeriv = vec![0; 16];
    rng.fill_bytes(&mut headeriv);
    let serialized = serializer::serialize_hmac_cbc(msg, iv.clone(), mac.finalize().into_bytes().to_vec(), headerkey, headermackey, headeriv);
    return serialized;
}
pub fn aes_256_cbc_hmac_sha256_decrypt(key: Vec<u8>, message: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    //let (headerkey, headermackey, messagekey, messagemackey) = keyderivation::hkdf::rk_to_mk_hk(key);
    let msg = encryption::aes::cbc::cbc_decrypt(message, key, iv.clone());
    return msg;
}