use sha3::{Digest, Sha3_256, Sha3_512};
use hmac::{Hmac, Mac, NewMac};
type HmacSha256 = Hmac<Sha3_256>;

pub fn perform_hmac_sha256(mackey: Vec<u8>, tomac: Vec<u8>) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(&mackey).unwrap();
    mac.update(&tomac);
    let mut result = mac.finalize();
    return result.into_bytes().to_vec();
}