use sha3::{Sha3_256};
use hmac::{Hmac, Mac, NewMac};
type HmacSha256 = Hmac<Sha3_256>;

pub fn perform_hmac_sha256(mackey: Vec<u8>, tomac: Vec<u8>) -> hmac::Hmac<sha3::Sha3_256> {
    let mut mac = HmacSha256::new_from_slice(&mackey).unwrap();
    mac.update(&tomac);
    //let mut result = mac.finalize();
    return mac;
}