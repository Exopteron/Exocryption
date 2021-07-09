use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
pub fn cbc_encrypt(mut message: Vec<u8>, message_key: Vec<u8>, message_iv: Vec<u8>) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(&message_key, &message_iv).unwrap();
    let message = cipher.encrypt_vec(&mut message);
    return message;
}
pub fn cbc_decrypt(mut message: Vec<u8>, message_key: Vec<u8>, message_iv: Vec<u8>) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(&message_key, &message_iv).unwrap();
    let message = cipher.decrypt(&mut message).unwrap();
    return message.to_vec();
}