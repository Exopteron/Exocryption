use sha3::{Digest, Sha3_256, Sha3_512};
use std::io::Read;
pub fn rk_to_mk_hk(rk: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let hkdf = hkdf::Hkdf::<Sha3_256>::new(Some(&vec![0; 32]), &rk);
    let mut okm = vec![0; 192];
    hkdf.expand(b"ROOTKEY_TO_MESSAGEKEY_HEADERKEY", &mut okm).unwrap();
    let mut okm = std::io::Cursor::new(okm);
    let mut hk = vec![0; 32];
    okm.read_exact(&mut hk);
    let mut hm = vec![0; 64];
    okm.read_exact(&mut hm);
    let mut mk = vec![0; 32];
    okm.read_exact(&mut mk);
    let mut mm = vec![0; 64];
    okm.read_exact(&mut mm);
    //let mut okm: Vec<&[u8]> = okm.chunks(32).collect();
    return (hk, hm, mk, mm);
}