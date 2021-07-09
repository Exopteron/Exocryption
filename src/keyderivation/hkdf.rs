use sha3::{Sha3_256};
use std::io::Read;
pub fn rk_to_mk_hk(rk: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let hkdf = hkdf::Hkdf::<Sha3_256>::new(Some(&vec![0; 32]), &rk);
    let mut okm = vec![0; 192];
    hkdf.expand(b"ROOTKEY_TO_MESSAGEKEY_HEADERKEY", &mut okm).unwrap();
    let mut okm = std::io::Cursor::new(okm);
    let mut hk = vec![0; 32];
    okm.read_exact(&mut hk).expect("Not enough bytes");
    let mut hm = vec![0; 64];
    okm.read_exact(&mut hm).expect("Not enough bytes");
    let mut mk = vec![0; 32];
    okm.read_exact(&mut mk).expect("Not enough bytes");
    let mut mm = vec![0; 64];
    okm.read_exact(&mut mm).expect("Not enough bytes");
    //let mut okm: Vec<&[u8]> = okm.chunks(32).collect();
    return (hk, hm, mk, mm);
}