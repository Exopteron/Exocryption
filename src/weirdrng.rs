use aes::cipher::{
    generic_array::GenericArray, BlockEncrypt, NewBlockCipher,
};
use aes::Aes256;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub fn get_random_bytes(amount: usize) -> Vec<u8> {
    let mut chacharng = ChaCha20Rng::from_entropy();
    let mut k = vec![0; 32];
    chacharng.fill_bytes(&mut k);
    let mut fortuna = fortuna(k, amount + 24);
    for _ in 0..24 {
        fortuna.remove(0);
    }
    let mut chacha = vec![0; amount];
    chacharng.fill_bytes(&mut chacha);
    let output = xor(fortuna, &chacha);
    return output;
}

fn fortuna(k: Vec<u8>, amount: usize) -> Vec<u8> {
    let mut c = 1;
    let mut k = sha3_256(k);
    return generaterandomdata(&mut k, &mut c, amount);
    fn generateblocks(capk: &mut Vec<u8>, c: &mut usize, k: usize) -> Vec<u8> {
        let mut r = vec![];
        for _ in 0..k {
            assert_eq!(capk.len(), 32);
            let key = GenericArray::from_slice(&capk);
            let cipher = Aes256::new(&key);
            let mut superc = c.to_le_bytes().to_vec();
            if superc.len() < 16 {
                for _ in 0..16 - superc.len() {
                    superc.push(0x00);
                }
            }
            let mut block = GenericArray::clone_from_slice(&superc);
            cipher.encrypt_block(&mut block);
            r.append(&mut block.clone().to_vec());
            //println!("R: {:?}",r);
            *c+=1;
        }
        return r;
    }

    fn generaterandomdata(capk: &mut Vec<u8>, c: &mut usize, n: usize) -> Vec<u8> {
        let r;
        let coolr = generateblocks(&mut capk.clone(), &mut c.clone(), (n / 16) + 1);
        //println!("Cool R: {:?}",coolr);
        r = coolr[0..n].to_vec();
        *capk = generateblocks(&mut capk.clone(), &mut c.clone(), 2);
        return r;
    }
}

fn xor(xor1: Vec<u8>, xor2: &Vec<u8>) -> Vec<u8> {
    let len;
    let xor2 = xor2.clone();
    if xor1.len() < xor2.len() {
        len = xor1.len();
    } else {
        len = xor2.len();
    }
    let mut xor1str = "".to_owned();
    let mut xor2str = "".to_owned();
    for i in 0..len {
        let mut var = format!("{:b}", xor1[i]);
        var = var.chars().rev().collect::<String>();
        for _g in 0..8 - var.chars().count() {
            if var.chars().count() < 8 {
                var.push_str("0");
            }
        }
        let xor1bruh = var.chars().rev().collect::<String>();
        xor1str.push_str(&xor1bruh);

        let mut var = format!("{:b}", xor2[i]);
        var = var.chars().rev().collect::<String>();
        for _g in 0..8 - var.chars().count() {
            if var.chars().count() < 8 {
                var.push_str("0");
            }
        }
        let xor2bruh = var.chars().rev().collect::<String>();
        xor2str.push_str(&xor2bruh);
    }
    let xor1: Vec<char> = xor1str.chars().collect();
    let xor2: Vec<char> = xor2str.chars().collect();
    let mut xoredstring = "".to_owned();
    for i in 0..len * 8 {
        /*
        println!("XOR1: {}",xor1str.len());
        println!("XOR2: {}",xor2str.len());
        println!("XORed string: {}",xoredstring);
        */
        if (xor1[i] == '0' && xor2[i] == '1') || (xor1[i] == '1' && xor2[i] == '0') {
            xoredstring.push_str("1");
        } else {
            xoredstring.push_str("0");
        }
    }
    let mut xored = vec![];
    let mut iter = 0;
    for _ in 0..(xoredstring.len() / 8) {
        xored.push(u8::from_str_radix(&xoredstring[iter..iter + 8], 2).unwrap());
        iter += 8;
    }
    // println!("XORed: {:?} {}",xored,xored.len());
    return xored.to_vec();
}

fn sha3_256(input: Vec<u8>) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    return hasher.finalize().to_vec();
}