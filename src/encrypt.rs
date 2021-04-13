extern crate crypto;
extern crate rand;
//use std::io;
use std::str;
use rand::Rng;
use serde::Serialize;
use serde::Deserialize;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use crypto::scrypt::ScryptParams;
extern crate serde;
extern crate serde_json;
use std::fs::File;
use std::io::Read;


pub fn main(verbose: bool,keyfilename: String, msg: String) {
    #[derive(Serialize, Deserialize)]
    struct Key {
        key: String,
        macsecret: String
    }
    //let verbose = false;
    let mut input;
    let mut fileduo = File::open(keyfilename).unwrap();
    let mut buffduo = String::new();
    fileduo.read_to_string(&mut buffduo).unwrap();
    let keyer: Key = serde_json::from_str(&buffduo).unwrap();
   /* println!("Key?");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    input = input.trim().to_string();
    */ input = keyer.key;
    //let graphuck = input.to_owned();
    let mut f = vec![0; 24];
    let params = ScryptParams::new(10,8,1);

    let mut iv = sha3_224(&rand::thread_rng().gen_range(1, 100001).to_string());
    for _i in 0..rand::thread_rng().gen_range(1,1001) {
        iv = sha3_224(&iv);
    }
    //println!("IV: {:?}",iv);

    crypto::scrypt::scrypt(input.as_bytes(),iv.as_bytes(),&params,&mut f);
    //println!("{:?}",f);
    input = "".to_owned();
    for i in 0..f.len() {
        input.push_str(&(f[i] as char).to_string());
    }
    let mut inkey = sha3_256(input.trim()).to_owned();
    let macsecret;
    /*println!("MAC Secret?");
    io::stdin()
    .read_line(&mut macsecret)
    .expect("Failed to read line");
    macsecret = macsecret.trim().to_string();
    */ macsecret = keyer.macsecret;
    /*
    let mut msg = String::new();
    println!("Message?");
    io::stdin()
    .read_line(&mut msg)
    .expect("Failed to read line");
    */



    
    let msgbytes = tobytes(&msg);
    let unwrappedmsgbytes: String = msgbytes.into_iter().collect();
    println!("Debug 3 {}",unwrappedmsgbytes);
    let mut finalized = "".to_owned();
    let mut msgbytes = vec!["".to_owned(); unwrappedmsgbytes.chars().count() / 8];
    let mut startpoint = 0;

    for i in 0..unwrappedmsgbytes.chars().count() / 8 {
        for j in startpoint..(startpoint + 8) {
            //println!("debug 1 billion {}",unwrappedmsgbytes.chars().nth(j).unwrap().to_string());
            finalized.push_str(&unwrappedmsgbytes.chars().nth(j).unwrap().to_string());
            if j % 7 == 0 && j != 0 {
                println!("debug like 20000 bruh {}",finalized);
                finalized = "".to_owned();
                startpoint = startpoint + 8;
                break
            }
        }
    }





/*

    for i in 0..unwrappedmsgbytes.chars().count() / 8 {
        println!("{} {} DEbug2",unwrappedmsgbytes.chars().count(), msgbytes.len());
        for j in startpoint..(startpoint + 8) {
                finalized.push_str(&unwrappedmsgbytes.chars().nth(j).unwrap().to_string());
                println!("Debug 4 {}",j);
                if j % 7 == 0 {
                    startpoint = startpoint + 8;
                    msgbytes[i] = finalized;
                    finalized = "".to_owned();
                }
            }

            
    }
    */
    for i in 0..msgbytes.len() {
        println!("DEBUG 5 {:?}",msgbytes[i]);
    }
    


    let mut key = "".trim().to_owned();
    let mut counter = 0;
    for i in 0..msg.chars().count() {
        if counter == inkey.chars().count() {
            if msg.chars().count() - key.chars().count() > 0 {
                inkey.push_str(&sha3_256(&inkey));
            
            }


        }
        
        key.push_str(&inkey.chars().nth(i).unwrap().to_string());
        //println!("looksie: {}",key);
        counter = counter + 1;
    }

    


    let keybytes = tobytes(&key);

/*
    for i in 0..msg.chars().count() {
   // println!("Message: {:?}", msgbytes[i]);

    }
    for i in 0..key.chars().count() {
     //   println!("Key: {:?}", keybytes[i]);
    
        }
        */
    
    let mut keybyte;
    let mut msgbyte;
    let mut ciphertext = "".to_owned();
    for ib in 0..(unwrappedmsgbytes.chars().count() / 8) {
    for i in 0..8 {
        println!("Debug: {} {}",msgbytes[ib],msgbytes[ib].chars().nth(1).unwrap());
        if msgbytes[ib].chars().nth(i).unwrap() == '0' {
            msgbyte = false;
        } else {
            msgbyte = true;
        }

        if keybytes[ib].chars().nth(i).unwrap() == '0' {
            keybyte = false;
        } else {
            keybyte = true;
        }
        ciphertext.push_str(&xor(keybyte, msgbyte).to_string());
    
    }
}
if verbose == true {
    println!("Ciphertext: {}",ciphertext);
    println!("IV: {}",iv);
}

let mut mac = "".to_owned();
let innermacsecret = sha3_512(&sha3_256(&macsecret));
let outermacsecret = sha3_512(&sha3_256(&sha3_224(&macsecret)));
mac.push_str(ciphertext.trim());
mac.push_str(iv.trim());
mac.push_str(macsecret.trim());
mac = sha3_256(&mac);
let mut innermac = "".to_owned();
innermac.push_str(&innermacsecret);
innermac.push_str(&mac);
innermac = sha3_512(&innermac);
mac = "".to_owned();
mac.push_str(&outermacsecret);
mac.push_str(&innermac);
mac = sha3_256(&mac);

//println!("Initial scrypt hash: {:?}",f);
//println!("{} {} {}",f[3],f[1],f[3]);
let ver1: usize = f[1].into();
let ver2: usize = f[3].into();
let mut verification = sha3_224(&(ver1 * ver2 / ver2).to_string()).to_owned();
verification.push_str(&mac);
verification = sha3_256(&verification);
verification = String::from(verification);
verification.truncate(8);
if verbose {
    println!("Unique message ID: {:?}",verification);
    println!("MAC: {}",mac);
}

#[derive(Serialize, Deserialize)]
struct Messagein {
    messageid: String,
    iv: String,
    mac: String,
    cipherbytes: String
}

let fileout: Messagein = { Messagein {messageid: verification,iv: iv, mac: mac, cipherbytes: ciphertext}};
let json = serde_json::to_string_pretty(&fileout).unwrap();
println!("{}",json);
}


// Exclusive OR function
fn xor(keybyte: bool, msgbyte: bool) -> u8 {
    if keybyte && msgbyte {
        return 0;
    } else if keybyte == false && msgbyte == false {
        return 0;
    } else {
        return 1;
    }
}


// Convert to bytes

fn tobytes(msg: &str) -> Vec<String> {
    let mut var;
    let mut out = vec!["a".to_owned(); msg.chars().count()];
    for i in 0..msg.chars().count() {
    let a: u8 = msg.chars().nth(i).unwrap() as u8;
   // println!("HERE {}",a);
    var = format!("{:b}", a).trim().to_owned();
    var = var.chars().rev().collect::<String>();
    for _g in 0..8 - var.chars().count() {
        if var.chars().count() < 8 {
            var.push_str("0");
        }
    }

    out[i] = var.chars().rev().collect::<String>();
    
    } 
    return out;
}

// Sha3 KDF

fn sha3_256(input: &str) -> String {
    let mut hasher = Sha3::sha3_256();

    hasher.input_str(input);
    return hasher.result_str();
}
fn sha3_512(input: &str) -> String {
    let mut hasher = Sha3::sha3_512();

    hasher.input_str(input);
    return hasher.result_str();
}

fn sha3_224(input: &str) -> String {
    let mut hasher = Sha3::sha3_224();

    hasher.input_str(input);
    return hasher.result_str();
}