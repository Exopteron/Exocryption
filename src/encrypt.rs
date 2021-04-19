extern crate crypto;
extern crate rand;
extern crate base64;
extern crate serde;
extern crate serde_json;
//use std::io;
use std::str;
use rand::Rng;
use std::iter::FromIterator;
use serde::Serialize;
use serde::Deserialize;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use crypto::scrypt::ScryptParams;
use crate::encrypt::crypto::symmetriccipher::Encryptor;
//use base64::encode;
use std::convert::TryInto;

#[derive(Serialize, Deserialize)]
pub struct Key {
    key: String,
    macsecret: String,
    pfssecret: String
}

pub fn main(verbose: bool,keyer: Key, msg: String) -> String {
    


    // Make sure given message fits
    if msg.chars().count() / 8 > 64 {
        println!("Err: Message too long");
        std::process::exit(1);
    }


    let mut input;
    input = keyer.key;

    // Get the pfssecret from the keyfile
    let pfssecret = keyer.pfssecret;

    // Define the vec for and the parameters of the scrypt hash
    let mut f = vec![0; 24];
    let params = ScryptParams::new(10,8,1);


    // Generate a random Initialization Vector
    let mut iv = sha3_224(&rand::thread_rng().gen_range(1, 100001).to_string());
    for _i in 0..rand::thread_rng().gen_range(1,1001) {
        iv = sha3_224(&iv);
    }

    // Perform the hash and turn into UTF-8
    crypto::scrypt::scrypt(input.as_bytes(),iv.as_bytes(),&params,&mut f);
    input = "".to_owned();
    for i in 0..f.len() {
        input.push_str(&(f[i] as char).to_string());
    }



    // Turn the scrypt hashed key into a string using SHA3-256
    let mut inkey = sha3_256(input.trim()).to_owned();


    // Get the macsecret from the file
    let macsecret;
    macsecret = keyer.macsecret;




    // Turn the message into a vec of bytes
    let msgbytes = tobytes(&msg);

    // Unwrap the vec of bytes into a string
    let mut unwrappedmsgbytes: String = msgbytes.into_iter().collect();

    // Create an empty variable
    let mut supermsgbytes = "".to_owned();

    // Generate random padding data
    let mut padding = sha3_512(&rand::thread_rng().gen_range(1, 100001).to_string());
    padding.push_str(&sha3_512(&rand::thread_rng().gen_range(1, 100001).to_string()));

    // Turn padding to bytes
    let padding = tobytes(&padding);

    // Clone unwrapped string of bytes
    let umbclone = unwrappedmsgbytes.clone();

    // Determine the padding length on both sides and subtract by the length of the message in bytes, to make each message the same length
    let paddinglen = rand::thread_rng().gen_range(0, 64 - (umbclone.chars().count() / 8));
    let otherpaddinglen = (64 - (umbclone.chars().count() / 8)) - paddinglen;
    
    // Push the padding
    for i in 0..paddinglen {
        unwrappedmsgbytes.push_str(&padding[i]);
    }

    // Verbose message
    if verbose {
        println!("Padding length: {}",paddinglen);
    }

    // Generate a length byte of the padding and add zeroes to make the byte an actual byte (8 bits)
    let paddinglenbyte = format!("{:b}", paddinglen).trim().to_owned();
    let mut paddinglenbyte = paddinglenbyte.chars().rev().collect::<String>();
    for _g in 0..8 - paddinglenbyte.chars().count() {
        if paddinglenbyte.chars().count() < 8 {
            paddinglenbyte.push_str("0");
        }
    }
    let paddinglenbyte = paddinglenbyte.chars().rev().collect::<String>();


    // Add the length byte to the string
    unwrappedmsgbytes.push_str(&paddinglenbyte.to_string());
    let mut unwrappedmsgbytes = unwrappedmsgbytes.chars().rev().collect::<String>();

    // Opposite side
    let paddinglen = otherpaddinglen;


    // Add padding to string
    for i in 0..paddinglen {
        unwrappedmsgbytes.push_str(&padding[i]);
    }

    // Format number to byte and add zeroes to make it 8 bits
    let paddinglenbyte = format!("{:b}", paddinglen).trim().to_owned();
    let mut paddinglenbyte = paddinglenbyte.chars().rev().collect::<String>();
    for _g in 0..8 - paddinglenbyte.chars().count() {
        if paddinglenbyte.chars().count() < 8 {
            paddinglenbyte.push_str("0");
        }
    }
    // Push to the string
    unwrappedmsgbytes.push_str(&paddinglenbyte);
    unwrappedmsgbytes = unwrappedmsgbytes.chars().rev().collect::<String>();


    // Split it back into a Vec by splitting " "s
    for i in 0..unwrappedmsgbytes.chars().count() {
        if i % 8 == 0 && i != 0 {
            supermsgbytes.push_str(" ");
        }
        supermsgbytes.push_str(&unwrappedmsgbytes.chars().nth(i).unwrap().to_string());

    }
    let msgbytes = Vec::from_iter(supermsgbytes.split(" ").map(String::from));

    

    // Generate the final key
    let mut key = "".trim().to_owned();
    let mut counter = 0;
    for i in 0..unwrappedmsgbytes.chars().count() / 8 {
        if counter == inkey.chars().count() {
            if unwrappedmsgbytes.chars().count() / 8 - key.chars().count() > 0 {
                inkey.push_str(&pfssecret);
                inkey.push_str(&sha3_256(&inkey));
            
            }


        }
        
        key.push_str(&inkey.chars().nth(i).unwrap().to_string());
        counter+=1;
    }

    

    // Turn the key into bytes
    let keybytes = tobytes(&key);


// Get the keybytes and the IV and truncate to the correct length
let mut bruhd = keybytes.into_iter().collect::<String>();
bruhd.truncate(32);
let mut bruhv = iv.to_string();
bruhv.truncate(24);

// Create a ChaCha20 object
let mut chacha = crypto::chacha20::ChaCha20::new_xchacha20(bruhd.as_bytes(),bruhv.as_bytes());
// Clone unwrappedmsgbytes
let msgbytesstring = unwrappedmsgbytes.clone();

// Turn the message to encrypt into a RefReadBuffer
let mut bruhduo = crypto::buffer::RefReadBuffer::new(msgbytesstring.as_bytes());

// Create a vec to be used as the output
let mut bruhse = vec![0; msgbytesstring.len()];

// Reference that vec in a RefWriteBuffer
let mut bruh = crypto::buffer::RefWriteBuffer::new(&mut bruhse);

// Perform the encryption
let _chachaenc = chacha.encrypt(&mut bruhduo, &mut bruh, true);

// Turn to binary and add zeroes where they're missing
let mut ciphertext = "".to_owned();
for i in 0..msgbytesstring.len() {
    let mut var = format!("{:b}", bruhse[i]).trim().to_owned();
    var = var.chars().rev().collect::<String>();
    for _g in 0..8 - var.chars().count() {
        if var.chars().count() < 8 {
            var.push_str("0");
        }
    }
    var = var.chars().rev().collect::<String>();
    ciphertext.push_str(&var);
}


let ctclone = ciphertext.clone();
let mut ctcloneout = "".to_owned();
let mut bigout: Vec<u8> = Vec::new();
for i in 0..ctclone.chars().count() {
    if i % 8 == 0 && i != 0 {
        ctcloneout.push_str(" ");
    }
    ctcloneout.push_str(&ctclone.chars().nth(i).unwrap().to_string());

}
let ctcloneout = Vec::from_iter(ctcloneout.split(" ").map(String::from));
for i in 0..ctcloneout.len() {
    bigout.push(isize::from_str_radix(&ctcloneout[i], 2).unwrap().try_into().unwrap());
}


let ctcloneout = base64::encode(&bigout);

//println!("Base64: {}",ctcloneout);
// Print more verbose information

if verbose == true {
    for i in 0..msgbytes.len() {
        println!("Original: {}",msgbytes[i]);
    }
    println!("Ciphertext: {}",ciphertext);
    println!("IV: {}",iv);
}


// Generate HMAC and message ID
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
let ver1: usize = f[1].into();
let ver2: usize = f[3].into();
let mut verification = sha3_224(&(ver1 * ver2 / ver2).to_string()).to_owned();
verification.push_str(&mac);
verification = sha3_256(&verification);
verification = String::from(verification);
verification.truncate(8);

// More verbose information
if verbose {
    println!("Unique message ID: {:?}",verification);
    println!("MAC: {}",mac);
}

// Define the message struct
#[derive(Serialize, Deserialize)]
struct Messagein {
    messageid: String,
    iv: String,
    mac: String,
    cipherbytes: String
}
let ciphertext = ctcloneout;
// Turn all the encrypted info into a fancy json and print
let fileout: Messagein = { Messagein {messageid: verification,iv: iv, mac: mac, cipherbytes: ciphertext}};
let json = serde_json::to_string_pretty(&fileout).unwrap();
return json;
}


// Exclusive OR function
/*
fn xor(keybyte: bool, msgbyte: bool) -> u8 {
    if keybyte && msgbyte {
        return 0;
    } else if keybyte == false && msgbyte == false {
        return 0;
    } else {
        return 1;
    }
}
*/

// Convert to bytes

fn tobytes(msg: &str) -> Vec<String> {
    let mut var;
    let mut out = vec!["a".to_owned(); msg.chars().count()];
    for i in 0..msg.chars().count() {
    let a: u8 = msg.chars().nth(i).unwrap() as u8;
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