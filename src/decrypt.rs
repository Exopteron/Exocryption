extern crate crypto;
//use std::io;
//use crate::encrypt::crypto::symmetriccipher::Decryptor;
use crypto::symmetriccipher::Decryptor;
use crypto::scrypt::ScryptParams;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use serde::Serialize;
use serde::Deserialize; 
use std::convert::TryInto;
use std::iter::FromIterator;
use std::sync::mpsc;
use std::thread;
extern crate serde;
extern crate serde_json;
//use std::io::prelude::*;
//#[macro_use] extern crate json_derive;


#[derive(Serialize, Deserialize)]
pub struct Messagein {
    iv: String,
    mac: String,
    cipherbytes: String,
    messageid: String
}

#[derive(Serialize, Deserialize)]
pub struct Key {
    key: String,
    macsecret: String,
    pfssecret: String
}

pub fn main(verbose: bool,keyer: Key, message: Messagein) -> String {
   // let mut line!() = 0;
   // // {}",line!());
    

   // // {}",line!());
    
/*

    println!("File name?");
    let mut inputout = String::new();
    io::stdin()
        .read_line(&mut inputout)
        .expect("Failed to read line");
        */

    

 //   // {}",line!());
    

 let mut input = keyer.key;
 let macsecret = keyer.macsecret;
 let pfssecret = keyer.pfssecret;

    
    let mut f = vec![0; 24];
    let params = ScryptParams::new(10,8,1);
    // {}",line!());
    
    /*
    println!("IV?");
    let mut iv = String::new();
    io::stdin()
        .read_line(&mut iv)
        .expect("Failed to read line");
     iv = iv.trim().to_string();
     */ let iv = message.iv;
     // {}",line!());
     
/*
     println!("MAC?");
     let mut mac = String::new();
     io::stdin()
         .read_line(&mut mac)
         .expect("Failed to read line");
      mac = mac.trim().to_string();

      */
      // {}",line!());
      
      let cipherbytes = message.cipherbytes;
      let decoded = base64::decode(&cipherbytes).unwrap();
let mut decoded2 = "".to_owned();
for i in 0..decoded.len() {
    let mut var = format!("{:b}", decoded[i]).trim().to_owned();
    var = var.chars().rev().collect::<String>();
    for _g in 0..8 - var.chars().count() {
        if var.chars().count() < 8 {
            var.push_str("0");
        }
    }
    var = var.chars().rev().collect::<String>();
    decoded2.push_str(&var);
}
    let cipherbytes = decoded2;
      let originalmac = message.mac;
     
      let mut mac = "".to_owned();
      let innermacsecret = sha3_512(&sha3_256(&macsecret));
      let outermacsecret = sha3_512(&sha3_256(&sha3_224(&macsecret)));
      mac.push_str(cipherbytes.trim());
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
      // {}",line!());
      
    crypto::scrypt::scrypt(input.as_bytes(),iv.as_bytes(),&params,&mut f);
    let ver1: usize = f[1].into();
let ver2: usize = f[3].into();
let mut verification = sha3_224(&(ver1 * ver2 / ver2).to_string()).to_owned();
verification.push_str(&mac);
verification = sha3_256(&verification);
verification = String::from(verification);
verification.truncate(8);
// {}",line!());

println!("Unique message ID: {:?}",verification);
if verification == message.messageid {
    println!("Message ID match.");
} else {
    println!("Message ID mismatch. Possible incorrect key?");
    std::process::exit(1);
}
if originalmac != mac {
    println!("Message has been tampered with.");
    std::process::exit(1);
}
// {}",line!());

    input = "".to_owned();
    for i in 0..f.len() {
        input.push_str(&(f[i] as char).to_string());
    }
   let mut inkey = sha3_256(input.trim()).to_owned();

   // {}",line!());
   
   /*println!("Cipher bytes?");
   io::stdin()
   .read_line(&mut cipherbytes)
   .expect("Failed to read line");
   cipherbytes = cipherbytes.trim().to_string();
*/ 
    let mut key = "".trim().to_owned();
    let mut counter = 0;
    for i in 0..cipherbytes.chars().count() / 8 {
        if counter == inkey.chars().count() {
            if cipherbytes.chars().count() / 8 - key.chars().count() > 0 {
                inkey.push_str(&pfssecret);
                inkey.push_str(&sha3_256(&inkey));
           
                
         
            } 
            }

        key.push_str(&inkey.chars().nth(i).unwrap().to_string());
        counter+=1;
    }
    
    let keybytes = tobytes(&key);
    if verbose {    
    println!("Key bytes: {}",keybytes);
    println!("Cipher bytes: {}",cipherbytes);
    }
    // {}",line!());
    
    //let mut output = "".to_owned();

    /*
    let mut keybyte;
    let mut msgbyte;
    for i in 0..key.chars().count() * 8 {
        if keybytes.chars().nth(i).unwrap() == '0' {
           keybyte = false;
        } else {
           keybyte = true;
        }
        if cipherbytes.chars().nth(i).unwrap() == '0' {
            msgbyte = false;
        } else {
            msgbyte = true;
        }
    output.push_str(&xor(keybyte, msgbyte).to_string());

*/

// {}",line!());

let mut bruhd = keybytes;
//println!("Bruhd: {}",bruhd);
bruhd.truncate(32);
let mut bruhv = iv.to_string();
bruhv.truncate(24);
//let mut bruhse = vec![0; bruhv.len()];
// {}",line!());

let mut chacha = crypto::chacha20::ChaCha20::new_xchacha20(bruhd.as_bytes(),bruhv.as_bytes());
//crypto::symmetriccipher::SynchronousStreamCipher::process(&mut chacha,bruhv.as_bytes(), &mut bruhse);
//let mbytesclone = msgbytes.clone();
// {}",line!());
//let msgbytesstring = unwrappedmsgbytes.clone();

let (tx, rx) = mpsc::channel();
//let (tx2, rx2) = mpsc::channel();
//let mut supercipherbytes = "".to_owned();
// e {}",line!());
let thread1work = cipherbytes.chars().count() / 2;
let thread2work = cipherbytes.chars().count() - cipherbytes.chars().count() / 2;
let cbclone = cipherbytes.clone();


let _thread1 = thread::spawn(move || {
    let cipherbytes = cbclone;
    let mut supercipherbytes = "".to_owned();
for i in thread2work..cipherbytes.chars().count() {
  // // b {}",i);
    if (((i >> 3) << 3) == i) && i != 0 {
       // // c {}",i);
        supercipherbytes.push_str(" ");
    }
  // // g {}",line!());
    supercipherbytes.push_str(&cipherbytes.chars().nth(i).unwrap().to_string());

}
tx.send(supercipherbytes).unwrap();
});

    let mut supercipherbytes = "".to_owned();
for i in 0..thread1work {
   // // b {}",i);
     if (((i >> 3) << 3) == i) && i != 0 {
        // // c {}",i);
         supercipherbytes.push_str(" ");
     }
    //// g {}",line!());
     supercipherbytes.push_str(&cipherbytes.chars().nth(i).unwrap().to_string());
 
 }
supercipherbytes.push_str(&rx.recv().unwrap());
//supercipherbytes.push_str(&rx2.recv().unwrap());
//println!("IMPORTANT {:?}",supercipherbytes);
//// {}",line!());

// println!("{}",supermsgbytes);
let supercipherbytes = Vec::from_iter(supercipherbytes.split(" ").map(String::from));
// {}",line!());

let mut cipherbytes: Vec<u8> = Vec::new();

for i in 0..supercipherbytes.len() {
    let cipherbyteslen: usize = isize::from_str_radix(&supercipherbytes[i], 2).unwrap().try_into().unwrap();
    cipherbytes.push(cipherbyteslen as u8);
}

// {}",line!());




let mut bruhduo = crypto::buffer::RefReadBuffer::new(&cipherbytes);
let mut bruhse = vec![0; cipherbytes.len()];
let mut bruh = crypto::buffer::RefWriteBuffer::new(&mut bruhse);
let _chachaenc = chacha.decrypt(&mut bruhduo, &mut bruh, true);
//println!("{:?}",bruhse);
//// {}",line!());

let mut ciphertext = "".to_owned();
for i in 0..cipherbytes.len() {
    let mut var = format!("{:b}", bruhse[i]).trim().to_owned();
    var = var.chars().rev().collect::<String>();
    for _g in 0..8 - var.chars().count() {
        if var.chars().count() < 8 {
            var.push_str("0");
        }
    }
    var = var.chars().rev().collect::<String>();
    ciphertext.push_str(&var);
    //println!("GROUCHY {}",ciphertext);
}
//// {}",line!());


// LOOOOOk
let (tx, rx) = mpsc::channel();
//let (tx2, rx2) = mpsc::channel();
//let mut supercipherbytes = "".to_owned();
//// e {}",line!());
let thread1work = ciphertext.chars().count() / 2;
let thread2work = ciphertext.chars().count() - ciphertext.chars().count() / 2;
let cbclone = ciphertext.clone();


let _thread1 = thread::spawn(move || {
    let ciphertext = cbclone;
    let mut supercipherbytes = "".to_owned();
for i in thread2work..ciphertext.chars().count() {
  // // b {}",i);
    if (((i >> 3) << 3) == i) && i != 0 {
       // // c {}",i);
        supercipherbytes.push_str(" ");
    }
  // // g {}",line!());
    supercipherbytes.push_str(&ciphertext.chars().nth(i).unwrap().to_string());

}
tx.send(supercipherbytes).unwrap();
});

    let mut supercipherbytes = "".to_owned();
for i in 0..thread1work {
   // // b {}",i);
     if (((i >> 3) << 3) == i) && i != 0 {
        // // c {}",i);
         supercipherbytes.push_str(" ");
     }
    //// g {}",line!());
     supercipherbytes.push_str(&ciphertext.chars().nth(i).unwrap().to_string());
 
 }
supercipherbytes.push_str(&rx.recv().unwrap());

// END OF LOOK
/*
let mut supercipherbytes = "".to_owned();
for i in 0..ciphertext.chars().count() {
    if (((i >> 3) << 3) == i) && i != 0 {
        supercipherbytes.push_str(" ");
    }
    supercipherbytes.push_str(&ciphertext.chars().nth(i).unwrap().to_string());

}
*/
// println!("{}",supermsgbytes);

let supercipherbytes = Vec::from_iter(supercipherbytes.split(" ").map(String::from));
//// {}",line!());

/*
for i in 0..supercipherbytes.len() / 8 {
    let mut var = format!("{:b}", bruhse[i]).trim().to_owned();
    var = var.chars().rev().collect::<String>();
    for _g in 0..8 - var.chars().count() {
        if var.chars().count() < 8 {
            var.push_str("0");
        }
    }
    var = var.chars().rev().collect::<String>();
  
    output.push_str(&var.to_string());
}
*/
// {}",line!());


let mut output = "".to_string();
for i in 0..supercipherbytes.len() {
    let intval: u8 = isize::from_str_radix(&supercipherbytes[i].to_string(), 2).unwrap().try_into().unwrap();
  
        output.push_str(&(*&intval as char).to_string());
    }


    if verbose {
    println!("Output: {}",output);
    }
    
    let padlength = output.clone();
    let padlength = padlength.chars().rev().collect::<String>();
    let padlength: String = padlength.chars().take(8).collect();
    let padlength = padlength.chars().rev().collect::<String>();
    let padlength: usize = isize::from_str_radix(&padlength, 2).unwrap().try_into().unwrap();
    if verbose {
        println!("Padding length: {}",padlength);
    }   
   
 //   println!("BIG DEBUG: {}",output);
    for _i in 0..(padlength * 8) + 8 {
        output.pop();
    }

    //println!("BIG DEBUG: {}",output);
    let padlengthr = output.clone();
   // println!("BIG DEBUG: {}",padlengthr);
    let padlengthr = padlengthr.chars().rev().collect::<String>();
    //println!("BIG DEBUG: {}",padlengthr);
    let padlengthr = padlengthr.chars().rev().collect::<String>();
   //println!("BIG DEBUG: {}",padlengthr);
    let padlengthr: String = padlengthr.chars().take(8).collect();
    //println!("BIG DEBUG: {}",padlengthr);
    let padlengthr = padlengthr.chars().rev().collect::<String>();
    //println!("BIG DEBUG: {}",padlengthr.chars().rev().collect::<String>());
    let padlengthr: usize = isize::from_str_radix(&padlengthr.chars().rev().collect::<String>(), 2).unwrap().try_into().unwrap();
    if verbose {
    println!("padding length reversed: {}",padlengthr);
    }

    output = output.chars().rev().collect::<String>();
    for _i in 0..(padlengthr * 8) + 8 {
        output.pop();
    }
    output = output.chars().rev().collect::<String>();

    // {}",line!());
    

    let mut veccer: Vec<String> = vec!["".to_string(); output.chars().count()];
    let mut inter = "".to_owned();
    //let mut iter = 0;
    //let mut sel = 0;
    let mut current = 0;

    let mut finale = "".to_owned();
    for i in 0..output.chars().count() / 8 {
        for ib in current..current + 8 {
            inter.push_str(&output.chars().nth(ib).unwrap().to_string());
            
        }
        veccer[i] = inter;
        inter = "".to_owned();
        current = current + 8;
        
    }
    for i in 0..veccer.len() / 8 {
    let intval: u8 = isize::from_str_radix(&veccer[i], 2).unwrap().try_into().unwrap();
  
        finale.push_str(&(*&intval as char).to_string());
    }
    if originalmac != mac {
        return "Message has been tampered with. (MAC Mismatch)".to_string();
    } else {
       return finale;
        
    }
}



// Exclusive OR Function
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


fn tobytes(msg: &str) -> String {
    let mut var;
    let mut out = "".to_owned();
    
    for i in 0..msg.chars().count() {
    let a: u8 = msg.chars().nth(i).unwrap() as u8;
    var = format!("{:b}", a).trim().to_owned();
    var = var.chars().rev().collect::<String>();
    for _g in 0..8 - var.chars().count() {
        if var.chars().count() < 8 {
            var.push_str("0");
        }
    }
    
    out.push_str(&var.chars().rev().collect::<String>());
    
    } 
    return out;
}

fn sha3_256(input: &str) -> String {
    let mut hasher = Sha3::sha3_256();

    hasher.input_str(input);
    return hasher.result_str();
}
fn sha3_224(input: &str) -> String {
    let mut hasher = Sha3::sha3_224();

    hasher.input_str(input);
    return hasher.result_str();
}
fn sha3_512(input: &str) -> String {
    let mut hasher = Sha3::sha3_512();

    hasher.input_str(input);
    return hasher.result_str();
}