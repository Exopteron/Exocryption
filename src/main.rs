use std::env;
extern crate getopts;
extern crate serde;
extern crate serde_json;
use getopts::Options;
use std::process;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use serde::Serialize;
use serde::Deserialize;
pub mod encrypt;
pub mod decrypt;

#[derive(Serialize, Deserialize)]
pub struct Key {
    key: String,
    macsecret: String,
    pfssecret: String
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut verbosity = false;
    let mut mode = "n";
    if args.len() < 2 {
        println!("Usage: exocryption [-v (verbose)] [[-e] [-encrypt]] | [[-d [-decrypt]] -k [keyfile] -t [message]");
        return
    }
    let mut opts = Options::new();
    opts.optflag("v","verbose","run in verbose mode");
    opts.optflag("e","encrypt","encrypt text");
    opts.optflag("d","decrypt","decrypt text");
    opts.optflag("h","help","print help");
    opts.optopt("k","keyfile","select keyfile","KEYFILE");
    opts.optopt("t","text","select text","\"text\"");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) } 
    };
    if matches.opt_present("h") {
        println!("Usage: exocryption [-v (verbose)] [[-e] [-encrypt]] | [[-d [-decrypt]] -k [keyfile] -t [message]");
        process::exit(1);
    }
    if matches.opt_present("v") {
        verbosity = true;
    }
    if matches.opt_present("e") {
        mode = "encrypt";
    }
    if matches.opt_present("d") {
        mode = "decrypt";
    }
    let keyfile = matches.opt_str("k");
    /*
    let _input1 = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        println!("Key error");
        return;
    };
    */

    let textin = matches.opt_str("t");
    /*
    let _input2 = if !matches.free.is_empty() {
        matches.free[0].clone();
    } else {
        println!("Text error");
        return;
    };
    */

   // let keyfile = "key.json"; //&args[2];
    let keyfilename = keyfile.unwrap().trim().to_string();
    // Make sure given keyfile exists
    if Path::new(&keyfilename).exists() == false {
        println!("{}: No such file",keyfilename);
        std::process::exit(1);
    }

    // Open the keyfile
    let mut fileduo = File::open(keyfilename).unwrap();

    // Create a new string and read the keyfile into said string
    let mut buffduo = String::new();
    fileduo.read_to_string(&mut buffduo).unwrap();



    

    
    // Create a "Key" object (Defined above) from the keyfile and create a variable called "input" to hold the key
    let keyeren: encrypt::Key = serde_json::from_str(&buffduo).unwrap();
    let keyerde: decrypt::Key = serde_json::from_str(&buffduo).unwrap();
    if mode == "e" || mode == "encrypt" {
        println!("{}",encrypt::main(verbosity,keyeren,textin.unwrap()));
    } else if mode == "d" || mode == "decrypt" {
        let inputout = textin.unwrap().trim().to_string();
        //println!("{:?}",inputout);
        if Path::new(&inputout).exists() == false {
           println!("{}: No such file",inputout);
           std::process::exit(1);
       }
     //  // {}",line!());
       
       let mut file = File::open(inputout).unwrap();
       let mut buff = String::new();
       file.read_to_string(&mut buff).unwrap();
    
     //  // {}",line!());
       
    let message: decrypt::Messagein = serde_json::from_str(&buff).unwrap();
        println!("{}",decrypt::main(verbosity,keyerde,message));
    } else {
        println!("Invalid subcommand: {}", mode);
    }
}