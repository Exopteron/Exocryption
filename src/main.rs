use std::env;
extern crate getopts;
use getopts::Options;
use std::process;
mod encrypt;
mod decrypt;

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
    if mode == "e" || mode == "encrypt" {
        encrypt::main(verbosity,keyfile.unwrap().trim().to_string(),textin.unwrap());
    } else if mode == "d" || mode == "decrypt" {
        decrypt::main(verbosity,keyfile.unwrap().trim().to_string(),textin.unwrap());
    } else {
        println!("Invalid subcommand: {}", mode);
    }
}