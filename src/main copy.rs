use std::env;
mod encrypt;
mod decrypt;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: exocryption [verbose (true,false)] [[e]ncrypt | [d]ecrypt] [keyfile] [message]");
        return
    }
    
    let verbosity = &args[1];
    let mode = &args[2];
    let keyfile = &args[3];
    let msg = &args[4];
    if mode == "e" || mode == "encrypt" {
        encrypt::main(verbosity.parse().unwrap(),keyfile.trim().to_string(),msg.trim().to_string());
    } else if mode == "d" || mode == "decrypt" {
        decrypt::main(verbosity.parse().unwrap(),keyfile.trim().to_string(),msg.trim().to_string());
    } else {
        println!("Invalid subcommand: {}", mode);
    }
}