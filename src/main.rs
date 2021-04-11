use std::env;
mod encrypt;
mod decrypt;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: exocryption {{e[ncrypt]|d[crypt]}}");
        return
    }
    
    let mode = &args[1];
    if mode == "e" || mode == "encrypt" {
        encrypt::main();
    } else if mode == "d" || mode == "decrypt" {
        decrypt::main();
    } else {
        println!("Invalid subcommand: {}", mode);
    }
}