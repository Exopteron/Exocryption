mod encrypt;
mod decrypt;
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
fn main() {
    println!("[Exocryption] Welcome to Exocryption v{}!",VERSION);
    println!("Updates from v0.0.2\n-- Final optimizations, released to GitHub!\n");
    println!("Updates from v0.0.1:\n-- New encoding format for smaller file sizes\n-- Better error handling\n-- More interactive interactive mode.\n");
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    let mut g = "";
    opts.optflag("e","encrypt","encrypt text");
    opts.optflag("d","decrypt","decrypt text");
    opts.optflag("h","help","get help");
    opts.optopt("f","file","select file","KEYFILE");
    opts.optopt("p","password","use this password","\"text\"");
    opts.optopt("c","cipher","select cipher","CIPHER");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!("{}",f.to_string()) } 
    };
    if matches.opt_present("h") {
        //println!("If you run with only the flag \"-g\", this will begin the key exchange process.");
        helpfn();
        std::process::exit(1);
    }
    if matches.opt_present("e") {
        g = "Encrypt";
    }
    if matches.opt_present("d") {
        g = "Decrypt";
    }
    if g == "" {
        println!("[Exocryption] No mode given. Please give mode.. (enc/dec)");
        let mut iostring = String::new();
        std::io::stdin()
            .read_line(&mut iostring)
            .ok()
            .expect("Couldn't read line");
        let iostring = iostring.trim();
        if iostring.to_lowercase().contains("enc") {
            g = "Encrypt";
        } else if iostring.to_lowercase().contains("dec") {
            g = "Decrypt";
        } else {
            println!("[Exocryption] Unknown mode.");
            std::process::exit(1);
        }

    }
    let userpassword = matches.opt_str("p");
    let password;
    if userpassword.is_none() {
        println!("[Exocryption] No password given. Please give password...");
        let mut iostring = String::new();
        std::io::stdin()
            .read_line(&mut iostring)
            .ok()
            .expect("Couldn't read line");
        let iostring = iostring.trim();
        password = iostring.to_string();
    } else {
        password = userpassword.unwrap();
    }
    let userfile = matches.opt_str("f");
    let file;
    if userfile.is_none() {
        println!("[Exocryption] No file given. Please give a file path...");
        let mut iostring = String::new();
        std::io::stdin()
            .read_line(&mut iostring)
            .ok()
            .expect("Couldn't read line");
        let iostring = iostring.trim();
        if !std::path::Path::new(iostring).exists() {
            println!("[Exocryption] File does not exist.");
            std::process::exit(1);
        }
        file = iostring.to_string();
    } else {
        file = userfile.unwrap();
    }
    let cipher = matches.opt_str("c");
    let cipher = match cipher {
        Some(x) => x,
        None => "AES-256-GCM-SIV".to_string(),
    };
    if cipher.to_lowercase() != "XChaCha20-Poly1305".to_lowercase() && cipher.to_lowercase() != "AES-256-GCM-SIV".to_lowercase() {
        helpfn();
        std::process::exit(1);
    }
    /*
    let _input1 = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        println!("Key error");
        return;
    };
    */

    if g == "Encrypt" {
        encrypt::main(password, file, cipher);
    } else if g == "Decrypt" {
        decrypt::main(password, file, cipher);
    } else if g == "" {
        println!("No mode selected.");
        helpfn();
    }
}

fn helpfn() {
    println!("Usage: exocryption [-c (cipher (choose between AES-256-GCM-SIV and XChaCha20-Poly1305, AES-256-GCM-SIV Default.) )] [[-e] [-encrypt]] | [[-d [-decrypt]] -p [password] -f [file]");
}