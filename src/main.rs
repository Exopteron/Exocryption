mod decrypt;
mod encrypt;
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigFile {
    changelog: bool,
    interactive: bool,
    defaultcipher: String
}
fn main() {
    let defaults: ConfigFile = ConfigFile {changelog: true, interactive: true, defaultcipher: "AES-256-GCM-SIV".to_string()};
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    let mut g = "";
    opts.optflag("e", "encrypt", "encrypt text");
    opts.optflag("d", "decrypt", "decrypt text");
    opts.optflag("h", "help", "get help");
    opts.optopt("f", "file", "select file", "FILE");
    opts.optopt("", "config", "select a config file (optional)", "FILE");
    opts.optopt("", "genConfig", "generate a configuration file", "FILE");
    opts.optopt("p", "password", "use this password", "\"text\"");
    opts.optopt("c", "cipher", "select cipher", "CIPHER");
    opts.optopt("o", "output", "select output file", "FILE");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };
    let genconfig = matches.opt_str("genConfig");
    if genconfig.is_none() {

    } else {
        let genconfig = genconfig.unwrap();
        let write = std::fs::write(genconfig.clone(), format!("# Default configuration file for Exocryption v0.0.3-a.\n\n{}",toml::to_string(&defaults).unwrap()));
        if write.is_err() == true {
            println!("[Exocryption] Couldn't write to {}.", genconfig);
            std::process::exit(1);
        } else {
            println!("[Exocryption] Writing config to {}", genconfig);
            std::process::exit(0);   
        }
    }
    let config: ConfigFile;
    let userfile = matches.opt_str("config");
    if userfile.is_none() {
        config = defaults;
    } else {
        let configfile = std::fs::read_to_string(userfile.unwrap()).unwrap();
        let configmaybe = toml::from_str::<ConfigFile>(&configfile);
        if configmaybe.is_err() == true {
            println!("[Exocryption] Invalid configuration file.");
            std::process::exit(1);
        } else {
            config = configmaybe.unwrap();
        }
    }
    println!("[Exocryption] Welcome to Exocryption v{}!", VERSION);
    if config.changelog == true {
        println!("Updates from v0.0.3\n-- New AES-256-GCM mode of operation.\n-- Fixed security vulnerability where if a path was specified instead of a file name, the encrypted file would (by default) decrypt to the same location on the decryptor's PC.\n");
        println!("Updates from v0.0.2c\n-- New encrypted file format (Exocryptionv2)\n-- HMAC of the entire file (including header), unlike before when only the encrypted contents were authenticated\n-- Header is encrypted with AES-256-CBC-HMAC always, which contains the encryption method and nonce.\n");
        println!("Updates from v0.0.2b\n-- Added output file flag -o\n");
        println!("Updates from v0.0.2\n-- Final optimizations, released to GitHub!\n");
        println!("Updates from v0.0.1:\n-- New encoding format for smaller file sizes\n-- Better error handling\n-- More interactive interactive mode.\n");   
    }
    if cfg!(target_os = "windows") {
        println!("[Exocryption] We have detected you are running on Windows. You may have issues as this was built on Linux. Please report any issues to the github!");
    }
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
    if g == "" && config.interactive == true {
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
            eprintln!("[Exocryption] Unknown mode.");
            std::process::exit(1);
        }
    } else if g == "" && config.interactive == false {
        eprintln!("[Exocryption] Err: No mode given.");
        std::process::exit(1);
    }
    let userpassword = matches.opt_str("p");
    let password;
    if userpassword.is_none() && config.interactive == true {
        println!("[Exocryption] No password given. Please give password...");
        let mut iostring = String::new();
        std::io::stdin()
            .read_line(&mut iostring)
            .ok()
            .expect("Couldn't read line");
        let iostring = iostring.trim();
        password = iostring.to_string();
    } else if userpassword.is_some() {
        password = userpassword.unwrap();
    } else {
        eprintln!("[Exocryption] Err: No password given.");
        std::process::exit(1);
    }
    let userfile = matches.opt_str("f");
    let file;
    if userfile.is_none() && config.interactive == true {
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
    } else if userfile.is_some() {
        file = userfile.unwrap();
    } else {
        eprintln!("[Exocryption] Err: No file given.");
        std::process::exit(1);
    }
    let outputfile = matches.opt_str("o");
    let outfile;
    if outputfile.is_none() && config.interactive == false {
        eprintln!("[Exocryption] No output file provided.");
        std::process::exit(1);
    }
    if outputfile.is_none() {
        outfile = "".to_owned();
    } else {
        outfile = outputfile.unwrap();
    }
    let cipher = matches.opt_str("c");
    let cipher = match cipher {
        Some(x) => x,
        None => config.defaultcipher
    };
    if cipher.to_lowercase() != "XChaCha20-Poly1305".to_lowercase()
        && cipher.to_lowercase() != "AES-256-GCM-SIV".to_lowercase()
        && cipher.to_lowercase() != "AES-256-GCM".to_lowercase()
    {
        helpfn();
        std::process::exit(1);
    }
    let mut finale;
    let mut finalename: String = "".to_owned();
    if g == "Encrypt" {
        finale = encrypt::main(password, file.clone(), cipher);
    } else if g == "Decrypt" {
        let ihatemself = decrypt::main(password, file.clone(), cipher);
        finale = ihatemself.0;
        finalename = ihatemself.1;
    } else if g == "" {
        finale = vec![];
        println!("No mode selected.");
        helpfn();
    } else {
        finale = vec![];
        finale.pop();
        std::process::exit(1);
    }
    let mut filefinal = "".to_owned();
    let mode;
    if g == "Encrypt" {
        mode = "encrypted";
    } else {
        mode = "decrypted";
    }
    if outfile == "" {
        if g == "Encrypt" {
            filefinal.push_str(&file);
            filefinal.push_str(".exo");
        } else {
            filefinal.push_str(&finalename);
        }
        let file2: Vec<&str>;
        if cfg!(windows) {
            file2 = filefinal.split(r#"\"#).collect();
        } else {
            file2 = filefinal.split("/").collect();
        }
        filefinal = file2.last().unwrap().to_string();
        println!(
            "[Exocryption] Done! Would you like to save to {}? (Blank if yes, filename if no.)",
            filefinal
        );
        let mut iostring = String::new();
        std::io::stdin()
            .read_line(&mut iostring)
            .ok()
            .expect("Couldn't read line");
        let iostring = iostring.trim();
        if iostring != "" {
            filefinal = iostring.to_string();
        }
        println!("[Exocryption] Writing {} file to {}", mode, filefinal);
    } else {
        filefinal = outfile;
    }
    let fswrite = std::fs::write(&filefinal, finale);
    if fswrite.is_err() {
        println!("[Exocryption] Couldn't write to {}!", filefinal);
    }
}

fn helpfn() {
    println!("Usage: exocryption [--config (config (Choose the configuration file to use (Optional)))] [-c (cipher (choose between AES-256-GCM-SIV, AES-256-GCM, and XChaCha20-Poly1305. AES-256-GCM-SIV is the default.) )] [[-e] [-encrypt]] | [[-d [-decrypt]] -p [password] -f [file] -o [output file]");
    println!("Doing exocryption --genConfig will generate a config at the specified location.");
    std::process::exit(0);
}
