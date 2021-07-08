mod keyderivation;
mod mac;
mod encryption;
mod serializer;
mod ciphers;
use keyderivation::argon2;
use std::io::Read;
use std::env;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    let mut g = "";
    opts.optflag("e", "encrypt", "encrypt text");
    opts.optflag("d", "decrypt", "decrypt text");
    opts.optflag("h", "help", "get help");
    opts.optopt("f", "file", "select file", "FILE");
    //opts.optopt("", "config", "select a config file (optional)", "FILE");
    //opts.optopt("", "genConfig", "generate a configuration file", "FILE");
    opts.optopt("p", "password", "use this password", "\"text\"");
    opts.optopt("c", "cipher", "select cipher", "CIPHER");
    opts.optopt("o", "output", "select output file", "FILE");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };
    let decrypt = matches.opt_present("decrypt");
    if decrypt {
        let mut file = matches.opt_str("file").unwrap();
        let mut file = std::fs::File::open(file).unwrap();
        let mut filebytes = vec![];
        file.read_to_end(&mut filebytes);
        let mut password = b"password1".to_vec();
        let key = keyderivation::argon2::password_to_rk(password, base64::encode("GoodSalt").as_bytes().to_vec());
        let key = key.as_bytes().to_vec();
        let (headerkey, headermackey, messagekey, messagemackey) = keyderivation::hkdf::rk_to_mk_hk(key);
        let deserialized = serializer::deserialize(filebytes, messagekey, messagemackey, headerkey, headermackey).unwrap();
        std::fs::write("decrypted.txt", deserialized);
    } else {
        let mut file = matches.opt_str("file").unwrap();
        let mut file = std::fs::File::open(file).unwrap();
        let mut filebytes = vec![];
        file.read_to_end(&mut filebytes);
        let mut password = b"password1".to_vec();
        let key = keyderivation::argon2::password_to_rk(password, base64::encode("GoodSalt").as_bytes().to_vec());
        let key = key.as_bytes().to_vec();
        let (headerkey, headermackey, messagekey, messagemackey) = keyderivation::hkdf::rk_to_mk_hk(key.clone());
        let mut msg = encryption::aes::cbc::cbc_encrypt(filebytes.clone(), messagekey, vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
        let mut mac = mac::hmac::perform_hmac_sha256(messagemackey, msg.clone());
        let mut serialized = serializer::serialize_hmac_cbc(msg, vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], mac, headerkey, headermackey, vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
        let serialized = ciphers::aes_256_cbc_hmac_sha256_encrypt(key, filebytes); 
        std::fs::write("test.txt.exo", serialized);
    }
    println!("G");
    //println!("{:?}", serializer::deserialize(filebytes, messagekey, messagemackey, headerkey, headermackey));
}