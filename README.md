# Exocryption
A simple file encryption program written in Rust using the Rust Crypto set of crates.

(SECURITY HAZARD WARNING) I've made this myself, and I am not a cryptographer. I've tested it to the best of my ability and put everything I know into practice, but it's pretty easy for someone to make something they themselves can't break. USE AT YOUR OWN RISK!

This is a terminal application that lets you encrypt files in a *hopefully* simple way.

Currently there are two algorithms to choose from and they are both high-level AEADs. This means your files are confidential and authenticated.

These include:

-- AES-256-GCM-SIV

-- XChaCha20-Poly1305

Both of these should be equally secure (AES may be slightly better on systems with dedicated AES instructions)

For key derivation, Argon2id is used with the parameters m: 37000, t: 2, p: 1.

The format of the encrypted files is designed to take up a tiny amount of extra space. (Pretty much equal encrypted/decrypted file sizes as opposed to the double-base64'd JSONified old format which more than doubled file sizes.)

Format:
First, `\x00\x00\x0fExocryption` is appended as the header. The program will check for this just to make sure it's not attempting decryption on something that isn't encrypted. (This definitely does not protect against malicious attacks, but it's not designed to.)

Next, a variable length integer (VarInt) is appended with the length of the method used. (In this case this will either be AES256GCMSIV-Argon2 or XChaCha20Poly1305-Argon2.)

Then, the method is appended.
Next is another VarInt of the length of the nonce. Then the nonce is appended.
Then, the rest of the file are the encrypted bytes.

Usage:
Arguments are:

-c (cipher) Choose between AES-256-GCM-SIV and XChaCha20-Poly1305. AES-256-GCM-SIV is the default.



The key and macsecret can be anything. It's hashed with scrypt using the randomly generated IV as a salt. Keystream is generated from xoring the bits of the scrypt hash with the bits of the message. If we run out of hash bits it's hashed again with SHA3-256 to get more bits.

I am not a cryptographer. Please don't use this for anything serious.

Usage:

If you run "exocryption -v" then it will be in verbose mode. Next flag is encrypt/decrypt. 

For encrypting:

`exocryption -e -k (key json) -t "(message)" `  
Keyfile format is up above. This will output a json which can be outputted into a file (Without verbose mode enabled) by doing

`exocryption -e -k (key json) -t "(message") > message.json`

To decrypt, simply run

`exocryption -d -k (key json) -t (message json)`
