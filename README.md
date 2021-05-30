# Exocryption
A simple file encryption program written in Rust using the Rust Crypto set of crates.

***(SECURITY HAZARD WARNING) I've made this myself, and I am not a cryptographer. I've tested it to the best of my ability and put everything I know into practice, but it's pretty easy for someone to make something they themselves can't break. Also, any branches other than "main" are very old and out of date. DO NOT USE THEM. And for all branches, USE AT YOUR OWN RISK!***

This is a terminal application that lets you encrypt files in a *hopefully* simple way.

The reason I made this software is all from trying to transfer an encrypted file from my Linux machine to my Mac.

First, I tried OpenSSL, using some long command to pick out each option, finding certain options would completely compromise security, and then finally I got a file encrypted. But, apparently macOS comes with a version of OpenSSL that doesn't support PBKDF2. Alright, I'll try just using a large iteration count of SHA-512. No luck, macOS OpenSSL doesn't support AES-256-CTR. Then I thought to try GPG, but macOS doesn't come with GPG. So sites recommended me to installing Homebrew to install GPG. So I tried, and couldn't get it to install properly on my older Mac. So I thought, to make it easier for others who find themselves in a similar position, I want to make an easy-to-use simple and (hopefully) secure file encryption program.

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

What gets encrypted is the file and the file name. This means if you change the encrypted file's name, you can still preserve the original name within.

Usage:
Arguments are:

`-c (cipher) Choose between AES-256-GCM-SIV and XChaCha20-Poly1305. AES-256-GCM-SIV is the default.`

`-e (encrypt) Go into encryption mode.`

`-d (decrypt) Go into decryption mode.`

`-p (password) Specify a password.`

`-f (file) Specify the file.`

If no arguments are provided, Exocryption will launch into Interactive mode.
If any arguments are missing, Interactive mode will start and ask for these arguments.

Afterward, Exocryption will ask where to save the file.

Decrypting a file will automatically pull the cipher used from the header.

This has only been tested on Linux, no clue if it works on Windows.

If you have any issues/feature requests, let me know!
