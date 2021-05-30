# Exocryption
A simple file encryption program written in Rust using the Rust Crypto set of crates.

(SECURITY HAZARD WARNING) I've made this myself, and I am not a cryptographer. I've tested it to the best of my ability and put everything I know into practice, but it's pretty easy for someone to make something they themselves can't break. USE AT YOUR OWN RISK!

This is a terminal application that lets you encrypt files in a *hopefully* simple way.
key.json format:
```
{
	"key": "text",
	"macsecret": "text"
}
```

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
