# Exocryption
Simple rust symmetric encryption using my own custom stream cipher for learning. This is not for use in real-world applications.


I've built this as a test to learn rust and some basic cryptography knowledge.

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
