# Project Titor

Project Titor is an application that encrypt files using AES-128 Algorithm and RSA password encryption. Use 3 levels of encryption:
- Encrypt file using AES-128 and generates a random password (private key) required to decrypt file.
- Encrypt the previous generated password with RSA Algorithm using a Private RSA PEM provided by user.
- Generate a SHA-512 hash with encrypted file buffer and compress this hash in 16 bytes for generate a new password for AES-128 Algorithm.
- Encrypt RSA encrypted buffer password and Encrypted file (packed in a single file) using AES-128 Algorithm using new password generated with SHA-512 hash.
- Store new encrypted file in system (with .wwe extension) and SHA-512 hash to validate the inner encrypted file in decryption process.

## Usage

```
Usage: titor -f FILEPATH -p RSA_PRIVATE_PEM [-d][-c HASHFILE_PATH]

Options:
  General Options:
	-f		Path to file to encrypt.
	-p		Path to private PEM file.
	-d		Decrypt mode.
	-c		Path to file that contains validator hash (FILAPATH + '.sha512' by default).
```

## Dependences
- CryptoPP: [https://www.cryptopp.com/](https://www.cryptopp.com/)
- GCC Compiler.

## Support

[whitewolf2690@gmail.com](mailto:whitewolf2690@gmail.com)
