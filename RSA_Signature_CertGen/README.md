```markdown
# RSA Digital Signature with OpenSSL

This project demonstrates how to generate and verify RSA digital signatures using OpenSSL. Additionally, it shows how to create an X.509 certificate.

## Features

1. **Key Pair Generation:** Generate RSA public and private keys and save them to `.pem` files.
2. **Digital Signature Generation:** Create a digital signature for an input file using MD5 as the message digest algorithm and RSA private key for signing.
3. **Digital Signature Verification:** Verify the authenticity of a file and its signature using RSA public key.
4. **X.509 Certificate Generation:** Create a sample X.509 certificate.

## Pre-requisites

- C++ Compiler
- OpenSSL library

## Usage

1. **Compile** the code:
```bash
$ g++ <filename>.cpp -o output -lcrypto
```

2. **Run** the program:
```bash
$ ./output
```

3. To use the digital signature feature, ensure you have a file named `Input.txt` in the same directory. This file will be signed and the signature will be verified.

## API Overview

### `generateRsaKeyPair(FILE* privKeyFile, FILE* pubKeyFile)`

Generates an RSA key pair and saves them into specified files.

### `generateESignRsa(long int inFileLen, FILE* inFile, FILE* privKeyFile)`

Generates an electronic signature (ESign) for a given file using RSA and MD5.

### `verifyESignRsa(long int inFileLen, FILE* inFile, FILE* signFile, FILE* pubKeyFile)`

Verifies the provided ESign of a file against its content using RSA and MD5.

### `generateX509Cert()`

Generates a sample X.509 certificate and its corresponding private key.

## Notes

- This program uses deprecated RSA key generation functions. It's recommended to use modern key generation techniques for real-world applications.
- MD5 is considered cryptographically broken and unsuitable for further use. Consider using SHA-256 or another secure hash algorithm.

## Author

Sandulescu Razvan Alexandru

## License

This project is open-source. Please ensure to give credit when using or modifying this code.
```
