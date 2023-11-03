# RSA Encryption & Decryption Tool

A simple C program to demonstrate RSA encryption and decryption using OpenSSL library functions.

## Overview

This tool allows you to:
- Generate an RSA key pair (private & public).
- Encrypt a given plaintext file using the RSA public key.
- Decrypt the encrypted file using the RSA private key.

## Requirements

- OpenSSL library: This code uses functions from the OpenSSL library, so it needs to be installed and set up properly in your system. Check OpenSSL's [official documentation](https://www.openssl.org/docs/) for setup instructions.

## Functions

- `generateRsaKeyPair`: Generates an RSA key pair and saves them into given files.
- `encryptRsa`: Encrypts the input file using the RSA public key and saves the encrypted data into an output file.
- `decryptRsa`: Decrypts the encrypted file using the RSA private key and saves the decrypted data into an output file.

## Usage

1. Create an input file named `Input.txt` containing the plaintext you want to encrypt.
2. Compile the code and run the generated executable.
3. The RSA key pair will be generated and saved in `privKeyFile.pem` and `pubKeyFile.pem`.
4. The input file will be encrypted and saved in `RSA-Encryption2.txt`.
5. The encrypted file will be decrypted and the output will be saved in `RSA-Decryption2.txt`.

## Notes

- The `generateRsaKeyPair` function generates a 1024-bit RSA key pair. You can modify the bit-length as per your requirement.
- Ensure proper file permissions and handle generated key files with caution.
- The decryption process uses the RSA_PKCS1_PADDING scheme for the last block decryption.
- Ensure the `Input.txt` exists in the working directory before running the program.

## Troubleshooting

- If you encounter an "Error when opening the input file!" message, ensure that `Input.txt` is present in the working directory and has proper read permissions.
