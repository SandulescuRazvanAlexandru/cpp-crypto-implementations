# OpenSSL Cryptographic Application

This application provides cryptographic functionalities based on the OpenSSL library. The following tasks are performed:

1. Decrypting a signature file (`hfile.sign`) and extracting its content as SHA-256.
2. Encrypting password candidates from a file (`wordlist.txt`) using AES-CBC 128 bits. The resulting encrypted password candidates are saved to `enclist.txt`.
3. Encrypting `enclist.txt` using RSA with PKCS1 padding.
4. Computing the SHA-1 hash for `enclist.txt`.

## Requirements

- A digital signature file named `hfile.sign`.
- A public key named `pExam.pem` as an RSA 1024 paired key.
- A list of password candidates in a file named `wordlist.txt`.

## Implementation

The provided C/C++ code utilizes the OpenSSL library to accomplish the tasks mentioned above.

## How to Run

1. Ensure OpenSSL is installed on your system.
2. Compile the source code.
3. Execute the compiled binary.
4. Check the output console for the SHA-256 and SHA-1 hash representations.


