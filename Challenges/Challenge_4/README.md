# README.md

## Overview

This source code provides functionalities for:

1. Decrypting the content of `sha256Enc.txt` using the AES CBC (Cipher Block Chaining) mode.
2. Computing the SHA-256 hash of the content in `Messages.txt` and comparing it with the decrypted hash.

## Prerequisites

- C++ compiler (e.g., GCC or Clang)
- OpenSSL library

## File Dependencies

1. `sha256Enc.txt`: A file containing the encrypted SHA256 value.
2. `Message.txt`: A file containing messages on which SHA256 needs to be computed.

## Build and Run

To compile and run the source code, you might need to link it against the OpenSSL library. An example using GCC is:

```bash
g++ source_file_name.cpp -o output_name -lcrypto -lssl
```

Then, to run:

```bash
./output_name
```

## Functions

### `decryptAesCbc()`

- Purpose: To decrypt an encrypted file using AES CBC mode.
- Parameters:
  - Length of the encrypted file.
  - AES key (password).
  - AES initialization vector (IV).
  - File pointer to the encrypted file.
- Returns: The decrypted content buffer.

### `computeSha256()`

- Purpose: To compute the SHA256 hash of a given file.
- Parameters:
  - Length of the file.
  - File pointer to the input file.
  - Buffer to store the resulting SHA256 hash.
- It also prints the computed SHA256 hash to the console.

## Main Function

1. Opens and reads the content from `sha256Enc.txt`.
2. Decrypts the content using AES CBC mode.
3. Opens and reads the content from `Messages.txt`.
4. Computes the SHA256 hash of the content from `Messages.txt`.
5. Compares the two SHA256 values and prints whether they are the same or different.

## Important Notes

- The AES key (password) and the IV are hardcoded in the source code.
- If either `sha256Enc.txt` or `Messages.txt` cannot be opened, an error message is displayed, and the program terminates.

## Potential Improvements

1. Avoid hardcoding the AES key and IV. Instead, fetch them securely at runtime or from a config file.
2. Implement error handling for potential issues during file reading or cryptographic operations.

## Disclaimer

This code is provided for demonstration and educational purposes. It's essential to evaluate its security and suitability for production environments.
