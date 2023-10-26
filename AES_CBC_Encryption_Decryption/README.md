# AES-CBC Encryption and Decryption with OpenSSL

This repository contains code that demonstrates the use of the AES-CBC encryption mode with OpenSSL to encrypt and decrypt files.

## Description

The program:
- Reads an input file named `Input.txt`.
- Outputs an encrypted file named `Cbc-Encryption.txt`.
- Decrypts the encrypted file to produce `Cbc-Decryption.txt`.

**Key features:**
- Utilizes AES-128-bit encryption.
- Employs the CBC (Cipher Block Chaining) mode.
- Initialization Vector (IV) is hardcoded with a specific pattern for the purpose of this demonstration.
- The encrypted file starts with the length of the original plaintext to aid in decryption.
- In case of missing input files, an error message is displayed.

## Dependencies

1. C++ Compiler
2. OpenSSL library

## Compilation and Execution

1. Compile the code using:
   ```sh
   g++ your_source_filename.cpp -o output_filename -lcrypto
   ```

2. To encrypt a file, rename it or ensure it's named `Input.txt` and place it in the directory.

3. Execute the program:
   ```sh
   ./output_filename
   ```

4. After execution:
   - Encrypted content will be found in `Cbc-Encryption.txt`.
   - Decrypted content (from the encrypted file) will be available in `Cbc-Decryption.txt`.

## Caution

- The secret key is hardcoded as `mysecretkey12345` for this demo. For real-world applications, ensure a secure method for key management.
- The Initialization Vector (IV) is also hardcoded with a repeated pattern. In actual applications, it's essential to use a unique and unpredictable IV for each encryption to maintain security.
- Always validate and ensure the correctness and security of cryptographic code before deploying it in production environments.

## Contribution

For improvements and suggestions, open an issue or submit a pull request.

## License

This project is open source and available under the MIT License. See the [LICENSE.md](LICENSE.md) file for more info.
