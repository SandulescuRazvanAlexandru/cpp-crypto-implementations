# AES-ECB Encryption and Decryption

This code demonstrates the use of the AES-ECB encryption mode with OpenSSL to encrypt and decrypt files.

## Description

The program reads from an input file named `Input.txt` and generates encrypted and decrypted output files named `Ecb-Encryption.txt` and `Ecb-Decryption.txt` respectively.

Key features include:
- Using the AES-128-bit encryption method.
- ECB (Electronic Codebook) mode of encryption.
- The encrypted file starts with the length of the original plaintext to assist in decryption.
- If the input file is not found, an error message is displayed.

## Dependencies

To run the program, you need:
- C++ compiler
- OpenSSL library

## Usage

1. Compile the code:
   ```sh
   g++ your_source_filename.cpp -o output_filename -lcrypto
   ```

2. Place the file you wish to encrypt as `Input.txt` in the directory.

3. Run the executable:
   ```sh
   ./output_filename
   ```

4. The encrypted file will be generated as `Ecb-Encryption.txt` and the decrypted version of this file will be generated as `Ecb-Decryption.txt`.

## Caution

- The secret key is hardcoded as `mysecretkey12345` for this demonstration. In a real-world application, it is recommended to use a secure method for key storage and retrieval.
- ECB mode is not recommended for most real-world applications as it doesn't provide semantic security. Use with caution and consider other modes like CBC or GCM for enhanced security.

## Contribution

Feel free to contribute to this project by opening issues or submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
