# OpenSSL DES Encryption & Decryption

This project provides an implementation for DES encryption and decryption using OpenSSL in CFB mode and Triple DES (3DES) in CFB mode.

## Prerequisites

- You need to have OpenSSL libraries installed.
- A compiler that supports C, like GCC.

## Usage

The program accepts command line arguments for encryption mode and paths to input and output files.

1. **For DES CFB Encryption and Decryption**:

   ```
   OpenSSLProj.exe -cfb [source-file] [encrypted-output-file] [decrypted-output-file]
   ```

2. **For 3DES CFB Encryption and Decryption**:

   ```
   OpenSSLProj.exe -3des [source-file] [encrypted-output-file] [decrypted-output-file]
   ```

Example:

```
OpenSSLProj.exe -cfb input.txt encrypted.txt decrypted.txt
```

## Functions

- `unsigned char* DES_CFB_Encrypt(unsigned char* Key, unsigned char* Msg, int size)` - Encrypts the given message using DES in CFB mode.

- `unsigned char* DES_CFB_Decrypt(unsigned char* Key, unsigned char* Msg, int size)` - Decrypts the given message using DES in CFB mode.

- `unsigned char* DES_3_CFB_Encrypt(unsigned char* Key, unsigned char* Msg, int size)` - Encrypts the given message using Triple DES in CFB mode.

- `unsigned char* DES_3_CFB_Decrypt(unsigned char* Key, unsigned char* Msg, int size)` - Decrypts the given message using Triple DES in CFB mode.

## Note

- The project uses hard-coded keys for 3DES mode. Modify the `kb1`, `kb2`, and `kb3` blocks in the functions for different keys.

- Ensure that your input file exists in the directory or provide the full path to the file.

## License

This project is licensed under the MIT License.

## Acknowledgments

- OpenSSL Project for the cryptographic library.
```
