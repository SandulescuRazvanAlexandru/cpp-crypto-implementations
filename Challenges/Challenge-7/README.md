# AES Encryption/Decryption with OpenSSL

This C++ application demonstrates the use of the OpenSSL library to perform AES encryption and decryption.

## Requirements

- C++ Compiler with C++11 support
- OpenSSL development library installed on the system

## Assignment Specification

1. **Class AESCipher**: A wrapper for OpenSSL AES cipher functionality.
   - Supports at least two AES cipher algorithms.
   - Provides static fields for crypto operations: encryption and decryption.
   - Includes constructors for object initialization and a destructor for cleanup.
   - Contains methods to pass content to be encrypted/decrypted and to get the operation result.

2. **Main Function**:
   - Demonstrates the AES functionality implemented by the AESCipher class.
   - Applies two different supported AES algorithms for encryption and decryption.
   - Prints out the encrypted and decrypted results.

## Project Structure

- `AESCipher`: The main class handling the AES encryption and decryption processes.
- `main`: The driver code demonstrating the use of `AESCipher`.

## Notes
   - The project uses static, hardcoded keys and IVs for demonstration purposes. For a production-level application, ensure you generate secure random keys and IVs.
   - Error handling in this project is minimal to keep the focus on OpenSSL usage. For production use, enhance the error handling as required.

## License
   - This project is open-sourced under the MIT License. See the LICENSE file for more details.
