# MD5 Hashing with OpenSSL

This repository contains code that demonstrates the computation of the MD5 hash for a file using the OpenSSL library.

## Description

The program:
- Reads an input file named `input.txt`.
- Computes its MD5 hash.
- Outputs the MD5 hash value on the console and also writes it to an output file named `output.txt`.

**Key features:**
- The program computes the MD5 hash in chunks of 128 bytes.
- It showcases how to initialize, update, and finalize MD5 hashing with OpenSSL.

## Dependencies

1. C++ Compiler
2. OpenSSL library

## Compilation and Execution

1. Compile the code using:
   ```sh
   g++ your_source_filename.cpp -o output_filename -lcrypto
   ```

2. To compute the MD5 hash for a file, rename it or ensure it's named `input.txt` and place it in the directory.

3. Execute the program:
   ```sh
   ./output_filename
   ```

4. After execution, the MD5 hash will be displayed on the console and will also be written to `output.txt`.

## Caution

- MD5 is considered cryptographically broken and unsuitable for further use. This demonstration is for educational purposes only. Do not use MD5 for security-sensitive operations.
- Always validate and ensure the correctness and security of cryptographic code before deploying it in production environments.

## Contribution

For improvements and suggestions, open an issue or submit a pull request.

## License

This project is open source and available under the MIT License. See the [LICENSE.md](LICENSE.md) file for more info.
