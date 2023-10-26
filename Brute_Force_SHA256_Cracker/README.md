# Brute Force Password Cracker using OpenSSL

A C++ application leveraging the OpenSSL library to brute force and identify a clear password from a pre-defined list based on its SHA-256 hash.

## Overview

Given a list of clear passwords, this application:
1. Generates the SHA-256 message digest for each password.
2. Compares each digest against a given digest.
3. If a match is found, prints the clear password to the console.
4. Writes the SHA-256 message digest of each password to an output file.

## Prerequisites

- C++ Compiler
- OpenSSL library

## Usage

### Compilation:
\```bash
$ g++ <filename>.cpp -o output -lcrypto
\```

### Execution:
\```bash
$ ./output [path_to_password_list]
\```

Ensure the password list file (`10-million-password-list-top-1000000.txt` or similar) is present in the directory or provide its path.

## Output

- The password corresponding to the given SHA-256 digest will be displayed in the console.
- An `output.txt` file will be generated containing the SHA-256 message digest for each password from the input list.

## Notes

- The application currently uses a predefined SHA-256 hash. Modify the `givenMessageDigest` variable in the code to check against a different hash.
- Handle output and input files with caution.

## License

This project is open-source. Please ensure to give credit when using or modifying this code.
