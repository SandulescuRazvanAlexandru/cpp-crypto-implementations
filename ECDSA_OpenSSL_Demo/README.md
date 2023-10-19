# ECDSA Signature Verification

This code provides a simple implementation for generating and verifying ECDSA (Elliptic Curve Digital Signature Algorithm) signatures using the OpenSSL library.

## Description

The code does the following steps:
1. Sets up an EC key based on the `secp224r1` curve.
2. Generates a new key pair (public and private).
3. Creates a SHA-256 hash.
4. Signs the hash using the private key.
5. Verifies the signature using the public key.

## Dependencies

- OpenSSL

## Usage

1. Install OpenSSL:
\```
[sudo] apt-get install libssl-dev
\```

2. Compile the code using g++:
\```
g++ <filename>.cpp -o output -lcrypto
\```

3. Run the code:
\```
./output
\```

## Functions

- `handleErrors()`: Outputs error details to stderr.

## Remarks

1. Always check for the return values and errors when dealing with cryptographic operations.
2. This example uses the `secp224r1` elliptic curve.
3. The code provides a mechanism to test the signature validation by altering a byte in the hash (commented out).

## License

[License Information]
