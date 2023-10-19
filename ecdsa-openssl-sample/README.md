# ECDSA Example with OpenSSL

This repository contains a simple implementation of Elliptic Curve Digital Signature Algorithm (ECDSA) using OpenSSL.

## Description

The code demonstrates the following operations:
1. Handling OpenSSL errors.
2. Generating and setting up an elliptic curve.
3. Creating an EC key pair.
4. Generating and verifying an ECDSA signature.

The curve used in this example is `secp224r1`, also known as `NIST P-224`.

## Dependencies

- OpenSSL

## Usage

1. Compile the code using the following command:
   ```bash
   gcc your_filename.c -o output_name -lcrypto
   ```

2. Run the compiled code:
   ```bash
   ./output_name
   ```

## Notes

Make sure you have OpenSSL development headers installed before compiling.

## License

Add licensing information here (if applicable).

## Contribution

Instructions on how to contribute to this project.
```
