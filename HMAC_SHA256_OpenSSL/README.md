# OpenSSL HMAC Example

This code is a demonstration of HMAC (Hash-based Message Authentication Code) functionality using the OpenSSL library.

## Requirements
- OpenSSL library (Tested with OpenSSL 1.0.1 x64)
- Make sure to set the Solution Platform to x64 if you're using a 64-bit version.

## How to Use

1. Compile and link with the OpenSSL library.
2. Run the executable. 

## Features

- Generation of HMAC keys.
- Signing a message using HMAC.
- Verifying the signature of a message using HMAC.

## Functions

- `make_keys(EVP_PKEY** skey, EVP_PKEY** vkey)`: Generates signing (skey) and verifying (vkey) HMAC keys.
- `sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)`: Signs a message using an HMAC key.
- `verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)`: Verifies the signature of a message using an HMAC key.
- `print_it(const char* label, const byte* buff, size_t len)`: Prints a buffer (e.g., a signature) to the console.

## Note

- For simplicity and demonstration purposes, the code uses assertions (`assert`). For production, you might want to handle errors more gracefully.
- The HMAC message digest algorithm used in this example is SHA256. You can replace it with another algorithm if needed.
- Tampering with the signature is optional and is demonstrated with the `#if 0` directives in the `main` function.

## License

Make sure to include licensing information if applicable.

