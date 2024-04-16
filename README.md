# C++ Cryptographic Implementations Repository

A repository dedicated to cryptographic operations and tools, implemented in C++ using the OpenSSL library.

## Overview

This repository provides an extensive collection of cryptographic operations ranging from hashing and encryption to signature generation and verification, all implemented in C++.

# Cryptography Concepts Overview

This document provides an overview of several key cryptographic and data handling concepts discussed in a conversation about securing and managing data effectively in software applications.

## Table of Contents
- [AES (Advanced Encryption Standard)](#aes-advanced-encryption-standard)
- [RSA (Rivest–Shamir–Adleman)](#rsa-rivestshamiradleman)
- [PBE (Password-Based Encryption)](#pbe-password-based-encryption)
- [PBKDF2 (Password-Based Key Derivation Function 2)](#pbkdf2-password-based-key-derivation-function-2)
- [OTP (One-Time Password)](#otp-one-time-password)
- [SecureRandom](#securerandom)
- [ECDSA (Elliptic Curve Digital Signature Algorithm)](#ecdsa-elliptic-curve-digital-signature-algorithm)
- [HMAC (Hash-Based Message Authentication Code)](#hmac-hash-based-message-authentication-code)
- [Encoding vs Encryption vs Hashing vs Obfuscation](#encoding-vs-encryption-vs-hashing-vs-obfuscation)

## AES (Advanced Encryption Standard)
AES is a symmetric encryption algorithm used widely for secure data encryption. It is known for its efficiency and strong security credentials, supporting key sizes of 128, 192, or 256 bits.

### Modes of AES
- **AES-ECB (Electronic Codebook Mode)**: Simple but vulnerable to pattern analysis.
- **AES-CBC (Cipher Block Chaining Mode)**: Encrypts blocks of plaintext with XOR operations, using a previous ciphertext block.

## RSA (Rivest–Shamir–Adleman)
RSA is an asymmetric cryptographic algorithm used for secure data transmission, utilizing a pair of keys (public and private) to encrypt and decrypt data.

## PBE (Password-Based Encryption)
This method uses passwords to derive cryptographic keys, combining the password with a salt and a repetition count to generate a key for data encryption.

## PBKDF2 (Password-Based Key Derivation Function 2)
A method that applies a pseudorandom function to derive a key from a password, using a salt and multiple iterations to enhance security against brute-force attacks.

## OTP (One-Time Password)
OTP is a password that is valid for only one login session or transaction, commonly used in two-factor authentication systems.

## SecureRandom
`SecureRandom` is a class used in programming to generate cryptographically strong random numbers or keys.

## ECDSA (Elliptic Curve Digital Signature Algorithm)
A variant of the Digital Signature Algorithm which uses elliptic curve cryptography to create digital signatures.

## HMAC (Hash-Based Message Authentication Code)
A construction for calculating a message authentication code using a cryptographic hash function and a secret key, providing data integrity and authenticity.

## Encoding vs Encryption vs Hashing vs Obfuscation
- **Encoding**: Converts data into a different format for interoperability (not secure).
- **Encryption**: Secures data by making it unreadable without the correct key (secure).
- **Hashing**: Transforms data into a fixed-size string to check data integrity (irreversible).
- **Obfuscation**: Makes software difficult to understand to protect against reverse engineering (partially reversible).

This README is designed to be a quick reference guide for understanding these important concepts and applying them in software development for data security and management.

## Features

### Brute_Force_SHA256_Cracker

Utility to brute-force passwords based on a provided SHA-256 hash, using a predefined list of passwords.

### AES_CBC_Encryption_Decryption

Tools to encrypt and decrypt data using the AES algorithm in CBC mode.

### AES_ECB_Encryption_Decryption

Utilities for data encryption and decryption using the AES algorithm in ECB mode.

### DES_TripleDES_Encryption_Decryption

Implementations for encrypting and decrypting data using DES and Triple DES cryptographic algorithms.

### SHA1_FileHashing_OpenSSL

Utility for generating SHA-1 hashes of files.

### SHA256_FileHashing_OpenSSL

Tools dedicated to generating SHA-256 hashes for files.

### HMAC_SHA256_OpenSSL

Implementation showcasing HMAC with the SHA-256 algorithm.

### MD5_FileHashing_OpenSSL

Utility to hash files using the MD5 algorithm.

### RSA_File_EncryptDecrypt

A set of tools for encrypting and decrypting files leveraging the RSA cryptographic algorithm.

### RSA_Signature_CertGen

Implementations for generating certificates and managing RSA signatures.

### ECDSA_Sample_OpenSSL

A basic sample showcasing the Elliptic Curve Digital Signature Algorithm.

### ECDSA_Signature_OpenSSL

Implementations for generating and verifying ECDSA signatures.

## Getting Started

1. **Prerequisites**: Ensure you have the C++ Compiler and OpenSSL library installed.
   
2. **Clone the Repository**:
    ```bash
    git clone [repository_url]
    ```

3. **Navigate & Compile**:
   Change to the desired directory and follow the individual README for instructions on compilation and usage.

## Contributions

Contributions are more than welcome! Whether it's refining existing code, adding new features, or reporting bugs - all feedback is invaluable. 
