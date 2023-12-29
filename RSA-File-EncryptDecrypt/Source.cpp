#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/applink.c>

void generateRsaKeyPair() {
    RSA* rsaKeyPair = RSA_new();
    BIGNUM* bignum = BN_new();
    BN_set_word(bignum, RSA_F4); // Commonly used public exponent 65537

    if (RSA_generate_key_ex(rsaKeyPair, 2048, bignum, nullptr) != 1) {
        ERR_print_errors_fp(stderr);
    }
    else {
        // Generate the RSA key pair
        FILE* privKeyFile = fopen("privKeyFile.pem", "wb");
        FILE* pubKeyFile = fopen("pubKeyFile.pem", "wb");
        if (privKeyFile == nullptr || pubKeyFile == nullptr) {
            perror("Error opening key files for writing");
        }
        else {
            // Write the keys to disk
            PEM_write_RSAPrivateKey(privKeyFile, rsaKeyPair, nullptr, nullptr, 0, nullptr, nullptr);
            PEM_write_RSAPublicKey(pubKeyFile, rsaKeyPair); // or PEM_write_RSA_PUBKEY for a more common format

            fclose(privKeyFile);
            fclose(pubKeyFile);
            printf("Generated the RSA key pair successfully!\n");
        }
    }

    RSA_free(rsaKeyPair);
    BN_free(bignum);
}

RSA* loadPublicKey(const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        perror("Error opening public key file");
        return nullptr;
    }
    RSA* rsaPublicKey = PEM_read_RSAPublicKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (rsaPublicKey == nullptr) {
        ERR_print_errors_fp(stderr);
    }
    return rsaPublicKey;
}

RSA* loadPrivateKey(const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        perror("Error opening private key file");
        return nullptr;
    }
    RSA* rsaPrivateKey = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (rsaPrivateKey == nullptr) {
        ERR_print_errors_fp(stderr);
    }
    return rsaPrivateKey;
}

int encryptRsa(const char* filename, RSA* rsaPublicKey) {
    FILE* inFile = fopen(filename, "rb");
    if (!inFile) {
        perror("Error opening input file for reading");
        return -1;
    }
    // Get file size
    fseek(inFile, 0, SEEK_END);
    long inFileLen = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    // Read file contents
    unsigned char* inBuffer = (unsigned char*)malloc(inFileLen + 1);
    fread(inBuffer, 1, inFileLen, inFile);
    fclose(inFile);
    inBuffer[inFileLen] = '\0';

    // Encrypt the data
    int rsaSize = RSA_size(rsaPublicKey);
    unsigned char* encryptedData = (unsigned char*)malloc(rsaSize);
    int encryptedDataLen = RSA_public_encrypt(inFileLen, inBuffer, encryptedData, rsaPublicKey, RSA_PKCS1_PADDING);
    if (encryptedDataLen == -1) {
        ERR_print_errors_fp(stderr);
        free(inBuffer);
        free(encryptedData);
        return -1;
    }

    // Write the encrypted data to a file
    FILE* outFile = fopen("encrypted_data.bin", "wb");
    fwrite(encryptedData, sizeof(unsigned char), encryptedDataLen, outFile);
    fclose(outFile);

    free(inBuffer);
    free(encryptedData);
    printf("Encryption complete!\n");

    return encryptedDataLen;
}

int decryptRsa(const char* filename, RSA* rsaPrivateKey, int encryptedDataLen) {
    FILE* inFile = fopen(filename, "rb");
    if (!inFile) {
        perror("Error opening encrypted data file for reading");
        return -1;
    }

    // Read encrypted contents
    unsigned char* encryptedData = (unsigned char*)malloc(encryptedDataLen);
    fread(encryptedData, sizeof(unsigned char), encryptedDataLen, inFile);
    fclose(inFile);

    // Decrypt the data
    unsigned char* decryptedData = (unsigned char*)malloc(encryptedDataLen);
    int decryptedDataLen = RSA_private_decrypt(encryptedDataLen, encryptedData, decryptedData, rsaPrivateKey, RSA_PKCS1_PADDING);
    if (decryptedDataLen == -1) {
        ERR_print_errors_fp(stderr);
        free(encryptedData);
        free(decryptedData);
        return -1;
    }

    // Write the decrypted data to a file
    FILE* outFile = fopen("decrypted_data.txt", "wb");
    fwrite(decryptedData, sizeof(unsigned char), decryptedDataLen, outFile);
    fclose(outFile);

    free(encryptedData);
    free(decryptedData);
    printf("Decryption complete!\n");

    return decryptedDataLen;
}

int main() {
    generateRsaKeyPair(); // This will create the key pair files

    RSA* rsaPublicKey = loadPublicKey("pubKeyFile.pem");
    if (rsaPublicKey == nullptr) {
        return 1;
    }

    int encryptedDataLen = encryptRsa("input.txt", rsaPublicKey);
    if (encryptedDataLen == -1) {
        RSA_free(rsaPublicKey);
        return 1;
    }

    RSA_free(rsaPublicKey);

    RSA* rsaPrivateKey = loadPrivateKey("privKeyFile.pem");
    if (rsaPrivateKey == nullptr) {
        return 1;
    }

    if (decryptRsa("encrypted_data.bin", rsaPrivateKey, encryptedDataLen) == -1) {
        RSA_free(rsaPrivateKey);
        return 1;
    }

    RSA_free(rsaPrivateKey);

    return 0;
}
