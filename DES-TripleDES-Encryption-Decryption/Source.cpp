#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#define ENCRYPT 1
#define DECRYPT 0

unsigned char* DES_CFB_Process(unsigned char* key, unsigned char* msg, int size, int operation) {
    unsigned char* res;
    int n = 0;
    DES_cblock key2;
    DES_key_schedule schedule;

    res = (unsigned char*)malloc(size);

    memcpy(key2, key, 8);
    DES_set_odd_parity(&key2);
    if (DES_set_key_checked(&key2, &schedule)) {
        printf("Key error, exiting...\n");
        free(res);
        return NULL;
    }

    DES_cfb64_encrypt(msg, res, size, &schedule, &key2, &n, operation);

    return res;
}

int main() {
    // Generate a random key
    DES_cblock key;
    DES_random_key(&key);

    // Read the clear text from "input.txt"
    FILE* fSrc = fopen("input.txt", "rb");
    if (fSrc == NULL) {
        printf("Error opening input.txt for reading.\n");
        return 1;
    }

    fseek(fSrc, 0, SEEK_END);
    long int inLen = ftell(fSrc);
    fseek(fSrc, 0, SEEK_SET);

    unsigned char* clear = (unsigned char*)malloc(inLen);
    fread(clear, inLen, 1, fSrc);
    fclose(fSrc);

    // Encrypt the clear text
    unsigned char* encrypted = DES_CFB_Process(key, clear, inLen, ENCRYPT);

    // Write the encrypted text to "encrypted.txt"
    FILE* fEnc = fopen("encrypted.txt", "wb");
    if (fEnc == NULL) {
        printf("Error opening encrypted.txt for writing.\n");
        free(clear);
        free(encrypted);
        return 1;
    }
    fwrite(encrypted, inLen, 1, fEnc);
    fclose(fEnc);

    // Decrypt the encrypted text
    unsigned char* decrypted = DES_CFB_Process(key, encrypted, inLen, DECRYPT);

    // Write the decrypted text back to "decrypted.txt"
    FILE* fDec = fopen("decrypted.txt", "wb");
    if (fDec == NULL) {
        printf("Error opening decrypted.txt for writing.\n");
        free(clear);
        free(encrypted);
        free(decrypted);
        return 1;
    }
    fwrite(decrypted, inLen, 1, fDec);
    fclose(fDec);

    // Cleanup
    free(clear);
    free(encrypted);
    free(decrypted);

    printf("Encryption and decryption finished.\n");

    return 0;
}
