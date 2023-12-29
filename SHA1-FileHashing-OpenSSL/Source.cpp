#include<iostream>
#include<cstdlib>  // Use cstdlib instead of malloc.h for C++ code
#include<openssl/sha.h>

#define MESSAGE_CHUNK 128

void computeSha1(int fileLen, unsigned char* buffer, char sha1[]) {
    SHA_CTX ctx; // context for sha1
    SHA1_Init(&ctx); // init the hash
    unsigned char sha1Digest[SHA_DIGEST_LENGTH]; // where final hash is stored

    unsigned char* tempBuffer = buffer; // copy buffer into a temp one

    while (fileLen > 0) {
        if (fileLen > MESSAGE_CHUNK) {
            SHA1_Update(&ctx, tempBuffer, MESSAGE_CHUNK); // update with MESSAGE_CHUNK value (128)
        }
        else {
            SHA1_Update(&ctx, tempBuffer, fileLen); // update with a value <= than 128
        }
        fileLen -= MESSAGE_CHUNK;
        tempBuffer += MESSAGE_CHUNK;
    }

    SHA1_Final(sha1Digest, &ctx); // finalize the hash

    FILE* fout = fopen("output.txt", "wb"); // Use fopen for compatibility

    if (fout != nullptr) { // Check if file was opened successfully
        printf("SHA1 computed: ");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            printf("%02X", sha1Digest[i]);
            fprintf(fout, "%02X", sha1Digest[i]);
            snprintf(sha1 + (i * 2), 3, "%02X", sha1Digest[i]); // Use snprintf for safety
        }
        fclose(fout);
        printf("\n");
    }
    else {
        std::cerr << "Error when opening file output.txt for writing!\n";
    }
}

int main() {
    FILE* f = fopen("input.txt", "rb");

    if (f) {
        fseek(f, 0, SEEK_END);
        int fileLen = ftell(f);
        fseek(f, 0, SEEK_SET);

        unsigned char* fileBuffer = (unsigned char*)malloc(fileLen);
        if (fileBuffer != nullptr) { // Check if memory allocation was successful
            fread(fileBuffer, fileLen, 1, f);

            char sha1[2 * SHA_DIGEST_LENGTH + 1] = { 0 }; // Ensure buffer is large enough and initialized
            computeSha1(fileLen, fileBuffer, sha1);
            printf("SHA1 cross check: %s \n", sha1);
            printf("\n");

            free(fileBuffer); // Free the allocated memory
        }
        else {
            std::cerr << "Memory allocation failed for fileBuffer.\n";
        }
        fclose(f);
    }
    else {
        std::cerr << "Error when opening file input.txt for reading!\n";
        return 1;
    }

    return 0;
}
