#include<iostream>
#include<malloc.h>
#include<openssl/sha.h>

#define MESSAGE_CHUNK 256

void computeSha1(int fileLen, unsigned char* buffer, char sha256[]) {
	SHA256_CTX ctx; //context for sha256
	SHA256_Init(&ctx); //init the hash
	unsigned char sha256Digest[SHA256_DIGEST_LENGTH]; //where final hash is stored

	unsigned char* tempBuffer = buffer; //copy buffer into a temp one

	while (fileLen > 0) {
		if (fileLen > MESSAGE_CHUNK) {
			SHA256_Update(&ctx, tempBuffer, MESSAGE_CHUNK); //update with MESSAGE_CHUNK value (256)
		}
		else {
			SHA256_Update(&ctx, tempBuffer, fileLen); //update with a value <= than 256
		}
		fileLen -= MESSAGE_CHUNK;
		tempBuffer += MESSAGE_CHUNK;
	}

	SHA256_Final(sha256Digest, &ctx); //finalize the hash

	FILE* fout = NULL;
	fopen_s(&fout, "output.txt", "wb");

	printf("SHA256 computed: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X", sha256Digest[i]);
		fprintf(fout, "%02X", sha256Digest[i]);
		sprintf(sha256 + (i * 2), "%02X", sha256Digest[i]);
	}

	fclose(fout);
	printf("\n");
}

int main() {
	FILE* f = fopen("input.txt", "rb");

	if (f) {
		char sha256[100];
		fseek(f, 0, SEEK_END);
		int fileLen = ftell(f);
		fseek(f, 0, SEEK_SET);

		unsigned char* fileBuffer = (unsigned char*)malloc(fileLen);
		fread(fileBuffer, fileLen, 1, f);

		computeSha1(fileLen, fileBuffer, sha256);
		printf("SHA256 cross check: %s \n", sha256);
		printf("\n");
		fclose(f);
	}
	else {
		printf("Error when opening file input!");
		return 1;
	}

	return 0;
}