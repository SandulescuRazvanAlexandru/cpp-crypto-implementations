#include<iostream>
#include<malloc.h>
#include<openssl/sha.h>

#define MESSAGE_CHUNK 128

void computeSha1(int fileLen, unsigned char* buffer, char sha1[]) {
	SHA_CTX ctx; //context for sha1
	SHA_Init(&ctx); //init the hash
	unsigned char sha1Digest[SHA_DIGEST_LENGTH]; //where final hash is stored

	unsigned char* tempBuffer = buffer; //copy buffer into a temp one

	while (fileLen > 0) {
		if (fileLen > MESSAGE_CHUNK) {
			SHA_Update(&ctx, tempBuffer, MESSAGE_CHUNK); //update with MESSAGE_CHUNK value (128)
		}
		else {
			SHA_Update(&ctx, tempBuffer, fileLen); //update with a value <= than 128
		}
		fileLen -= MESSAGE_CHUNK;
		tempBuffer += MESSAGE_CHUNK;
	}

	SHA1_Final(sha1Digest, &ctx); //finalize the hash
	 
	FILE* fout = NULL;
	fopen_s(&fout, "output.txt", "wb");

	printf("SHA1 computed: ");
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf("%02X", sha1Digest[i]);
		fprintf(fout, "%02X", sha1Digest[i]);
		sprintf(sha1 + (i * 2), "%02X", sha1Digest[i]);
	}

	fclose(fout);
	printf("\n");
}

int main() {
	FILE* f = fopen("input.txt", "rb");

	if (f) {
		char sha1[100];
		fseek(f, 0, SEEK_END);
		int fileLen = ftell(f);
		fseek(f, 0, SEEK_SET);

		unsigned char* fileBuffer = (unsigned char*)malloc(fileLen);
		fread(fileBuffer, fileLen, 1, f);

		computeSha1(fileLen, fileBuffer, sha1);
		printf("SHA1 cross check: %s \n", sha1);
		printf("\n");
		fclose(f);
	}
	else {
		printf("Error when opening file input!");
		return 1;
	}
	
	return 0;
}