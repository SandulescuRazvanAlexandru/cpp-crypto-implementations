#include<iostream>
#include<malloc.h>
#include<openssl/md5.h>

#define MESSAGE_CHUNK 128

void computeMD5(int fileLen, unsigned char* buffer, char md5[]) {
	MD5_CTX ctx; //context for MD5
	MD5_Init(&ctx); //init the hash
	unsigned char md5Digest[MD5_DIGEST_LENGTH]; //where final hash is stored

	unsigned char* tmpBuffer = buffer; //copy buffer into a temp one
	while (fileLen > 0) {
		if (fileLen > MESSAGE_CHUNK) {
			MD5_Update(&ctx, tmpBuffer, MESSAGE_CHUNK); //update with MESSAGE_CHUNK value (128)
		}
		else {
			MD5_Update(&ctx, tmpBuffer, fileLen); //update with a value <= than 128
		}
		fileLen -= MESSAGE_CHUNK;
		tmpBuffer += MESSAGE_CHUNK;
	}

	MD5_Final(md5Digest, &ctx); //finalize the hash

	FILE* fout = NULL;
	fopen_s(&fout, "output.txt", "wb");

	printf("MD5 computed: ");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02X", md5Digest[i]);
		fprintf(fout, "%02X", md5Digest[i]);
		sprintf(md5 + (i * 2), "%02X", md5Digest[i]);
	}
	fclose(fout);
	printf("\n");
}

int main() {
	FILE* f = fopen("input.txt", "rb");

	if (f) {
		char md5[100];
		fseek(f, 0, SEEK_END);
		int fileLen = ftell(f);
		fseek(f, 0, SEEK_SET);

		unsigned char* fileBuffer = (unsigned char*)malloc(fileLen);
		fread(fileBuffer, fileLen, 1, f);

		computeMD5(fileLen, fileBuffer, md5);
		printf("MD5 cross check: %s \n", md5);
		printf("\n");
		fclose(f);
	}
	else {
		printf("Error when opening file input!");
		return 1;
	}

	return 0;
}