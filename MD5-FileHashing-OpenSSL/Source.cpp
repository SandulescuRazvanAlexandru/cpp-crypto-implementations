#include<iostream>
#include<malloc.h>
#include<openssl/md5.h>

#define MESSAGE_CHUNK 128

//Teory MD5:
//-> message digest : as limited stream of bytes that tries to authenticate the content of a inpit message;
//it is not an encryption algorithm; it only tries to get a finger print to authenticate
//-> compute the message digest into several chuncks having 16 bytes each(each crunck provides it's input - the plain text 
//splitted into 4 blocks of 4 bytes); the resulted blocks will be arranged in a different way for the next itteration to be used as input

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