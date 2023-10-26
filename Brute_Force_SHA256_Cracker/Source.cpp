#include <stdio.h>
#include <malloc.h>
#include <openssl/sha.h>
#include <iostream>


/*
TO DO:
For exercise 1:
-> read all the passwords from the file and for every pass generate it's message digest
-> compare each message digest with the given one and print the clear password which message digest matches the hardcoded one
For exercise 2:
-> write in a file for every password, it's corresponding message digest
*/

#define MAX_LINE_LENGTH 100
#define MESSAGE_CHUNK 256

unsigned char* generateSHA256Digest(char* input, int lineLen) {
	SHA256_CTX ctx;
	unsigned char* finalDigest = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
	SHA256_Init(&ctx);

	char* tmpBuffer = (char*)malloc(lineLen);
	strcpy(tmpBuffer, input);

	while (lineLen > 0) {
		if (lineLen > MESSAGE_CHUNK) {
			SHA256_Update(&ctx, tmpBuffer, MESSAGE_CHUNK);
		}
		else {
			SHA256_Update(&ctx, tmpBuffer, lineLen);
		}
		lineLen -= MESSAGE_CHUNK;
		tmpBuffer += MESSAGE_CHUNK;
	}

	SHA256_Final(finalDigest, &ctx);
	return finalDigest;
}

int main(int argc, char** argv) {
	unsigned char givenMessageDigest[] = {
		0xf5 ,0x03 ,0x74 ,0xf5 ,0xac ,0xb5 ,0x3c ,
		0x12 ,0x0a ,0x6b ,0x5f ,0x65 ,0xad ,0x78 ,
		0xfc ,0xf5 ,0x09 ,0xad ,0x17 ,0x43 ,0x38 ,
		0xbe ,0x42 ,0xdb ,0x4e ,0x26 ,0x94 ,0x45 ,
		0x68 ,0xe6 ,0xba ,0x20 };


	printf("Given message digest:\n");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X ", givenMessageDigest[i]);
		printf(" ");
	}

	printf("\n");

	char buf[MAX_LINE_LENGTH] = "";

	FILE* fileInput = argc > 1 ? fopen(argv[1], "r") : stdin;
	FILE* fileOuput = argc > 1 ? fopen("output.txt", "w") : stdout;

	if (!fileInput) {
		fprintf(stderr, "Error: file open failed '%s'!\n", argv[1]);
		return 1;
	}

	if (!fileOuput) {
		fprintf(stderr, "Error: file open failed for output!");
	}

	printf("BUNICA: %s", argv[1]);
	printf("\n");

	while (fscanf(fileInput, "%s\n", buf) != EOF) {
		//ex1
		unsigned char* messageDigestValue = generateSHA256Digest(buf, strlen(buf));

		if (memcmp(givenMessageDigest, messageDigestValue, SHA256_DIGEST_LENGTH) == 0) {
			printf("Parola cautata este: %s", buf);
			printf("\n");
		}

		//ex2
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			fprintf(fileOuput, "%02X ", messageDigestValue[i]);
		}
		fprintf(fileOuput, "\n");
	}

	if (fileInput != stdin) fclose(fileInput);
	if (fileOuput != stdout) fclose(fileOuput);
	return 0;
}



