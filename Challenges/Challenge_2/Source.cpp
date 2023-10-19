#include <stdio.h>
#include <malloc.h>
#include <openssl/sha.h>
#include <vector>
#include <iostream>

void generateDigest(char* value, unsigned char& finalDigest) {
	SHA256_CTX ctx;
	int passwordLength = strlen(value);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, value, passwordLength);
	SHA256_Final(&finalDigest, &ctx);
}

int main(int argc, char** argv)
{
	if (argc == 2) {

		FILE* inputFile = NULL;
		FILE* outputFile = NULL;
		errno_t err;

		unsigned char* fileBuffer = NULL;
		unsigned char finalDigest[SHA256_DIGEST_LENGTH];
		unsigned char searchedDigest[] = {
			0xF5, 0x03, 0x74, 0xF5, 0xAC, 0xB5, 0x3C, 0x12,
			0x0A, 0x6B, 0x5F, 0x65, 0xAD, 0x78, 0xFC, 0xF5,
			0x09, 0xAD, 0x17, 0x43, 0x38, 0xBE, 0x42, 0xDB,
			0x4E, 0x26, 0x94, 0x45, 0x68, 0xE6, 0xBA, 0x20
		};
		/*
		int count = 0;
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			printf("%02X", searchedDigest[i]);
			printf(" ");
		}
		printf("\n");
		return 0;
		*/

		// Exercise 1
		// Password: woohooinwonderland
		err = fopen_s(&inputFile, argv[1], "rb");
		if (err == 0) {
			fseek(inputFile, 0, SEEK_END);
			int fileLength = ftell(inputFile);
			//fseek(inputFile, 7700000, SEEK_SET);
			fseek(inputFile, 0, SEEK_SET);

			fileBuffer = (unsigned char*)malloc(fileLength);
			fread(fileBuffer, fileLength, 1, inputFile);

			char* nextPassword;
			char* password = strtok_s((char*)fileBuffer, "\n", &nextPassword);
			while (password != NULL) {
				printf("\r%-25s ", password);

				generateDigest(password, *finalDigest);

				int count = 0;
				for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
					printf("%02X", finalDigest[i]);
					printf(" ");
				}
				//printf("\r");

				if (memcmp(searchedDigest, finalDigest, SHA256_DIGEST_LENGTH) == 0) {
					printf("\nDigest found!\n");
					printf("Password: %s\n", password);
					printf("Password SHA-256: ");
					int count = 0;
					for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
						printf("%02X", finalDigest[i]);
						printf(" ");
					}
					printf("\n");
					printf("Searched SHA-256: ");
					for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
						printf("%02X", searchedDigest[i]);
						printf(" ");
					}
					printf("\n");

					break;
				}
				password = strtok_s(NULL, "\n", &nextPassword);
			}

			fclose(inputFile);
		}


		// Exercise 2
		char outputFilePath[] = "output.txt";
		err = fopen_s(&inputFile, argv[1], "rb");
		err = fopen_s(&outputFile, outputFilePath, "wb");
		printf("\nWriting digest file...\n");
		if (err == 0) {
			fseek(inputFile, 0, SEEK_END);
			int fileLength = ftell(inputFile);
			fseek(inputFile, 0, SEEK_SET);

			fileBuffer = (unsigned char*)malloc(fileLength);
			fread(fileBuffer, fileLength, 1, inputFile);

			char* nextPassword;
			char* password = strtok_s((char*)fileBuffer, "\n", &nextPassword);
			while (password != NULL) {
				printf("\r%-25s ", password);

				generateDigest(password, *finalDigest);

				int count = 0;
				for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
					printf("%02X", finalDigest[i]);
					printf(" ");
				}
				//printf("\r");

				for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
					fprintf(outputFile, "%02X", finalDigest[i]);
					fprintf(outputFile, " ");
				}
				fprintf(outputFile, "\n");

				password = strtok_s(NULL, "\n", &nextPassword);
			}

			fclose(inputFile);
		}

	}
	else {
		printf("\n Usage Mode: SHA1.exe fSrc.txt \n\n");
		return 1;
	}

	return 0;
}
