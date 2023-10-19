#include <stdio.h>
#include <malloc.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <vector>
#include <string>
#include <iostream>

#define MESSAGE_CHUNK 160 
#define KEY_LENGTH 16

void printHash(unsigned char hash[]) {
	int count = 0;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X ", hash[i]);
	}
}

void generateFileHashValue(FILE* file, unsigned char* hash) {
	unsigned char* fileBuffer = NULL;
	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	fseek(file, 0, SEEK_END);
	int fileLength = ftell(file);
	fseek(file, 0, SEEK_SET);

	fileBuffer = (unsigned char*)malloc(fileLength);
	fread(fileBuffer, fileLength, 1, file);
	unsigned char* tmpBuffer = fileBuffer;

	while (fileLength > 0) {
		if (fileLength > MESSAGE_CHUNK) {
			SHA256_Update(&ctx, tmpBuffer, MESSAGE_CHUNK);
		}
		else {
			SHA256_Update(&ctx, tmpBuffer, fileLength);
		}
		fileLength -= MESSAGE_CHUNK;
		tmpBuffer += MESSAGE_CHUNK;
	}

	SHA256_Final(hash, &ctx);

}

bool verifyFileHashValue(FILE* file, unsigned char* hashValue) {
	unsigned char fileDigest[SHA256_DIGEST_LENGTH];
	generateFileHashValue(file, fileDigest);

	return (memcmp(hashValue, fileDigest, SHA256_DIGEST_LENGTH) == 0);
}


int main(int argc, char** argv)
{
	if (argc == 3) {
		FILE* keyDirectoryPath = NULL;
		errno_t errorCode;

		unsigned char accountHash[] = {
			0x93, 0x01, 0x63, 0xC0, 0x6B, 0xE0, 0x55, 0xB4,
			0x8A, 0x24, 0xFD, 0x40, 0x9D, 0x2F, 0xC2, 0x23,
			0xE5, 0x24, 0x18, 0xC3, 0x3E, 0x48, 0x81, 0x2A,
			0xB0, 0x96, 0x1D, 0x2E, 0x37, 0x7C, 0x4D, 0xD8
		};

		// Exercise 1
		// Key: User28.key
		FILE* inputFile = NULL;
		int keyCount = 72;
		std::string foundKey;
		for (int keyNumber = 1; keyNumber <= keyCount; keyNumber++) {
			char filename[20];
			sprintf_s(filename, 20, "User%d.key", keyNumber);
			std::string filenameString = filename;

			std::string keyFilePath = argv[1] + filenameString;

			errorCode = fopen_s(&inputFile, keyFilePath.c_str(), "rb");
			if (!errorCode) {
				bool result = verifyFileHashValue(inputFile, accountHash);
				if (result) {
					foundKey = filenameString;
					printf("Account key found: %s\n", filenameString.c_str());
					printf("Hash value: ");
					unsigned char tempDigest[SHA256_DIGEST_LENGTH];
					generateFileHashValue(inputFile, tempDigest);
					printHash(tempDigest);
					printf("\n");
				}
			}
			else {
				printf("Error opening file: %s. Error code: %s\n", keyFilePath.c_str(), errorCode);
			}
			fclose(inputFile);
		}


		// Exercise 2
		{
			FILE* initialFile;
			FILE* encryptedFile;
			std::string initialFileFilename = argv[2];
			std::string encryptedFileFilename = "Encrypted" + initialFileFilename;
			fopen_s(&initialFile, initialFileFilename.c_str(), "rb");
			fopen_s(&encryptedFile, encryptedFileFilename.c_str(), "wb");

			fseek(initialFile, 0, SEEK_END);
			long int initialFileLength = ftell(initialFile);
			fseek(initialFile, 0, SEEK_SET);
			long int encryptedFileLength = 0;
			if ((initialFileLength % KEY_LENGTH) == 0) {
				encryptedFileLength = initialFileLength;
			}
			else {
				encryptedFileLength = ((initialFileLength / KEY_LENGTH) * KEY_LENGTH) + KEY_LENGTH;
			}

			unsigned char* inputBuffer = (unsigned char*)malloc(encryptedFileLength);
			unsigned char* outputBuffer = (unsigned char*)malloc(encryptedFileLength);
			memset(inputBuffer, 0x00, encryptedFileLength);
			fread(inputBuffer, initialFileLength, 1, initialFile);

			unsigned char fileEncryptionKey[KEY_LENGTH];
			FILE* keyFile;
			std::string keyFilePath = argv[1] + foundKey;
			fopen_s(&keyFile, keyFilePath.c_str(), "rb");
			fread(fileEncryptionKey, 1, 128, keyFile);
			//printHash(fileEncryptionKey);

			AES_KEY aesKey;
			unsigned char IV[KEY_LENGTH];
			AES_set_encrypt_key(fileEncryptionKey, 128, &aesKey);
			memset(&IV, 0x01, sizeof(IV));
			AES_cbc_encrypt(inputBuffer, outputBuffer, encryptedFileLength, &aesKey, IV, AES_ENCRYPT);

			fwrite(&initialFileLength, sizeof(initialFileLength), 1, encryptedFile);
			fwrite(outputBuffer, encryptedFileLength, 1, encryptedFile);

			free(inputBuffer);
			free(outputBuffer);
			fclose(initialFile);
			fclose(encryptedFile);
		}

		// Exercise 3
		{
			FILE* initialFile;
			FILE* encryptedFile;
			FILE* decryptedFile;
			std::string initialFileFilename = argv[2];
			std::string encryptedFileFilename = "Encrypted" + initialFileFilename;
			std::string decryptedFileFilename = "Decrypted" + initialFileFilename;

			fopen_s(&encryptedFile, encryptedFileFilename.c_str(), "rb");
			fopen_s(&decryptedFile, decryptedFileFilename.c_str(), "wb");
			fseek(encryptedFile, 0, SEEK_END);

			long int encryptedFileLength = ftell(encryptedFile) - 4;
			fseek(encryptedFile, 0, SEEK_SET);
			long int decryptedFileLength = 0;
			fread(&decryptedFileLength, sizeof(decryptedFileLength), 1, encryptedFile);

			unsigned char* inputBuffer = (unsigned char*)malloc(encryptedFileLength);
			unsigned char* outputBuffer = (unsigned char*)malloc(encryptedFileLength);
			memset(inputBuffer, 0x00, encryptedFileLength);
			fread(inputBuffer, encryptedFileLength, 1, encryptedFile);

			unsigned char fileDecryptionKey[KEY_LENGTH];
			FILE* keyFile;
			std::string keyFilePath = argv[1] + foundKey;
			fopen_s(&keyFile, keyFilePath.c_str(), "rb");
			fread(fileDecryptionKey, 1, 128, keyFile);
			//printHash(fileEncryptionKey);

			AES_KEY aesKey;
			unsigned char IV[KEY_LENGTH];
			AES_set_decrypt_key(fileDecryptionKey, 128, &aesKey);
			memset(&IV, 0x01, sizeof(IV));
			AES_cbc_encrypt(inputBuffer, outputBuffer, encryptedFileLength, &aesKey, IV, AES_DECRYPT);
			fwrite(outputBuffer, decryptedFileLength, 1, decryptedFile);

			free(outputBuffer);
			free(inputBuffer);
			fclose(decryptedFile);
			fclose(encryptedFile);
		}
		// Check if the files are the same
		{
			FILE* initialFile;
			FILE* decryptedFile;
			std::string initialFileFilename = argv[2];
			std::string decryptedFileFilename = "Decrypted" + initialFileFilename;

			fopen_s(&initialFile, initialFileFilename.c_str(), "rb");
			fopen_s(&decryptedFile, decryptedFileFilename.c_str(), "rb");

			unsigned char initialFileHash[SHA256_DIGEST_LENGTH];
			unsigned char decryptedFileHash[SHA256_DIGEST_LENGTH];

			generateFileHashValue(initialFile, initialFileHash);
			generateFileHashValue(decryptedFile, decryptedFileHash);

			printHash(initialFileHash);
			printf("\n");
			printHash(decryptedFileHash);
			printf("\n");

			if (memcmp(&initialFileHash, &decryptedFileHash, SHA256_DIGEST_LENGTH) == 0) {
				printf("The files are the same.\n");
			}
			else {
				printf("The files are different.\n");
			}

			fclose(decryptedFile);
			fclose(initialFile);
		}
		printf("\n\n");
	}
	else {
		printf("\n Usage Mode: SHA1.exe fSrc.txt \n\n");
		return 1;
	}

	return 0;
}
