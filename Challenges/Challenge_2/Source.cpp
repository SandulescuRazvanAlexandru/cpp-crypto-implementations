#include <iostream>
#include <openssl/sha.h>
#include <stdio.h>
#include <malloc.h>
#include <openssl/aes.h>


#define MAX_LINE_LENGTH 256
#define MESSAGE_CHUNK 256


void computeSha256(int fSize, unsigned char* buffer, char sha256[]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	unsigned char sha256digested[SHA256_DIGEST_LENGTH];

	unsigned char* tmpB = buffer;
	while (fSize > 0) {
		if (fSize > MESSAGE_CHUNK) {
			SHA256_Update(&ctx, tmpB, MESSAGE_CHUNK);
		}
		else {
			SHA256_Update(&ctx, tmpB, fSize);
		}
		fSize -= MESSAGE_CHUNK;
		tmpB += MESSAGE_CHUNK;
	}

	SHA256_Final(sha256digested, &ctx);
	printf("\n");
	for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
		sprintf(sha256 + (j * 2), "%02x", sha256digested[j]);
		printf("%02x", sha256digested[j]);
	}
}

void aesCbcEncrypt(char* keyFound, char accounts[]) {
	FILE* accFile = fopen(accounts, "rb");
	FILE* encAesFile = fopen("aesAccounts.enc", "wb"); //encrypted content of accounts.txt

	fseek(accFile, 0, SEEK_END);
	long int inputSize = ftell(accFile);
	fseek(accFile, 0, SEEK_SET);

	long int outLen = 0;
	if ((inputSize % 16) == 0) {
		outLen = inputSize;
	}
	else {
		outLen = ((inputSize / 16) * 16) + 16;
	}

	unsigned char* inputBuffer = (unsigned char*)malloc(outLen);
	unsigned char* outBuffer = (unsigned char*)malloc(outLen);

	memset(inputBuffer, 0x00, outLen);
	fread(inputBuffer, inputSize, 1, accFile);
	unsigned char IV[16];
	memset(&IV, 0x01, sizeof(IV));
	// ENCRYPTING AES:
	AES_KEY aesKEY;
	AES_set_encrypt_key((unsigned char*)keyFound, 128, &aesKEY);
	AES_cbc_encrypt(inputBuffer, outBuffer, outLen, &aesKEY, IV, AES_ENCRYPT);

	// WRITE IN  THE FILE
	// WRITE LENGTH
	fwrite(&inputSize, sizeof(inputSize), 1, encAesFile);
	fwrite(outBuffer, outLen, 1, encAesFile);
	free(outBuffer);
	free(inputBuffer);
	fclose(encAesFile);
	fclose(accFile);

}

void aesCbcDecrypt(char* keyFound, char accounts[]) {
	FILE* encAesFile = fopen(accounts, "rb");
	FILE* decAesFile = fopen("aesDecAccounts.txt", "wb"); //encrypted content of accounts.txt

	fseek(encAesFile, 0, SEEK_END);
	long int encFileSize = ftell(encAesFile) - 4;
	fseek(encAesFile, 0, SEEK_SET);

	long int outLen = 0;
	fread(&outLen, sizeof(outLen), 1, encAesFile);

	unsigned char* inputBuffer = (unsigned char*)malloc(encFileSize);
	unsigned char* outBuffer = (unsigned char*)malloc(encFileSize);

	memset(inputBuffer, 0x00, outLen);
	fread(inputBuffer, encFileSize, 1, encAesFile);
	unsigned char IV[16];
	memset(&IV, 0x01, sizeof(IV));
	// DECRYPTING AES:
	AES_KEY aesKEY;
	AES_set_decrypt_key((unsigned char*)keyFound, 128, &aesKEY);
	AES_cbc_encrypt(inputBuffer, outBuffer, outLen, &aesKEY, IV, AES_DECRYPT);

	fwrite(outBuffer, outLen, 1, decAesFile);
	free(inputBuffer);
	free(outBuffer);
	fclose(decAesFile);
	fclose(encAesFile);
}

bool checkFilesContent(char accounts[], char decAccounts[]) {
	//file input 1
	FILE* fileAccounts = fopen(accounts, "rb");
	unsigned char* bufferInput1;

	fseek(fileAccounts, 0, SEEK_END);
	long int file1Size = ftell(fileAccounts) - 4;
	fseek(fileAccounts, 0, SEEK_SET);

	//file input 2
	FILE* fileDecAccounts = fopen(decAccounts, "rb");
	unsigned char* bufferInput2;

	fseek(fileDecAccounts, 0, SEEK_END);
	long int file2Size = ftell(fileDecAccounts) - 4;
	fseek(fileDecAccounts, 0, SEEK_SET);

	if (file1Size != file2Size)
	{
		fclose(fileAccounts);
		fclose(fileDecAccounts);
		return false;
	}
	bufferInput1 = (unsigned char*)malloc(file1Size);
	bufferInput2 = (unsigned char*)malloc(file2Size);

	memset(bufferInput1, 0x00, file1Size);
	memset(bufferInput2, 0x00, file2Size);

	fread(bufferInput1, file1Size, 1, fileAccounts);
	fread(bufferInput2, file2Size, 1, fileDecAccounts);

	for (int i = 0; i < file1Size; i++) {
		if (bufferInput1[i] != bufferInput2[i]) {
			fclose(fileAccounts);
			fclose(fileDecAccounts);
			return false;
		}
	}

	fclose(fileAccounts);
	fclose(fileDecAccounts);
	return true;
}


int main() {
	char myShaValue[] = "356575284de335c0d02268c5b970f3ac8964e04a7e29068ecd2f1a81cfcb22b4";
	FILE* keyFile;
	char keyFName[] = "Keys/User%d.key";
	char* keyFound = (char*)malloc(65);

	//ex1
	for (int i = 1; i <= 72; i++) {
		char buffer[100];
		sprintf(buffer, keyFName, i);
		printf("\nWorking with key: %s", buffer);
		keyFile = fopen(buffer, "rb");
		fseek(keyFile, 0, SEEK_END);
		long fSize = ftell(keyFile);
		fseek(keyFile, 0, SEEK_SET);
		unsigned char* keyBuffer = (unsigned char*)malloc(fSize);
		fread(keyBuffer, fSize, 1, keyFile);

		char sha256[65];
		computeSha256(fSize, keyBuffer, sha256);
		if (strcmp(myShaValue, sha256) == 0) {
			keyFound = (char*)sha256;
			printf("\nKey File found %d with name %s", i, buffer);
			printf("\nFound key: %s", keyFound);
		}

		printf("\n");
		fclose(keyFile);
	}

	//ex2 - encrypt aes cbc
	char accounts[] = "Accounts.txt";
	aesCbcEncrypt(keyFound, accounts);

	//ex3 - decrypt aes cbc
	char encAccounts[] = "aesAccounts.enc";
	aesCbcDecrypt(keyFound, encAccounts);

	char decAccounts[] = "aesDecAccounts.txt";
	bool check = checkFilesContent(accounts, decAccounts);
	if (check) {
		printf("\nThe files match!");
	}
	else {
		printf("\nThe files don't match!");
	}

	return 0;
}
