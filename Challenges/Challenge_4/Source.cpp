#include <stdio.h>
#include <malloc.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

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
	//printf("%d\n", fileLength);

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

void decryptAES(FILE* encryptedFile, FILE* decryptedFile, FILE* keyFile) {
	fseek(encryptedFile, 0, SEEK_END);
	long int encryptedFileLength = ftell(encryptedFile) - 4;
	fseek(encryptedFile, 0, SEEK_SET);
	long int decryptedFileLength = 0;
	fread(&decryptedFileLength, sizeof(decryptedFileLength), 1, encryptedFile);
	//printf("%d\n", encryptedFileLength);
	//printf("%d\n", decryptedFileLength);

	unsigned char* inputBuffer = (unsigned char*)malloc(encryptedFileLength);
	unsigned char* outputBuffer = (unsigned char*)malloc(encryptedFileLength);
	memset(inputBuffer, 0x00, encryptedFileLength);
	fread(inputBuffer, encryptedFileLength, 1, encryptedFile);

	unsigned char fileDecryptionKey[KEY_LENGTH];
	fread(fileDecryptionKey, 1, 128, keyFile);
	//printHash(fileDecryptionKey);

	AES_KEY aesKey;
	unsigned char IV[KEY_LENGTH];
	AES_set_decrypt_key(fileDecryptionKey, 128, &aesKey);
	memset(&IV, 0x01, sizeof(IV));
	AES_cbc_encrypt(inputBuffer, outputBuffer, encryptedFileLength, &aesKey, IV, AES_DECRYPT);
	fwrite(outputBuffer, decryptedFileLength, 1, decryptedFile);

	free(outputBuffer);
	free(inputBuffer);
}

void encryptAES(FILE* initialFile, FILE* encryptedFile, FILE* keyFile) {
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
}

void decryptRSA(FILE* encryptedFile, FILE* decryptedFile, int decryptedFileSize, FILE* privateKeyFile) {
	RSA* privateKey;
	privateKey = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
	int privateKeySize = RSA_size(privateKey);

	unsigned char* e_data = NULL;
	unsigned char* last_data = NULL;

	e_data = (unsigned char*)malloc(privateKeySize);
	last_data = (unsigned char*)malloc(privateKeySize);

	fseek(encryptedFile, 0, SEEK_END);
	int encryptedFileLength = ftell(encryptedFile);
	fseek(encryptedFile, 0, SEEK_SET);

	int maxChunks = encryptedFileLength / privateKeySize;
	int currentChunk = 1;

	if (encryptedFileLength != privateKeySize) {
		while (fread_s(e_data, privateKeySize, sizeof(unsigned char), privateKeySize, encryptedFile) == privateKeySize) {
			if (currentChunk != maxChunks) {
				RSA_private_decrypt(privateKeySize, e_data, last_data, privateKey, RSA_NO_PADDING);
				fwrite(last_data, sizeof(unsigned char), privateKeySize, decryptedFile);
				currentChunk++;
			}
		}
	}
	else {
		fread_s(e_data, privateKeySize, sizeof(unsigned char), privateKeySize, encryptedFile);
	}

	RSA_private_decrypt(privateKeySize, e_data, last_data, privateKey, RSA_PKCS1_PADDING);
	fwrite(last_data, sizeof(unsigned char), decryptedFileSize % privateKeySize, decryptedFile);
	//printHash(e_data);
	//fwrite(last_data, sizeof(unsigned char), privateKeySize, decryptedFile);

	free(last_data);
	free(e_data);

	RSA_free(privateKey);
}

bool verifySignature(FILE* signatureFile, FILE* publicKeyFile, unsigned char* hashValue) {
	RSA* publicKey;

	unsigned char* buffer = NULL;
	unsigned char* last_data = NULL;

	publicKey = RSA_new();
	publicKey = PEM_read_RSAPublicKey(publicKeyFile, NULL, NULL, NULL);

	buffer = (unsigned char*)malloc(RSA_size(publicKey));

	fread(buffer, RSA_size(publicKey), 1, signatureFile);

	last_data = (unsigned char*)malloc(16);

	RSA_public_decrypt(RSA_size(publicKey), buffer, last_data, publicKey, RSA_PKCS1_PADDING);

	//printHash(last_data);
	//printf("\n");
	//printHash(hashValue);
	//printf("\n");

	bool result = (memcmp(last_data, hashValue, 16) == 0);

	//	free(last_data);
	//	free(buffer);

	RSA_free(publicKey);

	return result;
}

int main(int argc, char** argv)
{
	if (argc == 2) {
		{
			FILE* decryptedFile;
			FILE* encryptedFile;
			FILE* privateKeyFile;
			std::string rootDirectory = argv[1];
			std::string encryptedFileFilename = rootDirectory + "Session.key";
			std::string decryptedFileFilename = rootDirectory + "DecryptedSession.key";
			std::string privateKeyFileFilename = rootDirectory + "sStudent.pem";

			fopen_s(&encryptedFile, encryptedFileFilename.c_str(), "rb");
			fopen_s(&decryptedFile, decryptedFileFilename.c_str(), "wb");
			fopen_s(&privateKeyFile, privateKeyFileFilename.c_str(), "r");

			decryptRSA(encryptedFile, decryptedFile, KEY_LENGTH, privateKeyFile);

			fclose(decryptedFile);
			unsigned char fileContent[16];
			fopen_s(&decryptedFile, decryptedFileFilename.c_str(), "rb");
			fread(fileContent, sizeof(unsigned char), 16, decryptedFile);
			printf("1. Decrypted file content: ");
			for (int i = 0; i < 16; i++) {
				printf("%02X ", fileContent[i]);
			}
			printf("\n");

			fclose(encryptedFile);
			fclose(decryptedFile);
			fclose(privateKeyFile);
		}

		{
			FILE* decryptedFile;
			FILE* publicKeyFile;
			FILE* signatureFile;
			std::string rootDirectory = argv[1];
			std::string decryptedFileFilename = rootDirectory + "DecryptedSession.key";
			std::string signatureFileFilename = rootDirectory + "sfile.sign";
			std::string publicKeyFileFilename = rootDirectory + "pISM.pem";
			fopen_s(&decryptedFile, decryptedFileFilename.c_str(), "rb");
			fopen_s(&signatureFile, signatureFileFilename.c_str(), "rb");
			fopen_s(&publicKeyFile, publicKeyFileFilename.c_str(), "r");

			unsigned char keyHashValue[SHA256_DIGEST_LENGTH];
			generateFileHashValue(decryptedFile, keyHashValue);

			if (verifySignature(signatureFile, publicKeyFile, keyHashValue)) {
				printf("2. The decrypted key is valid.\n");
			}
			else {
				printf("2. The decrypted key is NOT valid.\n");
			}

			fclose(publicKeyFile);
			fclose(decryptedFile);
			fclose(signatureFile);
		}

		{
			FILE* decryptedFile;
			FILE* signatureFile;
			FILE* publicKeyFile;
			std::string rootDirectory = argv[1];
			std::string decryptedFileFilename = rootDirectory + "DecryptedSession.key";
			std::string signatureFileFilename = rootDirectory + "mfile.sign";
			std::string publicKeyFileFilename = rootDirectory + "pISM.pem";
			for (int i = 1; i <= 3; i++) {
				FILE* encryptedMessage;
				FILE* decryptedMessage;
				std::string encryptedMessageFilename = rootDirectory + "message" + std::to_string(i) + ".enc";
				std::string decryptedMessageFilename = rootDirectory + "message" + std::to_string(i) + ".dec";
				fopen_s(&encryptedMessage, encryptedMessageFilename.c_str(), "rb");
				fopen_s(&decryptedMessage, decryptedMessageFilename.c_str(), "wb");

				fopen_s(&decryptedFile, decryptedFileFilename.c_str(), "rb");
				fopen_s(&signatureFile, signatureFileFilename.c_str(), "rb");
				fopen_s(&publicKeyFile, publicKeyFileFilename.c_str(), "r");

				decryptAES(encryptedMessage, decryptedMessage, decryptedFile);

				fclose(decryptedMessage);
				fopen_s(&decryptedMessage, decryptedMessageFilename.c_str(), "rb");
				unsigned char keyHashValue[SHA256_DIGEST_LENGTH];
				generateFileHashValue(decryptedMessage, keyHashValue);
				if (verifySignature(signatureFile, publicKeyFile, keyHashValue)) {
					printf("3. Message number %d is valid.\n", i);
				}
				else {
					printf("3. Message number %d is NOT valid.\n", i);
				}

				fclose(encryptedMessage);
				fclose(decryptedMessage);
				fclose(decryptedFile);
				fclose(signatureFile);
			}
		}

		{
			FILE* resultFile;
			std::string rootDirectory = argv[1];
			std::string resultFileFilename = rootDirectory + "result.txt";
			std::string name = "Butnaru Ioan - Sorin\n";
			std::string result = "message3\n";

			std::ofstream resultOutput(resultFileFilename.c_str());
			resultOutput << name << result;
			resultOutput.close();

			FILE* initialFile;
			FILE* encryptedFile;
			FILE* keyFile;
			std::string encryptedFileFilename = rootDirectory + "result.enc";
			std::string keyFilename = rootDirectory + "DecryptedSession.key";
			fopen_s(&initialFile, resultFileFilename.c_str(), "rb");
			fopen_s(&encryptedFile, encryptedFileFilename.c_str(), "wb");
			fopen_s(&keyFile, keyFilename.c_str(), "rb");

			encryptAES(initialFile, encryptedFile, keyFile);

			fclose(initialFile);
			fclose(encryptedFile);
		}

		printf("\n\n");
	}
	else {
		printf("\n Usage Mode: Challenge3.exe filesDirectory \n\n");
		return 1;
	}

	return 0;
}
