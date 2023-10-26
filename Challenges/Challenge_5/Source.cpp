#include<iostream>
#include<stdlib.h>
#include<stdio.h>
#include<malloc.h>
#include<openssl/sha.h>
#include<openssl/rsa.h>
#include<openssl/applink.c>
#include<openssl/pem.h>
#include<openssl/aes.h>

#define MESSAGE_CHUNK 256
#define MESSAGE_CHUNK_SHA1 160

void computeSha256(int fileLen, unsigned char* buffer, char sha256[]) {
	SHA256_CTX ctx; //context for sha256
	SHA256_Init(&ctx); //init the hash
	unsigned char sha256Digest[SHA256_DIGEST_LENGTH * 2 + 1]; //where final hash is stored

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

	printf("SHA256 computed: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X", sha256Digest[i]);
		sprintf(sha256 + (i * 2), "%02X", sha256Digest[i]);
	}

	printf("\n");
}

void encryptAesCbc(long int inFileLen, unsigned char* password, unsigned char iv[16], FILE* cbcFileIn) {
	AES_KEY key;

	char* inBuffer = (char*)malloc(inFileLen);

	fread(inBuffer, inFileLen, 1, cbcFileIn); //the entire content of the plaintext file is added into inBuf

	AES_set_encrypt_key(password, 128, &key);  //set the key into internal OpenSSL structure used later in other OpenSSL API calls

	FILE* cbcFileOut = fopen("enclist.txt", "wb"); //ciphertext file

	char* line = strtok(_strdup(inBuffer), "\n");
	while (line) {
		long int lineLen = strlen(line);
		long int outFileLen = 0;

		if ((lineLen % 16) == 0)
			outFileLen = lineLen;
		else
			outFileLen = ((lineLen / 16) * 16) + 16; //adjusted input length according to number of blocks needed by AES algorithm

		unsigned char* outBuffer = (unsigned char*)malloc(outFileLen);
		printf("%s\n", line);
		AES_cbc_encrypt((unsigned char*)line, outBuffer, outFileLen, &key, iv, AES_ENCRYPT); //performs the encryption for AES-CBC for entire content
		for (int i = 0; i < outFileLen; i++) {
			fprintf(cbcFileOut, "%02X", outBuffer[i]);
		}
		fprintf(cbcFileOut, "\n", NULL);
		free(outBuffer);
		line = strtok(NULL, "\n");
	}

	free(inBuffer);
	
	fclose(cbcFileIn);
	fclose(cbcFileOut);
}

void encryptRsa(long int inFileLen, FILE* inFile, FILE* pubKeyFile) {
	RSA* pubKey = RSA_new();

	pubKey = PEM_read_RSAPublicKey(pubKeyFile, NULL, NULL, NULL); //loads the public key (components) into RSA internal structure
	fclose(pubKeyFile);

	unsigned char* inBuffer = (unsigned char*)malloc(RSA_size(pubKey) + 1);
	inBuffer[RSA_size(pubKey)] = 0x00;
	unsigned char* eData = (unsigned char*)malloc(RSA_size(pubKey));

	FILE* outFile = fopen("Enclist_RSA.txt", "wb");

	if (inFileLen != RSA_size(pubKey)) {
		//for large files
		while (fread_s(inBuffer, RSA_size(pubKey), sizeof(unsigned char), RSA_size(pubKey), inFile) == RSA_size(pubKey)) {
			RSA_public_encrypt(RSA_size(pubKey), inBuffer, eData, pubKey, RSA_NO_PADDING); //encryption for a complete input data block by using the public key; no padding is required
			fwrite(eData, sizeof(unsigned char), RSA_size(pubKey), outFile); // write the result of encryption (encrypted data block) into enc file
		}
	}
	else {
		//for small file
		fread_s(inBuffer, RSA_size(pubKey), sizeof(unsigned char), RSA_size(pubKey), inFile);
	}

	RSA_public_encrypt(inFileLen % RSA_size(pubKey), inBuffer, eData, pubKey, RSA_PKCS1_PADDING); //encryption for the incomplete last input data block; the completion is made by the padding at content level
	fwrite(eData, sizeof(unsigned char), RSA_size(pubKey), outFile); //write the result of last last block encryption into enc file

	free(inBuffer);
	free(eData);
	RSA_free(pubKey);

	fclose(outFile);
	fclose(inFile);
}

void computeSha1(int fileLen, FILE* file) {
	SHA_CTX ctx; //context for sha1
	SHA_Init(&ctx); //init the hash
	unsigned char sha1Digest[SHA_DIGEST_LENGTH]; //where final hash is stored

	unsigned char* inBuffer = (unsigned char*)malloc(fileLen);
	fread(inBuffer, fileLen, 1, file);

	unsigned char* tempBuffer = inBuffer; //copy buffer into a temp one

	while (fileLen > 0) {
		if (fileLen > MESSAGE_CHUNK_SHA1) {
			SHA_Update(&ctx, tempBuffer, MESSAGE_CHUNK_SHA1); //update with MESSAGE_CHUNK value (128)
		}
		else {
			SHA_Update(&ctx, tempBuffer, fileLen); //update with a value <= than 128
		}
		fileLen -= MESSAGE_CHUNK_SHA1;
		tempBuffer += MESSAGE_CHUNK_SHA1;
	}

	SHA1_Final(sha1Digest, &ctx); //finalize the hash

	printf("SHA1 computed: ");
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf("%02X", sha1Digest[i]);
	}

	printf("\n");
}

int main() {
	//ex 1 - decrypt hfile.sign and get the result as a sha

	FILE* signFile = fopen("hfile.sign", "rb");
	FILE* pemFile = fopen("pExam.pem", "r");

	if (signFile && pemFile) {
		fseek(signFile, 0, SEEK_END);
		long int signFileLen = ftell(signFile);
		fseek(signFile, 0, SEEK_SET);

		RSA* pubKey = RSA_new();

		pubKey = PEM_read_RSAPublicKey(pemFile, NULL, NULL, NULL); //loads the public key (components) into RSA internal structure
		fclose(pemFile);

		unsigned char* encBuffer = (unsigned char*)malloc(signFileLen);
		fread(encBuffer, signFileLen, 1, signFile);
		fclose(signFile);
		unsigned char* decBuffer = (unsigned char*)malloc(RSA_size(pubKey));

		RSA_public_decrypt(RSA_size(pubKey), encBuffer, decBuffer, pubKey, RSA_PKCS1_PADDING); // decryption of the last (incomplete) encrypted data block; padding required

		free(encBuffer);
		RSA_free(pubKey);

		char sha256[SHA256_DIGEST_LENGTH * 2 + 1];
		computeSha256(SHA256_DIGEST_LENGTH, decBuffer, sha256);

		free(decBuffer);

		//ex2 - ecrypt wordlist.txt with aes cbc
		FILE* wordsFile = fopen("wordlist.txt", "rb");

		if (wordsFile) {
			fseek(wordsFile, 0, SEEK_END);
			long int wordsFileLen = ftell(wordsFile);
			fseek(wordsFile, 0, SEEK_SET);

			unsigned char iv[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
			unsigned char* password = (unsigned char*)malloc(16);

			memcpy(password, sha256, 16);

			encryptAesCbc(wordsFileLen, password, iv, wordsFile);
			free(password);
		}
		else {
			printf("Error when opening wordlist file\n");
			return -1;
		}

		//ex 3 - excrypt enclist.txt with RSA
		FILE* enclistFile = fopen("enclist.txt", "rb");
		pemFile = fopen("pExam.pem", "r");
		if (enclistFile && pemFile) {
			fseek(enclistFile, 0, SEEK_END);
			long int enclistLen = ftell(enclistFile);
			fseek(enclistFile, 0, SEEK_SET);

			//ex 4 - compute sha1 for enclist.txt
			computeSha1(enclistLen, enclistFile);

			encryptRsa(enclistLen, enclistFile, pemFile);
		}
		else {
			printf("Error when opening either enclist file or pem file\n");
			return -2;
		}
	}
	else {
		printf("Error when opening either sign file or pem file\n");
		return 1;
	}

	return 0;
}