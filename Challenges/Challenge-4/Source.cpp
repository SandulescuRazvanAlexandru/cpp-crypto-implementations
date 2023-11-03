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

unsigned char* decryptAesCbc(long int encFileLen, unsigned char password[16], unsigned char iv[16], FILE* encFile) {
	AES_KEY key;

	unsigned char* encBuffer = (unsigned char*)malloc(encFileLen); //entire ciphertext is allocated and read from the ciphertext input file
	unsigned char* decBuffer = (unsigned char*)malloc(encFileLen); //buffer for the restored plaintext
	fread(encBuffer, encFileLen, 1, encFile);

	AES_set_decrypt_key(password, 128, &key); //load the decription key into AES_KEY structure

	AES_cbc_encrypt(encBuffer, decBuffer, encFileLen, &key, iv, AES_DECRYPT); // same name like in the enc case; performs decription of the entire ciphertext

	free(encBuffer);
	fclose(encFile);
	
	return decBuffer;
}

void computeSha256(int fileLen, FILE* file, char sha256[]) {
	SHA256_CTX ctx; //context for sha256
	SHA256_Init(&ctx); //init the hash
	unsigned char sha256Digest[SHA256_DIGEST_LENGTH * 2 + 1]; //where final hash is stored

	unsigned char* buffer = (unsigned char*)malloc(fileLen);
	fread(buffer, fileLen, 1, file);
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

	printf("SHA256 computed for Messages.txt: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02X", sha256Digest[i]);
		sprintf(sha256 + (i * 2), "%02X", sha256Digest[i]);
	}
	fclose(file);

	printf("\n");
}


int main() {
	//ex1 - decrypt content of sha256Enc.txt with AES CBC
	FILE* encSha256File = fopen("sha256Enc.txt", "rb");
	if (encSha256File) {
		fseek(encSha256File, 0, SEEK_END);
		long int encShaFileLen = ftell(encSha256File);
		fseek(encSha256File, 0, SEEK_SET);

		unsigned char iv[16] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
		unsigned char password[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07 };

		unsigned char* decryptedSha256 = decryptAesCbc(encShaFileLen, password, iv, encSha256File);

		printf("Decrypted result as SHA256: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			printf("%02X", decryptedSha256[i]);
		}
		printf("\n\n");

		//ex2 - compute sha256 on messages.txt and compare the 2 sha values
		FILE* messageFile = fopen("Message.txt", "rb");
		if (messageFile) {
			fseek(messageFile, 0, SEEK_END);
			long int messageFileLen = ftell(messageFile);
			fseek(messageFile, 0, SEEK_SET);

			char sha256MsgFile [SHA256_DIGEST_LENGTH * 2 + 1];
			computeSha256(messageFileLen, messageFile, sha256MsgFile);

			int compare = memcmp(sha256MsgFile, decryptedSha256, sizeof(sha256MsgFile));
			if (compare == 0) {
				printf("The sha values are the same\n");
			}
			else {
				printf("The sha values are different\n");
			}
		}
		else {
			printf("Error when opening message file\n");
			return -1;
		}

		free(decryptedSha256);
	}
	else {
		printf("Error when opening sha256 enc file\n");
		return 1;
	}

	return 0;
}