#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

int main() {

	//===Decrypt Session_key.enc to get the plaintext content as an AES-CBC key. Print the key content in hexa into the Console Application===//
	FILE* privateFileKey = fopen("sStudent.pem", "r");
	RSA* apriv = PEM_read_RSAPrivateKey(privateFileKey, NULL, NULL, NULL);
	fclose(privateFileKey);

	unsigned char* encryptionKey = (unsigned char*)malloc(RSA_size(apriv));
	unsigned char* decryptionKey = (unsigned char*)malloc(RSA_size(apriv));

	FILE* sessionKeyEnc = NULL;
	errno_t err = fopen_s(&sessionKeyEnc, "Session_key.enc", "rb");
	unsigned char decryptionKeyHexArray[16];
	if (!err) {
		fseek(sessionKeyEnc, 0, SEEK_END);
		fseek(sessionKeyEnc, 0, SEEK_SET);

		int keySize = ftell(sessionKeyEnc);
		int maxChunks = keySize / RSA_size(apriv);
		int currentChunk = 1;

		if (keySize != RSA_size(apriv)) {
			while (fread_s(encryptionKey, RSA_size(apriv), sizeof(unsigned char), RSA_size(apriv), sessionKeyEnc) == RSA_size(apriv)) {
				if (currentChunk != maxChunks) {
					RSA_private_decrypt(RSA_size(apriv), encryptionKey, decryptionKey, apriv, RSA_NO_PADDING);
					++currentChunk;
				}
			}
		}
		else {
			fread_s(encryptionKey, RSA_size(apriv), sizeof(unsigned char), RSA_size(apriv), sessionKeyEnc);
		}

		RSA_private_decrypt(RSA_size(apriv), encryptionKey, decryptionKey, apriv, RSA_PKCS1_PADDING);

		for (int i = 0; i < 16; ++i) { // 0..15 hex
			decryptionKeyHexArray[i] = decryptionKey[i];
			printf("%02X ", decryptionKeyHexArray[i]);
		}

		printf("\n\n");

		free(encryptionKey);
		free(decryptionKey);
		fclose(sessionKeyEnc);
	}
	else {
		printf("Error at Session_key.enc");
		return -1;
	}

	//===Validate the AES-CBC key is the intended one by using file.sign. Print the validation statement into the Console Application.Message digest algorithm used was SHA - 256, and the encryption used was RSA, PKCS1 padding===//
	FILE* publicKeyFile = fopen("pISM.pem", "r");
	RSA* apub = PEM_read_RSAPublicKey(publicKeyFile, NULL, NULL, NULL);
	fclose(publicKeyFile);

	FILE* fileSign = NULL;
	err = fopen_s(&fileSign, "file.sign", "rb");
	if (!err) {
		unsigned char* buf = (unsigned char*)malloc(RSA_size(apub));
		if (buf) {
			fread(buf, RSA_size(apub), 1, fileSign);

			unsigned char* keySign = (unsigned char*)malloc(32); // 32 bytes: SHA-256 => 256 bits => 32 bytes
			if (keySign != 0) {
				RSA_public_decrypt(RSA_size(apub), buf, keySign, apub, RSA_PKCS1_PADDING);

				SHA256_CTX ctx;
				unsigned char finalDigest[SHA256_DIGEST_LENGTH];
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, decryptionKeyHexArray, sizeof(decryptionKeyHexArray));
				SHA256_Final(finalDigest, &ctx);

				if (!memcmp(keySign, finalDigest, 32))
					printf("Valid!");
				else
					printf("NOT Valid!");

				printf("\n\n");

				free(buf);
				fclose(fileSign);
				free(keySign);
			}
			else {
				printf("Error at keySign");
				return -1;
			}
		}
		else {
			printf("Error at buf");
			return -1;
		}
	}
	else {
		printf("Error at fileSign");
		return -1;
	}

	//===Decrypt message.enc by using AES-CBC with the restored and validated AES key. The IV has value 0x01 for each byte.Print out to Console Application the plaintext after decryption===//
	FILE* fSrc = fopen("message.enc", "rb");
	fseek(fSrc, 0, SEEK_END);

	long int inLen = ftell(fSrc) - 4;
	fseek(fSrc, 0, SEEK_SET);

	long int outLen = 0;
	fread(&outLen, sizeof(outLen), 1, fSrc);

	unsigned char* inBuf = (unsigned char*)malloc(inLen);
	if (inBuf) {
		unsigned char* outBuf = (unsigned char*)malloc(inLen);
		if (outBuf) {
			memset(inBuf, 0x00, inLen);
			fread(inBuf, inLen, 1, fSrc);

			AES_KEY akey;
			AES_set_decrypt_key(decryptionKeyHexArray, 128, &akey);

			unsigned char ivec[16];
			memset(&ivec, 0x01, sizeof(ivec));

			AES_cbc_encrypt(inBuf, outBuf, inLen, &akey, ivec, AES_DECRYPT);

			printf("%s\n", outBuf);

			free(inBuf);
			free(outBuf);
			fclose(fSrc);
		}
		else {
			printf("Error at outBuf");
			return -1;
		}
	}
	else {
		printf("Error at inBuf");
		return -1;
	}

	return 0;
}