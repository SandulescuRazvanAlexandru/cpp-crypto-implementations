#include <stdio.h>
#include <iostream>
#include <openssl/ssl.h>
#include <malloc.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/aes.h>


#define MESSAGE_CHUNK 256

void computeSHA256(int fSize, unsigned char* buffer, char sha256[]) {
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
	for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
		sprintf(sha256 + (j * 2), "%02x", sha256digested[j]);
		//printf("%02x", sha256digested[j]);
	}

}

char* decryptSession(char sessionKey[], char privateKey[]) {

	char privateKeyS[] = "sStudent.pem";
	FILE* privateKEY;
	RSA* privateRSAKEY = RSA_new();
	privateKEY = fopen(privateKeyS, "r");
	if (privateKEY == NULL) {
		printf("\nCan't open the file!\n");
	}
	privateRSAKEY = PEM_read_RSAPrivateKey(privateKEY, NULL, NULL, NULL);

	fclose(privateKEY);

	// Session file data
	unsigned char* sessionData = (unsigned char*)malloc(RSA_size(privateRSAKEY));
	unsigned char* lastSessionData = (unsigned char*)malloc(RSA_size(privateRSAKEY));

	// OPEN FILE SESSIONKEY
	FILE* sessionKEY = fopen(sessionKey, "rb");
	fseek(sessionKEY, 0, SEEK_END);
	long int accSize2 = ftell(sessionKEY);
	fseek(sessionKEY, 0, SEEK_SET);

	int maxChunks = accSize2 / RSA_size(privateRSAKEY);
	int currentChunk = 1;

	if (accSize2 != RSA_size(privateRSAKEY)) {
		while (fread_s(sessionData, RSA_size(privateRSAKEY), sizeof(unsigned char), RSA_size(privateRSAKEY), sessionKEY) == RSA_size(privateRSAKEY)) { //read one single encrypted complete data block
			if (currentChunk != maxChunks) {
				RSA_private_decrypt(RSA_size(privateRSAKEY), sessionData, lastSessionData, privateRSAKEY, RSA_NO_PADDING);  //decpryption of the complete encrypted data block => no padding needed
				fwrite(lastSessionData, sizeof(unsigned char), RSA_size(privateRSAKEY), sessionKEY);
				currentChunk++;
			}
		}
	}
	else {
		fread_s(sessionData, RSA_size(privateRSAKEY), sizeof(unsigned char), RSA_size(privateRSAKEY), sessionKEY);
	}


	// output file buffer
	unsigned char* outBuffer = (unsigned char*)malloc(RSA_size(privateRSAKEY));
	RSA_private_decrypt(RSA_size(privateRSAKEY), sessionData, outBuffer, privateRSAKEY, RSA_PKCS1_PADDING);

	printf("\n HEX VALUE: ");
	unsigned char* keyFinal = (unsigned char*)malloc(16);
	for (int i = 0; i < 16; i++) {
		printf("%02x", outBuffer[i]);
		keyFinal[i] = outBuffer[i];
	}


	// WRITE KEY into FILE
	FILE* decryptedKey = fopen("decryptedKey.key", "wb");
	fwrite(keyFinal, sizeof(unsigned char), RSA_size(privateRSAKEY), decryptedKey);
	fclose(decryptedKey);
	fclose(sessionKEY);
	RSA_free(privateRSAKEY);


	char* sha256Key = (char*)malloc(65);
	computeSHA256(16, keyFinal, sha256Key);

	return sha256Key;
}

bool checkSignFiles(char signFile[], char pubKey[], int len, char sha256Key[65]) {
	FILE* sigF = fopen(signFile, "rb");
	FILE* pubKEYF = fopen(pubKey, "rb");
	RSA* rsaPubKEY = RSA_new();
	rsaPubKEY = PEM_read_RSAPublicKey(pubKEYF, NULL, NULL, NULL);
	fclose(pubKEYF);
	unsigned char* inputBuffer = (unsigned char*)malloc(RSA_size(rsaPubKEY));
	memset(inputBuffer, 0x00, RSA_size(rsaPubKEY));
	fread(inputBuffer, RSA_size(rsaPubKEY), 1, sigF);
	fclose(sigF);
	unsigned char* outBuffer = (unsigned char*)malloc(len);
	RSA_public_decrypt(RSA_size(rsaPubKEY), inputBuffer, outBuffer, rsaPubKEY, RSA_PKCS1_PADDING);

	char sha256[65];
	for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
		sprintf(sha256 + (j * 2), "%02x", outBuffer[j]);

	}

	RSA_free(rsaPubKEY);

	if (memcmp(sha256, sha256Key, len) == 0) {
		printf("\n Signature Verifyed!\n");
		return true;
	}

	return false;
}

void decryptMessages(char mFileEnc[], char* sha256Key, char mFileSign[], char pubKey[], int nr) {
	//decrypt the message file
	FILE* mFEnc = fopen(mFileEnc, "rb"); //the current message.enc file

	char decMsgFile[30];
	sprintf(decMsgFile, "%d.txt", nr);
	FILE* mFDec = fopen(decMsgFile, "wb");

	//aes decryption with restored key
	fseek(mFEnc, 0, SEEK_END);
	long int msgEncSize = ftell(mFEnc) - 4;
	fseek(mFEnc, 0, SEEK_SET);

	long int outLen = 0;
	fread(&outLen, sizeof(outLen), 1, mFEnc);

	unsigned char* inputBuffer = (unsigned char*)malloc(msgEncSize);
	unsigned char* outBuffer = (unsigned char*)malloc(msgEncSize);

	memset(inputBuffer, 0x00, outLen);
	fread(inputBuffer, msgEncSize, 1, mFEnc);
	unsigned char IV[16];
	memset(&IV, 0x01, sizeof(IV));
	// DECRYPTING AES:
	AES_KEY aesKEY;
	AES_set_decrypt_key((unsigned char*)sha256Key, 128, &aesKEY);
	AES_cbc_encrypt(inputBuffer, outBuffer, outLen, &aesKEY, IV, AES_DECRYPT);

	fwrite(outBuffer, outLen, 1, mFDec);

	char msgShaValue[65];

	//compute sha value for the message file
	computeSHA256(outLen, outBuffer, msgShaValue);

	//open sign file
	FILE* mFSign = fopen(mFileSign, "rb"); //open mfile.sign
	FILE* pubKEYF = fopen(pubKey, "r");  //open pISM.pem
	RSA* rsaPubKEY = RSA_new();
	rsaPubKEY = PEM_read_RSAPublicKey(pubKEYF, NULL, NULL, NULL);

	unsigned char* signBuffer = (unsigned char*)malloc(RSA_size(rsaPubKEY));
	fread(signBuffer, RSA_size(rsaPubKEY), 1, mFSign);

	unsigned char* decSignBuffer = (unsigned char*)malloc(16);

	RSA_public_decrypt(RSA_size(rsaPubKEY), signBuffer, decSignBuffer, rsaPubKEY, RSA_PKCS1_PADDING);

	char signShaValue[65];

	//compute sha value for the msign file
	computeSHA256(16, decSignBuffer, signShaValue);

	if (memcmp(signShaValue, msgShaValue, 32) == 0) {
		printf("\nThe correct message file is %s: ", mFileEnc);
	}


	//free(inputBuffer);
	//free(outBuffer);
	//free(signBuffer);
	//free(decSignBuffer);
	fclose(mFDec);
	fclose(mFEnc);
	fclose(mFSign);
	fclose(pubKEYF);
}


int main() {
	char sessionKey[] = "Session.key";
	char privateKey[] = "sStudent.pem";

	//ex1 - rsa decrypt
	char* sha256Key = (char*)malloc(65);
	sha256Key = decryptSession(sessionKey, privateKey);
	printf("\nDecrypted session key content :%s\n", sha256Key);

	//ex2 - validate sign
	char signFile[] = "sfile.sign";
	char pubKey[] = "pISM.pem";
	bool checkSign = checkSignFiles(signFile, pubKey, 16, sha256Key);


	char messageFile[] = "message%d.enc";
	char mSignFile[] = "mfile.sign";

	//ex3 - decrypt messages
	for (int i = 1; i <= 3; i++) {
		char numeFis[30];
		sprintf(numeFis, messageFile, i);
		decryptMessages(numeFis, sha256Key, mSignFile, pubKey, i);
	}



	return 0;
}


//1. decriptez fiecare fisier mesaj
//2. hashuiesc fiecare fisier mesaj
//3. compar fiecare hash cu hashul lui mfile.sign

