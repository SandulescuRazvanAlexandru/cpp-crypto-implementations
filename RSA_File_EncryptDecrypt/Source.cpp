#include<stdio.h>
#include<malloc.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/applink.c>

void generateRsaKeyPair(FILE* privKeyFile, FILE* pubKeyFile) {
	RSA* rsaKeyPair = NULL; //pointer to RSA OpenSSL structure

	rsaKeyPair = RSA_new(); //allcation of RSA structure
	rsaKeyPair = RSA_generate_key(1024, 65535, NULL, NULL); //generate the RSA key pair

	RSA_check_key(rsaKeyPair); //check if the RSA key pair was generated fine

	PEM_write_RSAPrivateKey(privKeyFile, rsaKeyPair, NULL, NULL, 0, 0, NULL); //save the rsa private key in it's file
	PEM_write_RSAPublicKey(pubKeyFile, rsaKeyPair); //save the rsa public key in it's file

	fclose(privKeyFile);
	fclose(pubKeyFile);

	RSA_free(rsaKeyPair);
	printf("Generated the RSA key pair successfully!\n");
}

void encryptRsa(long int inFileLen, FILE* inFile, FILE* pubKeyFile) {
	RSA* pubKey = RSA_new();

	pubKey = PEM_read_RSAPublicKey(pubKeyFile, NULL, NULL, NULL); //loads the public key (components) into RSA internal structure
	fclose(pubKeyFile);

	unsigned char* inBuffer = (unsigned char*)malloc(RSA_size(pubKey) + 1);
	unsigned char* data = (unsigned char*)malloc(RSA_size(pubKey));

	FILE* outFile = fopen("RSA-Encryption2.txt", "wb");

	if (inFileLen != RSA_size(pubKey)) {
		while (fread_s(inBuffer, RSA_size(pubKey), sizeof(unsigned char), RSA_size(pubKey), inFile) == RSA_size(pubKey)) {
			RSA_public_encrypt(RSA_size(pubKey), inBuffer, data, pubKey, RSA_NO_PADDING); //encryption for a complete input data block by using the public key; no padding is required
			fwrite(data, sizeof(unsigned char), RSA_size(pubKey), outFile); // write the result of encryption (encrypted data block) into enc file
		}
	}
	else {
		fread_s(inBuffer, RSA_size(pubKey), sizeof(unsigned char), RSA_size(pubKey), inFile);
	}

	//RSA_public_encrypt(inFileLen % RSA_size(pubKey), inBuffer, data, pubKey, RSA_PKCS1_PADDING); //encryption for the incomplete last input data block; the completion is made by the padding at content level
	RSA_public_encrypt(RSA_size(pubKey), inBuffer, data, pubKey, RSA_PKCS1_PADDING);
	fwrite(data, sizeof(unsigned char), RSA_size(pubKey), outFile); //write the result of last last block encryption into enc file

	free(inBuffer);
	free(data);
	RSA_free(pubKey);

	fclose(outFile);
	fclose(inFile);
}

//void decryptRsa(long int inFileLen, long int encFileLen, FILE* encFile, FILE* privKeyFile, FILE* pubKeyFile) {
//	RSA* privKey = RSA_new();
//	RSA* pubKey = RSA_new();
//
//	privKey = PEM_read_RSAPublicKey(privKeyFile, NULL, NULL, NULL); //loads the private key (components) into RSA internal structure
//	pubKey = PEM_read_RSAPublicKey(pubKeyFile, NULL, NULL, NULL);
//	fclose(privKeyFile);
//	fclose(pubKeyFile);
//
//	unsigned char* eData = (unsigned char*)malloc(RSA_size(pubKey));
//	unsigned char* lastData = (unsigned char*)malloc(RSA_size(pubKey));
//
//	int maxChunks = encFileLen / RSA_size(pubKey); // number of encrypted data blocks
//	int currentChunk = 1;
//
//	FILE* decFile = fopen("RSA-Decryption.txt", "wb");
//
//	if (encFileLen != RSA_size(pubKey)) {
//		while (fread_s(eData, RSA_size(pubKey), sizeof(unsigned char), RSA_size(pubKey), encFile) == RSA_size(pubKey)) { // read one single encrypted complete data block
//			if (currentChunk != maxChunks) {
//				RSA_private_decrypt(RSA_size(pubKey), eData, lastData, privKey, RSA_NO_PADDING); // decryption of the complete encrypted data block; no padding required
//				fwrite(lastData, sizeof(unsigned char), RSA_size(pubKey), decFile);
//				currentChunk++;
//			}
//		}
//	}
//	else {
//		fread_s(eData, RSA_size(pubKey), sizeof(unsigned char), RSA_size(pubKey), encFile);
//	}
//
//	RSA_private_decrypt(RSA_size(pubKey), eData, lastData, privKey, RSA_PKCS1_PADDING); // decryption of the last (incomplete) encrypted data block; padding required
//	fwrite(lastData, sizeof(unsigned char), inFileLen % RSA_size(pubKey), decFile); // fileLen - length of the original/initial plaintext
//
//	free(eData);
//	free(lastData);
//	RSA_free(pubKey);
//	RSA_free(privKey);
//
//	fclose(encFile);
//	fclose(decFile);
//}

void decryptRsa(long int encFileLen, FILE* encFile, FILE* privKeyFile) {
	RSA* privKey = RSA_new();

	privKey = PEM_read_RSAPrivateKey(privKeyFile, NULL, NULL, NULL); //loads the private key (components) into RSA internal structure
	fclose(privKeyFile);

	unsigned char* encBuff = (unsigned char*)malloc(RSA_size(privKey));
	unsigned char* data = (unsigned char*)malloc(RSA_size(privKey));

	int maxChunks = encFileLen / RSA_size(privKey); // number of encrypted data blocks
	int currentChunk = 1;

	FILE* decFile = fopen("RSA-Decryption2.txt", "wb");

	if (encFileLen != RSA_size(privKey)) {
		while (fread_s(encBuff, RSA_size(privKey), sizeof(unsigned char), RSA_size(privKey), encFile) == RSA_size(privKey)) { // read one single encrypted complete data block
			if (currentChunk != maxChunks) {
				RSA_private_decrypt(RSA_size(privKey), encBuff, data, privKey, RSA_NO_PADDING); // decryption of the complete encrypted data block; no padding required
				fwrite(data, sizeof(unsigned char), RSA_size(privKey), decFile);
				currentChunk++;
			}
		}
	}
	else {
		fread_s(encBuff, RSA_size(privKey), sizeof(unsigned char), RSA_size(privKey), encFile);
	}

	RSA_private_decrypt(RSA_size(privKey), encBuff, data, privKey, RSA_PKCS1_PADDING); // decryption of the last (incomplete) encrypted data block; padding required
	//fwrite(data, sizeof(unsigned char), inFileLen % RSA_size(privKey), decFile); // fileLen - length of the original/initial plaintext
	fwrite(data, sizeof(unsigned char), RSA_size(privKey), decFile);

	free(encBuff);
	free(data);
	RSA_free(privKey);

	fclose(encFile);
	fclose(decFile);
}

int main() {

	FILE* privKeyFile = fopen("privKeyFile.pem", "w+");
	FILE* pubKeyFile = fopen("pubKeyFile.pem", "w+");

	generateRsaKeyPair(privKeyFile, pubKeyFile);

	if (privKeyFile && pubKeyFile) {
		pubKeyFile = fopen("pubKeyFile.pem", "rb");
		FILE* inputFile = fopen("Input.txt", "rb");

		if (inputFile) {
			fseek(inputFile, 0, SEEK_END);
			long int inFileLen = ftell(inputFile);
			fseek(inputFile, 0, SEEK_SET);

			encryptRsa(inFileLen, inputFile, pubKeyFile);

			FILE* encFile = fopen("RSA-Encryption.txt", "rb");
			
			if (encFile) {
				//pubKeyFile = fopen("pubKeyFile.pem", "rb");
				privKeyFile = fopen("privKeyFile.pem", "rb");

				fseek(encFile, 0, SEEK_END);
				long int encFileLen = ftell(encFile);
				fseek(encFile, 0, SEEK_SET);

				decryptRsa(encFileLen, encFile, privKeyFile);
			}
		}
		else {
			printf("Error when opening the input file!\n");
			return 1;
		}
	}

	return 0;
}