#include<stdio.h>
#include<malloc.h>
#include<openssl/aes.h>
#include<string>

void encryptAesEcb(long int inFileLen, const unsigned char* password, FILE* ecbFileIn) {
	AES_KEY key;
	long int outFileLen = 0;

	if ((inFileLen % 16) == 0)
		outFileLen = inFileLen;
	else
		outFileLen = ((inFileLen / 16) * 16) + 16; //adjusted input length according to number of blocks needed by AES algorithm

	unsigned char* inBuffer = (unsigned char*)malloc(outFileLen);
	unsigned char* outBuffer = (unsigned char*)malloc(outFileLen);

	fread(inBuffer, inFileLen, 1, ecbFileIn); //the entire content of the plaintext file is added into inBuf

	AES_set_encrypt_key(password, 128, &key);  //set the key into internal OpenSSL structure used later in other OpenSSL API calls

	for (int i = 0; i < (outFileLen / 16); i++) {
		AES_encrypt(&(inBuffer[i * 16]), &(outBuffer[i * 16]), &key); //performs the encryption for AES-ECB for each data block (16 bytes each block)
	}

	FILE* ecbFileOut = fopen("Ecb-Encryption.txt", "wb"); //ciphertext file
	fwrite(&inFileLen, sizeof(inFileLen), 1, ecbFileOut); //write the size of the plaintext in the output/encrypted file
	fwrite(outBuffer, outFileLen, 1, ecbFileOut); //write the ciphertext (byte-by-byte) after the size of the plaintext file

	free(inBuffer);
	free(outBuffer);
	fclose(ecbFileIn);
	fclose(ecbFileOut);
}

void decryptAesEcb(long int encFileLen, const unsigned char* password, FILE* encFile) {
	AES_KEY key;
	long int decFileLen = 0; //the length of the plaintext file
	fread(&decFileLen, sizeof(decFileLen), 1, encFile);

	unsigned char* encBuffer = (unsigned char*)malloc(encFileLen); //entire ciphertext is allocated and read from the ciphertext input file
	unsigned char* decBuffer = (unsigned char*)malloc(encFileLen); //buffer for the restored plaintext
	fread(encBuffer, encFileLen, 1, encFile);

	AES_set_decrypt_key(password, 128, &key); //load the decription key into AES_KEY structure

	for (int i = 0; i < (encFileLen / 16); i++) {
		AES_decrypt(&(encBuffer[i * 16]), &(decBuffer[i * 16]), &key); //performs a decryption operation at block level (16 bytes long)
	}

	FILE* decFile = fopen("Ecb-Decryption.txt", "wb"); //restored plaintext file
	fwrite(decBuffer, decFileLen, 1, decFile); //write into the destionation/restored file; length of the restored file is outLen (read from the first 4 bytes in ciphertext file)

	free(encBuffer);
	free(decBuffer);
	fclose(encFile);
	fclose(decFile);
}


int main() {
	FILE* ecbFileIn = fopen("Input.txt", "rb"); //plaintext file

	if (ecbFileIn) {
		fseek(ecbFileIn, 0, SEEK_END);
		long int fileInLen = ftell(ecbFileIn);
		fseek(ecbFileIn, 0, SEEK_SET);

		encryptAesEcb(fileInLen, (const unsigned char*)"mysecretkey12345", ecbFileIn);

		FILE* ecbFileEnc = fopen("Ecb-Encryption.txt", "rb"); //ciphertext file

		if (ecbFileEnc) {
			fseek(ecbFileEnc, 0, SEEK_END);
			long int encFileLen = ftell(ecbFileEnc) - 4; //-4 is for the bytes occupied by the length of the plaintext
			fseek(ecbFileEnc, 0, SEEK_SET);

			decryptAesEcb(encFileLen, (const unsigned char*)"mysecretkey12345", ecbFileEnc);
		}
	}
	else {
		printf("Error when opening the input file!\n");
		return 1;
	}

	return 0;
}