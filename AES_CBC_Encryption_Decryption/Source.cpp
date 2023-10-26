#include<stdio.h>
#include<malloc.h>
#include<openssl/aes.h>
#include<string>

void encryptAesCbc(long int inFileLen, const unsigned char* password, unsigned char iv[16], FILE* cbcFileIn) {
	AES_KEY key;
	long int outFileLen = 0;

	if ((inFileLen % 16) == 0)
		outFileLen = inFileLen;
	else
		outFileLen = ((inFileLen / 16) * 16) + 16; //adjusted input length according to number of blocks needed by AES algorithm

	unsigned char* inBuffer = (unsigned char*)malloc(outFileLen);
	unsigned char* outBuffer = (unsigned char*)malloc(outFileLen);

	fread(inBuffer, inFileLen, 1, cbcFileIn); //the entire content of the plaintext file is added into inBuf

	AES_set_encrypt_key(password, 128, &key);  //set the key into internal OpenSSL structure used later in other OpenSSL API calls

	AES_cbc_encrypt(inBuffer, outBuffer, outFileLen, &key, iv, AES_ENCRYPT); //performs the encryption for AES-CBC for entire content

	FILE* cbcFileOut = fopen("Cbc-Encryption.txt", "wb"); //ciphertext file
	fwrite(&inFileLen, sizeof(inFileLen), 1, cbcFileOut); //write the size of the plaintext in the output/encrypted file
	fwrite(outBuffer, outFileLen, 1, cbcFileOut); //write the ciphertext (byte-by-byte) after the size of the plaintext file

	free(inBuffer);
	free(outBuffer);
	fclose(cbcFileIn);
	fclose(cbcFileOut);
}

void decryptAesCbc(long int encFileLen, const unsigned char* password, unsigned char iv[16], FILE* encFile) {
	AES_KEY key;
	long int decFileLen = 0; //the length of the plaintext file
	fread(&decFileLen, sizeof(decFileLen), 1, encFile);

	unsigned char* encBuffer = (unsigned char*)malloc(encFileLen); //entire ciphertext is allocated and read from the ciphertext input file
	unsigned char* decBuffer = (unsigned char*)malloc(encFileLen); //buffer for the restored plaintext
	fread(encBuffer, encFileLen, 1, encFile);

	AES_set_decrypt_key(password, 128, &key); //load the decription key into AES_KEY structure

	AES_cbc_encrypt(encBuffer, decBuffer, encFileLen, &key, iv, AES_DECRYPT); // same name like in the enc case; performs decription of the entire ciphertext

	FILE* cbcFileOut = fopen("Cbc-Decryption.txt", "wb"); //restored plaintext file
	fwrite(decBuffer, decFileLen, 1, cbcFileOut); //write into the destionation/restored file; length of the restored file is outLen (read from the first 4 bytes in ciphertext file)

	free(encBuffer);
	free(decBuffer);
	fclose(encFile);
	fclose(cbcFileOut);
}

int main() {
	FILE* ecbFileIn = fopen("Input.txt", "rb"); //plaintext file

	if (ecbFileIn) {
		fseek(ecbFileIn, 0, SEEK_END);
		long int fileInLen = ftell(ecbFileIn);
		fseek(ecbFileIn, 0, SEEK_SET);

		unsigned char iv[16]; //initialization vector
		memset(&iv, 0x01, sizeof(iv)); 

		encryptAesCbc(fileInLen, (const unsigned char*)"mysecretkey12345", iv, ecbFileIn);

		FILE* cbcFileEnc = fopen("Cbc-Encryption.txt", "rb"); //ciphertext file

		if (cbcFileEnc) {
			fseek(cbcFileEnc, 0, SEEK_END);
			long int encFileLen = ftell(cbcFileEnc) - 4; //-4 is for the bytes occupied by the length of the plaintext
			fseek(cbcFileEnc, 0, SEEK_SET);
			memset(&iv, 0x01, sizeof(iv));

			decryptAesCbc(encFileLen, (const unsigned char*)"mysecretkey12345", iv, cbcFileEnc);
		}
	}
	else {
		printf("Error when opening the input file!\n");
		return 1;
	}

	return 0;
}
