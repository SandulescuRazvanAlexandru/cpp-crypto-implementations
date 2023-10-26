#include <stdio.h>
#include <string.h>
#include <openssl/des.h>


unsigned char* DES_CFB_Encrypt(unsigned char* Key, unsigned char* Msg, int size) {
	unsigned char* Res;
	int n = 0;
	DES_cblock Key2;
	DES_key_schedule schedule;

	Res = (unsigned char*)malloc(size);

	memcpy(Key2, Key, 8);
	DES_set_odd_parity(&Key2);
	if (DES_set_key_checked(&Key2, &schedule)) {
		printf("Key error, exiting...");
		return NULL;
	}

	DES_cfb64_encrypt((unsigned char*)Msg, (unsigned char*)Res, size, &schedule, &Key2, &n, DES_ENCRYPT);

	return Res;
}


unsigned char* DES_CFB_Decrypt(unsigned char* Key, unsigned char* Msg, int size) {
	unsigned char* Res;
	int n = 0;

	DES_cblock Key2;
	DES_key_schedule schedule;

	Res = (unsigned char*)malloc(size);

	memcpy(Key2, Key, 8);
	DES_set_odd_parity(&Key2);
	if (DES_set_key_checked(&Key2, &schedule)) {
		printf("Key error, exiting...");
		return NULL;
	}

	DES_cfb64_encrypt((unsigned char*)Msg, (unsigned char*)Res, size, &schedule, &Key2, &n, DES_DECRYPT);

	return Res;
}

unsigned char* DES_3_CFB_Encrypt(unsigned char* Key, unsigned char* Msg, int size) {
	unsigned char* Res;
	int n = 0;
	DES_cblock kb1 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
	DES_cblock kb2 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
	DES_cblock kb3 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
	DES_key_schedule s1, s2, s3;

	DES_cblock Key2;
	DES_key_schedule schedule;

	Res = (unsigned char*)malloc(size);

	memcpy(Key2, Key, 8);
	DES_set_odd_parity(&Key2);

	if (DES_set_key_checked(&kb1, &s1) || DES_set_key_checked(&kb2, &s2) || DES_set_key_checked(&kb3, &s3)) {
		printf("Key error, exiting ....\n");
		return NULL;
	}

	DES_ede3_cfb64_encrypt((unsigned char*)Msg, (unsigned char*)Res, size, &s1, &s2, &s3, &Key2, &n, DES_ENCRYPT);

	return Res;
}

unsigned char* DES_3_CFB_Decrypt(unsigned char* Key, unsigned char* Msg, int size) {
	unsigned char* Res;
	int n = 0;
	DES_cblock kb1 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
	DES_cblock kb2 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
	DES_cblock kb3 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
	DES_key_schedule s1, s2, s3;

	DES_cblock Key2;
	DES_key_schedule schedule;

	Res = (unsigned char*)malloc(size);

	memcpy(Key2, Key, 8);
	DES_set_odd_parity(&Key2);

	if (DES_set_key_checked(&kb1, &s1) || DES_set_key_checked(&kb2, &s2) || DES_set_key_checked(&kb3, &s3)) {
		printf("Key error, exiting ....\n");
		return NULL;
	}

	DES_ede3_cfb64_encrypt((unsigned char*)Msg, (unsigned char*)Res, size, &s1, &s2, &s3, &Key2, &n, DES_DECRYPT);

	return Res;
}



int main(int argc, char** argv) {
	unsigned char key[8];
	//	 void DES_random_key(DES_cblock *ret); // may be used to generate a random key
	DES_cblock pass;
	DES_random_key(&pass);
	memcpy_s(key, 8, &pass, 8);
	printf("\nPass: %s\n", key);

	unsigned char* clear = NULL;
	FILE* fSrc = NULL, * fEnc = NULL, * fDec = NULL;

	fopen_s(&fSrc, argv[2], "rb");
	fseek(fSrc, 0, SEEK_END);
	long int inLen = ftell(fSrc);
	fseek(fSrc, 0, SEEK_SET);

	clear = (unsigned char*)malloc(inLen);
	memset(clear, 0x00, inLen);
	fread(clear, inLen, 1, fSrc);

	fopen_s(&fEnc, argv[3], "wb");
	fopen_s(&fDec, argv[4], "wb");
	long int outLen = inLen;

	unsigned char* decrypted;
	unsigned char* encrypted;

	encrypted = (unsigned char*)malloc(sizeof(outLen));
	decrypted = (unsigned char*)malloc(sizeof(outLen));

	if (!strcmp(argv[1], "-cfb")) {
		printf("Clear text\t : %s \n", clear);
		encrypted = DES_CFB_Encrypt(key, clear, outLen);
		fwrite(encrypted, outLen, 1, fEnc);
		//printf("Encrypted text\t : %s \n",encrypted);

		decrypted = DES_CFB_Decrypt(key, encrypted, outLen);
		fwrite(decrypted, outLen, 1, fDec);
		//printf("Decrypted text\t : %s \n",decrypted);
	}
	else {
		if (!strcmp(argv[1], "-3des")) {
			printf("Clear text\t : %s \n", clear);
			encrypted = DES_3_CFB_Encrypt(key, clear, outLen);
			fwrite(encrypted, outLen, 1, fEnc);
			//printf("Encrypted text\t : %s \n",encrypted);

			decrypted = DES_3_CFB_Decrypt(key, encrypted, outLen);
			fwrite(decrypted, outLen, 1, fDec);
			//printf("Decrypted text\t : %s \n",decrypted);
		}
		else {
			printf("\n Usage Mode: OpenSSLProj.exe -cfb fSrc.txt fEnc.txt fDec.txt");
			printf("\n Usage Mode: OpenSSLProj.exe -3des fSrc.txt fEnc.txt fDec.txt");
			return 1;
		}
	}


	fclose(fSrc);
	fclose(fEnc);
	fclose(fDec);
	return 0;
}