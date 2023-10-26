#include<stdio.h>
#include<malloc.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/applink.c>
#include<iostream>
#include<string>
#include<openssl/md5.h>

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

void generateESignRsa(long int inFileLen, FILE* inFile, FILE* privKeyFile) {
	MD5_CTX ctx;
	MD5_Init(&ctx);

	unsigned char finalDigest[MD5_DIGEST_LENGTH];
	unsigned char* inBuffer = (unsigned char*)malloc(inFileLen);
	fread(inBuffer, inFileLen, 1, inFile);
	unsigned char* tmpBuffer = inBuffer;

	while (inFileLen > 0) {
		if (inFileLen > MD5_DIGEST_LENGTH) {
			MD5_Update(&ctx, tmpBuffer, MD5_DIGEST_LENGTH);
		}
		else {
			MD5_Update(&ctx, tmpBuffer, inFileLen);
		}
		inFileLen -= MD5_DIGEST_LENGTH;
		tmpBuffer += MD5_DIGEST_LENGTH;
	}

	MD5_Final(finalDigest, &ctx);

	printf("MD5 content for Input - when generating sign:\n");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
		printf("%02X", finalDigest[i]);
	printf("\n\n");

	RSA* privKey = RSA_new();
	FILE* signFile = fopen("RSA-ESign.ds", "wb");
	privKey = PEM_read_RSAPrivateKey(privKeyFile, NULL, NULL, NULL);
	fclose(privKeyFile);

	unsigned char* hashBuffer = (unsigned char*)malloc(sizeof(finalDigest));
	memcpy(hashBuffer, finalDigest, sizeof(finalDigest));
	unsigned char* eData = (unsigned char*)malloc(RSA_size(privKey)); //RSA_size => 1024 bits

	RSA_private_encrypt(sizeof(finalDigest), hashBuffer, eData, privKey, RSA_PKCS1_PADDING); //encryption for e-signature made using the PRIVATE key
	fwrite(eData, RSA_size(privKey), 1, signFile); //write the e-sign into the file

	free(eData);
	free(hashBuffer);
	RSA_free(privKey);

	fclose(signFile);
	fclose(inFile);

	printf("ESign generated successfully!\n");
}

void verifyESignRsa(long int inFileLen, FILE* inFile, FILE* signFile, FILE* pubKeyFile) {
	// Stage #1 Compute the message digest for the restored plaintext
	MD5_CTX ctx;
	unsigned char finalDigest[MD5_DIGEST_LENGTH]; // the computed message digest
	MD5_Init(&ctx);

	unsigned char* inBuffer = (unsigned char*)malloc(inFileLen);
	fread(inBuffer, inFileLen, 1, inFile);
	unsigned char* tmpBuffer = inBuffer;

	while (inFileLen > 0) {
		if (inFileLen > MD5_DIGEST_LENGTH) {
			MD5_Update(&ctx, tmpBuffer, MD5_DIGEST_LENGTH);
		}
		else {
			MD5_Update(&ctx, tmpBuffer, inFileLen);
		}
		inFileLen -= MD5_DIGEST_LENGTH;
		tmpBuffer += MD5_DIGEST_LENGTH;
	}

	MD5_Final(finalDigest, &ctx);

	printf("MD5 for content for Input - when verifying sign\n");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
		printf("%02X", finalDigest[i]);
	printf("\n\n");

	// Stage #2 Decrypt the content of e-signature and compare it with the message digest resulted from Stage #1
	RSA* pubKey = RSA_new();
	pubKey = PEM_read_RSAPublicKey(pubKeyFile, NULL, NULL, NULL); //public key is loaded into RSA key pair structure
	fclose(pubKeyFile);

	unsigned char* decBuffer = (unsigned char*)malloc(RSA_size(pubKey)); // posibil eroare pt ca RSA-size e 4 bytes doar 
	fread(decBuffer, RSA_size(pubKey), 1, signFile); //reads the e-signature from the file (a single block)
	unsigned char* lastData = (unsigned char*)malloc(16); //MD5_DIGEST_LENGTH);  //buffer for the restored message digest

	RSA_public_decrypt(RSA_size(pubKey), decBuffer, lastData, pubKey, RSA_PKCS1_PADDING); //decryption performed by using PUBLIC key
	// cu string
	printf("MD5 for lastdata \n");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
		printf("%02X", lastData[i]);
	printf("\n\n");

	if (memcmp(lastData, finalDigest, 16) == 0) //comparision between the computed and restored messages digests
		printf("\nSignature is OK!\n");
	else
		printf("\nSignature is wrong!\n");

	free(lastData);
	free(decBuffer);
	RSA_free(pubKey);

	fclose(inFile);
	fclose(signFile);
}

void generateX509Cert() {
	X509* X509Cert = X509_new();

	X509_set_version(X509Cert, 0x2);

	ASN1_INTEGER_set(X509_get_serialNumber(X509Cert), 1);

	X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "C", MBSTRING_ASC, (unsigned char*)"RO", -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "O", MBSTRING_ASC, (unsigned char*)"ASE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "OU", MBSTRING_ASC, (unsigned char*)"ITC Security Master", -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_issuer_name(X509Cert), "CN", MBSTRING_ASC, (unsigned char*)"Sandulescu Razvan Alexandru", -1, -1, 0);

	X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "C", MBSTRING_ASC, (unsigned char*)"RO", -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "O", MBSTRING_ASC, (unsigned char*)"ASE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "OU", MBSTRING_ASC, (unsigned char*)"ITC Security Master", -1, -1, 0);
	X509_NAME_add_entry_by_txt(X509_get_subject_name(X509Cert), "CN", MBSTRING_ASC, (unsigned char*)"Sandulescu Razvan Alexandru", -1, -1, 0);

	int DaysStart = 1;
	int DaysStop = 7;
	X509_gmtime_adj(X509_get_notBefore(X509Cert), (long)60 * 60 * 24 * DaysStart);
	X509_gmtime_adj(X509_get_notAfter(X509Cert), (long)60 * 60 * 24 * DaysStop);

	EVP_PKEY* pkey = EVP_PKEY_new();
	RSA* rsa = RSA_generate_key(1024, 65535, NULL, NULL);
	EVP_PKEY_set1_RSA(pkey, rsa);
	X509_set_pubkey(X509Cert, pkey);

	const EVP_MD* dgAlg = EVP_sha1();

	X509_sign(X509Cert, pkey, dgAlg);

	BIO* out1 = BIO_new_file("SampleCert.cer", "w");
	i2d_X509_bio(out1, X509Cert);
	BIO_free(out1);

	BIO* out2 = BIO_new_file("SampleCert.key", "w");
	i2d_PrivateKey_bio(out2, pkey);
	BIO_free(out2);

	RSA_free(rsa);
	EVP_PKEY_free(pkey);
	X509_free(X509Cert);
}

int main() {
	FILE* privKeyFile = fopen("privKeyFile.pem", "wb");
	FILE* pubKeyFile = fopen("pubKeyFile.pem", "wb");

	generateX509Cert();

	generateRsaKeyPair(privKeyFile, pubKeyFile);

	FILE* inputFile = fopen("Input.txt", "rb");
	privKeyFile = fopen("privKeyFile.pem", "r");
	pubKeyFile = fopen("pubKeyFile.pem", "r");

	if (privKeyFile && pubKeyFile && inputFile) {
		fseek(inputFile, 0, SEEK_END);
		long int inFileLen = ftell(inputFile);
		fseek(inputFile, 0, SEEK_SET);

		generateESignRsa(inFileLen, inputFile, privKeyFile);

		FILE* signFile = fopen("RSA-ESign.ds", "rb");
		if (signFile) {
			inputFile = fopen("Input.txt", "rb");
			verifyESignRsa(inFileLen, inputFile, signFile, pubKeyFile);
		}
	}
	else {
		printf("Error when opening either the input file or the pem files!\n");
		return 1;
	}

	return 0;
}