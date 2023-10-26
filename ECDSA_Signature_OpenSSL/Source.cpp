#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/applink.c>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	// abort();
}

int main()
{
	EC_KEY* key;

	if (NULL == (key = EC_KEY_new_by_curve_name(NID_secp224r1)))
		handleErrors();

	// key object has been set up and associated with the curve, but it is empty
	// generate new keys (public and private key pair)
	if (1 != EC_KEY_generate_key(key)) handleErrors();

	unsigned char in_data[32] = // SHA-256 content
	{ 0xf5,0x03,0x74,0xf5,0xac,0xb5,0x3c,0x12,
		0x0a,0x6b,0x5f,0x65,0xad,0x78,0xfc,0xf5,
		0x09,0xad,0x17,0x43,0x38,0xbe,0x42,0xdb,
		0x4e,0x26,0x94,0x45,0x68,0xe6,0xba,0x20 };
	unsigned char* signature = new unsigned char[80];
	unsigned int sig_len = 0;

	// generate the signature
	int result = ECDSA_sign(0, (const unsigned char*)in_data, sizeof(in_data), (unsigned char*)signature, (unsigned int*)&sig_len, key);

	if (1 != result) handleErrors();

	// verify the signature
	ECDSA_SIG* s = ECDSA_SIG_new();
	if (s != NULL) {
		if (d2i_ECDSA_SIG(&s, (const unsigned char**)&signature, sig_len) != NULL) {  // decode the DER encoded Signature into a ECDSA_SIG structure
			// DER encoding - one of ASN.1 encoding rules defined in ITU-T X.690, 2002, specification. 
			// ASN.1 encoding rules can be used to encode any data object into a binary file.

			// call to OpenSSL API to verify the signature
			// in_data[0] = 0xf6; // provoking signature invalidation
			result = ECDSA_do_verify((const unsigned char*)in_data, sizeof(in_data), s, key);
			if (1 != result)
			{
				printf("Signature is invalid!\n");
				handleErrors();
			}
			else
				printf("Signature is valid!\n");


			ECDSA_SIG_free(s);
		}
	}

	return 0;
}