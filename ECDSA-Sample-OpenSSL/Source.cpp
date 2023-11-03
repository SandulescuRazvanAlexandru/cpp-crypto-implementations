#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/applink.c>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	// abort();
}

EC_GROUP* create_curve(void)
{
	BN_CTX* ctx;
	EC_GROUP* curve;
	BIGNUM* a, * b, * p, * order, * x, * y;
	EC_POINT* generator;

	/* Binary data for the curve parameters */
	unsigned char a_bin[28] =
	{ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFE };
	unsigned char b_bin[28] =
	{ 0xB4,0x05,0x0A,0x85,0x0C,0x04,0xB3,0xAB,
		0xF5,0x41,0x32,0x56,0x50,0x44,0xB0,0xB7,
		0xD7,0xBF,0xD8,0xBA,0x27,0x0B,0x39,0x43,
		0x23,0x55,0xFF,0xB4 };
	unsigned char p_bin[28] =
	{ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x01 };
	unsigned char order_bin[28] =
	{ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x16,0xA2,
		0xE0,0xB8,0xF0,0x3E,0x13,0xDD,0x29,0x45,
		0x5C,0x5C,0x2A,0x3D };
	unsigned char x_bin[28] =
	{ 0xB7,0x0E,0x0C,0xBD,0x6B,0xB4,0xBF,0x7F,
		0x32,0x13,0x90,0xB9,0x4A,0x03,0xC1,0xD3,
		0x56,0xC2,0x11,0x22,0x34,0x32,0x80,0xD6,
		0x11,0x5C,0x1D,0x21 };
	unsigned char y_bin[28] =
	{ 0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,
		0x4c,0x22,0xdf,0xe6,0xcd,0x43,0x75,0xa0,
		0x5a,0x07,0x47,0x64,0x44,0xd5,0x81,0x99,
		0x85,0x00,0x7e,0x34 };

	/* Set up the BN_CTX */
	if (NULL == (ctx = BN_CTX_new())) handleErrors();

	/* Set the values for the various parameters */
	if (NULL == (a = BN_bin2bn(a_bin, 28, NULL))) handleErrors();
	if (NULL == (b = BN_bin2bn(b_bin, 28, NULL))) handleErrors();
	if (NULL == (p = BN_bin2bn(p_bin, 28, NULL))) handleErrors();
	if (NULL == (order = BN_bin2bn(order_bin, 28, NULL))) handleErrors();
	if (NULL == (x = BN_bin2bn(x_bin, 28, NULL))) handleErrors();
	if (NULL == (y = BN_bin2bn(y_bin, 28, NULL))) handleErrors();

	/* Create the curve */
	if (NULL == (curve = EC_GROUP_new_curve_GFp(p, a, b, ctx))) handleErrors(); // create a curve 

	/* Create the generator */
	if (NULL == (generator = EC_POINT_new(curve))) handleErrors(); // allocate a point (for generator)
	if (1 != EC_POINT_set_affine_coordinates_GFp(curve, generator, x, y, ctx)) // set generator into the curve
		handleErrors();

	/* Set the generator and the order */
	if (1 != EC_GROUP_set_generator(curve, generator, order, NULL)) // set generator and order into the curve
		handleErrors();

	EC_POINT_free(generator);
	BN_free(y);
	BN_free(x);
	BN_free(order);
	BN_free(p);
	BN_free(b);
	BN_free(a);
	BN_CTX_free(ctx);

	return curve;
}

void main()
{
	EC_KEY* key;

	if (NULL == (key = EC_KEY_new_by_curve_name(NID_secp224r1)))
		handleErrors();

	// key object has been set up and associated with the curve, but it is empty
	// generate new keys (public and private key pair)
	if (1 != EC_KEY_generate_key(key)) handleErrors();

	// setting the private key and/or public key
	BIGNUM* prv = BN_new();
	const EC_GROUP* group = EC_KEY_get0_group(key);
	EC_POINT* pub = EC_POINT_new(group);

	// set up private key in prv 
	if (1 != EC_KEY_set_private_key(key, prv)) handleErrors();
	/* Set up public key in pub */
	if (1 != EC_KEY_set_public_key(key, pub)) handleErrors();
	// having the private key only, the public key can be generated
	// below statemets are not available/right for the secp224r1 named curve
	//EC_GROUP *curve = create_curve();
	//BN_CTX * ctx = BN_CTX_new();
	//if (1 != EC_POINT_mul(curve, pub, prv, NULL, NULL, ctx))
	//	handleErrors();

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
			result = ECDSA_do_verify((const unsigned char*)in_data, sizeof(in_data), s, key);
			if (1 != result) handleErrors();

			ECDSA_SIG_free(s);
		}
	}

}