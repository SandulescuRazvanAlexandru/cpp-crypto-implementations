#include <iostream>
#include <vector>
#include <openssl/evp.h>

class AESCipher {
private:
    const EVP_CIPHER* cipher_algo; // Current cipher algorithm

public:
    AESCipher(const EVP_CIPHER* cipher_algo) : cipher_algo(cipher_algo) {
        OpenSSL_add_all_algorithms(); // Initialize OpenSSL algorithms
    }

    ~AESCipher() {
        EVP_cleanup(); // Cleanup OpenSSL
    }

    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
};

void handleErrors() {
    //ERR_print_errors_fp(stderr);
    abort();
}

std::string AESCipher::encrypt(const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    size_t ciphertext_len = 0;

    unsigned char key[EVP_MAX_KEY_LENGTH]; // Encryption key
    unsigned char iv[EVP_MAX_IV_LENGTH];   // Initialization vector
    // TODO: Properly initialize key and iv with secure values

    if (1 != EVP_EncryptInit_ex(ctx, cipher_algo, nullptr, key, iv)) handleErrors();
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size())) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
}

std::string AESCipher::decrypt(const std::string& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    size_t plaintext_len = 0;

    unsigned char key[EVP_MAX_KEY_LENGTH]; // Decryption key
    unsigned char iv[EVP_MAX_IV_LENGTH];   // Initialization vector
    // TODO: Properly initialize key and iv with secure values

    if (1 != EVP_DecryptInit_ex(ctx, cipher_algo, nullptr, key, iv)) handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size())) handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

int main() {
    std::string plaintext = "Hello, World! This is a test.";
    // Encryption and decryption using AES-256-CBC
    AESCipher aesCipher256(EVP_aes_256_cbc());
    std::string ciphertext256 = aesCipher256.encrypt(plaintext);
    std::string decryptedtext256 = aesCipher256.decrypt(ciphertext256);

    std::cout << "Using AES-256-CBC:" << std::endl;
    std::cout << "Plaintext is: " << plaintext << std::endl;
    std::cout << "Ciphertext (hex) is: ";
    for (unsigned char c : ciphertext256) {
        printf("%02x", c);
    }
    std::cout << std::endl;
    std::cout << "Decrypted text is: " << decryptedtext256 << std::endl;
    // Encryption and decryption using AES-128-CBC
    AESCipher aesCipher128(EVP_aes_128_cbc());
    std::string ciphertext128 = aesCipher128.encrypt(plaintext);
    std::string decryptedtext128 = aesCipher128.decrypt(ciphertext128);

    std::cout << "\nUsing AES-128-CBC:" << std::endl;
    std::cout << "Plaintext is: " << plaintext << std::endl;
    std::cout << "Ciphertext (hex) is: ";
    for (unsigned char c : ciphertext128) {
        printf("%02x", c);
    }
    std::cout << std::endl;
    std::cout << "Decrypted text is: " << decryptedtext128 << std::endl;

    // Clean up OpenSSL
    EVP_cleanup();

    return 0;
}

