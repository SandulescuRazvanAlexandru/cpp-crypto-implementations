#ifndef MESSAGE_DIGEST_H
#define MESSAGE_DIGEST_H

#include <openssl/evp.h>
#include <string>

class MessageDigest {
public:
    // Constructor to initialize with a chosen digest algorithm
    explicit MessageDigest(const std::string& digestName);

    // Destructor
    ~MessageDigest();

    // Method to add data to the digest
    void update(const std::string& data);

    // Method to retrieve the final digest result
    std::string digest();

private:
    // OpenSSL's context for digest operations
    EVP_MD_CTX* mdContext;

    // Static fields for supported message digest algorithms
    static const EVP_MD* getDigestMethod(const std::string& digestName);
};

#endif // MESSAGE_DIGEST_H
