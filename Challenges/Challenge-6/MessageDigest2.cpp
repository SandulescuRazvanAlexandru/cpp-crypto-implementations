#include "MessageDigest2.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>

// Constructor
MessageDigest::MessageDigest(const std::string& digestName) {
    // Initialize OpenSSL digest context
    mdContext = EVP_MD_CTX_new();
    if (!mdContext) {
        throw std::runtime_error("Failed to create digest context");
    }

    // Initialize the digest operation
    const EVP_MD* md = getDigestMethod(digestName);
    if (!EVP_DigestInit_ex(mdContext, md, nullptr)) {
        throw std::runtime_error("Failed to initialize digest");
    }
}

// Destructor
MessageDigest::~MessageDigest() {
    // Clean up the digest context
    EVP_MD_CTX_free(mdContext);
}

// Static method to choose the digest algorithm
const EVP_MD* MessageDigest::getDigestMethod(const std::string& digestName) {
    if (digestName == "SHA256") {
        return EVP_sha256();
    }
    else if (digestName == "MD5") {
        return EVP_md5();
    }
    else {
        throw std::invalid_argument("Unsupported digest algorithm");
    }
}

// Update the digest with new data
void MessageDigest::update(const std::string& data) {
    if (!EVP_DigestUpdate(mdContext, data.c_str(), data.size())) {
        throw std::runtime_error("Failed to update digest");
    }
}

// Finalize the digest and return the result
std::string MessageDigest::digest() {
    unsigned char mdValue[EVP_MAX_MD_SIZE];
    unsigned int mdLen;

    if (!EVP_DigestFinal_ex(mdContext, mdValue, &mdLen)) {
        throw std::runtime_error("Failed to finalize digest");
    }

    // Convert the hash to a hex string
    std::stringstream hexStringStream;
    for (unsigned int i = 0; i < mdLen; ++i) {
        hexStringStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mdValue[i]);
    }
    return hexStringStream.str();
}
