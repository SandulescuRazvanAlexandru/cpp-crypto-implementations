#include "MessageDigest2.h"
#include <iostream>
#include <string>

int main() {
    // Initialize OpenSSL algorithms
    OpenSSL_add_all_digests();

    // Input data to compute the digest for
    std::string data = "The quick brown fox jumps over the lazy dog";

    // Compute and print the SHA256 digest
    try {
        MessageDigest sha256Digest("SHA256");
        sha256Digest.update(data);
        std::string sha256Result = sha256Digest.digest();
        std::cout << "SHA256: " << sha256Result << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error computing SHA256 digest: " << e.what() << std::endl;
    }

    // Compute and print the MD5 digest
    try {
        MessageDigest md5Digest("MD5");
        md5Digest.update(data);
        std::string md5Result = md5Digest.digest();
        std::cout << "MD5: " << md5Result << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error computing MD5 digest: " << e.what() << std::endl;
    }

    // Cleanup OpenSSL algorithms
    EVP_cleanup();

    return 0;
}
