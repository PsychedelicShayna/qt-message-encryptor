#ifndef CRYPTO_HXX
#define CRYPTO_HXX

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <openssl/sha.h>
#include <openssl/aes.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

namespace Crypto {
    namespace Base64 {
        struct BIOFreeAll {
            void operator()(BIO* bio_ptr);
        };

        std::string Encode(const std::vector<uint8_t>& bytes);
        std::vector<uint8_t> Decode(const std::string& b64_string);
    }

    // Returns a Sha256 digest from from the supplied input data.
    std::vector<uint8_t> Sha256Digest(const std::vector<uint8_t>& bytes);

    // Applies Pkcs7 padding to the input data, using the specified multiple, and returns the padded result.
    std::vector<uint8_t> ApplyPkcs7(std::vector<uint8_t> bytes, const uint8_t& multiple);

    // Removes Pkcs7 padding from the input data, and returns the unpadded result.
    std::vector<uint8_t> StripPkcs7(std::vector<uint8_t> bytes);

    /* Automatically encrypts the input data using AES-256 CBC. The provided string is Sha256 hashed,
     * the digest of which is used as the encryption key. The first 16 bytes of the digest is used as
     * the initialization vector. The input data is also padded via Pkcs7 before being encrypted. */
    std::vector<uint8_t> Aes256CbcAutoEncrypt(std::vector<uint8_t> bytes, const std::string& plain_key);

    /* Automatically decrypts the input data using AES-256 CBC. The provided string is Sha256 hashed,
     * the digest of which is used as the decryption key. The first 16 bytes of the digest is used as
     * the initialization vector. The output data is Pkcs7 un-padded before being returned. */
    std::vector<uint8_t> Aes256CbcAutoDecrypt(std::vector<uint8_t> bytes, const std::string& plain_key);
}

#endif // CRYPTO_HXX
