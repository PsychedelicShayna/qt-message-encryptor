#ifndef CRYPTO_HXX
#define CRYPTO_HXX

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include <random>
#include <memory>
#include <string>
#include <vector>
#include <array>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace Ossl {
    struct BIOFreeAll {
        void operator()(BIO* bio_ptr);
    };

    namespace Base64 {
        std::string Encode(const std::vector<uint8_t>& bytes);
        std::vector<uint8_t> Decode(const std::string& b64_string);
    }

    namespace Hashing {
        // Returns a Sha256 digest from from the supplied input data.
        std::vector<uint8_t> Sha256Digest(const std::vector<uint8_t>& bytes);
    }

    namespace Util {
        // Applies Pkcs7 padding to the input data, using the specified multiple, and returns the padded result.
        std::vector<uint8_t> ApplyPkcs7Padding(std::vector<uint8_t> bytes, const uint8_t& multiple);

        // Removes Pkcs7 padding from the input data, and returns the unpadded result.
        std::vector<uint8_t> StripPkcs7Padding(std::vector<uint8_t> bytes);

        // Converts a vector of bytes into a string of hex.
        std::string Hexlify(const std::vector<uint8_t>& digest);
    }

    namespace Aes {
        enum KeySize {
            KS_128_BIT = 16, KS_192_BIT = 24, KS_256_BIT = 32
        };

        template<KeySize KS>
        std::vector<uint8_t> CbcEncrypt(std::vector<uint8_t> bytes, std::array<uint8_t, KS> key, std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector) {
            AES_KEY key_object;
            AES_set_encrypt_key(key.data(), key.size() * 8, &key_object);

            AES_cbc_encrypt(
                bytes.data(),
                bytes.data(),
                bytes.size(),
                &key_object,
                initialization_vector.data(),
                AES_ENCRYPT
            );

            return bytes;
        }

        template<KeySize KS>
        std::vector<uint8_t> CbcDecrypt(std::vector<uint8_t> bytes, std::array<uint8_t, KS> key, std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector) {
            AES_KEY key_object;
            AES_set_decrypt_key(key.data(), key.size() * 8, &key_object);

            AES_cbc_encrypt(
                bytes.data(),
                bytes.data(),
                bytes.size(),
                &key_object,
                initialization_vector.data(),
                AES_DECRYPT
            );

            return bytes;
        }

        template<KeySize KS>
        std::vector<uint8_t> CbcEncryptAuto_Pad_Iv(
            std::vector<uint8_t> bytes,
            std::vector<uint8_t> variable_key)
        {
            bytes = Util::ApplyPkcs7Padding(bytes, AES_BLOCK_SIZE);
            const std::vector<uint8_t>& key_sha256_digest = Hashing::Sha256Digest(variable_key);

            std::array<uint8_t, KS> encryption_key;
            std::copy_n(key_sha256_digest.begin(), KS, encryption_key.begin());

            std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector;
            std::copy_n(key_sha256_digest.begin(), AES_BLOCK_SIZE, initialization_vector.begin());

            return CbcEncrypt<KS>(bytes, encryption_key, initialization_vector);
        }

      template<KeySize KS>
      std::vector<uint8_t> CbcDecryptAuto_Pad_Iv(
          std::vector<uint8_t> bytes,
          std::vector<uint8_t> variable_key)
      {
        const std::vector<uint8_t>& key_sha256_digest = Hashing::Sha256Digest(variable_key);

        std::array<uint8_t, KS> decryption_key; // (key_sha256_digest.begin(), key_sha256_digest.begin() + KS);
        std::copy_n(key_sha256_digest.begin(), KS, decryption_key.begin());

        std::array<uint8_t, AES_BLOCK_SIZE> initialization_vector; // (key_sha256_digest.begin(), key_sha256_digest.begin() + KS);
        std::copy_n(key_sha256_digest.begin(), AES_BLOCK_SIZE, initialization_vector.begin());

        const std::vector<uint8_t>& decrypted_bytes = CbcDecrypt<KS>(bytes, decryption_key, initialization_vector);

        return Util::StripPkcs7Padding(decrypted_bytes);
      }
    }

    namespace Rsa {
        enum KeySize {
            KS_1024_B = 1024,
            KS_2048_B = 2048,
            KS_4096_B = 4096
        };

        RSA* GenerateKeypair(KeySize key_size, uint64_t public_exponent = 65537);

        std::string GetPublicKeyPem(RSA* public_key);
        std::string GetPrivateKeyPem(RSA* private_key);

        RSA* LoadPublicKeyPem(std::string public_key_pem);
        RSA* LoadPrivateKeyPem(std::string private_key_pem);

        std::pair<RSA*, RSA*> LoadRSAKeypairPem(std::string public_key_pem, std::string private_key_pem);

        std::pair<std::string, std::string> GetPemPair(RSA* keypair);
        RSA* LoadPublicPrivateKeyPem(std::string public_key_pem, std::string private_key_pem);

        std::vector<uint8_t> PublicEncrypt(std::vector<uint8_t> data, RSA* key, int padding = RSA_PKCS1_OAEP_PADDING);
        std::vector<uint8_t> PrivateDecrypt(std::vector<uint8_t> data, RSA* key, int padding = RSA_PKCS1_OAEP_PADDING);
    }

    namespace Random {
        int32_t NumberFromRange(const int32_t& from, const int32_t& to);
        std::vector<uint8_t> ByteVector(const size_t& size);
        std::vector<uint8_t> FromByteSet(const std::vector<uint8_t>& byte_set, const size_t& size);
    }
}

#endif // CRYPTO_HXX
