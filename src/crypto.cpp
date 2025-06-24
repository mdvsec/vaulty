#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <stdexcept>

#include <crypto.hpp>

namespace vaulty::crypto {

SecureBuffer deriveEncryptionKey(const SecureBuffer& masterPassword, const std::array<unsigned char, kSaltSize>& salt) {
    SecureBuffer key(kKeySize);

    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(masterPassword.data()),
                           static_cast<int>(masterPassword.size()),
                           salt.data(),
                           static_cast<int>(kSaltSize),
                           static_cast<int>(kIterationsCount),
                           EVP_sha512(), /* PBKDF2-HMAC-SHA512 */
                           static_cast<int>(kKeySize),
                           key.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC key derivation failed");
    }

    return key;
}

SecureBuffer encrypt(const SecureBuffer& key, const SecureBuffer& plaintext) {
    SecureBuffer iv(kIvSize);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    //SecureBuffer ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm())); /* the ciphertext may be longer than the plaintext */
    SecureBuffer ciphertext(plaintext.size());
    SecureBuffer tag(kTagSize);
    int ciphertext_len = 0;
    int len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvSize), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    if (ciphertext_len != static_cast<int>(ciphertext.size())) {
        ciphertext.resize(ciphertext_len);
    }

    return iv + ciphertext + tag;
}

} /* namespace vaulty::crypto */
