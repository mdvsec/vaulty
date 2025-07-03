#include <array>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <crypto.hpp>
#include <logger.hpp>

namespace vaulty::crypto {

SecureBuffer deriveEncryptionKey(const SecureBuffer& master_password, const std::array<unsigned char, kSaltSize>& salt) {
    LOG_INFO("Deriving encryption key using PBKDF2-HMAC-SHA512");

    SecureBuffer key(kKeySize);

    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(master_password.data()),
                           static_cast<int>(master_password.size()),
                           salt.data(),
                           static_cast<int>(kSaltSize),
                           static_cast<int>(kIterationsCount),
                           EVP_sha512(), /* PBKDF2-HMAC-SHA512 */
                           static_cast<int>(kKeySize),
                           key.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC key derivation failed");
    }

    LOG_INFO("Key derivation successful");
    return key;
}

SecureBuffer encrypt(const SecureBuffer& key, const SecureBuffer& plaintext) {
    LOG_INFO("Starting encryption");

    if (key.size() != kKeySize) {
        throw std::runtime_error("Invalid key size");
    }

    SecureBuffer iv(kIvSize);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

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

    LOG_INFO("Encryption completed successfully");
    return iv + ciphertext + tag;
}

SecureBuffer decrypt(const SecureBuffer& key, const SecureBuffer& blob) {
    LOG_INFO("Starting decryption");

    if (key.size() != kKeySize || blob.size() < kIvSize + kTagSize) {
        throw std::runtime_error("Invalid input sizes");
    }

    int ciphertext_len = blob.size() - kIvSize - kTagSize;
    int len = 0;
    int plaintext_len = 0;

    SecureBuffer iv(blob.data(), kIvSize);
    SecureBuffer ciphertext(blob.data() + kIvSize, ciphertext_len);
    SecureBuffer tag(blob.data() + blob.size() - kTagSize, kTagSize);
    SecureBuffer plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvSize), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_TAG failed");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: wrong master key or corrupted data");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    if (plaintext_len != static_cast<int>(plaintext.size())) {
        plaintext.resize(plaintext_len);
    }

    LOG_INFO("Decryption completed successfully");
    return plaintext;
}

} /* namespace vaulty::crypto */
