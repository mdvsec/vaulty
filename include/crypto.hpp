#pragma once

#include <array>

#include <secure_buffer.hpp>

/*
 * @namespace vaulty::crypto
 * @brief Cryptographic utilities for key derivation and AEAD encryption
 */
namespace vaulty::crypto {

static constexpr size_t kSaltSize = 64;
static constexpr size_t kKeySize = 32;
static constexpr size_t kIvSize = 12;
static constexpr size_t kTagSize = 16;
static constexpr size_t kIterationsCount = 210000;

SecureBuffer deriveEncryptionKey(const SecureBuffer& master_password, const std::array<unsigned char, kSaltSize>& salt);
SecureBuffer encrypt(const SecureBuffer& key, const SecureBuffer& plaintext);
SecureBuffer decrypt(const SecureBuffer& key, const SecureBuffer& blob);

} /* namespace vaulty::crypto */
