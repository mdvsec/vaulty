#pragma once

#include <array>

#include <secure_buffer.hpp>

namespace vaulty::crypto {

static constexpr size_t kSaltSize = 64;
static constexpr size_t kKeySize = 32;
static constexpr size_t kIterationsCount = 210000;

SecureBuffer deriveEncryptionKey(const SecureBuffer& masterPassword, const std::array<unsigned char, kSaltSize>& salt);

} /* namespace vaulty::crypto */
