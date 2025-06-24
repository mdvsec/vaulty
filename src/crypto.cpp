#include <openssl/evp.h>
#include <array>

#include <crypto.hpp>

namespace vaulty::crypto {

SecureBuffer deriveEncryptionKey(const SecureBuffer& masterPassword, const std::array<unsigned char, kSaltSize>& salt) {
    SecureBuffer key(kKeySize);

    if (!PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(masterPassword.data()),
                           static_cast<int>(masterPassword.size()),
                           salt.data(),
                           static_cast<int>(kSaltSize),
                           static_cast<int>(kIterationsCount),
                           EVP_sha512(),
                           static_cast<int>(kKeySize),
                           key.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC key derivation failed");
    }

    return key;
}

} /* namespace vaulty::crypto */
