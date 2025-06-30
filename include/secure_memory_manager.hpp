#pragma once

#include <stdexcept>

#include <openssl/crypto.h>

namespace vaulty {

/*
 * @class SecureMemoryManager
 * @brief Singleton to initialize and manage OpenSSL's secure heap
 *
 * Ensures secure memory is initialized once per process lifetime and properly
 * cleaned up on destruction. Disallows copying and moving to maintain singleton
 * semantics.
 *
 * @throws std::runtime_error if memory initialization fails
 */
class SecureMemoryManager {
public:
    static void ensureInitialized() {
        static SecureMemoryManager instance;
    }

    ~SecureMemoryManager() {
        CRYPTO_secure_malloc_done();
    }

    SecureMemoryManager(const SecureMemoryManager&) = delete;
    SecureMemoryManager& operator=(const SecureMemoryManager&) = delete;
    SecureMemoryManager(SecureMemoryManager&&) = delete;
    SecureMemoryManager& operator=(SecureMemoryManager&&) = delete;

private:
    SecureMemoryManager() {
        constexpr size_t kSecureMemPoolSize = 32768;
        constexpr size_t kSecureMemMinBlock = 32;

        if (!CRYPTO_secure_malloc_init(kSecureMemPoolSize, kSecureMemMinBlock)) {
            throw std::runtime_error("Failed to initialize OpenSSL secure memory");
        }
    }
};

} /* namespace vaulty */
