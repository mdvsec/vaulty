#pragma once

#include <openssl/crypto.h>
#include <stdexcept>

namespace vaulty {

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
        constexpr size_t SECURE_MEM_POOL_SIZE = 32768;
        constexpr size_t SECURE_MEM_MIN_BLOCK = 32;

        if (!CRYPTO_secure_malloc_init(SECURE_MEM_POOL_SIZE, SECURE_MEM_MIN_BLOCK)) {
            throw std::runtime_error("Failed to initialize OpenSSL secure memory");
        }
    }
};

} /* namespace vaulty */
