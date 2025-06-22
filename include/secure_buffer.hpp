#pragma once

#include <sys/mman.h>
#include <openssl/crypto.h>

#include <secure_memory_manager.hpp>

namespace vaulty {

class SecureBuffer {
public:
    explicit SecureBuffer(size_t size)
        : data_(nullptr), size_(size) {
        SecureMemoryManager::ensureInitialized();
        data_ = static_cast<unsigned char*>(OPENSSL_secure_zalloc(size_));
        if (!data_) {
            throw std::runtime_error("Failed to allocate secure memory");
        }
    }

    SecureBuffer(const char* data, size_t size)
        : SecureBuffer(size) {
        std::memcpy(data_, data, size);
    }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other)
        : data_(std::exchange(other.data_, nullptr)),
          size_(std::exchange(other.size_, 0)) {}

    SecureBuffer& operator=(SecureBuffer&& rhs) {
        if (this != &rhs) {
            release();
            data_ = std::exchange(rhs.data_, nullptr);
            size_ = std::exchange(rhs.size_, 0);
        }

        return *this;
    }

    ~SecureBuffer() {
        release();
    }

    bool operator==(const SecureBuffer& other) const {
        if (size_ != other.size_) {
            return false;
        }

        return CRYPTO_memcmp(data_, other.data_, size_) == 0;
    }

    bool operator!=(const SecureBuffer& other) const {
        return !(*this == other);
    }

private:
    unsigned char* data_;
    size_t size_;

private:
    void release() {
        if (data_) {
            OPENSSL_secure_clear_free(data_, size_);
        }
    }
};

} /* namespace vaulty */
