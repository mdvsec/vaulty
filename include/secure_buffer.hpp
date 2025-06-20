#pragma once

#include <sys/mman.h>
#include <openssl/crypto.h>

namespace vaulty {

class SecureBuffer {
public:
    explicit SecureBuffer(size_t size)
        : size_(size), data_(static_cast<unsigned char*>(OPENSSL_secure_zalloc(size))) {
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
        : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& rhs) {
        if (this != &rhs) {
            release();
            data_ = rhs.data_;
            size_ = rhs.size_;
            rhs.data_ = nullptr;
            rhs.size_ = 0;
        }

        return *this;
    }

    ~SecureBuffer() {
        release();
    }

    bool isEqual(const SecureBuffer& other) const {
        if (size_ != other.size_) {
            return false;
        }

        return CRYPTO_memcmp(data_, other.data_, size_) == 0;
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
