#pragma once

#include <sys/mman.h>
#include <openssl/crypto.h>
#include <utility>
#include <ostream>

#include <secure_memory_manager.hpp>

namespace vaulty {

class SecureBuffer {
public:
    static constexpr size_t kMaxPasswordLength = 128;

public:
    explicit SecureBuffer(size_t size = kMaxPasswordLength)
        : data_(nullptr), size_(size) {
        SecureMemoryManager::ensureInitialized();
        data_ = static_cast<unsigned char*>(OPENSSL_secure_zalloc(size_));
        if (!data_) {
            throw std::runtime_error("Failed to allocate secure memory");
        }
    }

    ~SecureBuffer() {
        release();
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

    unsigned char& operator[](size_t i) {
        if (i >= size_) {
            throw std::runtime_error("Index out of bounds");
        }

        return data_[i];
    }

    const unsigned char& operator[](size_t i) const {
        if (i >= size_) {
            throw std::runtime_error("Index out of bounds");
        }

        return data_[i];
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

    unsigned char* data() const {
        return data_;
    }

    size_t size() const {
        return size_;
    }

    void resize(size_t new_size) {
        if (new_size > size_) {
            throw std::invalid_argument("Resize to larger size is not supported");
        }

        if (new_size < size_) {
            OPENSSL_cleanse(data_ + new_size, size_ - new_size);
            size_ = new_size;
        }
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

inline std::ostream& operator<<(std::ostream& os, const SecureBuffer& buffer) {
    os.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return os;
}

} /* namespace vaulty */
