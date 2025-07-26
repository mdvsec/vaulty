#pragma once

#include <iomanip>
#include <ios>
#include <ostream>
#include <stdexcept>
#include <string>

#include <openssl/crypto.h>
#include <sys/mman.h>

#include <secure_memory_manager.hpp>

namespace vaulty {

/*
 * @class SecureBuffer
 * @brief Securely allocated memory buffer for sensitive data
 *
 * Allocates memory from OpenSSL's secure heap to protect sensitive data, with
 * automatic cleansing on release. Supports move semantics, constant-time
 * comparison and optional clipboard export with data sanitization.
 *
 * @throws std::runtime_error if memory allocation fails
 * @throws std::invalid_argument if resizing to a larger size is attempted
 * @throws std::out_of_range if index is out of range in operator[]
 */
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

    SecureBuffer(const SecureBuffer& a, const SecureBuffer& b)
        : SecureBuffer(a.size() + b.size()) {
        std::memcpy(data_, a.data(), a.size());
        std::memcpy(data_ + a.size(), b.data(), b.size());
    }

    SecureBuffer(std::string& source)
        : SecureBuffer(source.size()) {
        std::memcpy(data_, source.data(), source.size());
        if (source.size()) {
            OPENSSL_cleanse(&source[0], source.size());
        }
    }

    SecureBuffer(std::string&& source)
        : SecureBuffer(source.size()) {
        std::memcpy(data_, source.data(), source.size());
        if (source.size()) {
            OPENSSL_cleanse(&source[0], source.size());
        }
    }

    SecureBuffer(const void* source, size_t size)
        : SecureBuffer(size) {
        std::memcpy(data_, source, size);
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
            throw std::out_of_range("Index out of bounds");
        }

        return data_[i];
    }

    const unsigned char& operator[](size_t i) const {
        if (i >= size_) {
            throw std::out_of_range("Index out of bounds");
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

    SecureBuffer operator+(const SecureBuffer& rhs) {
        return SecureBuffer(*this, rhs);
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
    if ((os.flags() & std::ios_base::basefield) == std::ios_base::hex) {
        std::ios_base::fmtflags f(os.flags());
        os << std::hex << std::setfill('0');

        for (size_t i = 0; i < buffer.size(); ++i) {
            os << std::setw(2) << static_cast<int>(buffer[i]);
        }

        os.flags(f);
    } else {
        os.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    }

    return os;
}

} /* namespace vaulty */
