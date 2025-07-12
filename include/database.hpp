#pragma once

#include <array>
#include <memory>
#include <string>
#include <string_view>

#include <crypto.hpp>
#include <secure_buffer.hpp>

namespace vaulty {

/*
 * @class Database
 * @brief Manages encrypted storage of user credentials using SQLite
 *
 * Handles secure storage, retrieval, and management of user credentials.
 * Protects sensitive data in memory using SecureBuffer, and enforces access via
 * cryptographic keys. Provides methods to add, fetch, list, and delete
 * credential entries.
 *
 * @throws std::runtime_error if database initialization or opening fails
 */
class Database {
public:
    struct Entry {
        std::string domain;
        SecureBuffer username;
        SecureBuffer password;

        Entry(const std::string& d, SecureBuffer&& u, SecureBuffer&& p = SecureBuffer())
            : domain(d), username(std::move(u)), password(std::move(p)) {}
    };

public:
    explicit Database(std::string_view path = kDefaultPath);

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    Database(Database&&) = delete;
    Database& operator=(Database&&) = delete;

    ~Database();

    const std::array<unsigned char, crypto::kSaltSize>& getSalt() const;

    bool store(const SecureBuffer& key, const Entry& entry);
    bool fetch(const SecureBuffer& key, Entry& entry);
    bool fetchAll(std::vector<Entry>& entries_out);
    bool remove(const SecureBuffer& key, const Entry& entry);

private:
    static constexpr std::string_view kDefaultPath = "passwords.db";

    class Impl;
    std::unique_ptr<Impl> impl_;
};

} /* namespace vaulty */
