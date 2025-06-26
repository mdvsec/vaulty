#pragma once

#include <sqlite3.h>
#include <memory>
#include <string>
#include <array>
#include <string_view>

#include <secure_buffer.hpp>
#include <crypto.hpp>

namespace vaulty {

class Database {
public:
    struct Entry {
        std::string domain;
        SecureBuffer username;
        SecureBuffer password;
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
    bool fetch(const SecureBuffer& key, const std::string& domain, const SecureBuffer& username, SecureBuffer& password_out);
    bool remove(const std::string& domain, const std::string& username);

private:
    static constexpr std::string_view kDefaultPath = "passwords.db";

    class Impl;
    std::unique_ptr<Impl> impl_;
};

} /* namespace vaulty */
