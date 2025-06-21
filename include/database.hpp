#pragma once

#include <sqlite3.h>
#include <memory>
#include <string>
#include <string_view>

#include <secure_buffer.hpp>

namespace vaulty {

class Database {
public:
    struct Entry {
        std::string domain;
        SecureBuffer username;
        SecureBuffer password;
    };

public:
    explicit Database(std::string_view path);

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    Database(Database&&) = delete;
    Database& operator=(Database&&) = delete;

    ~Database();

    void lock();
    bool unlock(const SecureBuffer& master_key);

    bool store(const Entry& entry);
    Entry fetch(const std::string& domain, const std::string& username);
    bool remove(const std::string& domain, const std::string& username);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} /* namespace vaulty */
