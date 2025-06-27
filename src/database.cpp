#include <filesystem>
#include <stdexcept>
#include <array>
#include <vector>
#include <openssl/rand.h>

#include <database.hpp>
#include <crypto.hpp>

namespace vaulty {

class Database::Impl {
public:
    Impl(std::string_view path)
        : db_(nullptr), kdf_salt_{} {
        bool db_existed = std::filesystem::exists(path);

        if (sqlite3_open_v2(path.data(), &db_,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                            nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database: " + 
                                     std::string(sqlite3_errmsg(db_)));
        }

        applySecurityPragmas();

        if (db_existed) {
            verifyDatabaseIntegrity();
        } else {
            createTables();
            initSecurityParameters();
        }
    }

    ~Impl() {
        if (db_) {
            sqlite3_close(db_);
        }
    }

    const std::array<unsigned char, crypto::kSaltSize>& getSalt() const {
        return kdf_salt_;
    }

    bool store(const SecureBuffer& key, const Entry& entry);
    bool fetch(const SecureBuffer& key, const std::string& domain, const SecureBuffer& username, SecureBuffer& password_out);
    bool fetchAll(std::vector<Entry>& entries_out);
    bool remove(const SecureBuffer& key, const std::string& domain, const SecureBuffer& username);

private:
    sqlite3* db_;
    std::array<unsigned char, crypto::kSaltSize> kdf_salt_;

private:
    void applySecurityPragmas();
    void createTables();
    void initSecurityParameters();
    void verifyDatabaseIntegrity();
    std::vector<std::pair<SecureBuffer, SecureBuffer>> fetchAllByDomain(const std::string& domain);
};

Database::Database(std::string_view path)
    : impl_(std::make_unique<Impl>(path)) {}

Database::~Database() = default;

const std::array<unsigned char, crypto::kSaltSize>& Database::getSalt() const {
    return impl_->getSalt();
}

bool Database::store(const SecureBuffer& key, const Entry& entry) {
    return impl_->store(key, entry);
}

bool Database::fetch(const SecureBuffer& key, const std::string& domain, const SecureBuffer& username, SecureBuffer& password_out) {
    return impl_->fetch(key, domain, username, password_out);
}

bool Database::fetchAll(std::vector<Entry>& entries_out) {
    return impl_->fetchAll(entries_out);
}

bool Database::remove(const SecureBuffer& key, const std::string& domain, const SecureBuffer& username) {
    return impl_->remove(key, domain, username);
}

bool Database::Impl::store(const SecureBuffer& key, const Entry& entry) {
    SecureBuffer encrypted_username = crypto::encrypt(key, entry.username);
    SecureBuffer encrypted_password = crypto::encrypt(key, entry.password);

    const char* sql = "INSERT OR REPLACE INTO passwords (domain, username, password) VALUES (?, ?, ?)";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, entry.domain.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(stmt, 2, encrypted_username.data(), static_cast<int>(encrypted_username.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(stmt, 3, encrypted_password.data(), static_cast<int>(encrypted_password.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        return false;
    }

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return success;
}

bool Database::Impl::fetch(const SecureBuffer& key, const std::string& domain, const SecureBuffer& username, SecureBuffer& password_out) {
    auto entries = fetchAllByDomain(domain);

    for (const auto& [encrypted_username, encrypted_password] : entries) {
        SecureBuffer decrypted_username = crypto::decrypt(key, encrypted_username);
        if (decrypted_username == username) {
            password_out = crypto::decrypt(key, encrypted_password);
            return true;
        }
    }

    return false;
}

bool Database::Impl::fetchAll(std::vector<Entry>& entries_out) {
    const char* sql = "SELECT domain, username, password FROM passwords";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    std::vector<Entry> entries;
    bool done = false;
    while (!done) {
        int ret = sqlite3_step(stmt);
        switch (ret) {
            case SQLITE_ROW: {
                const unsigned char* domain_text = sqlite3_column_text(stmt, 0);
                std::string domain(reinterpret_cast<const char*>(domain_text));

                const void* username_blob = sqlite3_column_blob(stmt, 1);
                int username_size = sqlite3_column_bytes(stmt, 1);

                const void* password_blob = sqlite3_column_blob(stmt, 2);
                int password_size = sqlite3_column_bytes(stmt, 2);

                SecureBuffer encrypted_username(reinterpret_cast<const unsigned char*>(username_blob), username_size);
                SecureBuffer encrypted_password(reinterpret_cast<const unsigned char*>(password_blob), password_size);

                entries.emplace_back(Entry{domain, std::move(encrypted_username), std::move(encrypted_password)});
            }
            case SQLITE_DONE: {
                done = true;
                break;
            }
            default: {
                sqlite3_finalize(stmt);
                return false;
            }
        }
    }

    entries_out = std::move(entries);
    return true;
}

bool Database::Impl::remove(const SecureBuffer& key, const std::string& domain, const SecureBuffer& username) {
    auto entries = fetchAllByDomain(domain);

    for (const auto& [encrypted_username, _] : entries) {
        SecureBuffer decrypted_username = crypto::decrypt(key, encrypted_username);

        if (decrypted_username == username) {
            const char* sql = "DELETE FROM passwords WHERE domain = ? AND username = ?";

            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
                return false;
            }

            if (sqlite3_bind_text(stmt, 1, domain.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_blob(stmt, 2, encrypted_username.data(), static_cast<int>(encrypted_username.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                return false;
            }

            bool success = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);

            return true;
        }
    }

    return false;
}

std::vector<std::pair<SecureBuffer, SecureBuffer>> Database::Impl::fetchAllByDomain(const std::string& domain) {
    const char* sql = "SELECT username, password FROM passwords WHERE domain = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db_)));
    }

    if (sqlite3_bind_text(stmt, 1, domain.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to bind domain parameter");
    }

    std::vector<std::pair<SecureBuffer, SecureBuffer>> results;
    bool done = false;
    while (!done) {
        int ret = sqlite3_step(stmt);
        switch (ret) {
            case SQLITE_ROW: {
                const void* username_blob = sqlite3_column_blob(stmt, 0);
                int username_size = sqlite3_column_bytes(stmt, 0);

                const void* password_blob = sqlite3_column_blob(stmt, 1);
                int password_size = sqlite3_column_bytes(stmt, 1);

                SecureBuffer encrypted_username(reinterpret_cast<const unsigned char*>(username_blob), username_size);
                SecureBuffer encrypted_password(reinterpret_cast<const unsigned char*>(password_blob), password_size);

                results.emplace_back(std::move(encrypted_username), std::move(encrypted_password));
                break;
            }
            case SQLITE_DONE: {
                done = true;
                break;
            }
            default: {
                sqlite3_finalize(stmt);
                throw std::runtime_error("Error executing query");
            }
        }
    }

    sqlite3_finalize(stmt);
    return results;
}

void Database::Impl::applySecurityPragmas() {
    auto executePragma = [&](const std::string& name, const std::string& value) {
        std::string sql = "PRAGMA " + name + "=" + value + ";";
        if (sqlite3_exec(db_, sql.c_str(),
                         nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to set PRAGMA " + name);
        }
    };

    executePragma("journal_mode", "DELETE");
    executePragma("secure_delete", "ON");
}

void Database::Impl::createTables() {
    auto executeSQL = [&](std::string_view sql) {
        if (sqlite3_exec(db_, sql.data(),
                         nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQL execution failed: " +
                                     std::string(sqlite3_errmsg(db_)));
        }
    };

    const char* sql_passwords = "CREATE TABLE IF NOT EXISTS passwords ("
                                "domain TEXT NOT NULL, "
                                "username BLOB NOT NULL, "
                                "password BLOB NOT NULL, "
                                "PRIMARY KEY(domain,username))";

    const char* sql_params = "CREATE TABLE IF NOT EXISTS kdf_params ("
                             "id INTEGER PRIMARY KEY CHECK(id = 1),"
                             "salt BLOB NOT NULL,"
                             "iterations INTEGER NOT NULL)";
    executeSQL(sql_passwords);
    executeSQL(sql_params);
}

void Database::Impl::initSecurityParameters() {
    if (RAND_bytes(kdf_salt_.data(), kdf_salt_.size()) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }

    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO kdf_params (id, salt, iterations) VALUES (1, ?, ?)";
    if (sqlite3_prepare_v2(db_, sql,
                           -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement");
    }

    if (sqlite3_bind_blob(stmt, 1, kdf_salt_.data(),
                          static_cast<int>(kdf_salt_.size()),
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2,
                         static_cast<int>(crypto::kIterationsCount)) != SQLITE_OK) {
        throw std::runtime_error("Failed to bind statement parameters");
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert KDF parameters");
    }

    sqlite3_finalize(stmt);
}

void Database::Impl::verifyDatabaseIntegrity() {
    auto checkTable = [&](const char* table) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
        if (sqlite3_prepare_v2(db_, sql, -1,
                               &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare table existence check");
        }

        if (sqlite3_bind_text(stmt, 1, table,
                              -1, SQLITE_STATIC) != SQLITE_OK) {
            throw std::runtime_error("Failed to bind table existence parameters");
        }

        bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);

        return exists;
    };

    if (!checkTable("passwords") || !checkTable("kdf_params")) {
        throw std::runtime_error("Required tables missing");
    }

    sqlite3_stmt* stmt;
    const char* sql = "SELECT salt, iterations FROM kdf_params WHERE id=1";
    if (sqlite3_prepare_v2(db_, sql, -1,
                           &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare KDF parameters query");
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("KDF parameters not found");
    }

    const void* salt_blob = sqlite3_column_blob(stmt, 0);
    int salt_size = sqlite3_column_bytes(stmt, 0);
    int iterations = sqlite3_column_int(stmt, 1);

    if (!salt_blob || salt_size != static_cast<int>(crypto::kSaltSize)) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Invalid salt in KDF parameters");
    }

    std::memcpy(kdf_salt_.data(), salt_blob, crypto::kSaltSize);

    if (iterations < static_cast<int>(crypto::kIterationsCount)) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Iterations count too low in KDF parameters");
    }

    sqlite3_finalize(stmt);

    const char* integrity_sql = "PRAGMA integrity_check;";
    if (sqlite3_prepare_v2(db_, integrity_sql, -1,
                           &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare integrity check query");
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Integrity check query failed");
    }

    const unsigned char* result = sqlite3_column_text(stmt, 0);
    if (!result ||
        std::string_view(reinterpret_cast<const char*>(result)) != "ok") {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Database integrity check failed");
    }

    sqlite3_finalize(stmt);
}

} /* namespace vaulty */
