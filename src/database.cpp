#include <array>
#include <filesystem>
#include <stdexcept>
#include <vector>

#include <openssl/rand.h>

#include <crypto.hpp>
#include <database.hpp>
#include <logger.hpp>

namespace vaulty {

class Database::Impl {
public:
    Impl(std::string_view path)
        : db_(nullptr), kdf_salt_{} {
        bool db_existed = std::filesystem::exists(path);

        LOG_INFO("Opening database at path '{}'", path);

        if (sqlite3_open_v2(path.data(), &db_,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                            nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database: " + 
                                     std::string(sqlite3_errmsg(db_)));
        }

        applySecurityPragmas();

        if (db_existed) {
            LOG_INFO("Existing database detected, verifying integrity");
            verifyDatabaseIntegrity();
        } else {
            LOG_INFO("No existing database found, creating tables and initializing security parameters");
            createTables();
            initSecurityParameters();
        }
    }

    ~Impl() {
        if (db_) {
            LOG_INFO("Closing database");
            sqlite3_close(db_);
        }
    }

    const std::array<unsigned char, crypto::kSaltSize>& getSalt() const {
        return kdf_salt_;
    }

    bool store(const SecureBuffer& key, const Entry& entry);
    bool fetch(const SecureBuffer& key, Entry& entry);
    bool fetchAll(std::vector<Entry>& entries_out);
    bool remove(const SecureBuffer& key, const Entry& entry);

private:
    sqlite3* db_;
    std::array<unsigned char, crypto::kSaltSize> kdf_salt_;

private:
    void applySecurityPragmas();
    void createTables();
    void initSecurityParameters();
    void verifyDatabaseIntegrity();
    bool fetchAllByDomain(const std::string& domain, std::vector<Entry>& entries_out);
};

bool Database::Impl::store(const SecureBuffer& key, const Entry& entry) {
    LOG_INFO("Storing entry for domain '{}'", entry.domain);

    SecureBuffer encrypted_username = crypto::encrypt(key, entry.username);
    SecureBuffer encrypted_password = crypto::encrypt(key, entry.password);

    const char* sql = "INSERT OR REPLACE INTO passwords (domain, username, password) VALUES (?, ?, ?)";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement for storing entry: {}", sqlite3_errmsg(db_));
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, entry.domain.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(stmt, 2, encrypted_username.data(), static_cast<int>(encrypted_username.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(stmt, 3, encrypted_password.data(), static_cast<int>(encrypted_password.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
        LOG_ERROR("Failed to bind parameters for storing entry");
        return false;
    }

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    if (success) {
        LOG_INFO("Successfully stored entry for domain '{}'", entry.domain);
    } else {
        LOG_ERROR("Failed to execute statement to store entry for domain '{}'", entry.domain);
    }

    return success;
}

bool Database::Impl::fetch(const SecureBuffer& key, Entry& entry) {
    LOG_INFO("Fetching password for domain '{}'", entry.domain);

    std::vector<Entry> db_entries;
    if (!fetchAllByDomain(entry.domain, db_entries)) {
        return false;
    }

    for (auto& [_, encrypted_username, encrypted_password] : db_entries) {
        SecureBuffer decrypted_username = crypto::decrypt(key, encrypted_username);
        if (decrypted_username == entry.username) {
            SecureBuffer decrypted_password = crypto::decrypt(key, encrypted_password);
            entry.password = std::move(decrypted_password);
            LOG_INFO("Password fetched for domain '{}'", entry.domain);
            return true;
        }
    }

    LOG_WARN("No matching username found for domain '{}'", entry.domain);
    return false;
}

bool Database::Impl::fetchAll(std::vector<Entry>& entries_out) {
    LOG_INFO("Fetching all entries from database");

    const char* sql = "SELECT domain, username, password FROM passwords";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement for fetching all entries: {}", sqlite3_errmsg(db_));
        return false;
    }

    std::vector<Entry> db_entries;
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

                SecureBuffer encrypted_username(username_blob, username_size);
                SecureBuffer encrypted_password(password_blob, password_size);

                db_entries.emplace_back(Entry{domain, std::move(encrypted_username), std::move(encrypted_password)});
            }
            case SQLITE_DONE: {
                done = true;
                break;
            }
            default: {
                LOG_ERROR("Error executing fetchAll query: {}", sqlite3_errmsg(db_));
                sqlite3_finalize(stmt);
                return false;
            }
        }
    }

    sqlite3_finalize(stmt);

    LOG_INFO("Fetched {} entries from database", db_entries.size());

    entries_out = std::move(db_entries);
    return true;
}

bool Database::Impl::remove(const SecureBuffer& key, const Entry& entry) {
    LOG_INFO("Removing entry for domain '{}'", entry.domain);

    std::vector<Entry> db_entries;
    if (!fetchAllByDomain(entry.domain, db_entries)) {
        return false;
    }

    for (const auto& [_, encrypted_username, encrypted_password] : db_entries) {
        SecureBuffer decrypted_username = crypto::decrypt(key, encrypted_username);

        if (decrypted_username == entry.username) {
            const char* sql = "DELETE FROM passwords WHERE domain = ? AND username = ?";

            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
                LOG_ERROR("Failed to prepare statement for removal: {}", sqlite3_errmsg(db_));
                return false;
            }

            if (sqlite3_bind_text(stmt, 1, entry.domain.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_blob(stmt, 2, encrypted_username.data(), static_cast<int>(encrypted_username.size()), SQLITE_TRANSIENT) != SQLITE_OK) {
                LOG_ERROR("Failed to bind parameters for removal");
                sqlite3_finalize(stmt);
                return false;
            }

            bool success = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);

            if (success) {
                LOG_INFO("Successfully removed entry for domain '{}'", entry.domain);
            } else {
                LOG_ERROR("Failed to execute removal for domain '{}'", entry.domain);
            }

            return success;
        }
    }

    LOG_WARN("No matching entry found to remove for domain '{}'", entry.domain);
    return false;
}

bool Database::Impl::fetchAllByDomain(const std::string& domain, std::vector<Entry>& entries_out) {
    LOG_INFO("Fetching all entries by domain '{}'", domain);

    std::vector<Entry> db_entries;
    if (!fetchAll(db_entries)) {
        return false;
    }

    db_entries.erase(
        std::remove_if(db_entries.begin(), db_entries.end(),
                       [&domain](const Entry& entry) { return entry.domain != domain; }),
        db_entries.end()
    );
    entries_out = std::move(db_entries);

    LOG_INFO("Fetched {} entries for domain '{}'", entries_out.size(), domain);

    return true;
}

void Database::Impl::applySecurityPragmas() {
    LOG_INFO("Applying SQLite security pragmas");

    auto executePragma = [&](const std::string& name, const std::string& value) {
        std::string sql = "PRAGMA " + name + "=" + value + ";";
        if (sqlite3_exec(db_, sql.c_str(),
                         nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to set PRAGMA " + name);
        }
    };

    executePragma("journal_mode", "DELETE");
    executePragma("secure_delete", "ON");

    LOG_INFO("SQLite security pragmas applied");
}

void Database::Impl::createTables() {
    LOG_INFO("Creating database tables");

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

    LOG_INFO("Database tables created");
}

void Database::Impl::initSecurityParameters() {
    LOG_INFO("Initializing security parameters");

    if (RAND_bytes(kdf_salt_.data(), kdf_salt_.size()) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }

    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO kdf_params (id, salt, iterations) VALUES (1, ?, ?)";
    if (sqlite3_prepare_v2(db_, sql,
                           -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement for inserting KDF salt: {}", sqlite3_errmsg(db_));
        throw std::runtime_error("Failed to prepare statement");
    }

    if (sqlite3_bind_blob(stmt, 1, kdf_salt_.data(),
                          static_cast<int>(kdf_salt_.size()),
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2,
                         static_cast<int>(crypto::kIterationsCount)) != SQLITE_OK) {
        LOG_ERROR("Failed to bind KDF salt parameter");
        throw std::runtime_error("Failed to bind statement parameters");
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        LOG_ERROR("Failed to insert KDF salt");
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert KDF parameters");
    }

    sqlite3_finalize(stmt);

    LOG_INFO("Security parameters initialized");
}

void Database::Impl::verifyDatabaseIntegrity() {
    LOG_INFO("Verifying database integrity");

    auto checkTable = [&](const char* table) {
        LOG_INFO("Checking existence of table '{}'", table);

        sqlite3_stmt* stmt;
        const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
        if (sqlite3_prepare_v2(db_, sql, -1,
                               &stmt, nullptr) != SQLITE_OK) {
            LOG_ERROR("Failed to prepare table existence check for '{}'", table);
            throw std::runtime_error("Failed to prepare table existence check");
        }

        if (sqlite3_bind_text(stmt, 1, table,
                              -1, SQLITE_STATIC) != SQLITE_OK) {
            LOG_ERROR("Failed to bind parameters for table '{}'", table);
            throw std::runtime_error("Failed to bind table existence parameters");
        }

        bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);

        LOG_INFO("Table '{}' existence: {}", table, exists ? "found" : "not found");
        return exists;
    };

    if (!checkTable("passwords") || !checkTable("kdf_params")) {
        LOG_ERROR("Required tables missing");
        throw std::runtime_error("Required tables missing");
    }

    LOG_INFO("Fetching KDF parameters");
    sqlite3_stmt* stmt;
    const char* sql = "SELECT salt, iterations FROM kdf_params WHERE id=1";
    if (sqlite3_prepare_v2(db_, sql, -1,
                           &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare KDF parameters query");
        throw std::runtime_error("Failed to prepare KDF parameters query");
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        LOG_ERROR("KDF parameters not found");
        throw std::runtime_error("KDF parameters not found");
    }

    const void* salt_blob = sqlite3_column_blob(stmt, 0);
    int salt_size = sqlite3_column_bytes(stmt, 0);
    int iterations = sqlite3_column_int(stmt, 1);

    if (!salt_blob || salt_size != static_cast<int>(crypto::kSaltSize)) {
        sqlite3_finalize(stmt);
        LOG_ERROR("Invalid salt in KDF parameters");
        throw std::runtime_error("Invalid salt in KDF parameters");
    }

    std::memcpy(kdf_salt_.data(), salt_blob, crypto::kSaltSize);
    LOG_INFO("KDF salt loaded, iterations: {}", iterations);

    if (iterations < static_cast<int>(crypto::kIterationsCount)) {
        sqlite3_finalize(stmt);
        LOG_ERROR("Iterations count too low in KDF parameters: {}", iterations);
        throw std::runtime_error("Iterations count too low in KDF parameters");
    }

    sqlite3_finalize(stmt);

    LOG_INFO("Performing PRAGMA integrity_check");
    const char* integrity_sql = "PRAGMA integrity_check;";
    if (sqlite3_prepare_v2(db_, integrity_sql, -1,
                           &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare integrity check query");
        throw std::runtime_error("Failed to prepare integrity check query");
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        LOG_ERROR("Integrity check query failed");
        throw std::runtime_error("Integrity check query failed");
    }

    const unsigned char* result = sqlite3_column_text(stmt, 0);
    if (!result ||
        std::string_view(reinterpret_cast<const char*>(result)) != "ok") {
        sqlite3_finalize(stmt);
        LOG_ERROR("Database integrity check failed");
        throw std::runtime_error("Database integrity check failed");
    }

    sqlite3_finalize(stmt);

    LOG_INFO("Database integrity verified");
}

Database::Database(std::string_view path)
    : impl_(std::make_unique<Impl>(path)) {}

Database::~Database() = default;

const std::array<unsigned char, crypto::kSaltSize>& Database::getSalt() const {
    return impl_->getSalt();
}

bool Database::store(const SecureBuffer& key, const Entry& entry) {
    return impl_->store(key, entry);
}

bool Database::fetch(const SecureBuffer& key, Entry& entry) {
    return impl_->fetch(key, entry);
}

bool Database::fetchAll(std::vector<Entry>& entries_out) {
    return impl_->fetchAll(entries_out);
}

bool Database::remove(const SecureBuffer& key, const Entry& entry) {
    return impl_->remove(key, entry);
}

} /* namespace vaulty */
