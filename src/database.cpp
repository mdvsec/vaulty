#include <filesystem>
#include <stdexcept>
#include <array>
#include <openssl/rand.h>

#include <database.hpp>

namespace vaulty {

Database::Database(std::string_view path)
    : impl_(std::make_unique<Impl>(path)) {}

Database::~Database() = default;

class Database::Impl {
public:
    Impl(std::string_view path)
        : db_(nullptr) {
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

private:
    static constexpr size_t kSaltSize = 64;
    static constexpr size_t kIterationsCount = 210000;

    sqlite3* db_;

private:
    void applySecurityPragmas();
    void createTables();
    void initSecurityParameters();
    void verifyDatabaseIntegrity();
};

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
    std::array<unsigned char, kSaltSize> salt;
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }

    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO kdf_params (id, salt, iterations) VALUES (1, ?, ?)";
    if (sqlite3_prepare_v2(db_, sql,
                           -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement");
    }

    if (sqlite3_bind_blob(stmt, 1, salt.data(),
                          static_cast<int>(salt.size()),
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2,
                         kIterationsCount) != SQLITE_OK) {
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

    if (!salt_blob || salt_size != kSaltSize) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Invalid salt in KDF parameters");
    }

    if (iterations < kIterationsCount) {
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
