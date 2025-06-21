#include <filesystem>
#include <stdexcept>

#include <database.hpp>

namespace vaulty {

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
    sqlite3* db_;

private:
    void executeSQL(std::string_view sql) {
        if (sqlite3_exec(db_, sql.data(),
                         nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQL execution failed: " +
                                     std::string(sqlite3_errmsg(db_)));
        }
    }

    void executePragma(const std::string& name, const std::string& value) {
        std::string sql = "PRAGMA " + name + "=" + value + ";";
        if (sqlite3_exec(db_, sql.c_str(),
                         nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to set PRAGMA " + name);
        }
    }

    void applySecurityPragmas() {
        executePragma("journal_mode", "DELETE");
        executePragma("secure_delete", "ON");
    }

    void createTables() {
        const char* query = "CREATE TABLE IF NOT EXISTS passwords ("
                            "domain TEXT NOT NULL, "
                            "username BLOB NOT NULL, "
                            "password BLOB NOT NULL, "
                            "PRIMARY_KEY(domain,username))";
        executeSQL(query);
    }

    void initSecurityParameters() {

    }

    void verifyDatabaseIntegrity() {

    }
};

} /* namespace vaulty */
