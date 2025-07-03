#include <filesystem>
#include <memory>

#include <gtest/gtest.h>

#include <database.hpp>

using namespace vaulty;

class DatabaseTest : public ::testing::Test {
protected:
    std::string db_path = "test_passwords.db";
    std::unique_ptr<Database> db;
    SecureBuffer key;

    void SetUp() override {
        std::filesystem::remove(db_path);

        db = std::make_unique<Database>(db_path);
        key = crypto::deriveEncryptionKey(SecureBuffer("secret"), db->getSalt());
    }

    void TearDown() override {
        db.reset();
        std::filesystem::remove(db_path);
    }
};

TEST_F(DatabaseTest, StoreAndFetchEntry) {
    Database::Entry entry("example.com", SecureBuffer("user"), SecureBuffer("password"));
    EXPECT_TRUE(db->store(key, entry));

    Database::Entry fetched("example.com", SecureBuffer("user"));
    EXPECT_TRUE(db->fetch(key, fetched));
    EXPECT_EQ(fetched.password, SecureBuffer("password"));
}

TEST_F(DatabaseTest, StoredDataIsEncrypted) {
    Database::Entry entry("secure.com", SecureBuffer("username"), SecureBuffer("password"));
    ASSERT_TRUE(db->store(key, entry));

    sqlite3* raw_db = nullptr;
    ASSERT_EQ(sqlite3_open(db_path.c_str(), &raw_db), SQLITE_OK);

    const char* sql = "SELECT username, password FROM passwords WHERE domain = 'secure.com'";
    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(raw_db, sql, -1, &stmt, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);

    const void* username_blob = sqlite3_column_blob(stmt, 0);
    int username_size = sqlite3_column_bytes(stmt, 0);
    const void* password_blob = sqlite3_column_blob(stmt, 1);
    int password_size = sqlite3_column_bytes(stmt, 1);

    std::string username(reinterpret_cast<const char*>(username_blob), username_size);
    std::string password(reinterpret_cast<const char*>(password_blob), password_size);

    sqlite3_finalize(stmt);
    sqlite3_close(raw_db);

    EXPECT_EQ(username.find("username"), std::string::npos);
    EXPECT_EQ(password.find("password"), std::string::npos);
}

TEST_F(DatabaseTest, FetchNonexistentEntryReturnsFalse) {
    Database::Entry entry("nonexistent.com", SecureBuffer("user"));
    EXPECT_FALSE(db->fetch(key, entry));
}

TEST_F(DatabaseTest, RemoveEntryWorks) {
    Database::Entry entry("nonexistent.com", SecureBuffer("user"), SecureBuffer("password"));
    ASSERT_TRUE(db->store(key, entry));

    EXPECT_TRUE(db->remove(key, entry));

    Database::Entry fetched("nonexistent.com", SecureBuffer("user"));
    EXPECT_FALSE(db->fetch(key, fetched));
}

TEST_F(DatabaseTest, RemoveNonexistentEntryReturnsFalse) {
    Database::Entry not_entry("nonexistent.com", SecureBuffer("user"), SecureBuffer("password"));
    EXPECT_FALSE(db->remove(key, not_entry));
}

TEST_F(DatabaseTest, FetchAllReturnsStoredEntries) {
    Database::Entry entry1("example.com", SecureBuffer("user1"), SecureBuffer("password1"));
    Database::Entry entry2("test.com", SecureBuffer("user2"), SecureBuffer("password2"));

    ASSERT_TRUE(db->store(key, entry1));
    ASSERT_TRUE(db->store(key, entry2));

    std::vector<Database::Entry> entries;
    EXPECT_TRUE(db->fetchAll(entries));

    bool found1 = false, found2 = false;
    for (const auto& e : entries) {
        if (e.domain == "example.com") {
            found1 = true;
        } else if (e.domain == "test.com") {
            found2 = true;
        }
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST_F(DatabaseTest, FetchWithWrongKeyFailsToDecrypt) {
    Database::Entry entry("example.com", SecureBuffer("user"), SecureBuffer("password"));
    ASSERT_TRUE(db->store(key, entry));

    SecureBuffer wrong_password("wrongpassword");
    SecureBuffer wrong_key = crypto::deriveEncryptionKey(wrong_password, db->getSalt());

    Database::Entry fetched("example.com", SecureBuffer("user"));
    EXPECT_THROW(db->fetch(wrong_key, fetched), std::runtime_error);
}
