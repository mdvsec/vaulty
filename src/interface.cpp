#include <cstdlib>
#include <iostream>

#include <database.hpp>
#include <input_utils.hpp>
#include <interface.hpp>
#include <logger.hpp>
#include <secure_buffer.hpp>
#include <secure_buffer_writer.hpp>

namespace vaulty::cli {

int handleAdd(const std::string& domain) {
    LOG_INFO("Adding new entry for domain: {}", domain);

    Database db;
    SecureBuffer key;

    {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
        LOG_DEBUG("Derived encryption key for handleAdd()");
    }

    SecureBuffer username = readSensitiveInput("Create new username: ", false);
    SecureBuffer password = readSensitiveInput("Create new password: ");

    Database::Entry entry = {domain, std::move(username), std::move(password)};
    if (!db.store(key, entry)) {
        LOG_ERROR("Failed to store entry for domain: {}", domain);
        return EXIT_FAILURE;
    }

    std::cout << "Added entry for domain: " << domain << std::endl;

    return EXIT_SUCCESS;
}

int handleGet(const std::string& domain, std::string& username_raw) {
    LOG_INFO("Fetching password entry for domain: {}", domain);

    Database db;
    SecureBuffer key;

    {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
        LOG_DEBUG("Derived encryption key for handleGet()");
    }

    SecureBuffer username;
    if (username_raw.empty()) {
        username = readSensitiveInput("Enter your username: ", false);
    } else {
        username = SecureBuffer(username_raw);
    }

    Database::Entry entry = {domain, std::move(username)};
    if (!db.fetch(key, entry)) {
        LOG_ERROR("Failed to fetch entry for domain: {}", domain);
        return EXIT_FAILURE;
    }

    if (!SecureBufferWriter::copyToClipboard(entry.password)) {
        LOG_ERROR("Failed to copy password to clipboard for domain: {}", domain);
        return EXIT_FAILURE;
    }

    LOG_INFO("Password for user copied to clipboard for domain: {}", domain);
    std::cout << "Password for user copied to clipboard for domain " << domain << std::endl;

    return EXIT_SUCCESS;
}

int handleList(bool show_usernames) {
    LOG_INFO("Listing all entries; show usernames: {}", show_usernames);

    Database db;
    SecureBuffer key;

    if (show_usernames) {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
        LOG_DEBUG("Derived encryption key for handleList()");
    }

    std::vector<Database::Entry> db_entries;
    if (!db.fetchAll(db_entries)) {
        LOG_ERROR("Failed to fetch all entries from database");
        return EXIT_FAILURE;
    }

    if (db_entries.empty()) {
        LOG_WARN("Database is empty, no entries found");
        return EXIT_SUCCESS;
    }

    LOG_INFO("Entries count: {}", db_entries.size());
    std::cout << std::endl << "Entries found:" << std::endl;

    for (const auto& [domain, encrypted_username, _] : db_entries) {
        std::cout << "Domain: " << domain << std::endl;

        if (show_usernames) {
            SecureBuffer username = crypto::decrypt(key, encrypted_username);

            std::cout << "Username: " << username << std::endl;
        } else {
            std::cout << "Username: " << "[encrypted]" << std::endl;
            std::cout << "Password: " << "[encrypted]" << std::endl;
        }

        std::cout << std::endl;
    }

    return EXIT_SUCCESS;
}

int handleRemove(const std::string& domain, std::string& username_raw) {
    LOG_INFO("Removing entry for domain: {}", domain);

    Database db;
    SecureBuffer key;

    {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
        LOG_DEBUG("Derived encryption key for handleRemove()");
    }

    SecureBuffer username;
    if (username_raw.empty()) {
        username = readSensitiveInput("Enter your username: ", false);
    } else {
        username = SecureBuffer(username_raw);
    }

    char confirmation;
    std::cout << "Do you really want to delete the entry for domain " << domain
              << " and username " << username << "? [y/N]: ";
    std::cin >> confirmation;

    if (confirmation != 'y' && confirmation != 'Y') {
        LOG_INFO("User aborted removal of entry for domain: {}", domain);
        std::cout << "Aborted" << std::endl;
        return EXIT_FAILURE;
    }

    if (!db.remove(key, Database::Entry{domain, std::move(username)})) {
        LOG_ERROR("Failed to remove entry for domain: {}", domain);
        return EXIT_FAILURE;
    }

    LOG_INFO("Successfully removed entry for domain: {}", domain);
    std::cout << "Entry for user on " << domain << " successfully removed" << std::endl;

    return EXIT_SUCCESS;
}

} /* namespace vaulty::cli */
