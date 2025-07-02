#include <cstdlib>

#include <interface.hpp>
#include <logger.hpp>

namespace vaulty::cli {

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho = true);
SecureBuffer readMasterPassword();

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

    LOG_INFO("Successfully added entry for domain: {}", domain);
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

    if (!entry.password.copyToClipboard()) {
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

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho) {
    LOG_DEBUG("Prompting user for sensitive input: '{}'", prompt);
    SecureBuffer buffer;

    std::cout << prompt << std::flush;

    auto readInput = [&]() -> ssize_t {
        if (noecho) {
            TerminalEchoGuard guard;
            return read(STDIN_FILENO, buffer.data(), SecureBuffer::kMaxPasswordLength);
        }

        return read(STDIN_FILENO, buffer.data(), SecureBuffer::kMaxPasswordLength);
    };

    ssize_t bytes_read = readInput();
    if (bytes_read <= 0) {
        throw std::runtime_error("Failed to read sensitive input from CLI");
    }

    size_t len = static_cast<size_t>(bytes_read);
    if (len > 0 && buffer[len - 1] == '\n') {
        --len;
    }

    if (noecho) {
        std::cout << std::endl;
    }

    buffer.resize(len);

    LOG_DEBUG("Sensitive input read successfully (length {})", len);
    return buffer;
}

SecureBuffer readMasterPassword() {
    LOG_INFO("Requesting master password from user");

    SecureBuffer master_password = readSensitiveInput("Enter master password: ");
    SecureBuffer verification = readSensitiveInput("Confirm master password: ");

    if (master_password != verification) {
        throw std::runtime_error("Master password confirmation failed");
    }

    LOG_INFO("Master password confirmed successfully");
    return master_password;
}

} /* namespace vaulty::cli */
