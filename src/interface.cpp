#include <cstdlib>

#include <interface.hpp>

namespace vaulty::cli {

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho = true);
SecureBuffer readMasterPassword();

int handleAdd(const std::string& domain) {
    Database db;
    SecureBuffer key;

    {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
    }

    SecureBuffer username = readSensitiveInput("Create new username: ", false);
    SecureBuffer password = readSensitiveInput("Create new password: ");

    Database::Entry entry = {domain, std::move(username), std::move(password)};
    if (!db.store(key, entry)) {
        std::cerr << "Error occurred while adding entry for domain: " << domain << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Added entry for domain: " << domain << std::endl;

    return EXIT_SUCCESS;
}

int handleGet(const std::string& domain, const std::string& username_raw) {
    Database db;
    SecureBuffer key;

    {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
    }

    SecureBuffer username;
    if (username_raw.empty()) {
        username = readSensitiveInput("Enter your username: ", false);
   } else {
        username = SecureBuffer(username_raw.data(), username_raw.size());
    }

    SecureBuffer password;
    if (!db.fetch(key, domain, username, password)) {
        std::cerr << "Error occurred while fetching entry for domain: " << domain << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Password for " << username << " on " << domain << " is: " << password << std::endl;

    return EXIT_SUCCESS;
}

int handleList(bool show_usernames) {
    Database db;
    SecureBuffer key;

    if (show_usernames) {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
    }

    std::vector<Database::Entry> entries;
    if (!db.fetchAll(entries)) {
        std::cerr << "Error occured while fetching all entries from database" << std::endl;
        return EXIT_FAILURE;
    }

    if (entries.empty()) {
        std::cout << "Database is empty, no entries found" << std::endl;
        return EXIT_SUCCESS;
    }

    std::cout << std::endl << "Entries found:" << std::endl;

    for (const auto& [domain, encrypted_username, _] : entries) {
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

int handleRemove(const std::string& domain, const std::string& username_raw) {
    Database db;
    SecureBuffer key;

    {
        SecureBuffer master_password = readMasterPassword();
        key = crypto::deriveEncryptionKey(master_password, db.getSalt());
    }

    SecureBuffer username;
    if (username_raw.empty()) {
        username = readSensitiveInput("Enter your username: ", false);
    } else {
        username = SecureBuffer(username_raw.data(), username_raw.size());
    }

    char confirmation;
    std::cout << "Do you really want to delete the entry for domain " << domain
              << " and username " << username << "? [y/N]: ";
    std::cin >> confirmation;

    if (confirmation != 'y' && confirmation != 'Y') {
        std::cout << "Aborted" << std::endl;
        return EXIT_FAILURE;
    }

    if (!db.remove(key, domain, username)) {
        std::cerr << "Failed to remove entry for domain: " << domain << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Entry for " << username << " on "
              << domain << " successfully removed." << std::endl;

    return EXIT_SUCCESS;
}

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho) {
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
        throw std::runtime_error("Aborted: failed to read from the CLI");
    }

    size_t len = static_cast<size_t>(bytes_read);
    if (len > 0 && buffer[len - 1] == '\n') {
        --len;
    }

    if (noecho) {
        std::cout << std::endl;
    }

    buffer.resize(len);

    return buffer;
}

SecureBuffer readMasterPassword() {
    SecureBuffer master_password = readSensitiveInput("Enter master password: ");
    SecureBuffer verification = readSensitiveInput("Confirm master password: ");

    if (master_password != verification) {
        throw std::runtime_error("Aborted: passwords do not match");
    }

    return master_password;
}

} /* namespace vaulty::cli */
