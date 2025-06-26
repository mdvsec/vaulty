#include <interface.hpp>

namespace vaulty::cli {

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho) {
    SecureBuffer buffer;

    std::cout << prompt << std::flush;

    auto readInput = [&]() -> ssize_t {
        if (noecho) {
            TerminalEchoGuard guard;
            return read(STDIN_FILENO, buffer.data(), SecureBuffer::kMaxPasswordLength);
        } else {
            return read(STDIN_FILENO, buffer.data(), SecureBuffer::kMaxPasswordLength);
        }
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

int handleAdd(const std::string& domain) {
    Database db;

    SecureBuffer master_password = readMasterPassword();
    SecureBuffer key = crypto::deriveEncryptionKey(master_password, db.getSalt());

    SecureBuffer username = readSensitiveInput("Create new username: ", false);
    SecureBuffer password = readSensitiveInput("Create new password: ");

    Database::Entry entry = {domain, std::move(username), std::move(password)}; /* No designated initializers in C++17 :( */

    if (!db.store(key, entry)) {
        std::cerr << "Error occurred while adding entry for domain: " << domain << std::endl;
        return 1;
    }

    std::cout << "Added entry for domain: " << domain << std::endl;

    return 0;
}

int handleGet(const std::string& domain, const std::string& username_raw) {
    Database db;

    SecureBuffer master_password = readMasterPassword();
    SecureBuffer key = crypto::deriveEncryptionKey(master_password, db.getSalt());

    if (username_raw.empty()) {
        SecureBuffer username = readSensitiveInput("Enter your username: ", false);
        SecureBuffer password;

        if (!db.fetch(key, domain, username, password)) {
            std::cerr << "Error occurred while fetching entry for domain: " << domain << std::endl;
            return 1;
        }

        std::cout << "Password for " << username << " on " << domain << " is: " << password << std::endl;
    } else {
        std::cout << "NOT IMPLEMENTED YET" << std::endl;
    }

    return 0;
}

int handleList(const std::string& domain) {
    return 0;
}

int handleRemove(const std::string& domain, const std::string& username_raw) {
    return 0;
}

} /* namespace vaulty::cli */
