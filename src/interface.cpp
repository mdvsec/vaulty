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

    SecureBuffer username = readSensitiveInput("Create new username: ", false);
    SecureBuffer password = readSensitiveInput("Create new password: ");

    std::cout << std::endl;

    std::cout << "Username: " << username << std::endl;
    std::cout << "Password: " << password << std::endl;

    SecureBuffer key = crypto::deriveEncryptionKey(master_password, db.getSalt());
    std::cout << "Derived key: " << std::hex << key << std::endl;

    SecureBuffer ciphertext = crypto::encrypt(key, password);
    std::cout << "Encrypted password: " << std::hex << ciphertext << std::endl;

    SecureBuffer plaintext = crypto::decrypt(key, ciphertext);
    std::cout << "Decrypted password: " << std::dec << plaintext << std::endl;

    return 0;
}

int handleGet(const std::string& domain, const std::string& username_raw) {
    return 0;
}

int handleList(const std::string& domain) {
    return 0;
}

int handleRemove(const std::string& domain, const std::string& username_raw) {
    return 0;
}

} /* namespace vaulty::cli */
