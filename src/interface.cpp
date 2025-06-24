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
        throw std::runtime_error("Failed to read master password");
    }

    size_t len = static_cast<size_t>(bytes_read);
    if (len > 0 && buffer[len - 1] == '\n') {
        --len;
    }

    buffer.resize(len);

    return buffer; 
}

int handleAdd(const std::string& domain) {
    Database db;
    SecureBuffer username;
    SecureBuffer password;

    username = readSensitiveInput("Enter username: ", false);
    password = readSensitiveInput("Enter password: ");

    std::cout << std::endl;

    std::cout << "Username: " << username << std::endl;
    std::cout << "Password: " << password << std::endl;

    SecureBuffer key = crypto::deriveEncryptionKey(password, db.getSalt());
    std::cout << "Derived key: " << std::hex << key << std::endl;

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
