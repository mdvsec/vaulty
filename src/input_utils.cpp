#include <iostream>

#include <input_utils.hpp>
#include <logger.hpp>

namespace vaulty::cli {

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
