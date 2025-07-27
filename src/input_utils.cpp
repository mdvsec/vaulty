#include <ostream>

#include <input_utils.hpp>
#include <logger.hpp>

namespace vaulty::cli {

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho, std::ostream& os) {
    LOG_DEBUG("Prompting user for sensitive input: '{}'", prompt);

    os << prompt << std::flush;

    SecureBuffer buffer;
    size_t len = 0;

    if (noecho) {
        TerminalEchoGuard guard;

        char c = 0;
        while (len < SecureBuffer::kMaxPasswordLength) {
            ssize_t n = read(STDIN_FILENO, &c, 1);
            if (n < 0) {
                throw std::runtime_error("Failed to read sensitive input from CLI");
            }

            if (n == 0 || c == '\n') {
                break;
            }

            if (c == '\b' || c == 127) {
                if (len > 0) {
                    --len;
                    os << "\b \b" << std::flush;
                }
            } else {
                buffer[len++] = c;
                os << '*' << std::flush;
            }
        }
        os << std::endl;
    } else {
        ssize_t bytes_read = read(STDIN_FILENO, buffer.data(), SecureBuffer::kMaxPasswordLength);
        if (bytes_read < 0) {
            throw std::runtime_error("Failed to read sensitive input from CLI");
        }

        len = static_cast<size_t>(bytes_read);
        if (len > 0 && buffer[len - 1] == '\n') {
            --len;
        }
    }

    buffer.resize(len);

    LOG_DEBUG("Sensitive input read successfully (length {})", len);
    return buffer;
}

SecureBuffer readMasterPassword(std::ostream& os) {
    LOG_INFO("Requesting master password from user");

    SecureBuffer master_password = readSensitiveInput("Enter master password: ", true, os);
    SecureBuffer verification = readSensitiveInput("Confirm master password: ", true, os);

    if (master_password != verification) {
        throw std::runtime_error("Master password confirmation failed");
    }

    LOG_INFO("Master password confirmed successfully");
    return master_password;
}

} /* namespace vaulty::cli */
