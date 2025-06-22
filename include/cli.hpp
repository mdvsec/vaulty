#pragma once

#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

#include <secure_buffer.hpp>

namespace vaulty::cli {

constexpr size_t MAX_PASSWORD_LENGTH = 128;

class TerminalEchoGuard {
public:
    TerminalEchoGuard() {
        if (tcgetattr(STDIN_FILENO, &original_)) {
            throw std::runtime_error("Failed to get terminal attributes");
        }

        termios noecho = original_;
        noecho.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho)) {
            throw std::runtime_error("Failed to set terminal attributes");
        }
    }

    ~TerminalEchoGuard() {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
    }

    TerminalEchoGuard(const TerminalEchoGuard&) = delete;
    TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;
    TerminalEchoGuard(TerminalEchoGuard&&) = delete;
    TerminalEchoGuard& operator=(TerminalEchoGuard&&) = delete;

private:
    termios original_;
};

SecureBuffer readMasterPassword() {
    TerminalEchoGuard guard;
    SecureBuffer buffer(MAX_PASSWORD_LENGTH);

    std::cout << "Enter master password: " << std::flush;
    ssize_t bytes_read = read(STDIN_FILENO, buffer.data(), MAX_PASSWORD_LENGTH);
    if (bytes_read <= 0) {
        throw std::runtime_error("Failed to read master password");
    }

    size_t len = static_cast<size_t>(bytes_read);
    if (len > 0 && buffer[len - 1] == '\n') {
        --len;
    }

    std::cout << std::endl;

    buffer.resize(len);

    return buffer; 
}

} /* namespace vaulty::cli */
