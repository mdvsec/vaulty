#pragma once

#include <iostream>
#include <stdexcept>
#include <string_view>

#include <unistd.h>
#include <termios.h>

#include <secure_buffer.hpp>

namespace vaulty::cli {

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho = true, std::ostream& os = std::cout);
SecureBuffer readMasterPassword(std::ostream& os = std::cout);

/*
 * @class TerminalEchoGuard
 * @brief RAII guard to disable terminal echo while active
 *
 * Disables echo on stdin (useful for password input), restoring original
 * terminal settings on destruction.
 *
 * @throws std::runtime_error if terminal attributes cannot be changed
 */
class TerminalEchoGuard {
public:
    TerminalEchoGuard() {
        if (tcgetattr(STDIN_FILENO, &original_)) {
            throw std::runtime_error("Failed to get terminal attributes");
        }

        termios noecho = original_;
        noecho.c_lflag &= ~(ECHO | ICANON);
        noecho.c_cc[VMIN] = 1;
        noecho.c_cc[VTIME] = 0;

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

} /* namespace vaulty::cli */
