#pragma once

#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

#include <secure_buffer.hpp>
#include <database.hpp>

namespace vaulty::cli {

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

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho = true);
int handleAdd(const std::string& domain);
int handleGet(const std::string& domain, const std::string& username_raw);
int handleList(bool show_usernames = false);
int handleRemove(const std::string& domain, const std::string& username_raw);

} /* namespace vaulty::cli */
