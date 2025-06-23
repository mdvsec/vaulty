#pragma once

#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include <CLI/CLI.hpp>

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

SecureBuffer readSensitiveInput(std::string_view prompt, bool noecho = true) {
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

int run(int argc, char** argv) {
    std::string domain;
    std::string username_raw;
    SecureBuffer master_password;
    SecureBuffer username;
    SecureBuffer password;

    CLI::App app("vaulty -- CLI password manager", "vaulty");
    app.set_version_flag("--version", "vaulty 0.1");

    auto add = app.add_subcommand("add", "Add a new credential");
    add->add_option("--domain", domain)->required();

    auto get = app.add_subcommand("get", "Get credentials by domain");
    get->add_option("--domain", domain)->required();
    get->add_option("--username", username_raw);

    auto list = app.add_subcommand("list", "List stored credentials");
    list->add_option("--domain", domain);

    auto remove = app.add_subcommand("remove", "Remove a credential");
    remove->add_option("--domain", domain)->required();
    remove->add_option("--username", username_raw);

    CLI11_PARSE(app, argc, argv);

    if (add->parsed()) {
        Database db;

        username = readSensitiveInput("Enter username: ", false);
        password = readSensitiveInput("Enter password: ");

        std::cout << std::endl;

        std::cout << "Username: " << username << std::endl;
        std::cout << "Password: " << password << std::endl;
    } else if (get->parsed()) {
    } else if (list->parsed()) {
    } else if (remove->parsed()) {
        if (username_raw.empty()) {
            username = readSensitiveInput("Enter username: ", false);

            std::cout << std::endl;

            std::cout << "Username: " << username << std::endl;
        } else {
            std::cout << "Username: " << username_raw << std::endl;
        }
    } else {
        std::cout << app.help() << std::endl;
    }

    return 0;
}

} /* namespace vaulty::cli */
