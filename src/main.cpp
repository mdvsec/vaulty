#include <iostream>

#include <secure_buffer.hpp>
#include <cli.hpp>

int main() {
    vaulty::SecureBuffer password = vaulty::cli::readMasterPassword();
    std::cout << "Your password is: " << password << std::endl;

    return 0;
}
