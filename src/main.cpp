#include <string>

#include <secure_buffer.hpp>

int main() {
    std::string str = "superpassword";
    vaulty::SecureBuffer buffer(str.c_str(), str.size());

    return 0;
}
