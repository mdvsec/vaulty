#include <string>

#include <secure_buffer.hpp>

static constexpr size_t SECURE_MEM_POOL_SIZE = 32768;
static constexpr size_t SECURE_MEM_MIN_BLOCK = 32;

int main() {
    /* TDB: constructor? */
    if (!CRYPTO_secure_malloc_init(SECURE_MEM_POOL_SIZE, SECURE_MEM_MIN_BLOCK)) {
        return 1;
    }

    std::string str = "superpassword";
    vaulty::SecureBuffer buffer(str.c_str(), str.size());

    return 0;
}
