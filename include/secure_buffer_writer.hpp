#pragma once

#include <string>

#include <clip.h>
#include <openssl/crypto.h>

#include <secure_buffer.hpp>

namespace vaulty {

/*
 * @class SecureBufferWriter
 * @brief Securely exports SecureBuffer data, e.g., to clipboard with cleansing.
 */
class SecureBufferWriter {
public:
    static bool copyToClipboard(const SecureBuffer& buffer) {
        std::string tmp(reinterpret_cast<const char *>(buffer.data()), buffer.size());
        bool result = clip::set_text(tmp);

        if (tmp.size()) {
            OPENSSL_cleanse(&tmp[0], tmp.size());
        }

        return result;
    }
};

} /* namespace vaulty */
