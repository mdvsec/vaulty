#pragma once

#include <string>

namespace vaulty::cli {

int handleAdd(const std::string& domain);
int handleGet(const std::string& domain, std::string& username_raw);
int handleList(bool show_usernames = false);
int handleRemove(const std::string& domain, std::string& username_raw);

} /* namespace vaulty::cli */
