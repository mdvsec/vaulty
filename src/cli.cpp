#include <cstdlib>
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>

#include <cli.hpp>
#include <interface.hpp>

namespace vaulty::cli {

int run(int argc, char** argv) {
    int ret = EXIT_SUCCESS;

    try {
        std::string domain;
        std::string username_raw;
        bool show_usernames = false;

        CLI::App app("vaulty -- CLI password manager", "vaulty");
        app.set_version_flag("--version", "vaulty 0.1");

        auto add = app.add_subcommand("add", "Add a new credential");
        add->add_option("--domain", domain)->required();

        auto get = app.add_subcommand("get", "Get credentials by domain");
        get->add_option("--domain", domain)->required();
        get->add_option("--username", username_raw, "Get password for specific username");

        auto list = app.add_subcommand("list", "List stored credentials");
        list->add_flag("--show", show_usernames, "Show decrypted usernames");

        auto remove = app.add_subcommand("remove", "Remove a credential");
        remove->add_option("--domain", domain)->required();
        remove->add_option("--username", username_raw);

        CLI11_PARSE(app, argc, argv);

        if (add->parsed()) {
            ret = handleAdd(domain);
        } else if (get->parsed()) {
            ret = handleGet(domain, username_raw);
        } else if (list->parsed()) {
            ret = handleList(show_usernames);
        } else if (remove->parsed()) {
            ret = handleRemove(domain, username_raw);
        } else {
            std::cout << app.help() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }

    return ret;
}

} /* namespace vaulty::cli */
