#include <fcntl.h>
#include <gtest/gtest.h>

#include <input_utils.hpp>

using namespace vaulty;
using namespace vaulty::cli;

class InputUtilsTest : public ::testing::Test {
protected:
    int original_stdin;

    void SetUp() override {
        original_stdin = dup(STDIN_FILENO);
    }

    void TearDown() override {
        dup2(original_stdin, STDIN_FILENO);
        close(original_stdin);
    }

    void setInputData(const std::string& data) {
        int fds[2];
        pipe(fds);

        write(fds[1], data.c_str(), data.size());
        close(fds[1]);

        dup2(fds[0], STDIN_FILENO);
        close(fds[0]);
    }
};

TEST_F(InputUtilsTest, ReadSensitiveInputWithEcho) {
    setInputData("secret\n");

    SecureBuffer result = readSensitiveInput("Enter password: ", false);
    EXPECT_EQ(result, SecureBuffer("secret"));
}

TEST_F(InputUtilsTest, ReadMasterPasswordMismatch) {
    setInputData("secret\nnosecret\n");

    EXPECT_THROW(readMasterPassword(), std::runtime_error);
}
