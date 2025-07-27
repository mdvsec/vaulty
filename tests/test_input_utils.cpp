#include <fcntl.h>
#include <gtest/gtest.h>
#include <sstream>

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
    std::ostringstream dummy_output;

    SecureBuffer result = readSensitiveInput("Enter password: ", false, dummy_output);
    EXPECT_EQ(result, SecureBuffer("secret"));
}

TEST_F(InputUtilsTest, ReadMasterPasswordMismatch) {
    setInputData("secret\nnosecret\n");
    std::ostringstream dummy_output;

    EXPECT_THROW(readMasterPassword(dummy_output), std::runtime_error);
}
