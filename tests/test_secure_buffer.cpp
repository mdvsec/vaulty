#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include <secure_buffer.hpp>

using namespace vaulty;

TEST(SecureBufferTest, ConstructsWithDefaultSize) {
    SecureBuffer buffer;
    EXPECT_EQ(buffer.size(), SecureBuffer::kMaxPasswordLength);
    EXPECT_NE(buffer.data(), nullptr);
}

TEST(SecureBufferTest, ConstructsFromTwoBuffers) {
    SecureBuffer a(std::string("foo"));
    SecureBuffer b(std::string("bar"));
    SecureBuffer result(a, b);

    std::string expected = "foobar";
    EXPECT_EQ(result.size(), expected.size());
    EXPECT_EQ(std::memcmp(result.data(), expected.data(), expected.size()), 0);
}

TEST(SecureBufferTest, ConstructsFromStringCleansesInput) {
    std::string input = "secret";
    std::string original = input;

    SecureBuffer buffer(input);

    EXPECT_EQ(std::memcmp(buffer.data(), original.data(), original.size()), 0);
    for (char& c : input) {
        EXPECT_EQ(c, 0);
    }
}

TEST(SecureBufferTest, ConstructsFromRawPointer) {
    const char source[] = {'a', 'b', 'c', '\0', 'x'};
    size_t len = sizeof(source);

    SecureBuffer buffer(source, len);

    EXPECT_EQ(buffer.size(), len);
    EXPECT_EQ(std::memcmp(buffer.data(), source, len), 0);
}

TEST(SecureBufferTest, MoveConstructorWorks) {
    SecureBuffer original(std::string("secret"));
    auto original_ptr = original.data();

    SecureBuffer moved(std::move(original));

    EXPECT_EQ(moved.data(), original_ptr);
    EXPECT_EQ(original.size(), 0);
    EXPECT_EQ(original.data(), nullptr);
}

TEST(SecureBufferTest, MoveAssignmentWorks) {
    SecureBuffer source(std::string("secret"));
    auto source_ptr = source.data();

    SecureBuffer dest(std::string("temp"));
    dest = std::move(source);

    EXPECT_EQ(dest.data(), source_ptr);
    EXPECT_EQ(source.size(), 0);
    EXPECT_EQ(source.data(), nullptr);
}

TEST(SecureBufferTest, ThrowsOnOutOfRangeAccess) {
    SecureBuffer buffer(4);

    EXPECT_THROW(buffer[4], std::out_of_range);
    EXPECT_NO_THROW(buffer[3]);
}

TEST(SecureBufferTest, EqualityAndInequality) {
    SecureBuffer a(std::string("secret"));
    SecureBuffer b(std::string("secret"));
    SecureBuffer c(std::string("not a secret"));

    EXPECT_TRUE(a == b);
    EXPECT_FALSE(a == c);
    EXPECT_TRUE(a != c);
}

TEST(SecureBufferTest, ConcatenationWorks) {
    SecureBuffer a(std::string("foo"));
    SecureBuffer b(std::string("bar"));
    
    auto result = a + b;

    std::string expected = "foobar";
    EXPECT_EQ(result.size(), expected.size());
    EXPECT_EQ(std::memcmp(result.data(), expected.data(), expected.size()), 0);
}

TEST(SecureBufferTest, ConcatenatesEmptyBuffers) {
    SecureBuffer empty1(0);
    SecureBuffer empty2(0);
    SecureBuffer data(std::string("secret"));

    auto result1 = empty1 + empty2;
    EXPECT_EQ(result1.size(), 0);

    auto result2 = empty1 + data;
    EXPECT_EQ(result2.size(), data.size());
    EXPECT_TRUE(result2 == data);

    auto result3 = empty2 + data;
    EXPECT_EQ(result3.size(), data.size());
    EXPECT_TRUE(result3 == data);
}

TEST(SecureBufferTest, CopyToClipboard) {
    SecureBuffer buffer(std::string("secret"));
    EXPECT_TRUE(buffer.copyToClipboard());

    std::string clipboard_data;
    EXPECT_TRUE(clip::get_text(clipboard_data));
    EXPECT_EQ(clipboard_data, "secret");
}

TEST(SecureBufferTest, ResizeToSmallerSizeAllowedCleansesMemory) {
    SecureBuffer buffer(16);
    auto ptr = buffer.data();
    buffer[15] = 'X';

    EXPECT_EQ(*(ptr + 15), 'X');

    buffer.resize(4);
    
    EXPECT_EQ(buffer.size(), 4);
    EXPECT_EQ(buffer.data(), ptr);
    EXPECT_NE(*(ptr + 15), 'X');
}

TEST(SecureBufferTest, ResizeToLargerSizeThrows) {
    SecureBuffer buffer(4);
    EXPECT_THROW(buffer.resize(16), std::invalid_argument);
}

TEST(SecureBufferTest, OutputDefaultFormat) {
    SecureBuffer buffer(std::string("foobar"));
    std::ostringstream ss;
    ss << buffer;

    EXPECT_EQ(ss.str(), "foobar");
}

TEST(SecureBufferTest, OutputHexFormat) {
    SecureBuffer buffer(std::string("foobar"));
    std::ostringstream ss;
    ss << std::hex << buffer;

    EXPECT_EQ(ss.str(), "666f6f626172");
}
