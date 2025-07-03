#include <array>

#include <gtest/gtest.h>

#include <crypto.hpp>

using namespace vaulty;
using namespace vaulty::crypto;

class CryptoTest : public ::testing::Test {
protected:
    std::array<unsigned char, kSaltSize> salt{};
    SecureBuffer key;

    void SetUp() override {
        for (size_t i = 0; i < salt.size(); ++i) {
            salt[i] = static_cast<unsigned char>(i);
        }
        key = deriveEncryptionKey(SecureBuffer("secret"), salt);
    }
};

TEST_F(CryptoTest, DeriveEncryptionKeyProducesCorrectSize) {
    EXPECT_EQ(key.size(), kKeySize);
}

TEST_F(CryptoTest, DeriveEncryptionKeyIsDeterministic) {
    SecureBuffer password1("secret");
    SecureBuffer password2("secret");
    std::array<unsigned char, kSaltSize> salt_copy = salt;

    SecureBuffer key1 = deriveEncryptionKey(password1, salt);
    SecureBuffer key2 = deriveEncryptionKey(password2, salt_copy);

    EXPECT_EQ(key1, key2);
}

TEST_F(CryptoTest, EncryptReturnsNonEmptyCiphertext) {
    SecureBuffer plaintext("secret");
    SecureBuffer ciphertext = encrypt(key, plaintext);

    EXPECT_GT(ciphertext.size(), 0);
}

TEST_F(CryptoTest, EncryptDecryptRound) {
    SecureBuffer plaintext("secret");
    SecureBuffer ciphertext = encrypt(key, plaintext);
    SecureBuffer decrypted = decrypt(key, ciphertext);

    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CryptoTest, EncryptDecryptWithEmptyPlaintext) {
    SecureBuffer empty_plaintext("");
    SecureBuffer ciphertext = encrypt(key, empty_plaintext);
    SecureBuffer decrypted = decrypt(key, ciphertext);

    EXPECT_EQ(decrypted.size(), 0);
}

TEST_F(CryptoTest, EncryptProducesDifferentCiphertextsForSamePlaintext) {
    SecureBuffer plaintext("secret");
    SecureBuffer ciphertext1 = encrypt(key, plaintext);
    SecureBuffer ciphertext2 = encrypt(key, plaintext);

    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(CryptoTest, EncryptFailsWithEmptyKeyThrows) {
    SecureBuffer empty_key(0);
    SecureBuffer plaintext("secret");

    EXPECT_THROW(encrypt(empty_key, plaintext), std::runtime_error);
}

TEST_F(CryptoTest, DecryptWithCorruptedCiphertextThrows) {
    SecureBuffer plaintext("secret");
    SecureBuffer ciphertext = encrypt(key, plaintext);

    ciphertext[0] ^= 0xFF;

    EXPECT_THROW(decrypt(key, ciphertext), std::runtime_error);
}

TEST_F(CryptoTest, DecryptWithWrongTagThrows) {
    SecureBuffer plaintext("secret");
    SecureBuffer ciphertext = encrypt(key, plaintext);

    ciphertext[ciphertext.size() - 1] ^= 0xFF;

    EXPECT_THROW(decrypt(key, ciphertext), std::runtime_error);
}

TEST_F(CryptoTest, DecryptWithWrongKeyThrows) {
    SecureBuffer plaintext("secret");
    SecureBuffer ciphertext = encrypt(key, plaintext);

    SecureBuffer wrong_password("password");
    SecureBuffer wrong_key = deriveEncryptionKey(wrong_password, salt);

    EXPECT_THROW(decrypt(wrong_key, ciphertext), std::runtime_error);
}

TEST_F(CryptoTest, DecryptFailsWithEmptyCiphertextThrows) {
    SecureBuffer empty_blob(0);

    EXPECT_THROW(decrypt(key, empty_blob), std::runtime_error);
}
