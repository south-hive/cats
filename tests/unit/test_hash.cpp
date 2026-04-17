#include "libsed/security/hash_password.h"
#include <cassert>
#include <cstdio>

#ifndef TEST
#define TEST(suite, name) void test_##suite##_##name()
#define EXPECT_EQ(a, b) assert((a) == (b))
#define EXPECT_TRUE(a) assert(a)
#define RUN_TEST(suite, name) do { printf("  " #suite "." #name "..."); test_##suite##_##name(); printf(" OK\n"); } while(0)
#endif

using namespace libsed;

TEST(Hash, Sha256Empty) {
    auto hash = HashPassword::sha256(nullptr, 0);
    EXPECT_EQ(hash.size(), 32u);
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    EXPECT_EQ(hash[0], 0xe3);
    EXPECT_EQ(hash[1], 0xb0);
    EXPECT_EQ(hash[31], 0x55);
}

TEST(Hash, Sha256Known) {
    std::string msg = "abc";
    auto hash = HashPassword::sha256(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    EXPECT_EQ(hash.size(), 32u);
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    EXPECT_EQ(hash[0], 0xba);
    EXPECT_EQ(hash[1], 0x78);
    EXPECT_EQ(hash[31], 0xad);
}

TEST(Hash, HmacSha256) {
    Bytes key = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                 0x0b, 0x0b, 0x0b, 0x0b};
    std::string msg = "Hi There";
    Bytes data(msg.begin(), msg.end());
    auto hmac = HashPassword::hmacSha256(key, data);
    EXPECT_EQ(hmac.size(), 32u);
    // Known HMAC-SHA256 for this test vector
    EXPECT_EQ(hmac[0], 0xb0);
    EXPECT_EQ(hmac[1], 0x34);
}

TEST(Hash, Pbkdf2) {
    auto dk = HashPassword::pbkdf2Sha256("password", Bytes{'s','a','l','t'}, 1, 32);
    EXPECT_EQ(dk.size(), 32u);
    // PBKDF2-HMAC-SHA256("password", "salt", 1, 32) is a known value
    // First byte should be 0x12
    EXPECT_EQ(dk[0], 0x12);
}

TEST(Hash, PasswordToBytes) {
    auto bytes = HashPassword::passwordToBytes("test");
    // passwordToBytes now uses SHA-256, producing 32-byte output
    EXPECT_EQ(bytes.size(), 32u);
    // SHA-256("test") first byte = 0x9f
    EXPECT_EQ(bytes[0], 0x9f);
}

#ifndef GTEST_INCLUDE_GTEST_GTEST_H_
void run_hash_tests() {
    printf("Hash tests:\n");
    RUN_TEST(Hash, Sha256Empty);
    RUN_TEST(Hash, Sha256Known);
    RUN_TEST(Hash, HmacSha256);
    RUN_TEST(Hash, Pbkdf2);
    RUN_TEST(Hash, PasswordToBytes);
    printf("  All Hash tests passed!\n\n");
}
#endif
