/*
©AngelaMos | 2026
test_hashers.cpp

Tests for all hash algorithm implementations against known vectors

Verifies MD5, SHA-1, SHA-256, SHA-512, SHA3-256, and SHA3-512 against
known test vectors for empty string and "password". Checks static name()
and digest_length() properties. Confirms deterministic output and
non-empty results.

Connects to:
  hash/MD5Hasher.hpp    - MD5Hasher tested
  hash/SHA1Hasher.hpp   - SHA1Hasher tested
  hash/SHA3_256Hasher.hpp - SHA3_256Hasher tested
  hash/SHA3_512Hasher.hpp - SHA3_512Hasher tested
  hash/SHA256Hasher.hpp - SHA256Hasher tested
  hash/SHA512Hasher.hpp - SHA512Hasher tested
  hash/EVPHasher.hpp    - underlying implementation
*/

#include "src/hash/MD5Hasher.hpp"
#include "src/hash/SHA1Hasher.hpp"
#include "src/hash/SHA3_256Hasher.hpp"
#include "src/hash/SHA3_512Hasher.hpp"
#include "src/hash/SHA256Hasher.hpp"
#include "src/hash/SHA512Hasher.hpp"
#include <gtest/gtest.h>

TEST(SHA256HasherTest, KnownVectors) {
    SHA256Hasher hasher;
    EXPECT_EQ(hasher.hash(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(hasher.hash("password"),
              "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8");
    EXPECT_EQ(hasher.hash("hello"),
              "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST(SHA256HasherTest, StaticProperties) {
    EXPECT_EQ(SHA256Hasher::name(), "SHA256");
    EXPECT_EQ(SHA256Hasher::digest_length(), 64);
}

TEST(SHA256HasherTest, Deterministic) {
    SHA256Hasher hasher;
    auto h1 = hasher.hash("test");
    auto h2 = hasher.hash("test");
    EXPECT_EQ(h1, h2);
}

TEST(MD5HasherTest, KnownVectors) {
    MD5Hasher hasher;
    EXPECT_EQ(hasher.hash(""), "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(hasher.hash("password"), "5f4dcc3b5aa765d61d8327deb882cf99");
}

TEST(MD5HasherTest, StaticProperties) {
    EXPECT_EQ(MD5Hasher::name(), "MD5");
    EXPECT_EQ(MD5Hasher::digest_length(), 32);
}

TEST(SHA1HasherTest, KnownVectors) {
    SHA1Hasher hasher;
    EXPECT_EQ(hasher.hash(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    EXPECT_EQ(hasher.hash("password"), "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
}

TEST(SHA1HasherTest, StaticProperties) {
    EXPECT_EQ(SHA1Hasher::name(), "SHA1");
    EXPECT_EQ(SHA1Hasher::digest_length(), 40);
}

TEST(SHA512HasherTest, KnownVectors) {
    SHA512Hasher hasher;
    EXPECT_EQ(hasher.hash(""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    EXPECT_EQ(hasher.hash("password"),
              "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb9"
              "80b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86");
}

TEST(SHA512HasherTest, StaticProperties) {
    EXPECT_EQ(SHA512Hasher::name(), "SHA512");
    EXPECT_EQ(SHA512Hasher::digest_length(), 128);
}

TEST(SHA3_256HasherTest, KnownVectors) {
    SHA3_256Hasher hasher;
    EXPECT_EQ(hasher.hash(""),
              "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    EXPECT_EQ(hasher.hash("abc"),
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    EXPECT_EQ(hasher.hash("password"),
              "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484");
}

TEST(SHA3_256HasherTest, StaticProperties) {
    EXPECT_EQ(SHA3_256Hasher::name(), "SHA3-256");
    EXPECT_EQ(SHA3_256Hasher::digest_length(), 64);
}

TEST(SHA3_512HasherTest, KnownVectors) {
    SHA3_512Hasher hasher;
    EXPECT_EQ(
        hasher.hash(""),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    EXPECT_EQ(
        hasher.hash("abc"),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    EXPECT_EQ(
        hasher.hash("password"),
        "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3"
        "a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716");
}

TEST(SHA3_512HasherTest, StaticProperties) {
    EXPECT_EQ(SHA3_512Hasher::name(), "SHA3-512");
    EXPECT_EQ(SHA3_512Hasher::digest_length(), 128);
}

TEST(HasherTest, NeverReturnsEmpty) {
    EXPECT_FALSE(MD5Hasher{}.hash("test").empty());
    EXPECT_FALSE(SHA1Hasher{}.hash("test").empty());
    EXPECT_FALSE(SHA256Hasher{}.hash("test").empty());
    EXPECT_FALSE(SHA512Hasher{}.hash("test").empty());
    EXPECT_FALSE(SHA3_256Hasher{}.hash("test").empty());
    EXPECT_FALSE(SHA3_512Hasher{}.hash("test").empty());
}
