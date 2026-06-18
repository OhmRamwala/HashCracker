/*
©AngelaMos | 2026
test_hash_detector.cpp

Tests for hash algorithm auto-detection by digest length

Verifies detection of MD5 (32 chars), SHA-1 (40), SHA-256 (64), and
SHA-512 (128) from real and synthetic hex strings. Confirms SHA3 hashes
with ambiguous lengths require an explicit type selection outside auto-
detection, and rejects invalid lengths and non-hex characters with
CrackError::InvalidHash.

Connects to:
  hash/HashDetector.hpp - HashDetector::detect tested
  core/Concepts.hpp     - CrackError enum for error assertions
*/

#include "src/hash/HashDetector.hpp"
#include <gtest/gtest.h>

TEST(HashDetectorTest, DetectsMD5) {
    auto result = HashDetector::detect("d41d8cd98f00b204e9800998ecf8427e");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::MD5);
}

TEST(HashDetectorTest, DetectsSHA1) {
    auto result = HashDetector::detect("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA1);
}

TEST(HashDetectorTest, DetectsSHA256) {
    auto result =
        HashDetector::detect("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA256);
}

TEST(HashDetectorTest, DetectsSHA512) {
    auto result = HashDetector::detect(std::string(128, 'a'));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA512);
}

TEST(HashDetectorTest, Ambiguous64CharHashDefaultsToSHA256InAutoMode) {
    auto result =
        HashDetector::detect("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA256);
}

TEST(HashDetectorTest, Ambiguous128CharHashDefaultsToSHA512InAutoMode) {
    auto result = HashDetector::detect(
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA512);
}

TEST(HashDetectorTest, RejectsInvalidLength) {
    auto result = HashDetector::detect("abc");
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CrackError::InvalidHash);
}

TEST(HashDetectorTest, RejectsNonHex) {
    auto result = HashDetector::detect(std::string(64, 'z'));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CrackError::InvalidHash);
}
