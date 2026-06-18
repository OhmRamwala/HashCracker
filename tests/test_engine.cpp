/*
©AngelaMos | 2026
test_engine.cpp

End-to-end tests for the crack engine

Verifies Engine::crack with SHA256Hasher + DictionaryAttack finds
"password" from the test wordlist. Confirms CrackError::Exhausted when
the target hash is not in the wordlist. Tests salt support by cracking
a prepend-salted hash.

Connects to:
  core/Engine.hpp             - Engine::crack tested
  hash/SHA256Hasher.hpp       - SHA256Hasher used in dictionary tests
  hash/SHA3_256Hasher.hpp     - SHA3_256Hasher used in SHA3 test
  attack/DictionaryAttack.hpp - DictionaryAttack as the attack strategy
  tests/data/small_wordlist.txt - fixture wordlist
*/

#include "src/core/Engine.hpp"
#include "src/hash/SHA3_256Hasher.hpp"
#include "src/hash/SHA256Hasher.hpp"
#include <gtest/gtest.h>
#include <vector>

TEST(EngineTest, CracksSHA256WithDictionary) {
    CrackConfig cfg;
    cfg.target_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.thread_count = 2;

    auto result = Engine::crack<SHA256Hasher, DictionaryAttack>(cfg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->plaintext, "password");
}

TEST(EngineTest, ReturnsExhaustedWhenNotFound) {
    CrackConfig cfg;
    cfg.target_hash = std::string(64, 'f');
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.thread_count = 1;

    auto result = Engine::crack<SHA256Hasher, DictionaryAttack>(cfg);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CrackError::Exhausted);
}

TEST(EngineTest, CracksWithSalt) {
    SHA256Hasher hasher;
    auto salted_hash = hasher.hash("saltpassword");

    CrackConfig cfg;
    cfg.target_hash = salted_hash;
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.salt = "salt";
    cfg.salt_position = "prepend";
    cfg.thread_count = 1;

    auto result = Engine::crack<SHA256Hasher, DictionaryAttack>(cfg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->plaintext, "password");
}

TEST(EngineTest, CracksSHA3_256WithDictionary) {
    CrackConfig cfg;
    cfg.target_hash = "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484";
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.thread_count = 2;

    auto result = Engine::crack<SHA3_256Hasher, DictionaryAttack>(cfg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->plaintext, "password");
}

TEST(EngineTest, CracksBatchSHA256WithDictionary) {
    CrackConfig cfg;
    cfg.hash_type = "sha256";
    cfg.hash_type_confidence = "user-selected";
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.thread_count = 2;

    std::vector<std::string> targets = {
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "0bb09d80600eec3eb9d7793a6f859bedde2a2d83899b70bd78e961ed674b32f4",
        "ca3704aa0b06f5954c79ee837faa152d84d6b2d42838f0637a15eda8337dbdce",
    };

    auto result = Engine::crack_batch<SHA256Hasher, DictionaryAttack>(cfg, targets);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->algorithm, "SHA256");
    EXPECT_EQ(result->cracked_count, 2);
    EXPECT_EQ(result->total_hashes, 3);
    ASSERT_EQ(result->items.size(), 3);
    EXPECT_TRUE(result->items[0].cracked);
    EXPECT_EQ(result->items[0].plaintext, "password");
    EXPECT_TRUE(result->items[1].cracked);
    EXPECT_EQ(result->items[1].plaintext, "shadow");
    EXPECT_FALSE(result->items[2].cracked);
}
