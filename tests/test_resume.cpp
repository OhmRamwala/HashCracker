/*
©AngelaMos | 2026
test_resume.cpp

Tests for attack resume positions
*/

#include "src/attack/BruteForceAttack.hpp"
#include "src/attack/DictionaryAttack.hpp"
#include <gtest/gtest.h>

TEST(ResumeTest, BruteForceResumesFromSavedIndex) {
    BruteForceAttack attack("ab", 2, 0, 1);
    ASSERT_TRUE(attack.next().has_value());
    ASSERT_TRUE(attack.next().has_value());
    auto saved_index = attack.checkpoint_position();

    BruteForceAttack resumed("ab", 2, 0, 1);
    resumed.resume_from_checkpoint(saved_index);
    auto next = resumed.next();
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, "aa");
}

TEST(ResumeTest, DictionaryResumesFromSavedOffset) {
    auto attack = DictionaryAttack::create("tests/data/small_wordlist.txt", 0, 1);
    ASSERT_TRUE(attack.has_value());
    auto first = attack->next();
    ASSERT_TRUE(first.has_value());
    auto saved_offset = attack->checkpoint_position();

    auto resumed = DictionaryAttack::create("tests/data/small_wordlist.txt", 0, 1, saved_offset);
    ASSERT_TRUE(resumed.has_value());
    auto next = resumed->next();
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, "123456");
}
