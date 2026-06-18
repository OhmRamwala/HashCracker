/*
©AngelaMos | 2026
test_checkpoint_file.cpp

Tests for resumable checkpoint save/load helpers
*/

#include "src/io/CheckpointFile.hpp"
#include <gtest/gtest.h>
#include <filesystem>

TEST(CheckpointFileTest, SavesAndLoadsState) {
    auto path = std::filesystem::temp_directory_path() / "hashcracker-checkpoint-test.chk";
    CheckpointState state{
        .mode = "bruteforce",
        .algorithm = "SHA256",
        .target_hash = "abc123",
        .wordlist_path = "",
        .charset = "abc",
        .salt = "salt",
        .salt_position = "prepend",
        .max_length = 4,
        .thread_count = 2,
        .elapsed_seconds = 12.5,
        .candidates_tested = 2048,
        .thread_positions = {10, 20},
    };

    auto saved = CheckpointFile::save(path.string(), state);
    ASSERT_TRUE(saved.has_value());

    auto loaded = CheckpointFile::load(path.string());
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->mode, state.mode);
    EXPECT_EQ(loaded->algorithm, state.algorithm);
    EXPECT_EQ(loaded->target_hash, state.target_hash);
    EXPECT_EQ(loaded->charset, state.charset);
    EXPECT_EQ(loaded->salt, state.salt);
    EXPECT_EQ(loaded->thread_positions, state.thread_positions);

    std::filesystem::remove(path);
}
