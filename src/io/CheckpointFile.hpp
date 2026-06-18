/*
©AngelaMos | 2026
CheckpointFile.hpp

Linux-first checkpoint file helpers for resumable cracking

Connects to:
  io/CheckpointFile.cpp - atomic save/load implementation
  core/Engine.hpp       - engine writes and restores checkpoints
*/

#pragma once

#include "src/core/Concepts.hpp"
#include <cstddef>
#include <expected>
#include <string>
#include <vector>

struct CheckpointState {
    std::string mode;
    std::string algorithm;
    std::string target_hash;
    std::string wordlist_path;
    std::string charset;
    std::string salt;
    std::string salt_position;
    std::size_t max_length = 0;
    unsigned thread_count = 0;
    double elapsed_seconds = 0.0;
    std::size_t candidates_tested = 0;
    std::vector<std::size_t> thread_positions;
};

class CheckpointFile {
  public:
    static auto save(const std::string &path, const CheckpointState &state)
        -> std::expected<void, CrackError>;
    static auto load(const std::string &path) -> std::expected<CheckpointState, CrackError>;
};
