/*
©AngelaMos | 2026
CheckpointFile.cpp

Atomic checkpoint save/load for resumable cracking on Linux
*/

#include "src/io/CheckpointFile.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {

auto escape_field(const std::string &value) -> std::string {
    std::string escaped;
    escaped.reserve(value.size());
    for (char c : value) {
        if (c == '\\' || c == '\n') {
            escaped += '\\';
        }
        escaped += c == '\n' ? 'n' : c;
    }
    return escaped;
}

auto unescape_field(const std::string &value) -> std::string {
    std::string unescaped;
    unescaped.reserve(value.size());
    bool escaped = false;
    for (char c : value) {
        if (!escaped && c == '\\') {
            escaped = true;
            continue;
        }
        if (escaped && c == 'n') {
            unescaped += '\n';
        } else {
            unescaped += c;
        }
        escaped = false;
    }
    return unescaped;
}

auto parse_line(const std::string &line) -> std::pair<std::string, std::string> {
    auto pos = line.find('=');
    if (pos == std::string::npos) {
        return {"", ""};
    }
    return {line.substr(0, pos), line.substr(pos + 1)};
}

} // namespace

auto CheckpointFile::save(const std::string &path, const CheckpointState &state)
    -> std::expected<void, CrackError> {
    auto temp_path = path + ".tmp";
    std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return std::unexpected(CrackError::FileNotFound);
    }

    out << "mode=" << escape_field(state.mode) << '\n';
    out << "algorithm=" << escape_field(state.algorithm) << '\n';
    out << "target_hash=" << escape_field(state.target_hash) << '\n';
    out << "wordlist_path=" << escape_field(state.wordlist_path) << '\n';
    out << "charset=" << escape_field(state.charset) << '\n';
    out << "salt=" << escape_field(state.salt) << '\n';
    out << "salt_position=" << escape_field(state.salt_position) << '\n';
    out << "max_length=" << state.max_length << '\n';
    out << "thread_count=" << state.thread_count << '\n';
    out << "elapsed_seconds=" << state.elapsed_seconds << '\n';
    out << "candidates_tested=" << state.candidates_tested << '\n';
    out << "thread_positions=";
    for (std::size_t i = 0; i < state.thread_positions.size(); ++i) {
        if (i > 0) {
            out << ',';
        }
        out << state.thread_positions[i];
    }
    out << '\n';
    out.flush();
    out.close();

    std::error_code ec;
    std::filesystem::rename(temp_path, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(temp_path, path, ec);
        if (ec) {
            return std::unexpected(CrackError::InvalidConfig);
        }
    }

    return {};
}

auto CheckpointFile::load(const std::string &path) -> std::expected<CheckpointState, CrackError> {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(CrackError::FileNotFound);
    }

    CheckpointState state;
    std::string line;
    while (std::getline(in, line)) {
        auto [key, value] = parse_line(line);
        if (key.empty()) {
            continue;
        }

        if (key == "mode") {
            state.mode = unescape_field(value);
        } else if (key == "algorithm") {
            state.algorithm = unescape_field(value);
        } else if (key == "target_hash") {
            state.target_hash = unescape_field(value);
        } else if (key == "wordlist_path") {
            state.wordlist_path = unescape_field(value);
        } else if (key == "charset") {
            state.charset = unescape_field(value);
        } else if (key == "salt") {
            state.salt = unescape_field(value);
        } else if (key == "salt_position") {
            state.salt_position = unescape_field(value);
        } else if (key == "max_length") {
            state.max_length = static_cast<std::size_t>(std::stoull(value));
        } else if (key == "thread_count") {
            state.thread_count = static_cast<unsigned>(std::stoul(value));
        } else if (key == "elapsed_seconds") {
            state.elapsed_seconds = std::stod(value);
        } else if (key == "candidates_tested") {
            state.candidates_tested = static_cast<std::size_t>(std::stoull(value));
        } else if (key == "thread_positions") {
            std::stringstream ss(value);
            std::string part;
            while (std::getline(ss, part, ',')) {
                if (!part.empty()) {
                    state.thread_positions.push_back(static_cast<std::size_t>(std::stoull(part)));
                }
            }
        }
    }

    if (state.thread_positions.empty()) {
        return std::unexpected(CrackError::InvalidConfig);
    }

    return state;
}
