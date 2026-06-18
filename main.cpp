/*
©AngelaMos | 2026
main.cpp

CLI entry point with hash type dispatch and attack mode selection

Parses command-line arguments via boost::program_options for hash target,
algorithm (md5/sha1/sha256/sha512/sha3-256/sha3-512/auto), attack mode
(dictionary, brute-force, or rule-based), charset selection, and salt.
build_charset assembles a character set from comma-separated
tokens (lower, upper, digits, special). dispatch_hasher selects the
concrete EVPHasher instantiation at runtime via a switch on HashType,
then dispatch_attack picks the attack strategy (BruteForceAttack,
RuleAttack, or DictionaryAttack) based on config flags. When auto-
detection is requested, HashDetector identifies the algorithm from hex
digest length. Linux-first checkpointing supports resumable brute-force
and dictionary cracking via periodic atomic progress file writes.

Key exports:
  main - Entry point, returns 0 on crack success, 1 on failure or exhaustion

Connects to:
  config/Config.hpp         - CrackConfig, CrackResult, charset constants, defaults
  core/Concepts.hpp         - CrackError enum for error propagation
  core/Engine.hpp           - Engine::crack<H, A> template drives the crack session
  hash/HashDetector.hpp     - HashDetector::detect for auto-detection
  hash/MD5Hasher.hpp et al. - Concrete hasher types for dispatch
  attack/BruteForceAttack.hpp - BruteForceAttack for exhaustive mode
  attack/DictionaryAttack.hpp - DictionaryAttack for wordlist mode
  attack/RuleAttack.hpp       - RuleAttack for mutation mode
*/

#include "src/attack/BruteForceAttack.hpp"
#include "src/attack/DictionaryAttack.hpp"
#include "src/attack/RuleAttack.hpp"
#include "src/config/Config.hpp"
#include "src/core/Concepts.hpp"
#include "src/core/Engine.hpp"
#include "src/hash/HashDetector.hpp"
#include "src/hash/MD5Hasher.hpp"
#include "src/hash/SHA1Hasher.hpp"
#include "src/hash/SHA3_256Hasher.hpp"
#include "src/hash/SHA3_512Hasher.hpp"
#include "src/hash/SHA256Hasher.hpp"
#include "src/hash/SHA512Hasher.hpp"
#include <algorithm>
#include <boost/program_options.hpp>
#include <fstream>
#include <expected>
#include <iostream>
#include <print>
#include <ranges>
#include <string>
#include <vector>

namespace po = boost::program_options;

static std::string build_charset(const std::string &spec) {
    std::string result;

    auto has = [&](std::string_view token) { return spec.find(token) != std::string::npos; };

    if (has("lower")) {
        result += config::CHARSET_LOWER;
    }
    if (has("upper")) {
        result += config::CHARSET_UPPER;
    }
    if (has("digits")) {
        result += config::CHARSET_DIGITS;
    }
    if (has("special")) {
        result += config::CHARSET_SPECIAL;
    }

    if (result.empty()) {
        result += config::CHARSET_LOWER;
        result += config::CHARSET_DIGITS;
    }

    return result;
}

template <Hasher H>
static auto dispatch_attack(const CrackConfig &cfg) -> std::expected<CrackResult, CrackError> {
    if (cfg.bruteforce) {
        return Engine::crack<H, BruteForceAttack>(cfg);
    }
    if (cfg.use_rules) {
        return Engine::crack<H, RuleAttack>(cfg);
    }
    return Engine::crack<H, DictionaryAttack>(cfg);
}

template <Hasher H>
static auto dispatch_batch_attack(const CrackConfig &cfg, const std::vector<std::string> &targets)
    -> std::expected<BatchCrackResult, CrackError> {
    if (cfg.bruteforce) {
        return Engine::crack_batch<H, BruteForceAttack>(cfg, targets);
    }
    if (cfg.use_rules) {
        return Engine::crack_batch<H, RuleAttack>(cfg, targets);
    }
    return Engine::crack_batch<H, DictionaryAttack>(cfg, targets);
}

static auto dispatch_hasher(HashType type, const CrackConfig &cfg)
    -> std::expected<CrackResult, CrackError> {
    switch (type) {
        case HashType::MD5:
            return dispatch_attack<MD5Hasher>(cfg);
        case HashType::SHA1:
            return dispatch_attack<SHA1Hasher>(cfg);
        case HashType::SHA256:
            return dispatch_attack<SHA256Hasher>(cfg);
        case HashType::SHA512:
            return dispatch_attack<SHA512Hasher>(cfg);
        case HashType::SHA3_256:
            return dispatch_attack<SHA3_256Hasher>(cfg);
        case HashType::SHA3_512:
            return dispatch_attack<SHA3_512Hasher>(cfg);
    }
    return std::unexpected(CrackError::UnsupportedAlgorithm);
}

static auto dispatch_batch_hasher(HashType type, const CrackConfig &cfg,
                                  const std::vector<std::string> &targets)
    -> std::expected<BatchCrackResult, CrackError> {
    switch (type) {
        case HashType::MD5:
            return dispatch_batch_attack<MD5Hasher>(cfg, targets);
        case HashType::SHA1:
            return dispatch_batch_attack<SHA1Hasher>(cfg, targets);
        case HashType::SHA256:
            return dispatch_batch_attack<SHA256Hasher>(cfg, targets);
        case HashType::SHA512:
            return dispatch_batch_attack<SHA512Hasher>(cfg, targets);
        case HashType::SHA3_256:
            return dispatch_batch_attack<SHA3_256Hasher>(cfg, targets);
        case HashType::SHA3_512:
            return dispatch_batch_attack<SHA3_512Hasher>(cfg, targets);
    }
    return std::unexpected(CrackError::UnsupportedAlgorithm);
}

static std::string trim(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' ||
                              value.back() == '\t')) {
        value.pop_back();
    }
    auto start = value.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return "";
    }
    return value.substr(start);
}

static auto load_hashes_from_file(const std::string &path)
    -> std::expected<std::vector<std::string>, CrackError> {
    std::ifstream input(path);
    if (!input) {
        return std::unexpected(CrackError::FileNotFound);
    }

    std::vector<std::string> hashes;
    std::string line;
    while (std::getline(input, line)) {
        line = trim(std::move(line));
        if (!line.empty()) {
            hashes.push_back(std::move(line));
        }
    }

    if (hashes.empty()) {
        return std::unexpected(CrackError::InvalidConfig);
    }

    return hashes;
}

static auto resolve_hash_type(CrackConfig &cfg, const std::vector<std::string> &targets)
    -> std::expected<HashType, CrackError> {
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    if (!std::ranges::all_of(targets, [&](const auto &hash) { return std::ranges::all_of(hash, is_hex); })) {
        return std::unexpected(CrackError::InvalidHash);
    }

    if (cfg.hash_type == "auto") {
        auto detected = HashDetector::detect(targets.front());
        if (!detected.has_value()) {
            return std::unexpected(detected.error());
        }

        const auto expected_length = targets.front().size();
        if (!std::ranges::all_of(targets, [&](const auto &hash) { return hash.size() == expected_length; })) {
            return std::unexpected(CrackError::InvalidConfig);
        }

        cfg.hash_type_display = [type = *detected]() {
            switch (type) {
                case HashType::MD5:
                    return std::string("MD5");
                case HashType::SHA1:
                    return std::string("SHA1");
                case HashType::SHA256:
                    return std::string("SHA256");
                case HashType::SHA512:
                    return std::string("SHA512");
                case HashType::SHA3_256:
                    return std::string("SHA3-256");
                case HashType::SHA3_512:
                    return std::string("SHA3-512");
            }
            return std::string("Unknown");
        }();

        cfg.hash_type_confidence =
            (expected_length == config::MD5_HEX_LENGTH || expected_length == config::SHA1_HEX_LENGTH) ? "high"
                                                                                                       : "low";
        return *detected;
    }

    cfg.hash_type_confidence = "user-selected";
    auto expect_uniform_length = [&](std::size_t digest_length) -> bool {
        return std::ranges::all_of(targets, [&](const auto &hash) { return hash.size() == digest_length; });
    };
    if (cfg.hash_type == "md5" && expect_uniform_length(config::MD5_HEX_LENGTH)) {
        cfg.hash_type_display = "MD5";
        return HashType::MD5;
    }
    if (cfg.hash_type == "sha1" && expect_uniform_length(config::SHA1_HEX_LENGTH)) {
        cfg.hash_type_display = "SHA1";
        return HashType::SHA1;
    }
    if (cfg.hash_type == "sha256" && expect_uniform_length(config::SHA256_HEX_LENGTH)) {
        cfg.hash_type_display = "SHA256";
        return HashType::SHA256;
    }
    if (cfg.hash_type == "sha512" && expect_uniform_length(config::SHA512_HEX_LENGTH)) {
        cfg.hash_type_display = "SHA512";
        return HashType::SHA512;
    }
    if (cfg.hash_type == "sha3-256" && expect_uniform_length(config::SHA3_256_HEX_LENGTH)) {
        cfg.hash_type_display = "SHA3-256";
        return HashType::SHA3_256;
    }
    if (cfg.hash_type == "sha3-512" && expect_uniform_length(config::SHA3_512_HEX_LENGTH)) {
        cfg.hash_type_display = "SHA3-512";
        return HashType::SHA3_512;
    }

    return std::unexpected(cfg.hash_type == "md5" || cfg.hash_type == "sha1" ||
                                       cfg.hash_type == "sha256" || cfg.hash_type == "sha512" ||
                                       cfg.hash_type == "sha3-256" || cfg.hash_type == "sha3-512"
                                   ? CrackError::InvalidHash
                                   : CrackError::UnsupportedAlgorithm);
}

int main(int argc, char *argv[]) {
    po::options_description desc("hashcracker - Multi-threaded hash cracking tool");
    desc.add_options()("help,h", "Show help message")("hash", po::value<std::string>(),
                                                      "Target hash to crack")(
        "type", po::value<std::string>()->default_value("auto"),
        "Hash type: md5, sha1, sha256, sha512, sha3-256, sha3-512, auto")(
        "wordlist,w", po::value<std::string>(), "Path to wordlist file")(
        "hash-file", po::value<std::string>(), "Path to file containing target hashes")(
        "checkpoint-file", po::value<std::string>(),
        "Write resumable progress checkpoints to this file")(
        "checkpoint-interval", po::value<int>()->default_value(config::DEFAULT_CHECKPOINT_INTERVAL_SECONDS),
        "Seconds between checkpoint writes")(
        "resume", "Resume from --checkpoint-file (brute force and dictionary only)")(
        "bruteforce,b", "Use brute-force attack mode")(
        "charset", po::value<std::string>()->default_value("lower,digits"),
        "Character sets: lower,upper,digits,special")(
        "max-length", po::value<std::size_t>()->default_value(config::DEFAULT_MAX_BRUTE_LENGTH),
        "Max password length for brute-force")("rules,r",
                                               "Apply mutation rules to dictionary words")(
        "chain-rules", "Chain mutation rules in combination")("salt", po::value<std::string>(),
                                                              "Salt value to prepend/append")(
        "salt-position", po::value<std::string>()->default_value("prepend"),
        "Salt position: prepend or append")("threads,t",
                                            po::value<unsigned>()->default_value(
                                                config::DEFAULT_THREAD_COUNT),
                                            "Thread count (0 = auto)");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error &e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    }

    if (vm.count("help") || (!vm.count("hash") && !vm.count("hash-file"))) {
        std::cout << desc << std::endl;
        return vm.count("help") ? 0 : 1;
    }

    CrackConfig cfg;
    if (vm.count("hash")) {
        cfg.target_hash = vm["hash"].as<std::string>();
    }
    cfg.hash_type = vm["type"].as<std::string>();
    cfg.thread_count = vm["threads"].as<unsigned>();
    cfg.bruteforce = vm.count("bruteforce") > 0;
    cfg.use_rules = vm.count("rules") > 0;
    cfg.chain_rules = vm.count("chain-rules") > 0;
    cfg.max_length = vm["max-length"].as<std::size_t>();

    if (vm.count("wordlist")) {
        cfg.wordlist_path = vm["wordlist"].as<std::string>();
    }
    if (vm.count("hash-file")) {
        cfg.hash_file_path = vm["hash-file"].as<std::string>();
    }
    if (vm.count("checkpoint-file")) {
        cfg.checkpoint_path = vm["checkpoint-file"].as<std::string>();
    }
    if (vm.count("salt")) {
        cfg.salt = vm["salt"].as<std::string>();
    }
    cfg.salt_position = vm["salt-position"].as<std::string>();
    cfg.checkpoint_interval_seconds = vm["checkpoint-interval"].as<int>();
    cfg.resume = vm.count("resume") > 0;

    if (cfg.bruteforce) {
        cfg.charset = build_charset(vm["charset"].as<std::string>());
    } else if (cfg.wordlist_path.empty()) {
        std::println(stderr, "Error: --wordlist required for dictionary/rule attacks");
        return 1;
    }
    if (cfg.resume && cfg.checkpoint_path.empty()) {
        std::println(stderr, "Error: --resume requires --checkpoint-file");
        return 1;
    }
    if (cfg.checkpoint_interval_seconds <= 0) {
        std::println(stderr, "Error: --checkpoint-interval must be greater than 0");
        return 1;
    }
    if (cfg.resume && !cfg.hash_file_path.empty()) {
        std::println(stderr, "Error: --resume is not supported with --hash-file");
        return 1;
    }

    std::vector<std::string> targets;
    if (!cfg.hash_file_path.empty()) {
        auto loaded_hashes = load_hashes_from_file(cfg.hash_file_path);
        if (!loaded_hashes.has_value()) {
            std::println(stderr, "Error: {}", crack_error_message(loaded_hashes.error()));
            return 1;
        }
        targets = std::move(*loaded_hashes);
    } else {
        targets.push_back(cfg.target_hash);
    }

    auto hash_type = resolve_hash_type(cfg, targets);
    if (!hash_type.has_value()) {
        std::println(stderr, "Error: {}", crack_error_message(hash_type.error()));
        return 1;
    }

    if (!cfg.hash_file_path.empty()) {
        auto result = dispatch_batch_hasher(*hash_type, cfg, targets);
        return result.has_value() ? 0 : 1;
    }

    cfg.target_hash = targets.front();
    auto result = dispatch_hasher(*hash_type, cfg);
    return result.has_value() ? 0 : 1;
}
