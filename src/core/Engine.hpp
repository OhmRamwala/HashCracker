/*
©AngelaMos | 2026
Engine.hpp

Template-driven crack engine orchestrating threads, attacks, and progress

Engine::crack<H, A> is the single function that runs an entire crack
session. It creates a ThreadPool, spawns one attack instance per thread
(each partitioned to a disjoint slice of the keyspace or wordlist), and
runs a background jthread for progress display updates. Each worker
thread hashes candidates through the Hasher H, prepending or appending
salt if configured, and checks against the target hash. The first match
sets SharedState::found atomically and stores the plaintext. Candidate
counts are flushed from thread-local accumulators to the shared atomic
counter every 1024 iterations to reduce contention. Returns a CrackResult
on success or CrackError::Exhausted when all candidates are spent.

Key exports:
  Engine::crack<H, A> - Runs a full crack session for Hasher H and AttackStrategy A

Connects to:
  config/Config.hpp           - reads CrackConfig options, produces CrackResult
  core/Concepts.hpp           - Hasher and AttackStrategy concept constraints
  threading/ThreadPool.hpp    - ThreadPool for parallel worker dispatch
  display/Progress.hpp        - Progress for live terminal feedback
  attack/BruteForceAttack.hpp - instantiated when A = BruteForceAttack
  attack/DictionaryAttack.hpp - instantiated when A = DictionaryAttack
  attack/RuleAttack.hpp       - instantiated when A = RuleAttack
  main.cpp                    - called from dispatch_attack
*/

#pragma once

#include "src/attack/BruteForceAttack.hpp"
#include "src/attack/DictionaryAttack.hpp"
#include "src/attack/RuleAttack.hpp"
#include "src/config/Config.hpp"
#include "src/core/Concepts.hpp"
#include "src/display/Progress.hpp"
#include "src/io/CheckpointFile.hpp"
#include "src/threading/ThreadPool.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class Engine {
  public:
    template <Hasher H, AttackStrategy A>
    static auto crack(const CrackConfig &cfg) -> std::expected<CrackResult, CrackError>;

    template <Hasher H, AttackStrategy A>
    static auto crack_batch(const CrackConfig &cfg, const std::vector<std::string> &targets)
        -> std::expected<BatchCrackResult, CrackError>;
};

namespace engine_detail {

template <typename A> constexpr auto supports_resume() -> bool {
    return std::same_as<A, BruteForceAttack> || std::same_as<A, DictionaryAttack>;
}

template <typename A> auto attack_mode_name(const CrackConfig &cfg) -> std::string_view {
    if (cfg.bruteforce) {
        return "Brute Force";
    }
    if (cfg.use_rules) {
        return "Rules";
    }
    return "Dictionary";
}

template <typename A> auto checkpoint_mode_name(const CrackConfig &cfg) -> std::string {
    if (cfg.bruteforce) {
        return "bruteforce";
    }
    if (cfg.use_rules) {
        return "rules";
    }
    return "dictionary";
}

template <typename A> auto total_estimate(const CrackConfig &cfg) -> std::size_t {
    if constexpr (std::same_as<A, BruteForceAttack>) {
        BruteForceAttack probe(cfg.charset, cfg.max_length, 0, 1);
        return probe.total();
    } else if constexpr (std::same_as<A, RuleAttack>) {
        auto probe = DictionaryAttack::create(cfg.wordlist_path, 0, 1);
        if (!probe) {
            return 0;
        }
        return probe->total() * 2005;
    } else {
        auto probe = DictionaryAttack::create(cfg.wordlist_path, 0, 1);
        if (!probe) {
            return 0;
        }
        return probe->total();
    }
}

template <typename A>
auto validate_checkpoint(const CrackConfig &cfg, const CheckpointState &checkpoint,
                         unsigned thread_count) -> bool {
    return checkpoint.mode == checkpoint_mode_name<A>(cfg) &&
           checkpoint.algorithm == std::string(cfg.hash_type_display) &&
           checkpoint.target_hash == cfg.target_hash && checkpoint.wordlist_path == cfg.wordlist_path &&
           checkpoint.charset == cfg.charset && checkpoint.salt == cfg.salt &&
           checkpoint.salt_position == cfg.salt_position &&
           checkpoint.max_length == cfg.max_length && checkpoint.thread_count == thread_count &&
           checkpoint.thread_positions.size() == thread_count;
}

template <typename A>
auto create_attack(const CrackConfig &cfg, unsigned tid, unsigned total,
                   const std::vector<std::size_t> &resume_positions) {
    if constexpr (std::same_as<A, BruteForceAttack>) {
        BruteForceAttack attack(cfg.charset, cfg.max_length, tid, total);
        if (!resume_positions.empty()) {
            attack.resume_from_checkpoint(resume_positions[tid]);
        }
        return std::expected<BruteForceAttack, CrackError>(std::move(attack));
    } else if constexpr (std::same_as<A, RuleAttack>) {
        return RuleAttack::create(cfg.wordlist_path, cfg.chain_rules, tid, total);
    } else {
        if (!resume_positions.empty()) {
            return DictionaryAttack::create(cfg.wordlist_path, tid, total, resume_positions[tid]);
        }
        return DictionaryAttack::create(cfg.wordlist_path, tid, total);
    }
}

template <typename Attack>
auto checkpoint_position(const Attack &attack) -> std::size_t {
    if constexpr (requires { attack.checkpoint_position(); }) {
        return attack.checkpoint_position();
    } else {
        return attack.progress();
    }
}

} // namespace engine_detail

template <Hasher H, AttackStrategy A>
auto Engine::crack(const CrackConfig &cfg) -> std::expected<CrackResult, CrackError> {
    unsigned thread_count =
        cfg.thread_count > 0 ? cfg.thread_count : std::thread::hardware_concurrency();

    if ((cfg.resume || !cfg.checkpoint_path.empty()) && !engine_detail::supports_resume<A>()) {
        return std::unexpected(CrackError::InvalidConfig);
    }

    ThreadPool pool(thread_count);
    std::vector<std::size_t> resume_positions;
    double resumed_elapsed_seconds = 0.0;
    std::size_t resumed_tested = 0;
    if (cfg.resume) {
        if (cfg.checkpoint_path.empty()) {
            return std::unexpected(CrackError::InvalidConfig);
        }
        auto checkpoint = CheckpointFile::load(cfg.checkpoint_path);
        if (!checkpoint.has_value() ||
            !engine_detail::validate_checkpoint<A>(cfg, *checkpoint, thread_count)) {
            return std::unexpected(CrackError::InvalidConfig);
        }
        resume_positions = checkpoint->thread_positions;
        resumed_elapsed_seconds = checkpoint->elapsed_seconds;
        resumed_tested = checkpoint->candidates_tested;
    }

    pool.state().tested_count.store(resumed_tested, std::memory_order_relaxed);

    auto attack_name = engine_detail::attack_mode_name<A>(cfg);
    auto total_estimate = engine_detail::total_estimate<A>(cfg);

    Progress progress(H::name(), attack_name, cfg.hash_type == "auto" ? "auto-detected" : "specified",
                      cfg.hash_type_confidence, thread_count, total_estimate, pool.state().found,
                      resumed_elapsed_seconds, pool.state().tested_count);

    if (Progress::is_tty()) {
        progress.print_banner();
        std::puts("");
        std::puts("");
        std::puts("");
    }

    auto start = std::chrono::steady_clock::now();
    std::vector<std::atomic<std::size_t>> checkpoint_positions(thread_count);
    for (unsigned i = 0; i < thread_count; ++i) {
        checkpoint_positions[i].store(resume_positions.empty() ? 0 : resume_positions[i],
                                      std::memory_order_relaxed);
    }

    std::jthread display_thread;
    if (Progress::is_tty()) {
        display_thread = std::jthread([&](std::stop_token st) {
            while (!st.stop_requested() && !pool.state().found.load(std::memory_order_relaxed)) {
                progress.update();
                std::this_thread::sleep_for(std::chrono::milliseconds(config::PROGRESS_UPDATE_MS));
            }
        });
    }

    std::jthread checkpoint_thread;
    if (!cfg.checkpoint_path.empty()) {
        checkpoint_thread = std::jthread([&](std::stop_token st) {
            while (!st.stop_requested() && !pool.state().found.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(
                    std::chrono::seconds(std::max(cfg.checkpoint_interval_seconds, 1)));
                if (st.stop_requested()) {
                    break;
                }

                CheckpointState state{
                    .mode = engine_detail::checkpoint_mode_name<A>(cfg),
                    .algorithm = std::string(H::name()),
                    .target_hash = cfg.target_hash,
                    .wordlist_path = cfg.wordlist_path,
                    .charset = cfg.charset,
                    .salt = cfg.salt,
                    .salt_position = cfg.salt_position,
                    .max_length = cfg.max_length,
                    .thread_count = thread_count,
                    .elapsed_seconds =
                        resumed_elapsed_seconds +
                        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count(),
                    .candidates_tested =
                        pool.state().tested_count.load(std::memory_order_relaxed),
                };
                state.thread_positions.reserve(thread_count);
                for (unsigned i = 0; i < thread_count; ++i) {
                    state.thread_positions.push_back(
                        checkpoint_positions[i].load(std::memory_order_relaxed));
                }
                (void)CheckpointFile::save(cfg.checkpoint_path, state);
            }
        });
    }

    pool.run([&](unsigned tid, unsigned total, SharedState &state) {
        H hasher;
        auto attack = engine_detail::create_attack<A>(cfg, tid, total, resume_positions);
        if (!attack.has_value()) {
            return;
        }
        checkpoint_positions[tid].store(engine_detail::checkpoint_position(*attack),
                                        std::memory_order_relaxed);

        std::size_t local_count = 0;
        while (!state.found.load(std::memory_order_relaxed)) {
            auto candidate = attack->next();
            if (!candidate.has_value()) {
                break;
            }
            checkpoint_positions[tid].store(engine_detail::checkpoint_position(*attack),
                                            std::memory_order_relaxed);

            std::string to_hash = *candidate;
            if (!cfg.salt.empty()) {
                if (cfg.salt_position == "prepend") {
                    to_hash = cfg.salt + to_hash;
                } else {
                    to_hash = to_hash + cfg.salt;
                }
            }

            if (hasher.hash(to_hash) == cfg.target_hash) {
                state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
                state.set_result(std::move(*candidate));
                break;
            }

            ++local_count;
            if ((local_count & 0x3FF) == 0) {
                state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
                local_count = 0;
                checkpoint_positions[tid].store(engine_detail::checkpoint_position(*attack),
                                                std::memory_order_relaxed);
            }
        }
        state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
        checkpoint_positions[tid].store(engine_detail::checkpoint_position(*attack),
                                        std::memory_order_relaxed);
    });

    if (display_thread.joinable()) {
        display_thread.request_stop();
        display_thread.join();
    }
    if (checkpoint_thread.joinable()) {
        CheckpointState state{
            .mode = engine_detail::checkpoint_mode_name<A>(cfg),
            .algorithm = std::string(H::name()),
            .target_hash = cfg.target_hash,
            .wordlist_path = cfg.wordlist_path,
            .charset = cfg.charset,
            .salt = cfg.salt,
            .salt_position = cfg.salt_position,
            .max_length = cfg.max_length,
            .thread_count = thread_count,
            .elapsed_seconds =
                resumed_elapsed_seconds +
                std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count(),
            .candidates_tested = pool.state().tested_count.load(std::memory_order_relaxed),
        };
        state.thread_positions.reserve(thread_count);
        for (unsigned i = 0; i < thread_count; ++i) {
            state.thread_positions.push_back(checkpoint_positions[i].load(std::memory_order_relaxed));
        }
        (void)CheckpointFile::save(cfg.checkpoint_path, state);
        checkpoint_thread.request_stop();
        checkpoint_thread.join();
    }

    auto end = std::chrono::steady_clock::now();
    double elapsed = resumed_elapsed_seconds + std::chrono::duration<double>(end - start).count();
    auto tested = pool.state().tested_count.load(std::memory_order_relaxed);

    auto &state = pool.state();
    if (state.found.load(std::memory_order_relaxed) && state.result.has_value()) {
        double speed = (elapsed > 0.0) ? static_cast<double>(tested) / elapsed : 0.0;
        CrackResult result{.plaintext = *state.result,
                           .hash = cfg.target_hash,
                           .algorithm = std::string(H::name()),
                           .elapsed_seconds = elapsed,
                           .candidates_tested = tested,
                           .hashes_per_second = speed};

        if (!cfg.checkpoint_path.empty()) {
            std::filesystem::remove(cfg.checkpoint_path);
        }
        progress.print_cracked(result);
        return result;
    }

    if (!cfg.checkpoint_path.empty()) {
        std::filesystem::remove(cfg.checkpoint_path);
    }
    progress.print_exhausted(cfg.target_hash, H::name());
    return std::unexpected(CrackError::Exhausted);
}

template <Hasher H, AttackStrategy A>
auto Engine::crack_batch(const CrackConfig &cfg, const std::vector<std::string> &targets)
    -> std::expected<BatchCrackResult, CrackError> {
    if (targets.empty()) {
        return std::unexpected(CrackError::InvalidConfig);
    }
    if (cfg.resume || !cfg.checkpoint_path.empty()) {
        return std::unexpected(CrackError::InvalidConfig);
    }

    unsigned thread_count =
        cfg.thread_count > 0 ? cfg.thread_count : std::thread::hardware_concurrency();

    ThreadPool pool(thread_count);

    auto attack_name = engine_detail::attack_mode_name<A>(cfg);
    auto total_estimate = engine_detail::total_estimate<A>(cfg);

    Progress progress(H::name(), attack_name, cfg.hash_type == "auto" ? "auto-detected" : "specified",
                      cfg.hash_type_confidence, thread_count, total_estimate, pool.state().found,
                      0.0, pool.state().tested_count);

    if (Progress::is_tty()) {
        progress.print_banner();
        std::puts("");
        std::puts("");
        std::puts("");
    }

    std::unordered_set<std::string> remaining_targets(targets.begin(), targets.end());
    std::unordered_map<std::string, std::string> cracked;
    std::mutex targets_mutex;

    auto start = std::chrono::steady_clock::now();

    std::jthread display_thread;
    if (Progress::is_tty()) {
        display_thread = std::jthread([&](std::stop_token st) {
            while (!st.stop_requested() && !pool.state().found.load(std::memory_order_relaxed)) {
                progress.update();
                std::this_thread::sleep_for(std::chrono::milliseconds(config::PROGRESS_UPDATE_MS));
            }
        });
    }

    pool.run([&](unsigned tid, unsigned total, SharedState &state) {
        H hasher;

        auto attack = engine_detail::create_attack<A>(cfg, tid, total, std::vector<std::size_t>{});
        if (!attack.has_value()) {
            return;
        }

        std::size_t local_count = 0;
        while (!state.found.load(std::memory_order_relaxed)) {
            auto candidate = attack->next();
            if (!candidate.has_value()) {
                break;
            }

            std::string to_hash = *candidate;
            if (!cfg.salt.empty()) {
                if (cfg.salt_position == "prepend") {
                    to_hash = cfg.salt + to_hash;
                } else {
                    to_hash += cfg.salt;
                }
            }

            auto hash_value = hasher.hash(to_hash);
            {
                auto lock = std::lock_guard{targets_mutex};
                if (auto it = remaining_targets.find(hash_value); it != remaining_targets.end()) {
                    cracked.emplace(*it, *candidate);
                    remaining_targets.erase(it);
                    if (remaining_targets.empty()) {
                        state.found.store(true, std::memory_order_relaxed);
                    }
                }
            }

            ++local_count;
            if ((local_count & 0x3FF) == 0) {
                state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
                local_count = 0;
            }
        }
        state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
    });

    if (display_thread.joinable()) {
        display_thread.request_stop();
        display_thread.join();
    }

    auto end = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    auto tested = pool.state().tested_count.load(std::memory_order_relaxed);
    double speed = (elapsed > 0.0) ? static_cast<double>(tested) / elapsed : 0.0;

    BatchCrackResult result{
        .algorithm = std::string(H::name()),
        .elapsed_seconds = elapsed,
        .candidates_tested = tested,
        .hashes_per_second = speed,
        .cracked_count = 0,
        .total_hashes = targets.size(),
    };

    result.items.reserve(targets.size());
    for (const auto &hash : targets) {
        if (auto it = cracked.find(hash); it != cracked.end()) {
            result.items.push_back(BatchCrackItem{.hash = hash, .plaintext = it->second, .cracked = true});
            ++result.cracked_count;
        } else {
            result.items.push_back(BatchCrackItem{.hash = hash, .plaintext = "", .cracked = false});
        }
    }

    progress.print_batch_result(result);
    return result;
}
