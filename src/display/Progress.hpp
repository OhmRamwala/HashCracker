/*
©AngelaMos | 2026
Progress.hpp

Terminal progress display with live speed, ETA, and result rendering

Connects to:
  display/Progress.cpp  - implementation of banner, update loop, and result display
  config/Config.hpp     - color, box, symbol constants and PROGRESS_* settings
  core/Engine.hpp       - Engine::crack creates Progress and calls update in a jthread
*/

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>

struct CrackResult;
struct BatchCrackResult;

class Progress {
  public:
    Progress(std::string_view algorithm, std::string_view attack_mode,
             std::string_view detection_mode, std::string_view confidence_label, unsigned thread_count,
             std::size_t total_candidates, const std::atomic<bool> &found,
             double initial_elapsed_seconds,
             const std::atomic<std::size_t> &tested);

    void print_banner() const;
    void update();
    void print_cracked(const CrackResult &result) const;
    void print_batch_result(const BatchCrackResult &result) const;
    void print_exhausted(std::string_view hash, std::string_view algorithm) const;
    static bool is_tty();

  private:
    std::string algorithm_;
    std::string attack_mode_;
    std::string detection_mode_;
    std::string confidence_label_;
    unsigned thread_count_;
    std::size_t total_;
    const std::atomic<bool> &found_;
    const std::atomic<std::size_t> &tested_;

    std::chrono::steady_clock::time_point start_time_;

    static std::size_t terminal_width();
    std::string render_bar(double fraction, std::size_t width) const;
    static std::string format_count(std::size_t n);
    static std::string format_time(double seconds);
    static std::string format_speed(double hps);
};
