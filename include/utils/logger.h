/* utils/logger.h - tree-style console logger */

#ifndef K4_TRACKER_LOGGER_H
#define K4_TRACKER_LOGGER_H

#include <ida.hpp>
#include <kernwin.hpp>
#include <vector>
#include <chrono>

namespace tracker {

class TreeLogger {
    std::vector<bool> indent_is_last;

public:
    void print_prefix() {
        for (size_t i = 0; i < indent_is_last.size(); ++i) {
            if (i == indent_is_last.size() - 1) {
                msg(indent_is_last[i] ? "  └─ " : "  ├─ ");
            } else {
                msg(indent_is_last[i] ? "    " : "  │ ");
            }
        }
    }

    void item(bool last, const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        indent_is_last.push_back(last);
        print_prefix();
        vmsg(fmt, args);
        msg("\n");
        indent_is_last.pop_back();
        va_end(args);
    }

    void open_branch(bool last, const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        indent_is_last.push_back(last);
        print_prefix();
        vmsg(fmt, args);
        msg("\n");
        va_end(args);
    }

    void close_branch() {
        if (!indent_is_last.empty()) {
            indent_is_last.pop_back();
        }
    }

    void header(const char* title) {
        msg("\n");
        msg("╔══════════════════════════════════════════════════════════════════╗\n");
        msg("║ GDT - %s\n", title);
        msg("╚══════════════════════════════════════════════════════════════════╝\n");
    }

    void section(const char* title) {
        msg("\n[%s]\n", title);
    }

    void success(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        msg("  [OK] ");
        vmsg(fmt, args);
        msg("\n");
        va_end(args);
    }

    void error(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        msg("  [ERROR] ");
        vmsg(fmt, args);
        msg("\n");
        va_end(args);
    }

    void progress(size_t current, size_t total, const char* item_name) {
        msg("  [%zu/%zu] %s\n", current, total, item_name);
    }
};

class Timer {
    std::chrono::high_resolution_clock::time_point start;
    const char* name;
    TreeLogger* logger;
    bool is_last;
    bool silenced;

public:
    Timer(const char* n, TreeLogger* l = nullptr, bool last = false)
        : name(n), logger(l), is_last(last), silenced(false),
          start(std::chrono::high_resolution_clock::now()) {}

    ~Timer() {
        if (silenced) return;
        auto end = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        if (logger) {
            logger->item(is_last, "%s: %lldms", name, (long long)ms);
        } else {
            msg("  %s: %lldms\n", name, (long long)ms);
        }
    }

    void silence() { silenced = true; }

    int64_t elapsed_ms() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    }
};

} // namespace tracker

#endif // K4_TRACKER_LOGGER_H
