#pragma once

/// @file log.h
/// @brief Pluggable logging interface for libsed.
///
/// Default: stderr output. Plug in external logging via ILogSink:
/// @code
///   class MyPlatformLog : public libsed::ILogSink {
///       void log(LogLevel lv, const char* file, int line,
///                const std::string& msg) override {
///           platform_log_write(lv, file, line, msg);
///       }
///   };
///   libsed::Logger::setSink(std::make_shared<MyPlatformLog>());
/// @endcode

#include <cstdint>
#include <string>
#include <cstdio>
#include <cstdarg>
#include <fstream>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <vector>

namespace libsed {

enum class LogLevel : uint8_t {
    Trace = 0,
    Debug = 1,
    Info  = 2,
    Warn  = 3,
    Error = 4,
    None  = 5,
};

/// Convert LogLevel to short string ("TRC", "DBG", "INF", "WRN", "ERR")
inline const char* logLevelName(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRC";
        case LogLevel::Debug: return "DBG";
        case LogLevel::Info:  return "INF";
        case LogLevel::Warn:  return "WRN";
        case LogLevel::Error: return "ERR";
        default:              return "???";
    }
}

// ═══════════════════════════════════════════════════════
//  ILogSink — implement this to plug in external logging
// ═══════════════════════════════════════════════════════

class ILogSink {
public:
    virtual ~ILogSink() = default;

    /// Called for each log message that passes the level filter.
    /// Implementations must be thread-safe.
    virtual void log(LogLevel level, const char* file, int line,
                     const std::string& msg) = 0;
};

// ═══════════════════════════════════════════════════════
//  Built-in sinks
// ═══════════════════════════════════════════════════════

/// Default sink: writes to stderr with [LVL] file:line: msg format
class StderrSink : public ILogSink {
public:
    void log(LogLevel level, const char* file, int line,
             const std::string& msg) override {
        fprintf(stderr, "[%s] %s:%d: %s\n", logLevelName(level), file, line, msg.c_str());
    }
};

/// File sink: writes the same [LVL] file:line: msg format to a file. Thread-safe.
/// Use together with TeeSink or StderrSink to mirror screen + file.
class FileSink : public ILogSink {
public:
    explicit FileSink(const std::string& path, bool append = true)
        : path_(path) {
        file_.open(path_, std::ios::out | (append ? std::ios::app : std::ios::trunc));
    }
    ~FileSink() override {
        std::lock_guard<std::mutex> lk(mu_);
        if (file_.is_open()) { file_.flush(); file_.close(); }
    }

    void log(LogLevel level, const char* file, int line,
             const std::string& msg) override {
        std::lock_guard<std::mutex> lk(mu_);
        if (!file_.is_open()) return;
        file_ << '[' << logLevelName(level) << "] " << file << ':' << line
              << ": " << msg << '\n';
        file_.flush();
    }

    bool isOpen() const {
        std::lock_guard<std::mutex> lk(mu_);
        return file_.is_open();
    }
    std::string path() const { return path_; }

private:
    mutable std::mutex mu_;
    std::ofstream      file_;
    std::string        path_;
};

/// Fan-out composite sink: forwards each log call to every registered child.
/// Useful for "screen AND file" output without writing a custom sink.
class TeeSink : public ILogSink {
public:
    TeeSink() = default;

    TeeSink(std::initializer_list<std::shared_ptr<ILogSink>> sinks) {
        for (auto& s : sinks) if (s) sinks_.push_back(s);
    }

    void add(std::shared_ptr<ILogSink> sink) {
        if (!sink) return;
        std::lock_guard<std::mutex> lk(mu_);
        sinks_.push_back(std::move(sink));
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        sinks_.clear();
    }

    void log(LogLevel level, const char* file, int line,
             const std::string& msg) override {
        std::vector<std::shared_ptr<ILogSink>> copy;
        {
            std::lock_guard<std::mutex> lk(mu_);
            copy = sinks_;
        }
        for (auto& s : copy) s->log(level, file, line, msg);
    }

private:
    std::mutex                                   mu_;
    std::vector<std::shared_ptr<ILogSink>>       sinks_;
};

// ═══════════════════════════════════════════════════════
//  Logger singleton
// ═══════════════════════════════════════════════════════

class Logger {
public:
    static Logger& instance() {
        static Logger log;
        return log;
    }

    // ── Level control ──

    void setLevel(LogLevel level) { level_ = level; }
    LogLevel level() const { return level_; }

    // ── Sink management ──

    /// Set external log sink. Pass nullptr to revert to default stderr.
    static void setSink(std::shared_ptr<ILogSink> sink) {
        std::lock_guard<std::mutex> lk(instance().mutex_);
        instance().sink_ = std::move(sink);
    }

    /// Get current sink (never null — returns StderrSink if none set)
    static std::shared_ptr<ILogSink> sink() {
        std::lock_guard<std::mutex> lk(instance().mutex_);
        auto& s = instance().sink_;
        return s ? s : defaultSink();
    }

    // ── Log entry point (called by macros) ──

    void log(LogLevel level, const char* file, int line, const char* fmt, ...) {
        if (level < level_) return;

        char buf[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        std::shared_ptr<ILogSink> s;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            s = sink_ ? sink_ : defaultSink();
        }
        s->log(level, file, line, std::string(buf));
    }

private:
    Logger() = default;

    static std::shared_ptr<ILogSink> defaultSink() {
        static auto s = std::shared_ptr<ILogSink>(std::make_shared<StderrSink>());
        return s;
    }

    LogLevel level_ = LogLevel::Info;
    std::shared_ptr<ILogSink> sink_;
    std::mutex mutex_;
};

// ═══════════════════════════════════════════════════════
//  Log macros
// ═══════════════════════════════════════════════════════

namespace detail {

template <typename... Args>
inline void logFwd(LogLevel level, const char* file, int line,
                   const char* fmt, Args&&... args) {
    Logger::instance().log(level, file, line, fmt, std::forward<Args>(args)...);
}

inline void logFwd(LogLevel level, const char* file, int line,
                   const char* msg) {
    Logger::instance().log(level, file, line, "%s", msg);
}

} // namespace detail

#define LIBSED_LOG(level, ...)  ::libsed::detail::logFwd(level, __FILE__, __LINE__, __VA_ARGS__)

#define LIBSED_TRACE(...) LIBSED_LOG(::libsed::LogLevel::Trace, __VA_ARGS__)
#define LIBSED_DEBUG(...) LIBSED_LOG(::libsed::LogLevel::Debug, __VA_ARGS__)
#define LIBSED_INFO(...)  LIBSED_LOG(::libsed::LogLevel::Info,  __VA_ARGS__)
#define LIBSED_WARN(...)  LIBSED_LOG(::libsed::LogLevel::Warn,  __VA_ARGS__)
#define LIBSED_ERROR(...) LIBSED_LOG(::libsed::LogLevel::Error, __VA_ARGS__)

// ═══════════════════════════════════════════════════════
//  Convenience helpers
// ═══════════════════════════════════════════════════════

/// Install a Tee of StderrSink + FileSink(path) as the global sink.
/// After this call, every LIBSED_INFO/DEBUG/WARN/ERROR goes to both
/// stderr and the given file. Returns the composite so the caller can
/// add more children (e.g., a platform-specific sink) without rebuilding.
///
/// @code
///   libsed::installDefaultFlowLog("/var/log/tc/libsed.log");
///   // ... later, optionally merge in the platform logger too:
///   libsed::Logger::sink();  // still the TeeSink
/// @endcode
inline std::shared_ptr<TeeSink> installDefaultFlowLog(const std::string& filePath,
                                                      bool append = true) {
    auto tee = std::make_shared<TeeSink>(
        std::initializer_list<std::shared_ptr<ILogSink>>{
            std::make_shared<StderrSink>(),
            std::make_shared<FileSink>(filePath, append)
        });
    Logger::setSink(tee);
    return tee;
}

} // namespace libsed
