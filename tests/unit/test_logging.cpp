#include "libsed/core/log.h"
#include "libsed/debug/command_logger.h"
#include "libsed/debug/logging_transport.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#ifndef TEST
#define TEST(suite, name) void test_##suite##_##name()
#define EXPECT_EQ(a, b) assert((a) == (b))
#define EXPECT_NE(a, b) assert((a) != (b))
#define EXPECT_TRUE(a) assert(a)
#define EXPECT_FALSE(a) assert(!(a))
#define RUN_TEST(suite, name) do { printf("  " #suite "." #name "..."); test_##suite##_##name(); printf(" OK\n"); } while(0)
#endif

using namespace libsed;

static std::string readAll(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string tmpPath(const char* tag) {
    char buf[256];
    snprintf(buf, sizeof(buf), "/tmp/libsed_log_%s_%ld.log", tag, (long)getpid());
    return buf;
}

// ── FileSink ────────────────────────────────────────────────────────

TEST(Logging, FileSinkWritesFormat) {
    auto path = tmpPath("fs1");
    std::remove(path.c_str());

    {
        FileSink sink(path, /*append=*/false);
        EXPECT_TRUE(sink.isOpen());
        sink.log(LogLevel::Info, "foo.cpp", 42, "hello");
        sink.log(LogLevel::Error, "bar.cpp", 7, "boom");
    } // destructor flushes+closes

    auto content = readAll(path);
    EXPECT_TRUE(content.find("[INF] foo.cpp:42: hello\n") != std::string::npos);
    EXPECT_TRUE(content.find("[ERR] bar.cpp:7: boom\n") != std::string::npos);

    std::remove(path.c_str());
}

TEST(Logging, FileSinkAppendPreservesExisting) {
    auto path = tmpPath("fs2");
    std::remove(path.c_str());

    { FileSink a(path, false); a.log(LogLevel::Info, "a", 1, "first"); }
    { FileSink b(path, true);  b.log(LogLevel::Info, "b", 2, "second"); }

    auto content = readAll(path);
    EXPECT_TRUE(content.find("first")  != std::string::npos);
    EXPECT_TRUE(content.find("second") != std::string::npos);

    std::remove(path.c_str());
}

// ── TeeSink ─────────────────────────────────────────────────────────

namespace {
struct RecordingSink : ILogSink {
    int calls = 0;
    std::string lastMsg;
    void log(LogLevel, const char*, int, const std::string& m) override {
        ++calls;
        lastMsg = m;
    }
};
}

TEST(Logging, TeeSinkFansOut) {
    auto a = std::make_shared<RecordingSink>();
    auto b = std::make_shared<RecordingSink>();
    TeeSink tee({a, b});

    tee.log(LogLevel::Info, "t.cpp", 1, "x");
    tee.log(LogLevel::Info, "t.cpp", 2, "y");

    EXPECT_EQ(a->calls, 2);
    EXPECT_EQ(b->calls, 2);
    EXPECT_EQ(a->lastMsg, std::string("y"));
    EXPECT_EQ(b->lastMsg, std::string("y"));
}

TEST(Logging, TeeSinkClearStopsDelivery) {
    auto a = std::make_shared<RecordingSink>();
    TeeSink tee({a});
    tee.log(LogLevel::Info, "t.cpp", 1, "x");
    EXPECT_EQ(a->calls, 1);

    tee.clear();
    tee.log(LogLevel::Info, "t.cpp", 2, "y");
    EXPECT_EQ(a->calls, 1); // no additional delivery
}

// ── installDefaultFlowLog ───────────────────────────────────────────

TEST(Logging, InstallDefaultFlowLogMirrorsToFile) {
    auto path = tmpPath("flow");
    std::remove(path.c_str());

    installDefaultFlowLog(path, /*append=*/false);
    LIBSED_INFO("hello from flow log");

    // File should have captured the message
    auto content = readAll(path);
    EXPECT_TRUE(content.find("hello from flow log") != std::string::npos);

    // Restore default (nullptr reverts to StderrSink) to keep subsequent tests clean
    Logger::setSink(nullptr);
    std::remove(path.c_str());
}

TEST(Logging, LoggerSetSinkNullRevertsToStderrSink) {
    // After installing a custom sink, setSink(nullptr) must restore the built-in
    // default so the screen remains the fallback when platform code un-plugs.
    auto rec = std::make_shared<RecordingSink>();
    Logger::setSink(rec);
    LIBSED_INFO("a");
    EXPECT_EQ(rec->calls, 1);

    Logger::setSink(nullptr);
    // sink() must never return null — built-in StderrSink takes over.
    auto s = Logger::sink();
    EXPECT_TRUE(s != nullptr);
    // Ensure further logs do NOT land in our recording sink.
    LIBSED_INFO("b");
    EXPECT_EQ(rec->calls, 1);
}

// ── CommandLogger: explicit filePath overrides auto-naming ──────────

TEST(Logging, CommandLoggerExplicitFilePath) {
    auto path = tmpPath("cmd_explicit");
    std::remove(path.c_str());

    debug::LoggerConfig cfg;
    cfg.toFile   = true;
    cfg.filePath = path;
    debug::CommandLogger logger(cfg);

    EXPECT_EQ(logger.filePath(), path);
    EXPECT_TRUE(logger.isOpen());

    logger.close();
    // File exists at the exact path we asked for (no timestamp suffix).
    std::ifstream f(path);
    EXPECT_TRUE(f.good());
    std::remove(path.c_str());
}

// ── CommandLogger: file output contains raw hex even at verbosity 0 ──

TEST(Logging, CommandLoggerFileAlwaysIncludesRawHex) {
    auto path = tmpPath("cmd_rawhex");
    std::remove(path.c_str());

    debug::LoggerConfig cfg;
    cfg.toFile = true;
    cfg.filePath = path;
    cfg.verbosity = 0; // file must still include raw hex despite v=0
    debug::CommandLogger logger(cfg);

    // Send a canned ComID-mgmt payload (Protocol 0x02). StackReset request = code 2.
    uint8_t payload[16] = { 0,0,0,0, 0,0,0,2, 0,0,0,0, 0,0,0,0 };
    logger.logIfSend(0x02, 0x0001, ByteSpan(payload, sizeof(payload)));
    logger.close();

    auto content = readAll(path);
    // Decoded marker
    EXPECT_TRUE(content.find("StackReset") != std::string::npos);
    // Raw hex marker — writeRawHex emits offset-prefixed lines starting at "    0000:"
    EXPECT_TRUE(content.find("    0000:") != std::string::npos);

    std::remove(path.c_str());
}

// ── CommandLogger: stream at verbosity 0 stays compact (no hex) ─────

TEST(Logging, CommandLoggerStreamRespectsVerbosity) {
    std::ostringstream stream;

    debug::LoggerConfig cfg;
    cfg.toFile = false;
    cfg.toStream = true;
    cfg.stream = &stream;
    cfg.verbosity = 0; // stream must NOT include raw hex at v=0
    debug::CommandLogger logger(cfg);

    uint8_t payload[16] = { 0,0,0,0, 0,0,0,2, 0,0,0,0, 0,0,0,0 };
    logger.logIfSend(0x02, 0x0001, ByteSpan(payload, sizeof(payload)));

    auto content = stream.str();
    EXPECT_TRUE(content.find("StackReset") != std::string::npos);
    // No hex block at v=0
    EXPECT_TRUE(content.find("    0000:") == std::string::npos);
}

// ── Driver (for standalone runner) ──────────────────────────────────

#ifndef GTEST_INCLUDE_GTEST_GTEST_H_
void run_logging_tests() {
    printf("Logging tests:\n");
    RUN_TEST(Logging, FileSinkWritesFormat);
    RUN_TEST(Logging, FileSinkAppendPreservesExisting);
    RUN_TEST(Logging, TeeSinkFansOut);
    RUN_TEST(Logging, TeeSinkClearStopsDelivery);
    RUN_TEST(Logging, InstallDefaultFlowLogMirrorsToFile);
    RUN_TEST(Logging, LoggerSetSinkNullRevertsToStderrSink);
    RUN_TEST(Logging, CommandLoggerExplicitFilePath);
    RUN_TEST(Logging, CommandLoggerFileAlwaysIncludesRawHex);
    RUN_TEST(Logging, CommandLoggerStreamRespectsVerbosity);
    printf("  All Logging tests passed!\n\n");
}
#endif
