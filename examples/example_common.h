#pragma once

/// @file example_common.h
/// @brief Shared utilities for all TCG SED examples.
///
/// Provides step reporting, hex dumping, and banner printing.
/// Each example only needs: #include "example_common.h"

#include <cats.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

using namespace libsed;
using namespace libsed::eval;

// ── Step reporting ──────────────────────────────────

inline void step(int n, const char* name, Result r) {
    printf("  [Step %2d] %-40s %s\n", n, name,
           r.ok() ? "\033[32mOK\033[0m" : "\033[31mFAIL\033[0m");
    if (r.failed()) {
        printf("            -> %s\n", r.message().c_str());
    }
}

inline void step(int n, const char* name, bool ok) {
    printf("  [Step %2d] %-40s %s\n", n, name,
           ok ? "\033[32mOK\033[0m" : "\033[31mFAIL\033[0m");
}

// ── Section banners ─────────────────────────────────

inline void banner(const char* title) {
    printf("\n══════════════════════════════════════════\n");
    printf("  %s\n", title);
    printf("══════════════════════════════════════════\n");
}

inline void scenario(int n, const char* title) {
    printf("\n── Scenario %d: %s ──\n\n", n, title);
}

// ── Hex dump ────────────────────────────────────────

inline void dumpHex(const char* label, const uint8_t* data, size_t len) {
    printf("  %s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx: ", i);
        for (size_t j = 0; j < 16 && i + j < len; j++)
            printf("%02x ", data[i + j]);
        printf("\n");
    }
}

inline void dumpHex(const char* label, const Bytes& data) {
    dumpHex(label, data.data(), data.size());
}

// ── Print helpers ───────────────────────────────────

inline void printHex(const char* label, const Bytes& data) {
    printf("  %s: ", label);
    for (auto b : data) printf("%02x", b);
    printf(" (%zu bytes)\n", data.size());
}

inline void printString(const char* label, const Bytes& data) {
    printf("  %s: %.*s (%zu bytes)\n", label,
           static_cast<int>(data.size()), reinterpret_cast<const char*>(data.data()),
           data.size());
}

// ── Common init ─────────────────────────────────────

/// Parse args and create transport. Returns nullptr on failure (usage printed).
inline std::shared_ptr<ITransport> initTransport(int argc, char* argv[],
                                                  cli::CliOptions& opts,
                                                  const char* desc) {
    if (!cli::parseCommon(argc, argv, opts, desc)) return nullptr;
    auto transport = TransportFactory::create(opts.device);
    return cli::applyLogging(transport, opts);
}

// ── Safety interlock for destructive operations ────

/// Prompt for confirmation before destructive operations.
/// Returns true if --force was passed or user types 'y'.
inline bool confirmDestructive(const cli::CliOptions& opts, const char* action) {
    if (opts.force) return true;
    printf("\n  WARNING: This will %s on %s\n", action, opts.device.c_str());
    printf("  Are you sure? [y/N] ");
    fflush(stdout);
    int c = getchar();
    return (c == 'y' || c == 'Y');
}

// ── Credential parameterization ────────────────────

/// Shared default passwords — same across ALL examples.
/// Override with --password or SED_PASSWORD env var.
static constexpr const char* DEFAULT_SID_PW    = "TestSid1";        // 8 bytes (≥8 required by most Opal drives)
static constexpr const char* DEFAULT_ADMIN1_PW = "TestSid1_Admin1";
static constexpr const char* DEFAULT_USER1_PW  = "TestSid1_User1";

/// Get password: CLI --password > env SED_PASSWORD > fallback default.
inline std::string getPassword(const cli::CliOptions& opts,
                               const char* fallback = DEFAULT_SID_PW) {
    if (!opts.password.empty()) return opts.password;
    const char* env = std::getenv("SED_PASSWORD");
    if (env && env[0]) return env;
    return fallback;
}
