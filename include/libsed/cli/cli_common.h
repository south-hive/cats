#pragma once

/// @file cli_common.h
/// @brief Common CLI argument parsing and transport wrapping for examples/tools.
///
/// Usage:
/// @code
///   cli::CliOptions opts;
///   if (!cli::parseCommon(argc, argv, opts, "Level 0 Discovery")) return 0;
///   auto transport = TransportFactory::createNvme(opts.device);
///   transport = cli::applyLogging(transport, opts);
/// @endcode

#include "../transport/i_transport.h"
#include "../transport/transport_factory.h"
#include "../debug/logging_transport.h"
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace libsed {
namespace cli {

struct CliOptions {
    std::string device;              ///< Device path (e.g., /dev/nvme0)
    bool dump = false;               ///< --dump: decoded packet summary to stderr
    int  dumpLevel = 0;              ///< 0=off, 1=decoded (--dump), 2=decoded+hex (--dump2)
    bool log = false;                ///< --log: write command log to file
    bool help = false;               ///< --help: show usage
    bool force = false;              ///< --force: skip confirmation for destructive operations
    std::string password;            ///< --password: override default test password
    std::string logDir = ".";        ///< --logdir: log file directory
    std::vector<std::string> extra;  ///< Unrecognized args (for example-specific parsing)
};

/// Parse common CLI arguments. Returns false if --help was requested or device is missing.
/// When false is returned, usage has already been printed.
inline bool parseCommon(int argc, char* argv[], CliOptions& opts,
                        const char* description = nullptr) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--dump")       { opts.dump = true; if (opts.dumpLevel < 1) opts.dumpLevel = 1; }
        else if (arg == "--dump2") { opts.dump = true; opts.dumpLevel = 2; }
        else if (arg == "--log")   opts.log = true;
        else if (arg == "--force") opts.force = true;
        else if (arg == "--help" || arg == "-h") opts.help = true;
        else if (arg == "--logdir" && i + 1 < argc) opts.logDir = argv[++i];
        else if (arg == "--password" && i + 1 < argc) opts.password = argv[++i];
        else if (arg[0] != '-' && opts.device.empty()) opts.device = arg;
        else opts.extra.push_back(arg);
    }

    if (opts.help || opts.device.empty()) {
        std::string name = argv[0];
        auto pos = name.rfind('/');
        if (pos != std::string::npos) name = name.substr(pos + 1);

        std::cerr << "Usage: " << name << " <device> [options]\n";
        if (description) std::cerr << "\n  " << description << "\n";
        std::cerr << "\nOptions:\n"
                  << "  --dump        Show decoded IF-SEND/IF-RECV packets on stderr\n"
                  << "  --dump2       Like --dump but also show raw ComPacket hex\n"
                  << "  --log         Write command log to file\n"
                  << "  --logdir D    Log file directory (default: .)\n"
                  << "  --force       Skip confirmation for destructive operations\n"
                  << "  --password PW Override default test password\n"
                  << "  --help        Show this help\n";
        return false;
    }
    return true;
}

/// Scan for --dump/--dump2/--log flags without touching positional args.
/// Use this when examples have their own complex argument parsing.
inline void scanFlags(int argc, char* argv[], CliOptions& opts) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--dump")       { opts.dump = true; if (opts.dumpLevel < 1) opts.dumpLevel = 1; }
        else if (arg == "--dump2") { opts.dump = true; opts.dumpLevel = 2; }
        else if (arg == "--log")   opts.log = true;
        else if (arg == "--logdir" && i + 1 < argc) opts.logDir = argv[++i];
    }
}

/// Wrap transport based on CLI options (--dump and/or --log).
inline std::shared_ptr<ITransport> applyLogging(
    std::shared_ptr<ITransport> transport,
    const CliOptions& opts) {
    if (opts.dump && opts.log) {
        // Both: create logger with file + stream output
        debug::LoggerConfig config;
        config.toFile = true;
        config.toStream = true;
        config.stream = &std::cerr;
        config.verbosity = opts.dumpLevel;
        config.logDir = opts.logDir;
        auto logger = std::make_shared<debug::CommandLogger>(config);
        auto lt = std::make_shared<debug::LoggingTransport>(transport, logger);
        std::cerr << "Log: " << logger->filePath() << "\n";
        return lt;
    }
    if (opts.dump) {
        return debug::LoggingTransport::wrapDump(transport, std::cerr, opts.dumpLevel);
    }
    if (opts.log) {
        auto lt = debug::LoggingTransport::wrap(transport, opts.logDir);
        auto* p = dynamic_cast<debug::LoggingTransport*>(lt.get());
        if (p) std::cerr << "Log: " << p->logger()->filePath() << "\n";
        return lt;
    }
    return transport;
}

} // namespace cli
} // namespace libsed
