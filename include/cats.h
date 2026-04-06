#pragma once

/// @file cats.h
/// @brief Single include for TCG SED evaluation — all you need.
///
/// @code
///   #include <cats.h>
///   using namespace libsed;
///
///   int main(int argc, char* argv[]) {
///       cli::CliOptions opts;
///       if (!cli::parseCommon(argc, argv, opts, "My TC")) return 0;
///       auto transport = TransportFactory::createNvme(opts.device);
///       transport = cli::applyLogging(transport, opts);
///       EvalApi api;
///       // ...
///   }
/// @endcode

// ── Core library (eval, transport, session, discovery, security) ──
#include "libsed/sed_library.h"

// ── CLI utilities (--dump, --log, arg parsing) ──
#include "libsed/cli/cli_common.h"

// ── Debug / logging transport ──
#include "libsed/debug/logging_transport.h"
#include "libsed/debug/command_logger.h"
