#pragma once

/// @file sed_library.h
/// @brief Master include for TCG SED Library.
///
/// Single header for all common use cases. Instead of multiple includes:
///   #include <libsed/eval/eval_api.h>
///   #include <libsed/transport/transport_factory.h>
///   #include <libsed/security/hash_password.h>
///   #include <libsed/eval/test_helpers.h>
///   #include <libsed/sed_library.h>
///
/// Just use:
///   #include <libsed/sed_library.h>

// ── Core ──
#include "version.h"
#include "core/types.h"
#include "core/error.h"
#include "core/uid.h"
#include "core/log.h"

// ── Transport ──
#include "transport/i_transport.h"
#include "transport/i_nvme_device.h"
#include "transport/transport_factory.h"
#include "transport/sim_transport.h"

// ── Discovery ──
#include "discovery/discovery.h"
#include "discovery/feature_descriptor.h"

// ── Session & Method ──
#include "session/session.h"
#include "method/method_uids.h"

// ── Evaluation API ──
#include "eval/eval_api.h"
#include "eval/eval_composite.h"
#include "eval/sed_context.h"
#include "eval/test_helpers.h"

// ── Security ──
#include "security/hash_password.h"

// ── Facade (TC developer API) ──
#include "facade/sed_drive.h"

namespace libsed {

/// Initialize the library (call once at startup)
void initialize();

/// Shutdown and cleanup
void shutdown();

/// Get library version string
const char* versionString();

// ──────────────────────────────────────────────────────────
//  Re-exports: commonly used types from nested namespaces
//  so users can write a single `using namespace libsed;` and
//  get everything they need without having to know the split
//  between libsed:: and libsed::eval::.
// ──────────────────────────────────────────────────────────
using eval::EvalApi;
using eval::RawResult;
using eval::StartSessionResult;
using eval::SyncSessionResult;
using eval::PropertiesResult;
using eval::TableResult;
using eval::LockingInfo;
using eval::DataOpResult;
using eval::SedContext;
using eval::composite::CompositeResult;

} // namespace libsed
