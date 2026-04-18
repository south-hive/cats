// cats-cli eval transaction — JSON script runner.
//
// Schema reference: docs/cats_cli_transaction_schema.md (v1).
// One session, many ops, commit/rollback at end, on_error policy.
#pragma once

#include <json.hpp>

#include <libsed/core/types.h>
#include <libsed/eval/eval_api.h>
#include <libsed/session/session.h>

#include <chrono>
#include <string>
#include <vector>

namespace catscli {

using nlohmann::json;

/// One parsed op from the script.
struct TxOp {
    std::string op;                 // "start_transaction" | "commit" | "rollback" |
                                    // "get" | "set" | "genkey" | "erase" |
                                    // "authenticate" | "sleep"
    uint64_t    objectUid = 0;      // get/set/genkey/erase
    std::string objectLabel;        // original name for reporting
    uint32_t    colStart  = 0;      // get
    uint32_t    colEnd    = 0;      // get
    // Set values: (colId, variant). We keep both uint and bytes paths.
    struct Value {
        uint32_t col;
        bool     isBytes;
        uint64_t uintVal = 0;
        libsed::Bytes byteVal;
    };
    std::vector<Value> values;      // set
    uint64_t    authUid  = 0;       // authenticate
    std::string authLabel;          // authenticate (display)
    libsed::Bytes credential;       // authenticate (already resolved)
    uint32_t    sleepMs  = 0;       // sleep
};

/// Parsed top-level script.
struct TxScript {
    int                         version = 1;
    uint64_t                    spUid   = 0;
    std::string                 spLabel;
    uint64_t                    authUid = 0;
    std::string                 authLabel;
    bool                        write   = true;
    bool                        anonymous = false;  // authority == "Anybody"
    libsed::Bytes               credential;         // already resolved (pw / pw_env / pw_file)
    std::vector<TxOp>           ops;
    std::string                 onError = "rollback"; // "rollback" | "continue" | "abort"
};

/// Per-op execution result.
struct TxStepResult {
    int         step = 0;
    std::string op;
    std::string objectLabel;
    bool        transportOk = true;
    int         tcgStatus   = 0;      // MethodStatus as int, 0 on success
    std::string tcgStatusName;
    long        elapsedMs   = 0;
    libsed::Bytes rawSend;
    libsed::Bytes rawRecv;
    std::string errorNote;            // for script-level failures (parse/lookup)
};

struct TxResult {
    bool                         ok = true;
    std::string                  terminatedBy;  // "commit" | "rollback" | "abort" | "continue"
    std::vector<TxStepResult>    steps;
};

/// Parse a JSON text into a TxScript. Returns error message on failure, empty
/// string on success. Resolves password fields using the given environment
/// accessor so the caller can provide a custom one during tests.
std::string parseTxScript(const std::string& jsonText,
                           TxScript& out,
                           std::string (*getenvFn)(const char*) = nullptr);

/// Execute the parsed script against a transport. Opens/closes session.
/// Populates TxResult.steps with per-op outcome. The returned Result is the
/// transport-level status of the *last* op that was actually executed.
libsed::Result runTxScript(const TxScript& script,
                            libsed::eval::EvalApi& api,
                            std::shared_ptr<libsed::ITransport> transport,
                            uint16_t comId,
                            TxResult& result);

} // namespace catscli
