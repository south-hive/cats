// cats-cli — TCG SED Evaluation & Debugging Platform
//
// This is the MVP scaffolding for cats-cli. The full feature set is defined in
// the design doc (reviewed §1~§12) and broken into Phase 0~4 in the plan file.
// This file currently delivers a minimal working baseline: discover, msid,
// range list, plus a few eval primitives (tx-start, table-get, raw-method).
// Remaining commands are tracked in docs/internal/cats_cli_review.md.

#include <CLI11.hpp>

#include <libsed/cli/cli_common.h>
#include <libsed/core/log.h>
#include <libsed/debug/logging_transport.h>
#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/codec/token_decoder.h>
#include <libsed/packet/com_packet.h>

#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using namespace libsed;
using namespace libsed::eval;

// ── Exit codes ──────────────────────────────────────────────────────
// Public schema — design doc §8.3. Callers trap main's return value.
enum ExitCode : int {
    EC_OK              = 0,
    EC_USAGE           = 1,  // CLI / parse error
    EC_TRANSPORT       = 2,  // NVMe/ATA/SCSI ioctl error
    EC_TCG_METHOD      = 3,  // TCG method status != 0 (see tcg_status in JSON)
    EC_AUTH            = 4,  // Authentication failed (method status 0x01)
    EC_NOT_SUPPORTED   = 5,  // Feature not supported by drive (SSC mismatch, etc.)
};

// ── Packet Dissector (trace mode) ───────────────────────────────────

namespace {

void dumpToken(const Token& tok, int depth) {
    std::string indent(depth * 2 + 6, ' ');
    std::cout << indent;

    switch (tok.type) {
        case TokenType::StartList:       std::cout << "[\n"; break;
        case TokenType::EndList:         std::cout << "]\n"; break;
        case TokenType::StartName:       std::cout << "{\n"; break;
        case TokenType::EndName:         std::cout << "}\n"; break;
        case TokenType::Call:            std::cout << "CALL\n"; break;
        case TokenType::EndOfData:       std::cout << "END_OF_DATA\n"; break;
        case TokenType::EndOfSession:    std::cout << "END_OF_SESSION\n"; break;
        case TokenType::StartTransaction:std::cout << "START_TRANSACTION\n"; break;
        case TokenType::EndTransaction:  std::cout << "END_TRANSACTION\n"; break;
        case TokenType::EmptyAtom:       std::cout << "EMPTY\n"; break;
        default:
            if (tok.isByteSequence) {
                auto b = tok.getBytes();
                if (b.size() == 8) {
                    uint64_t u = 0;
                    for (auto v : b) u = (u << 8) | v;
                    std::cout << "UID: 0x" << std::hex << std::setw(16)
                              << std::setfill('0') << u << std::dec << "\n";
                } else {
                    std::cout << "BYTES[" << b.size() << "]\n";
                }
            } else {
                std::cout << (tok.isSigned ? "INT: " : "UINT: ") << tok.getUint() << "\n";
            }
            break;
    }
}

void dumpPayload(const Bytes& payload) {
    TokenDecoder d;
    if (d.decode(payload).failed()) return;
    int depth = 0;
    for (const auto& tok : d.tokens()) {
        if (tok.type == TokenType::EndList || tok.type == TokenType::EndName) --depth;
        dumpToken(tok, depth);
        if (tok.type == TokenType::StartList || tok.type == TokenType::StartName) ++depth;
    }
}

void dissect(const std::string& label, const Bytes& data) {
    if (data.empty()) return;
    std::cout << "  [RAW] " << label << " (" << data.size() << " bytes)\n";
    if (data.size() < 56) return;
    uint32_t tsn = Endian::readBe32(data.data() + 20);
    uint32_t hsn = Endian::readBe32(data.data() + 24);
    uint32_t subLen = Endian::readBe32(data.data() + 52);
    std::cout << "    Headers: TSN=" << tsn << " HSN=" << hsn << " SubLen=" << subLen << "\n";
    if (subLen > 0 && data.size() >= 56 + subLen) {
        Bytes payload(data.begin() + 56, data.begin() + 56 + subLen);
        dumpPayload(payload);
    }
}

} // anonymous namespace

// ── Context & session helper ────────────────────────────────────────

// Verbosity levels per design doc §2.2:
//   0 = quiet  (stdout: result data only)
//   1 = info   (human progress lines; default)
//   2 = debug  (TCG method name + status each step)
//   3 = trace  (decoded packet tree at every boundary)
enum class Verbosity : int { Quiet = 0, Info = 1, Debug = 2, Trace = 3 };

struct Context {
    std::string device;
    int         verbosityRaw = 1;
    std::string logFile;
    std::string password;
    bool        force = false;   // needed for brick-risky --eval raw-method etc.

    std::shared_ptr<ITransport> transport;
    EvalApi                     api;

    Verbosity v() const { return static_cast<Verbosity>(verbosityRaw); }

    // Opens the NVMe device and wires logging based on -v and --log-file.
    // Returns an ExitCode (0 = success).
    int init() {
        transport = TransportFactory::createNvme(device);
        if (!transport) {
            std::cerr << "error: failed to open " << device << "\n";
            return EC_TRANSPORT;
        }

        // Map CLI verbosity → library LogLevel (design doc §8.2).
        switch (v()) {
            case Verbosity::Quiet: Logger::instance().setLevel(LogLevel::Error); break;
            case Verbosity::Info:  Logger::instance().setLevel(LogLevel::Info);  break;
            case Verbosity::Debug: Logger::instance().setLevel(LogLevel::Debug); break;
            case Verbosity::Trace: Logger::instance().setLevel(LogLevel::Trace); break;
        }

        // trace verbosity → packet dump decorator on stderr
        if (v() == Verbosity::Trace) {
            transport = debug::LoggingTransport::wrapDump(transport, std::cerr, /*verbosity=*/2);
        }

        // --log-file: mirror flow log (LIBSED_*) to screen + file via Tee.
        if (!logFile.empty()) {
            installDefaultFlowLog(logFile);
        }

        return EC_OK;
    }

    Bytes pwBytes() const { return Bytes(password.begin(), password.end()); }

    void trace(const RawResult& r) const {
        if (v() < Verbosity::Trace) return;
        dissect("SENT", r.rawSendPayload);
        dissect("RECV", r.rawRecvPayload);
    }
};

// RAII session guard — every callback used to repeat 6 lines of open/close
// boilerplate. This type removes the duplication and closes on scope exit
// (even if the callback returns early after an error).
class SessionScope {
public:
    SessionScope(Context& ctx, uint16_t comId) : ctx_(ctx), session_(ctx.transport, comId) {}
    ~SessionScope() { if (open_) ctx_.api.closeSession(session_); }

    SessionScope(const SessionScope&) = delete;
    SessionScope& operator=(const SessionScope&) = delete;

    Result openAnonymous(uint64_t spUid, bool write) {
        StartSessionResult ssr;
        auto r = ctx_.api.startSession(session_, spUid, write, ssr);
        open_ = r.ok();
        return r;
    }

    Result openWithAuth(uint64_t spUid, bool write,
                         uint64_t authUid, const Bytes& credential) {
        StartSessionResult ssr;
        auto r = ctx_.api.startSessionWithAuth(session_, spUid, write,
                                                authUid, credential, ssr);
        open_ = r.ok();
        return r;
    }

    Session& raw() { return session_; }

private:
    Context& ctx_;
    Session  session_;
    bool     open_ = false;
};

// ── Output helpers ──────────────────────────────────────────────────

static int mapTcgStatusToExit(MethodStatus status) {
    if (status == MethodStatus::Success)       return EC_OK;
    if (status == MethodStatus::NotAuthorized) return EC_AUTH;
    return EC_TCG_METHOD;
}

static int reportResult(const Context& ctx, const std::string& label, Result r) {
    if (r.ok()) {
        if (ctx.v() >= Verbosity::Info)
            std::cout << "  ✓ " << label << "\n";
        return EC_OK;
    }
    std::cerr << "  ✗ " << label << " — " << r.message() << "\n";
    return EC_TRANSPORT;
}

static int reportRaw(const Context& ctx, const std::string& label, const RawResult& r) {
    const bool tOk = r.transportError == ErrorCode::Success;
    const bool mOk = r.methodResult.isSuccess();

    if (ctx.v() >= Verbosity::Info) {
        std::cout << (tOk && mOk ? "  ✓ " : "  ✗ ") << label
                  << "  transport=" << (tOk ? "OK" : Result(r.transportError).message())
                  << "  method=St=0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(r.methodResult.status()) << std::dec
                  << " (" << r.methodResult.statusMessage() << ")"
                  << "\n";
    }
    if (!tOk) return EC_TRANSPORT;
    return mapTcgStatusToExit(r.methodResult.status());
}

// ── Hex helpers ─────────────────────────────────────────────────────

// Parse a hex string into bytes. Tolerates whitespace, common prefixes (0x),
// and produces EC_USAGE diagnostics for malformed input (odd digit count,
// non-hex chars).
static bool parseHexString(const std::string& in, Bytes& out, std::string& err) {
    out.clear();
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        s.push_back(c);
    }
    // strip leading 0x/0X
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);

    if (s.size() % 2 != 0) {
        err = "hex string must have an even number of nibbles";
        return false;
    }
    for (size_t i = 0; i < s.size(); i += 2) {
        char c1 = s[i], c2 = s[i+1];
        if (!std::isxdigit((unsigned char)c1) || !std::isxdigit((unsigned char)c2)) {
            err = "non-hex character in payload";
            return false;
        }
        out.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    }
    return true;
}

// ── Subcommand implementations ──────────────────────────────────────

namespace cmd {

int drive_discover(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    DiscoveryInfo info;
    auto r = ctx.api.discovery0(ctx.transport, info);
    if (r.failed()) return reportResult(ctx, "discovery0", r);

    if (ctx.v() >= Verbosity::Info) {
        std::cout << "Device: " << ctx.device << "\n";
        std::cout << "  Base ComID : 0x" << std::hex << info.baseComId << std::dec << "\n";
        std::cout << "  # ComIDs   : " << info.numComIds << "\n";
        std::cout << "  SSC        : ";
        switch (info.primarySsc) {
            case SscType::Opal20:     std::cout << "Opal 2.0\n"; break;
            case SscType::Opal10:     std::cout << "Opal 1.0\n"; break;
            case SscType::Enterprise: std::cout << "Enterprise\n"; break;
            case SscType::Pyrite10:   std::cout << "Pyrite 1.0\n"; break;
            case SscType::Pyrite20:   std::cout << "Pyrite 2.0\n"; break;
            default:                  std::cout << "Unknown\n"; break;
        }
        std::cout << "  Locking    : " << (info.lockingPresent ? "present" : "absent")
                  << (info.lockingEnabled ? ", enabled" : "")
                  << (info.locked ? ", locked" : "") << "\n";
        std::cout << "  MBR Shadow : " << (info.mbrEnabled ? "enabled" : "disabled")
                  << (info.mbrDone ? ", Done" : "") << "\n";
    }
    return EC_OK;
}

int drive_msid(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    DiscoveryInfo info;
    if (auto r = ctx.api.discovery0(ctx.transport, info); r.failed())
        return reportResult(ctx, "discovery0", r);

    SessionScope s(ctx, info.baseComId);
    if (auto r = s.openAnonymous(uid::SP_ADMIN, /*write=*/false); r.failed())
        return reportResult(ctx, "startSession(AdminSP)", r);

    Bytes msid;
    auto r = ctx.api.getCPin(s.raw(), uid::CPIN_MSID, msid);
    if (r.failed()) return reportResult(ctx, "getCPin(MSID)", r);

    // Always print MSID (even at quiet) — it's the requested result.
    std::cout << std::string(msid.begin(), msid.end()) << "\n";
    return EC_OK;
}

int range_list(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    DiscoveryInfo info;
    if (auto r = ctx.api.discovery0(ctx.transport, info); r.failed())
        return reportResult(ctx, "discovery0", r);

    SessionScope s(ctx, info.baseComId);
    if (auto r = s.openWithAuth(uid::SP_LOCKING, /*write=*/false,
                                 uid::AUTH_ADMIN1, ctx.pwBytes()); r.failed())
        return reportResult(ctx, "startSession(LockingSP/Admin1)", r);

    std::vector<LockingInfo> ranges;
    auto r = ctx.api.getAllLockingInfo(s.raw(), ranges, /*maxRanges=*/8);
    if (r.failed()) return reportResult(ctx, "getAllLockingInfo", r);

    if (ctx.v() >= Verbosity::Info) {
        std::cout << "Range  Start      Length     RLE WLE RLck WLck\n";
        for (const auto& ri : ranges) {
            std::cout << "  " << std::setw(2) << ri.rangeId << "  "
                      << std::setw(10) << ri.rangeStart << "  "
                      << std::setw(10) << ri.rangeLength << "  "
                      << (ri.readLockEnabled ? "Y" : "N") << "   "
                      << (ri.writeLockEnabled ? "Y" : "N") << "   "
                      << (ri.readLocked ? "Y" : "N") << "    "
                      << (ri.writeLocked ? "Y" : "N") << "\n";
        }
    }
    return EC_OK;
}

int eval_tx_start(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    DiscoveryInfo info;
    if (auto r = ctx.api.discovery0(ctx.transport, info); r.failed())
        return reportResult(ctx, "discovery0", r);

    SessionScope s(ctx, info.baseComId);
    if (auto r = s.openAnonymous(uid::SP_ADMIN, /*write=*/true); r.failed())
        return reportResult(ctx, "startSession(AdminSP)", r);

    RawResult raw;
    ctx.api.startTransaction(s.raw(), raw);
    int ec = reportRaw(ctx, "startTransaction", raw);
    ctx.trace(raw);

    // NOTE: the session closes on scope exit, so the TPer transaction state
    // ends here. For a real multi-op transaction use `eval transaction
    // <script.json>` (not yet implemented — see review doc).
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "  (session closes on exit — use script runner for "
                     "multi-op transactions)\n";
    }
    return ec;
}

struct TableGetArgs {
    uint64_t tableUid = 0;
    uint32_t col = 0;
};

int eval_table_get(Context& ctx, const TableGetArgs& a) {
    if (int e = ctx.init(); e) return e;
    DiscoveryInfo info;
    if (auto r = ctx.api.discovery0(ctx.transport, info); r.failed())
        return reportResult(ctx, "discovery0", r);

    SessionScope s(ctx, info.baseComId);
    if (auto r = s.openWithAuth(uid::SP_ADMIN, /*write=*/false,
                                 uid::AUTH_SID, ctx.pwBytes()); r.failed())
        return reportResult(ctx, "startSession(AdminSP/SID)", r);

    Token val;
    RawResult raw;
    ctx.api.tableGetColumn(s.raw(), a.tableUid, a.col, val, raw);
    int ec = reportRaw(ctx, "tableGetColumn", raw);
    ctx.trace(raw);

    if (raw.methodResult.isSuccess()) {
        std::cout << "  col[" << a.col << "] = " << val.toString() << "\n";
    }
    return ec;
}

struct RawMethodArgs {
    uint64_t    invoker = 0;
    uint64_t    methodUid = 0;
    std::string hexPayload;
};

int eval_raw_method(Context& ctx, const RawMethodArgs& a) {
    // Brick-risk gate: this path is fuzzing-grade. Refuse without --force.
    if (!ctx.force) {
        std::cerr << "error: 'eval raw-method' can brick the drive. "
                     "Re-run with --force if you understand the risk.\n";
        return EC_USAGE;
    }

    Bytes payload;
    if (!a.hexPayload.empty()) {
        std::string err;
        if (!parseHexString(a.hexPayload, payload, err)) {
            std::cerr << "error: --payload: " << err << "\n";
            return EC_USAGE;
        }
    }

    if (int e = ctx.init(); e) return e;
    DiscoveryInfo info;
    if (auto r = ctx.api.discovery0(ctx.transport, info); r.failed())
        return reportResult(ctx, "discovery0", r);

    SessionScope s(ctx, info.baseComId);
    if (auto r = s.openAnonymous(uid::SP_ADMIN, /*write=*/true); r.failed())
        return reportResult(ctx, "startSession(AdminSP)", r);

    Bytes tokens = EvalApi::buildMethodCall(a.invoker, a.methodUid, payload);

    RawResult raw;
    ctx.api.sendRawMethod(s.raw(), tokens, raw);
    int ec = reportRaw(ctx, "sendRawMethod", raw);
    ctx.trace(raw);
    return ec;
}

} // namespace cmd

// ── main ────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    CLI::App app{"cats-cli — TCG SED evaluation & debugging platform"};
    app.require_subcommand(1);

    Context ctx;
    app.add_option("-d,--device",    ctx.device, "Target NVMe device (e.g. /dev/nvme0)")
        ->required();
    app.add_option("-v,--verbosity", ctx.verbosityRaw,
                   "0=quiet, 1=info (default), 2=debug, 3=trace")
        ->default_val(1)->check(CLI::Range(0, 3));
    app.add_option("--log-file",     ctx.logFile,
                   "Mirror library flow log (LIBSED_INFO/…) to stderr AND this file");
    app.add_option("-p,--password",  ctx.password,
                   "Password (warning: visible in 'ps'; prefer env/file in CI)");
    app.add_flag  ("--force",        ctx.force,
                   "Required for brick-risky operations (eval raw-method etc.)");

    // Return code carrier — CLI11 callbacks are void, so the last command to
    // run writes into this integer which main returns.
    int finalExit = EC_OK;

    // ── drive ──
    auto* drive = app.add_subcommand("drive", "Device-level operations");
    drive->add_subcommand("discover", "Level 0 Discovery + summary")
        ->callback([&]{ finalExit = cmd::drive_discover(ctx); });
    drive->add_subcommand("msid", "Read MSID from Admin SP")
        ->callback([&]{ finalExit = cmd::drive_msid(ctx); });

    // ── range ──
    auto* range = app.add_subcommand("range", "Locking Range (Opal SSC)");
    range->add_subcommand("list", "List all configured ranges")
        ->callback([&]{ finalExit = cmd::range_list(ctx); });

    // ── eval ──
    auto* eval = app.add_subcommand("eval", "Expert / evaluator primitives");

    eval->add_subcommand("tx-start", "Send StartTransaction (closes on exit — use script runner for real txns)")
        ->callback([&]{ finalExit = cmd::eval_tx_start(ctx); });

    cmd::TableGetArgs tga;
    auto* tget = eval->add_subcommand("table-get", "Read one column from any table");
    tget->add_option("--table", tga.tableUid, "Table/object UID (hex e.g. 0x0000000B00008402)")
        ->required();
    tget->add_option("--col", tga.col, "Column ID")->default_val(0);
    tget->callback([&]{ finalExit = cmd::eval_table_get(ctx, tga); });

    cmd::RawMethodArgs rma;
    auto* rawMethod = eval->add_subcommand("raw-method",
        "Send an arbitrary method call (REQUIRES --force — can brick the drive)");
    rawMethod->add_option("--invoke", rma.invoker, "Invoking UID (hex)")->required();
    rawMethod->add_option("--method", rma.methodUid, "Method UID (hex)")->required();
    rawMethod->add_option("--payload", rma.hexPayload,
                           "Raw params as hex (inside STARTLIST/ENDLIST), optional");
    rawMethod->callback([&]{ finalExit = cmd::eval_raw_method(ctx, rma); });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);  // CLI11 prints help / usage as needed
    }

    return finalExit;
}
