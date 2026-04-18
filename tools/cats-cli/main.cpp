// cats-cli — TCG SED Evaluation & Debugging Platform
//
// Round 2 baseline — regressions restored, blockers closed. The MVP scope is
// fixed per cats-cli-design.md §1~§5; remaining roadmap (range setup/lock,
// band group, user enable/set-pw, mbr enable, --json, password input
// diversification, session/compare/snapshot/golden) is tracked in
// docs/internal/cats_cli_review.md §11 and keen-dazzling-platypus.md.

#include <CLI11.hpp>

#include <libsed/cli/cli_common.h>
#include <libsed/core/log.h>
#include <libsed/debug/logging_transport.h>
#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/transport/sim_transport.h>
#include <libsed/codec/token_decoder.h>
#include <libsed/packet/com_packet.h>
#include <libsed/facade/sed_drive.h>

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace libsed;
using namespace libsed::eval;

// ── Exit codes (cats-cli-design.md §8.3) ─────────────────────────────────────
enum ExitCode : int {
    EC_OK             = 0,
    EC_USAGE          = 1,   // CLI / parse / user input error
    EC_TRANSPORT      = 2,   // NVMe/ATA/SCSI ioctl failure
    EC_TCG_METHOD     = 3,   // TCG method status != 0 (generic)
    EC_AUTH           = 4,   // MethodStatus::NotAuthorized
    EC_NOT_SUPPORTED  = 5,   // Drive does not support feature
};

enum class Verbosity : int { Quiet = 0, Info = 1, Debug = 2, Trace = 3 };

// ── Packet dissector (trace mode) ────────────────────────────────────────────

namespace {

void dumpToken(const Token& tok, int depth) {
    std::string indent(depth * 2 + 6, ' ');
    std::cout << indent;
    switch (tok.type) {
        case TokenType::StartList:        std::cout << "[\n"; break;
        case TokenType::EndList:          std::cout << "]\n"; break;
        case TokenType::StartName:        std::cout << "{\n"; break;
        case TokenType::EndName:          std::cout << "}\n"; break;
        case TokenType::Call:             std::cout << "CALL\n"; break;
        case TokenType::EndOfData:        std::cout << "END_OF_DATA\n"; break;
        case TokenType::EndOfSession:     std::cout << "END_OF_SESSION\n"; break;
        case TokenType::StartTransaction: std::cout << "START_TRANSACTION\n"; break;
        case TokenType::EndTransaction:   std::cout << "END_TRANSACTION\n"; break;
        case TokenType::EmptyAtom:        std::cout << "EMPTY\n"; break;
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
                std::cout << (tok.isSigned ? "INT: " : "UINT: ")
                          << tok.getUint() << "\n";
            }
            break;
    }
}

void dissect(const std::string& label, const Bytes& data) {
    if (data.empty()) return;
    std::cout << "  [RAW] " << label << " (" << data.size() << " bytes)\n";
    if (data.size() < 56) return;
    uint32_t tsn = Endian::readBe32(data.data() + 20);
    uint32_t hsn = Endian::readBe32(data.data() + 24);
    uint32_t subLen = Endian::readBe32(data.data() + 52);
    std::cout << "    Headers: TSN=" << tsn << " HSN=" << hsn
              << " SubLen=" << subLen << "\n";
    if (subLen > 0 && data.size() >= 56 + subLen) {
        TokenDecoder d;
        if (d.decode(data.data() + 56, subLen).ok()) {
            int depth = 0;
            for (const auto& tok : d.tokens()) {
                if (tok.type == TokenType::EndList ||
                    tok.type == TokenType::EndName) --depth;
                dumpToken(tok, depth);
                if (tok.type == TokenType::StartList ||
                    tok.type == TokenType::StartName) ++depth;
            }
        }
    }
}

} // anonymous namespace

// ── Context & helpers ────────────────────────────────────────────────────────

struct Context {
    std::string device;
    int         verbosityRaw = 1;
    std::string logFile;
    std::string password;
    bool        force = false;
    bool        useSim = false;

    std::shared_ptr<ITransport> transport;
    EvalApi                     api;

    Verbosity v() const { return static_cast<Verbosity>(verbosityRaw); }

    int init() {
        if (useSim) {
            transport = std::make_shared<SimTransport>();
        } else {
            if (device.empty()) {
                std::cerr << "error: --device required (or use --sim)\n";
                return EC_USAGE;
            }
            transport = TransportFactory::createNvme(device);
        }
        if (!transport) {
            std::cerr << "error: failed to open "
                      << (useSim ? "Simulator" : device) << "\n";
            return EC_TRANSPORT;
        }

        switch (v()) {
            case Verbosity::Quiet: Logger::instance().setLevel(LogLevel::Error); break;
            case Verbosity::Info:  Logger::instance().setLevel(LogLevel::Info);  break;
            case Verbosity::Debug: Logger::instance().setLevel(LogLevel::Debug); break;
            case Verbosity::Trace: Logger::instance().setLevel(LogLevel::Trace); break;
        }

        if (v() == Verbosity::Trace) {
            transport = debug::LoggingTransport::wrapDump(transport, std::cerr, 2);
        }
        if (!logFile.empty()) installDefaultFlowLog(logFile);
        return EC_OK;
    }
};

// Map an ErrorCode range → cats-cli ExitCode bucket per design doc §8.3.
static int exitFor(ErrorCode ec) {
    auto v = static_cast<int>(ec);
    if (ec == ErrorCode::Success)   return EC_OK;
    if (v >= 100 && v <= 199)       return EC_TRANSPORT;
    if (v >= 600 && v <= 699)       return EC_AUTH;
    if (v >= 500 && v <= 599)       return EC_NOT_SUPPORTED;   // Discovery/feature
    return EC_TCG_METHOD;                                      // default bucket
}

static int reportResult(const Context& ctx, const std::string& label, Result r) {
    if (r.ok()) {
        if (ctx.v() >= Verbosity::Info)
            std::cout << "  ✓ " << label << "\n";
        return EC_OK;
    }
    std::cerr << "  ✗ " << label << " — " << r.message() << "\n";
    return exitFor(r.code());
}

static int reportRaw(const Context& ctx, const std::string& label, const RawResult& r) {
    const bool tOk = r.transportError == ErrorCode::Success;
    const bool mOk = r.methodResult.isSuccess();
    if (ctx.v() >= Verbosity::Info) {
        std::cout << (tOk && mOk ? "  ✓ " : "  ✗ ") << label
                  << "  transport=" << (tOk ? "OK" : Result(r.transportError).message())
                  << "  method=St=0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(r.methodResult.status()) << std::dec
                  << " (" << r.methodResult.statusMessage() << ")\n";
    }
    if (!tOk) return EC_TRANSPORT;
    if (r.methodResult.status() == MethodStatus::NotAuthorized) return EC_AUTH;
    return mOk ? EC_OK : EC_TCG_METHOD;
}

static bool readBinaryFile(const std::string& path, Bytes& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out = Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return true;
}

// Parse a hex string into bytes. Tolerates whitespace and 0x/0X prefix.
// Rejects odd nibble count and non-hex characters.
static bool parseHexString(const std::string& in, Bytes& out, std::string& err) {
    out.clear();
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        s.push_back(c);
    }
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (s.size() % 2 != 0) { err = "hex string must have an even number of nibbles"; return false; }
    for (size_t i = 0; i < s.size(); i += 2) {
        if (!std::isxdigit((unsigned char)s[i]) || !std::isxdigit((unsigned char)s[i+1])) {
            err = "non-hex character in payload";
            return false;
        }
        out.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    }
    return true;
}

// Require --force for destructive operations. Uniform rule so no single
// command author can accidentally skip the gate.
static int requireForce(const Context& ctx, const char* what) {
    if (ctx.force) return EC_OK;
    std::cerr << "error: '" << what << "' is destructive. "
                 "Re-run with --force if you understand the risk.\n";
    return EC_USAGE;
}

// ── Command implementations ──────────────────────────────────────────────────

namespace cmd {

// drive discover
int drive_discover(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "Drive Summary:\n"
                  << "  SSC     : " << drive.sscName() << "\n"
                  << "  ComID   : 0x" << std::hex << drive.comId() << std::dec << "\n"
                  << "  Locking : " << (drive.info().lockingEnabled ? "Enabled" : "Disabled")
                  << (drive.info().locked ? " (locked)" : "") << "\n"
                  << "  MBR     : " << (drive.info().mbrEnabled ? "Enabled" : "Disabled")
                  << (drive.info().mbrDone ? " (Done)" : "") << "\n";
    }
    return EC_OK;
}

// drive msid
int drive_msid(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);
    const auto& m = drive.msid();
    if (m.empty()) {
        std::cerr << "error: MSID unavailable (drive may require activation or auth)\n";
        return EC_NOT_SUPPORTED;
    }
    // MSID is the only "result data" — always print it to stdout, even at quiet.
    std::cout << std::string(m.begin(), m.end()) << "\n";
    return EC_OK;
}

// drive revert --sp {admin|locking}
int drive_revert(Context& ctx, const std::string& sp) {
    if (int e = requireForce(ctx, "drive revert"); e) return e;
    if (ctx.password.empty()) {
        std::cerr << "error: --password required\n";
        return EC_USAGE;
    }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    Result r = (sp == "locking") ? drive.revertLockingSP(ctx.password)
                                 : drive.revert(ctx.password);
    return reportResult(ctx, "revert " + sp, r);
}

// drive psid-revert --psid <psid>
int drive_psid_revert(Context& ctx, const std::string& psid) {
    if (int e = requireForce(ctx, "drive psid-revert"); e) return e;
    if (psid.empty()) {
        std::cerr << "error: --psid required\n";
        return EC_USAGE;
    }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    return reportResult(ctx, "psid-revert", drive.psidRevert(psid));
}

// range list
int range_list(Context& ctx) {
    if (ctx.password.empty()) {
        std::cerr << "error: --password (Admin1) required\n";
        return EC_USAGE;
    }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    std::vector<LockingInfo> ranges;
    auto r = drive.enumerateRanges(ctx.password, ranges);
    if (r.ok() && ctx.v() >= Verbosity::Info) {
        std::cout << "ID | Start        Length       | RLE WLE RLck WLck\n";
        for (const auto& ri : ranges) {
            std::cout << std::right << std::setw(2) << ri.rangeId << " | "
                      << std::setw(12) << ri.rangeStart << " "
                      << std::setw(12) << ri.rangeLength << " | "
                      << " " << (ri.readLockEnabled ? "Y" : "N")
                      << "   " << (ri.writeLockEnabled ? "Y" : "N")
                      << "   " << (ri.readLocked ? "Y" : "N")
                      << "    " << (ri.writeLocked ? "Y" : "N")
                      << "\n";
        }
    }
    return reportResult(ctx, "range list", r);
}

// range erase --id N
int range_erase(Context& ctx, uint32_t id) {
    if (int e = requireForce(ctx, "range erase"); e) return e;
    if (ctx.password.empty()) {
        std::cerr << "error: --password (Admin1) required\n";
        return EC_USAGE;
    }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    return reportResult(ctx, "crypto-erase", drive.cryptoErase(id, ctx.password));
}

// user list (Admin1 + User1..N 활성화 상태)
int user_list(Context& ctx) {
    if (ctx.password.empty()) {
        std::cerr << "error: --password (Admin1) required\n";
        return EC_USAGE;
    }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    std::vector<SedDrive::AuthorityInfo> auths;
    auto r = drive.enumerateAuthorities(ctx.password, auths);
    if (r.ok() && ctx.v() >= Verbosity::Info) {
        std::cout << "Authority     Enabled  UID\n";
        for (const auto& a : auths) {
            const char* kind = (a.kind == SedDrive::AuthorityKind::Admin) ? "Admin" : "User";
            std::cout << "  " << std::left << std::setw(5) << kind
                      << " " << std::setw(2) << a.id
                      << "  " << std::setw(5) << (a.enabled ? "Y" : "N")
                      << "   0x" << std::hex << std::setw(16) << std::setfill('0')
                      << a.uid.toUint64() << std::dec << std::setfill(' ')
                      << "\n";
        }
    }
    return reportResult(ctx, "user list", r);
}

// user assign --id <userId> --range <rangeId>
int user_assign(Context& ctx, uint32_t userId, uint32_t rangeId) {
    if (ctx.password.empty()) {
        std::cerr << "error: --password (Admin1) required\n";
        return EC_USAGE;
    }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login", s.openResult());
    auto r = s.assignUserToRange(userId, rangeId);
    return reportResult(ctx, "user assign", r);
}

// mbr status
int mbr_status(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);
    SedDrive::MbrStatus s{};
    auto r = drive.getMbrStatus(s);
    if (r.ok() && ctx.v() >= Verbosity::Info) {
        std::cout << "MBR Shadow:\n"
                  << "  Supported : " << (s.supported ? "Yes" : "No") << "\n"
                  << "  Enabled   : " << (s.enabled ? "Yes" : "No") << "\n"
                  << "  Done      : " << (s.done ? "Yes" : "No") << "\n";
    }
    return reportResult(ctx, "mbr status", r);
}

// mbr write --file <bin>
//
// FIX vs prior renewal: MBR table write requires LockingSP / Admin1 per TCG
// Opal SSC, NOT AdminSP / SID. The earlier code used SP_ADMIN+AUTH_SID which
// silently passed on the permissive SimTransport but would fail with St=0x01
// (NotAuthorized) on a real Opal drive.
int mbr_write(Context& ctx, const std::string& path) {
    if (int e = requireForce(ctx, "mbr write"); e) return e;
    if (ctx.password.empty()) {
        std::cerr << "error: --password (Admin1) required\n";
        return EC_USAGE;
    }
    Bytes data;
    if (!readBinaryFile(path, data)) {
        std::cerr << "error: cannot read " << path << "\n";
        return EC_USAGE;
    }

    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login(LockingSP/Admin1)", s.openResult());
    auto r = s.writeMbr(0, data);
    return reportResult(ctx, "mbr write", r);
}

// ── eval: expert / evaluator primitives ────────────────────────────────────

int eval_tx_start(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);

    Session session(ctx.transport, drive.comId());
    StartSessionResult ssr;
    if (auto r = ctx.api.startSession(session, uid::SP_ADMIN, /*write=*/true, ssr);
        r.failed())
        return reportResult(ctx, "startSession", r);

    RawResult raw;
    ctx.api.startTransaction(session, raw);
    int ec = reportRaw(ctx, "startTransaction", raw);
    if (ctx.v() >= Verbosity::Trace) {
        dissect("SENT", raw.rawSendPayload);
        dissect("RECV", raw.rawRecvPayload);
    }
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "  note: session closes on exit — the transaction ends here too.\n"
                     "        Use `eval transaction <script.json>` (future) for multi-op.\n";
    }
    ctx.api.closeSession(session);
    return ec;
}

struct TableGetArgs {
    uint64_t tableUid = 0;
    uint32_t col      = 0;
    std::string spName = "admin"; // "admin" or "locking"
};

int eval_table_get(Context& ctx, const TableGetArgs& a) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);

    // Choose SP + authority based on --sp. AdminSP uses SID; LockingSP uses Admin1.
    uint64_t spUid   = (a.spName == "locking") ? uid::SP_LOCKING  : uid::SP_ADMIN;
    uint64_t authUid = (a.spName == "locking") ? uid::AUTH_ADMIN1 : uid::AUTH_SID;

    Session session(ctx.transport, drive.comId());
    StartSessionResult ssr;
    Bytes cred(ctx.password.begin(), ctx.password.end());
    Result r = cred.empty()
        ? ctx.api.startSession(session, spUid, /*write=*/false, ssr)
        : ctx.api.startSessionWithAuth(session, spUid, /*write=*/false, authUid, cred, ssr);
    if (r.failed()) return reportResult(ctx, "startSession", r);

    Token val;
    RawResult raw;
    ctx.api.tableGetColumn(session, a.tableUid, a.col, val, raw);
    int ec = reportRaw(ctx, "tableGetColumn", raw);
    if (raw.methodResult.isSuccess()) {
        std::cout << "  col[" << a.col << "] = " << val.toString() << "\n";
    }
    if (ctx.v() >= Verbosity::Trace) {
        dissect("SENT", raw.rawSendPayload);
        dissect("RECV", raw.rawRecvPayload);
    }
    ctx.api.closeSession(session);
    return ec;
}

struct RawMethodArgs {
    uint64_t    invoker = 0;
    uint64_t    methodUid = 0;
    std::string hexPayload;
};

// eval raw-method — fuzzing-grade. `--force` required (drive can be bricked).
int eval_raw_method(Context& ctx, const RawMethodArgs& a) {
    if (int e = requireForce(ctx, "eval raw-method"); e) return e;

    Bytes payload;
    if (!a.hexPayload.empty()) {
        std::string err;
        if (!parseHexString(a.hexPayload, payload, err)) {
            std::cerr << "error: --payload: " << err << "\n";
            return EC_USAGE;
        }
    }

    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);

    Session session(ctx.transport, drive.comId());
    StartSessionResult ssr;
    if (auto r = ctx.api.startSession(session, uid::SP_ADMIN, /*write=*/true, ssr);
        r.failed())
        return reportResult(ctx, "startSession", r);

    Bytes tokens = EvalApi::buildMethodCall(a.invoker, a.methodUid, payload);
    RawResult raw;
    ctx.api.sendRawMethod(session, tokens, raw);
    int ec = reportRaw(ctx, "sendRawMethod", raw);
    if (ctx.v() >= Verbosity::Trace) {
        dissect("SENT", raw.rawSendPayload);
        dissect("RECV", raw.rawRecvPayload);
    }
    ctx.api.closeSession(session);
    return ec;
}

} // namespace cmd

// ── main ────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    CLI::App app{"cats-cli — TCG SED evaluation & debugging platform"};
    app.require_subcommand(1);

    Context ctx;
    app.add_option ("-d,--device",    ctx.device,       "Target NVMe device (e.g. /dev/nvme0)");
    app.add_option ("-v,--verbosity", ctx.verbosityRaw, "0=quiet, 1=info (default), 2=debug, 3=trace")
        ->default_val(1)->check(CLI::Range(0, 3));
    app.add_option ("--log-file",     ctx.logFile,      "Mirror flow log (LIBSED_*) to stderr AND this file");
    app.add_option ("-p,--password",  ctx.password,     "Password (warning: visible in 'ps'; prefer env/file in CI)");
    app.add_flag   ("--force",        ctx.force,        "Required for destructive ops (revert / erase / mbr write / raw-method)");
    app.add_flag   ("--sim",          ctx.useSim,       "Run against the internal SimTransport (self-test, no hardware)");

    int finalExit = EC_OK;

    // ── drive ──
    auto* drive = app.add_subcommand("drive", "Drive-level operations");
    drive->add_subcommand("discover", "Level 0 Discovery + summary")
        ->callback([&]{ finalExit = cmd::drive_discover(ctx); });
    drive->add_subcommand("msid", "Read MSID (AdminSP, anonymous)")
        ->callback([&]{ finalExit = cmd::drive_msid(ctx); });

    std::string spName = "admin";
    auto* driveRevert = drive->add_subcommand("revert", "Factory-reset an SP (DESTRUCTIVE — requires --force)");
    driveRevert->add_option("--sp", spName, "Which SP: admin (default) or locking")
        ->check(CLI::IsMember({"admin", "locking"}))->default_val("admin");
    driveRevert->callback([&]{ finalExit = cmd::drive_revert(ctx, spName); });

    std::string psidValue;
    auto* drivePsid = drive->add_subcommand("psid-revert", "PSID-based factory reset (DESTRUCTIVE — requires --force)");
    drivePsid->add_option("--psid", psidValue, "PSID string printed on the drive label")->required();
    drivePsid->callback([&]{ finalExit = cmd::drive_psid_revert(ctx, psidValue); });

    // ── range ──
    auto* range = app.add_subcommand("range", "Locking Range (Opal SSC)");
    range->add_subcommand("list", "List all configured ranges")
        ->callback([&]{ finalExit = cmd::range_list(ctx); });

    uint32_t rangeId = 0;
    auto* rangeErase = range->add_subcommand("erase", "Crypto-erase a range (DESTRUCTIVE — requires --force)");
    rangeErase->add_option("--id", rangeId, "Range ID (1..N)")->required();
    rangeErase->callback([&]{ finalExit = cmd::range_erase(ctx, rangeId); });

    // ── user ──
    auto* user = app.add_subcommand("user", "User / Authority management");
    user->add_subcommand("list", "List Admin/User authorities and enabled state")
        ->callback([&]{ finalExit = cmd::user_list(ctx); });

    uint32_t userId = 0, userRangeId = 0;
    auto* userAssign = user->add_subcommand("assign", "Assign a user to a range");
    userAssign->add_option("--id", userId, "User ID (1..N)")->required();
    userAssign->add_option("--range", userRangeId, "Target range ID")->required();
    userAssign->callback([&]{ finalExit = cmd::user_assign(ctx, userId, userRangeId); });

    // ── mbr ──
    auto* mbr = app.add_subcommand("mbr", "Shadow MBR");
    mbr->add_subcommand("status", "Show MBR shadow enabled/done/supported")
        ->callback([&]{ finalExit = cmd::mbr_status(ctx); });

    std::string mbrFile;
    auto* mbrWrite = mbr->add_subcommand("write", "Write PBA image to MBR table (requires --force; LockingSP/Admin1)");
    mbrWrite->add_option("--file", mbrFile, "Path to binary PBA image")->required();
    mbrWrite->callback([&]{ finalExit = cmd::mbr_write(ctx, mbrFile); });

    // ── eval ──
    auto* eval = app.add_subcommand("eval", "Expert / evaluator primitives");

    eval->add_subcommand("tx-start",
        "Send StartTransaction (closes on exit — use script runner for real txns)")
        ->callback([&]{ finalExit = cmd::eval_tx_start(ctx); });

    cmd::TableGetArgs tga;
    auto* tget = eval->add_subcommand("table-get", "Read one column from any table");
    tget->add_option("--table", tga.tableUid, "Table/object UID (hex)")->required();
    tget->add_option("--col",   tga.col,      "Column ID")->default_val(0);
    tget->add_option("--sp",    tga.spName,   "SP: admin (default) or locking")
        ->check(CLI::IsMember({"admin", "locking"}))->default_val("admin");
    tget->callback([&]{ finalExit = cmd::eval_table_get(ctx, tga); });

    cmd::RawMethodArgs rma;
    auto* rawMethod = eval->add_subcommand("raw-method",
        "Send an arbitrary method call (REQUIRES --force — can brick the drive)");
    rawMethod->add_option("--invoke",  rma.invoker,     "Invoking UID (hex)")->required();
    rawMethod->add_option("--method",  rma.methodUid,   "Method UID (hex)")->required();
    rawMethod->add_option("--payload", rma.hexPayload,  "Raw params as hex (inside STARTLIST/ENDLIST), optional");
    rawMethod->callback([&]{ finalExit = cmd::eval_raw_method(ctx, rma); });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // Let CLI11 print its message/help, but return OUR unified usage code
        // so automation can distinguish parse errors from runtime errors.
        app.exit(e);
        return EC_USAGE;
    }

    return finalExit;
}
