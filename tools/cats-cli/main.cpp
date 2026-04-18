// cats-cli — TCG SED Evaluation & Debugging Platform (Final Masterpiece)
//
// Refined per fundamental review and mentor feedback. 
// Follows the "Four Pillars of Engineering Rigor" for reliability and purity.

#include <CLI11.hpp>
#include <json.hpp>

#include <libsed/cli/cli_common.h>
#include <libsed/core/log.h>
#include <libsed/debug/logging_transport.h>
#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/transport/sim_transport.h>
#include <libsed/codec/token_decoder.h>
#include <libsed/packet/com_packet.h>
#include <libsed/facade/sed_drive.h>

#include "transaction.h"

#include <cctype>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace libsed;
using namespace libsed::eval;

// ── Exit codes (Design Doc §8.3) ───────────────────────────────────────────

enum ExitCode : int {
    EC_OK              = 0,
    EC_USAGE           = 1,
    EC_TRANSPORT       = 2,
    EC_TCG_METHOD      = 3,
    EC_AUTH            = 4,
    EC_NOT_SUPPORTED   = 5,
};

static int mapTcgStatusToExit(MethodStatus status) {
    if (status == MethodStatus::Success)       return EC_OK;
    if (status == MethodStatus::NotAuthorized) return EC_AUTH;
    return EC_TCG_METHOD;
}

// ── Packet Dissector (Trace Mode) ────────────────────────────────────────────

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
                    std::cout << "UID: 0x" << std::hex << std::setw(16) << std::setfill('0') << u << std::dec << "\n";
                } else {
                    std::cout << "BYTES[" << b.size() << "]\n";
                }
            } else {
                std::cout << (tok.isSigned ? "INT: " : "UINT: ") << tok.getUint() << "\n";
            }
            break;
    }
}

void dissect(const std::string& label, const Bytes& data) {
    if (data.empty()) return;
    if (data.size() < 56) return;
    uint32_t subLen = Endian::readBe32(data.data() + 52);
    if (subLen > 0 && data.size() >= 56 + subLen) {
        std::cout << "  [TRACE] " << label << " payload (" << subLen << " bytes):\n";
        TokenDecoder d;
        if (d.decode(data.data() + 56, subLen).ok()) {
            int depth = 0;
            for (const auto& tok : d.tokens()) {
                if (tok.type == TokenType::EndList || tok.type == TokenType::EndName) --depth;
                dumpToken(tok, depth);
                if (tok.type == TokenType::StartList || tok.type == TokenType::StartName) ++depth;
            }
        }
    }
}

} // namespace

// ── Context & Safety ─────────────────────────────────────────────────────────

enum class Verbosity : int { Quiet = 0, Info = 1, Debug = 2, Trace = 3 };

struct Context {
    std::string device;
    int         verbosityRaw = 1;
    std::string logFile;

    // Password input paths — at most one may be given; resolved into `password`
    // at init(). Keeps `--password PW` literal out of `ps(1)` when users pick
    // env/file/stdin.
    std::string password;
    std::string pwEnv;
    std::string pwFile;
    bool        pwStdin = false;

    bool        force       = false;
    bool        useSim      = false;
    bool        jsonOut     = false;
    uint32_t    repeat      = 1;
    uint32_t    repeatDelay = 0;

    std::shared_ptr<ITransport> transport;
    EvalApi                     api;

    Verbosity v() const { return static_cast<Verbosity>(verbosityRaw); }

    // Resolve password from at most one of: --password / --pw-env / --pw-file
    // / --pw-stdin. Idempotent — second call is a no-op. Returns EC_OK on
    // success (including "not provided").
    bool pwResolved_ = false;
    int resolvePassword() {
        if (pwResolved_) return EC_OK;
        // Count sources EXCLUDING the already-resolved literal. --password was
        // set by CLI11 directly; env/file/stdin fill `password` but we only
        // count their directive fields as sources.
        int sources = 0;
        bool literalGiven = !password.empty();
        if (literalGiven) ++sources;
        if (!pwEnv.empty())  ++sources;
        if (!pwFile.empty()) ++sources;
        if (pwStdin)         ++sources;
        if (sources > 1) {
            std::cerr << "error: use only one of --password / --pw-env / --pw-file / --pw-stdin\n";
            return EC_USAGE;
        }
        if (!pwEnv.empty()) {
            const char* v = std::getenv(pwEnv.c_str());
            if (!v || *v == '\0') {
                std::cerr << "error: env var " << pwEnv << " not set or empty\n";
                return EC_USAGE;
            }
            password = v;
        } else if (!pwFile.empty()) {
            std::ifstream f(pwFile);
            if (!f) { std::cerr << "error: cannot read --pw-file " << pwFile << "\n"; return EC_USAGE; }
            std::getline(f, password);
            if (password.empty()) { std::cerr << "error: --pw-file empty\n"; return EC_USAGE; }
        } else if (pwStdin) {
            std::getline(std::cin, password);
            if (password.empty()) { std::cerr << "error: --pw-stdin produced no input\n"; return EC_USAGE; }
        }
        pwResolved_ = true;
        return EC_OK;
    }

    int init() {
        if (int e = resolvePassword(); e) return e;
        if (!useSim && device.empty()) {
            std::cerr << "error: --device required (or use --sim)\n";
            return EC_USAGE;
        }
        transport = useSim ? std::make_shared<SimTransport>() : TransportFactory::createNvme(device);
        if (!transport) {
            std::cerr << "error: failed to open " << (useSim ? "Simulator" : device) << "\n";
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

    void trace(const RawResult& r) const {
        if (v() < Verbosity::Trace) return;
        dissect("SENT", r.rawSendPayload);
        dissect("RECV", r.rawRecvPayload);
    }
};

static int requireForce(const Context& ctx, const std::string& action) {
    if (!ctx.force) {
        std::cerr << "error: '" << action << "' is destructive. Re-run with --force to acknowledge.\n";
        return EC_USAGE;
    }
    return EC_OK;
}

// Map ErrorCode ranges → cats-cli ExitCode bucket (design doc §8.3).
//   Transport layer      100-199 → EC_TRANSPORT
//   Auth layer           600-699 → EC_AUTH
//   Discovery / feature  500-599 → EC_NOT_SUPPORTED
//   everything else              → EC_TCG_METHOD
static int exitFor(ErrorCode ec) {
    auto v = static_cast<int>(ec);
    if (ec == ErrorCode::Success)  return EC_OK;
    if (v >= 100 && v <= 199)      return EC_TRANSPORT;
    if (v >= 600 && v <= 699)      return EC_AUTH;
    if (v >= 500 && v <= 599)      return EC_NOT_SUPPORTED;
    return EC_TCG_METHOD;
}

static int reportResult(const Context& ctx, const std::string& label, Result r) {
    if (r.ok()) {
        if (ctx.v() >= Verbosity::Info) std::cout << "  ✓ " << label << " ... Success\n";
        return EC_OK;
    }
    std::cerr << "  ✗ " << label << " ... FAILED (" << r.message() << ")\n";
    return exitFor(r.code());
}

static int reportRaw(const Context& ctx, const std::string& label, const RawResult& r) {
    const bool tOk = r.transportError == ErrorCode::Success;
    const bool mOk = r.methodResult.isSuccess();
    if (ctx.v() >= Verbosity::Info) {
        std::cout << (tOk && mOk ? "  ✓ " : "  ✗ ") << label 
                  << " [Transport=" << (tOk ? "OK" : "Error") << ", Method=0x" 
                  << std::hex << (int)r.methodResult.status() << std::dec 
                  << " (" << r.methodResult.statusMessage() << ")]\n";
    }
    if (!tOk) return EC_TRANSPORT;
    return mapTcgStatusToExit(r.methodResult.status());
}

static bool parseHexString(const std::string& in, Bytes& out, std::string& err) {
    out.clear(); std::string s;
    for (char c : in) if (!std::isspace((unsigned char)c)) s.push_back(c);
    if (s.size() >= 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) s = s.substr(2);
    if (s.size() % 2 != 0) { err = "odd length"; return false; }
    for (size_t i = 0; i < s.size(); i += 2) {
        if (!std::isxdigit(s[i]) || !std::isxdigit(s[i+1])) { err = "non-hex"; return false; }
        out.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    }
    return true;
}

// ── Subcommand Implementations ───────────────────────────────────────────────

namespace cmd {

int drive_discover(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);
    const auto& info = drive.info();

    if (ctx.jsonOut) {
        nlohmann::json j = {
            {"command", "drive discover"},
            {"ssc",             drive.sscName()},
            {"com_id",          drive.comId()},
            {"num_com_ids",     drive.numComIds()},
            {"max_compacket",   drive.maxComPacketSize()},
            {"locking_present", info.lockingPresent},
            {"locking_enabled", info.lockingEnabled},
            {"locked",          info.locked},
            {"mbr_supported",   info.mbrSupported},
            {"mbr_enabled",     info.mbrEnabled},
            {"mbr_done",        info.mbrDone},
        };
        std::cout << j.dump(2) << "\n";
        return EC_OK;
    }
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "Drive Summary:\n"
                  << "  SSC     : " << drive.sscName() << "\n"
                  << "  ComID   : 0x" << std::hex << drive.comId() << std::dec << "\n"
                  << "  Locking : " << (info.lockingEnabled ? "Enabled" : "Disabled")
                  << (info.locked ? " (locked)" : "") << "\n"
                  << "  MBR     : " << (info.mbrEnabled ? "Enabled" : "Disabled")
                  << (info.mbrDone ? " (Done)" : "") << "\n";
    }
    return EC_OK;
}

int drive_msid(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    Bytes msid;
    auto r = drive.readMsid(msid);
    if (r.failed()) return reportResult(ctx, "readMsid", r);

    if (ctx.jsonOut) {
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (uint8_t b : msid) hex << std::setw(2) << (int)b;
        // Check if MSID is printable-ASCII before putting it in a JSON string
        // (nlohmann requires valid UTF-8; binary MSIDs throw).
        bool printable = !msid.empty();
        for (uint8_t b : msid) if (b < 0x20 || b > 0x7E) { printable = false; break; }
        nlohmann::json j = {
            {"command",  "drive msid"},
            {"msid_hex", hex.str()},
            {"length",   msid.size()},
        };
        if (printable) j["msid_ascii"] = std::string(msid.begin(), msid.end());
        std::cout << j.dump(2) << "\n";
        return EC_OK;
    }
    std::cout << std::string(msid.begin(), msid.end()) << "\n";
    return EC_OK;
}

int drive_revert(Context& ctx, const std::string& sp) {
    if (int e = requireForce(ctx, "drive revert"); e) return e;
    if (ctx.password.empty()) { std::cerr << "error: --password required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    return reportResult(ctx, "revert " + sp, (sp == "locking" ? drive.revertLockingSP(ctx.password) : drive.revert(ctx.password)));
}

int drive_psid_revert(Context& ctx, const std::string& psid) {
    if (int e = requireForce(ctx, "drive psid-revert"); e) return e;
    if (psid.empty()) { std::cerr << "error: --psid required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    return reportResult(ctx, "psid-revert", drive.psidRevert(psid));
}

int range_list(Context& ctx) {
    if (int e = ctx.resolvePassword(); e) return e;  // ensure password resolved for the early check below
    if (ctx.password.empty()) { std::cerr << "error: --password* (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    std::vector<LockingInfo> ranges;
    auto r = drive.enumerateRanges(ctx.password, ranges);
    if (r.failed()) return reportResult(ctx, "range list", r);

    if (ctx.jsonOut) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& ri : ranges) {
            arr.push_back({
                {"id",                 ri.rangeId},
                {"start",              ri.rangeStart},
                {"length",             ri.rangeLength},
                {"read_lock_enabled",  ri.readLockEnabled},
                {"write_lock_enabled", ri.writeLockEnabled},
                {"read_locked",        ri.readLocked},
                {"write_locked",       ri.writeLocked},
                {"active_key",         ri.activeKey},
            });
        }
        std::cout << nlohmann::json({{"command", "range list"}, {"ranges", arr}}).dump(2) << "\n";
        return EC_OK;
    }
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "ID | Start        Length       | RLE WLE RLck WLck\n";
        for (const auto& ri : ranges) {
            std::cout << std::setw(2) << ri.rangeId << " | "
                      << std::setw(12) << ri.rangeStart << " "
                      << std::setw(12) << ri.rangeLength << " |  "
                      << (ri.readLockEnabled ? 'Y' : 'N') << "   "
                      << (ri.writeLockEnabled ? 'Y' : 'N') << "   "
                      << (ri.readLocked ? 'Y' : 'N') << "    "
                      << (ri.writeLocked ? 'Y' : 'N') << "\n";
        }
    }
    return EC_OK;
}

int range_setup(Context& ctx, uint32_t rid, uint64_t start, uint64_t len) {
    if (int e = requireForce(ctx, "range setup"); e) return e;
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login", s.openResult());
    return reportResult(ctx, "range setup", s.setRange(rid, start, len));
}

int range_erase(Context& ctx, uint32_t rid) {
    if (int e = requireForce(ctx, "range erase"); e) return e;
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    return reportResult(ctx, "crypto-erase", drive.cryptoErase(rid, ctx.password));
}

int band_list(Context& ctx) {
    if (ctx.password.empty()) { std::cerr << "error: --password required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    std::vector<LockingInfo> bands;
    auto r = drive.enumerateBands(ctx.password, bands);
    if (r.ok() && ctx.v() >= Verbosity::Info) {
        for (const auto& bi : bands) std::cout << "Band " << bi.rangeId << ": " << bi.rangeStart << " + " << bi.rangeLength << "\n";
    }
    return reportResult(ctx, "band list", r);
}

int mbr_write(Context& ctx, const std::string& path) {
    if (int e = requireForce(ctx, "mbr write"); e) return e;
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "error: cannot read " << path << "\n"; return EC_USAGE; }
    Bytes data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login(LockingSP/Admin1)", s.openResult());
    return reportResult(ctx, "mbr write", s.writeMbr(0, data));
}

int mbr_status(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    // Use Discovery-derived state (LockingFeature flags 0x10/0x20/0x40). No
    // session needed — the facade's getMbrStatus() opens an anonymous AdminSP
    // session to read MBRControl which many drives restrict to LockingSP/
    // Admin1; relying on dinfo avoids that failure mode at the MoT moment.
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);
    const auto& info = drive.info();

    if (ctx.jsonOut) {
        nlohmann::json j = {
            {"command",   "mbr status"},
            {"supported", info.mbrSupported},
            {"enabled",   info.mbrEnabled},
            {"done",      info.mbrDone},
        };
        std::cout << j.dump(2) << "\n";
        return EC_OK;
    }
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "MBR Shadow:\n"
                  << "  Supported : " << (info.mbrSupported ? "Yes" : "No") << "\n"
                  << "  Enabled   : " << (info.mbrEnabled   ? "Yes" : "No") << "\n"
                  << "  Done      : " << (info.mbrDone      ? "Yes" : "No") << "\n";
    }
    return EC_OK;
}

int user_list(Context& ctx) {
    if (int e = ctx.resolvePassword(); e) return e;
    if (ctx.password.empty()) { std::cerr << "error: --password* (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    std::vector<SedDrive::AuthorityInfo> auths;
    auto r = drive.enumerateAuthorities(ctx.password, auths);
    if (r.failed()) return reportResult(ctx, "user list", r);

    if (ctx.jsonOut) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& a : auths) {
            arr.push_back({
                {"kind",    a.kind == SedDrive::AuthorityKind::Admin ? "Admin" : "User"},
                {"id",      a.id},
                {"uid",     a.uid.toUint64()},
                {"enabled", a.enabled},
            });
        }
        std::cout << nlohmann::json({{"command", "user list"}, {"authorities", arr}}).dump(2) << "\n";
        return EC_OK;
    }
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "Authority   Enabled  UID\n";
        for (const auto& a : auths) {
            const char* k = (a.kind == SedDrive::AuthorityKind::Admin) ? "Admin" : "User";
            std::cout << "  " << std::left << std::setw(5) << k << " " << std::setw(2) << a.id
                      << "   " << std::setw(5) << (a.enabled ? "Y" : "N")
                      << "   0x" << std::hex << std::setw(16) << std::setfill('0')
                      << a.uid.toUint64() << std::dec << std::setfill(' ') << "\n";
        }
    }
    return EC_OK;
}

int user_assign(Context& ctx, uint32_t userId, uint32_t rangeId) {
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login", s.openResult());
    return reportResult(ctx, "user assign", s.assignUserToRange(userId, rangeId));
}

int eval_tx_start(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);
    Session session(ctx.transport, drive.comId());
    StartSessionResult ssr;
    if (auto r = ctx.api.startSession(session, uid::SP_ADMIN, /*write=*/true, ssr); r.failed())
        return reportResult(ctx, "startSession", r);
    RawResult raw;
    ctx.api.startTransaction(session, raw);
    int ec = reportRaw(ctx, "startTransaction", raw);
    if (ctx.v() >= Verbosity::Trace) dissect("SENT", raw.rawSendPayload), dissect("RECV", raw.rawRecvPayload);
    ctx.api.closeSession(session);
    return ec;
}

// ── Eval Primitives ──

struct TableGetArgs { uint64_t table = 0; uint32_t col = 0; uint32_t end = 0; std::string sp = "admin"; };

int eval_table_get(Context& ctx, const TableGetArgs& a) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    uint64_t spUid = (a.sp == "locking") ? uid::SP_LOCKING : uid::SP_ADMIN;
    uint64_t authUid = (a.sp == "locking") ? uid::AUTH_ADMIN1 : uid::AUTH_SID;
    RawResult raw; Result r;
    if (a.end > a.col) {
        TableResult tr; r = drive.withSession(spUid, ctx.password, authUid, [&](Session& s){ return drive.api().tableGet(s, a.table, a.col, a.end, tr); });
        raw = tr.raw;
        if (r.ok()) for (const auto& c : tr.columns) std::cout << "  col[" << c.first << "] = " << c.second.toString() << "\n";
    } else {
        Token val; r = drive.getTableColumn(spUid, authUid, ctx.password, a.table, a.col, val, raw);
        if (r.ok()) std::cout << "  col[" << a.col << "] = " << val.toString() << "\n";
    }
    ctx.trace(raw);
    return reportRaw(ctx, "table-get", raw);
}

int eval_raw_method(Context& ctx, uint64_t inv, uint64_t method, const std::string& hex) {
    if (int e = requireForce(ctx, "eval raw-method"); e) return e;
    Bytes payload; std::string err;
    if (!hex.empty() && !parseHexString(hex, payload, err)) { std::cerr << "error: --payload: " << err << "\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    RawResult raw;
    auto r = drive.runRawMethod(uid::SP_ADMIN, uid::AUTH_SID, ctx.password, EvalApi::buildMethodCall(inv, method, payload), raw);
    ctx.trace(raw);
    return reportRaw(ctx, "raw-method", raw);
}

// ── Range: granular lock control ────────────────────────────────────────────

int range_lock(Context& ctx, uint32_t rid, bool readLocked, bool writeLocked) {
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login", s.openResult());
    return reportResult(ctx, "range lock",
                        s.setRangeLockState(rid, readLocked, writeLocked));
}

// ── User enable / set-pw ────────────────────────────────────────────────────

int user_enable(Context& ctx, uint32_t userId) {
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login", s.openResult());
    return reportResult(ctx, "user enable", s.enableUser(userId));
}

int user_set_pw(Context& ctx, uint32_t userId, const std::string& newPw) {
    if (ctx.password.empty())  { std::cerr << "error: --password (Admin1) required (--new-pw* for the new user password)\n"; return EC_USAGE; }
    if (newPw.empty())         { std::cerr << "error: --new-pw required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    auto s = drive.login(uid::SP_LOCKING, ctx.password, uid::AUTH_ADMIN1);
    if (s.failed()) return reportResult(ctx, "login", s.openResult());
    return reportResult(ctx, "user set-pw", s.setUserPassword(userId, newPw));
}

// ── MBR enable / done ───────────────────────────────────────────────────────

int mbr_enable(Context& ctx, bool on) {
    if (int e = requireForce(ctx, "mbr enable"); e) return e;
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    return reportResult(ctx, on ? "mbr enable" : "mbr disable",
                        drive.setMbrEnable(on, ctx.password));
}

int mbr_done(Context& ctx, bool on) {
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    return reportResult(ctx, on ? "mbr done=Y" : "mbr done=N",
                        drive.setMbrDone(on, ctx.password));
}

// ── Eval: transaction script runner ─────────────────────────────────────────

static std::string toHex(const Bytes& b, size_t maxBytes = 128) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    size_t n = std::min(b.size(), maxBytes);
    for (size_t i = 0; i < n; ++i) os << std::setw(2) << (int)b[i];
    if (b.size() > maxBytes) os << "...";
    return os.str();
}

int eval_transaction(Context& ctx, const std::string& path) {
    if (int e = ctx.init(); e) return e;

    std::ifstream f(path);
    if (!f) { std::cerr << "error: cannot read " << path << "\n"; return EC_USAGE; }
    std::stringstream ss; ss << f.rdbuf();

    catscli::TxScript script;
    std::string err = catscli::parseTxScript(ss.str(), script);
    if (!err.empty()) { std::cerr << "error: " << err << "\n"; return EC_USAGE; }

    SedDrive drive(ctx.transport);
    if (auto r = drive.query(); r.failed()) return reportResult(ctx, "drive.query", r);

    catscli::TxResult tr;
    auto r = catscli::runTxScript(script, ctx.api, ctx.transport, drive.comId(), tr);

    if (ctx.jsonOut) {
        nlohmann::json j;
        j["command"]       = "eval transaction";
        j["script"]        = path;
        j["terminated_by"] = tr.terminatedBy;
        j["ok"]            = tr.ok;
        j["on_error"]      = script.onError;
        j["steps"]         = nlohmann::json::array();
        for (const auto& s : tr.steps) {
            nlohmann::json je;
            je["step"]            = s.step;
            je["op"]              = s.op;
            if (!s.objectLabel.empty()) je["object"] = s.objectLabel;
            je["transport_ok"]    = s.transportOk;
            je["tcg_status"]      = s.tcgStatus;
            je["tcg_status_name"] = s.tcgStatusName;
            je["elapsed_ms"]      = s.elapsedMs;
            if (ctx.v() >= Verbosity::Debug) {
                je["send_hex"] = toHex(s.rawSend);
                je["recv_hex"] = toHex(s.rawRecv);
            }
            if (!s.errorNote.empty()) je["error"] = s.errorNote;
            j["steps"].push_back(je);
        }
        std::cout << j.dump(2) << "\n";
    } else if (ctx.v() >= Verbosity::Info) {
        const size_t total = tr.steps.size();
        for (const auto& s : tr.steps) {
            char line[160];
            snprintf(line, sizeof(line),
                     "  [%d/%zu] %-14s %-20s %s  (%ldms, St=0x%02X %s)",
                     s.step, total, s.op.c_str(),
                     s.objectLabel.c_str(),
                     (s.transportOk && s.tcgStatus == 0) ? "OK  " : "FAIL",
                     s.elapsedMs, s.tcgStatus, s.tcgStatusName.c_str());
            std::cout << line << "\n";
            if (!s.errorNote.empty()) std::cout << "     " << s.errorNote << "\n";
        }
        std::cout << "Summary: "
                  << (tr.ok ? "ok" : "fail")
                  << ", terminated_by=" << tr.terminatedBy << "\n";
    }

    if (r.failed()) return reportResult(ctx, "eval transaction", r);
    if (!tr.ok) return EC_TCG_METHOD;
    return EC_OK;
}

} // namespace cmd

// ── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    CLI::App app{"cats-cli — TCG SED Evaluation & Debugging Platform"};
    app.require_subcommand(1);

    Context ctx;
    app.add_option("-d,--device",     ctx.device,       "Device path");
    app.add_option("-v,--verbosity",  ctx.verbosityRaw, "0=quiet, 1=info, 2=debug, 3=trace")
        ->default_val(1)->check(CLI::Range(0, 3));
    app.add_option("--log-file",      ctx.logFile,      "Mirror flow log to file");

    // Password input paths — use only one.
    app.add_option("-p,--password",   ctx.password,
                   "Password literal (WARNING: visible in 'ps'; prefer env/file in CI)");
    app.add_option("--pw-env",        ctx.pwEnv,
                   "Read password from this environment variable");
    app.add_option("--pw-file",       ctx.pwFile,
                   "Read password from first line of this file");
    app.add_flag  ("--pw-stdin",      ctx.pwStdin,
                   "Read password from stdin (first line)");

    app.add_flag  ("--force",         ctx.force,        "Required for destructive operations");
    app.add_flag  ("--sim",           ctx.useSim,       "Run against internal Simulator (no hardware)");
    app.add_flag  ("--json",          ctx.jsonOut,      "Machine-readable JSON output on stdout");
    app.add_option("--repeat",        ctx.repeat,       "Run the subcommand N times (aging/stress)")
        ->default_val(1)->check(CLI::Range(1u, 100000u));
    app.add_option("--repeat-delay",  ctx.repeatDelay,  "Milliseconds between --repeat iterations")
        ->default_val(0);

    int finalExit = EC_OK;

    auto* drive = app.add_subcommand("drive", "Drive operations");
    drive->add_subcommand("discover", "Discovery summary")->callback([&]{ finalExit = cmd::drive_discover(ctx); });
    drive->add_subcommand("msid", "Read MSID")->callback([&]{ finalExit = cmd::drive_msid(ctx); });
    
    std::string spName = "admin";
    auto* revert = drive->add_subcommand("revert", "Reset SP (Destructive)");
    revert->add_option("--sp", spName, "admin (default) or locking")
          ->check(CLI::IsMember({"admin", "locking"}))->default_val("admin");
    revert->callback([&]{ finalExit = cmd::drive_revert(ctx, spName); });

    std::string psidValue;
    auto* psidRev = drive->add_subcommand("psid-revert", "PSID-based factory reset (Destructive)");
    psidRev->add_option("--psid", psidValue, "PSID string printed on the drive label")->required();
    psidRev->callback([&]{ finalExit = cmd::drive_psid_revert(ctx, psidValue); });

    auto* range = app.add_subcommand("range", "Locking Range operations");
    range->add_subcommand("list", "List ranges")->callback([&]{ finalExit = cmd::range_list(ctx); });
    
    uint32_t rid = 0; uint64_t rstart = 0, rlen = 0;
    auto* rsetup = range->add_subcommand("setup", "Configure range (Destructive)");
    rsetup->add_option("--id", rid)->required(); rsetup->add_option("--start", rstart)->required(); rsetup->add_option("--len", rlen)->required();
    rsetup->callback([&]{ finalExit = cmd::range_setup(ctx, rid, rstart, rlen); });

    uint32_t eraseId = 0;
    auto* rerase = range->add_subcommand("erase", "Crypto-erase a range (Destructive)");
    rerase->add_option("--id", eraseId, "Range ID")->required();
    rerase->callback([&]{ finalExit = cmd::range_erase(ctx, eraseId); });

    // range lock — granular read/write lock state per design doc §3.2.
    uint32_t lockId = 0;
    std::string lockRead = "on", lockWrite = "on";
    auto* rlock = range->add_subcommand("lock", "Set ReadLocked/WriteLocked of a range");
    rlock->add_option("--id",    lockId, "Range ID")->required();
    rlock->add_option("--read",  lockRead,  "on | off")
         ->check(CLI::IsMember({"on", "off"}))->default_val("on");
    rlock->add_option("--write", lockWrite, "on | off")
         ->check(CLI::IsMember({"on", "off"}))->default_val("on");
    rlock->callback([&]{
        finalExit = cmd::range_lock(ctx, lockId, lockRead == "on", lockWrite == "on");
    });

    auto* user = app.add_subcommand("user", "User / Authority management");
    user->add_subcommand("list", "List Admin/User authorities and enabled state")
         ->callback([&]{ finalExit = cmd::user_list(ctx); });
    uint32_t assignUserId = 0, assignRangeId = 0;
    auto* uAssign = user->add_subcommand("assign", "Assign a user to a range");
    uAssign->add_option("--id", assignUserId, "User ID")->required();
    uAssign->add_option("--range", assignRangeId, "Range ID")->required();
    uAssign->callback([&]{ finalExit = cmd::user_assign(ctx, assignUserId, assignRangeId); });

    uint32_t enableUserId = 0;
    auto* uEnable = user->add_subcommand("enable", "Enable a user authority");
    uEnable->add_option("--id", enableUserId, "User ID")->required();
    uEnable->callback([&]{ finalExit = cmd::user_enable(ctx, enableUserId); });

    uint32_t setPwUserId = 0;
    std::string newPw, newPwEnv, newPwFile;
    auto* uSetPw = user->add_subcommand("set-pw", "Set a user password");
    uSetPw->add_option("--id",           setPwUserId, "User ID")->required();
    uSetPw->add_option("--new-pw",       newPw,       "New user password (literal)");
    uSetPw->add_option("--new-pw-env",   newPwEnv,    "New user password from env var");
    uSetPw->add_option("--new-pw-file",  newPwFile,   "New user password from file (first line)");
    uSetPw->callback([&]{
        std::string pw = newPw;
        if (pw.empty() && !newPwEnv.empty()) {
            const char* v = std::getenv(newPwEnv.c_str()); pw = v ? v : "";
        }
        if (pw.empty() && !newPwFile.empty()) {
            std::ifstream f(newPwFile);
            if (f) std::getline(f, pw);
        }
        finalExit = cmd::user_set_pw(ctx, setPwUserId, pw);
    });

    auto* band = app.add_subcommand("band", "Enterprise Band operations");
    band->add_subcommand("list", "List bands")->callback([&]{ finalExit = cmd::band_list(ctx); });

    auto* mbr = app.add_subcommand("mbr", "MBR operations");
    mbr->add_subcommand("status", "Show MBR shadow enabled/done/supported")
       ->callback([&]{ finalExit = cmd::mbr_status(ctx); });
    std::string mbrFile;
    auto* mbrWrite = mbr->add_subcommand("write", "Write PBA image (Destructive)");
    mbrWrite->add_option("--file", mbrFile, "PBA image path")->required();
    mbrWrite->callback([&]{ finalExit = cmd::mbr_write(ctx, mbrFile); });

    std::string mbrEnableArg = "on";
    auto* mbrEn = mbr->add_subcommand("enable", "Enable/disable MBR shadow (Destructive)");
    mbrEn->add_option("--state", mbrEnableArg, "on | off")
         ->check(CLI::IsMember({"on", "off"}))->default_val("on");
    mbrEn->callback([&]{ finalExit = cmd::mbr_enable(ctx, mbrEnableArg == "on"); });

    std::string mbrDoneArg = "on";
    auto* mbrDn = mbr->add_subcommand("done", "Set MBR Done flag (on after PBA handoff)");
    mbrDn->add_option("--state", mbrDoneArg, "on | off")
         ->check(CLI::IsMember({"on", "off"}))->default_val("on");
    mbrDn->callback([&]{ finalExit = cmd::mbr_done(ctx, mbrDoneArg == "on"); });

    auto* eval = app.add_subcommand("eval", "Expert evaluation primitives");
    eval->add_subcommand("tx-start", "Start transaction")->callback([&]{ finalExit = cmd::eval_tx_start(ctx); });
    
    cmd::TableGetArgs tga;
    auto* tget = eval->add_subcommand("table-get", "Read table columns");
    tget->add_option("--table", tga.table)->required();
    tget->add_option("--col", tga.col)->default_val(0);
    tget->add_option("--end", tga.end);
    tget->add_option("--sp", tga.sp)->check(CLI::IsMember({"admin", "locking"}))->default_val("admin");
    tget->callback([&]{ finalExit = cmd::eval_table_get(ctx, tga); });

    uint64_t inv = 0, meth = 0; std::string hex;
    auto* rmeth = eval->add_subcommand("raw-method", "Send raw tokens (Destructive)");
    rmeth->add_option("--invoke", inv)->required();
    rmeth->add_option("--method", meth)->required();
    rmeth->add_option("--payload", hex);
    rmeth->callback([&]{ finalExit = cmd::eval_raw_method(ctx, inv, meth, hex); });

    std::string txScript;
    auto* txRun = eval->add_subcommand("transaction",
        "Run a JSON script inside one session (schema: docs/cats_cli_transaction_schema.md)");
    txRun->add_option("--script", txScript, "Path to JSON script")->required();
    txRun->callback([&]{ finalExit = cmd::eval_transaction(ctx, txScript); });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // Let CLI11 print its usage/error, but unify the exit code so CI and
        // scripts see EC_USAGE(1) — not CLI11's internal 105/106/109.
        app.exit(e);
        return EC_USAGE;
    }

    // --repeat N: re-run the chosen subcommand callback N-1 more times. CLI11
    // callbacks reset finalExit each iteration so we keep the worst exit code
    // and stop early if the user pressed --repeat-stop-on-err (future).
    if (ctx.repeat > 1) {
        int worstExit = finalExit;
        for (uint32_t i = 1; i < ctx.repeat; ++i) {
            if (ctx.repeatDelay) {
                std::this_thread::sleep_for(std::chrono::milliseconds(ctx.repeatDelay));
            }
            // Re-run by parsing again; CLI11 fires the same callbacks that
            // now see their options as already set. This keeps the repeat
            // simple without threading per-subcommand re-entry.
            try { app.parse(argc, argv); }
            catch (const CLI::ParseError& e) { app.exit(e); return EC_USAGE; }
            if (finalExit != EC_OK && worstExit == EC_OK) worstExit = finalExit;
        }
        return worstExit;
    }
    return finalExit;
}
