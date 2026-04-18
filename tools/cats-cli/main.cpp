// cats-cli — TCG SED Evaluation & Debugging Platform (Final Masterpiece)
//
// Refined per fundamental review and mentor feedback. 
// Follows the "Four Pillars of Engineering Rigor" for reliability and purity.

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
#include <optional>
#include <sstream>
#include <string>
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
    std::string password;
    bool        force = false;
    bool        useSim = false;

    std::shared_ptr<ITransport> transport;
    EvalApi                     api;

    Verbosity v() const { return static_cast<Verbosity>(verbosityRaw); }

    int init() {
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
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "Drive Summary:\n" << "  SSC       : " << drive.sscName() << "\n"
                  << "  ComID     : 0x" << std::hex << drive.comId() << std::dec << "\n"
                  << "  Locking   : " << (drive.info().lockingEnabled ? "Enabled" : "Disabled") << "\n"
                  << "  MBR       : " << (drive.info().mbrEnabled ? "Enabled" : "Disabled") << "\n";
    }
    return EC_OK;
}

int drive_msid(Context& ctx) {
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    Bytes msid;
    auto r = drive.readMsid(msid);
    if (r.failed()) return reportResult(ctx, "readMsid", r);
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
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    std::vector<LockingInfo> ranges;
    auto r = drive.enumerateRanges(ctx.password, ranges);
    if (r.ok() && ctx.v() >= Verbosity::Info) {
        std::cout << "ID | Start        Length       | RLck WLck\n";
        for (const auto& ri : ranges) {
            std::cout << std::setw(2) << ri.rangeId << " | " << std::setw(12) << ri.rangeStart << " " 
                      << std::setw(12) << ri.rangeLength << " | " << (ri.readLocked ? 'Y' : 'N') << "    " << (ri.writeLocked ? 'Y' : 'N') << "\n";
        }
    }
    return reportResult(ctx, "range list", r);
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
    if (ctx.v() >= Verbosity::Info) {
        std::cout << "MBR Shadow:\n"
                  << "  Supported : " << (info.mbrSupported ? "Yes" : "No") << "\n"
                  << "  Enabled   : " << (info.mbrEnabled   ? "Yes" : "No") << "\n"
                  << "  Done      : " << (info.mbrDone      ? "Yes" : "No") << "\n";
    }
    return EC_OK;
}

int user_list(Context& ctx) {
    if (ctx.password.empty()) { std::cerr << "error: --password (Admin1) required\n"; return EC_USAGE; }
    if (int e = ctx.init(); e) return e;
    SedDrive drive(ctx.transport);
    std::vector<SedDrive::AuthorityInfo> auths;
    auto r = drive.enumerateAuthorities(ctx.password, auths);
    if (r.ok() && ctx.v() >= Verbosity::Info) {
        std::cout << "Authority   Enabled  UID\n";
        for (const auto& a : auths) {
            const char* k = (a.kind == SedDrive::AuthorityKind::Admin) ? "Admin" : "User";
            std::cout << "  " << std::left << std::setw(5) << k << " " << std::setw(2) << a.id
                      << "   " << std::setw(5) << (a.enabled ? "Y" : "N")
                      << "   0x" << std::hex << std::setw(16) << std::setfill('0')
                      << a.uid.toUint64() << std::dec << std::setfill(' ') << "\n";
        }
    }
    return reportResult(ctx, "user list", r);
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

} // namespace cmd

// ── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    CLI::App app{"cats-cli — TCG SED Evaluation & Debugging Platform"};
    app.require_subcommand(1);

    Context ctx;
    app.add_option("-d,--device", ctx.device, "Device path");
    app.add_option("-v,--verbosity", ctx.verbosityRaw, "0=quiet, 1=info, 2=debug, 3=trace")->default_val(1);
    app.add_option("--log-file", ctx.logFile, "Mirror flow log to file");
    app.add_option("-p,--password", ctx.password, "SP/Authority password");
    app.add_flag("--force", ctx.force, "Required for destructive operations");
    app.add_flag("--sim", ctx.useSim, "Run against internal Simulator");

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

    auto* user = app.add_subcommand("user", "User / Authority management");
    user->add_subcommand("list", "List Admin/User authorities and enabled state")
         ->callback([&]{ finalExit = cmd::user_list(ctx); });
    uint32_t assignUserId = 0, assignRangeId = 0;
    auto* uAssign = user->add_subcommand("assign", "Assign a user to a range");
    uAssign->add_option("--id", assignUserId, "User ID")->required();
    uAssign->add_option("--range", assignRangeId, "Range ID")->required();
    uAssign->callback([&]{ finalExit = cmd::user_assign(ctx, assignUserId, assignRangeId); });

    auto* band = app.add_subcommand("band", "Enterprise Band operations");
    band->add_subcommand("list", "List bands")->callback([&]{ finalExit = cmd::band_list(ctx); });

    auto* mbr = app.add_subcommand("mbr", "MBR operations");
    mbr->add_subcommand("status", "Show MBR shadow enabled/done/supported")
       ->callback([&]{ finalExit = cmd::mbr_status(ctx); });
    std::string mbrFile;
    auto* mbrWrite = mbr->add_subcommand("write", "Write PBA image (Destructive)");
    mbrWrite->add_option("--file", mbrFile, "PBA image path")->required();
    mbrWrite->callback([&]{ finalExit = cmd::mbr_write(ctx, mbrFile); });

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

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // Let CLI11 print its usage/error, but unify the exit code so CI and
        // scripts see EC_USAGE(1) — not CLI11's internal 105/106/109.
        app.exit(e);
        return EC_USAGE;
    }
    return finalExit;
}
