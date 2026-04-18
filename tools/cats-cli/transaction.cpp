#include "transaction.h"

#include <libsed/core/uid.h>
#include <libsed/codec/token_list.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <thread>

namespace catscli {

using namespace libsed;
using namespace libsed::eval;

// ── Name → UID mapping ───────────────────────────────────────────────────────

static std::string hexStr(uint64_t v) {
    std::ostringstream o;
    o << "0x" << std::hex << std::uppercase;
    o.width(16); o.fill('0');
    o << v;
    return o.str();
}

static bool parseHexU64(const std::string& s, uint64_t& out) {
    // Accepts "0x..." or bare hex; rejects non-hex.
    const char* p = s.c_str();
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) p += 2;
    if (*p == '\0') return false;
    char* end = nullptr;
    auto v = std::strtoull(p, &end, 16);
    if (end == p || *end != '\0') return false;
    out = v;
    return true;
}

static bool resolveObject(const std::string& name, uint64_t& out) {
    static const std::map<std::string, uint64_t> table = {
        { "LockingRange0",  uid::LOCKING_GLOBALRANGE },
        { "GlobalRange",    uid::LOCKING_GLOBALRANGE },
        { "C_PIN_SID",      uid::CPIN_SID },
        { "C_PIN_MSID",     uid::CPIN_MSID },
        { "C_PIN_Admin1",   uid::CPIN_ADMIN1 },
        { "C_PIN_User1",    uid::CPIN_USER1 },
        { "MBRControl",     uid::MBRCTRL_SET },
        { "MBR",            uid::TABLE_MBR },
        { "DataStore",      uid::TABLE_DATASTORE },
    };
    auto it = table.find(name);
    if (it != table.end()) { out = it->second; return true; }

    // "LockingRange<N>" for N >= 1
    if (name.rfind("LockingRange", 0) == 0) {
        try {
            uint32_t n = static_cast<uint32_t>(std::stoul(name.substr(12)));
            if (n == 0) { out = uid::LOCKING_GLOBALRANGE; return true; }
            out = uid::makeLockingRangeUid(n).toUint64();
            return true;
        } catch (...) {}
    }

    // raw UID hex literal
    if (parseHexU64(name, out)) return true;

    return false;
}

static bool resolveSP(const std::string& name, uint64_t& out) {
    if (name == "Admin")      { out = uid::SP_ADMIN;      return true; }
    if (name == "Locking")    { out = uid::SP_LOCKING;    return true; }
    if (name == "Enterprise") { out = uid::SP_ENTERPRISE; return true; }
    return false;
}

static bool resolveAuthority(const std::string& name, uint64_t& out) {
    static const std::map<std::string, uint64_t> table = {
        { "SID",         uid::AUTH_SID },
        { "Admin1",      uid::AUTH_ADMIN1 },
        { "Admin2",      uid::AUTH_ADMIN2 },
        { "Admin3",      uid::AUTH_ADMIN3 },
        { "Admin4",      uid::AUTH_ADMIN4 },
        { "User1",       uid::AUTH_USER1 },
        { "User2",       uid::AUTH_USER2 },
        { "User3",       uid::AUTH_USER3 },
        { "User4",       uid::AUTH_USER4 },
        { "User5",       uid::AUTH_USER5 },
        { "BandMaster0", uid::AUTH_BANDMASTER0 },
        { "EraseMaster", uid::AUTH_ERASEMASTER },
        { "PSID",        uid::AUTH_PSID },
        { "Anybody",     uid::AUTH_ANYBODY },
    };
    auto it = table.find(name);
    if (it != table.end()) { out = it->second; return true; }
    return false;
}

// ── Column name → ID mapping (set values) ────────────────────────────────────

struct ColumnSpec { uint32_t id; bool isBytes; };

static bool resolveColumn(const std::string& name, ColumnSpec& out) {
    static const std::map<std::string, ColumnSpec> table = {
        { "RangeStart",        { uid::col::RANGE_START,    false } },
        { "RangeLength",       { uid::col::RANGE_LENGTH,   false } },
        { "ReadLockEnabled",   { uid::col::READ_LOCK_EN,   false } },
        { "WriteLockEnabled",  { uid::col::WRITE_LOCK_EN,  false } },
        { "ReadLocked",        { uid::col::READ_LOCKED,    false } },
        { "WriteLocked",       { uid::col::WRITE_LOCKED,   false } },
        { "LockOnReset",       { uid::col::LOCK_ON_RESET,  false } },
        { "PIN",               { uid::col::PIN,            true  } },
        { "Enabled",           { uid::col::AUTH_ENABLED,   false } },
        { "Enable",            { uid::col::MBR_ENABLE,     false } },
        { "Done",              { uid::col::MBR_DONE,       false } },
    };
    auto it = table.find(name);
    if (it != table.end()) { out = it->second; return true; }
    return false;
}

// ── Password resolver for script-level credentials ───────────────────────────

static std::string defaultGetenv(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

static bool resolveCredential(const json& obj, Bytes& out, std::string& err,
                               std::string (*getenvFn)(const char*)) {
    int count = 0;
    if (obj.contains("pw"))      ++count;
    if (obj.contains("pw_env"))  ++count;
    if (obj.contains("pw_file")) ++count;
    if (count > 1) { err = "use only one of pw / pw_env / pw_file"; return false; }
    if (count == 0) { out.clear(); return true; } // anonymous or authenticate-without-cred

    if (!getenvFn) getenvFn = defaultGetenv;

    std::string raw;
    if (obj.contains("pw")) {
        raw = obj["pw"].get<std::string>();
    } else if (obj.contains("pw_env")) {
        auto name = obj["pw_env"].get<std::string>();
        raw = getenvFn(name.c_str());
        if (raw.empty()) { err = "env var " + name + " empty/unset"; return false; }
    } else { // pw_file
        auto path = obj["pw_file"].get<std::string>();
        std::ifstream f(path);
        if (!f) { err = "cannot read pw_file " + path; return false; }
        std::getline(f, raw);
        if (raw.empty()) { err = "pw_file empty: " + path; return false; }
    }
    // Hash host-side per SedDrive::login(string) convention: SHA-256.
    // We do NOT hash here; leaving raw so the caller can pass to login(string)
    // which handles SHA-256. For the script's initial session we call the
    // string overload. For authenticate op we re-hash.
    out = Bytes(raw.begin(), raw.end());
    return true;
}

// ── Parser ───────────────────────────────────────────────────────────────────

std::string parseTxScript(const std::string& jsonText, TxScript& out,
                           std::string (*getenvFn)(const char*)) {
    json j;
    try {
        j = json::parse(jsonText);
    } catch (const std::exception& e) {
        return std::string("JSON parse error: ") + e.what();
    }

    if (!j.contains("version") || !j["version"].is_number_integer() ||
        j["version"].get<int>() != 1) {
        return "missing or unsupported 'version' (must be 1)";
    }
    out.version = 1;

    if (!j.contains("session") || !j["session"].is_object())
        return "missing 'session' object";
    const auto& sess = j["session"];

    if (!sess.contains("sp") || !sess["sp"].is_string())
        return "session.sp missing";
    out.spLabel = sess["sp"].get<std::string>();
    if (!resolveSP(out.spLabel, out.spUid))
        return "unknown session.sp: " + out.spLabel;

    if (!sess.contains("authority") || !sess["authority"].is_string())
        return "session.authority missing";
    out.authLabel = sess["authority"].get<std::string>();
    if (!resolveAuthority(out.authLabel, out.authUid))
        return "unknown session.authority: " + out.authLabel;
    out.anonymous = (out.authLabel == "Anybody");

    out.write = sess.value("write", true);
    if (out.anonymous) out.write = false;

    if (out.anonymous) {
        if (sess.contains("pw") || sess.contains("pw_env") || sess.contains("pw_file"))
            return "session.authority=Anybody must not carry a password";
    } else {
        std::string err;
        if (!resolveCredential(sess, out.credential, err, getenvFn))
            return "session: " + err;
        if (out.credential.empty())
            return "session: authority '" + out.authLabel + "' requires pw / pw_env / pw_file";
    }

    if (!j.contains("ops") || !j["ops"].is_array())
        return "missing 'ops' array";

    int step = 0;
    for (const auto& item : j["ops"]) {
        ++step;
        if (!item.is_object() || !item.contains("op"))
            return "op #" + std::to_string(step) + " missing 'op'";

        TxOp op;
        op.op = item["op"].get<std::string>();

        if (op.op == "start_transaction" || op.op == "commit" || op.op == "rollback") {
            // no extra fields required
        } else if (op.op == "get") {
            if (!item.contains("object"))
                return "op #" + std::to_string(step) + " (get) missing 'object'";
            op.objectLabel = item["object"].get<std::string>();
            if (!resolveObject(op.objectLabel, op.objectUid))
                return "op #" + std::to_string(step) + " (get) unknown object: " + op.objectLabel;
            if (item.contains("columns")) {
                auto& c = item["columns"];
                if (!c.is_array() || c.size() != 2)
                    return "op #" + std::to_string(step) + " (get) columns must be [start,end]";
                op.colStart = c[0].get<uint32_t>();
                op.colEnd   = c[1].get<uint32_t>();
            }
        } else if (op.op == "set") {
            if (!item.contains("object"))
                return "op #" + std::to_string(step) + " (set) missing 'object'";
            op.objectLabel = item["object"].get<std::string>();
            if (!resolveObject(op.objectLabel, op.objectUid))
                return "op #" + std::to_string(step) + " (set) unknown object: " + op.objectLabel;
            if (!item.contains("values") || !item["values"].is_object())
                return "op #" + std::to_string(step) + " (set) missing 'values' object";
            for (auto it = item["values"].begin(); it != item["values"].end(); ++it) {
                ColumnSpec cs;
                if (!resolveColumn(it.key(), cs))
                    return "op #" + std::to_string(step) + " (set) unknown column: " + it.key();
                TxOp::Value v;
                v.col = cs.id;
                v.isBytes = cs.isBytes;
                if (cs.isBytes) {
                    if (!it->is_string())
                        return "op #" + std::to_string(step) + " (set) column " + it.key() +
                               " requires hex string";
                    std::string hex = it->get<std::string>();
                    // parse "0x..." hex
                    if (hex.size() >= 2 && (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')))
                        hex = hex.substr(2);
                    if (hex.size() % 2 != 0)
                        return "op #" + std::to_string(step) + " (set) hex column " + it.key() +
                               " has odd length";
                    for (size_t i = 0; i < hex.size(); i += 2) {
                        v.byteVal.push_back(
                            static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
                    }
                } else {
                    if (it->is_boolean())      v.uintVal = it->get<bool>() ? 1 : 0;
                    else if (it->is_number())  v.uintVal = it->get<uint64_t>();
                    else return "op #" + std::to_string(step) + " (set) column " + it.key() +
                                " requires number or boolean";
                }
                op.values.push_back(v);
            }
        } else if (op.op == "genkey" || op.op == "erase") {
            if (!item.contains("object"))
                return "op #" + std::to_string(step) + " (" + op.op + ") missing 'object'";
            op.objectLabel = item["object"].get<std::string>();
            if (!resolveObject(op.objectLabel, op.objectUid))
                return "op #" + std::to_string(step) + " (" + op.op +
                       ") unknown object: " + op.objectLabel;
        } else if (op.op == "authenticate") {
            if (!item.contains("authority"))
                return "op #" + std::to_string(step) + " (authenticate) missing 'authority'";
            op.authLabel = item["authority"].get<std::string>();
            if (!resolveAuthority(op.authLabel, op.authUid))
                return "op #" + std::to_string(step) +
                       " (authenticate) unknown authority: " + op.authLabel;
            std::string err;
            if (!resolveCredential(item, op.credential, err, getenvFn))
                return "op #" + std::to_string(step) + " (authenticate): " + err;
        } else if (op.op == "sleep") {
            if (!item.contains("ms") || !item["ms"].is_number_integer())
                return "op #" + std::to_string(step) + " (sleep) missing integer 'ms'";
            op.sleepMs = item["ms"].get<uint32_t>();
        } else {
            return "op #" + std::to_string(step) + " unknown op: " + op.op;
        }

        out.ops.push_back(std::move(op));
    }

    out.onError = j.value("on_error", std::string("rollback"));
    if (out.onError != "rollback" && out.onError != "continue" && out.onError != "abort")
        return "on_error must be one of: rollback, continue, abort";

    return {};
}

// ── Executor ────────────────────────────────────────────────────────────────

static bool stepOk(const TxStepResult& s) {
    return s.transportOk && s.tcgStatus == 0;
}

static TxStepResult doStartTxn(EvalApi& api, Session& s) {
    TxStepResult sr; sr.op = "start_transaction";
    auto t0 = std::chrono::steady_clock::now();
    RawResult raw;
    api.startTransaction(s, raw);
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    sr.transportOk = (raw.transportError == ErrorCode::Success);
    sr.tcgStatus = static_cast<int>(raw.methodResult.status());
    sr.tcgStatusName = raw.methodResult.statusMessage();
    sr.rawSend = raw.rawSendPayload;
    sr.rawRecv = raw.rawRecvPayload;
    return sr;
}

static TxStepResult doEndTxn(EvalApi& api, Session& s, bool commit) {
    TxStepResult sr; sr.op = commit ? "commit" : "rollback";
    auto t0 = std::chrono::steady_clock::now();
    RawResult raw;
    api.endTransaction(s, commit, raw);
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    sr.transportOk = (raw.transportError == ErrorCode::Success);
    sr.tcgStatus = static_cast<int>(raw.methodResult.status());
    sr.tcgStatusName = raw.methodResult.statusMessage();
    sr.rawSend = raw.rawSendPayload;
    sr.rawRecv = raw.rawRecvPayload;
    return sr;
}

static TxStepResult doGet(EvalApi& api, Session& s, const TxOp& op) {
    TxStepResult sr; sr.op = "get"; sr.objectLabel = op.objectLabel;
    auto t0 = std::chrono::steady_clock::now();
    TableResult tr;
    Result r;
    if (op.colEnd >= op.colStart && (op.colStart != 0 || op.colEnd != 0)) {
        r = api.tableGet(s, op.objectUid, op.colStart, op.colEnd, tr);
    } else {
        r = api.tableGetAll(s, op.objectUid, tr);
    }
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    sr.transportOk = (tr.raw.transportError == ErrorCode::Success);
    sr.tcgStatus = static_cast<int>(tr.raw.methodResult.status());
    sr.tcgStatusName = tr.raw.methodResult.statusMessage();
    sr.rawSend = tr.raw.rawSendPayload;
    sr.rawRecv = tr.raw.rawRecvPayload;
    (void)r;
    return sr;
}

static TxStepResult doSet(EvalApi& api, Session& s, const TxOp& op) {
    TxStepResult sr; sr.op = "set"; sr.objectLabel = op.objectLabel;
    TokenList values;
    for (const auto& v : op.values) {
        if (v.isBytes) values.addBytes(v.col, v.byteVal);
        else           values.addUint(v.col, v.uintVal);
    }
    std::vector<std::pair<uint32_t, Token>> cols;
    // Use tableSet path — accepts vector<pair<uint32_t, Token>>.
    for (const auto& v : op.values) {
        Token t;
        if (v.isBytes) { t.isByteSequence = true; t.byteData = v.byteVal; }
        else           { t.uintVal = v.uintVal; }
        cols.emplace_back(v.col, t);
    }
    auto t0 = std::chrono::steady_clock::now();
    RawResult raw;
    api.tableSet(s, op.objectUid, cols, raw);
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    sr.transportOk = (raw.transportError == ErrorCode::Success);
    sr.tcgStatus = static_cast<int>(raw.methodResult.status());
    sr.tcgStatusName = raw.methodResult.statusMessage();
    sr.rawSend = raw.rawSendPayload;
    sr.rawRecv = raw.rawRecvPayload;
    return sr;
}

static TxStepResult doGenKey(EvalApi& api, Session& s, const TxOp& op) {
    TxStepResult sr; sr.op = "genkey"; sr.objectLabel = op.objectLabel;
    auto t0 = std::chrono::steady_clock::now();
    Bytes tokens = MethodCall::buildGenKey(Uid(op.objectUid));
    RawResult raw;
    api.sendRawMethod(s, tokens, raw);
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    sr.transportOk = (raw.transportError == ErrorCode::Success);
    sr.tcgStatus = static_cast<int>(raw.methodResult.status());
    sr.tcgStatusName = raw.methodResult.statusMessage();
    sr.rawSend = raw.rawSendPayload;
    sr.rawRecv = raw.rawRecvPayload;
    return sr;
}

static TxStepResult doErase(EvalApi& api, Session& s, const TxOp& op) {
    TxStepResult sr; sr.op = "erase"; sr.objectLabel = op.objectLabel;
    auto t0 = std::chrono::steady_clock::now();
    RawResult raw;
    api.erase(s, op.objectUid, raw);
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    sr.transportOk = (raw.transportError == ErrorCode::Success);
    sr.tcgStatus = static_cast<int>(raw.methodResult.status());
    sr.tcgStatusName = raw.methodResult.statusMessage();
    sr.rawSend = raw.rawSendPayload;
    sr.rawRecv = raw.rawRecvPayload;
    return sr;
}

static TxStepResult doAuthenticate(EvalApi& api, Session& s, const TxOp& op) {
    // In-session re-authentication: build Authenticate(ThisSP) with the new
    // authority UID and credential, send as a raw method on the active session.
    // Hash the credential SHA-256 the same way SedDrive::login(string) does.
    TxStepResult sr; sr.op = "authenticate"; sr.objectLabel = op.authLabel;
    Bytes credHashed = op.credential;
    if (!credHashed.empty()) {
        std::string raw(credHashed.begin(), credHashed.end());
        credHashed = EvalApi::hashPassword(raw);
    }
    Bytes tokens = MethodCall::buildAuthenticate(
        Uid(op.authUid), credHashed,
        method::authenticateUidFor(s.sscType()));

    auto t0 = std::chrono::steady_clock::now();
    RawResult rr;
    api.sendRawMethod(s, tokens, rr);
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    sr.transportOk = (rr.transportError == ErrorCode::Success);
    sr.tcgStatus = static_cast<int>(rr.methodResult.status());
    sr.tcgStatusName = rr.methodResult.statusMessage();
    sr.rawSend = rr.rawSendPayload;
    sr.rawRecv = rr.rawRecvPayload;
    return sr;
}

static TxStepResult doSleep(const TxOp& op) {
    TxStepResult sr; sr.op = "sleep";
    auto t0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(op.sleepMs));
    auto t1 = std::chrono::steady_clock::now();
    sr.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    return sr;
}

Result runTxScript(const TxScript& script, EvalApi& api,
                    std::shared_ptr<ITransport> transport, uint16_t comId,
                    TxResult& result) {
    Session session(transport, comId);
    StartSessionResult ssr;
    Result r;
    if (script.anonymous) {
        r = api.startSession(session, script.spUid, script.write, ssr);
    } else {
        // For Enterprise-capable SPs, the wire is EGET/ESET/EAUTHENTICATE.
        if (script.spUid == uid::SP_ENTERPRISE) session.setSscType(SscType::Enterprise);
        // Match SedDrive::login(string) semantics: SHA-256 the password.
        Bytes credHashed;
        if (!script.credential.empty()) {
            std::string pw(script.credential.begin(), script.credential.end());
            credHashed = EvalApi::hashPassword(pw);
        }
        r = api.startSessionWithAuth(session, script.spUid, script.write,
                                      script.authUid, credHashed, ssr);
    }
    if (r.failed()) {
        result.ok = false;
        result.terminatedBy = "abort";
        TxStepResult srStart;
        srStart.step = 0;
        srStart.op = "startSession";
        srStart.transportOk = false;
        srStart.errorNote = r.message();
        result.steps.push_back(srStart);
        return r;
    }

    bool inTxn = false;
    bool errored = false;

    int i = 0;
    for (const auto& op : script.ops) {
        ++i;
        TxStepResult sr;
        if (op.op == "start_transaction") { sr = doStartTxn(api, session); inTxn = true; }
        else if (op.op == "commit")       { sr = doEndTxn(api, session, true);  inTxn = false; }
        else if (op.op == "rollback")     { sr = doEndTxn(api, session, false); inTxn = false; }
        else if (op.op == "get")          sr = doGet(api, session, op);
        else if (op.op == "set")          sr = doSet(api, session, op);
        else if (op.op == "genkey")       sr = doGenKey(api, session, op);
        else if (op.op == "erase")        sr = doErase(api, session, op);
        else if (op.op == "authenticate") sr = doAuthenticate(api, session, op);
        else if (op.op == "sleep")        sr = doSleep(op);

        sr.step = i;
        result.steps.push_back(sr);

        if (!stepOk(sr) && op.op != "sleep") {
            errored = true;
            if (script.onError == "abort") {
                result.ok = false;
                result.terminatedBy = "abort";
                api.closeSession(session);
                return Result(ErrorCode::Success); // abort is a valid termination
            }
            if (script.onError == "continue") {
                continue; // ignore, proceed
            }
            // "rollback": if inside txn, emit one synthetic rollback op
            if (inTxn) {
                TxStepResult rbSr = doEndTxn(api, session, false);
                rbSr.step = ++i;
                rbSr.op = "rollback (on_error)";
                result.steps.push_back(rbSr);
                inTxn = false;
            }
            result.ok = false;
            result.terminatedBy = "rollback";
            api.closeSession(session);
            return Result(ErrorCode::Success);
        }
    }

    // Script ran clean to the end. terminatedBy follows the last op.
    if (!result.steps.empty()) {
        const auto& last = result.steps.back().op;
        if (last == "commit" || last == "rollback") {
            result.terminatedBy = last;
        } else {
            result.terminatedBy = errored ? "continue" : "commit";
        }
    }
    result.ok = !errored;
    api.closeSession(session);
    return Result(ErrorCode::Success);
}

} // namespace catscli
