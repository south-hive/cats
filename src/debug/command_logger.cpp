/// @file command_logger.cpp
/// @brief Compact one-line-per-command logger for TC developers.
///
/// Format:
///   #seq DIR Method              Status    P=xx C=xxxx TSN=n HSN=n   elapsed
///   #001 >> SMUID.Properties              P=01 C=0C01 TSN=0 HSN=0       2ms
///   #002 << SMUID.Properties  St=0(OK)    P=01 C=0C01 TSN=0 HSN=0       5ms
///       TPerProps: MaxComPkt=65536 MaxPkt=65516 MaxIndTok=65480
///
/// Key params on indented continuation line. Raw hex only on error.

#include <libsed/debug/command_logger.h>
#include <libsed/packet/com_packet.h>
#include <libsed/codec/token_decoder.h>
#include <libsed/core/uid.h>
#include <libsed/core/endian.h>
#include <libsed/method/method_uids.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <unordered_map>

#ifdef __linux__
#include <unistd.h>
#include <climits>
#endif

namespace libsed {
namespace debug {

// ═══════════════════════════════════════════════════
//  UID → name tables
// ═══════════════════════════════════════════════════

static const std::unordered_map<uint64_t, const char*>& uidNameTable() {
    static const std::unordered_map<uint64_t, const char*> table = {
        {uid::SMUID,                    "SMUID"},
        {uid::THIS_SP,                  "ThisSP"},
        {uid::SP_ADMIN,                 "AdminSP"},
        {uid::SP_LOCKING,               "LockingSP"},
        {uid::SP_ENTERPRISE,            "EnterpriseSP"},
        {uid::AUTH_ANYBODY,             "Anybody"},
        {uid::AUTH_ADMINS,              "Admins"},
        {uid::AUTH_MAKERS,              "Makers"},
        {uid::AUTH_SID,                 "SID"},
        {uid::AUTH_PSID,                "PSID"},
        {uid::AUTH_MSID,                "MSID"},
        {uid::AUTH_ADMIN1,              "Admin1"},
        {uid::AUTH_ADMIN2,              "Admin2"},
        {uid::AUTH_ADMIN3,              "Admin3"},
        {uid::AUTH_ADMIN4,              "Admin4"},
        {uid::AUTH_USER1,               "User1"},
        {uid::AUTH_USER2,               "User2"},
        {uid::AUTH_USER3,               "User3"},
        {uid::AUTH_USER4,               "User4"},
        {uid::AUTH_USER5,               "User5"},
        {uid::AUTH_USER6,               "User6"},
        {uid::AUTH_USER7,               "User7"},
        {uid::AUTH_USER8,               "User8"},
        {uid::AUTH_USER9,               "User9"},
        {uid::AUTH_ERASEMASTER,         "EraseMaster"},
        {uid::AUTH_BANDMASTER0,         "BandMaster0"},
        {uid::AUTH_BANDMASTER1,         "BandMaster1"},
        {uid::AUTH_BANDMASTER2,         "BandMaster2"},
        {uid::TABLE_SP,                 "Table<SP>"},
        {uid::TABLE_LOCKING,            "Table<Locking>"},
        {uid::TABLE_MBRCTRL,            "Table<MBRControl>"},
        {uid::TABLE_MBR,                "Table<MBR>"},
        {uid::TABLE_ACE,                "Table<ACE>"},
        {uid::TABLE_AUTHORITY,          "Table<Authority>"},
        {uid::TABLE_CPIN,               "Table<C_PIN>"},
        {uid::TABLE_DATASTORE,          "Table<DataStore>"},
        {uid::TABLE_K_AES,              "Table<K_AES>"},
        {uid::BAND_MASTER_TABLE,        "Table<BandMaster>"},
        {uid::LOCKING_GLOBALRANGE,      "GlobalRange"},
        {uid::LOCKING_RANGE1,           "Range1"},
        {uid::LOCKING_RANGE2,           "Range2"},
        {uid::CPIN_SID,                 "C_PIN<SID>"},
        {uid::CPIN_MSID,                "C_PIN<MSID>"},
        {uid::CPIN_ADMIN1,              "C_PIN<Admin1>"},
        {uid::CPIN_USER1,               "C_PIN<User1>"},
        {uid::CPIN_USER2,               "C_PIN<User2>"},
        {uid::CPIN_BANDMASTER0,         "C_PIN<BandMaster0>"},
        {uid::CPIN_ERASEMASTER,         "C_PIN<EraseMaster>"},
        {uid::MBRCTRL_SET,              "MBRControl"},
        {uid::ACE_LOCKING_RANGE_SET_RDLOCKED,         "ACE<Range_RdLock>"},
        {uid::ACE_LOCKING_RANGE_SET_WRLOCKED,         "ACE<Range_WrLock>"},
        {uid::ACE_LOCKING_GLOBALRANGE_SET_RDLOCKED,   "ACE<Global_RdLock>"},
        {uid::ACE_LOCKING_GLOBALRANGE_SET_WRLOCKED,   "ACE<Global_WrLock>"},
        {uid::K_AES_GLOBALRANGE,        "K_AES<GlobalRange>"},
        {uid::DATASTORE_TABLE_0,        "DataStore0"},
    };
    return table;
}

static const std::unordered_map<uint64_t, const char*>& methodNameTable() {
    static const std::unordered_map<uint64_t, const char*> table = {
        {method::SM_PROPERTIES,              "Properties"},
        {method::SM_START_SESSION,           "StartSession"},
        {method::SM_SYNC_SESSION,            "SyncSession"},
        {method::SM_START_TRUSTED_SESSION,   "StartTrustedSession"},
        {method::SM_SYNC_TRUSTED_SESSION,    "SyncTrustedSession"},
        {method::SM_CLOSE_SESSION,           "CloseSession"},
        {method::GET,                        "Get"},
        {method::SET,                        "Set"},
        {method::NEXT,                       "Next"},
        {method::GETACL,                     "GetACL"},
        {method::GENKEY,                     "GenKey"},
        {method::REVERTSP,                   "RevertSP"},
        {method::AUTHENTICATE,               "Authenticate"},
        {method::REVERT,                     "Revert"},
        {method::ACTIVATE,                   "Activate"},
        {method::ERASE,                      "Erase"},
        {method::RANDOM,                     "Random"},
        {method::ASSIGN,                     "Assign"},
        {method::REMOVE,                     "Remove"},
        {method::CREATE_ROW,                 "CreateRow"},
        {method::DELETE_ROW,                 "DeleteRow"},
        {method::GET_CLOCK,                  "GetClock"},
    };
    return table;
}

// ═══════════════════════════════════════════════════
//  UID helpers
// ═══════════════════════════════════════════════════

const char* CommandLogger::resolveUid(uint64_t uid) {
    auto& table = uidNameTable();
    auto it = table.find(uid);
    if (it != table.end()) return it->second;
    auto& mtable = methodNameTable();
    auto mit = mtable.find(uid);
    if (mit != mtable.end()) return mit->second;
    return nullptr;
}

const char* CommandLogger::resolveMethodUid(uint64_t uid) {
    auto& table = methodNameTable();
    auto it = table.find(uid);
    if (it != table.end()) return it->second;
    return nullptr;
}

uint64_t CommandLogger::bytesToUid(const uint8_t* data, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len && i < 8; i++)
        val = (val << 8) | data[i];
    return val;
}

const char* CommandLogger::methodStatusName(uint64_t status) {
    switch (status) {
        case 0x00: return "OK";
        case 0x01: return "NotAuthorized";
        case 0x02: return "Obsolete";
        case 0x03: return "SpBusy";
        case 0x04: return "SpFailed";
        case 0x05: return "SpDisabled";
        case 0x06: return "SpFrozen";
        case 0x07: return "NoSessions";
        case 0x08: return "UniquenessConflict";
        case 0x09: return "InsufficientSpace";
        case 0x0A: return "InsufficientRows";
        case 0x0C: return "InvalidParam";
        case 0x0F: return "TPerMalfunction";
        case 0x10: return "TxnFailure";
        case 0x11: return "ResponseOverflow";
        case 0x12: return "AuthLockedOut";
        case 0x3F: return "Fail";
        default:   return nullptr;
    }
}

std::string CommandLogger::formatAtomValue(const Token& tok) {
    if (tok.isByteSequence) {
        if (tok.byteData.size() == 8) {
            uint64_t uid = bytesToUid(tok.byteData.data(), 8);
            const char* name = resolveUid(uid);
            if (name) return name;
        }
        if (tok.byteData.empty()) return "\"\"";
        // Printable ASCII
        bool printable = true;
        for (auto b : tok.byteData)
            if (b < 0x20 || b > 0x7E) { printable = false; break; }
        if (printable)
            return "\"" + std::string(tok.byteData.begin(), tok.byteData.end()) + "\"";
        // Short hex
        if (tok.byteData.size() <= 8) {
            std::ostringstream h;
            h << std::hex << std::setfill('0');
            for (auto b : tok.byteData) h << std::setw(2) << (int)b;
            return h.str();
        }
        return "(" + std::to_string(tok.byteData.size()) + "B)";
    }
    return std::to_string(tok.isSigned ? tok.intVal : (int64_t)tok.uintVal);
}

// ═══════════════════════════════════════════════════
//  File name generation
// ═══════════════════════════════════════════════════

std::string CommandLogger::getExecutableName() {
#ifdef __linux__
    char buf[PATH_MAX] = {};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        std::string path(buf);
        auto pos = path.rfind('/');
        if (pos != std::string::npos) path = path.substr(pos + 1);
        auto dot = path.rfind('.');
        if (dot != std::string::npos && dot > 0) path = path.substr(0, dot);
        if (!path.empty()) return path;
    }
#endif
    return "libsed";
}

std::string CommandLogger::getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d_%02d%02d%02d",
                  tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                  tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    return buf;
}

// ═══════════════════════════════════════════════════
//  Constructor / Destructor
// ═══════════════════════════════════════════════════

CommandLogger::CommandLogger(const std::string& logDir) {
    std::string dir = logDir;
    if (dir.empty()) dir = ".";
    if (dir.back() != '/') dir += '/';
    filePath_ = dir + getExecutableName() + "_" + getTimestamp() + ".sed.log";
    file_.open(filePath_, std::ios::out | std::ios::trunc);
}

CommandLogger::CommandLogger(const std::string& filePath, bool /*explicit_path*/) {
    filePath_ = filePath;
    file_.open(filePath_, std::ios::out | std::ios::trunc);
}

CommandLogger::CommandLogger(const LoggerConfig& config)
    : stream_(config.toStream ? config.stream : nullptr),
      alwaysHex_(config.alwaysHex) {
    if (config.toFile) {
        std::string dir = config.logDir;
        if (dir.empty()) dir = ".";
        if (dir.back() != '/') dir += '/';
        filePath_ = dir + getExecutableName() + "_" + getTimestamp() + ".sed.log";
        file_.open(filePath_, std::ios::out | std::ios::trunc);
    }
}

std::shared_ptr<CommandLogger> CommandLogger::createDumper(std::ostream& os) {
    LoggerConfig config;
    config.toFile = false;
    config.toStream = true;
    config.stream = &os;
    config.alwaysHex = true;
    return std::make_shared<CommandLogger>(config);
}

CommandLogger::~CommandLogger() {
    if (file_.is_open()) { file_.flush(); file_.close(); }
}

std::string CommandLogger::filePath() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return filePath_;
}

bool CommandLogger::isOpen() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return file_.is_open();
}

void CommandLogger::close() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (file_.is_open()) { file_.flush(); file_.close(); }
}

// ═══════════════════════════════════════════════════
//  Public interface
// ═══════════════════════════════════════════════════

void CommandLogger::logIfSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        lastSendTime_ = std::chrono::steady_clock::now();
    }
    logCommand(">>", protocolId, comId, payload.data(), payload.size());
}

void CommandLogger::logIfRecv(uint8_t protocolId, uint16_t comId,
                              const uint8_t* data, size_t bytesReceived) {
    logCommand("<<", protocolId, comId, data, bytesReceived);
}

// ═══════════════════════════════════════════════════
//  Token payload offset constant
// ═══════════════════════════════════════════════════

static constexpr size_t TOKEN_OFFSET =
    ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE +
    SubPacketHeader::HEADER_SIZE;  // 56

// ═══════════════════════════════════════════════════
//  Extract method name from token stream
// ═══════════════════════════════════════════════════

std::string CommandLogger::formatMethod(const uint8_t* data, size_t len) {
    if (len < TOKEN_OFFSET + 1) return "";

    SubPacketHeader sph;
    static constexpr size_t SPH_OFF = ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE;
    auto r = SubPacketHeader::deserialize(data + SPH_OFF, len - SPH_OFF, sph);
    if (r.failed() || sph.length == 0) return "";

    size_t tokenLen = sph.length;
    if (TOKEN_OFFSET + tokenLen > len) tokenLen = len - TOKEN_OFFSET;

    TokenDecoder dec;
    r = dec.decode(data + TOKEN_OFFSET, tokenLen);
    if (r.failed() || dec.count() == 0) return "";

    // EndOfSession
    if (dec[0].type == TokenType::EndOfSession)
        return "EndOfSession";

    // CALL invoking method
    if (dec[0].type == TokenType::Call && dec.count() >= 3) {
        std::string s = formatAtomValue(dec[1]);
        s += ".";
        s += formatAtomValue(dec[2]);
        return s;
    }

    return "";
}

// ═══════════════════════════════════════════════════
//  Extract status from recv token stream
// ═══════════════════════════════════════════════════

std::string CommandLogger::formatStatus(const uint8_t* data, size_t len) {
    if (len < TOKEN_OFFSET + 1) return "";

    SubPacketHeader sph;
    static constexpr size_t SPH_OFF = ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE;
    auto r = SubPacketHeader::deserialize(data + SPH_OFF, len - SPH_OFF, sph);
    if (r.failed() || sph.length == 0) return "";

    size_t tokenLen = sph.length;
    if (TOKEN_OFFSET + tokenLen > len) tokenLen = len - TOKEN_OFFSET;

    TokenDecoder dec;
    r = dec.decode(data + TOKEN_OFFSET, tokenLen);
    if (r.failed()) return "";

    // Find EOD → next list has status
    for (size_t i = 0; i < dec.count(); i++) {
        if (dec[i].type == TokenType::EndOfData) {
            if (i + 2 < dec.count() &&
                dec[i + 1].type == TokenType::StartList &&
                dec[i + 2].isAtom() && !dec[i + 2].isByteSequence) {
                uint64_t st = dec[i + 2].uintVal;
                const char* name = methodStatusName(st);
                std::string result = "St=" + std::to_string(st);
                if (name) { result += "("; result += name; result += ")"; }
                return result;
            }
            break;
        }
    }
    return "";
}

// ═══════════════════════════════════════════════════
//  Extract key params from send token stream
// ═══════════════════════════════════════════════════

std::string CommandLogger::formatParams(const uint8_t* data, size_t len) {
    if (len < TOKEN_OFFSET + 1) return "";

    SubPacketHeader sph;
    static constexpr size_t SPH_OFF = ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE;
    auto r = SubPacketHeader::deserialize(data + SPH_OFF, len - SPH_OFF, sph);
    if (r.failed() || sph.length == 0) return "";

    size_t tokenLen = sph.length;
    if (TOKEN_OFFSET + tokenLen > len) tokenLen = len - TOKEN_OFFSET;

    TokenDecoder dec;
    r = dec.decode(data + TOKEN_OFFSET, tokenLen);
    if (r.failed() || dec.count() < 4) return "";

    // Skip CALL + invoking + method → find STARTLIST
    if (dec[0].type != TokenType::Call) return "";
    size_t pos = 3;
    if (pos >= dec.count() || dec[pos].type != TokenType::StartList) return "";
    pos++; // skip STARTLIST

    // Determine method
    uint64_t methodUid = 0;
    if (dec[2].isByteSequence && dec[2].byteData.size() == 8)
        methodUid = bytesToUid(dec[2].byteData.data(), 8);

    std::ostringstream os;

    // StartSession: HSN, SP, Write, [Challenge], [Authority]
    if (methodUid == method::SM_START_SESSION) {
        // Positional: HSN, SP, Write
        if (pos < dec.count() && dec[pos].isAtom()) {
            // HSN (skip, already in header)
            pos++;
        }
        if (pos < dec.count() && dec[pos].isAtom()) {
            os << "SP=" << formatAtomValue(dec[pos]);
            pos++;
        }
        if (pos < dec.count() && dec[pos].isAtom()) {
            os << " Write=" << dec[pos].uintVal;
            pos++;
        }
        // Named params
        while (pos < dec.count() && dec[pos].type == TokenType::StartName) {
            pos++; // skip STARTNAME
            if (pos < dec.count() && dec[pos].isAtom()) {
                uint64_t idx = dec[pos].uintVal;
                pos++;
                if (pos < dec.count() && dec[pos].isAtom()) {
                    if (idx == 0)
                        os << " Challenge=" << formatAtomValue(dec[pos]);
                    else if (idx == 3)
                        os << " Auth=" << formatAtomValue(dec[pos]);
                    pos++;
                }
            }
            if (pos < dec.count() && dec[pos].type == TokenType::EndName) pos++;
        }
        return os.str();
    }

    // Get: CellBlock
    if (methodUid == method::GET) {
        // STARTLIST CellBlock ENDLIST
        if (pos < dec.count() && dec[pos].type == TokenType::StartList) {
            pos++; // inner STARTLIST
            uint32_t startCol = 0, endCol = 0;
            bool hasStart = false, hasEnd = false;
            while (pos < dec.count() && dec[pos].type == TokenType::StartName) {
                pos++;
                if (pos + 1 < dec.count() && dec[pos].isAtom() && dec[pos + 1].isAtom()) {
                    uint64_t key = dec[pos].uintVal;
                    uint64_t val = dec[pos + 1].uintVal;
                    if (key == 0) { startCol = (uint32_t)val; hasStart = true; }
                    if (key == 1) { endCol = (uint32_t)val; hasEnd = true; }
                    pos += 2;
                }
                if (pos < dec.count() && dec[pos].type == TokenType::EndName) pos++;
            }
            if (hasStart && hasEnd)
                os << "CellBlock: col[" << startCol << ".." << endCol << "]";
            else if (hasStart)
                os << "CellBlock: col[" << startCol << "+]";
        }
        return os.str();
    }

    // Set: extract column=value pairs from Values list
    if (methodUid == method::SET) {
        // Skip Where (STARTNAME 0 STARTLIST ENDLIST ENDNAME)
        // Find Values (STARTNAME 1 STARTLIST ... ENDLIST ENDNAME)
        while (pos < dec.count()) {
            if (dec[pos].type == TokenType::StartName) {
                pos++;
                if (pos < dec.count() && dec[pos].isAtom() && dec[pos].uintVal == 1) {
                    pos++; // skip "1"
                    if (pos < dec.count() && dec[pos].type == TokenType::StartList) {
                        pos++; // skip STARTLIST
                        bool first = true;
                        while (pos < dec.count() && dec[pos].type == TokenType::StartName) {
                            pos++;
                            if (!first) os << " ";
                            first = false;
                            if (pos + 1 < dec.count() && dec[pos].isAtom() && dec[pos + 1].isAtom()) {
                                os << "col" << dec[pos].uintVal << "=" << formatAtomValue(dec[pos + 1]);
                                pos += 2;
                            }
                            if (pos < dec.count() && dec[pos].type == TokenType::EndName) pos++;
                        }
                    }
                    break;
                }
                // Skip other named params
                while (pos < dec.count() && dec[pos].type != TokenType::EndName) pos++;
                if (pos < dec.count()) pos++;
            } else {
                pos++;
            }
        }
        return os.str();
    }

    return "";
}

// ═══════════════════════════════════════════════════
//  Extract result values from recv token stream
// ═══════════════════════════════════════════════════

std::string CommandLogger::formatResult(const uint8_t* data, size_t len) {
    if (len < TOKEN_OFFSET + 1) return "";

    SubPacketHeader sph;
    static constexpr size_t SPH_OFF = ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE;
    auto r = SubPacketHeader::deserialize(data + SPH_OFF, len - SPH_OFF, sph);
    if (r.failed() || sph.length == 0) return "";

    size_t tokenLen = sph.length;
    if (TOKEN_OFFSET + tokenLen > len) tokenLen = len - TOKEN_OFFSET;

    TokenDecoder dec;
    r = dec.decode(data + TOKEN_OFFSET, tokenLen);
    if (r.failed() || dec.count() == 0) return "";

    // Skip CALL header if present (SM responses)
    size_t pos = 0;
    if (dec[0].type == TokenType::Call) {
        pos = 3; // skip CALL + 2 UIDs
    }

    // Properties response: extract TPerProperties values
    // SyncSession response: extract TSN, HSN
    // Get response: extract column values
    if (pos >= dec.count()) return "";

    // Look for STARTLIST (result list)
    if (dec[pos].type != TokenType::StartList) return "";
    pos++;

    std::ostringstream os;

    // Check if this is a named-value response (Properties, Get)
    if (pos < dec.count() && dec[pos].type == TokenType::StartName) {
        bool first = true;
        while (pos < dec.count() && dec[pos].type == TokenType::StartName) {
            pos++;
            if (pos < dec.count() && dec[pos].isAtom()) {
                std::string key = formatAtomValue(dec[pos]);
                pos++;
                // Value might be a list or an atom
                if (pos < dec.count() && dec[pos].type == TokenType::StartList) {
                    // Named list (e.g., TPerProperties)
                    if (key == "\"TPerProperties\"") {
                        pos++; // skip STARTLIST
                        os << "TPerProps:";
                        while (pos < dec.count() && dec[pos].type == TokenType::StartName) {
                            pos++;
                            if (pos + 1 < dec.count() && dec[pos].isAtom() && dec[pos + 1].isAtom()) {
                                os << " " << formatAtomValue(dec[pos]) << "=" << formatAtomValue(dec[pos + 1]);
                                pos += 2;
                            }
                            if (pos < dec.count() && dec[pos].type == TokenType::EndName) pos++;
                        }
                        // Skip to ENDLIST
                        while (pos < dec.count() && dec[pos].type != TokenType::EndList) pos++;
                        if (pos < dec.count()) pos++;
                    } else {
                        // Skip list
                        int depth = 1;
                        while (pos < dec.count() && depth > 0) {
                            if (dec[pos].type == TokenType::StartList) depth++;
                            if (dec[pos].type == TokenType::EndList) depth--;
                            pos++;
                        }
                    }
                } else if (pos < dec.count() && dec[pos].isAtom()) {
                    // Simple named value (Get result)
                    if (!first) os << " ";
                    first = false;
                    os << "[" << key << "=" << formatAtomValue(dec[pos]) << "]";
                    pos++;
                }
            }
            if (pos < dec.count() && dec[pos].type == TokenType::EndName) pos++;
        }
        return os.str();
    }

    // Positional values (SyncSession: HSN, TSN)
    // Just show first few atom values
    bool first = true;
    int shown = 0;
    while (pos < dec.count() && dec[pos].type != TokenType::EndList && shown < 4) {
        if (dec[pos].isAtom()) {
            if (!first) os << " ";
            first = false;
            os << formatAtomValue(dec[pos]);
            shown++;
        }
        pos++;
    }

    return os.str();
}

// ═══════════════════════════════════════════════════
//  Raw hex (compact, non-zero bytes only)
// ═══════════════════════════════════════════════════

void CommandLogger::writeRawHex(std::ostream& os, const uint8_t* data, size_t len) {
    // Find actual payload end (skip trailing zeros)
    size_t actualLen = len;
    while (actualLen > 0 && data[actualLen - 1] == 0) actualLen--;
    if (actualLen == 0) { os << "    (empty)\n"; return; }

    // Cap at 256 bytes
    size_t dumpLen = std::min(actualLen, (size_t)256);
    for (size_t off = 0; off < dumpLen; off += 16) {
        os << "    " << std::hex << std::setfill('0') << std::setw(4) << off << ":";
        for (size_t col = 0; col < 16; col++) {
            if (col % 4 == 0) os << " ";
            if (off + col < dumpLen)
                os << " " << std::setw(2) << (int)data[off + col];
            else
                os << "   ";
        }
        os << "\n";
    }
    if (dumpLen < actualLen)
        os << "    ...(" << std::dec << actualLen << "B total)\n";
    os << std::dec;
}

// ═══════════════════════════════════════════════════
//  Main log entry
// ═══════════════════════════════════════════════════

void CommandLogger::logCommand(const char* direction,
                               uint8_t protocolId, uint16_t comId,
                               const uint8_t* data, size_t len) {
    uint32_t cmdNum = cmdCount_.fetch_add(1) + 1;
    bool isSend = (direction[0] == '>');

    // Calculate elapsed time
    long elapsedMs = 0;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!isSend) {
            auto now = std::chrono::steady_clock::now();
            elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastSendTime_).count();
        }
    }

    std::ostringstream os;

    // ── Protocol 0x02: ComID Management (compact) ──
    if (protocolId == 0x02) {
        std::string op = "ComID_Mgmt";
        if (len >= 8) {
            uint32_t reqCode = Endian::readBe32(data + 4);
            if (reqCode == 0) op = "VerifyComID";
            else if (reqCode == 2) op = "StackReset";
        }
        os << "#" << std::setfill('0') << std::setw(3) << cmdNum
           << " " << direction << " " << std::setfill(' ') << std::left << std::setw(30) << op
           << std::right
           << " P=02 C=" << std::hex << std::setfill('0') << std::setw(4) << comId
           << std::dec;
        if (!isSend)
            os << std::setw(8) << std::right << elapsedMs << "ms";
        os << "\n";
        if (alwaysHex_) writeRawHex(os, data, len);

        {
            std::lock_guard<std::mutex> lk(mutex_);
            std::string text = os.str();
            if (file_.is_open()) { file_ << text; file_.flush(); }
            if (stream_) { *stream_ << text; stream_->flush(); }
        }
        return;
    }

    // ── Protocol 0x01, ComID < 0x1000: Discovery ──
    if (protocolId == 0x01 && comId < 0x1000) {
        os << "#" << std::setfill('0') << std::setw(3) << cmdNum
           << " " << direction << " " << std::setfill(' ') << std::left << std::setw(30) << "Discovery"
           << std::right
           << " P=01 C=" << std::hex << std::setfill('0') << std::setw(4) << comId
           << std::dec;
        if (!isSend)
            os << std::setw(8) << std::right << elapsedMs << "ms";
        os << "\n";
        if (alwaysHex_) writeRawHex(os, data, len);

        {
            std::lock_guard<std::mutex> lk(mutex_);
            std::string text = os.str();
            if (file_.is_open()) { file_ << text; file_.flush(); }
            if (stream_) { *stream_ << text; stream_->flush(); }
        }
        return;
    }

    // ── Protocol 0x01, ComID >= 0x1000: TCG ComPacket ──

    // Extract TSN/HSN from packet header
    uint32_t tsn = 0, hsn = 0;
    if (len >= ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE) {
        PacketHeader ph;
        PacketHeader::deserialize(data + ComPacketHeader::HEADER_SIZE,
                                  len - ComPacketHeader::HEADER_SIZE, ph);
        tsn = ph.tperSessionNumber;
        hsn = ph.hostSessionNumber;
    }

    // Method name
    std::string method = formatMethod(data, len);
    if (method.empty()) method = "???";

    // Status (recv only)
    std::string status;
    bool isError = false;
    if (!isSend) {
        status = formatStatus(data, len);
        // Check if status indicates error (anything other than St=0)
        if (!status.empty() && status.find("St=0") == std::string::npos) {
            isError = true;
        }
    }

    // Build summary line
    // #001 >> SMUID.Properties              P=01 C=0C01 TSN=0 HSN=0       2ms
    std::string methodStatus = method;
    if (!status.empty()) {
        // Pad method to 20 chars, then append status
        while (methodStatus.size() < 20) methodStatus += ' ';
        methodStatus += " " + status;
    }

    os << "#" << std::setfill('0') << std::setw(3) << cmdNum
       << " " << direction << " " << std::setfill(' ') << std::left << std::setw(40) << methodStatus
       << std::right
       << " P=" << std::hex << std::setfill('0') << std::setw(2) << (int)protocolId
       << " C=" << std::setw(4) << comId
       << std::dec
       << " TSN=" << tsn << " HSN=" << hsn;
    if (!isSend)
        os << std::setw(8) << std::right << elapsedMs << "ms";
    os << "\n";

    // ── Key params (indented, send only) ──
    if (isSend) {
        std::string params = formatParams(data, len);
        if (!params.empty())
            os << "    " << params << "\n";
    }

    // ── Result values (indented, recv only) ──
    if (!isSend) {
        std::string result = formatResult(data, len);
        if (!result.empty())
            os << "    " << result << "\n";
    }

    // ── Raw hex: on error always, on success if alwaysHex_ ──
    if (isError) {
        os << "    --- RAW (error response) ---\n";
        writeRawHex(os, data, len);
    } else if (alwaysHex_) {
        writeRawHex(os, data, len);
    }

    std::lock_guard<std::mutex> lk(mutex_);
    std::string text = os.str();
    if (file_.is_open()) { file_ << text; file_.flush(); }
    if (stream_) { *stream_ << text; stream_->flush(); }
}

} // namespace debug
} // namespace libsed
