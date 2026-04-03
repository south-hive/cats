/// @file command_logger.cpp
/// @brief CommandLogger 구현 — IF-SEND/IF-RECV 명령 이력 기록.
///
/// 각 명령에 대해 다음 4개 섹션을 출력한다:
///   1. Command Info: SP (Protocol ID), SPS (ComID), Transfer Length
///   2. TCG Head: ComPacket, Packet, SubPacket 헤더 필드
///   3. TCG Payload: 토큰 디코딩 (타입, 값, UID 해석)
///   4. Raw Payload: 16바이트/줄 헥스 덤프

#include <libsed/debug/command_logger.h>
#include <libsed/packet/com_packet.h>
#include <libsed/codec/token_decoder.h>
#include <libsed/core/uid.h>
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
//  UID → 이름 매핑 테이블
// ═══════════════════════════════════════════════════

/// @brief 잘 알려진 TCG UID를 사람이 읽을 수 있는 이름으로 매핑
static const std::unordered_map<uint64_t, const char*>& uidNameTable() {
    static const std::unordered_map<uint64_t, const char*> table = {
        // Session Manager
        {uid::SMUID,                    "SMUID"},
        {uid::THIS_SP,                  "ThisSP"},

        // Security Providers
        {uid::SP_ADMIN,                 "AdminSP"},
        {uid::SP_LOCKING,               "LockingSP"},
        {uid::SP_ENTERPRISE,            "EnterpriseSP"},

        // Authority
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

        // Tables
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

        // Locking Range rows
        {uid::LOCKING_GLOBALRANGE,      "GlobalRange"},
        {uid::LOCKING_RANGE1,           "Range1"},
        {uid::LOCKING_RANGE2,           "Range2"},

        // C_PIN rows
        {uid::CPIN_SID,                 "C_PIN<SID>"},
        {uid::CPIN_MSID,                "C_PIN<MSID>"},
        {uid::CPIN_ADMIN1,              "C_PIN<Admin1>"},
        {uid::CPIN_USER1,               "C_PIN<User1>"},
        {uid::CPIN_USER2,               "C_PIN<User2>"},
        {uid::CPIN_BANDMASTER0,         "C_PIN<BandMaster0>"},
        {uid::CPIN_ERASEMASTER,         "C_PIN<EraseMaster>"},

        // MBR Control
        {uid::MBRCTRL_SET,              "MBRControl"},

        // ACE
        {uid::ACE_LOCKING_RANGE_SET_RDLOCKED,         "ACE<Range_RdLock>"},
        {uid::ACE_LOCKING_RANGE_SET_WRLOCKED,         "ACE<Range_WrLock>"},
        {uid::ACE_LOCKING_GLOBALRANGE_SET_RDLOCKED,   "ACE<Global_RdLock>"},
        {uid::ACE_LOCKING_GLOBALRANGE_SET_WRLOCKED,   "ACE<Global_WrLock>"},

        // K_AES
        {uid::K_AES_GLOBALRANGE,        "K_AES<GlobalRange>"},
        {uid::DATASTORE_TABLE_0,        "DataStore0"},
    };
    return table;
}

/// @brief 잘 알려진 Method UID를 이름으로 매핑
static const std::unordered_map<uint64_t, const char*>& methodNameTable() {
    static const std::unordered_map<uint64_t, const char*> table = {
        // Session Manager methods
        {method::SM_PROPERTIES,              "Properties"},
        {method::SM_START_SESSION,           "StartSession"},
        {method::SM_SYNC_SESSION,            "SyncSession"},
        {method::SM_START_TRUSTED_SESSION,   "StartTrustedSession"},
        {method::SM_SYNC_TRUSTED_SESSION,    "SyncTrustedSession"},
        {method::SM_CLOSE_SESSION,           "CloseSession"},

        // Standard methods
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

        // Table methods
        {method::ASSIGN,                     "Assign"},
        {method::REMOVE,                     "Remove"},
        {method::CREATE_ROW,                 "CreateRow"},
        {method::DELETE_ROW,                 "DeleteRow"},

        // Clock
        {method::GET_CLOCK,                  "GetClock"},
    };
    return table;
}

// ═══════════════════════════════════════════════════
//  UID 해석 헬퍼
// ═══════════════════════════════════════════════════

const char* CommandLogger::resolveUid(uint64_t uid) {
    auto& table = uidNameTable();
    auto it = table.find(uid);
    if (it != table.end()) return it->second;

    // Method UID에서도 검색 (invokingUID가 method일 수 있음)
    auto& mtable = methodNameTable();
    auto mit = mtable.find(uid);
    if (mit != mtable.end()) return mit->second;

    return nullptr;
}

const char* CommandLogger::resolveMethodUid(uint64_t uid) {
    auto& table = methodNameTable();
    auto it = table.find(uid);
    if (it != table.end()) return it->second;

    // Object UID에서도 검색
    auto& utable = uidNameTable();
    auto uit = utable.find(uid);
    if (uit != utable.end()) return uit->second;

    return nullptr;
}

uint64_t CommandLogger::bytesToUid(const uint8_t* data, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len && i < 8; i++) {
        val = (val << 8) | data[i];
    }
    return val;
}

// ═══════════════════════════════════════════════════
//  파일 이름 생성
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
        // 확장자 제거
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
//  생성자 / 소멸자
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

CommandLogger::~CommandLogger() {
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
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
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
}

// ═══════════════════════════════════════════════════
//  공개 인터페이스
// ═══════════════════════════════════════════════════

void CommandLogger::logIfSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) {
    logCommand("IF-SEND", protocolId, comId, payload.data(), payload.size());
}

void CommandLogger::logIfRecv(uint8_t protocolId, uint16_t comId,
                              const uint8_t* data, size_t bytesReceived) {
    logCommand("IF-RECV", protocolId, comId, data, bytesReceived);
}

// ═══════════════════════════════════════════════════
//  명령 포맷팅 및 기록
// ═══════════════════════════════════════════════════

void CommandLogger::logCommand(const char* direction,
                               uint8_t protocolId, uint16_t comId,
                               const uint8_t* data, size_t len) {
    uint32_t cmdNum = cmdCount_.fetch_add(1) + 1;

    std::ostringstream os;
    os << "\n<<CMD #" << cmdNum << ", " << direction << ">>\n";

    writeCommandInfo(os, protocolId, comId, len);

    // TCG Head/Payload는 Protocol 0x01 + ComID >= 0x1000일 때만 파싱
    // ComID 0x0001 = Level 0 Discovery (binary format, NOT ComPacket)
    // Protocol 0x02 = ComID Management (별도 binary format)
    static constexpr size_t MIN_COMPACKET_SIZE =
        ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE + SubPacketHeader::HEADER_SIZE;

    if (protocolId == 0x01 && comId >= 0x1000 && len >= MIN_COMPACKET_SIZE) {
        writeTcgHead(os, data, len);
        writeTcgPayload(os, data, len);
    }

    writeRawPayload(os, data, len);

    // 파일에 원자적으로 기록
    std::lock_guard<std::mutex> lk(mutex_);
    if (file_.is_open()) {
        file_ << os.str();
        file_.flush();
    }
}

// ── Command Info ────────────────────────────────────

void CommandLogger::writeCommandInfo(std::ostream& os,
                                     uint8_t protocolId, uint16_t comId,
                                     size_t len) {
    os << "Command Info\n";
    os << "  SP (Protocol ID) : 0x" << std::hex << std::setfill('0')
       << std::setw(2) << (int)protocolId << "\n";
    os << "  SPS (ComID)      : 0x" << std::setw(4) << comId << "\n";
    os << "  Transfer Length   : " << std::dec << len << "\n";
}

// ── TCG Head ────────────────────────────────────────

void CommandLogger::writeTcgHead(std::ostream& os,
                                 const uint8_t* data, size_t len) {
    os << "TCG Head\n";

    // ComPacket Header (offset 0, 20 bytes)
    ComPacketHeader cph;
    auto r = ComPacketHeader::deserialize(data, len, cph);
    if (r.ok()) {
        os << "  ComPacket : comId=0x" << std::hex << std::setfill('0')
           << std::setw(4) << cph.comId
           << " ext=0x" << std::setw(4) << cph.comIdExtension
           << " outstanding=" << std::dec << cph.outstandingData
           << " minXfer=" << cph.minTransfer
           << " len=" << cph.length << "\n";
    }

    // Packet Header (offset 20, 24 bytes)
    if (len >= ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE) {
        PacketHeader ph;
        r = PacketHeader::deserialize(data + ComPacketHeader::HEADER_SIZE,
                                      len - ComPacketHeader::HEADER_SIZE, ph);
        if (r.ok()) {
            os << "  Packet    : TSN=" << ph.tperSessionNumber
               << " HSN=" << ph.hostSessionNumber
               << " seq=" << ph.seqNumber
               << " ackType=" << ph.ackType
               << " ack=" << ph.acknowledgement
               << " len=" << ph.length << "\n";
        }
    }

    // SubPacket Header (offset 44, 12 bytes)
    static constexpr size_t SPH_OFFSET =
        ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE;
    if (len >= SPH_OFFSET + SubPacketHeader::HEADER_SIZE) {
        SubPacketHeader sph;
        r = SubPacketHeader::deserialize(data + SPH_OFFSET,
                                         len - SPH_OFFSET, sph);
        if (r.ok()) {
            os << "  SubPacket : kind=0x" << std::hex << std::setfill('0')
               << std::setw(4) << sph.kind
               << (sph.kind == 0 ? "(Data)" : "(Credit)")
               << " len=" << std::dec << sph.length << "\n";
        }
    }
}

// ── TCG Payload ─────────────────────────────────────

/// @brief MethodStatus 코드를 이름으로 변환
static const char* methodStatusName(uint64_t status) {
    switch (status) {
        case 0x00: return "Success";
        case 0x01: return "NotAuthorized";
        case 0x02: return "Obsolete";
        case 0x03: return "SpBusy";
        case 0x04: return "SpFailed";
        case 0x05: return "SpDisabled";
        case 0x06: return "SpFrozen";
        case 0x07: return "NoSessionsAvailable";
        case 0x08: return "UniquenessConflict";
        case 0x09: return "InsufficientSpace";
        case 0x0A: return "InsufficientRows";
        case 0x0C: return "InvalidParameter";
        case 0x0F: return "TPerMalfunction";
        case 0x10: return "TransactionFailure";
        case 0x11: return "ResponseOverflow";
        case 0x12: return "AuthorityLockedOut";
        case 0x3F: return "Fail";
        default:   return nullptr;
    }
}

/// @brief 바이트 배열이 출력 가능한 ASCII 문자열인지 판별
static bool isPrintableAscii(const Bytes& data) {
    if (data.empty()) return false;
    for (auto b : data) {
        if (b < 0x20 || b > 0x7E) return false;
    }
    return true;
}

/// @brief atom 값을 의미 있는 문자열로 변환 (UID 이름, 문자열, 숫자, hex)
std::string CommandLogger::formatAtomValue(const Token& tok) {
    if (tok.isByteSequence) {
        // 8바이트 UID → 이름 해석 시도
        if (tok.byteData.size() == 8) {
            uint64_t uid = bytesToUid(tok.byteData.data(), 8);
            const char* name = resolveUid(uid);
            if (!name) name = resolveMethodUid(uid);
            if (name) return name;
        }
        if (tok.byteData.empty()) return "\"\"";
        // 출력 가능한 ASCII면 문자열로 표시
        if (isPrintableAscii(tok.byteData)) {
            return "\"" + std::string(tok.byteData.begin(), tok.byteData.end()) + "\"";
        }
        // 짧은 바이트는 hex
        if (tok.byteData.size() <= 16) {
            std::ostringstream h;
            h << std::hex << std::setfill('0');
            for (auto b : tok.byteData) h << std::setw(2) << (int)b;
            return h.str();
        }
        return "(" + std::to_string(tok.byteData.size()) + " bytes)";
    }
    // Integer
    return std::to_string(tok.isSigned ? tok.intVal : (int64_t)tok.uintVal);
}

void CommandLogger::writeTcgPayload(std::ostream& os,
                                    const uint8_t* data, size_t len) {
    // Token payload는 SubPacket 이후 (offset 56)
    static constexpr size_t TOKEN_OFFSET =
        ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE +
        SubPacketHeader::HEADER_SIZE;

    if (len <= TOKEN_OFFSET) return;

    // SubPacket length를 읽어서 토큰 영역 크기 결정
    SubPacketHeader sph;
    static constexpr size_t SPH_OFFSET =
        ComPacketHeader::HEADER_SIZE + PacketHeader::HEADER_SIZE;
    auto r = SubPacketHeader::deserialize(data + SPH_OFFSET,
                                          len - SPH_OFFSET, sph);
    if (r.failed()) return;

    size_t tokenLen = sph.length;
    if (tokenLen == 0) return;
    if (TOKEN_OFFSET + tokenLen > len) tokenLen = len - TOKEN_OFFSET;

    TokenDecoder decoder;
    r = decoder.decode(data + TOKEN_OFFSET, tokenLen);
    if (r.failed() || decoder.count() == 0) return;

    os << "TCG Payload\n";

    // 1단계: 토큰 스트림을 의미 단위로 파싱하여 출력
    //   - CALL invokingUID methodUID → "InvokingName.MethodName"
    //   - { args } → "{ val1, val2, ... }"
    //   - EOD → "EOD"
    //   - { status reserved1 reserved2 } → "Status: N (Name)"

    size_t pos = 0;
    const size_t count = decoder.count();

    while (pos < count) {
        const auto& tok = decoder[pos];

        // ── CALL invokingUID methodUID ──
        if (tok.type == TokenType::Call) {
            os << "  ";
            pos++;
            // invokingUID
            if (pos < count && decoder[pos].isAtom()) {
                os << formatAtomValue(decoder[pos]);
                pos++;
            }
            // methodUID
            if (pos < count && decoder[pos].isAtom()) {
                os << "." << formatAtomValue(decoder[pos]);
                pos++;
            }
            os << "\n";
            continue;
        }

        // ── EndOfData ──
        if (tok.type == TokenType::EndOfData) {
            os << "  EOD\n";
            pos++;

            // EOD 직후의 { status reserved1 reserved2 } → "Status: N (Name)"
            if (pos < count && decoder[pos].type == TokenType::StartList) {
                pos++; // skip {
                std::vector<uint64_t> statusVals;
                while (pos < count && decoder[pos].type != TokenType::EndList) {
                    if (decoder[pos].isAtom() && !decoder[pos].isByteSequence) {
                        statusVals.push_back(decoder[pos].uintVal);
                    }
                    pos++;
                }
                if (pos < count) pos++; // skip }

                if (!statusVals.empty()) {
                    uint64_t st = statusVals[0];
                    const char* stName = methodStatusName(st);
                    os << "  Status: " << st;
                    if (stName) os << " (" << stName << ")";
                    os << "\n";
                }
            }
            continue;
        }

        // ── EndOfSession ──
        if (tok.type == TokenType::EndOfSession) {
            os << "  END_OF_SESSION\n";
            pos++;
            continue;
        }

        // ── StartList — 재귀적으로 { val, val, [name=val], ... } 형태 출력 ──
        if (tok.type == TokenType::StartList) {
            writeListSemantic(os, decoder, pos, 1);
            os << "\n";
            continue;
        }

        // ── Bare atom (리스트 밖의 단독 값) ──
        if (tok.isAtom()) {
            os << "  " << formatAtomValue(tok) << "\n";
            pos++;
            continue;
        }

        // ── 기타 제어 토큰 ──
        pos++;
    }
}

/// @brief 리스트를 의미 있는 한 줄 형태로 출력 (중첩 지원)
/// 형식: { val1, val2, [name = val], { nested }, ... }
void CommandLogger::writeListSemantic(std::ostream& os,
                                       const TokenDecoder& decoder,
                                       size_t& pos,
                                       int depth) {
    // indent
    if (depth == 1) os << "  ";

    os << "{ ";
    pos++; // skip StartList

    bool first = true;
    const size_t count = decoder.count();

    while (pos < count && decoder[pos].type != TokenType::EndList) {
        if (!first) os << ", ";
        first = false;

        const auto& tok = decoder[pos];

        // Named value pair: StartName key value EndName → [key = value]
        if (tok.type == TokenType::StartName) {
            pos++; // skip StartName
            std::string key, val;
            if (pos < count && decoder[pos].isAtom()) {
                key = formatAtomValue(decoder[pos]);
                pos++;
            }
            if (pos < count && decoder[pos].isAtom()) {
                val = formatAtomValue(decoder[pos]);
                pos++;
            } else if (pos < count && decoder[pos].type == TokenType::StartList) {
                // Named value가 리스트인 경우
                std::ostringstream sub;
                writeListSemantic(sub, decoder, pos, depth + 1);
                val = sub.str();
            }
            if (pos < count && decoder[pos].type == TokenType::EndName) {
                pos++; // skip EndName
            }
            os << "[" << key << " = " << val << "]";
            continue;
        }

        // 중첩 리스트
        if (tok.type == TokenType::StartList) {
            std::ostringstream sub;
            writeListSemantic(sub, decoder, pos, depth + 1);
            os << sub.str();
            continue;
        }

        // Atom value
        if (tok.isAtom()) {
            os << formatAtomValue(tok);
            pos++;
            continue;
        }

        // 예상치 못한 토큰 — skip
        pos++;
    }

    os << " }";
    if (pos < count) pos++; // skip EndList
}

// ── Raw Payload ─────────────────────────────────────

static constexpr size_t MAX_RAW_DUMP = 1024;

void CommandLogger::writeRawPayload(std::ostream& os,
                                    const uint8_t* data, size_t len) {
    os << "Raw Payload\n";

    size_t dumpLen = std::min(len, MAX_RAW_DUMP);
    for (size_t off = 0; off < dumpLen; off += 16) {
        // 오프셋
        os << "  " << std::hex << std::setfill('0') << std::setw(4) << off << ":";

        // 16바이트를 4바이트씩 4그룹
        for (size_t col = 0; col < 16; col++) {
            if (col % 4 == 0) os << " ";
            if (off + col < dumpLen) {
                os << " " << std::setw(2) << (int)data[off + col];
            } else {
                os << "   ";
            }
        }
        os << "\n";
    }

    if (len > MAX_RAW_DUMP) {
        os << "  ...truncated (" << std::dec << len << " bytes total, "
           << MAX_RAW_DUMP << " shown)\n";
    }

    os << std::dec;
}

} // namespace debug
} // namespace libsed
