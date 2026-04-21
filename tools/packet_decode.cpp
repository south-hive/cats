/// @file packet_decode.cpp
/// CLI tool: hex-dump 파일을 읽어 rosetta_stone.md 형식으로 디코드
///
/// 입력 형식:
///   - 각 라인: "[주소(: 선택)]  hex bytes..." (예: "0000: 0000 0000 1004 ...")
///   - 주소는 0000, 0000:, 0x0000:, 0x0000 모두 허용
///   - 빈 줄 / '#' 주석 / '>>>' / '<<<' 로 시작하는 라인은 패킷 경계
///   - 주소가 0으로 돌아오면 새 패킷으로 간주

#include <libsed/codec/token_decoder.h>
#include <libsed/core/uid.h>
#include <libsed/core/endian.h>

#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace libsed;

// ───────────────────────────── helpers ─────────────────────────────

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

static bool isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// "0000:" / "0x0010:" / "0020" 같은 주소 prefix를 감지해 제거하고
/// 데이터 부분과 주소 정수를 반환. 주소가 없으면 hasAddr=false.
struct LineParse {
    bool hasAddr = false;
    uint64_t addr = 0;
    std::string data;
};

static LineParse stripAddress(const std::string& line) {
    LineParse out;
    std::string s = trim(line);
    if (s.empty()) return out;

    size_t i = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) i = 2;

    size_t hexStart = i;
    while (i < s.size() && isHexDigit(s[i])) ++i;
    size_t hexEnd = i;

    // 주소로 보이려면 반드시 뒤에 ':' 또는 공백/탭이 있어야 하고, 16진 문자 ≥1개
    if (hexEnd == hexStart) return { false, 0, s };

    size_t sepPos = i;
    bool hasColon = false;
    if (sepPos < s.size() && s[sepPos] == ':') { hasColon = true; ++sepPos; }
    bool hasSpace = (sepPos < s.size() &&
                     (s[sepPos] == ' ' || s[sepPos] == '\t'));

    // ':' 없고 공백 없으면 일반 hex 라인으로 간주
    if (!hasColon && !hasSpace) return { false, 0, s };

    // ':' 없는 경우: 첫 토큰만 4자리 이하의 짧은 16진이면 주소로 취급
    if (!hasColon && (hexEnd - hexStart) > 8) return { false, 0, s };

    out.hasAddr = true;
    try {
        out.addr = std::stoull(s.substr(hexStart, hexEnd - hexStart), nullptr, 16);
    } catch (...) {
        return { false, 0, s };
    }
    out.data = trim(s.substr(sepPos));
    return out;
}

/// "ff ab 00 f1..." → bytes. 공백/탭/'-'/'|' 무시. ASCII sidecar가 있으면 중단.
static std::vector<uint8_t> parseHexBytes(const std::string& s) {
    std::vector<uint8_t> out;
    std::string token;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '-' || c == '|') {
            if (!token.empty()) {
                if (token.size() % 2 != 0) token.insert(token.begin(), '0');
                for (size_t j = 0; j + 1 < token.size(); j += 2) {
                    out.push_back(static_cast<uint8_t>(
                        std::stoul(token.substr(j, 2), nullptr, 16)));
                }
                token.clear();
            }
            // ASCII sidecar 차단: '|' 뒤는 대부분 ASCII 해석
            if (c == '|') break;
            continue;
        }
        if (!isHexDigit(c)) break;   // 비-16진 문자가 나오면 종료 (ASCII sidecar 등)
        token += c;
        if (token.size() >= 32) {
            for (size_t j = 0; j + 1 < token.size(); j += 2) {
                out.push_back(static_cast<uint8_t>(
                    std::stoul(token.substr(j, 2), nullptr, 16)));
            }
            token.clear();
        }
    }
    if (!token.empty()) {
        if (token.size() % 2 != 0) token.insert(token.begin(), '0');
        for (size_t j = 0; j + 1 < token.size(); j += 2) {
            out.push_back(static_cast<uint8_t>(
                std::stoul(token.substr(j, 2), nullptr, 16)));
        }
    }
    return out;
}

// ───────────────────────────── UID/method 이름 해석 ─────────────────────────────

static const char* knownUidName(uint64_t u) {
    switch (u) {
        case uid::SMUID:            return "SMUID";
        case uid::THIS_SP:          return "THIS_SP";
        case uid::UID_HEXFF:        return "UID_HEXFF (null/sentinel)";
        case uid::SP_ADMIN:         return "SP_ADMIN";
        case uid::SP_LOCKING:       return "SP_LOCKING";
        case uid::SP_ENTERPRISE:    return "SP_ENTERPRISE";
        case uid::AUTH_ANYBODY:     return "AUTH_ANYBODY";
        case uid::AUTH_ADMINS:      return "AUTH_ADMINS";
        case uid::AUTH_MAKERS:      return "AUTH_MAKERS";
        case uid::AUTH_SID:         return "AUTH_SID";
        case uid::AUTH_PSID:        return "AUTH_PSID";
        case uid::AUTH_MSID:        return "AUTH_MSID";
        case uid::AUTH_ADMIN1:      return "AUTH_ADMIN1";
        case uid::AUTH_USER1:       return "AUTH_USER1";
        case uid::AUTH_BANDMASTER0: return "AUTH_BANDMASTER0";
        case uid::AUTH_ERASEMASTER: return "AUTH_ERASEMASTER";
        case uid::CPIN_SID:         return "CPIN_SID";
        case uid::CPIN_MSID:        return "CPIN_MSID";
        case uid::CPIN_ADMIN1:      return "CPIN_ADMIN1";
        case uid::CPIN_USER1:       return "CPIN_USER1";
        case uid::LOCKING_GLOBALRANGE: return "LOCKING_GLOBALRANGE";
        case uid::LOCKING_RANGE1:   return "LOCKING_RANGE1";
        case uid::MBRCTRL_SET:      return "MBRCTRL_SET";
        case uid::TABLE_MBR:        return "TABLE_MBR";
        case uid::TABLE_LOCKING:    return "TABLE_LOCKING";
        case uid::TABLE_CPIN:       return "TABLE_CPIN";
        case uid::TABLE_AUTHORITY:  return "TABLE_AUTHORITY";
        // Methods (SMUID에서 호출되는 SM 메서드)
        case 0x000000000000FF01ULL: return "SM_PROPERTIES";
        case 0x000000000000FF02ULL: return "SM_START_SESSION";
        case 0x000000000000FF03ULL: return "SM_SYNC_SESSION";
        case 0x000000000000FF06ULL: return "SM_CLOSE_SESSION";
        // Object methods
        case 0x0000000600000006ULL: return "EGET (Enterprise Get)";
        case 0x0000000600000007ULL: return "ESET (Enterprise Set)";
        case 0x0000000600000008ULL: return "NEXT";
        case 0x000000060000000CULL: return "EAUTHENTICATE";
        case 0x0000000600000010ULL: return "GENKEY";
        case 0x0000000600000011ULL: return "REVERTSP";
        case 0x0000000600000016ULL: return "GET";
        case 0x0000000600000017ULL: return "SET";
        case 0x000000060000001CULL: return "AUTHENTICATE";
        case 0x0000000600000202ULL: return "REVERT";
        case 0x0000000600000203ULL: return "ACTIVATE";
        case 0x0000000600000601ULL: return "RANDOM";
        case 0x0000000600000803ULL: return "ERASE";
        default: break;
    }
    return nullptr;
}

static std::string uidHex(uint64_t u) {
    std::ostringstream os;
    os << "0x" << std::hex << std::setw(16) << std::setfill('0') << u;
    return os.str();
}

// ───────────────────────────── 메서드 상태 코드 ─────────────────────────────

static const char* methodStatusName(uint64_t s) {
    switch (s) {
        case 0x00: return "SUCCESS";
        case 0x01: return "NOT_AUTHORIZED";
        case 0x03: return "SP_BUSY";
        case 0x04: return "SP_FAILED";
        case 0x05: return "SP_DISABLED";
        case 0x06: return "SP_FROZEN";
        case 0x07: return "NO_SESSIONS_AVAILABLE";
        case 0x08: return "UNIQUENESS_CONFLICT";
        case 0x09: return "INSUFFICIENT_SPACE";
        case 0x0A: return "INSUFFICIENT_ROWS";
        case 0x0C: return "INVALID_PARAMETER";
        case 0x0F: return "TPER_MALFUNCTION";
        case 0x10: return "TRANSACTION_FAILURE";
        case 0x11: return "RESPONSE_OVERFLOW";
        case 0x12: return "AUTHORITY_LOCKED_OUT";
        case 0x3F: return "FAIL";
        default:   return "UNKNOWN";
    }
}

// ───────────────────────────── 토큰 출력 ─────────────────────────────

static std::string asciiPreview(const Bytes& b) {
    std::string out;
    for (auto c : b) {
        if (c >= 0x20 && c < 0x7F) out += static_cast<char>(c);
        else return {};
    }
    return out;
}

static std::string hexString(const Bytes& b, size_t maxBytes = 32) {
    std::ostringstream os;
    size_t n = std::min(b.size(), maxBytes);
    for (size_t i = 0; i < n; ++i) {
        os << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(b[i]);
        if (i + 1 < n) os << " ";
    }
    if (b.size() > maxBytes) os << " …(+" << (b.size() - maxBytes) << ")";
    return os.str();
}

static void printToken(const Token& tok, int depth, std::ostream& os) {
    std::string ind(depth * 2, ' ');
    switch (tok.type) {
        case TokenType::StartList:        os << ind << "STARTLIST   [\n";  return;
        case TokenType::EndList:          os << ind << "ENDLIST     ]\n";  return;
        case TokenType::StartName:        os << ind << "STARTNAME   {\n";  return;
        case TokenType::EndName:          os << ind << "ENDNAME     }\n";  return;
        case TokenType::Call:             os << ind << "CALL\n";           return;
        case TokenType::EndOfData:        os << ind << "EOD\n";            return;
        case TokenType::EndOfSession:     os << ind << "END_OF_SESSION (0xFA)\n"; return;
        case TokenType::StartTransaction: os << ind << "START_TRANSACTION\n";     return;
        case TokenType::EndTransaction:   os << ind << "END_TRANSACTION\n";       return;
        case TokenType::EmptyAtom:        os << ind << "EMPTY (0xFF)\n";          return;
        default: break;
    }
    if (tok.isByteSequence) {
        const auto& b = tok.getBytes();
        if (b.size() == 8) {
            uint64_t u = 0;
            for (auto c : b) u = (u << 8) | c;
            const char* name = knownUidName(u);
            os << ind << "UID  " << uidHex(u);
            if (name) os << "  (" << name << ")";
            os << "\n";
            return;
        }
        auto ascii = asciiPreview(b);
        os << ind << "BYTES[" << b.size() << "] " << hexString(b);
        if (!ascii.empty()) os << "  \"" << ascii << "\"";
        os << "\n";
        return;
    }
    if (tok.isSigned) {
        os << ind << "INT   " << tok.getInt() << "\n";
    } else {
        os << ind << "UINT  " << tok.getUint();
        if (tok.getUint() <= 0xFFFF) {
            os << " (0x" << std::hex << tok.getUint() << std::dec << ")";
        }
        os << "\n";
    }
}

static void printTokens(const std::vector<Token>& toks, std::ostream& os) {
    int depth = 0;
    for (const auto& t : toks) {
        if (t.type == TokenType::EndList || t.type == TokenType::EndName) --depth;
        printToken(t, depth, os);
        if (t.type == TokenType::StartList || t.type == TokenType::StartName) ++depth;
    }
}

// ───────────────────────────── 패킷 디코드 ─────────────────────────────

static uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}
static uint16_t readBE16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

static void decodePacket(const std::vector<uint8_t>& buf,
                         size_t index,
                         const std::string& label,
                         std::ostream& os) {
    os << "══════════════════════════════════════════════════════════════\n";
    os << " Packet #" << index;
    if (!label.empty()) os << " — " << label;
    os << "   (" << buf.size() << " bytes)\n";
    os << "══════════════════════════════════════════════════════════════\n";

    if (buf.size() < 20) {
        os << "  [too short for ComPacket header]\n\n";
        return;
    }

    // ComPacket header (20 bytes)
    uint32_t cp_reserved = readBE32(buf.data() + 0);
    uint16_t comId       = readBE16(buf.data() + 4);
    uint16_t comIdExt    = readBE16(buf.data() + 6);
    uint32_t outstanding = readBE32(buf.data() + 8);
    uint32_t minXfer     = readBE32(buf.data() + 12);
    uint32_t cpLen       = readBE32(buf.data() + 16);

    os << "ComPacket (20 B)\n";
    os << "  reserved        = 0x" << std::hex << std::setw(8) << std::setfill('0')
       << cp_reserved << std::dec << "\n";
    os << "  ComID           = 0x" << std::hex << std::setw(4) << std::setfill('0')
       << comId << std::dec << "  ext=0x" << std::hex << comIdExt << std::dec << "\n";
    os << "  OutstandingData = " << outstanding << "\n";
    os << "  MinTransfer     = " << minXfer << "\n";
    os << "  Length          = " << cpLen << " (payload after this field)\n";

    if (buf.size() < 20 + 24) {
        os << "  [no Packet header]\n\n";
        return;
    }

    // Packet header (24 bytes)
    uint32_t tsn        = readBE32(buf.data() + 20);
    uint32_t hsn        = readBE32(buf.data() + 24);
    uint32_t seqNum     = readBE32(buf.data() + 28);
    uint16_t p_reserved = readBE16(buf.data() + 32);
    uint16_t ackType    = readBE16(buf.data() + 34);
    uint32_t ackVal     = readBE32(buf.data() + 36);
    uint32_t pLen       = readBE32(buf.data() + 40);

    os << "Packet (24 B)\n";
    os << "  TSN             = 0x" << std::hex << tsn << std::dec
       << " (" << tsn << ")\n";
    os << "  HSN             = 0x" << std::hex << hsn << std::dec
       << " (" << hsn << ")";
    if (hsn == 105) os << "  ← sedutil standard";
    os << "\n";
    os << "  SeqNumber       = " << seqNum << "\n";
    os << "  reserved        = 0x" << std::hex << p_reserved << std::dec << "\n";
    os << "  AckType         = 0x" << std::hex << ackType << std::dec << "\n";
    os << "  Acknowledgement = 0x" << std::hex << ackVal << std::dec << "\n";
    os << "  Length          = " << pLen << " (SubPacket area, padded to 4)\n";

    if (buf.size() < 20 + 24 + 12) {
        os << "  [no SubPacket]\n\n";
        return;
    }

    // SubPacket header (12 bytes)
    uint16_t sp_kind = readBE16(buf.data() + 44 + 6);
    uint32_t sp_len  = readBE32(buf.data() + 44 + 8);

    os << "SubPacket (12 B)\n";
    os << "  Kind            = " << sp_kind
       << (sp_kind == 0 ? " (Data)" : sp_kind == 1 ? " (CreditControl)" : "") << "\n";
    os << "  Length          = " << sp_len << " (token payload, unpadded)\n";

    // Token payload
    size_t tokOff = 56;
    if (tokOff + sp_len > buf.size()) {
        os << "  [payload truncated: need " << sp_len
           << " bytes, have " << (buf.size() - tokOff) << "]\n\n";
        return;
    }

    std::vector<uint8_t> payload(buf.begin() + tokOff,
                                 buf.begin() + tokOff + sp_len);

    os << "Token Payload (" << sp_len << " B)\n";
    os << "  raw: " << hexString(payload, 64) << "\n";

    TokenDecoder dec;
    auto r = dec.decode(payload.data(), payload.size());
    if (r.failed()) {
        os << "  [decode error: " << r.message() << "]\n\n";
        return;
    }

    os << "  decoded:\n";
    std::ostringstream tos;
    printTokens(dec.tokens(), tos);
    // 토큰 출력에 2칸 들여쓰기 추가
    std::istringstream iss(tos.str());
    std::string line;
    while (std::getline(iss, line)) os << "    " << line << "\n";

    // 요청 vs 응답 판별: CALL 토큰이 있으면 요청(Host→TPer), 없으면 응답.
    bool isRequest = false;
    for (const auto& t : dec.tokens()) {
        if (t.type == TokenType::Call) { isRequest = true; break; }
    }

    // 상태 리스트: EOD 뒤 첫 UInt = status 값
    uint64_t statusVal = 0;
    bool foundStatus = false;
    bool seenEOD = false;
    for (const auto& t : dec.tokens()) {
        if (t.type == TokenType::EndOfData) { seenEOD = true; continue; }
        if (seenEOD && t.isAtom() && !t.isByteSequence && !t.isSigned &&
            t.type != TokenType::StartList && t.type != TokenType::EndList &&
            t.type != TokenType::EmptyAtom) {
            statusVal = t.getUint();
            foundStatus = true;
            break;
        }
    }
    if (foundStatus) {
        if (isRequest) {
            os << "  ► Direction: REQUEST (host→TPer)   status placeholder = 0x"
               << std::hex << std::setw(2) << std::setfill('0') << statusVal
               << std::dec << "\n";
        } else {
            os << "  ► Direction: RESPONSE (TPer→host)  Method Status = 0x"
               << std::hex << std::setw(2) << std::setfill('0') << statusVal
               << std::dec << " (" << methodStatusName(statusVal) << ")\n";
        }
    }
    os << "\n";
}

// ───────────────────────────── 파일 → 패킷 분리 ─────────────────────────────

struct RawPacket {
    std::string label;           // '>>>' / '<<<' 라벨 또는 '#' 주석
    std::vector<uint8_t> bytes;
};

static std::vector<RawPacket> splitPackets(std::istream& in) {
    std::vector<RawPacket> packets;
    RawPacket cur;
    uint64_t lastAddr = UINT64_MAX;
    std::string pendingLabel;

    auto flush = [&]() {
        if (!cur.bytes.empty()) {
            if (cur.label.empty()) cur.label = pendingLabel;
            packets.push_back(std::move(cur));
            cur = {};
        }
        lastAddr = UINT64_MAX;
    };

    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty()) { flush(); pendingLabel.clear(); continue; }

        // 주석/라벨 라인: 내용 자체를 라벨로 사용하고 경계로 처리
        if (t[0] == '#' || t.find(">>>") != std::string::npos ||
            t.find("<<<") != std::string::npos) {
            flush();
            pendingLabel = t;
            continue;
        }

        auto lp = stripAddress(line);
        // 주소가 없는 라인은 hex-dump가 아니라고 간주하고 무시
        if (!lp.hasAddr) continue;

        // 주소가 0으로 돌아오면 새 패킷
        if (lastAddr != UINT64_MAX && lp.addr < lastAddr) {
            flush();
        }
        lastAddr = lp.addr;

        auto bytes = parseHexBytes(lp.data);
        if (bytes.empty()) continue;   // 주소만 있고 데이터가 없는 라인
        if (cur.label.empty()) cur.label = pendingLabel;
        cur.bytes.insert(cur.bytes.end(), bytes.begin(), bytes.end());
    }
    flush();
    return packets;
}

// ───────────────────────────── main ─────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hexdump_file> [-o output]\n\n"
                  << "입력 파일은 다음과 같은 hex-dump 라인을 포함:\n"
                  << "  0000: 0000 0000 1004 0000 ...\n"
                  << "  0010  0000 0048 0000 1060 ...\n"
                  << "빈 줄 / '#' 주석 / '>>>' / '<<<' 는 패킷 경계.\n"
                  << "주소가 0으로 되돌아오면 다음 패킷으로 간주됩니다.\n";
        return 1;
    }

    std::string inPath = argv[1];
    std::string outPath;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-o" && i + 1 < argc) outPath = argv[++i];
    }

    std::ifstream fin(inPath);
    if (!fin) {
        std::cerr << "Cannot open: " << inPath << "\n";
        return 1;
    }

    auto packets = splitPackets(fin);
    if (packets.empty()) {
        std::cerr << "No packets found in " << inPath << "\n";
        return 1;
    }

    std::ofstream fout;
    std::ostream* out = &std::cout;
    if (!outPath.empty()) {
        fout.open(outPath);
        if (!fout) { std::cerr << "Cannot write: " << outPath << "\n"; return 1; }
        out = &fout;
    }

    *out << "# Decoded " << packets.size() << " packet(s) from " << inPath << "\n\n";
    for (size_t i = 0; i < packets.size(); ++i) {
        decodePacket(packets[i].bytes, i + 1, packets[i].label, *out);
    }
    return 0;
}
