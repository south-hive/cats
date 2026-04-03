/// @file ioctl_validator.cpp
/// @brief Offline packet comparison: libsed API vs sedutil manual byte construction
///
/// Validates that libsed's PacketBuilder/MethodCall/ParamEncoder produce
/// byte-identical packets to sedutil's DtaCommand/DtaDevOpal for every
/// command in the --query flow. No hardware required.
///
/// If all 5 tests PASS, the Properties 0x0C bug is NOT in packet encoding —
/// it must be in the NVMe ioctl layer or TPer firmware state.
///
/// Usage: ./ioctl_validator

#include <libsed/codec/token_encoder.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/uid.h>
#include <libsed/core/endian.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>

using namespace libsed;

using Packet = std::vector<uint8_t>;

// ═══════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════

static constexpr uint16_t COMID = 0x0001;
static constexpr uint32_t HSN   = 105;    // sedutil default
static constexpr uint32_t TSN   = 1;

// ═══════════════════════════════════════════════════════
//  SedutilPacketWriter — manual byte-by-byte builder
//  matching sedutil's DtaCommand encoding exactly
// ═══════════════════════════════════════════════════════

struct SedutilPacketWriter {
    Packet buf;
    size_t pos;

    SedutilPacketWriter() : buf(2048, 0), pos(56) {}

    void addByte(uint8_t b) { buf[pos++] = b; }

    void addStr(const char* s) {
        size_t len = strlen(s);
        if (len <= 15) {
            buf[pos++] = 0xA0 | static_cast<uint8_t>(len & 0x0F);
        } else {
            buf[pos++] = 0xD0 | static_cast<uint8_t>((len >> 8) & 0x07);
            buf[pos++] = static_cast<uint8_t>(len & 0xFF);
        }
        memcpy(&buf[pos], s, len);
        pos += len;
    }

    void addUid(uint64_t uid) {
        buf[pos++] = 0xA8;  // short atom, byte, unsigned, len=8
        for (int i = 7; i >= 0; --i)
            buf[pos++] = static_cast<uint8_t>((uid >> (i * 8)) & 0xFF);
    }

    void addUint(uint32_t value) {
        if (value < 64) {
            buf[pos++] = static_cast<uint8_t>(value & 0x3F);
        } else if (value < 0x100) {
            buf[pos++] = 0x81;
            buf[pos++] = static_cast<uint8_t>(value);
        } else if (value < 0x10000) {
            buf[pos++] = 0x82;
            buf[pos++] = static_cast<uint8_t>(value >> 8);
            buf[pos++] = static_cast<uint8_t>(value);
        } else {
            buf[pos++] = 0x84;
            buf[pos++] = static_cast<uint8_t>(value >> 24);
            buf[pos++] = static_cast<uint8_t>(value >> 16);
            buf[pos++] = static_cast<uint8_t>(value >> 8);
            buf[pos++] = static_cast<uint8_t>(value);
        }
    }

    void addBytes(const uint8_t* data, size_t len) {
        if (len <= 15) {
            buf[pos++] = 0xA0 | static_cast<uint8_t>(len & 0x0F);
        } else {
            buf[pos++] = 0xD0 | static_cast<uint8_t>((len >> 8) & 0x07);
            buf[pos++] = static_cast<uint8_t>(len & 0xFF);
        }
        memcpy(&buf[pos], data, len);
        pos += len;
    }

    void addProp(const char* name, uint32_t value) {
        addByte(0xF2);  // STARTNAME
        addStr(name);
        addUint(value);
        addByte(0xF3);  // ENDNAME
    }

    /// Finalize with EndOfData + status list, then write headers
    Packet complete(uint16_t comId, uint32_t tsn, uint32_t hsn) {
        addByte(0xF9);  // EndOfData
        addByte(0xF0); addByte(0x00); addByte(0x00); addByte(0x00); addByte(0xF1);
        return finalize(comId, tsn, hsn);
    }

    /// Finalize without EndOfData (for CloseSession)
    Packet completeNoEod(uint16_t comId, uint32_t tsn, uint32_t hsn) {
        return finalize(comId, tsn, hsn);
    }

private:
    Packet finalize(uint16_t comId, uint32_t tsn, uint32_t hsn) {
        size_t tokenLen = pos - 56;
        Endian::writeBe32(&buf[52], static_cast<uint32_t>(tokenLen));  // SubPacket.length
        while (pos % 4 != 0) pos++;                                    // pad to 4-byte
        Endian::writeBe32(&buf[40], static_cast<uint32_t>(pos - 44));  // Packet.length
        Endian::writeBe16(&buf[4],  comId);                            // ComPacket.comId
        Endian::writeBe32(&buf[16], static_cast<uint32_t>(pos - 20));  // ComPacket.length
        Endian::writeBe32(&buf[20], tsn);                              // Packet.TSN
        Endian::writeBe32(&buf[24], hsn);                              // Packet.HSN
        return buf;
    }
};

// ═══════════════════════════════════════════════════════
//  Utility: hex dump
// ═══════════════════════════════════════════════════════

static void hexDump(const char* label, const uint8_t* data, size_t len, size_t maxBytes = 0) {
    printf("=== %s (%zu bytes) ===\n", label, len);
    size_t limit = (maxBytes > 0) ? std::min(len, maxBytes) : len;
    for (size_t i = 0; i < limit; i += 16) {
        printf("  %04zX: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < limit) printf("%02X ", data[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < limit; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '.');
        }
        printf("|\n");
    }
    if (limit < len) printf("  ... (%zu more bytes)\n", len - limit);
    printf("\n");
}

// ═══════════════════════════════════════════════════════
//  Utility: TCG-aware header field name
// ═══════════════════════════════════════════════════════

static const char* headerFieldName(size_t offset) {
    if (offset < 4)  return "ComPacket.reserved";
    if (offset < 6)  return "ComPacket.comId";
    if (offset < 8)  return "ComPacket.comIdExtension";
    if (offset < 12) return "ComPacket.outstandingData";
    if (offset < 16) return "ComPacket.minTransfer";
    if (offset < 20) return "ComPacket.length";
    if (offset < 24) return "Packet.TSN";
    if (offset < 28) return "Packet.HSN";
    if (offset < 32) return "Packet.seqNumber";
    if (offset < 34) return "Packet.reserved";
    if (offset < 36) return "Packet.ackType";
    if (offset < 40) return "Packet.acknowledgement";
    if (offset < 44) return "Packet.length";
    if (offset < 50) return "SubPacket.reserved";
    if (offset < 52) return "SubPacket.kind";
    if (offset < 56) return "SubPacket.length";
    return "payload";
}

// ═══════════════════════════════════════════════════════
//  Utility: byte-by-byte diff with TCG field labels
// ═══════════════════════════════════════════════════════

static int diffPackets(const Packet& a, const Packet& b) {
    size_t maxLen = std::max(a.size(), b.size());
    int diffs = 0;
    for (size_t i = 0; i < maxLen; i++) {
        uint8_t av = (i < a.size()) ? a[i] : 0;
        uint8_t bv = (i < b.size()) ? b[i] : 0;
        if (av != bv) {
            printf("    offset 0x%04zX [%s]: libsed=0x%02X  sedutil=0x%02X",
                   i, headerFieldName(i), av, bv);
            if (av >= 0x20 && av <= 0x7E && bv >= 0x20 && bv <= 0x7E)
                printf("  ('%c' vs '%c')", av, bv);
            printf("\n");
            diffs++;
            if (diffs >= 50) { printf("    ... (too many diffs)\n"); break; }
        }
    }
    if (a.size() != b.size())
        printf("    Size: libsed=%zu  sedutil=%zu\n", a.size(), b.size());
    return diffs;
}

// ═══════════════════════════════════════════════════════
//  Utility: token stream decoder
// ═══════════════════════════════════════════════════════

static void tokenDump(const char* label, const uint8_t* data, size_t len) {
    printf("  %s tokens:\n", label);
    size_t i = 0;
    while (i < len) {
        uint8_t b = data[i];
        if (b >= 0xF0 && b <= 0xFF) {
            const char* names[] = {
                "STARTLIST","ENDLIST","STARTNAME","ENDNAME",
                "??F4","??F5","??F6","??F7",
                "CALL","ENDOFDATA","ENDOFSESSION","STARTTXN",
                "ENDTXN","??FD","??FE","EMPTY"
            };
            printf("    [%04zX] %s\n", i, names[b - 0xF0]);
            i++;
        } else if ((b & 0xC0) == 0x00) {
            printf("    [%04zX] uint: %u\n", i, b & 0x3F);
            i++;
        } else if ((b & 0xC0) == 0x40) {
            printf("    [%04zX] int: %d\n", i,
                   static_cast<int>(static_cast<int8_t>((b & 0x3F) | ((b & 0x20) ? 0xC0 : 0))));
            i++;
        } else if ((b & 0xC0) == 0x80) {
            bool isB = b & 0x20;
            size_t al = b & 0x0F;
            i++;
            if (isB) {
                bool printable = true;
                for (size_t j = 0; j < al && (i + j) < len; j++)
                    if (data[i + j] < 0x20 || data[i + j] > 0x7E) { printable = false; break; }
                if (printable && al > 0) {
                    printf("    [%04zX] \"", i - 1);
                    for (size_t j = 0; j < al; j++) printf("%c", data[i + j]);
                    printf("\"\n");
                } else {
                    printf("    [%04zX] bytes[%zu]: ", i - 1, al);
                    for (size_t j = 0; j < al; j++) printf("%02X", data[i + j]);
                    printf("\n");
                }
            } else {
                uint64_t v = 0;
                for (size_t j = 0; j < al; j++) v = (v << 8) | data[i + j];
                printf("    [%04zX] uint: %llu\n", i - 1, static_cast<unsigned long long>(v));
            }
            i += al;
        } else if ((b & 0xE0) == 0xC0) {
            bool isB = b & 0x10;
            size_t al = (static_cast<size_t>(b & 0x07) << 8) | data[i + 1];
            i += 2;
            if (isB) {
                bool printable = true;
                for (size_t j = 0; j < al && (i + j) < len; j++)
                    if (data[i + j] < 0x20 || data[i + j] > 0x7E) { printable = false; break; }
                if (printable && al > 0) {
                    printf("    [%04zX] \"", i - 2);
                    for (size_t j = 0; j < al; j++) printf("%c", data[i + j]);
                    printf("\"\n");
                } else {
                    printf("    [%04zX] bytes[%zu]: ", i - 2, al);
                    for (size_t j = 0; j < al; j++) printf("%02X", data[i + j]);
                    printf("\n");
                }
            } else {
                uint64_t v = 0;
                for (size_t j = 0; j < al; j++) v = (v << 8) | data[i + j];
                printf("    [%04zX] uint: %llu\n", i - 2, static_cast<unsigned long long>(v));
            }
            i += al;
        } else {
            printf("    [%04zX] ?? 0x%02X\n", i, b);
            i++;
        }
    }
}

// ═══════════════════════════════════════════════════════
//  Test structure
// ═══════════════════════════════════════════════════════

struct TestCase {
    const char* name;
    std::function<Packet()> buildLibsed;
    std::function<Packet()> buildSedutil;
};

// ═══════════════════════════════════════════════════════
//  Test 1: Properties (SM 0xFF01)
// ═══════════════════════════════════════════════════════

static Packet buildLibsedProperties() {
    ParamEncoder::HostProperties hp;
    hp.maxComPacketSize = 2048;
    hp.maxPacketSize    = 2028;
    hp.maxIndTokenSize  = 1992;
    hp.maxPackets       = 1;
    hp.maxSubPackets    = 1;
    hp.maxMethods       = 1;

    Bytes params = ParamEncoder::encodeProperties(hp);
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutilProperties() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);                      // Session Manager UID
    w.addUid(method::SM_PROPERTIES);           // SM_PROPERTIES method

    w.addByte(0xF0);                           // STARTLIST
    w.addByte(0xF2);                           // STARTNAME
    w.addStr("HostProperties");
    w.addByte(0xF0);                           // STARTLIST

    w.addProp("MaxComPacketSize", 2048);
    w.addProp("MaxPacketSize",    2028);
    w.addProp("MaxIndTokenSize",  1992);
    w.addProp("MaxPackets",       1);
    w.addProp("MaxSubpackets",    1);
    w.addProp("MaxMethods",       1);

    w.addByte(0xF1);                           // ENDLIST
    w.addByte(0xF3);                           // ENDNAME
    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);
}

// ═══════════════════════════════════════════════════════
//  Test 2: StartSession unauthenticated (SM 0xFF02)
// ═══════════════════════════════════════════════════════

static Packet buildLibsedStartSessionUnauth() {
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), true, {}, Uid(), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutilStartSessionUnauth() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);                      // SMUID
    w.addUid(method::SM_START_SESSION);        // SM_START_SESSION

    w.addByte(0xF0);                           // STARTLIST
    w.addUint(HSN);                            // HostSessionID = 105
    w.addUid(uid::SP_ADMIN);                   // SP UID
    w.addUint(1);                              // Write = true
    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);
}

// ═══════════════════════════════════════════════════════
//  Test 3: StartSession authenticated (SM 0xFF02)
// ═══════════════════════════════════════════════════════

static Packet buildLibsedStartSessionAuth() {
    Bytes credential(32, 0x41);  // dummy 32-byte credential
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), true, credential, Uid(uid::AUTH_SID), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutilStartSessionAuth() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);                      // SMUID
    w.addUid(method::SM_START_SESSION);        // SM_START_SESSION

    w.addByte(0xF0);                           // STARTLIST
    w.addUint(HSN);                            // HostSessionID = 105
    w.addUid(uid::SP_ADMIN);                   // SP UID
    w.addUint(1);                              // Write = true

    // Named param 0: HostChallenge (32-byte credential)
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // index 0 = HostChallenge
    {
        uint8_t cred[32];
        memset(cred, 0x41, 32);
        w.addBytes(cred, 32);
    }
    w.addByte(0xF3);                           // ENDNAME

    // Named param 3: HostExchangeAuthority = AUTH_SID
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(3);                              // index 3 = HostExchangeAuthority
    w.addUid(uid::AUTH_SID);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);
}

// ═══════════════════════════════════════════════════════
//  Test 4: Get C_PIN_MSID (method 0x06)
// ═══════════════════════════════════════════════════════

static Packet buildLibsedGetMsid() {
    CellBlock cb;
    cb.startColumn = 3;  // PIN column
    cb.endColumn   = 3;

    Bytes methodTokens = MethodCall::buildGet(Uid(uid::CPIN_MSID), cb);

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN, HSN);
    return pb.buildComPacket(methodTokens);
}

static Packet buildSedutilGetMsid() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::CPIN_MSID);                 // Invoking: C_PIN_MSID row
    w.addUid(method::GET);                     // Method: Get

    w.addByte(0xF0);                           // STARTLIST (outer param list)
    w.addByte(0xF0);                           // STARTLIST (CellBlock)

    // startColumn = 3 (PIN)
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // key: startColumn
    w.addUint(3);                              // value: 3
    w.addByte(0xF3);                           // ENDNAME

    // endColumn = 3
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(1);                              // key: endColumn
    w.addUint(3);                              // value: 3
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST (CellBlock)
    w.addByte(0xF1);                           // ENDLIST (outer)

    return w.complete(COMID, TSN, HSN);
}

// ═══════════════════════════════════════════════════════
//  Test 5: CloseSession (EndOfSession token only)
// ═══════════════════════════════════════════════════════

static Packet buildLibsedCloseSession() {
    TokenEncoder enc;
    enc.endOfSession();

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN, HSN);
    return pb.buildComPacket(enc.data());
}

static Packet buildSedutilCloseSession() {
    SedutilPacketWriter w;
    w.addByte(0xFA);  // EndOfSession — no EOD, no status list
    return w.completeNoEod(COMID, TSN, HSN);
}

// ═══════════════════════════════════════════════════════
//  Main runner
// ═══════════════════════════════════════════════════════

int main() {
    TestCase tests[] = {
        { "Properties (SM 0xFF01, TSN=0/HSN=0)",
          buildLibsedProperties, buildSedutilProperties },
        { "StartSession unauth (SM 0xFF02, TSN=0/HSN=0)",
          buildLibsedStartSessionUnauth, buildSedutilStartSessionUnauth },
        { "StartSession auth (SM 0xFF02, TSN=0/HSN=0, 32B cred, AUTH_SID)",
          buildLibsedStartSessionAuth, buildSedutilStartSessionAuth },
        { "Get C_PIN_MSID (0x06, TSN=1/HSN=105, col 3-3)",
          buildLibsedGetMsid, buildSedutilGetMsid },
        { "CloseSession (EndOfSession, TSN=1/HSN=105)",
          buildLibsedCloseSession, buildSedutilCloseSession },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    int passed = 0;

    printf("ioctl_validator: comparing libsed vs sedutil packet encoding\n");
    printf("ComID=0x%04X  HSN=%u  TSN=%u\n\n", COMID, HSN, TSN);

    for (int i = 0; i < total; i++) {
        auto& t = tests[i];
        Packet libsed  = t.buildLibsed();
        Packet sedutil = t.buildSedutil();

        int diffs = 0;
        if (libsed.size() != sedutil.size()) {
            diffs = 1;
        } else {
            for (size_t j = 0; j < libsed.size(); j++) {
                if (libsed[j] != sedutil[j]) { diffs++; }
            }
        }

        if (diffs == 0) {
            printf("[PASS] %d/%d  %s\n", i + 1, total, t.name);
            passed++;
        } else {
            printf("[FAIL] %d/%d  %s\n", i + 1, total, t.name);
            diffPackets(libsed, sedutil);

            // Show token payloads for diagnosis
            uint32_t libTokenLen = 0, sedTokenLen = 0;
            if (libsed.size() >= 56)
                libTokenLen = Endian::readBe32(libsed.data() + 52);
            if (sedutil.size() >= 56)
                sedTokenLen = Endian::readBe32(sedutil.data() + 52);

            if (libTokenLen > 0)
                tokenDump("libsed", libsed.data() + 56, libTokenLen);
            if (sedTokenLen > 0)
                tokenDump("sedutil", sedutil.data() + 56, sedTokenLen);

            hexDump("libsed", libsed.data(), libsed.size(), 128);
            hexDump("sedutil", sedutil.data(), sedutil.size(), 128);
        }
    }

    printf("\n========================================\n");
    printf("  Result: %d/%d PASS\n", passed, total);
    printf("========================================\n");

    return (passed == total) ? 0 : 1;
}
