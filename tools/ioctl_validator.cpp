/// @file ioctl_validator.cpp
/// @brief Offline packet comparison: libsed API vs sedutil manual byte construction
///
/// Validates that libsed's PacketBuilder/MethodCall/ParamEncoder produce
/// byte-identical packets to sedutil's DtaCommand/DtaDevOpal for complete
/// TCG command sequences. No hardware required.
///
/// Tests are organized as real TCG protocol sequences following the
/// Application Note flow (AppNote 3-13), not isolated commands:
///
///   Sequence A: Query Flow (sedutil --query)
///     Properties → StartSession(AdminSP, RO) → Get(MSID) → CloseSession
///
///   Sequence B: Take Ownership (AppNote 3)
///     StartSession(AdminSP, RW, SID+MSID) → Set(C_PIN_SID) → CloseSession
///
///   Sequence C: Activate Locking SP (AppNote 4)
///     StartSession(AdminSP, RW, SID) → Activate(LockingSP) → CloseSession
///
///   Sequence D: Configure + Lock Range (AppNote 5, 8)
///     StartSession(LockingSP, RW, Admin1) → Set(Range lock) → CloseSession
///
///   Sequence E: Revert (AppNote 13)
///     StartSession(AdminSP, RW, PSID) → RevertSP → CloseSession
///
/// Session number progression:
///   SM packets (Properties, StartSession): header TSN=0, HSN=0
///   After SyncSession: TPer assigns TSN (1,2,3,...), confirms HSN
///   In-session packets: use assigned TSN/HSN
///   Each new session gets next TSN from TPer
///
/// Usage: ./ioctl_validator

#include <libsed/codec/token_encoder.h>
#include <libsed/codec/token_list.h>
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
//  Constants — matching sedutil defaults
// ═══════════════════════════════════════════════════════

static constexpr uint16_t COMID = 0x0001;
static constexpr uint32_t HSN   = 105;    // sedutil hardcoded host session number

// TPer-assigned session numbers (simulated sequential assignment)
// Each new StartSession gets the next TSN from the TPer.
static constexpr uint32_t TSN_A = 1;  // Sequence A: Query session
static constexpr uint32_t TSN_B = 2;  // Sequence B: Take Ownership session
static constexpr uint32_t TSN_C = 3;  // Sequence C: Activate session
static constexpr uint32_t TSN_D = 4;  // Sequence D: Lock/Unlock session
static constexpr uint32_t TSN_E = 5;  // Sequence E: Revert session

// Dummy credentials for testing encoding (not real passwords)
static const uint8_t MSID_CRED[32] = {
    0x4D, 0x53, 0x49, 0x44, 0x5F, 0x43, 0x52, 0x45,  // "MSID_CRE"
    0x44, 0x45, 0x4E, 0x54, 0x49, 0x41, 0x4C, 0x5F,  // "DENTIAL_"
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  // "01234567"
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46   // "89ABCDEF"
};
static const uint8_t NEW_SID_PIN[8] = {
    0x6E, 0x65, 0x77, 0x5F, 0x73, 0x69, 0x64, 0x21   // "new_sid!"
};
static const uint8_t ADMIN1_CRED[32] = {
    0x41, 0x44, 0x4D, 0x49, 0x4E, 0x31, 0x5F, 0x43,  // "ADMIN1_C"
    0x52, 0x45, 0x44, 0x45, 0x4E, 0x54, 0x49, 0x41,  // "REDENTIA"
    0x4C, 0x5F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,  // "L_012345"
    0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44   // "6789ABCD"
};
static const uint8_t PSID_CRED[32] = {
    0x50, 0x53, 0x49, 0x44, 0x5F, 0x43, 0x52, 0x45,  // "PSID_CRE"
    0x44, 0x45, 0x4E, 0x54, 0x49, 0x41, 0x4C, 0x5F,  // "DENTIAL_"
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  // "01234567"
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46   // "89ABCDEF"
};

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

// ╔═══════════════════════════════════════════════════════╗
// ║  Sequence A: Query Flow (sedutil --query)             ║
// ║                                                       ║
// ║  This is the most basic TCG flow. No authentication.  ║
// ║  Properties → StartSession(RO) → Get(MSID) → Close   ║
// ║                                                       ║
// ║  SM packets: TSN=0, HSN=0 (session manager level)     ║
// ║  After SyncSession: TSN=1, HSN=105 (TPer assigns)    ║
// ╚═══════════════════════════════════════════════════════╝

// ── A.1: Properties Exchange (SM level, TSN=0/HSN=0) ──

static Packet buildLibsed_A1_Properties() {
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

static Packet buildSedutil_A1_Properties() {
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

    return w.complete(COMID, 0, 0);            // SM: TSN=0, HSN=0
}

// ── A.2: StartSession unauthenticated to AdminSP (SM level) ──
// sedutil: DtaDevOpal::start(OPAL_UID::SP_ADMIN, password=NULL, OPAL_UID::OPAL_SID_UID)
// Packet header: TSN=0, HSN=0 (still at session manager)
// Method param: HostSessionID=105, SP=AdminSP, Write=false

static Packet buildLibsed_A2_StartSessionAnon() {
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), false, {}, Uid(), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutil_A2_StartSessionAnon() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);                      // SMUID
    w.addUid(method::SM_START_SESSION);        // SM_START_SESSION

    w.addByte(0xF0);                           // STARTLIST
    w.addUint(HSN);                            // HostSessionID = 105
    w.addUid(uid::SP_ADMIN);                   // SP UID
    w.addUint(0);                              // Write = false (read-only)
    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);            // SM: TSN=0, HSN=0
}

// ── A.3: Get C_PIN_MSID (in-session, TSN=1/HSN=105) ──
// After SyncSession: TPer assigned TSN=1, confirmed HSN=105
// sedutil: DtaDevOpal::getTable(..., CPIN_MSID, PIN)

static Packet buildLibsed_A3_GetMsid() {
    CellBlock cb;
    cb.startColumn = 3;  // PIN column
    cb.endColumn   = 3;

    Bytes methodTokens = MethodCall::buildGet(Uid(uid::CPIN_MSID), cb);

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_A, HSN);          // TSN=1, HSN=105
    return pb.buildComPacket(methodTokens);
}

static Packet buildSedutil_A3_GetMsid() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::CPIN_MSID);                 // Invoking: C_PIN_MSID row
    w.addUid(method::GET);                     // Method: Get

    w.addByte(0xF0);                           // STARTLIST (outer param list)
    w.addByte(0xF0);                           // STARTLIST (CellBlock)

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // key: startColumn
    w.addUint(3);                              // value: PIN column
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(1);                              // key: endColumn
    w.addUint(3);                              // value: PIN column
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST (CellBlock)
    w.addByte(0xF1);                           // ENDLIST (outer)

    return w.complete(COMID, TSN_A, HSN);      // TSN=1, HSN=105
}

// ── A.4: CloseSession (in-session, TSN=1/HSN=105) ──
// Just EndOfSession token — no CALL/EOD/status
// After this, session TSN=1 is dead

static Packet buildLibsed_A4_CloseSession() {
    TokenEncoder enc;
    enc.endOfSession();

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_A, HSN);          // TSN=1, HSN=105
    return pb.buildComPacket(enc.data());
}

static Packet buildSedutil_A4_CloseSession() {
    SedutilPacketWriter w;
    w.addByte(0xFA);  // EndOfSession — no EOD, no status list
    return w.completeNoEod(COMID, TSN_A, HSN); // TSN=1, HSN=105
}

// ╔═══════════════════════════════════════════════════════╗
// ║  Sequence B: Take Ownership (AppNote 3)               ║
// ║                                                       ║
// ║  After reading MSID in Sequence A, change SID PIN.    ║
// ║  Requires authenticated write session to AdminSP.     ║
// ║                                                       ║
// ║  StartSession(AdminSP, RW, SID+MSID) →               ║
// ║    Set(C_PIN_SID, newPIN) → CloseSession              ║
// ║                                                       ║
// ║  New session: TPer assigns TSN=2, HSN=105             ║
// ╚═══════════════════════════════════════════════════════╝

// ── B.1: StartSession with SID auth using MSID credential (SM level) ──
// sedutil: start(AdminSP, MSID_credential, AUTH_SID)
// HostChallenge = MSID (named param 0), HostExchangeAuthority = AUTH_SID (named param 3)

static Packet buildLibsed_B1_StartSessionAuth() {
    Bytes msid(MSID_CRED, MSID_CRED + 32);
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), true, msid, Uid(uid::AUTH_SID), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutil_B1_StartSessionAuth() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);                      // SMUID
    w.addUid(method::SM_START_SESSION);        // SM_START_SESSION

    w.addByte(0xF0);                           // STARTLIST
    w.addUint(HSN);                            // HostSessionID = 105
    w.addUid(uid::SP_ADMIN);                   // SP UID
    w.addUint(1);                              // Write = true

    // Named param 0: HostChallenge = MSID credential
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // index 0 = HostChallenge
    w.addBytes(MSID_CRED, 32);
    w.addByte(0xF3);                           // ENDNAME

    // Named param 3: HostExchangeAuthority = AUTH_SID
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(3);                              // index 3 = HostExchangeAuthority
    w.addUid(uid::AUTH_SID);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);            // SM: TSN=0, HSN=0
}

// ── B.2: Set C_PIN_SID = new password (in-session, TSN=2/HSN=105) ──
// sedutil: setTable(C_PIN_SID, PIN_COL, newPIN)
// Method: SET with Where (empty) + Values { PIN: newPIN }

static Packet buildLibsed_B2_SetSidPin() {
    TokenList values;
    Bytes newPin(NEW_SID_PIN, NEW_SID_PIN + 8);
    values.addBytes(uid::col::PIN, newPin);

    Bytes tokens = MethodCall::buildSet(Uid(uid::CPIN_SID), values);

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_B, HSN);          // TSN=2, HSN=105
    return pb.buildComPacket(tokens);
}

static Packet buildSedutil_B2_SetSidPin() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::CPIN_SID);                  // Invoking: C_PIN_SID
    w.addUid(method::SET);                     // Method: Set

    w.addByte(0xF0);                           // STARTLIST (params)

    // Where (empty) — required by sedutil convention
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // key: Where
    w.addByte(0xF0);                           // STARTLIST (empty)
    w.addByte(0xF1);                           // ENDLIST
    w.addByte(0xF3);                           // ENDNAME

    // Values
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(1);                              // key: Values
    w.addByte(0xF0);                           // STARTLIST

    // PIN column = new password
    w.addByte(0xF2);                           // STARTNAME
    w.addUint(uid::col::PIN);                  // column 3
    w.addBytes(NEW_SID_PIN, 8);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST (Values)
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST (params)

    return w.complete(COMID, TSN_B, HSN);      // TSN=2, HSN=105
}

// ── B.3: CloseSession (in-session, TSN=2/HSN=105) ──
// Session TSN=2 is now dead. SID password has been changed.

static Packet buildLibsed_B3_CloseSession() {
    TokenEncoder enc;
    enc.endOfSession();

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_B, HSN);          // TSN=2, HSN=105
    return pb.buildComPacket(enc.data());
}

static Packet buildSedutil_B3_CloseSession() {
    SedutilPacketWriter w;
    w.addByte(0xFA);
    return w.completeNoEod(COMID, TSN_B, HSN); // TSN=2, HSN=105
}

// ╔═══════════════════════════════════════════════════════╗
// ║  Sequence C: Activate Locking SP (AppNote 4)          ║
// ║                                                       ║
// ║  After taking ownership, activate Locking SP.         ║
// ║  Requires SID auth to AdminSP with new password.      ║
// ║                                                       ║
// ║  StartSession(AdminSP, RW, SID+newPW) →               ║
// ║    Activate(LockingSP) → CloseSession                 ║
// ║                                                       ║
// ║  New session: TPer assigns TSN=3, HSN=105             ║
// ╚═══════════════════════════════════════════════════════╝

// ── C.1: StartSession auth as SID (SM level) ──
// Uses the new SID password set in Sequence B

static Packet buildLibsed_C1_StartSessionSid() {
    Bytes sidCred(NEW_SID_PIN, NEW_SID_PIN + 8);
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), true, sidCred, Uid(uid::AUTH_SID), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutil_C1_StartSessionSid() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);
    w.addUid(method::SM_START_SESSION);

    w.addByte(0xF0);                           // STARTLIST
    w.addUint(HSN);                            // HostSessionID = 105
    w.addUid(uid::SP_ADMIN);                   // SP UID
    w.addUint(1);                              // Write = true

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // HostChallenge
    w.addBytes(NEW_SID_PIN, 8);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(3);                              // HostExchangeAuthority
    w.addUid(uid::AUTH_SID);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);            // SM: TSN=0, HSN=0
}

// ── C.2: Activate Locking SP (in-session, TSN=3/HSN=105) ──
// sedutil: DtaDevOpal::activate(LockingSP)
// No parameters — just CALL + empty param list

static Packet buildLibsed_C2_Activate() {
    Bytes tokens = MethodCall::buildActivate(Uid(uid::SP_LOCKING));

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_C, HSN);          // TSN=3, HSN=105
    return pb.buildComPacket(tokens);
}

static Packet buildSedutil_C2_Activate() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SP_LOCKING);                // Invoking: Locking SP
    w.addUid(method::ACTIVATE);                // Method: Activate

    w.addByte(0xF0);                           // STARTLIST (empty params)
    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, TSN_C, HSN);      // TSN=3, HSN=105
}

// ── C.3: CloseSession (in-session, TSN=3/HSN=105) ──

static Packet buildLibsed_C3_CloseSession() {
    TokenEncoder enc;
    enc.endOfSession();

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_C, HSN);
    return pb.buildComPacket(enc.data());
}

static Packet buildSedutil_C3_CloseSession() {
    SedutilPacketWriter w;
    w.addByte(0xFA);
    return w.completeNoEod(COMID, TSN_C, HSN);
}

// ╔═══════════════════════════════════════════════════════╗
// ║  Sequence D: Configure + Lock Range (AppNote 5, 8)    ║
// ║                                                       ║
// ║  After Locking SP is active, configure and lock a     ║
// ║  range. Requires Admin1 auth to Locking SP.           ║
// ║                                                       ║
// ║  StartSession(LockingSP, RW, Admin1) →                ║
// ║    Set(Range1 config) → Set(Range lock) →             ║
// ║    CloseSession                                       ║
// ║                                                       ║
// ║  New session: TPer assigns TSN=4, HSN=105             ║
// ╚═══════════════════════════════════════════════════════╝

// ── D.1: StartSession auth as Admin1 to LockingSP (SM level) ──

static Packet buildLibsed_D1_StartSessionAdmin1() {
    Bytes admin1Cred(ADMIN1_CRED, ADMIN1_CRED + 32);
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_LOCKING), true, admin1Cred, Uid(uid::AUTH_ADMIN1), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutil_D1_StartSessionAdmin1() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);
    w.addUid(method::SM_START_SESSION);

    w.addByte(0xF0);                           // STARTLIST
    w.addUint(HSN);                            // HostSessionID = 105
    w.addUid(uid::SP_LOCKING);                // SP_LOCKING
    w.addUint(1);                              // Write = true

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // HostChallenge
    w.addBytes(ADMIN1_CRED, 32);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(3);                              // HostExchangeAuthority
    w.addUid(uid::AUTH_ADMIN1);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);            // SM: TSN=0, HSN=0
}

// ── D.2: Set Range1 config (in-session, TSN=4/HSN=105) ──
// AppNote 5: Configure range start/length + enable read/write lock
// SET on Locking Range 1 with columns: RangeStart(3), RangeLength(4),
//   ReadLockEnabled(5), WriteLockEnabled(6)

static Packet buildLibsed_D2_SetRangeConfig() {
    TokenList values;
    values.addUint(uid::col::RANGE_START, 0);
    values.addUint(uid::col::RANGE_LENGTH, 1048576);  // 1M sectors
    values.addUint(uid::col::READ_LOCK_EN, 1);
    values.addUint(uid::col::WRITE_LOCK_EN, 1);

    Bytes tokens = MethodCall::buildSet(Uid(uid::LOCKING_RANGE1), values);

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_D, HSN);          // TSN=4, HSN=105
    return pb.buildComPacket(tokens);
}

static Packet buildSedutil_D2_SetRangeConfig() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::LOCKING_RANGE1);            // Invoking: Locking Range 1
    w.addUid(method::SET);                     // Method: Set

    w.addByte(0xF0);                           // STARTLIST (params)

    // Where (empty)
    w.addByte(0xF2); w.addUint(0);
    w.addByte(0xF0); w.addByte(0xF1);
    w.addByte(0xF3);

    // Values
    w.addByte(0xF2); w.addUint(1);
    w.addByte(0xF0);

    // RangeStart = 0 (col 3)
    w.addByte(0xF2); w.addUint(uid::col::RANGE_START);
    w.addUint(0);
    w.addByte(0xF3);

    // RangeLength = 1048576 (col 4)
    w.addByte(0xF2); w.addUint(uid::col::RANGE_LENGTH);
    w.addUint(1048576);
    w.addByte(0xF3);

    // ReadLockEnabled = true (col 5)
    w.addByte(0xF2); w.addUint(uid::col::READ_LOCK_EN);
    w.addUint(1);
    w.addByte(0xF3);

    // WriteLockEnabled = true (col 6)
    w.addByte(0xF2); w.addUint(uid::col::WRITE_LOCK_EN);
    w.addUint(1);
    w.addByte(0xF3);

    w.addByte(0xF1);                           // ENDLIST (Values)
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST (params)

    return w.complete(COMID, TSN_D, HSN);      // TSN=4, HSN=105
}

// ── D.3: Set Range1 lock (in-session, TSN=4/HSN=105) ──
// AppNote 8: Lock the range by setting ReadLocked=true, WriteLocked=true
// Same session as D.2 — sequential command

static Packet buildLibsed_D3_SetRangeLock() {
    TokenList values;
    values.addUint(uid::col::READ_LOCKED, 1);
    values.addUint(uid::col::WRITE_LOCKED, 1);

    Bytes tokens = MethodCall::buildSet(Uid(uid::LOCKING_RANGE1), values);

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_D, HSN);          // TSN=4, HSN=105 (same session)
    return pb.buildComPacket(tokens);
}

static Packet buildSedutil_D3_SetRangeLock() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::LOCKING_RANGE1);            // Invoking: Locking Range 1
    w.addUid(method::SET);                     // Method: Set

    w.addByte(0xF0);                           // STARTLIST (params)

    // Where (empty)
    w.addByte(0xF2); w.addUint(0);
    w.addByte(0xF0); w.addByte(0xF1);
    w.addByte(0xF3);

    // Values
    w.addByte(0xF2); w.addUint(1);
    w.addByte(0xF0);

    // ReadLocked = true (col 7)
    w.addByte(0xF2); w.addUint(uid::col::READ_LOCKED);
    w.addUint(1);
    w.addByte(0xF3);

    // WriteLocked = true (col 8)
    w.addByte(0xF2); w.addUint(uid::col::WRITE_LOCKED);
    w.addUint(1);
    w.addByte(0xF3);

    w.addByte(0xF1);                           // ENDLIST (Values)
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST (params)

    return w.complete(COMID, TSN_D, HSN);      // TSN=4, HSN=105
}

// ── D.4: CloseSession (in-session, TSN=4/HSN=105) ──

static Packet buildLibsed_D4_CloseSession() {
    TokenEncoder enc;
    enc.endOfSession();

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_D, HSN);
    return pb.buildComPacket(enc.data());
}

static Packet buildSedutil_D4_CloseSession() {
    SedutilPacketWriter w;
    w.addByte(0xFA);
    return w.completeNoEod(COMID, TSN_D, HSN);
}

// ╔═══════════════════════════════════════════════════════╗
// ║  Sequence E: PSID Revert (AppNote 13)                 ║
// ║                                                       ║
// ║  Factory reset via PSID (physical label on drive).    ║
// ║  Used when SID password is lost.                      ║
// ║                                                       ║
// ║  StartSession(AdminSP, RW, PSID) →                   ║
// ║    RevertSP(AdminSP) → CloseSession                   ║
// ║                                                       ║
// ║  New session: TPer assigns TSN=5, HSN=105             ║
// ╚═══════════════════════════════════════════════════════╝

// ── E.1: StartSession auth as PSID (SM level) ──

static Packet buildLibsed_E1_StartSessionPsid() {
    Bytes psidCred(PSID_CRED, PSID_CRED + 32);
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), true, psidCred, Uid(uid::AUTH_PSID), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildSedutil_E1_StartSessionPsid() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SMUID);
    w.addUid(method::SM_START_SESSION);

    w.addByte(0xF0);                           // STARTLIST
    w.addUint(HSN);                            // HostSessionID = 105
    w.addUid(uid::SP_ADMIN);
    w.addUint(1);                              // Write = true

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(0);                              // HostChallenge
    w.addBytes(PSID_CRED, 32);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF2);                           // STARTNAME
    w.addUint(3);                              // HostExchangeAuthority
    w.addUid(uid::AUTH_PSID);
    w.addByte(0xF3);                           // ENDNAME

    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, 0, 0);            // SM: TSN=0, HSN=0
}

// ── E.2: RevertSP on AdminSP (in-session, TSN=5/HSN=105) ──
// sedutil: DtaDevOpal::revertTPer() → RevertSP on AdminSP
// No parameters — just CALL + empty param list

static Packet buildLibsed_E2_RevertSP() {
    Bytes tokens = MethodCall::buildRevertSP(Uid(uid::SP_ADMIN));

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_E, HSN);          // TSN=5, HSN=105
    return pb.buildComPacket(tokens);
}

static Packet buildSedutil_E2_RevertSP() {
    SedutilPacketWriter w;

    w.addByte(0xF8);                           // CALL
    w.addUid(uid::SP_ADMIN);                  // Invoking: Admin SP
    w.addUid(method::REVERTSP);                // Method: RevertSP

    w.addByte(0xF0);                           // STARTLIST (empty params)
    w.addByte(0xF1);                           // ENDLIST

    return w.complete(COMID, TSN_E, HSN);      // TSN=5, HSN=105
}

// ── E.3: CloseSession (in-session, TSN=5/HSN=105) ──
// Note: After RevertSP, the TPer may close the session automatically.
// But the host still sends CloseSession for proper protocol termination.

static Packet buildLibsed_E3_CloseSession() {
    TokenEncoder enc;
    enc.endOfSession();

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_E, HSN);
    return pb.buildComPacket(enc.data());
}

static Packet buildSedutil_E3_CloseSession() {
    SedutilPacketWriter w;
    w.addByte(0xFA);
    return w.completeNoEod(COMID, TSN_E, HSN);
}

// ═══════════════════════════════════════════════════════
//  Main runner
// ═══════════════════════════════════════════════════════

int main() {
    struct Sequence {
        const char* name;
        const char* description;
        std::vector<TestCase> steps;
    };

    Sequence sequences[] = {
        { "A", "Query Flow (sedutil --query): Properties → StartSession(RO) → Get(MSID) → Close", {
            { "A.1 Properties (SM, TSN=0/HSN=0)",
              buildLibsed_A1_Properties, buildSedutil_A1_Properties },
            { "A.2 StartSession anon AdminSP (SM, TSN=0/HSN=0)",
              buildLibsed_A2_StartSessionAnon, buildSedutil_A2_StartSessionAnon },
            { "A.3 Get C_PIN_MSID (TSN=1/HSN=105)",
              buildLibsed_A3_GetMsid, buildSedutil_A3_GetMsid },
            { "A.4 CloseSession (TSN=1/HSN=105)",
              buildLibsed_A4_CloseSession, buildSedutil_A4_CloseSession },
        }},
        { "B", "Take Ownership (AppNote 3): StartSession(SID+MSID) → Set(C_PIN_SID) → Close", {
            { "B.1 StartSession SID auth+MSID (SM, TSN=0/HSN=0)",
              buildLibsed_B1_StartSessionAuth, buildSedutil_B1_StartSessionAuth },
            { "B.2 Set C_PIN_SID new password (TSN=2/HSN=105)",
              buildLibsed_B2_SetSidPin, buildSedutil_B2_SetSidPin },
            { "B.3 CloseSession (TSN=2/HSN=105)",
              buildLibsed_B3_CloseSession, buildSedutil_B3_CloseSession },
        }},
        { "C", "Activate Locking SP (AppNote 4): StartSession(SID) → Activate → Close", {
            { "C.1 StartSession SID auth (SM, TSN=0/HSN=0)",
              buildLibsed_C1_StartSessionSid, buildSedutil_C1_StartSessionSid },
            { "C.2 Activate Locking SP (TSN=3/HSN=105)",
              buildLibsed_C2_Activate, buildSedutil_C2_Activate },
            { "C.3 CloseSession (TSN=3/HSN=105)",
              buildLibsed_C3_CloseSession, buildSedutil_C3_CloseSession },
        }},
        { "D", "Configure + Lock Range (AppNote 5,8): StartSession(Admin1) → SetRange → Lock → Close", {
            { "D.1 StartSession Admin1 to LockingSP (SM, TSN=0/HSN=0)",
              buildLibsed_D1_StartSessionAdmin1, buildSedutil_D1_StartSessionAdmin1 },
            { "D.2 Set Range1 config (TSN=4/HSN=105)",
              buildLibsed_D2_SetRangeConfig, buildSedutil_D2_SetRangeConfig },
            { "D.3 Set Range1 lock (TSN=4/HSN=105, same session)",
              buildLibsed_D3_SetRangeLock, buildSedutil_D3_SetRangeLock },
            { "D.4 CloseSession (TSN=4/HSN=105)",
              buildLibsed_D4_CloseSession, buildSedutil_D4_CloseSession },
        }},
        { "E", "PSID Revert (AppNote 13): StartSession(PSID) → RevertSP → Close", {
            { "E.1 StartSession PSID auth (SM, TSN=0/HSN=0)",
              buildLibsed_E1_StartSessionPsid, buildSedutil_E1_StartSessionPsid },
            { "E.2 RevertSP AdminSP (TSN=5/HSN=105)",
              buildLibsed_E2_RevertSP, buildSedutil_E2_RevertSP },
            { "E.3 CloseSession (TSN=5/HSN=105)",
              buildLibsed_E3_CloseSession, buildSedutil_E3_CloseSession },
        }},
    };

    int totalTests = 0;
    int totalPassed = 0;
    int seqCount = static_cast<int>(sizeof(sequences) / sizeof(sequences[0]));

    printf("ioctl_validator: TCG command sequence comparison (libsed vs sedutil)\n");
    printf("ComID=0x%04X  HSN=%u  Sessions: A(TSN=%u) B(TSN=%u) C(TSN=%u) D(TSN=%u) E(TSN=%u)\n\n",
           COMID, HSN, TSN_A, TSN_B, TSN_C, TSN_D, TSN_E);

    for (int s = 0; s < seqCount; s++) {
        auto& seq = sequences[s];
        printf("── Sequence %s: %s ──\n", seq.name, seq.description);

        int seqPassed = 0;
        int seqTotal = static_cast<int>(seq.steps.size());

        for (int i = 0; i < seqTotal; i++) {
            auto& t = seq.steps[i];
            totalTests++;

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
                printf("  [PASS] %s\n", t.name);
                seqPassed++;
                totalPassed++;
            } else {
                printf("  [FAIL] %s\n", t.name);
                diffPackets(libsed, sedutil);

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

        printf("  ── %s result: %d/%d ──\n\n", seq.name, seqPassed, seqTotal);
    }

    printf("════════════════════════════════════════\n");
    printf("  Total: %d/%d PASS\n", totalPassed, totalTests);
    printf("════════════════════════════════════════\n");

    return (totalPassed == totalTests) ? 0 : 1;
}
