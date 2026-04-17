/// @file ioctl_validator.cpp
/// @brief Offline packet comparison: libsed API vs sedutil manual byte construction
///
/// Validates that libsed's PacketBuilder/MethodCall/ParamEncoder produce
/// byte-identical packets to sedutil's real DtaCommand class for complete
/// TCG command sequences. No hardware required.
///
/// The sedutil side uses actual DtaCommand code from third_party/sedutil/,
/// not a hand-written approximation. This ensures the reference packets
/// are 100% faithful to sedutil's encoding behavior.
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

// Real sedutil DtaCommand — third_party/sedutil/
#include "os.h"
#include "DtaStructures.h"
#include "DtaEndianFixup.h"
#include "DtaCommand.h"

#include "packet_diff.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>

using namespace libsed;
using namespace libsed::test;  // Packet, hexDump, diffPackets, tokenDump

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
// Byte arrays used by libsed side
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

// Null-terminated C string versions for sedutil's DtaCommand::addToken(const char*)
// sedutil always passes passwords as C strings — strlen() determines length.
static const char MSID_CRED_STR[]   = "MSID_CREDENTIAL_0123456789ABCDEF";  // 32 chars
static const char NEW_SID_PIN_STR[] = "new_sid!";                           // 8 chars
static const char ADMIN1_CRED_STR[] = "ADMIN1_CREDENTIAL_0123456789ABCD";  // 32 chars
static const char PSID_CRED_STR[]   = "PSID_CREDENTIAL_0123456789ABCDEF";  // 32 chars

// ═══════════════════════════════════════════════════════
//  Helper: extract DtaCommand buffer as a 2048-byte Packet
//  (matches libsed's PacketBuilder output size)
// ═══════════════════════════════════════════════════════

static Packet extractPacket(DtaCommand& cmd) {
    uint8_t* buf = static_cast<uint8_t*>(cmd.getCmdBuffer());
    Packet pkt(buf, buf + MIN_BUFFER_LENGTH);

    // Fix TSN/HSN byte order: DtaCommand::setTSN/setHSN store in host byte order
    // (LE on x86) without SWAP32. TCG Core Spec requires big-endian for Packet
    // header fields. Fix by swapping to BE for comparison with libsed.
    // Packet header starts at offset 20 (after 20-byte ComPacket header):
    //   offset 20-23: TSN (4 bytes)
    //   offset 24-27: HSN (4 bytes)
    auto swapBe32 = [](uint8_t* p) {
        uint8_t t;
        t = p[0]; p[0] = p[3]; p[3] = t;
        t = p[1]; p[1] = p[2]; p[2] = t;
    };
    swapBe32(&pkt[20]);  // TSN
    swapBe32(&pkt[24]);  // HSN

    return pkt;
}

/// Build a Locking Range N UID vector (with 0xA8 atom header) for DtaCommand::reset(vector, vector)
/// sedutil builds range UIDs from OPAL_LOCKINGRANGE_GLOBAL by modifying the last byte.
static std::vector<uint8_t> buildLockingRangeUid(int rangeNum) {
    std::vector<uint8_t> uid;
    uid.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
    for (int i = 0; i < 8; i++)
        uid.push_back(OPALUID[OPAL_LOCKINGRANGE_GLOBAL][i]);
    uid[8] = static_cast<uint8_t>(rangeNum + 1);  // Range 1 → 0x02, Range 2 → 0x03, etc.
    return uid;
}

/// Build a method UID vector (with 0xA8 atom header) for DtaCommand::reset(vector, vector)
static std::vector<uint8_t> buildMethodUid(OPAL_METHOD method) {
    std::vector<uint8_t> m;
    m.push_back(OPAL_SHORT_ATOM::BYTESTRING8);
    for (int i = 0; i < 8; i++)
        m.push_back(OPALMETHOD[method][i]);
    return m;
}

// Shared utilities (hexDump, headerFieldName, diffPackets, tokenDump)
// are now in packet_diff.h — included above via "packet_diff.h"

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
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, PROPERTIES);

    // Real sedutil-cli wraps HostProperties with STARTNAME uint(0) STARTLIST
    // (confirmed via hex dump: F2 00 F0 ... F1 F3)
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);   // numeric key 0
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxComPacketSize");
    cmd.addToken((uint64_t)2048);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxPacketSize");
    cmd.addToken((uint64_t)2028);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxIndTokenSize");
    cmd.addToken((uint64_t)1992);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxPackets");
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxSubpackets");
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxMethods");
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);  // close inner STARTLIST
    cmd.addToken(OPAL_TOKEN::ENDNAME);  // close STARTNAME uint(0)

    cmd.addToken(OPAL_TOKEN::ENDLIST);  // close outer STARTLIST

    cmd.complete();
    cmd.setcomID(COMID);
    // SM packets: TSN=0, HSN=0 (already zero from reset)

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)HSN);               // HostSessionID = 105
    cmd.addToken(OPAL_ADMINSP_UID);            // SP UID
    cmd.addToken((uint64_t)0);                 // Write = false (read-only)
    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_C_PIN_MSID, GET);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::STARTCOLUMN);     // key = 0x03 (startColumn)
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);     // value: PIN column
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::ENDCOLUMN);       // key = 0x04 (endColumn)
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);     // value: PIN column
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_A);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset();
    cmd.addToken(OPAL_TOKEN::ENDOFSESSION);
    cmd.complete(0);                           // No EOD, no status list
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_A);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)HSN);               // HostSessionID = 105
    cmd.addToken(OPAL_ADMINSP_UID);            // SP UID
    cmd.addToken((uint64_t)1);                 // Write = true

    // Named param 0: HostChallenge = MSID credential
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);     // index 0 = HostChallenge
    cmd.addToken(MSID_CRED_STR);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    // Named param 3: HostExchangeAuthority = AUTH_SID
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);     // index 3 = HostExchangeAuthority
    cmd.addToken(OPAL_SID_UID);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);

    return extractPacket(cmd);
}

// ── B.2: Set C_PIN_SID = new password (in-session, TSN=2/HSN=105) ──
// sedutil: setTable(C_PIN_SID, PIN_COL, newPIN)
// Method: SET with Values only (no Where — row is identified by invoking UID)

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
    DtaCommand cmd;
    cmd.reset(OPAL_C_PIN_SID, SET);

    cmd.addToken(OPAL_TOKEN::STARTLIST);

    // Values only — no empty Where (row identified by invoking UID per TCG §5.3.3)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::VALUES);          // key = 0x01 (Values)
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    // PIN column = new password
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::PIN);             // column 3
    cmd.addToken(NEW_SID_PIN_STR);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_B);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset();
    cmd.addToken(OPAL_TOKEN::ENDOFSESSION);
    cmd.complete(0);
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_B);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)HSN);
    cmd.addToken(OPAL_ADMINSP_UID);
    cmd.addToken((uint64_t)1);                 // Write = true

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);     // HostChallenge
    cmd.addToken(NEW_SID_PIN_STR);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);     // HostExchangeAuthority
    cmd.addToken(OPAL_SID_UID);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_LOCKINGSP_UID, ACTIVATE);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_C);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset();
    cmd.addToken(OPAL_TOKEN::ENDOFSESSION);
    cmd.complete(0);
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_C);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)HSN);
    cmd.addToken(OPAL_LOCKINGSP_UID);          // SP_LOCKING
    cmd.addToken((uint64_t)1);                 // Write = true

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);     // HostChallenge
    cmd.addToken(ADMIN1_CRED_STR);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);     // HostExchangeAuthority
    cmd.addToken(OPAL_ADMIN1_UID);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);

    return extractPacket(cmd);
}

// ── D.2: Set Range1 config (in-session, TSN=4/HSN=105) ──
// AppNote 5: Configure range start/length + enable read/write lock
// SET on Locking Range 1 with columns: RangeStart(3), RangeLength(4),
//   ReadLockEnabled(5), WriteLockEnabled(6) — Values only, no empty Where

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
    auto rangeUid = buildLockingRangeUid(1);
    auto setMethod = buildMethodUid(SET);
    DtaCommand cmd;
    cmd.reset(rangeUid, setMethod);

    cmd.addToken(OPAL_TOKEN::STARTLIST);

    // Values only — no empty Where (row identified by invoking UID per TCG §5.3.3)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::VALUES);
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    // RangeStart = 0 (col 3)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::RANGESTART);
    cmd.addToken((uint64_t)0);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    // RangeLength = 1048576 (col 4)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::RANGELENGTH);
    cmd.addToken((uint64_t)1048576);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    // ReadLockEnabled = true (col 5)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::READLOCKENABLED);
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    // WriteLockEnabled = true (col 6)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::WRITELOCKENABLED);
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_D);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
}

// ── D.3: Set Range1 lock (in-session, TSN=4/HSN=105) ──
// AppNote 8: Lock the range by setting ReadLocked=true, WriteLocked=true
// Same session as D.2 — sequential command — Values only, no empty Where

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
    auto rangeUid = buildLockingRangeUid(1);
    auto setMethod = buildMethodUid(SET);
    DtaCommand cmd;
    cmd.reset(rangeUid, setMethod);

    cmd.addToken(OPAL_TOKEN::STARTLIST);

    // Values only — no empty Where (row identified by invoking UID per TCG §5.3.3)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::VALUES);
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    // ReadLocked = true (col 7)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::READLOCKED);
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    // WriteLocked = true (col 8)
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::WRITELOCKED);
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_D);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset();
    cmd.addToken(OPAL_TOKEN::ENDOFSESSION);
    cmd.complete(0);
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_D);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)HSN);
    cmd.addToken(OPAL_ADMINSP_UID);
    cmd.addToken((uint64_t)1);                 // Write = true

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);     // HostChallenge
    cmd.addToken(PSID_CRED_STR);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);     // HostExchangeAuthority
    cmd.addToken(OPAL_PSID_UID);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset(OPAL_ADMINSP_UID, REVERTSP);

    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.complete();
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_E);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
    DtaCommand cmd;
    cmd.reset();
    cmd.addToken(OPAL_TOKEN::ENDOFSESSION);
    cmd.complete(0);
    cmd.setcomID(COMID);
    cmd.setTSN(TSN_E);
    cmd.setHSN(HSN);

    return extractPacket(cmd);
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
                dumpFailDiagnostics("libsed", "sedutil", libsed, sedutil);
            }
        }

        printf("  ── %s result: %d/%d ──\n\n", seq.name, seqPassed, seqTotal);
    }

    printf("════════════════════════════════════════\n");
    printf("  Total: %d/%d PASS\n", totalPassed, totalTests);
    printf("════════════════════════════════════════\n");

    return (totalPassed == totalTests) ? 0 : 1;
}
