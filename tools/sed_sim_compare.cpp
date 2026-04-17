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

#include "integration/packet_diff.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <iostream>
#include <functional>

using namespace libsed;
using namespace libsed::test;

static constexpr uint16_t COMID = 0x0001;
static constexpr uint32_t HSN   = 105;

// Helper to extract DtaCommand buffer
static Packet extractPacket(DtaCommand& cmd, uint32_t tsn = 0, uint32_t hsn = 0) {
    cmd.setTSN(tsn);
    cmd.setHSN(hsn);
    
    uint8_t* buf = static_cast<uint8_t*>(cmd.getCmdBuffer());
    Packet pkt(buf, buf + 2048);

    auto swapBe32 = [](uint8_t* p) {
        uint8_t t;
        t = p[0]; p[0] = p[3]; p[3] = t;
        t = p[1]; p[1] = p[2]; p[2] = t;
    };
    
    // DtaCommand stores TSN/HSN in host byte order, fix to BE for comparison
    swapBe32(&pkt[20]);  // TSN
    swapBe32(&pkt[24]);  // HSN

    return pkt;
}

void compare(const char* name, const Packet& cats, const Packet& ref) {
    printf("Comparing [%s]: ", name);
    int diffs = diffPackets("cats", cats, ref);
    if (diffs == 0) {
        printf("PASS (Byte-identical)\n");
    } else {
        printf("FAIL (%d differences)\n", diffs);
        dumpFailDiagnostics("cats", "sedutil", cats, ref);
    }
}

// ── Query Sequence ──
void runQuery() {
    printf("\n=== Command: sedutil-cli --query ===\n");

    // 1. Properties
    {
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
        Packet catsPkt = pb.buildSessionManagerPacket(methodTokens);

        DtaCommand cmd;
        cmd.reset(OPAL_SMUID_UID, PROPERTIES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TINY_ATOM::UINT_00);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxComPacketSize"); cmd.addToken((uint64_t)2048); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxPacketSize");    cmd.addToken((uint64_t)2028); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxIndTokenSize"); cmd.addToken((uint64_t)1992); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxPackets");       cmd.addToken((uint64_t)1);    cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxSubpackets");    cmd.addToken((uint64_t)1);    cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxMethods");       cmd.addToken((uint64_t)1);    cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet refPkt = extractPacket(cmd, 0, 0);

        compare("Properties", catsPkt, refPkt);
    }

    // 2. StartSession (anon)
    {
        Bytes params = ParamEncoder::encodeStartSession(HSN, Uid(uid::SP_ADMIN), false, {}, Uid(), Uid());
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
        PacketBuilder pb;
        pb.setComId(COMID);
        Packet catsPkt = pb.buildSessionManagerPacket(methodTokens);

        DtaCommand cmd;
        cmd.reset(OPAL_SMUID_UID, STARTSESSION);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken((uint64_t)HSN);
        cmd.addToken(OPAL_ADMINSP_UID);
        cmd.addToken((uint64_t)0);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet refPkt = extractPacket(cmd, 0, 0);

        compare("StartSession(anon)", catsPkt, refPkt);
    }
}

// ── Initial Setup Sequence ──
void runInitialSetup(const char* password) {
    printf("\n=== Command: sedutil-cli --initialSetup %s ===\n", password);

    // 1. StartSession (SID auth with MSID)
    {
        const char* msid_str = "MSID_01234567890123456789012345";
        Bytes msid_bytes((const uint8_t*)msid_str, (const uint8_t*)msid_str + strlen(msid_str));

        Bytes params = ParamEncoder::encodeStartSession(HSN, Uid(uid::SP_ADMIN), true, msid_bytes, Uid(uid::AUTH_SID), Uid());
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
        PacketBuilder pb;
        pb.setComId(COMID);
        Packet catsPkt = pb.buildSessionManagerPacket(methodTokens);

        DtaCommand cmd;
        cmd.reset(OPAL_SMUID_UID, STARTSESSION);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken((uint64_t)HSN);
        cmd.addToken(OPAL_ADMINSP_UID);
        cmd.addToken((uint64_t)1);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TINY_ATOM::UINT_00); cmd.addToken(msid_str); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TINY_ATOM::UINT_03); cmd.addToken(OPAL_SID_UID); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet refPkt = extractPacket(cmd, 0, 0);

        compare("StartSession(SID+MSID)", catsPkt, refPkt);
    }

    // 2. Set C_PIN_SID
    {
        uint32_t tsn = 123; // assigned by TPer

        TokenList values;
        Bytes newPin((const uint8_t*)password, (const uint8_t*)password + strlen(password));
        values.addBytes(uid::col::PIN, newPin);
        Bytes tokens = MethodCall::buildSet(Uid(uid::CPIN_SID), values);

        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet catsPkt = pb.buildComPacket(tokens);

        DtaCommand cmd;
        cmd.reset(OPAL_C_PIN_SID, SET);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WHERE); cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::VALUES); cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::PIN); cmd.addToken(password); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet refPkt = extractPacket(cmd, tsn, HSN);

        compare("Set(C_PIN_SID)", catsPkt, refPkt);
    }
}

// ── Revert Sequence ──
void runRevert(const char* password) {
    printf("\n=== Command: sedutil-cli --revertTPer %s ===\n", password);

    // RevertSP on AdminSP
    {
        uint32_t tsn = 456;

        Bytes tokens = MethodCall::buildRevertSP(Uid(uid::SP_ADMIN));
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet catsPkt = pb.buildComPacket(tokens);

        DtaCommand cmd;
        cmd.reset(OPAL_ADMINSP_UID, REVERTSP);
        cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet refPkt = extractPacket(cmd, tsn, HSN);

        compare("RevertSP(AdminSP)", catsPkt, refPkt);
    }
}

// ── Range Configuration Sequence ──
void runRangeConfig(const char* password) {
    printf("\n=== Command: sedutil-cli --setLockingRange 1 RW %s ===\n", password);

    // Set Range1 to RW mode
    {
        uint32_t tsn = 789;

        TokenList values;
        values.addUint(uid::col::READ_LOCK_EN, 1);
        values.addUint(uid::col::WRITE_LOCK_EN, 1);
        values.addUint(uid::col::READ_LOCKED, 0);
        values.addUint(uid::col::WRITE_LOCKED, 0);
        Bytes tokens = MethodCall::buildSet(Uid(uid::LOCKING_RANGE1), values);

        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet catsPkt = pb.buildComPacket(tokens);

        DtaCommand cmd;
        // build range UID manually for DtaCommand
        std::vector<uint8_t> rangeUid = {0xA8, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x02}; // Range 1
        std::vector<uint8_t> setMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17};
        cmd.reset(rangeUid, setMethod);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WHERE); cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::VALUES); cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKENABLED); cmd.addToken((uint64_t)1); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKENABLED); cmd.addToken((uint64_t)1); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKED); cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKED); cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet refPkt = extractPacket(cmd, tsn, HSN);

        compare("SetRange(RW)", catsPkt, refPkt);
    }

    // Unlock Range1
    {
        uint32_t tsn = 321;

        TokenList values;
        values.addUint(uid::col::READ_LOCKED, 0);
        values.addUint(uid::col::WRITE_LOCKED, 0);
        Bytes tokens = MethodCall::buildSet(Uid(uid::LOCKING_RANGE1), values);

        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet catsPkt = pb.buildComPacket(tokens);

        DtaCommand cmd;
        std::vector<uint8_t> rangeUid = {0xA8, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x02};
        std::vector<uint8_t> setMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17};
        cmd.reset(rangeUid, setMethod);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WHERE); cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::VALUES); cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKED); cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKED); cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet refPkt = extractPacket(cmd, tsn, HSN);

        compare("UnlockRange", catsPkt, refPkt);
    }
}

int main(int argc, char* argv[]) {
    printf("cats vs sedutil-cli Packet Composition Comparator\n");

    runQuery();
    runInitialSetup("password123");
    runRevert("password123");
    runRangeConfig("password123");

    return 0;
}
