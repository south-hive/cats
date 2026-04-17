#include "common.h"

namespace sed_compare {

Totals& totals() {
    static Totals t;
    return t;
}

Section::Section(const std::string& commandLine) : cmd_(commandLine) {
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║ %-60s ║\n", cmd_.c_str());
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

Section::~Section() {
    if (pass_ + fail_ > 0) {
        if (fail_ == 0) {
            printf("  ✓ %d/%d packets byte-identical\n", pass_, pass_ + fail_);
        } else {
            printf("  ✗ %d/%d packets FAILED\n", fail_, pass_ + fail_);
        }
    }
}

void Section::compare(const std::string& stepName,
                      const Packet& cats, const Packet& ref) {
    ++step_;
    printf("  [%d] %-40s ... ", step_, stepName.c_str());
    int diffs = diffPackets("cats", cats, ref);
    if (diffs == 0) {
        printf("PASS\n");
        ++pass_; ++totals().pass;
    } else {
        printf("FAIL (%d byte diffs)\n", diffs);
        dumpFailDiagnostics("cats", "sedutil", cats, ref);
        ++fail_; ++totals().fail;
    }
}

Packet extractSedutilPacket(DtaCommand& cmd, uint32_t tsn, uint32_t hsn) {
    cmd.setTSN(tsn);
    cmd.setHSN(hsn);

    uint8_t* buf = static_cast<uint8_t*>(cmd.getCmdBuffer());
    Packet pkt(buf, buf + 2048);

    // DtaCommand stores TSN/HSN in host byte order; swap to BE for wire comparison.
    auto swapBe32 = [](uint8_t* p) {
        uint8_t t;
        t = p[0]; p[0] = p[3]; p[3] = t;
        t = p[1]; p[1] = p[2]; p[2] = t;
    };
    swapBe32(&pkt[20]);  // TSN
    swapBe32(&pkt[24]);  // HSN

    return pkt;
}

// ══════════════════════════════════════════════════════
//  Shared step helpers
// ══════════════════════════════════════════════════════

void compareStartSessionAnon(Section& sec, const std::string& stepName,
                             uint64_t spUid, bool write) {
    // libsed
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(spUid), write, {}, Uid(), Uid());
    Bytes tokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
    PacketBuilder pb;
    pb.setComId(COMID);
    Packet cats = pb.buildSessionManagerPacket(tokens);

    // sedutil — mirrors DtaSession::start(OPAL_UID) with no credentials
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)HSN);
    // spUid → map to sedutil OPAL_UID enum at call sites via helpers below
    if (spUid == uid::SP_ADMIN)        cmd.addToken(OPAL_ADMINSP_UID);
    else if (spUid == uid::SP_LOCKING) cmd.addToken(OPAL_LOCKINGSP_UID);
    else { fprintf(stderr, "unsupported SP UID 0x%lx\n", spUid); exit(1); }
    cmd.addToken((uint64_t)(write ? 1 : 0));
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, 0, 0);

    sec.compare(stepName, cats, ref);
}

void compareStartSessionAuth(Section& sec, const std::string& stepName,
                             uint64_t spUid, bool write,
                             const Bytes& challenge, uint64_t authUid) {
    // libsed
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(spUid), write, challenge, Uid(authUid), Uid());
    Bytes tokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
    PacketBuilder pb;
    pb.setComId(COMID);
    Packet cats = pb.buildSessionManagerPacket(tokens);

    // sedutil — DtaSession::start(SP, password, SignAuthority).
    // sedutil encodes challenge as a c-string token. Since we pass raw bytes,
    // we simulate the same by writing the bytes through addToken(const char*)
    // after null-terminating a local buffer.
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)HSN);
    if (spUid == uid::SP_ADMIN)        cmd.addToken(OPAL_ADMINSP_UID);
    else if (spUid == uid::SP_LOCKING) cmd.addToken(OPAL_LOCKINGSP_UID);
    else { fprintf(stderr, "unsupported SP UID 0x%lx\n", spUid); exit(1); }
    cmd.addToken((uint64_t)(write ? 1 : 0));
    // HostChallenge (name=0) + challenge bytes as c-string
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);
    std::string chalStr(reinterpret_cast<const char*>(challenge.data()), challenge.size());
    cmd.addToken(chalStr.c_str());
    cmd.addToken(OPAL_TOKEN::ENDNAME);
    // HostSigningAuthority (name=3) + authority UID
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);
    if (authUid == uid::AUTH_SID)         cmd.addToken(OPAL_SID_UID);
    else if (authUid == uid::AUTH_ADMIN1) cmd.addToken(OPAL_ADMIN1_UID);
    else if (authUid == uid::AUTH_USER1)  cmd.addToken(OPAL_USER1_UID);
    else if (authUid == uid::AUTH_USER2)  cmd.addToken(OPAL_USER2_UID);
    else if (authUid == uid::AUTH_PSID)   cmd.addToken(OPAL_PSID_UID);
    else { fprintf(stderr, "unsupported auth UID 0x%lx\n", authUid); exit(1); }
    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, 0, 0);

    sec.compare(stepName, cats, ref);
}

void compareCloseSession(Section& sec, const std::string& stepName,
                         uint32_t tsn) {
    // libsed: just 0xFA token in a ComPacket with (tsn, hsn).
    TokenEncoder enc;
    enc.endOfSession();
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(enc.data());

    // sedutil — DtaSession::~DtaSession builds:
    //   reset() with NO CALL header, then ENDOFSESSION, complete(0) (no EOD).
    DtaCommand cmd;
    cmd.reset();
    cmd.addToken(OPAL_TOKEN::ENDOFSESSION);
    cmd.complete(0);
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare(stepName, cats, ref);
}

void compareRevertSP(Section& sec, const std::string& stepName,
                     uint32_t tsn, uint64_t spUid) {
    Bytes tokens = MethodCall::buildRevertSP(Uid(spUid));
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    DtaCommand cmd;
    if (spUid == uid::SP_ADMIN)        cmd.reset(OPAL_ADMINSP_UID, REVERTSP);
    else if (spUid == uid::SP_LOCKING) cmd.reset(OPAL_LOCKINGSP_UID, REVERTSP);
    else if (spUid == uid::THIS_SP)    cmd.reset(OPAL_THISSP_UID, REVERTSP);
    else { fprintf(stderr, "unsupported SP UID for RevertSP 0x%lx\n", spUid); exit(1); }
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare(stepName, cats, ref);
}

void compareProperties(Section& sec, const std::string& stepName) {
    ParamEncoder::HostProperties hp;
    hp.maxComPacketSize = 2048;
    hp.maxPacketSize    = 2028;
    hp.maxIndTokenSize  = 1992;
    hp.maxPackets       = 1;
    hp.maxSubPackets    = 1;
    hp.maxMethods       = 1;
    Bytes params = ParamEncoder::encodeProperties(hp);
    Bytes tokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);
    PacketBuilder pb;
    pb.setComId(COMID);
    Packet cats = pb.buildSessionManagerPacket(tokens);

    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, PROPERTIES);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxComPacketSize"); cmd.addToken((uint64_t)2048); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxPacketSize");    cmd.addToken((uint64_t)2028); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxIndTokenSize");  cmd.addToken((uint64_t)1992); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxPackets");       cmd.addToken((uint64_t)1);    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxSubpackets");    cmd.addToken((uint64_t)1);    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxMethods");       cmd.addToken((uint64_t)1);    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, 0, 0);

    sec.compare(stepName, cats, ref);
}

} // namespace sed_compare
