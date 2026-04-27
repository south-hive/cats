// sedutil-cli --setLockingRange <n> <RW|RO|LK> <password>
//
// Sedutil flow (DtaDevOpal::setLockingRange):
//   1. StartSession(LockingSP, Admin1 + password)
//   2. Set(LockingRange[n], ReadLocked=x, WriteLocked=y)
//        - RW : RL=0, WL=0
//        - RO : RL=0, WL=1
//        - LK : RL=1, WL=1
//   3. CloseSession

#include "common.h"

namespace sed_compare {

static void compareSetRangeLockState(Section& sec, uint32_t tsn,
                                     uint64_t rangeUidVal, uint8_t rl, uint8_t wl,
                                     const char* modeName) {
    TokenList values;
    values.addUint(uid::col::READ_LOCKED,  rl);
    values.addUint(uid::col::WRITE_LOCKED, wl);
    Bytes tokens = MethodCall::buildSet(Uid(rangeUidVal), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    // sedutil takes a raw UID vector — build it from the libsed constant.
    std::vector<uint8_t> rangeUid = {0xA8};
    for (int i = 7; i >= 0; --i) rangeUid.push_back((uint8_t)((rangeUidVal >> (i*8)) & 0xFF));
    std::vector<uint8_t> setMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17};

    DtaCommand cmd;
    cmd.reset(rangeUid, setMethod);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKED);  cmd.addToken((uint64_t)rl); cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKED); cmd.addToken((uint64_t)wl); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    std::string step = "Set(Range1, ";
    step += modeName;
    step += ")";
    sec.compare(step, cats, ref);
}

void runSetLockingRange() {
    Section sec("sedutil-cli --setLockingRange 1 <RW|RO|LK> <pw>");

    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                            uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);

    compareSetRangeLockState(sec, 0x6001, uid::LOCKING_RANGE1, 0, 0, "RL=0 WL=0 (RW)");
    compareSetRangeLockState(sec, 0x6002, uid::LOCKING_RANGE1, 0, 1, "RL=0 WL=1 (RO)");
    compareSetRangeLockState(sec, 0x6003, uid::LOCKING_RANGE1, 1, 1, "RL=1 WL=1 (LK)");

    compareCloseSession(sec, "CloseSession", 0x6003);
}

} // namespace sed_compare
