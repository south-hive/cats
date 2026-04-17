// sedutil-cli --enableLockingRange <n> <password>
// sedutil-cli --disableLockingRange <n> <password>
//
// Sedutil flow (DtaDevOpal::configureLockingRange with ENABLE_LOCKING):
//   1. StartSession(LockingSP, Admin1 + password)
//   2. Set(LockingRange[n], ReadLockEnabled=x, WriteLockEnabled=x)
//        enable : RLE=1, WLE=1
//        disable: RLE=0, WLE=0, ReadLocked=0, WriteLocked=0
//   3. CloseSession

#include "common.h"

namespace sed_compare {

static void compareSetRange_EnableLocking(Section& sec, uint32_t tsn,
                                          uint64_t rangeUidVal) {
    TokenList values;
    values.addUint(uid::col::READ_LOCK_EN,  1);
    values.addUint(uid::col::WRITE_LOCK_EN, 1);
    Bytes tokens = MethodCall::buildSet(Uid(rangeUidVal), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    std::vector<uint8_t> rangeUid = {0xA8};
    for (int i = 7; i >= 0; --i) rangeUid.push_back((uint8_t)((rangeUidVal >> (i*8)) & 0xFF));
    std::vector<uint8_t> setMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17};

    DtaCommand cmd;
    cmd.reset(rangeUid, setMethod);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::WHERE);
        cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKENABLED);  cmd.addToken((uint64_t)1); cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKENABLED); cmd.addToken((uint64_t)1); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Set(Range1, RLE=1, WLE=1)", cats, ref);
}

static void compareSetRange_DisableLocking(Section& sec, uint32_t tsn,
                                           uint64_t rangeUidVal) {
    TokenList values;
    values.addUint(uid::col::READ_LOCK_EN,  0);
    values.addUint(uid::col::WRITE_LOCK_EN, 0);
    values.addUint(uid::col::READ_LOCKED,   0);
    values.addUint(uid::col::WRITE_LOCKED,  0);
    Bytes tokens = MethodCall::buildSet(Uid(rangeUidVal), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    std::vector<uint8_t> rangeUid = {0xA8};
    for (int i = 7; i >= 0; --i) rangeUid.push_back((uint8_t)((rangeUidVal >> (i*8)) & 0xFF));
    std::vector<uint8_t> setMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17};

    DtaCommand cmd;
    cmd.reset(rangeUid, setMethod);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::WHERE);
        cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKENABLED);  cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKENABLED); cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKED);       cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKED);      cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Set(Range1, RLE=0 WLE=0 RL=0 WL=0)", cats, ref);
}

void runEnableLockingRange() {
    {
        Section sec("sedutil-cli --enableLockingRange 1 <pw>");
        const char* pw = "sid_pw";
        Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));
        compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                                uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);
        compareSetRange_EnableLocking(sec, 0x7001, uid::LOCKING_RANGE1);
        compareCloseSession(sec, "CloseSession", 0x7001);
    }
    {
        Section sec("sedutil-cli --disableLockingRange 1 <pw>");
        const char* pw = "sid_pw";
        Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));
        compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                                uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);
        compareSetRange_DisableLocking(sec, 0x7002, uid::LOCKING_RANGE1);
        compareCloseSession(sec, "CloseSession", 0x7002);
    }
}

} // namespace sed_compare
