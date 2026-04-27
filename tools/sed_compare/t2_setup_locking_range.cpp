// sedutil-cli --setupLockingRange <n> <start> <len> <password>
//
// Sedutil flow (DtaDevOpal::setupLockingRange):
//   1. StartSession(LockingSP, Admin1 + password)
//   2. Set(LockingRange[n],
//          RangeStart=<start>, RangeLength=<len>,
//          ReadLockEnabled=0, WriteLockEnabled=0,
//          ReadLocked=0, WriteLocked=0)
//   3. CloseSession

#include "common.h"

namespace sed_compare {

void runSetupLockingRange() {
    Section sec("sedutil-cli --setupLockingRange 1 <start> <len> <pw>");

    const char* pw = "sid_pw";
    const uint64_t rangeStart  = 0x100000;  // 1 MiB
    const uint64_t rangeLength = 0x200000;  // 2 MiB
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                            uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);

    // Set(LockingRange[1], ...)
    {
        const uint32_t tsn = 0x8001;
        const uint64_t rangeUidVal = uid::LOCKING_RANGE1;

        TokenList values;
        values.addUint(uid::col::RANGE_START,    rangeStart);
        values.addUint(uid::col::RANGE_LENGTH,   rangeLength);
        values.addUint(uid::col::READ_LOCK_EN,   0);
        values.addUint(uid::col::WRITE_LOCK_EN,  0);
        values.addUint(uid::col::READ_LOCKED,    0);
        values.addUint(uid::col::WRITE_LOCKED,   0);
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
            cmd.addToken(OPAL_TOKEN::VALUES);
            cmd.addToken(OPAL_TOKEN::STARTLIST);
              cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::RANGESTART);       cmd.addToken((uint64_t)rangeStart);  cmd.addToken(OPAL_TOKEN::ENDNAME);
              cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::RANGELENGTH);      cmd.addToken((uint64_t)rangeLength); cmd.addToken(OPAL_TOKEN::ENDNAME);
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

        sec.compare("Set(Range1, start/len/RLE=0/WLE=0/RL=0/WL=0)", cats, ref);
    }

    compareCloseSession(sec, "CloseSession", 0x8001);
}

} // namespace sed_compare
