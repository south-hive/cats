// sedutil-cli --rekeyLockingRange <n> <pw>
//
// Sedutil flow (DtaDevOpal::rekeyLockingRange):
//   1. StartSession(LockingSP, Admin1 + pw)
//   2. GenKey(LockingRange[n])   — method UID 0x0000000600000010, empty params
//   3. CloseSession
//
// GenKey on a locking range rotates its AES key, atomically destroying all
// ciphertext in that range (crypto-erase).

#include "common.h"

namespace sed_compare {

void runRekey() {
    Section sec("sedutil-cli --rekeyLockingRange 1 <pw>");

    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                            uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);

    // GenKey(Range1)
    {
        const uint32_t tsn = 0xD001;
        const uint64_t rangeUidVal = uid::LOCKING_RANGE1;

        Bytes tokens = MethodCall::buildGenKey(Uid(rangeUidVal));
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet cats = pb.buildComPacket(tokens);

        std::vector<uint8_t> rangeUid = {0xA8};
        for (int i = 7; i >= 0; --i)
            rangeUid.push_back((uint8_t)((rangeUidVal >> (i*8)) & 0xFF));
        std::vector<uint8_t> genKeyMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x10};

        DtaCommand cmd;
        cmd.reset(rangeUid, genKeyMethod);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet ref = extractSedutilPacket(cmd, tsn, HSN);

        sec.compare("GenKey(Range1)", cats, ref);
    }

    compareCloseSession(sec, "CloseSession", 0xD001);
}

} // namespace sed_compare
