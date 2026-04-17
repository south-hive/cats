// sedutil-cli --activateLockingSP <sid-password>
//
// Sedutil flow (DtaDevOpal::activateLockingSP):
//   1. StartSession(AdminSP, SID + sid-password)
//   2. Activate(LockingSP)    — method UID 0x0000000600000203, empty params
//   3. CloseSession

#include "common.h"

namespace sed_compare {

void runActivateLockingSP() {
    Section sec("sedutil-cli --activateLockingSP <pw>");

    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(AdminSP, SID + pw)",
                            uid::SP_ADMIN, true, pwBytes, uid::AUTH_SID);

    // Activate(LockingSP)
    {
        const uint32_t tsn = 0x5001;
        Bytes tokens = MethodCall::buildActivate(Uid(uid::SP_LOCKING));
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet cats = pb.buildComPacket(tokens);

        DtaCommand cmd;
        cmd.reset(OPAL_LOCKINGSP_UID, ACTIVATE);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet ref = extractSedutilPacket(cmd, tsn, HSN);

        sec.compare("Activate(LockingSP)", cats, ref);
    }

    compareCloseSession(sec, "CloseSession", 0x5001);
}

} // namespace sed_compare
