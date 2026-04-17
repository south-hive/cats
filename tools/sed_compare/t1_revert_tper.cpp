// sedutil-cli --revertTPer <sid-password>
//
// Sedutil flow (DtaDevOpal::revertTPer):
//   1. StartSession(AdminSP, SID + sid-password)
//   2. Revert method on AdminSP (terminates the session — no CloseSession)
//
// Revert method UID: 0x0000000600000202 (not REVERTSP=0x11).

#include "common.h"

namespace sed_compare {

void runRevertTPer() {
    Section sec("sedutil-cli --revertTPer <pw>");

    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(AdminSP, SID + pw)",
                            uid::SP_ADMIN, true, pwBytes, uid::AUTH_SID);

    // Revert on AdminSP
    {
        const uint32_t tsn = 0x1000;

        // libsed: build Revert call manually (buildRevertSP would use REVERTSP=0x11).
        MethodCall call;
        call.setInvokingId(Uid(uid::SP_ADMIN));
        call.setMethodId(Uid(method::REVERT));
        Bytes tokens = call.build();
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet cats = pb.buildComPacket(tokens);

        // sedutil: cmd.reset(OPAL_ADMINSP_UID, REVERT)
        DtaCommand cmd;
        cmd.reset(OPAL_ADMINSP_UID, REVERT);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet ref = extractSedutilPacket(cmd, tsn, HSN);

        sec.compare("Revert(AdminSP)", cats, ref);
    }
}

} // namespace sed_compare
