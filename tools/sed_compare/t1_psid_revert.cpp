// sedutil-cli --PSIDrevert <psid>
// (alias: --yesIreallywanttoERASEALLmydatausingthePSID)
//
// Sedutil flow (DtaDevOpal::PSIDrevert):
//   1. StartSession(AdminSP, PSID + psid)
//   2. Revert method on AdminSP (terminates the session — no CloseSession)
//
// PSIDs are printed on the drive label — emergency factory reset path even
// when SID is lost.

#include "common.h"

namespace sed_compare {

void runPsidRevert() {
    Section sec("sedutil-cli --PSIDrevert <psid>");

    const char* psid = "PSID0123456789ABCDEF0123456789AB"; // 32 ASCII chars
    Bytes psidBytes((const uint8_t*)psid, (const uint8_t*)psid + strlen(psid));

    compareStartSessionAuth(sec, "StartSession(AdminSP, PSID + psid)",
                            uid::SP_ADMIN, true, psidBytes, uid::AUTH_PSID);

    // Revert on AdminSP
    {
        const uint32_t tsn = 0x3000;

        MethodCall call;
        call.setInvokingId(Uid(uid::SP_ADMIN));
        call.setMethodId(Uid(method::REVERT));
        Bytes tokens = call.build();
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet cats = pb.buildComPacket(tokens);

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
