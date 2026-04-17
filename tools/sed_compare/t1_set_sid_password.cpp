// sedutil-cli --setSIDPassword <old-pw> <new-pw>
//
// Sedutil flow (DtaDevOpal::setSIDPassword):
//   1. StartSession(AdminSP, SID + old-pw)
//   2. Set(C_PIN_SID, Pin=newPwBytes)
//   3. CloseSession
//
// Passwords are passed as raw c-strings on the wire; real sedutil PBKDF2-hashes
// them host-side before this call (with MSID as salt), but we pass the hashed
// (or raw) bytes straight through to test the encoding path.

#include "common.h"

namespace sed_compare {

void runSetSIDPassword() {
    Section sec("sedutil-cli --setSIDPassword <old> <new>");

    const char* oldPw = "old_pw";
    const char* newPw = "new_pw";
    Bytes oldBytes((const uint8_t*)oldPw, (const uint8_t*)oldPw + strlen(oldPw));

    compareStartSessionAuth(sec, "StartSession(AdminSP, SID + old)",
                            uid::SP_ADMIN, true, oldBytes, uid::AUTH_SID);

    // Set C_PIN_SID
    {
        const uint32_t tsn = 0x4000;

        TokenList values;
        Bytes newBytes((const uint8_t*)newPw, (const uint8_t*)newPw + strlen(newPw));
        values.addBytes(uid::col::PIN, newBytes);
        Bytes tokens = MethodCall::buildSet(Uid(uid::CPIN_SID), values);
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet cats = pb.buildComPacket(tokens);

        DtaCommand cmd;
        cmd.reset(OPAL_C_PIN_SID, SET);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::WHERE);
          cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::VALUES);
          cmd.addToken(OPAL_TOKEN::STARTLIST);
            cmd.addToken(OPAL_TOKEN::STARTNAME);
            cmd.addToken(OPAL_TOKEN::PIN);
            cmd.addToken(newPw);
            cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet ref = extractSedutilPacket(cmd, tsn, HSN);

        sec.compare("Set(C_PIN_SID, Pin=new)", cats, ref);
    }

    compareCloseSession(sec, "CloseSession", 0x4000);
}

} // namespace sed_compare
