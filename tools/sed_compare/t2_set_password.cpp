// sedutil-cli --setPassword <owner-pw> <userid> <new-user-pw>
//
// Sedutil flow (DtaDevOpal::setPassword for a User authority):
//   1. StartSession(LockingSP, Admin1 + owner-pw)
//   2. Set(C_PIN_User[n], Pin=newUserPwBytes)
//   3. CloseSession

#include "common.h"

namespace sed_compare {

void runSetPassword() {
    Section sec("sedutil-cli --setPassword <owner> User1 <new>");

    const char* ownerPw = "admin1_pw";
    const char* newPw   = "user1_pw";
    Bytes ownerBytes((const uint8_t*)ownerPw, (const uint8_t*)ownerPw + strlen(ownerPw));
    Bytes newBytes  ((const uint8_t*)newPw,   (const uint8_t*)newPw   + strlen(newPw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + owner)",
                            uid::SP_LOCKING, true, ownerBytes, uid::AUTH_ADMIN1);

    // Set(C_PIN_USER1, Pin=newPw)
    {
        const uint32_t tsn = 0xA001;
        const uint64_t cpinUid = uid::CPIN_USER1;

        TokenList values;
        values.addBytes(uid::col::PIN, newBytes);
        Bytes tokens = MethodCall::buildSet(Uid(cpinUid), values);
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet cats = pb.buildComPacket(tokens);

        std::vector<uint8_t> cpinBytes = {0xA8};
        for (int i = 7; i >= 0; --i) cpinBytes.push_back((uint8_t)((cpinUid >> (i*8)) & 0xFF));
        std::vector<uint8_t> setMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17};

        DtaCommand cmd;
        cmd.reset(cpinBytes, setMethod);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME);
            cmd.addToken(OPAL_TOKEN::WHERE);
            cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
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

        sec.compare("Set(C_PIN_User1, Pin=new)", cats, ref);
    }

    compareCloseSession(sec, "CloseSession", 0xA001);
}

} // namespace sed_compare
