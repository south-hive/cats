// sedutil-cli --enableUser <password> <userid>
//
// Sedutil flow (DtaDevOpal::enableUser):
//   1. StartSession(LockingSP, Admin1 + password)
//   2. Set(Authority[User1], Enabled=TRUE)   — column Enabled = 5
//   3. CloseSession

#include "common.h"

namespace sed_compare {

void runEnableUser() {
    Section sec("sedutil-cli --enableUser <pw> User1");

    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                            uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);

    // Set(AUTH_USER1, Enabled=1)
    {
        const uint32_t tsn = 0x9001;
        const uint64_t userAuthUid = uid::AUTH_USER1;

        TokenList values;
        values.addUint(uid::col::AUTH_ENABLED, 1);
        Bytes tokens = MethodCall::buildSet(Uid(userAuthUid), values);
        PacketBuilder pb;
        pb.setComId(COMID);
        pb.setSessionNumbers(tsn, HSN);
        Packet cats = pb.buildComPacket(tokens);

        std::vector<uint8_t> userUid = {0xA8};
        for (int i = 7; i >= 0; --i) userUid.push_back((uint8_t)((userAuthUid >> (i*8)) & 0xFF));
        std::vector<uint8_t> setMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17};

        DtaCommand cmd;
        cmd.reset(userUid, setMethod);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME);
            cmd.addToken(OPAL_TOKEN::WHERE);
            cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
          cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::STARTNAME);
            cmd.addToken(OPAL_TOKEN::VALUES);
            cmd.addToken(OPAL_TOKEN::STARTLIST);
              cmd.addToken(OPAL_TOKEN::STARTNAME);
              cmd.addToken(OPAL_TINY_ATOM::UINT_05);  // column Enabled = 5
              cmd.addToken(OPAL_TINY_ATOM::UINT_01);  // value TRUE
              cmd.addToken(OPAL_TOKEN::ENDNAME);
            cmd.addToken(OPAL_TOKEN::ENDLIST);
          cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
        cmd.complete();
        cmd.setcomID(COMID);
        Packet ref = extractSedutilPacket(cmd, tsn, HSN);

        sec.compare("Set(AUTH_USER1, Enabled=1)", cats, ref);
    }

    compareCloseSession(sec, "CloseSession", 0x9001);
}

} // namespace sed_compare
