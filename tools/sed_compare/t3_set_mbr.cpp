// sedutil-cli --setMBREnable <Y|N> <pw>
// sedutil-cli --setMBRDone   <Y|N> <pw>
//
// Sedutil flow (DtaDevOpal::setMBREnable / setMBRDone):
//   1. StartSession(AdminSP, SID + pw)
//   2. Set(MBRControl, Enable=x) or Set(MBRControl, Done=x)
//   3. CloseSession

#include "common.h"

namespace sed_compare {

static void compareSet_MBRControl_Enable(Section& sec, uint32_t tsn, uint8_t value) {
    TokenList values;
    values.addUint(uid::col::MBR_ENABLE, value);
    Bytes tokens = MethodCall::buildSet(Uid(uid::MBRCTRL_SET), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    DtaCommand cmd;
    cmd.reset(OPAL_MBRCONTROL, SET);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::MBRENABLE); cmd.addToken((uint64_t)value); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    std::string label = "Set(MBRControl, Enable=";
    label += (value ? "1" : "0");
    label += ")";
    sec.compare(label, cats, ref);
}

static void compareSet_MBRControl_Done(Section& sec, uint32_t tsn, uint8_t value) {
    TokenList values;
    values.addUint(uid::col::MBR_DONE, value);
    Bytes tokens = MethodCall::buildSet(Uid(uid::MBRCTRL_SET), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    DtaCommand cmd;
    cmd.reset(OPAL_MBRCONTROL, SET);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::MBRDONE); cmd.addToken((uint64_t)value); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    std::string label = "Set(MBRControl, Done=";
    label += (value ? "1" : "0");
    label += ")";
    sec.compare(label, cats, ref);
}

void runSetMBREnable() {
    Section sec("sedutil-cli --setMBREnable Y <pw>");
    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));
    compareStartSessionAuth(sec, "StartSession(AdminSP, SID + pw)",
                            uid::SP_ADMIN, true, pwBytes, uid::AUTH_SID);
    compareSet_MBRControl_Enable(sec, 0xC001, 1);
    compareCloseSession(sec, "CloseSession", 0xC001);
}

void runSetMBRDone() {
    Section sec("sedutil-cli --setMBRDone Y <pw>");
    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));
    compareStartSessionAuth(sec, "StartSession(AdminSP, SID + pw)",
                            uid::SP_ADMIN, true, pwBytes, uid::AUTH_SID);
    compareSet_MBRControl_Done(sec, 0xC101, 1);
    compareCloseSession(sec, "CloseSession", 0xC101);
}

} // namespace sed_compare
