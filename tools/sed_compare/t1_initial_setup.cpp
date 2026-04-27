// sedutil-cli --initialSetup <new-pw>
//
// Sedutil flow (DtaDevOpal::initialSetup composes five sub-ops):
//
//   A. takeOwnership(newPw):
//      A1. StartSession(AdminSP, anon, read)   — to read MSID
//      A2. Get(C_PIN_MSID, startCol=PIN, endCol=PIN)
//      A3. CloseSession
//      A4. StartSession(AdminSP, SID + MSID)
//      A5. Set(C_PIN_SID, Pin=newPw)
//      A6. CloseSession
//
//   B. activateLockingSP(newPw):
//      B1. StartSession(AdminSP, SID + newPw)
//      B2. Activate(LockingSP)
//      B3. CloseSession
//
//   C. configureLockingRange(0, DISABLELOCKING, newPw):
//      C1. StartSession(LockingSP, Admin1 + newPw)
//      C2. Set(LockingRange.Global, RLE=0, WLE=0)
//      C3. CloseSession
//
//   D. setLockingRange(0, READWRITE, newPw):
//      D1. StartSession(LockingSP, Admin1 + newPw)
//      D2. Set(LockingRange.Global, RL=0, WL=0)
//      D3. CloseSession
//
//   E. setMBREnable(0, newPw):
//      E1. StartSession(AdminSP, SID + newPw)
//      E2. Set(MBRControl, Enable=0)
//      E3. CloseSession

#include "common.h"

namespace sed_compare {

static void compareSet_CPIN_SID(Section& sec, uint32_t tsn, const char* pw) {
    TokenList values;
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));
    values.addBytes(uid::col::PIN, pwBytes);
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
        cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::PIN);
          cmd.addToken(pw);
          cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Set(C_PIN_SID, Pin=newPw)", cats, ref);
}

static void compareGet_CPIN_MSID_Pin(Section& sec, uint32_t tsn) {
    CellBlock cb;
    cb.startColumn = 3; // PIN
    cb.endColumn   = 3;
    Bytes tokens = MethodCall::buildGet(Uid(uid::CPIN_MSID), cb);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    DtaCommand cmd;
    cmd.reset(OPAL_C_PIN_MSID, GET);
    // Real sedutil-cli emits a NESTED list for the CellBlock — verified by
    // hex dump on hardware. Earlier reference here was missing the inner
    // STARTLIST/ENDLIST and matched libsed's (also wrong) flat encoding,
    // which is why this test always passed despite drive-level 0x0F.
    cmd.addToken(OPAL_TOKEN::STARTLIST);          // outer args list
      cmd.addToken(OPAL_TOKEN::STARTLIST);        // inner CellBlock list
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::STARTCOLUMN);
          cmd.addToken(OPAL_TINY_ATOM::UINT_03); // PIN
        cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::ENDCOLUMN);
          cmd.addToken(OPAL_TINY_ATOM::UINT_03); // PIN
        cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::ENDLIST);          // close inner CellBlock
    cmd.addToken(OPAL_TOKEN::ENDLIST);            // close outer args
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Get(C_PIN_MSID, col=PIN)", cats, ref);
}

static void compareActivate_LockingSP(Section& sec, uint32_t tsn) {
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

static void compareSet_GlobalRange_DisableLocking(Section& sec, uint32_t tsn) {
    TokenList values;
    values.addUint(uid::col::READ_LOCK_EN, 0);
    values.addUint(uid::col::WRITE_LOCK_EN, 0);
    Bytes tokens = MethodCall::buildSet(Uid(uid::LOCKING_GLOBALRANGE), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    DtaCommand cmd;
    cmd.reset(OPAL_LOCKINGRANGE_GLOBAL, SET);
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
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Set(LockingRange.Global, RLE=0, WLE=0)", cats, ref);
}

static void compareSet_GlobalRange_Unlock(Section& sec, uint32_t tsn) {
    TokenList values;
    values.addUint(uid::col::READ_LOCKED,  0);
    values.addUint(uid::col::WRITE_LOCKED, 0);
    Bytes tokens = MethodCall::buildSet(Uid(uid::LOCKING_GLOBALRANGE), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    DtaCommand cmd;
    cmd.reset(OPAL_LOCKINGRANGE_GLOBAL, SET);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::WHERE);
        cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::READLOCKED);  cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::WRITELOCKED); cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Set(LockingRange.Global, RL=0, WL=0)", cats, ref);
}

static void compareSet_MBRControl_Enable0(Section& sec, uint32_t tsn) {
    TokenList values;
    values.addUint(uid::col::MBR_ENABLE, 0);
    Bytes tokens = MethodCall::buildSet(Uid(uid::MBRCTRL_SET), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    DtaCommand cmd;
    cmd.reset(OPAL_MBRCONTROL, SET);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::WHERE);
        cmd.addToken(OPAL_TOKEN::STARTLIST); cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::STARTNAME);
        cmd.addToken(OPAL_TOKEN::VALUES);
        cmd.addToken(OPAL_TOKEN::STARTLIST);
          cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken(OPAL_TOKEN::MBRENABLE); cmd.addToken((uint64_t)0); cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::ENDLIST);
      cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Set(MBRControl, Enable=0)", cats, ref);
}

void runInitialSetup() {
    Section sec("sedutil-cli --initialSetup <new-pw>");

    const char* newPw = "newPw12345";
    const char* msid  = "MSID0123456789ABCDEF0123456789AB";
    Bytes newPwBytes((const uint8_t*)newPw, (const uint8_t*)newPw + strlen(newPw));
    Bytes msidBytes ((const uint8_t*)msid,  (const uint8_t*)msid  + strlen(msid));

    // ── A. takeOwnership ──
    compareStartSessionAnon(sec, "[A1] StartSession(AdminSP, anon, read)",
                            uid::SP_ADMIN, false);
    compareGet_CPIN_MSID_Pin(sec, 0x1001);
    compareCloseSession(sec, "[A3] CloseSession", 0x1001);

    compareStartSessionAuth(sec, "[A4] StartSession(AdminSP, SID + MSID)",
                            uid::SP_ADMIN, true, msidBytes, uid::AUTH_SID);
    compareSet_CPIN_SID(sec, 0x1002, newPw);
    compareCloseSession(sec, "[A6] CloseSession", 0x1002);

    // ── B. activateLockingSP ──
    compareStartSessionAuth(sec, "[B1] StartSession(AdminSP, SID + newPw)",
                            uid::SP_ADMIN, true, newPwBytes, uid::AUTH_SID);
    compareActivate_LockingSP(sec, 0x1003);
    compareCloseSession(sec, "[B3] CloseSession", 0x1003);

    // ── C. configureLockingRange (disable locking on Global) ──
    compareStartSessionAuth(sec, "[C1] StartSession(LockingSP, Admin1 + newPw)",
                            uid::SP_LOCKING, true, newPwBytes, uid::AUTH_ADMIN1);
    compareSet_GlobalRange_DisableLocking(sec, 0x1004);
    compareCloseSession(sec, "[C3] CloseSession", 0x1004);

    // ── D. setLockingRange (unlock Global for RW) ──
    compareStartSessionAuth(sec, "[D1] StartSession(LockingSP, Admin1 + newPw)",
                            uid::SP_LOCKING, true, newPwBytes, uid::AUTH_ADMIN1);
    compareSet_GlobalRange_Unlock(sec, 0x1005);
    compareCloseSession(sec, "[D3] CloseSession", 0x1005);

    // ── E. setMBREnable(0) ──
    compareStartSessionAuth(sec, "[E1] StartSession(AdminSP, SID + newPw)",
                            uid::SP_ADMIN, true, newPwBytes, uid::AUTH_SID);
    compareSet_MBRControl_Enable0(sec, 0x1006);
    compareCloseSession(sec, "[E3] CloseSession", 0x1006);
}

} // namespace sed_compare
