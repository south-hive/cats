// sedutil-cli --listLockingRanges <password>
//
// Sedutil flow (DtaDevOpal::listLockingRanges):
//   1. StartSession(LockingSP, Admin1 + password)
//   2. Get(LockingRange.Global, startCol=0, endCol=10)  — all columns
//   3. Get(LockingRange[1], startCol=0, endCol=10)
//   ... (one Get per range, but we verify Global + Range1 here)
//   N. CloseSession

#include "common.h"

namespace sed_compare {

static void compareGet_RangeAllCols(Section& sec, uint32_t tsn,
                                    uint64_t rangeUidVal, const std::string& label) {
    CellBlock cb;
    cb.startColumn = 0;
    cb.endColumn   = 10;
    Bytes tokens = MethodCall::buildGet(Uid(rangeUidVal), cb);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    std::vector<uint8_t> rangeUid = {0xA8};
    for (int i = 7; i >= 0; --i) rangeUid.push_back((uint8_t)((rangeUidVal >> (i*8)) & 0xFF));
    std::vector<uint8_t> getMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x16};

    DtaCommand cmd;
    cmd.reset(rangeUid, getMethod);
    // CellBlock 은 outer args 안에 inner list 로 wrap (실 sedutil 동작)
    cmd.addToken(OPAL_TOKEN::STARTLIST);          // outer args
      cmd.addToken(OPAL_TOKEN::STARTLIST);        // inner CellBlock
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::STARTCOLUMN);
          cmd.addToken(OPAL_TINY_ATOM::UINT_00);
        cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::ENDCOLUMN);
          cmd.addToken(OPAL_TINY_ATOM::UINT_10);
        cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::ENDLIST);          // close inner CellBlock
    cmd.addToken(OPAL_TOKEN::ENDLIST);            // close outer args
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Get(" + label + ", cols 0-10)", cats, ref);
}

void runListLockingRanges() {
    Section sec("sedutil-cli --listLockingRanges <pw>");

    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                            uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);

    compareGet_RangeAllCols(sec, 0xB001, uid::LOCKING_GLOBALRANGE, "Global");
    compareGet_RangeAllCols(sec, 0xB002, uid::LOCKING_RANGE1,      "Range1");

    compareCloseSession(sec, "CloseSession", 0xB002);
}

} // namespace sed_compare
