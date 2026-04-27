// sedutil-cli --readData  <pw>        (DataStore read)
// sedutil-cli --writeData <pw> <file> (DataStore write, multi-chunk)
//
// Sedutil flow (DtaDevOpal::readData / writeData):
//
//   Read:
//     1. StartSession(LockingSP, User1 + pw)
//     2. Get(DataStore, startRow=offset, endRow=offset+len-1)
//     3. CloseSession
//
//   Write (small chunk — sedutil splits larger payloads across multiple
//   Set calls with increasing Where offsets):
//     1. StartSession(LockingSP, User1 + pw)
//     2. Set(DataStore, Where=offset, Values=<raw bytes>)
//     3. CloseSession
//
// DataStore (TABLE_DATASTORE = 0x0000100100000000) is a byte table: Get's
// CellBlock names refer to byte offsets (startRow/endRow), Set's Values
// parameter is the raw byte payload — NOT a list of named column pairs.

#include "common.h"

namespace sed_compare {

static void compareGet_DataStore(Section& sec, uint32_t tsn,
                                 uint32_t offset, uint32_t length) {
    CellBlock cb;
    cb.startRow = offset;
    cb.endRow   = offset + length - 1;
    Bytes tokens = MethodCall::buildGet(Uid(uid::TABLE_DATASTORE), cb);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(tsn, HSN);
    Packet cats = pb.buildComPacket(tokens);

    std::vector<uint8_t> tableUid = {0xA8, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00};
    std::vector<uint8_t> getMethod = {0xA8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x16};

    DtaCommand cmd;
    cmd.reset(tableUid, getMethod);
    // CellBlock 은 outer args 안에 inner list 로 wrap (실 sedutil 동작)
    cmd.addToken(OPAL_TOKEN::STARTLIST);          // outer args
      cmd.addToken(OPAL_TOKEN::STARTLIST);        // inner CellBlock
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::STARTROW);
          cmd.addToken((uint64_t)offset);
        cmd.addToken(OPAL_TOKEN::ENDNAME);
        cmd.addToken(OPAL_TOKEN::STARTNAME);
          cmd.addToken(OPAL_TOKEN::ENDROW);
          cmd.addToken((uint64_t)(offset + length - 1));
        cmd.addToken(OPAL_TOKEN::ENDNAME);
      cmd.addToken(OPAL_TOKEN::ENDLIST);          // close inner CellBlock
    cmd.addToken(OPAL_TOKEN::ENDLIST);            // close outer args
    cmd.complete();
    cmd.setcomID(COMID);
    Packet ref = extractSedutilPacket(cmd, tsn, HSN);

    sec.compare("Get(DataStore, rows " + std::to_string(offset) +
                ".." + std::to_string(offset + length - 1) + ")",
                cats, ref);
}

void runReadData() {
    Section sec("sedutil-cli --readData <pw>");

    const char* pw = "user1_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, User1 + pw)",
                            uid::SP_LOCKING, true, pwBytes, uid::AUTH_USER1);

    compareGet_DataStore(sec, 0xE001, 0, 256);

    compareCloseSession(sec, "CloseSession", 0xE001);
}

} // namespace sed_compare
