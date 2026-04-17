// sedutil-cli --query
//
// Sedutil flow:
//   1. IF-RECV Discovery (Protocol 0x01, ComID 0x0001) — raw binary, not a ComPacket
//   2. (implicit) Properties exchange before any session
//   3. StartSession(AdminSP, anonymous) — opens a session to probe later
//
// Step 1 is not a ComPacket so there's nothing to byte-compare here. We verify
// steps 2 and 3 which are what sedutil uses when it actually talks to the SP.

#include "common.h"

namespace sed_compare {

void runQuery() {
    Section sec("sedutil-cli --query");
    compareProperties(sec, "Properties");
    compareStartSessionAnon(sec, "StartSession(AdminSP, anon, read)",
                            uid::SP_ADMIN, /*write=*/false);
}

} // namespace sed_compare
