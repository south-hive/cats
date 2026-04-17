// sedutil-cli --revertLockingSP <sid-password>
//
// Sedutil flow (DtaDevOpal::revertLockingSP):
//   1. StartSession(LockingSP, Admin1 + sid-password)
//   2. RevertSP method on ThisSP (terminates the session — no CloseSession)
//
// Note: invoker is THISSP (0x...01), not the LockingSP UID — this is the
// conventional way sedutil calls RevertSP from within a LockingSP session.

#include "common.h"

namespace sed_compare {

void runRevertLockingSP() {
    Section sec("sedutil-cli --revertLockingSP <pw>");

    const char* pw = "sid_pw";
    Bytes pwBytes((const uint8_t*)pw, (const uint8_t*)pw + strlen(pw));

    compareStartSessionAuth(sec, "StartSession(LockingSP, Admin1 + pw)",
                            uid::SP_LOCKING, true, pwBytes, uid::AUTH_ADMIN1);

    compareRevertSP(sec, "RevertSP(ThisSP)", 0x2000, uid::THIS_SP);
}

} // namespace sed_compare
