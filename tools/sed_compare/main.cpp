// sed_compare: byte-for-byte comparison of libsed (cats) TCG command packets
// against sedutil-cli's DtaCommand output, across the Tier 1 & Tier 2
// sedutil-cli command surface.
//
// Each runXxx() function covers one sedutil-cli command and prints a section
// banner + per-packet PASS/FAIL result. The summary at end shows totals.

#include "common.h"

namespace sed_compare {
// Tier 1 — ownership / revert
void runQuery();
void runInitialSetup();
void runSetSIDPassword();
void runRevertTPer();
void runRevertLockingSP();
void runPsidRevert();
// Tier 2 — locking & users
void runActivateLockingSP();
void runSetLockingRange();
void runEnableLockingRange();
void runSetupLockingRange();
void runEnableUser();
void runSetPassword();
void runListLockingRanges();
// Tier 3 — MBR / DataStore / rekey
void runSetMBREnable();
void runSetMBRDone();
void runRekey();
void runReadData();
} // namespace sed_compare

int main() {
    using namespace sed_compare;

    printf("═══════════════════════════════════════════════════════════════\n");
    printf(" sed_compare — libsed vs sedutil-cli byte-for-byte packet proof\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    printf("\n>>> TIER 1: Ownership & Revert\n");
    runQuery();
    runInitialSetup();
    runSetSIDPassword();
    runRevertTPer();
    runRevertLockingSP();
    runPsidRevert();

    printf("\n>>> TIER 2: Locking & Users\n");
    runActivateLockingSP();
    runSetLockingRange();
    runEnableLockingRange();
    runSetupLockingRange();
    runEnableUser();
    runSetPassword();
    runListLockingRanges();

    printf("\n>>> TIER 3: MBR / DataStore / Crypto\n");
    runSetMBREnable();
    runSetMBRDone();
    runRekey();
    runReadData();

    const int total = totals().pass + totals().fail;
    printf("\n═══════════════════════════════════════════════════════════════\n");
    if (totals().fail == 0) {
        printf(" ✓ ALL %d packets byte-identical across Tier 1/2/3 commands\n", total);
    } else {
        printf(" ✗ %d/%d packets FAILED\n", totals().fail, total);
    }
    printf("═══════════════════════════════════════════════════════════════\n");

    return totals().fail > 0 ? 1 : 0;
}
