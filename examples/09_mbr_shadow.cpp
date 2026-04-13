/// @file 09_mbr_shadow.cpp
/// @brief Shadow MBR — Pre-Boot Authentication Image
///
/// TCG SPEC CONTEXT:
/// The Shadow MBR is a hidden area that the drive presents as the boot
/// sector when the system powers on, BEFORE any OS-level SED unlocking.
///
/// How it works:
///   1. MBR Shadow is enabled (MBRControl.Enable = true)
///   2. On power-up, the drive presents the Shadow MBR data instead of
///      the real disk contents — typically a small PBA (Pre-Boot Auth) image
///   3. The PBA prompts the user for a password
///   4. The PBA authenticates to the drive and unlocks the locking range
///   5. The PBA sets MBRDone = true → drive now shows real disk contents
///   6. BIOS/UEFI reboots or chain-loads from the now-visible real disk
///
/// Key tables:
///   - MBRControl (UID 0x0000080300000001): Enable and Done flags
///   - MBR (UID 0x0000080400000000): The shadow MBR data (up to ~128MB)
///
/// The MBR table is a ByteTable — you write/read arbitrary byte ranges
/// at specific offsets, like a mini filesystem.
///
/// API LAYER: EvalApi + SedSession
/// PREREQUISITES: 01-06 (Locking SP must be activated)
///
/// Usage: ./09_mbr_shadow /dev/nvmeX [--dump]

#include "example_common.h"

static std::string SID_PW;
static std::string ADMIN1_PW;

static bool setupDrive(EvalApi& api, std::shared_ptr<ITransport> transport,
                       uint16_t comId) {
    auto cr = composite::takeOwnership(api, transport, comId, SID_PW);
    if (cr.failed()) return false;

    Bytes sidPw(SID_PW.begin(), SID_PW.end());
    auto r = composite::withSession(api, transport, comId,
        uid::SP_ADMIN, true, uid::AUTH_SID, sidPw,
        [&](Session& s) { return api.activate(s, uid::SP_LOCKING); });
    if (r.failed()) return false;

    return composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, Bytes{},
        [&](Session& s) { return api.setAdmin1Password(s, ADMIN1_PW); }).ok();
}

// ── Scenario 1: MBR Enable/Disable and Done flag ──

static bool scenario1_mbrControl(std::shared_ptr<ITransport> transport,
                                  uint16_t comId) {
    scenario(1, "MBR Control — Enable and Done Flags");

    EvalApi api;
    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());

    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            // Check initial MBR status
            bool mbrEnabled = false, mbrDone = false;
            auto r2 = api.getMbrStatus(session, mbrEnabled, mbrDone);
            step(1, "Get MBR status", r2);
            printf("    MBR Enabled: %s, MBR Done: %s\n",
                   mbrEnabled ? "yes" : "no", mbrDone ? "yes" : "no");

            // Enable MBR Shadow
            r2 = api.setMbrEnable(session, true);
            step(2, "Enable MBR Shadow", r2);

            // Set MBRDone = true (simulate PBA completion)
            r2 = api.setMbrDone(session, true);
            step(3, "Set MBRDone = true", r2);

            // Verify
            r2 = api.getMbrStatus(session, mbrEnabled, mbrDone);
            step(4, "Verify MBR status", r2);
            printf("    MBR Enabled: %s, MBR Done: %s\n",
                   mbrEnabled ? "yes" : "no", mbrDone ? "yes" : "no");

            // Disable MBR Shadow (back to normal)
            r2 = api.setMbrEnable(session, false);
            step(5, "Disable MBR Shadow", r2);

            return ErrorCode::Success;
        });

    return r.ok();
}

// ── Scenario 2: Write and Read MBR Data ──
//
// Write a small "PBA image" to the MBR table and read it back.
// In real usage, this would be a bootable image (e.g., 512B-128MB).

static bool scenario2_mbrData(std::shared_ptr<ITransport> transport,
                               uint16_t comId) {
    scenario(2, "MBR Data Write/Read");

    EvalApi api;
    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());

    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            // Create a small test "PBA image"
            // In reality, this would be a bootable binary
            Bytes pbaImage(512, 0);
            // MBR signature at bytes 510-511
            pbaImage[510] = 0x55;
            pbaImage[511] = 0xAA;
            // Some marker text
            const char* marker = "CATS PBA TEST IMAGE";
            std::memcpy(pbaImage.data(), marker, strlen(marker));

            // Write to MBR table at offset 0
            auto r2 = api.writeMbrData(session, 0, pbaImage);
            step(1, "Write 512B PBA image to MBR", r2);
            if (r2.failed()) return r2;

            // Read it back
            Bytes readBack;
            r2 = api.readMbrData(session, 0, 512, readBack);
            step(2, "Read back 512B from MBR", r2);
            if (r2.ok()) {
                bool match = (readBack == pbaImage);
                step(3, "Verify data matches", match);
                if (!match) {
                    printf("    Written %zu bytes, read %zu bytes\n",
                           pbaImage.size(), readBack.size());
                }
                dumpHex("MBR[0..64]", readBack.data(), std::min((size_t)64, readBack.size()));
            }

            return ErrorCode::Success;
        });

    return r.ok();
}

// ── Scenario 3: Boot cycle simulation ──
//
// Simulates what happens during a PBA boot:
// 1. Enable MBR shadow (admin does this once during setup)
// 2. Power cycle (simulated by new session)
// 3. MBRDone is false after power cycle
// 4. PBA authenticates and sets MBRDone=true
// 5. Drive now shows real disk

static bool scenario3_bootCycle(std::shared_ptr<ITransport> transport,
                                 uint16_t comId) {
    scenario(3, "Boot Cycle Simulation");

    EvalApi api;
    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());

    // Admin enables MBR shadow (one-time setup)
    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            auto r2 = api.setMbrEnable(session, true);
            step(1, "Admin: Enable MBR shadow", r2);
            // Set MBRDone=false to simulate "needs PBA"
            r2 = api.setMbrDone(session, false);
            step(2, "Admin: Set MBRDone=false", r2);
            return r2;
        });
    if (r.failed()) return false;

    // --- Simulate power cycle (new session) ---
    printf("\n    --- Simulated Power Cycle ---\n\n");

    // After power cycle, MBRDone should be false
    // PBA authenticates and sets MBRDone=true
    r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            bool mbrEnabled = false, mbrDone = false;
            auto r2 = api.getMbrStatus(session, mbrEnabled, mbrDone);
            step(3, "PBA: Check MBR status", r2);
            printf("    MBRDone=%s (should be false)\n", mbrDone ? "true" : "false");

            // PBA sets MBRDone=true → drive shows real disk
            r2 = api.setMbrDone(session, true);
            step(4, "PBA: Set MBRDone=true", r2);

            // Cleanup: disable MBR shadow
            r2 = api.setMbrEnable(session, false);
            step(5, "Cleanup: Disable MBR shadow", r2);
            return r2;
        });

    return r.ok();
}

static bool cleanup(std::shared_ptr<ITransport> transport, uint16_t comId) {
    scenario(0, "Cleanup");
    EvalApi api;
    auto cr = composite::revertToFactory(api, transport, comId, SID_PW);
    step(1, "RevertToFactory", cr.overall);
    return cr.ok();
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Shadow MBR — Pre-Boot Authentication image management");
    if (!transport) return 1;

    SID_PW = getPassword(opts);
    ADMIN1_PW = SID_PW + "_Admin1";

    banner("09: Shadow MBR");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    if (!setupDrive(api, transport, info.baseComId)) {
        printf("  Setup failed.\n"); return 1;
    }

    bool ok = true;
    ok &= scenario1_mbrControl(transport, info.baseComId);
    ok &= scenario2_mbrData(transport, info.baseComId);
    ok &= scenario3_bootCycle(transport, info.baseComId);
    cleanup(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
