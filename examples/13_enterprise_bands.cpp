/// @file 13_enterprise_bands.cpp
/// @brief Enterprise SSC — Bands, BandMasters, and EraseMaster
///
/// TCG SPEC CONTEXT:
/// Enterprise SSC is designed for data-center drives. Key differences from Opal:
///
///   - "Bands" instead of "Locking Ranges" — same concept, different name
///   - BandMaster0..N: each BandMaster controls one band
///   - EraseMaster: can erase any/all bands (for decommissioning)
///   - No User authorities — only BandMasters and EraseMaster
///   - No MBR Shadow — servers don't need pre-boot auth
///   - No "Activate" step — bands are available immediately after ownership
///
/// Band configuration:
///   - Band 0 = Global Band (like Global Range in Opal)
///   - Band 1..N = Named bands with explicit LBA ranges
///   - Each band has its own AES key, lock settings, and LockOnReset
///
/// Authority model:
///   - SID: takes ownership (same as Opal)
///   - BandMaster0: manages Band 0 (global)
///   - BandMaster1..N: each manages their respective band
///   - EraseMaster: can erase any band or all bands at once
///
/// NOTE: This example only works on Enterprise SSC drives.
/// If your drive is Opal, use examples 06-08 instead.
///
/// API LAYER: EvalApi (enterprise-specific methods)
/// PREREQUISITES: 01-05 (Discovery, Properties, Sessions, MSID, Ownership)
///
/// Usage: ./13_enterprise_bands /dev/nvmeX [--dump]

#include "example_common.h"

static std::string SID_PW;
static std::string BM1_PW;
static std::string EM_PW;

// ── Scenario 1: Check for Enterprise SSC ──

static bool scenario1_checkEnterprise(std::shared_ptr<ITransport> transport,
                                       uint16_t comId) {
    scenario(1, "Check for Enterprise SSC");

    EvalApi api;
    DiscoveryInfo info;
    api.discovery0(transport, info);

    bool isEnterprise = (info.primarySsc == SscType::Enterprise);
    step(1, "Drive SSC type", true);
    printf("    SSC: %s\n",
           info.primarySsc == SscType::Enterprise ? "Enterprise" :
           info.primarySsc == SscType::Opal20 ? "Opal 2.0" :
           "Other");

    if (!isEnterprise) {
        printf("    This drive is NOT Enterprise SSC.\n");
        printf("    Enterprise examples require a data-center SED drive.\n");
        printf("    For Opal drives, see examples 06-08.\n");
    }

    return isEnterprise;
}

// ── Scenario 2: Configure Band 1 ──

static bool scenario2_configureBand(std::shared_ptr<ITransport> transport,
                                     uint16_t comId) {
    scenario(2, "Configure Band 1");

    EvalApi api;

    // Take ownership
    auto cr = composite::takeOwnership(api, transport, comId, SID_PW);
    step(1, "Take ownership", cr.overall);
    if (cr.failed()) return false;

    // Set BandMaster1 password (auth as SID to Enterprise SP)
    Bytes sidPw = pwBytes(SID_PW);
    auto r = composite::withSession(api, transport, comId,
        uid::SP_ENTERPRISE, true, uid::AUTH_SID, sidPw,
        [&](Session& session) -> Result {
            // Set BandMaster1 password
            auto r2 = api.setBandMasterPassword(session, 1,
                pwBytes(BM1_PW));
            step(2, "Set BandMaster1 password", r2);

            // Set EraseMaster password
            r2 = api.setEraseMasterPassword(session,
                pwBytes(EM_PW));
            step(3, "Set EraseMaster password", r2);

            return ErrorCode::Success;
        });

    // Configure Band 1 as BandMaster1
    Bytes bm1Pw = pwBytes(BM1_PW);
    r = composite::withSession(api, transport, comId,
        uid::SP_ENTERPRISE, true, uid::AUTH_BANDMASTER0 + 1, bm1Pw,
        [&](Session& session) -> Result {
            // Configure Band 1: LBA 0-2047, enable locking
            auto r2 = api.configureBand(session, 1, 0, 2048, true, true);
            step(4, "Configure Band 1 (LBA 0-2047)", r2);

            // Read band info
            LockingInfo bInfo;
            r2 = api.getBandInfo(session, 1, bInfo);
            step(5, "Read Band 1 info", r2);
            if (r2.ok()) {
                printf("    Start=%lu, Length=%lu, RLE=%d, WLE=%d\n",
                       bInfo.rangeStart, bInfo.rangeLength,
                       bInfo.readLockEnabled, bInfo.writeLockEnabled);
            }

            return ErrorCode::Success;
        });

    return r.ok();
}

// ── Scenario 3: Lock/Unlock Band ──

static bool scenario3_lockUnlock(std::shared_ptr<ITransport> transport,
                                  uint16_t comId) {
    scenario(3, "Band Lock/Unlock");

    EvalApi api;
    Bytes bm1Pw = pwBytes(BM1_PW);

    auto r = composite::withSession(api, transport, comId,
        uid::SP_ENTERPRISE, true, uid::AUTH_BANDMASTER0 + 1, bm1Pw,
        [&](Session& session) -> Result {
            auto r2 = api.lockBand(session, 1);
            step(1, "Lock Band 1", r2);

            LockingInfo bInfo;
            api.getBandInfo(session, 1, bInfo);
            printf("    Locked: read=%d, write=%d\n",
                   bInfo.readLocked, bInfo.writeLocked);

            r2 = api.unlockBand(session, 1);
            step(2, "Unlock Band 1", r2);

            api.getBandInfo(session, 1, bInfo);
            printf("    Locked: read=%d, write=%d\n",
                   bInfo.readLocked, bInfo.writeLocked);

            return ErrorCode::Success;
        });

    return r.ok();
}

// ── Scenario 4: EraseMaster Erase ──

static bool scenario4_eraseMaster(std::shared_ptr<ITransport> transport,
                                   uint16_t comId) {
    scenario(4, "EraseMaster Band Erase");

    EvalApi api;
    Bytes emPw = pwBytes(EM_PW);

    auto r = composite::withSession(api, transport, comId,
        uid::SP_ENTERPRISE, true, uid::AUTH_ERASEMASTER, emPw,
        [&](Session& session) -> Result {
            // Erase Band 1 (crypto erase — regenerates key)
            auto r2 = api.eraseBand(session, 1);
            step(1, "EraseMaster: Erase Band 1", r2);
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
        "Enterprise SSC — Bands, BandMasters, EraseMaster");
    if (!transport) return 1;

    SID_PW = getPassword(opts);
    BM1_PW = SID_PW + "_BandMaster1";
    EM_PW  = SID_PW + "_EraseMaster";

    banner("13: Enterprise Bands");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    // Check if this is an Enterprise drive
    if (!scenario1_checkEnterprise(transport, info.baseComId)) {
        printf("\n  Skipping Enterprise scenarios (not an Enterprise drive).\n");
        return 0;
    }

    bool ok = true;
    ok &= scenario2_configureBand(transport, info.baseComId);
    ok &= scenario3_lockUnlock(transport, info.baseComId);
    ok &= scenario4_eraseMaster(transport, info.baseComId);
    cleanup(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
