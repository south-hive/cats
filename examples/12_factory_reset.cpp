/// @file 12_factory_reset.cpp
/// @brief Factory Reset — RevertSP and PSID Revert
///
/// TCG SPEC CONTEXT:
/// There are two ways to return a drive to factory state:
///
/// 1. RevertSP (with SID authentication):
///    - Requires knowing the SID password
///    - Resets Admin SP: SID password → MSID, all settings cleared
///    - Also reverts Locking SP: ranges cleared, users disabled, keys regenerated
///    - All data encrypted by old keys becomes unrecoverable
///
/// 2. PSID Revert (Physical Security ID):
///    - Uses the PSID printed on the drive's physical label
///    - Does NOT require knowing SID or any other password
///    - This is the "emergency escape hatch" — used when passwords are lost
///    - Destroys ALL data and ALL configuration
///    - PSID is hardcoded and never changes
///
/// After either revert:
///    - Locking SP returns to Manufactured-Inactive
///    - SID password == MSID
///    - All locking ranges, users, MBR shadow, DataStore are wiped
///    - All AES encryption keys are regenerated
///
/// WARNING: Both operations destroy all encrypted data irreversibly!
///
/// API LAYER: EvalApi + EvalComposite + SedDrive
/// PREREQUISITES: 01-06
///
/// Usage: ./12_factory_reset /dev/nvmeX [--psid <PSID>] [--dump]

#include "example_common.h"

static const char* DEFAULT_SID_PW = "TestSid12";
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

// ── Scenario 1: RevertSP via SID ──
//
// Standard revert when you know the SID password.

static bool scenario1_revertSP(std::shared_ptr<ITransport> transport,
                                uint16_t comId) {
    scenario(1, "RevertSP with SID Authentication");

    EvalApi api;

    // Setup: own + activate to have something to revert
    if (!setupDrive(api, transport, comId)) return false;
    step(1, "Drive setup (own + activate)", true);

    // Verify Locking SP is active before revert
    DiscoveryInfo info;
    api.discovery0(transport, info);
    step(2, "Locking SP active before revert",  info.lockingEnabled);

    // RevertSP from Admin SP, authenticated as SID
    auto cr = composite::revertToFactory(api, transport, comId, SID_PW);
    step(3, "RevertToFactory(SID)", cr.overall);
    if (cr.failed()) return false;

    // Print step-by-step results from composite
    for (auto& entry : cr.steps) {
        printf("      %s: %s\n", entry.name.c_str(),
               entry.result.ok() ? "OK" : entry.result.message().c_str());
    }

    // Verify: Locking SP should be inactive, SID should equal MSID
    api.discovery0(transport, info);
    step(4, "Locking SP inactive after revert", !info.lockingEnabled);

    // Verify SID auth with MSID works
    Bytes msid;
    cr = composite::getMsid(api, transport, comId, msid);
    if (cr.ok()) {
        Session session(transport, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                           uid::AUTH_SID, msid, ssr);
        step(5, "SID auth with MSID (factory state)", r);
        if (r.ok()) api.closeSession(session);
    }

    return true;
}

// ── Scenario 2: PSID Revert ──
//
// Emergency recovery when SID password is lost.
// Requires the PSID from the drive label.

static bool scenario2_psidRevert(std::shared_ptr<ITransport> transport,
                                  uint16_t comId, const std::string& psid) {
    scenario(2, "PSID Revert (Emergency Recovery)");

    if (psid.empty()) {
        printf("    PSID not provided (use --psid <value>). Skipping.\n");
        printf("    The PSID is printed on the physical drive label.\n");
        return true;
    }

    EvalApi api;

    // Setup: own + activate
    if (!setupDrive(api, transport, comId)) return false;
    step(1, "Drive setup (own + activate)", true);

    // Now "forget" the SID password — simulate lockout
    printf("    Simulating password lockout...\n");

    // PSID Revert — this works even without knowing SID
    // PSID authenticates to Admin SP as PSID authority
    auto cr = composite::psidRevertAndVerify(api, transport, comId, psid);
    step(2, "PSID Revert", cr.overall);

    for (auto& entry : cr.steps) {
        printf("      %s: %s\n", entry.name.c_str(),
               entry.result.ok() ? "OK" : entry.result.message().c_str());
    }

    if (cr.ok()) {
        DiscoveryInfo info;
        api.discovery0(transport, info);
        step(3, "Locking SP inactive after PSID revert", !info.lockingEnabled);
    }

    return cr.ok();
}

// ── Scenario 3: SedDrive one-liners ──

static bool scenario3_facade(const char* device, cli::CliOptions& opts) {
    scenario(3, "SedDrive::revert() and psidRevert()");

    SedDrive drive(device);
    if (opts.dump) drive.enableDump();
    drive.query();

    // Take ownership and activate
    auto r = drive.takeOwnership(SID_PW);
    step(1, "takeOwnership", r);
    if (r.failed()) return false;

    r = drive.activateLocking(SID_PW);
    step(2, "activateLocking", r);

    // Revert with SID
    r = drive.revert(SID_PW);
    step(3, "SedDrive::revert(SID)", r);

    return r.ok();
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Factory Reset — RevertSP and PSID Revert");
    if (!transport) return 1;

    // Parse --psid from extra args
    std::string psid;
    for (size_t i = 0; i < opts.extra.size(); i++) {
        if (opts.extra[i] == "--psid" && i + 1 < opts.extra.size()) {
            psid = opts.extra[i + 1];
        }
    }

    SID_PW = getPassword(opts, DEFAULT_SID_PW);
    ADMIN1_PW = SID_PW + "_Admin1";

    banner("12: Factory Reset");
    printf("  WARNING: This example destroys all data on the drive!\n\n");

    if (!confirmDestructive(opts, "factory-reset the drive (ALL data lost)")) return 0;

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_revertSP(transport, info.baseComId);
    ok &= scenario2_psidRevert(transport, info.baseComId, psid);
    ok &= scenario3_facade(opts.device.c_str(), opts);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
