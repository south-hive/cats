/// @file 05_take_ownership.cpp
/// @brief Take Ownership — Change SID Password from MSID
///
/// TCG SPEC CONTEXT:
/// "Taking ownership" means changing the SID password from the factory
/// default (MSID) to a secret only you know. This is the most important
/// step in securing a drive — until you do this, anyone who can read
/// the MSID (printed on the drive label) has full control.
///
/// Protocol flow (AppNote Section 3):
///   1. Anonymous session → Admin SP → read C_PIN_MSID.PIN
///   2. Authenticated write session → Admin SP → SID auth with MSID
///   3. Set(C_PIN_SID, column PIN, newPassword)
///   4. Close session
///
/// After this, the SID password is your chosen secret. The MSID doesn't
/// change — it's burned into the drive — but it no longer grants access.
///
/// IMPORTANT: Remember your SID password! If you lose it and don't have
/// the PSID (Physical Security ID, also on the label), the only way to
/// recover is PSID Revert, which destroys all data and keys.
///
/// This example reverts to factory state at the end to leave the drive clean.
///
/// API LAYER: Both EvalApi (step-by-step) and SedDrive (one-liner).
/// PREREQUISITES: 01-04 (Discovery, Properties, Sessions, MSID)
///
/// Usage: ./05_take_ownership /dev/nvmeX [--dump]

#include "example_common.h"

static std::string TEST_SID_PW;

// ── Scenario 1: Take Ownership step-by-step (EvalApi) ──
//
// The full protocol flow with explicit session management.
// This is what happens "under the hood" when you call SedDrive::takeOwnership().

static bool scenario1_evalOwnership(std::shared_ptr<ITransport> transport,
                                     uint16_t comId,
                                     const PropertiesResult& props) {
    scenario(1, "Take Ownership Step-by-Step (EvalApi)");

    EvalApi api;

    // ── Step 1: Read MSID (anonymous) ──
    Session anonSession(transport, comId);
    anonSession.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    auto r = api.startSession(anonSession, uid::SP_ADMIN, false, ssr);
    step(1, "Anonymous session to Admin SP", r);
    if (r.failed()) return false;

    Bytes msid;
    r = api.getCPin(anonSession, uid::CPIN_MSID, msid);
    step(2, "Read C_PIN_MSID", r);
    api.closeSession(anonSession);
    if (r.failed() || msid.empty()) {
        printf("    Cannot read MSID\n");
        return false;
    }
    printString("MSID", msid);

    // ── Step 2: Authenticate as SID using MSID ──
    Session authSession(transport, comId);
    authSession.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(authSession, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, msid, ssr2);
    step(3, "SID-auth write session (MSID credential)", r);
    if (r.failed()) {
        printf("    SID auth with MSID failed — drive may already be owned\n");
        return false;
    }

    // ── Step 3: Change SID password ──
    // setCPin() wraps: Set(C_PIN_SID, column=3(PIN), newPassword)
    r = api.setCPin(authSession, uid::CPIN_SID, TEST_SID_PW);
    step(4, "Set C_PIN_SID to new password", r);
    api.closeSession(authSession);
    if (r.failed()) return false;

    printf("    SID password changed to: \"%s\"\n", TEST_SID_PW.c_str());

    // ── Step 4: Verify — auth with new password ──
    Session verifySession(transport, comId);
    verifySession.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr3;
    Bytes sidPin = pwBytes(TEST_SID_PW);
    r = api.startSessionWithAuth(verifySession, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, sidPin, ssr3);
    step(5, "Verify: SID auth with new password", r);
    api.closeSession(verifySession);
    if (r.failed()) return false;


    // ── Step 5: Verify old MSID no longer works ──
    Session failSession(transport, comId);
    failSession.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr4;
    r = api.startSessionWithAuth(failSession, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, msid, ssr4);
    bool oldFailed = r.failed();
    step(6, "Verify: SID auth with old MSID fails", oldFailed);
    if (!oldFailed) api.closeSession(failSession);

    return oldFailed;
}

// ── Scenario 2: Revert to factory (restore MSID as SID) ──
//
// Important: always clean up after ownership tests!
// revertSP() on Admin SP resets SID password back to MSID.

static bool scenario2_revert(std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const PropertiesResult& props) {
    scenario(2, "Revert to Factory State");

    EvalApi api;

    // Auth as SID with the new password
    Session session(transport, comId);
    session.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    Bytes sidPin = pwBytes(TEST_SID_PW);
    auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                       uid::AUTH_SID, sidPin, ssr);
    step(1, "SID auth with current password", r);
    if (r.failed()) return false;

    // Revert Admin SP — this resets SID password back to MSID
    r = api.revertSP(session, uid::SP_ADMIN);
    step(2, "RevertSP(Admin SP)", r);
    // Session is invalidated after revert, no need to close

    // Verify MSID works again
    if (r.ok()) {
        Session verifySession(transport, comId);
        verifySession.setMaxComPacketSize(props.tperMaxComPacketSize);
        StartSessionResult ssr2;
        auto r2 = api.startSession(verifySession, uid::SP_ADMIN, false, ssr2);
        Bytes msid;
        if (r2.ok()) {
            api.getCPin(verifySession, uid::CPIN_MSID, msid);
            api.closeSession(verifySession);
        }

        if (!msid.empty()) {
            Session msidAuth(transport, comId);
            msidAuth.setMaxComPacketSize(props.tperMaxComPacketSize);
            StartSessionResult ssr3;
            r2 = api.startSessionWithAuth(msidAuth, uid::SP_ADMIN, true,
                                           uid::AUTH_SID, msid, ssr3);
            step(3, "Verify: SID auth with MSID works again", r2);
            if (r2.ok()) api.closeSession(msidAuth);
        }
    }

    return r.ok();
}

// ── Scenario 3: SedDrive one-liner ──
//
// SedDrive::takeOwnership() does everything in one call.
// Then SedDrive::revert() cleans up.

static bool scenario3_facade(const char* device, cli::CliOptions& opts) {
    scenario(3, "SedDrive One-Liner Ownership");

    SedDrive drive(device);
    if (opts.dump) drive.enableDump(std::cerr, opts.dumpLevel);
    auto r = drive.query();
    if (r.failed()) return false;

    r = drive.takeOwnership(TEST_SID_PW);
    step(1, "SedDrive::takeOwnership()", r);
    if (r.failed()) return false;

    // Clean up
    r = drive.revert(TEST_SID_PW);
    step(2, "SedDrive::revert() (back to factory)", r);

    return r.ok();
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Take Ownership — change SID password from MSID");
    if (!transport) return 1;

    TEST_SID_PW = getPassword(opts);

    banner("05: Take Ownership");
    printf("  WARNING: This example changes the SID password and reverts.\n");
    printf("  The drive should be in factory state (SID == MSID).\n\n");

    if (!confirmDestructive(opts, "change the SID password")) return 0;

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    // Properties must be exchanged before any session to match the sedutil wire
    // pattern — some drives return NOT_AUTHORIZED / TPER_MALFUNCTION on auth
    // attempts made before Properties. Internally this also runs StackReset
    // to force the ComID to Issued(idle) state.
    PropertiesResult props;
    r = api.exchangeProperties(transport, info.baseComId, props);
    if (r.failed()) { printf("Properties exchange failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_evalOwnership(transport, info.baseComId, props);
    ok &= scenario2_revert(transport, info.baseComId, props);
    ok &= scenario3_facade(opts.device.c_str(), opts);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
