/// @file 03_sessions.cpp
/// @brief Session Lifecycle — TSN/HSN, Anonymous vs Authenticated
///
/// TCG SPEC CONTEXT:
/// A "session" is a conversation between Host and TPer within a specific
/// Security Provider (SP). TCG defines two SPs that every drive has:
///
///   - Admin SP (UID 0x0000020500000001): Manages ownership, credentials,
///     and the lifecycle of other SPs. Always available.
///
///   - Locking SP (UID 0x0000020500000002): Controls locking ranges,
///     encryption keys, MBR shadow, and DataStore. Must be "activated"
///     before use (starts in Manufactured-Inactive state).
///
/// Session types:
///   - Anonymous (read-only): No authentication. Used to read public
///     tables like C_PIN_MSID. SM_START_SESSION with hostSignAuth=0.
///   - Authenticated (read or read-write): Requires authority UID +
///     credential. SM_START_SESSION with HostChallenge and HostExchangeAuth.
///
/// Each session gets a pair of sequence numbers:
///   - TSN (TPer Session Number): assigned by the TPer
///   - HSN (Host Session Number): proposed by the Host (usually 1)
/// These go in every Packet header for the session's lifetime.
///
/// API LAYER: Session class directly, then SedDrive for comparison.
/// PREREQUISITES: 01 (Discovery), 02 (Properties for ComID)
///
/// Usage: ./03_sessions /dev/nvmeX [--dump]

#include "example_common.h"

// ── Scenario 1: Anonymous Read Session to Admin SP ──
//
// The simplest session: no credentials needed.
// You can read public tables but cannot write anything.

static bool scenario1_anonymousSession(std::shared_ptr<ITransport> transport,
                                        uint16_t comId) {
    scenario(1, "Anonymous Read Session to Admin SP");

    EvalApi api;

    // Create a Session object — it manages TSN/HSN state
    Session session(transport, comId);
    StartSessionResult ssr;

    // startSession() sends SM_START_SESSION (method 0xFF02) and
    // receives SM_SYNC_SESSION (method 0xFF03) response.
    //   SP = Admin SP, write = false (read-only)
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(1, "Open anonymous session to Admin SP", r);
    if (r.failed()) return false;

    // After SyncSession, we have TSN and HSN
    printf("    TSN (TPer assigned): %u\n", session.tperSessionNumber());
    printf("    HSN (Host proposed): %u\n", session.hostSessionNumber());
    printf("    Session is active:   %s\n", session.isActive() ? "yes" : "no");

    // Always close sessions explicitly!
    // closeSession() sends SM_CLOSE_SESSION (method 0xFF06).
    // If you don't close, the TPer may keep the session slot occupied.
    r = api.closeSession(session);
    step(2, "Close session", r);

    printf("    Session is active:   %s\n", session.isActive() ? "yes" : "no");

    return true;
}

// ── Scenario 2: Authenticated Session with MSID ──
//
// To modify tables, you need an authenticated write session.
// On a factory-state drive, SID password == MSID (the factory credential).
// Here we authenticate as SID using MSID.

static bool scenario2_authenticatedSession(std::shared_ptr<ITransport> transport,
                                            uint16_t comId) {
    scenario(2, "Authenticated Write Session (SID auth)");

    EvalApi api;

    // First, read MSID via anonymous session
    Session anonSession(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(anonSession, uid::SP_ADMIN, false, ssr);
    step(1, "Open anonymous session for MSID", r);
    if (r.failed()) return false;

    Bytes msid;
    r = api.getCPin(anonSession, uid::CPIN_MSID, msid);
    step(2, "Read C_PIN_MSID", r);
    api.closeSession(anonSession);

    if (r.failed() || msid.empty()) {
        printf("    Cannot read MSID (drive may be owned) — skipping auth test\n");
        return true;  // Not a failure, just can't demo
    }
    printHex("MSID", msid);

    // Now open an authenticated write session as SID using MSID.
    // This only works on factory-state drives (SID == MSID).
    // If the drive is already owned (SID != MSID), auth fails — that's OK.
    Session authSession(transport, comId);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(authSession, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, msid, ssr2);
    if (r.failed()) {
        step(3, "SID auth with MSID (drive is owned — skip)", true);
        printf("    Drive is already owned (SID != MSID).\n");
        printf("    To test this scenario, revert to factory state first:\n");
        printf("      ./12_factory_reset /dev/nvmeX --force\n");
        return true;
    }
    step(3, "Open SID-auth write session", r);

    printf("    TSN: %u, HSN: %u (authenticated write session)\n",
           authSession.tperSessionNumber(), authSession.hostSessionNumber());

    // We could write to tables here (e.g., change SID password)
    // For now, just demonstrate that we're authenticated and close.

    r = api.closeSession(authSession);
    step(4, "Close authenticated session", r);

    return true;
}

// ── Scenario 3: SedDrive RAII Session ──
//
// SedDrive provides login()/loginAnonymous() which return SedSession objects.
// SedSession is RAII — the session is closed when the object is destroyed.

static bool scenario3_facadeSession(const char* device, cli::CliOptions& opts) {
    scenario(3, "SedDrive RAII Sessions");

    SedDrive drive(device);
    if (opts.dump) drive.enableDump();

    auto r = drive.query();
    step(1, "SedDrive::query()", r);
    if (r.failed()) return false;

    // loginAnonymous() returns a SedSession — RAII, auto-closes
    {
        auto session = drive.loginAnonymous(Uid(uid::SP_ADMIN));
        step(2, "SedDrive::loginAnonymous(Admin SP)", session.openResult());
        if (session.ok()) {
            printf("    Session is active: %s\n", session.isActive() ? "yes" : "no");
            // Read MSID through the session
            Bytes pin;
            r = session.getPin(Uid(uid::CPIN_MSID), pin);
            step(3, "SedSession::getPin(MSID)", r);
            if (r.ok()) printString("MSID", pin);
        }
        // SedSession destructor calls close automatically
    }
    printf("    (SedSession destroyed — session closed)\n");

    return true;
}

// ── Scenario 4: withSession callback pattern ──
//
// For one-shot operations, withSession/withAnonymousSession provides
// a clean pattern: open, run your lambda, close — all in one call.

static bool scenario4_withSession(std::shared_ptr<ITransport> transport,
                                   uint16_t comId) {
    scenario(4, "withSession Callback Pattern");

    EvalApi api;
    Bytes msid;

    // composite::withAnonymousSession opens, calls your lambda, closes
    auto r = composite::withAnonymousSession(api, transport, comId,
        uid::SP_ADMIN,
        [&](Session& session) -> Result {
            return api.getCPin(session, uid::CPIN_MSID, msid);
        });
    step(1, "composite::withAnonymousSession", r);
    if (r.ok()) printString("MSID (via callback)", msid);

    return true;
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Session Lifecycle — TSN/HSN, anonymous vs authenticated sessions");
    if (!transport) return 1;

    banner("03: Sessions");

    // Get ComID from Discovery
    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_anonymousSession(transport, info.baseComId);
    ok &= scenario2_authenticatedSession(transport, info.baseComId);
    ok &= scenario3_facadeSession(opts.device.c_str(), opts);
    ok &= scenario4_withSession(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
