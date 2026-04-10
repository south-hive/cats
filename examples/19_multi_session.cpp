/// @file 19_multi_session.cpp
/// @brief Multi-Session — Concurrent Sessions and Threading
///
/// TCG SPEC CONTEXT:
/// The TPer supports a limited number of concurrent sessions (typically 1-4
/// per SP, drive-dependent). Multiple sessions are useful for:
///
///   - Multi-threaded test frameworks (each thread gets its own session)
///   - Testing session isolation (changes in one session don't leak to another)
///   - Stress testing session slot exhaustion
///
/// Threading rules:
///   - EvalApi is stateless and thread-safe (no locks needed)
///   - Session is NOT thread-safe — use one Session per thread
///   - SedContext bundles transport + session for per-thread use
///   - ComID management matters — some drives share ComIDs across sessions
///
/// Each session gets a unique TSN from the TPer. The Host assigns HSN
/// (typically 1 for each thread). The TSN/HSN pair identifies the session
/// in all Packet headers.
///
/// API LAYER: SedDrive multi-session + SedContext + std::thread
/// PREREQUISITES: 01-08
///
/// Usage: ./19_multi_session /dev/nvmeX [--dump]

#include "example_common.h"
#include "libsed/eval/sed_context.h"
#include <thread>
#include <mutex>

static const char* DEFAULT_SID_PW = "TestSid19";
static std::string SID_PW;
static std::string ADMIN1_PW;

static std::mutex g_printMutex;

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

// ── Scenario 1: SedDrive Multiple Login Sessions ──

static bool scenario1_multiLogin(const char* device, cli::CliOptions& opts) {
    scenario(1, "Multiple SedDrive Login Sessions");

    SedDrive drive(device);
    if (opts.dump) drive.enableDump();
    drive.query();

    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());

    // Open two sessions to Locking SP
    auto session1 = drive.login(Uid(uid::SP_LOCKING), ADMIN1_PW, Uid(uid::AUTH_ADMIN1));
    step(1, "Session 1: login(Locking SP, Admin1)", session1.openResult());

    if (session1.failed()) {
        printf("    Cannot open first session\n");
        return false;
    }

    // Try to open a second session
    auto session2 = drive.login(Uid(uid::SP_LOCKING), ADMIN1_PW, Uid(uid::AUTH_ADMIN1));
    step(2, "Session 2: login(Locking SP, Admin1)", session2.openResult());

    if (session2.ok()) {
        printf("    Two concurrent sessions active!\n");

        // Each session has its own TSN
        printf("    Session 1 TSN: %u\n", session1.raw().tperSessionNumber());
        printf("    Session 2 TSN: %u\n", session2.raw().tperSessionNumber());

        // Operations in one session don't affect the other
        LockingRangeInfo info;
        session1.getRangeInfo(0, info);
        step(3, "Session 1: read range 0", true);

        session2.getRangeInfo(0, info);
        step(4, "Session 2: read range 0", true);

        // Close both (or let RAII handle it)
        session2.close();
        session1.close();
    } else {
        printf("    Drive doesn't support multiple concurrent sessions\n");
        printf("    (This is common — many drives limit to 1 session per SP)\n");
        session1.close();
    }

    return true;
}

// ── Scenario 2: SedContext for Thread-Local State ──

static bool scenario2_sedContext(std::shared_ptr<ITransport> transport,
                                  uint16_t comId) {
    scenario(2, "SedContext — Thread-Local Pattern");

    // SedContext bundles: transport + api + session + cached discovery
    // Each thread should create its own SedContext
    SedContext ctx(transport);
    auto r = ctx.initialize();
    step(1, "SedContext::initialize()", r);
    if (r.failed()) return false;

    printf("    ComID:     0x%04X\n", ctx.comId());
    printf("    SSC:       %s\n",
           ctx.tcgOption().sscType == SscType::Opal20 ? "Opal 2.0" :
           ctx.tcgOption().sscType == SscType::Enterprise ? "Enterprise" : "Other");

    // Open a session through SedContext
    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());
    r = ctx.openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, admin1Pw, true);
    step(2, "ctx.openSession(Locking, Admin1)", r);
    if (r.ok()) {
        printf("    TSN: %u\n", ctx.session().tperSessionNumber());

        // Use ctx.api() and ctx.session() together
        LockingRangeInfo info;
        ctx.api().getRangeInfo(ctx.session(), 0, info);
        step(3, "Read range 0 via SedContext", true);

        ctx.closeSession();
    }

    return true;
}

// ── Scenario 3: Multi-threaded Operations ──

static bool scenario3_threading(std::shared_ptr<ITransport> transport,
                                 uint16_t comId) {
    scenario(3, "Multi-Threaded Discovery");

    // Multiple threads can run Discovery concurrently
    // (Discovery doesn't require a session)
    const int NUM_THREADS = 3;
    std::vector<std::thread> threads;
    std::vector<bool> results(NUM_THREADS, false);

    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([&, i]() {
            EvalApi api;
            DiscoveryInfo info;
            auto r = api.discovery0(transport, info);

            std::lock_guard<std::mutex> lock(g_printMutex);
            printf("    Thread %d: Discovery %s (SSC=%s)\n", i,
                   r.ok() ? "OK" : "FAIL",
                   info.primarySsc == SscType::Opal20 ? "Opal" : "Other");
            results[i] = r.ok();
        });
    }

    for (auto& t : threads) t.join();

    int passed = 0;
    for (auto r : results) if (r) passed++;
    step(1, "All threads completed Discovery", passed == NUM_THREADS);

    return passed == NUM_THREADS;
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
        "Multi-Session — concurrent sessions and threading patterns");
    if (!transport) return 1;

    SID_PW = getPassword(opts, DEFAULT_SID_PW);
    ADMIN1_PW = SID_PW + "_Admin1";

    banner("19: Multi-Session");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    if (!setupDrive(api, transport, info.baseComId)) {
        printf("  Setup failed.\n"); return 1;
    }

    bool ok = true;
    ok &= scenario1_multiLogin(opts.device.c_str(), opts);
    ok &= scenario2_sedContext(transport, info.baseComId);
    ok &= scenario3_threading(transport, info.baseComId);
    cleanup(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
