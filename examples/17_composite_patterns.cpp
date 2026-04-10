/// @file 17_composite_patterns.cpp
/// @brief EvalComposite — Multi-Step Operations with Step Logging
///
/// TCG SPEC CONTEXT:
/// Many TCG operations require multiple protocol steps in sequence.
/// For example, "Take Ownership" requires:
///   1. Open anonymous session → read MSID
///   2. Close session
///   3. Open authenticated session with MSID
///   4. Set C_PIN_SID
///   5. Close session
///
/// EvalComposite wraps these multi-step sequences into single function calls.
/// Each CompositeResult contains:
///   - overall: did the entire sequence succeed?
///   - steps[]: individual StepEntry with name, result, and raw payloads
///   - passCount()/failCount(): summary statistics
///
/// This gives you the convenience of high-level operations with the
/// transparency of step-by-step execution.
///
/// API LAYER: EvalComposite (built on EvalApi)
/// PREREQUISITES: 01-05, 16 (EvalApi understanding)
///
/// Usage: ./17_composite_patterns /dev/nvmeX [--dump]

#include "example_common.h"

using composite::CompositeResult;

static const std::string SID_PW    = "TestSid17";
static const std::string ADMIN1_PW = "TestAdmin1_17";
static const std::string USER1_PW  = "TestUser1_17";

// Helper: print CompositeResult details
static void printCompositeResult(const CompositeResult& cr) {
    printf("    Overall: %s (%u passed, %u failed)\n",
           cr.ok() ? "OK" : "FAIL", cr.passCount(), cr.failCount());
    for (auto& entry : cr.steps) {
        printf("      %-30s %s\n", entry.name.c_str(),
               entry.result.ok() ? "OK" : entry.result.message().c_str());
    }
}

// ── Scenario 1: getMsid composite ──

static bool scenario1_getMsid(std::shared_ptr<ITransport> transport,
                               uint16_t comId) {
    scenario(1, "composite::getMsid()");

    EvalApi api;
    Bytes msid;

    // getMsid bundles: openSession → getCPin(MSID) → closeSession
    auto cr = composite::getMsid(api, transport, comId, msid);
    step(1, "getMsid", cr.overall);
    printCompositeResult(cr);
    if (cr.ok()) printString("MSID", msid);

    return cr.ok();
}

// ── Scenario 2: takeOwnership composite ──

static bool scenario2_takeOwnership(std::shared_ptr<ITransport> transport,
                                     uint16_t comId) {
    scenario(2, "composite::takeOwnership()");

    EvalApi api;

    auto cr = composite::takeOwnership(api, transport, comId, SID_PW);
    step(1, "takeOwnership", cr.overall);
    printCompositeResult(cr);

    return cr.ok();
}

// ── Scenario 3: activateAndSetup composite ──

static bool scenario3_activateAndSetup(std::shared_ptr<ITransport> transport,
                                        uint16_t comId) {
    scenario(3, "composite::activateAndSetup()");

    EvalApi api;

    // activateAndSetup bundles:
    //   1. Activate Locking SP (as SID in Admin SP)
    //   2. Set Admin1 password (in Locking SP)
    //   3. Enable User1 (in Locking SP)
    //   4. Set User1 password (in Locking SP)
    auto cr = composite::activateAndSetup(api, transport, comId,
                                           SID_PW, ADMIN1_PW, USER1_PW);
    step(1, "activateAndSetup", cr.overall);
    printCompositeResult(cr);

    return cr.ok();
}

// ── Scenario 4: configureRangeAndLock composite ──

static bool scenario4_configureRange(std::shared_ptr<ITransport> transport,
                                      uint16_t comId) {
    scenario(4, "composite::configureRangeAndLock()");

    EvalApi api;

    auto cr = composite::configureRangeAndLock(api, transport, comId,
                                                ADMIN1_PW,
                                                1,      // rangeId
                                                0,      // start LBA
                                                1024);  // length
    step(1, "configureRangeAndLock", cr.overall);
    printCompositeResult(cr);

    return cr.ok();
}

// ── Scenario 5: dataStoreRoundTrip composite ──

static bool scenario5_dataStoreRoundTrip(std::shared_ptr<ITransport> transport,
                                          uint16_t comId) {
    scenario(5, "composite::dataStoreRoundTrip()");

    EvalApi api;
    Bytes testData = {'C', 'o', 'm', 'p', 'o', 's', 'i', 't', 'e', '!'};

    auto cr = composite::dataStoreRoundTrip(api, transport, comId,
                                             ADMIN1_PW, 0, testData);
    step(1, "dataStoreRoundTrip", cr.overall);
    printCompositeResult(cr);

    return cr.ok();
}

// ── Scenario 6: cryptoEraseAndVerify composite ──

static bool scenario6_cryptoErase(std::shared_ptr<ITransport> transport,
                                   uint16_t comId) {
    scenario(6, "composite::cryptoEraseAndVerify()");

    EvalApi api;

    auto cr = composite::cryptoEraseAndVerify(api, transport, comId,
                                               ADMIN1_PW, 1);
    step(1, "cryptoEraseAndVerify", cr.overall);
    printCompositeResult(cr);

    return cr.ok();
}

// ── Scenario 7: revertToFactory composite ──

static bool scenario7_revert(std::shared_ptr<ITransport> transport,
                              uint16_t comId) {
    scenario(7, "composite::revertToFactory()");

    EvalApi api;

    auto cr = composite::revertToFactory(api, transport, comId, SID_PW);
    step(1, "revertToFactory", cr.overall);
    printCompositeResult(cr);

    return cr.ok();
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "EvalComposite — multi-step operations with step logging");
    if (!transport) return 1;

    banner("17: Composite Patterns");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_getMsid(transport, info.baseComId);
    ok &= scenario2_takeOwnership(transport, info.baseComId);
    ok &= scenario3_activateAndSetup(transport, info.baseComId);
    ok &= scenario4_configureRange(transport, info.baseComId);
    ok &= scenario5_dataStoreRoundTrip(transport, info.baseComId);
    ok &= scenario6_cryptoErase(transport, info.baseComId);
    ok &= scenario7_revert(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
