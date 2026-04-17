/// @file 18_fault_injection.cpp
/// @brief Fault Injection — FaultBuilder and TestContext
///
/// TCG SPEC CONTEXT:
/// Testing SED software requires verifying behavior under failure conditions.
/// What happens when:
///   - A packet is corrupted in transit?
///   - The TPer returns an unexpected error?
///   - A session times out mid-operation?
///   - Authentication fails after a partial setup?
///
/// libsed's debug layer provides:
///
///   FaultBuilder: Fluent API to define fault injection rules
///     .at(FaultPoint)   — where in the protocol to inject
///     .returnError()    — make a step return an error code
///     .corrupt()        — corrupt payload bytes
///     .delay()          — add latency
///     .drop()           — silently drop the packet
///     .replaceWith()    — substitute a different payload
///     .callback()       — custom logic
///     .once()/.times(n)/.always() — how many times to fire
///
///   TestContext: Manages armed fault rules and test state
///     .arm(rule)        — activate a fault rule
///     .disarmAll()      — clear all rules
///
///   FaultPoints (24 injection points):
///     BeforeSend, AfterSend, BeforeRecv, AfterRecv,
///     BeforeStartSession, AfterStartSession,
///     BeforeCloseSession, BeforeAuthenticate, etc.
///
/// API LAYER: EvalApi + Debug (FaultBuilder, TestContext)
/// PREREQUISITES: 01-05, 16 (EvalApi understanding)
///
/// Usage: ./18_fault_injection /dev/nvmeX [--dump]

#include "example_common.h"
#include "libsed/debug/fault_builder.h"
#include "libsed/debug/test_context.h"

using namespace libsed::debug;

// ── Scenario 1: Simulate Transport Failure ──

static bool scenario1_transportFailure(std::shared_ptr<ITransport> transport,
                                        uint16_t comId) {
    scenario(1, "Simulate Transport Send Failure");

    EvalApi api;

    // Arm a fault: make the next IF-SEND return an error
    FaultBuilder builder;
    auto rule = builder
        .at(FaultPoint::BeforeIfSend)
        .returnError(ErrorCode::TransportSendFailed)
        .once()
        .build();

    auto ruleId = TestContext::instance().armFault(rule);
    printf("    Armed fault rule: %s\n", ruleId.c_str());

    // Try Properties Exchange — should fail due to injected fault
    PropertiesResult props;
    auto r = api.exchangeProperties(transport, comId, props);
    step(1, "Properties with injected send failure", r.failed());
    printf("    Error: %s\n", r.message().c_str());

    // Disarm and retry — should succeed now
    TestContext::instance().disarmAllFaults();
    r = api.exchangeProperties(transport, comId, props);
    step(2, "Properties after disarm (should succeed)", r);

    return true;
}

// ── Scenario 2: Corrupt Payload ──

static bool scenario2_corruptPayload(std::shared_ptr<ITransport> transport,
                                      uint16_t comId) {
    scenario(2, "Corrupt Outgoing Payload");

    EvalApi api;

    // Arm: corrupt the send payload (flip a byte at offset 30)
    FaultBuilder builder;
    auto rule = builder
        .at(FaultPoint::BeforeIfSend)
        .corrupt(30, 0xFF)  // XOR byte at offset 30 with 0xFF
        .once()
        .build();

    TestContext::instance().armFault(rule);

    // Properties with corrupted payload — TPer should reject
    PropertiesResult props;
    auto r = api.exchangeProperties(transport, comId, props);
    step(1, "Properties with corrupted payload", r.failed());
    printf("    Result: %s\n", r.message().c_str());

    TestContext::instance().disarmAllFaults();
    return true;
}

// ── Scenario 3: Multi-fire Faults ──

static bool scenario3_multiFire(std::shared_ptr<ITransport> transport,
                                 uint16_t comId) {
    scenario(3, "Multi-Fire Fault (fail N times)");

    EvalApi api;

    // Arm: fail the first 2 attempts, then succeed
    FaultBuilder builder;
    auto rule = builder
        .at(FaultPoint::BeforeIfSend)
        .returnError(ErrorCode::TransportSendFailed)
        .times(2)  // Fail first 2 calls only
        .build();

    TestContext::instance().armFault(rule);

    PropertiesResult props;
    for (int i = 0; i < 3; i++) {
        auto r = api.exchangeProperties(transport, comId, props);
        char label[64];
        snprintf(label, sizeof(label), "Attempt %d", i + 1);
        step(i + 1, label, r);
        printf("    %s\n", r.ok() ? "Success" : r.message().c_str());
    }

    TestContext::instance().disarmAllFaults();
    return true;
}

// ── Scenario 4: Fault Callback ──

static bool scenario4_callback(std::shared_ptr<ITransport> transport,
                                uint16_t comId) {
    scenario(4, "Custom Fault Callback");

    EvalApi api;
    int callCount = 0;

    // Arm: custom callback that logs and allows the call
    FaultBuilder builder;
    auto rule = builder
        .at(FaultPoint::BeforeIfSend)
        .callback([&callCount](Bytes& payload) -> Result {
            callCount++;
            printf("    [Callback] Intercepted send #%d, payload %zu bytes\n",
                   callCount, payload.size());
            // Return Success to allow the call to proceed
            return ErrorCode::Success;
        })
        .times(3)
        .build();

    TestContext::instance().armFault(rule);

    // Run some operations — callback will fire on each send
    PropertiesResult props;
    api.exchangeProperties(transport, comId, props);

    Session session(transport, comId);
    StartSessionResult ssr;
    api.startSession(session, uid::SP_ADMIN, true, ssr);
    api.closeSession(session);

    step(1, "Callback fired on sends", callCount > 0);
    printf("    Total callback invocations: %d\n", callCount);

    TestContext::instance().disarmAllFaults();
    return true;
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Fault Injection — FaultBuilder and TestContext");
    if (!transport) return 1;

    banner("18: Fault Injection");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_transportFailure(transport, info.baseComId);
    ok &= scenario2_corruptPayload(transport, info.baseComId);
    ok &= scenario3_multiFire(transport, info.baseComId);
    ok &= scenario4_callback(transport, info.baseComId);

    // Always clean up
    TestContext::instance().disarmAllFaults();

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
