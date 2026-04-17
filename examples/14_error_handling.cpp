/// @file 14_error_handling.cpp
/// @brief Error Handling — Method Status Codes, Auth Failures, Error Layers
///
/// TCG SPEC CONTEXT:
/// Errors in TCG SED come from multiple layers:
///
///   Layer 1 — Transport: NVMe ioctl failures, timeout, device not found
///     ErrorCode range: 100-199
///
///   Layer 2 — Protocol: Malformed packets, invalid ComID, session errors
///     ErrorCode range: 200-299 (protocol), 300-399 (session)
///
///   Layer 3 — Method Status: The TPer's response to a method call
///     MethodStatus codes (embedded in SubPacket response):
///       0x00 = Success
///       0x01 = NotAuthorized — wrong password or insufficient privileges
///       0x03 = SPBusy — SP is in use by another session
///       0x05 = SPDisabled — SP not activated (Locking SP in Manufactured)
///       0x07 = NoSessionsAvailable — all session slots occupied
///       0x0C = InvalidParameter — malformed method arguments
///       0x12 = AuthorityLockedOut — too many failed auth attempts
///
///   Layer 4 — Application: Our library's interpretation of the above
///     ErrorCode range: 400-499 (method), 500-599 (discovery), 600-699 (auth)
///
/// Understanding which layer an error comes from is essential for debugging.
///
/// API LAYER: EvalApi (to trigger specific errors)
/// PREREQUISITES: 01-05
///
/// Usage: ./14_error_handling /dev/nvmeX [--dump]

#include "example_common.h"

// ── Scenario 1: NotAuthorized (wrong password) ──

static bool scenario1_notAuthorized(std::shared_ptr<ITransport> transport,
                                     uint16_t comId) {
    scenario(1, "NotAuthorized — Wrong Password");

    EvalApi api;

    // Try to authenticate with a wrong password
    Session session(transport, comId);
    StartSessionResult ssr;
    Bytes wrongPw = {'w', 'r', 'o', 'n', 'g'};
    auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                       uid::AUTH_SID, wrongPw, ssr);

    // Expected: NotAuthorized (0x01)
    step(1, "SID auth with wrong password", r.failed());
    printf("    Error code: %d\n", static_cast<int>(r.code()));
    printf("    Message: %s\n", r.message().c_str());

    // The Result object carries the full error chain
    // You can check for specific error types:
    bool isAuthError = (r.code() >= ErrorCode::AuthFailed &&
                        r.code() <= ErrorCode::AuthLockedOut);
    printf("    Is auth error: %s\n", isAuthError ? "yes" : "no");

    return r.failed();  // Expected to fail
}

// ── Scenario 2: SPDisabled (session to non-activated Locking SP) ──

static bool scenario2_spDisabled(std::shared_ptr<ITransport> transport,
                                  uint16_t comId) {
    scenario(2, "SPDisabled — Locking SP Not Activated");

    EvalApi api;
    DiscoveryInfo info;
    api.discovery0(transport, info);

    if (info.lockingEnabled) {
        printf("    Locking SP is already active — skipping\n");
        printf("    (Run on factory-state drive to see this error)\n");
        return true;
    }

    // Try to open a session to Locking SP when it's not activated
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(session, uid::SP_LOCKING, true, ssr);

    step(1, "Session to inactive Locking SP", r.failed());
    printf("    Error: %s\n", r.message().c_str());
    printf("    (TPer returns SPDisabled because Locking SP is Manufactured-Inactive)\n");

    return r.failed();  // Expected to fail
}

// ── Scenario 3: InvalidParameter (malformed method) ──

static bool scenario3_invalidParam(std::shared_ptr<ITransport> transport,
                                    uint16_t comId) {
    scenario(3, "InvalidParameter — Bad Method Arguments");

    EvalApi api;

    // Open a valid anonymous session
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(session, uid::SP_ADMIN, true, ssr);
    if (r.failed()) return false;

    // Try to read from a non-existent table row
    // This should return an error (the specific error depends on the TPer)
    TableResult tResult;
    r = api.tableGet(session, 0xDEADBEEF00000000ULL, 0, 10, tResult);
    step(1, "Get on non-existent row", r.failed());
    printf("    Error: %s\n", r.message().c_str());

    api.closeSession(session);
    return true;
}

// ── Scenario 4: Transport errors ──

static bool scenario4_transportErrors() {
    scenario(4, "Transport Errors");

    // Try to open a transport to a non-existent device
    auto transport = TransportFactory::createNvme("/dev/nvme_nonexistent_99");
    bool opened = (transport != nullptr);

    // On Android/non-Linux, transport creation might still succeed
    // but ifSend/ifRecv will fail
    if (transport) {
        uint8_t buf[512] = {};
        MutableByteSpan span(buf, sizeof(buf));
        size_t received = 0;
        auto r = transport->ifRecv(0x01, 0x0001, span, received);
        step(1, "ifRecv on bad device", r.failed());
        printf("    Error: %s\n", r.message().c_str());
    } else {
        step(1, "Transport creation fails for bad path", true);
    }

    return true;
}

// ── Scenario 5: Error code ranges ──

static bool scenario5_errorCodeRanges() {
    scenario(5, "Error Code Ranges Reference");

    printf("    Transport errors:  100-199\n");
    printf("    Protocol errors:   200-299\n");
    printf("    Session errors:    300-399\n");
    printf("    Method errors:     400-499\n");
    printf("    Discovery errors:  500-599\n");
    printf("    Auth errors:       600-699\n");
    printf("\n    Key MethodStatus values:\n");
    printf("      0x00 Success\n");
    printf("      0x01 NotAuthorized\n");
    printf("      0x03 SPBusy\n");
    printf("      0x05 SPDisabled\n");
    printf("      0x07 NoSessionsAvailable\n");
    printf("      0x0C InvalidParameter\n");
    printf("      0x12 AuthorityLockedOut\n");

    return true;
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Error Handling — understanding TCG SED error layers");
    if (!transport) return 1;

    banner("14: Error Handling");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_notAuthorized(transport, info.baseComId);
    ok &= scenario2_spDisabled(transport, info.baseComId);
    ok &= scenario3_invalidParam(transport, info.baseComId);
    ok &= scenario4_transportErrors();
    ok &= scenario5_errorCodeRanges();

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
