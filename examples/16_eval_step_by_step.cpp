/// @file 16_eval_step_by_step.cpp
/// @brief Full EvalApi Manual Protocol Control
///
/// TCG SPEC CONTEXT:
/// EvalApi is the lowest-level API in libsed. Every protocol step is
/// an independent function call with full access to raw payloads.
///
/// Why use EvalApi instead of SedDrive?
///   - Inspect raw sent/received payloads (RawResult.rawSendPayload/rawRecvPayload)
///   - Control every step independently (no bundled operations)
///   - Inject faults between steps (see example 18)
///   - Test edge cases and error recovery
///   - Compare byte-exact behavior with other implementations (sedutil, etc.)
///
/// EvalApi is stateless — it doesn't remember anything between calls.
/// The Session object carries all state (TSN, HSN, sequence numbers).
/// This makes EvalApi safe for multi-threaded use.
///
/// API LAYER: EvalApi exclusively
/// PREREQUISITES: 01-05, 15 (wire format knowledge)
///
/// Usage: ./16_eval_step_by_step /dev/nvmeX [--dump]

#include "example_common.h"

static const std::string SID_PW = "TestSid16";

// ── Scenario 1: Complete query flow with raw payloads ──
//
// Walk through Discovery → Properties → MSID with RawResult inspection.

static bool scenario1_fullQueryRaw(std::shared_ptr<ITransport> transport,
                                    uint16_t comId) {
    scenario(1, "Full Query Flow with Raw Payloads");

    EvalApi api;

    // Step 1: Discovery (no session needed)
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    step(1, "Discovery", r);

    // Step 2: Properties Exchange with raw inspection
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    step(2, "Properties Exchange", r);
    printf("    MaxComPacketSize: %u (TPer)\n", props.tperMaxComPacketSize);

    // Step 3: Open anonymous session — get the raw send/recv payloads
    Session session(transport, comId);
    StartSessionResult ssr;
    r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(3, "StartSession (anonymous)", r);
    if (r.failed()) return false;

    printf("    TSN=%u, HSN=%u\n",
           session.tperSessionNumber(), session.hostSessionNumber());

    // Step 4: Read MSID with RawResult to see the wire payloads
    Bytes msidPin;
    RawResult rawResult;
    r = api.getCPin(session, uid::CPIN_MSID, msidPin, rawResult);
    step(4, "getCPin(MSID) with RawResult", r);
    if (r.ok()) {
        printString("MSID", msidPin);
        printf("    Sent payload: %zu bytes\n", rawResult.rawSendPayload.size());
        printf("    Recv payload: %zu bytes\n", rawResult.rawRecvPayload.size());

        // Dump first 64 bytes of sent payload for inspection
        if (!rawResult.rawSendPayload.empty()) {
            dumpHex("Sent (first 64B)", rawResult.rawSendPayload.data(),
                    std::min((size_t)64, rawResult.rawSendPayload.size()));
        }
    }

    // Step 5: Close
    r = api.closeSession(session);
    step(5, "CloseSession", r);

    return true;
}

// ── Scenario 2: Explicit StartSession parameters ──
//
// Use sendStartSession/recvSyncSession for maximum control over
// the StartSession/SyncSession handshake.

static bool scenario2_explicitStartSession(std::shared_ptr<ITransport> transport,
                                            uint16_t comId) {
    scenario(2, "Explicit StartSession/SyncSession");

    EvalApi api;

    // Build StartSession parameters manually
    StartSessionParams params;
    params.hostSessionId = 42;  // Custom HSN
    params.spUid = uid::SP_ADMIN;
    params.write = false;

    // Send StartSession and get the raw sent payload
    Bytes sentPayload;
    auto r = api.sendStartSession(transport, comId, params, sentPayload);
    step(1, "sendStartSession (custom HSN=42)", r);
    if (r.failed()) return false;

    printf("    Sent StartSession payload: %zu bytes\n", sentPayload.size());

    // Receive SyncSession
    SyncSessionResult syncResult;
    r = api.recvSyncSession(transport, comId, syncResult);
    step(2, "recvSyncSession", r);
    if (r.ok()) {
        printf("    TPer assigned TSN: %u\n", syncResult.tperSessionNumber);
        printf("    HSN echoed back: %u\n", syncResult.hostSessionNumber);

        // Create session with the result to close it properly
        Session session(transport, comId);
        // Need to close the session that was opened
        api.closeSession(session);
    }
    return true;
}

// ── Scenario 3: Generic table access ──
//
// Use tableGet/tableSet for any table, any column range.

static bool scenario3_genericTable(std::shared_ptr<ITransport> transport,
                                    uint16_t comId) {
    scenario(3, "Generic Table Get/Set");

    EvalApi api;
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    if (r.failed()) return false;

    // tableGetAll: returns all columns of a row
    TableResult tResult;
    r = api.tableGetAll(session, uid::CPIN_MSID, tResult);
    step(1, "tableGetAll(C_PIN_MSID)", r);
    if (r.ok()) {
        printf("    Returned %zu values:\n", tResult.columns.size());
        for (auto& [col, token] : tResult.columns) {
            printf("    Column %u: type=%d", col, static_cast<int>(token.type));
            if (token.isByteSequence) {
                printf(" bytes[%zu]", token.getBytes().size());
            } else if (token.isAtom()) {
                printf(" uint=%lu", token.getUint());
            }
            printf("\n");
        }
    }

    // Read a specific column
    Token pinToken;
    RawResult colRaw;
    r = api.tableGetColumn(session, uid::CPIN_MSID, 3, pinToken, colRaw);
    step(2, "tableGetColumn(MSID, col=3/PIN)", r);
    if (r.ok() && pinToken.isByteSequence) {
        printHex("PIN value", pinToken.getBytes());
    }

    api.closeSession(session);
    return true;
}

// ── Scenario 4: Take ownership with raw result inspection ──

static bool scenario4_ownershipRaw(std::shared_ptr<ITransport> transport,
                                    uint16_t comId) {
    scenario(4, "Take Ownership — Inspecting Every Step");

    EvalApi api;

    // Read MSID
    Bytes msid;
    RawResult raw;
    auto r = composite::withAnonymousSession(api, transport, comId,
        uid::SP_ADMIN, [&](Session& s) { return api.getCPin(s, uid::CPIN_MSID, msid, raw); });
    step(1, "Read MSID", r);
    if (r.failed() || msid.empty()) return false;

    // Authenticated session and Set C_PIN_SID
    Session authSession(transport, comId);
    StartSessionResult ssr;
    r = api.startSessionWithAuth(authSession, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, msid, ssr);
    step(2, "SID auth", r);
    if (r.failed()) return false;

    r = api.setCPin(authSession, uid::CPIN_SID, SID_PW, raw);
    step(3, "setCPin(SID, newPw)", r);
    printf("    Set payload: %zu bytes\n", raw.rawSendPayload.size());
    printf("    Response:    %zu bytes\n", raw.rawRecvPayload.size());

    api.closeSession(authSession);

    // Revert
    Bytes pw(SID_PW.begin(), SID_PW.end());
    r = composite::withSession(api, transport, comId,
        uid::SP_ADMIN, true, uid::AUTH_SID, pw,
        [&](Session& s) { return api.revertSP(s, uid::SP_ADMIN); });
    step(4, "Revert (cleanup)", r);

    return true;
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "EvalApi Step-by-Step — full manual protocol control");
    if (!transport) return 1;

    banner("16: EvalApi Step-by-Step");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_fullQueryRaw(transport, info.baseComId);
    ok &= scenario2_explicitStartSession(transport, info.baseComId);
    ok &= scenario3_genericTable(transport, info.baseComId);
    ok &= scenario4_ownershipRaw(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
