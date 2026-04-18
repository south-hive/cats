/// @file 21_transactions.cpp
/// @brief TCG Transactions — explicit Start / Commit / Rollback
///
/// TCG SPEC CONTEXT:
/// TCG Core Spec §3.2.1.3 lets a host group multiple method calls into an
/// atomic transaction. The host sends the StartTransaction token (0xFB) to
/// open the group; every subsequent Set/Get/etc. within the same session
/// accumulates in the TPer. The group closes when the host sends
/// EndTransaction (0xFC) + a 1-byte commit status:
///   - 0x00 → commit (TPer applies all accumulated ops atomically)
///   - 0x01 → abort  (TPer discards them)
///
/// WHY EXPLICIT BOUNDARIES?
/// TC scenarios need to observe NVMe transport errors and TCG method status
/// independently at each boundary. A "withTransaction(fn)" RAII helper would
/// hide that detail, which is exactly what TC platforms do NOT want. So
/// libsed exposes the primitives and the caller composes manually:
///
///     EvalApi api;
///     RawResult txStart, txEnd, setRaw;
///
///     api.startTransaction(session, txStart);
///     // inspect txStart.transportError  (NVMe layer)
///     // inspect txStart.methodResult.status()  (TCG layer)
///
///     api.setRange(session, 1, 0, 0x1000, true, true, setRaw);
///     // inspect setRaw similarly
///
///     if (setRaw.ok() && setRaw.methodResult.isSuccess()) {
///         api.commitTransaction(session, txEnd);
///     } else {
///         api.rollbackTransaction(session, txEnd);
///     }
///
/// VENDOR VARIANCE WARNING:
/// Real Opal drives have uneven transaction support. Many return status
/// 0x0F (TPer_Malfunction) or 0x10 (TRANSACTION_FAILURE) instead of
/// implementing the semantics. This example prints status bytes at every
/// step so you can see exactly what your drive does without guessing.
///
/// API LAYER: EvalApi only — SedDrive facade does not expose these on
/// purpose (transactions are evaluation-layer concerns, not app concerns).
/// PREREQUISITES: 03 (Sessions), 04 (MSID), 14 (Error handling)
///
/// Usage: ./21_transactions /dev/nvmeX [--dump]

#include "example_common.h"

// ── Helper: print raw result breakdown ─────────────────────────────

static void printRaw(const char* label, const RawResult& raw) {
    const char* tr = raw.transportError == ErrorCode::Success ? "OK" : "ERR";
    const char* md = raw.methodResult.isSuccess() ? "OK" : "ERR";
    printf("    [%s]  transport=%s(%d)  method=%s(0x%02X %s)\n",
           label,
           tr, static_cast<int>(raw.transportError),
           md, raw.methodResult.status(),
           raw.methodResult.statusMessage().c_str());
    printf("          sent=%zuB  recv=%zuB\n",
           raw.rawSendPayload.size(), raw.rawRecvPayload.size());
}

// ── Scenario 1: Empty transaction — does the drive accept start + commit? ──

static bool scenario1_emptyCommit(std::shared_ptr<ITransport> transport,
                                    uint16_t comId) {
    scenario(1, "Empty transaction: Start → Commit (probe support)");

    EvalApi api;
    Session session(transport, comId);
    StartSessionResult ssr;

    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(1, "Open anonymous AdminSP session", r);
    if (r.failed()) return false;

    RawResult txStart, txEnd;
    api.startTransaction(session, txStart);
    step(2, "StartTransaction", txStart.transportError);
    printRaw("start", txStart);

    api.commitTransaction(session, txEnd);
    step(3, "CommitTransaction", txEnd.transportError);
    printRaw("commit", txEnd);

    api.closeSession(session);
    return true;
}

// ── Scenario 2: Start → Get(MSID) → Commit (operation inside transaction) ──

static bool scenario2_readInside(std::shared_ptr<ITransport> transport,
                                   uint16_t comId) {
    scenario(2, "Transaction with a read inside: Start → Get(MSID) → Commit");

    EvalApi api;
    Session session(transport, comId);
    StartSessionResult ssr;

    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(1, "Open anonymous AdminSP session", r);
    if (r.failed()) return false;

    RawResult txStart, txEnd;
    api.startTransaction(session, txStart);
    step(2, "StartTransaction", txStart.transportError);
    printRaw("start", txStart);

    Bytes msid;
    r = api.getCPin(session, uid::CPIN_MSID, msid);
    step(3, "Get(C_PIN_MSID) inside transaction", r);
    if (r.ok()) printf("          MSID bytes = %zu\n", msid.size());

    api.commitTransaction(session, txEnd);
    step(4, "CommitTransaction", txEnd.transportError);
    printRaw("commit", txEnd);

    api.closeSession(session);
    return true;
}

// ── Scenario 3: Start → Get → Rollback (explicit abort) ─────────────

static bool scenario3_rollback(std::shared_ptr<ITransport> transport,
                                 uint16_t comId) {
    scenario(3, "Explicit rollback: Start → Get → Rollback");

    EvalApi api;
    Session session(transport, comId);
    StartSessionResult ssr;

    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(1, "Open anonymous AdminSP session", r);
    if (r.failed()) return false;

    RawResult txStart, txEnd;
    api.startTransaction(session, txStart);
    step(2, "StartTransaction", txStart.transportError);
    printRaw("start", txStart);

    Bytes msid;
    r = api.getCPin(session, uid::CPIN_MSID, msid);
    step(3, "Get(C_PIN_MSID) inside transaction", r);

    // Decide to roll back. In a real scenario this would follow an error
    // check across the preceding operations; here we roll back unconditionally
    // so the demo is non-destructive.
    api.rollbackTransaction(session, txEnd);
    step(4, "RollbackTransaction", txEnd.transportError);
    printRaw("rollback", txEnd);

    api.closeSession(session);
    return true;
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Transactions — explicit start / commit / rollback for TC scenarios");
    if (!transport) return 1;

    banner("21: Transactions");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_emptyCommit(transport, info.baseComId);
    ok &= scenario2_readInside(transport, info.baseComId);
    ok &= scenario3_rollback(transport, info.baseComId);

    printf("\nNOTE: status bytes in the output reveal whether your drive\n");
    printf("      actually implements transactions. 0x00 = success; 0x10\n");
    printf("      = TRANSACTION_FAILURE; 0x0F = TPer_Malfunction. Many\n");
    printf("      drives ignore or reject the tokens — that's expected and\n");
    printf("      the TC scenario should handle it explicitly.\n");

    return ok ? 0 : 1;
}
