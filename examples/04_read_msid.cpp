/// @file 04_read_msid.cpp
/// @brief Admin SP, C_PIN Table, and MSID Factory Credential
///
/// TCG SPEC CONTEXT:
/// The MSID (Manufacturer's SID) is the factory-default credential stored
/// in the C_PIN_MSID row of the Admin SP's C_PIN table. Key facts:
///
///   - C_PIN is a table where each row holds a credential (PIN).
///   - C_PIN_MSID (UID 0x0000000B00008402) is readable by Anybody
///     in the Admin SP — no authentication required.
///   - C_PIN_SID (UID 0x0000000B00000001) holds the SID (Security ID)
///     password. On a factory drive, SID == MSID.
///   - The MSID is typically the drive serial number or a random value
///     printed on the drive label.
///
/// SESSION REUSE:
/// A single session can serve multiple Get requests — there's no need to
/// close and reopen between reads. Close only when switching SP or auth
/// level. Scenarios 1 and 2 share one anonymous session to demonstrate this.
///
/// API LAYER: EvalApi (to show Get step by step), SedDrive (convenience).
/// PREREQUISITES: 01 (Discovery), 03 (Sessions)
///
/// Usage: ./04_read_msid /dev/nvmeX [--dump]

#include "example_common.h"

// ── Scenario 1: Read MSID and SID via getCPin (EvalApi) ──
// ── Scenario 2: Generic tableGet on C_PIN columns ──
//
// Both use a SINGLE anonymous session — multiple Get calls are fine
// within the same session. No need to close and reopen.

static bool scenario1_and_2(std::shared_ptr<ITransport> transport,
                             uint16_t comId) {
    EvalApi api;
    Session session(transport, comId);
    StartSessionResult ssr;

    auto r = api.startSession(session, uid::SP_ADMIN, true, ssr);
    step(1, "Anonymous session to Admin SP", r);
    if (r.failed()) return false;

    // ── Scenario 1: getCPin for MSID and SID ──
    scenario(1, "Read MSID and SID (getCPin)");

    Bytes msidPin;
    r = api.getCPin(session, uid::CPIN_MSID, msidPin);
    step(2, "getCPin(C_PIN_MSID)", r);
    if (r.ok()) {
        printString("MSID", msidPin);
        printHex("MSID (hex)", msidPin);
        printf("    Length: %zu bytes\n", msidPin.size());
    }

    // SID PIN — on a factory drive, should be empty or equal MSID
    Bytes sidPin;
    r = api.getCPin(session, uid::CPIN_SID, sidPin);
    step(3, "getCPin(C_PIN_SID)", r);
    if (r.ok()) {
        if (sidPin.empty()) {
            printf("    SID PIN: (empty — factory default, equals MSID)\n");
        } else {
            printHex("SID PIN", sidPin);
            bool same = (sidPin == msidPin);
            printf("    SID == MSID: %s\n", same ? "yes (factory state)" : "no (owned)");
        }
    } else {
        printf("    SID PIN: cannot read (drive may be owned)\n");
    }

    // ── Scenario 2: Generic tableGet (same session!) ──
    scenario(2, "Generic Table Get on C_PIN (same session)");

    // C_PIN columns: 0=UID, 1=Name, 2=CommonName, 3=PIN,
    //                4=CharSet, 5=TryLimit, 6=Tries, 7=Persistence
    TableResult result;
    r = api.tableGet(session, uid::CPIN_MSID, 3, 4, result);
    step(4, "tableGet(C_PIN_MSID, cols 3-4)", r);
    if (r.ok()) {
        printf("    Returned %zu column(s)\n", result.columns.size());
        for (auto& [col, token] : result.columns) {
            printf("    Column %u: ", col);
            if (token.isByteSequence) {
                auto& bytes = token.getBytes();
                if (bytes.empty()) printf("(empty)\n");
                else {
                    for (auto b : bytes) printf("%02x", b);
                    printf(" (%zu bytes)\n", bytes.size());
                }
            } else if (token.isAtom()) {
                printf("%lu\n", token.getUint());
            } else {
                printf("(type=%d)\n", static_cast<int>(token.type));
            }
        }
    }

    // One close for all reads
    api.closeSession(session);
    step(5, "Close session (one session for all reads)", Result(ErrorCode::Success));

    return true;
}

// ── Scenario 3: Read MSID via SedDrive facade ──
//
// SedDrive manages sessions internally — query() opens and closes its own.
// This is the convenience trade-off: simpler API, but you can't control
// session reuse.

static bool scenario3_facadeMsid(const char* device, cli::CliOptions& opts) {
    scenario(3, "Read MSID via SedDrive");

    SedDrive drive(device);
    if (opts.dump) drive.enableDump(std::cerr, opts.dumpLevel);

    // query() runs Discovery + Properties + readMsid (opens/closes session internally)
    auto r = drive.query();
    step(1, "SedDrive::query()", r);
    if (r.failed()) return false;

    // MSID was already cached by query() — readMsid() opens another session.
    // For efficiency, use drive.msid() which returns the cached value.
    const Bytes& msid = drive.msid();
    step(2, "drive.msid() (cached, no extra session)", !msid.empty());
    if (!msid.empty()) {
        printString("MSID", msid);
    }

    return !msid.empty();
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "MSID and C_PIN Table — reading factory credentials");
    if (!transport) return 1;

    banner("04: Read MSID");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_and_2(transport, info.baseComId);
    ok &= scenario3_facadeMsid(opts.device.c_str(), opts);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
