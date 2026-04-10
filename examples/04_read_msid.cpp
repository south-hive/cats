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
/// The "Take Ownership" flow (example 05) reads MSID, then uses it
/// to authenticate as SID and change SID's password. Until you do that,
/// anyone who can read MSID can control the drive.
///
/// The Get method (0x06) is used to read table cells. The CellBlock
/// parameters specify which columns to return:
///   startColumn=3, endColumn=3 → just the PIN column of C_PIN.
///
/// API LAYER: EvalApi (to show Get step by step), SedDrive (convenience).
/// PREREQUISITES: 01 (Discovery), 03 (Sessions)
///
/// Usage: ./04_read_msid /dev/nvmeX [--dump]

#include "example_common.h"

// ── Scenario 1: Read MSID step-by-step with EvalApi ──
//
// This walks through the exact protocol steps:
// 1. Open anonymous session to Admin SP
// 2. Send Get(C_PIN_MSID, column=PIN)
// 3. Parse the response to extract the PIN bytes
// 4. Close session

static bool scenario1_evalMsid(std::shared_ptr<ITransport> transport,
                                uint16_t comId) {
    scenario(1, "Read MSID Step-by-Step (EvalApi)");

    EvalApi api;
    Session session(transport, comId);
    StartSessionResult ssr;

    // Step 1: Anonymous session — no auth needed for MSID
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(1, "Anonymous session to Admin SP", r);
    if (r.failed()) return false;

    // Step 2: Get C_PIN_MSID → PIN column
    // getCPin() wraps a Get method call with CellBlock targeting column 3 (PIN).
    // Under the hood: Get(C_PIN_MSID, startColumn=3, endColumn=3)
    Bytes msidPin;
    r = api.getCPin(session, uid::CPIN_MSID, msidPin);
    step(2, "getCPin(C_PIN_MSID)", r);
    if (r.ok()) {
        printString("MSID", msidPin);
        printHex("MSID (hex)", msidPin);
        printf("    Length: %zu bytes\n", msidPin.size());
    }

    // Step 3: Also read the SID PIN for comparison
    // On a factory drive, C_PIN_SID.PIN should be empty or equal MSID
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
        // Not Authorized = SID password has been changed (drive is owned)
        printf("    SID PIN: cannot read (drive may be owned)\n");
    }

    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ── Scenario 2: Read MSID via SedDrive facade ──
//
// SedDrive::readMsid() or query() handles all the session management
// internally. One-liner approach.

static bool scenario2_facadeMsid(const char* device, cli::CliOptions& opts) {
    scenario(2, "Read MSID via SedDrive");

    SedDrive drive(device);
    if (opts.dump) drive.enableDump();

    Bytes msid;
    auto r = drive.readMsid(msid);
    step(1, "SedDrive::readMsid()", r);
    if (r.ok()) {
        printString("MSID", msid);
    }

    return r.ok();
}

// ── Scenario 3: Read C_PIN table columns (generic Get) ──
//
// For learning: use tableGet() to read any table row's columns.
// C_PIN has columns: 0=UID, 1=Name, 2=CommonName, 3=PIN,
//                    4=CharSet, 5=TryLimit, 6=Tries, 7=Persistence

static bool scenario3_genericGet(std::shared_ptr<ITransport> transport,
                                  uint16_t comId) {
    scenario(3, "Generic Table Get on C_PIN");

    EvalApi api;
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    if (r.failed()) return false;

    // Read multiple columns of C_PIN_MSID: columns 3-4 (PIN and CharSet)
    TableResult result;
    r = api.tableGet(session, uid::CPIN_MSID, 3, 4, result);
    step(1, "tableGet(C_PIN_MSID, cols 3-4)", r);
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

    api.closeSession(session);
    return true;
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
    ok &= scenario1_evalMsid(transport, info.baseComId);
    ok &= scenario2_facadeMsid(opts.device.c_str(), opts);
    ok &= scenario3_genericGet(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
