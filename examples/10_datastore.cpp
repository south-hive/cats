/// @file 10_datastore.cpp
/// @brief DataStore (ByteTable) — Persistent Key-Value Storage on the Drive
///
/// TCG SPEC CONTEXT:
/// The DataStore table is a ByteTable in the Locking SP that provides
/// persistent storage on the drive itself. Use cases:
///   - Store encryption metadata, key fingerprints, or configuration
///   - Store recovery tokens or audit logs
///   - Any data that should persist across OS reinstalls
///
/// Key facts:
///   - Table UID: 0x0000100100000000 (DataStore table 0)
///   - Some drives support multiple DataStore tables (table 0, 1, 2...)
///   - Size is drive-dependent (typically 32KB-128KB per table)
///   - Access is controlled by ACE — Admin1 and authorized users
///   - Data persists across power cycles but is destroyed on Revert
///
/// ByteTable operations:
///   - TCG Write: write bytes at a specific offset
///   - TCG Read: read bytes from a specific offset
///   - TCG Compare: compare bytes at offset (constant-time comparison)
///
/// API LAYER: EvalApi for ByteTable operations
/// PREREQUISITES: 01-06 (Locking SP activated)
///
/// Usage: ./10_datastore /dev/nvmeX [--dump]

#include "example_common.h"

static std::string SID_PW;
static std::string ADMIN1_PW;

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

// ── Scenario 1: DataStore Info Query ──

static bool scenario1_info(std::shared_ptr<ITransport> transport,
                            uint16_t comId) {
    scenario(1, "DataStore Table Info");

    EvalApi api;
    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());

    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            ByteTableInfo btInfo;
            auto r2 = api.getByteTableInfo(session, btInfo);
            step(1, "getByteTableInfo()", r2);
            if (r2.ok()) {
                printf("    Table UID: 0x%016lx\n", btInfo.tableUid);
                printf("    Max size:  %u bytes\n", btInfo.maxSize);
                printf("    Used size: %u bytes\n", btInfo.usedSize);
            }
            return r2;
        });

    return r.ok();
}

// ── Scenario 2: Write-Read-Compare Cycle ──

static bool scenario2_writeReadCompare(std::shared_ptr<ITransport> transport,
                                        uint16_t comId) {
    scenario(2, "Write → Read → Compare Cycle");

    EvalApi api;
    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());

    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            // Prepare test data
            const char* testStr = "Hello from TCG DataStore! This data persists on the drive.";
            Bytes testData(testStr, testStr + strlen(testStr));

            // Write at offset 0
            auto r2 = api.tcgWriteDataStore(session, 0, testData);
            step(1, "Write test data at offset 0", r2);
            if (r2.failed()) return r2;

            // Read back
            DataOpResult readResult;
            r2 = api.tcgReadDataStore(session, 0, static_cast<uint32_t>(testData.size()),
                                       readResult);
            step(2, "Read back from offset 0", r2);
            if (r2.ok()) {
                bool match = (readResult.data == testData);
                step(3, "Verify data matches", match);
                printf("    Written: \"%s\"\n", testStr);
                printf("    Read:    \"%.*s\"\n",
                       static_cast<int>(readResult.data.size()),
                       reinterpret_cast<const char*>(readResult.data.data()));
            }

            // Write more data at a different offset
            const char* str2 = "Second block at offset 256";
            Bytes data2(str2, str2 + strlen(str2));
            r2 = api.tcgWriteDataStore(session, 256, data2);
            step(4, "Write second block at offset 256", r2);

            // Read it back
            r2 = api.tcgReadDataStore(session, 256, static_cast<uint32_t>(data2.size()),
                                       readResult);
            step(5, "Read back from offset 256", r2);
            if (r2.ok()) {
                bool match = (readResult.data == data2);
                step(6, "Verify second block", match);
            }

            return ErrorCode::Success;
        });

    return r.ok();
}

// ── Scenario 3: Multi-Table Access ──
//
// Some drives support multiple DataStore tables.
// Table 0 and Table 1 are independent storage areas.

static bool scenario3_multiTable(std::shared_ptr<ITransport> transport,
                                  uint16_t comId) {
    scenario(3, "Multi-Table DataStore");

    EvalApi api;
    Bytes admin1Pw(ADMIN1_PW.begin(), ADMIN1_PW.end());

    auto r = composite::withSession(api, transport, comId,
        uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw,
        [&](Session& session) -> Result {
            // Try writing to table 1 — if the drive doesn't support
            // multiple tables, this will fail gracefully.

            // Write to table 0
            Bytes data0 = {'T', 'a', 'b', 'l', 'e', '0'};
            auto r2 = api.tcgWriteDataStoreN(session, 0, 0, data0);
            step(1, "Write to Table 0", r2);

            // Write to table 1
            Bytes data1 = {'T', 'a', 'b', 'l', 'e', '1'};
            r2 = api.tcgWriteDataStoreN(session, 1, 0, data1);
            step(2, "Write to Table 1", r2);

            // Read from table 0 — should still be "Table0"
            DataOpResult res0;
            r2 = api.tcgReadDataStoreN(session, 0, 0, 6, res0);
            step(3, "Read Table 0", r2);
            if (r2.ok()) {
                bool match = (res0.data == data0);
                step(4, "Table 0 isolation check", match);
                printf("    Table 0: \"%.*s\"\n", 6,
                       reinterpret_cast<const char*>(res0.data.data()));
            }

            // Read from table 1
            DataOpResult res1;
            r2 = api.tcgReadDataStoreN(session, 1, 0, 6, res1);
            step(5, "Read Table 1", r2);
            if (r2.ok()) {
                bool match = (res1.data == data1);
                step(6, "Table 1 isolation check", match);
                printf("    Table 1: \"%.*s\"\n", 6,
                       reinterpret_cast<const char*>(res1.data.data()));
            }

            return ErrorCode::Success;
        });

    return r.ok();
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
        "DataStore — persistent byte storage on the drive");
    if (!transport) return 1;

    SID_PW = getPassword(opts);
    ADMIN1_PW = SID_PW + "_Admin1";

    banner("10: DataStore");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    if (!setupDrive(api, transport, info.baseComId)) {
        printf("  Setup failed.\n"); return 1;
    }

    bool ok = true;
    ok &= scenario1_info(transport, info.baseComId);
    ok &= scenario2_writeReadCompare(transport, info.baseComId);
    ok &= scenario3_multiTable(transport, info.baseComId);
    cleanup(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
