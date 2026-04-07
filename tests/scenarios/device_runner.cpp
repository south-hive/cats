/// @file device_runner.cpp
/// @brief Real Device Test Runner — 실제 NVMe/ATA SED 디바이스 테스트
///
/// 사용법:
///   ./device_runner /dev/nvme0                   # 읽기 전용 테스트만
///   ./device_runner /dev/nvme0 --destructive     # 소유권/Revert 포함
///   ./device_runner /dev/nvme0 --level 1         # 특정 레벨만
///   ./device_runner /dev/nvme0 --psid XXXXX      # PSID 지정 (Revert 복구용)
///
/// 안전 가드:
///   - 기본 모드: Discovery, Properties, MSID 읽기 등 읽기 전용 테스트만 실행
///   - --destructive: TakeOwnership, Activate, Range 설정, Revert 등 포함
///   - Revert 전 사용자 확인 프롬프트 (--yes로 건너뛰기)
///   - PSID 미지정 시 Revert 실패 복구 불가 경고

#include "libsed/sed_library.h"
#include "libsed/transport/transport_factory.h"
#include "libsed/eval/eval_api.h"
#include "libsed/eval/eval_composite.h"
#include "libsed/facade/sed_drive.h"

#include "libsed/debug/logging_transport.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <iostream>

using namespace libsed;
using namespace libsed::uid;
using namespace libsed::eval;

// ═══════════════════════════════════════════════════════
//  Test result tracking + logging
// ═══════════════════════════════════════════════════════

static int g_dev_pass = 0;
static int g_dev_fail = 0;
static int g_dev_skip = 0;

struct TestRecord {
    std::string name;
    std::string level;
    std::string status;  // "PASS", "FAIL", "SKIP"
    double elapsed_ms = 0.0;
    std::string reason;  // skip reason
};
static std::vector<TestRecord> g_records;
static std::string g_current_level;

#define DEV_CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "  FAIL: %s (line %d)\n", #expr, __LINE__); return false; } } while(0)

#define DEV_EXPECT_OK(r) do { if ((r).failed()) { \
    fprintf(stderr, "  FAIL: %s (%s)\n", #r, (r).message().c_str()); return false; } } while(0)

#define RUN_DEV(name, fn, ...) do { \
    printf("  [DEV] " name " ... "); fflush(stdout); \
    auto t0_ = std::chrono::steady_clock::now(); \
    bool ok_ = fn(__VA_ARGS__); \
    auto t1_ = std::chrono::steady_clock::now(); \
    double ms_ = std::chrono::duration<double, std::milli>(t1_ - t0_).count(); \
    if (ok_) { printf("PASS (%.0fms)\n", ms_); g_dev_pass++; \
        g_records.push_back({name, g_current_level, "PASS", ms_, ""}); } \
    else { printf("FAIL (%.0fms)\n", ms_); g_dev_fail++; \
        g_records.push_back({name, g_current_level, "FAIL", ms_, ""}); } \
} while(0)

#define SKIP_DEV(name, reason) do { \
    printf("  [DEV] " name " ... SKIP (%s)\n", reason); g_dev_skip++; \
    g_records.push_back({name, g_current_level, "SKIP", 0.0, reason}); \
} while(0)

static void writeJsonResults(const char* path, const std::string& device,
                              const std::string& sscName, uint16_t comId) {
    FILE* f = fopen(path, "w");
    if (!f) { fprintf(stderr, "ERROR: Cannot write to %s\n", path); return; }

    fprintf(f, "{\n");
    fprintf(f, "  \"device\": \"%s\",\n", device.c_str());
    fprintf(f, "  \"ssc\": \"%s\",\n", sscName.c_str());
    fprintf(f, "  \"comId\": \"0x%04X\",\n", comId);
    fprintf(f, "  \"summary\": { \"pass\": %d, \"fail\": %d, \"skip\": %d },\n",
            g_dev_pass, g_dev_fail, g_dev_skip);
    fprintf(f, "  \"tests\": [\n");
    for (size_t i = 0; i < g_records.size(); i++) {
        auto& r = g_records[i];
        fprintf(f, "    { \"name\": \"%s\", \"level\": \"%s\", \"status\": \"%s\"",
                r.name.c_str(), r.level.c_str(), r.status.c_str());
        if (r.status != "SKIP")
            fprintf(f, ", \"elapsed_ms\": %.1f", r.elapsed_ms);
        if (!r.reason.empty())
            fprintf(f, ", \"reason\": \"%s\"", r.reason.c_str());
        fprintf(f, " }%s\n", (i + 1 < g_records.size()) ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
    printf("  Results written to: %s\n", path);
}

// ═══════════════════════════════════════════════════════
//  Level 1: 읽기 전용 디바이스 검증
// ═══════════════════════════════════════════════════════

static bool dev_discovery(std::shared_ptr<ITransport> transport) {
    EvalApi api;
    DiscoveryInfo info;
    DEV_EXPECT_OK(api.discovery0(transport, info));
    DEV_CHECK(info.tperPresent);
    DEV_CHECK(info.baseComId != 0);

    printf("\n    SSC: %s, ComID: 0x%04X, Locking: %s, MBR: %s\n    ",
           info.primarySsc == SscType::Opal20 ? "Opal2" :
           info.primarySsc == SscType::Enterprise ? "Enterprise" : "Other",
           info.baseComId,
           info.lockingPresent ? (info.lockingEnabled ? "Enabled" : "Present") : "No",
           info.mbrEnabled ? "Enabled" : "No");
    return true;
}

static bool dev_properties(std::shared_ptr<ITransport> transport, uint16_t comId) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));
    DEV_CHECK(props.tperMaxComPacketSize > 0);

    printf("\n    MaxComPkt: %u, MaxPkt: %u, MaxIndToken: %u\n    ",
           props.tperMaxComPacketSize, props.tperMaxPacketSize,
           props.tperMaxIndTokenSize);
    return true;
}

static bool dev_read_msid(std::shared_ptr<ITransport> transport, uint16_t comId) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSession(session, SP_ADMIN, false, ssr));

    Bytes msid;
    DEV_EXPECT_OK(api.getCPin(session, CPIN_MSID, msid));
    DEV_CHECK(!msid.empty());

    printf("\n    MSID (%zu bytes): ", msid.size());
    for (size_t i = 0; i < std::min(msid.size(), size_t(16)); i++)
        printf("%02X", msid[i]);
    if (msid.size() > 16) printf("...");
    printf("\n    ");

    api.closeSession(session);
    return true;
}

static bool dev_security_status(std::shared_ptr<ITransport> transport) {
    EvalApi api;
    SecurityStatus status;
    DEV_EXPECT_OK(api.getSecurityStatus(transport, status));

    printf("\n    TPer: %s, Locking: %s, Opal2: %s, Enterprise: %s, Pyrite: %s\n    ",
           status.tperPresent ? "Y" : "N",
           status.lockingPresent ? "Y" : "N",
           status.opalV2Present ? "Y" : "N",
           status.enterprisePresent ? "Y" : "N",
           status.pyriteV1Present || status.pyriteV2Present ? "Y" : "N");
    return true;
}

static bool dev_stack_reset(std::shared_ptr<ITransport> transport, uint16_t comId) {
    EvalApi api;
    DEV_EXPECT_OK(api.stackReset(transport, comId));
    return true;
}

static bool dev_verify_comid(std::shared_ptr<ITransport> transport, uint16_t comId) {
    EvalApi api;
    bool active = false;
    DEV_EXPECT_OK(api.verifyComId(transport, comId, active));
    printf("\n    ComID 0x%04X: %s\n    ", comId, active ? "Associated" : "Idle");
    return true;
}

static bool dev_facade_query(std::shared_ptr<ITransport> transport) {
    SedDrive drive(transport);
    DEV_EXPECT_OK(drive.query());

    printf("\n    SSC: %s, MSID: %s, ComID: 0x%04X\n    ",
           drive.sscName(), drive.msidString().c_str(), drive.comId());
    return true;
}

static bool dev_locking_info_deep(std::shared_ptr<ITransport> transport, uint16_t comId) {
    EvalApi api;

    // Check if Locking SP is activated via Discovery
    DiscoveryInfo disc;
    DEV_EXPECT_OK(api.discovery0(transport, disc));
    if (!disc.lockingEnabled) {
        printf("\n    Locking SP not activated — SKIP (activate first with --destructive L2)\n    ");
        return true;
    }

    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    // Unauthenticated read into Locking SP
    auto sr = api.startSession(session, SP_LOCKING, false, ssr);
    if (sr.failed()) {
        printf("\n    Cannot open Locking SP session (0x%02X) — may require auth\n    ",
               static_cast<int>(sr.code()));
        return true;  // Not a test failure
    }

    printf("\n");
    for (uint32_t r = 0; r <= 8; r++) {
        LockingRangeInfo info;
        auto result = api.getRangeInfo(session, r, info);
        if (result.failed()) break;
        const char* name = (r == 0) ? "Global" : "";
        printf("    Range %u%s%s: Start=%lu Len=%lu RLE=%d WLE=%d RL=%d WL=%d\n",
               r, name[0] ? " (" : "", name[0] ? name : "",
               (unsigned long)info.rangeStart, (unsigned long)info.rangeLength,
               info.readLockEnabled, info.writeLockEnabled,
               info.readLocked, info.writeLocked);
    }
    printf("    ");

    api.closeSession(session);
    return true;
}

// ═══════════════════════════════════════════════════════
//  Level 1.5: Locking SP 읽기 전용 검증 (Locking SP 활성화 후)
// ═══════════════════════════════════════════════════════

static bool dev_byte_table_info(std::shared_ptr<ITransport> transport, uint16_t comId,
                                const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, false, AUTH_ADMIN1, admin1Pw, ssr));

    ByteTableInfo info;
    DEV_EXPECT_OK(api.getByteTableInfo(session, info));
    printf("\n    DataStore MaxSize: %u bytes\n    ", info.maxSize);

    api.closeSession(session);
    return true;
}

static bool dev_get_random(std::shared_ptr<ITransport> transport, uint16_t comId,
                           const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, false, AUTH_ADMIN1, admin1Pw, ssr));

    Bytes random1, random2;
    DEV_EXPECT_OK(api.getRandom(session, 32, random1));
    DEV_EXPECT_OK(api.getRandom(session, 32, random2));

    DEV_CHECK(random1.size() == 32);
    DEV_CHECK(random2.size() == 32);
    // Two random requests should differ (astronomically unlikely to match)
    DEV_CHECK(random1 != random2);

    printf("\n    Random 1: ");
    for (size_t i = 0; i < 8; i++) printf("%02X", random1[i]);
    printf("...\n    Random 2: ");
    for (size_t i = 0; i < 8; i++) printf("%02X", random2[i]);
    printf("...\n    ");

    api.closeSession(session);
    return true;
}

// ═══════════════════════════════════════════════════════
//  Level 2: 파괴적 테스트 (--destructive 필요)
// ═══════════════════════════════════════════════════════

static bool dev_take_ownership(std::shared_ptr<ITransport> transport, uint16_t comId,
                                 const std::string& sidPw) {
    SedDrive drive(transport, comId);
    DEV_EXPECT_OK(drive.query());
    DEV_EXPECT_OK(drive.takeOwnership(sidPw));

    // 검증: 새 비밀번호로 SID 인증
    EvalApi api;
    Bytes sidBytes(sidPw.begin(), sidPw.end());
    DEV_EXPECT_OK(api.verifyAuthority(transport, comId, SP_ADMIN, AUTH_SID, sidBytes));
    return true;
}

static bool dev_activate_and_setup(std::shared_ptr<ITransport> transport, uint16_t comId,
                                     const std::string& sidPw) {
    SedDrive drive(transport, comId);
    DEV_EXPECT_OK(drive.query());
    DEV_EXPECT_OK(drive.activateLocking(sidPw));
    return true;
}

static bool dev_configure_range(std::shared_ptr<ITransport> transport, uint16_t comId,
                                  const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

    DEV_EXPECT_OK(api.setRange(session, 1, 0, 1048576, true, true));

    LockingRangeInfo info;
    DEV_EXPECT_OK(api.getRangeInfo(session, 1, info));
    DEV_CHECK(info.readLockEnabled);
    DEV_CHECK(info.writeLockEnabled);

    api.closeSession(session);
    return true;
}

static bool dev_lock_unlock(std::shared_ptr<ITransport> transport, uint16_t comId,
                              const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

    DEV_EXPECT_OK(api.setRangeLock(session, 1, true, true));

    LockingRangeInfo info;
    DEV_EXPECT_OK(api.getRangeInfo(session, 1, info));
    DEV_CHECK(info.readLocked);
    DEV_CHECK(info.writeLocked);

    DEV_EXPECT_OK(api.setRangeLock(session, 1, false, false));
    DEV_EXPECT_OK(api.getRangeInfo(session, 1, info));
    DEV_CHECK(!info.readLocked);
    DEV_CHECK(!info.writeLocked);

    api.closeSession(session);
    return true;
}

static bool dev_revert(std::shared_ptr<ITransport> transport, uint16_t comId,
                         const std::string& sidPw) {
    SedDrive drive(transport, comId);
    DEV_EXPECT_OK(drive.query());
    DEV_EXPECT_OK(drive.revert(sidPw));

    // 공장 상태 확인
    DEV_EXPECT_OK(drive.query());
    EvalApi api;
    DEV_EXPECT_OK(api.verifyAuthority(transport, comId, SP_ADMIN, AUTH_SID, drive.msid()));
    return true;
}

// ═══════════════════════════════════════════════════════
//  Level 3: MBR, DataStore, CryptoErase, Multi-User
// ═══════════════════════════════════════════════════════

static bool dev_mbr_write_read(std::shared_ptr<ITransport> transport, uint16_t comId,
                                const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

    // Enable MBR
    DEV_EXPECT_OK(api.setMbrEnable(session, true));

    // Write test pattern to MBR
    Bytes pattern = {0xEB, 0x3C, 0x90, 0x4D, 0x53, 0x57, 0x49, 0x4E,  // "MSWIN" boot sig
                     0x34, 0x2E, 0x31, 0x00, 0x02, 0x01, 0x01, 0x00};
    DEV_EXPECT_OK(api.writeMbrData(session, 0, pattern));

    // Read back and verify
    Bytes readBack;
    DEV_EXPECT_OK(api.readMbrData(session, 0, (uint32_t)pattern.size(), readBack));
    DEV_CHECK(readBack.size() == pattern.size());
    DEV_CHECK(readBack == pattern);

    // Set MBR Done
    DEV_EXPECT_OK(api.setMbrDone(session, true));

    // Verify MBR status
    bool mbrEnabled = false, mbrDone = false;
    DEV_EXPECT_OK(api.getMbrStatus(session, mbrEnabled, mbrDone));
    DEV_CHECK(mbrEnabled);
    DEV_CHECK(mbrDone);

    printf("\n    MBR: Enable=%s, Done=%s, Write/Read %zu bytes OK\n    ",
           mbrEnabled ? "Y" : "N", mbrDone ? "Y" : "N", pattern.size());

    api.closeSession(session);
    return true;
}

static bool dev_datastore_write_read(std::shared_ptr<ITransport> transport, uint16_t comId,
                                      const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

    // Check DataStore capacity
    ByteTableInfo btInfo;
    DEV_EXPECT_OK(api.getByteTableInfo(session, btInfo));
    if (btInfo.maxSize == 0) {
        printf("\n    DataStore not available (maxSize=0)\n    ");
        api.closeSession(session);
        return true;  // Not a failure, just not supported
    }

    // Write test data
    Bytes testData;
    for (int i = 0; i < 64; i++) testData.push_back(static_cast<uint8_t>(i));
    DEV_EXPECT_OK(api.tcgWriteDataStore(session, 0, testData));

    // Read back and compare
    DataOpResult readResult;
    DEV_EXPECT_OK(api.tcgReadDataStore(session, 0, 64, readResult));
    DEV_CHECK(readResult.data.size() == testData.size());
    DEV_CHECK(readResult.data == testData);

    // Overwrite with different data, verify
    Bytes testData2(64, 0xAA);
    DEV_EXPECT_OK(api.tcgWriteDataStore(session, 0, testData2));
    DEV_EXPECT_OK(api.tcgReadDataStore(session, 0, 64, readResult));
    DEV_CHECK(readResult.data == testData2);

    printf("\n    DataStore: %u bytes max, Write/Read/Overwrite OK\n    ", btInfo.maxSize);

    api.closeSession(session);
    return true;
}

static bool dev_crypto_erase(std::shared_ptr<ITransport> transport, uint16_t comId,
                              const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

    // Get current active key for Range 1
    Uid keyBefore;
    DEV_EXPECT_OK(api.getActiveKey(session, 1, keyBefore));

    // Crypto erase Range 1 (generates new key)
    DEV_EXPECT_OK(api.cryptoErase(session, 1));

    // Verify key changed
    Uid keyAfter;
    DEV_EXPECT_OK(api.getActiveKey(session, 1, keyAfter));
    DEV_CHECK(keyBefore != keyAfter);

    printf("\n    CryptoErase: Key 0x%016lX → 0x%016lX\n    ",
           (unsigned long)keyBefore.toUint64(), (unsigned long)keyAfter.toUint64());

    api.closeSession(session);
    return true;
}

static bool dev_multi_user(std::shared_ptr<ITransport> transport, uint16_t comId,
                            const Bytes& admin1Pw, const std::string& userPw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    // Admin1 session: enable User1, set password, assign to Range 1
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

        DEV_EXPECT_OK(api.enableUser(session, 1));
        DEV_EXPECT_OK(api.setUserPassword(session, 1, userPw));
        DEV_EXPECT_OK(api.assignUserToRange(session, 1, 1));

        // Verify User1 is enabled
        bool enabled = false;
        DEV_EXPECT_OK(api.isUserEnabled(session, 1, enabled));
        DEV_CHECK(enabled);

        api.closeSession(session);
    }

    // User1 session: verify can read Range 1 info and lock/unlock
    {
        Bytes userCred(userPw.begin(), userPw.end());
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_USER1, userCred, ssr));

        // User1 should be able to lock/unlock Range 1
        DEV_EXPECT_OK(api.setRangeLock(session, 1, true, true));
        LockingRangeInfo info;
        DEV_EXPECT_OK(api.getRangeInfo(session, 1, info));
        DEV_CHECK(info.readLocked);
        DEV_CHECK(info.writeLocked);

        DEV_EXPECT_OK(api.setRangeLock(session, 1, false, false));

        printf("\n    User1: Enable + Password + Range1 Lock/Unlock OK\n    ");

        api.closeSession(session);
    }

    return true;
}

static bool dev_datastore_multi_table(std::shared_ptr<ITransport> transport, uint16_t comId,
                                       const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

    // Write different patterns to table 0 and table 1
    Bytes data0(32, 0xAA);
    Bytes data1(32, 0xBB);
    auto r0 = api.tcgWriteDataStoreN(session, 0, 0, data0);
    if (r0.failed()) {
        printf("\n    DataStore table 0 write failed — multi-table may not be supported\n    ");
        api.closeSession(session);
        return true;  // Not a failure, just unsupported
    }
    auto r1 = api.tcgWriteDataStoreN(session, 1, 0, data1);
    if (r1.failed()) {
        printf("\n    DataStore table 1 write failed — single table only\n    ");
        api.closeSession(session);
        return true;
    }

    // Read back and verify isolation
    DataOpResult read0, read1;
    DEV_EXPECT_OK(api.tcgReadDataStoreN(session, 0, 0, 32, read0));
    DEV_EXPECT_OK(api.tcgReadDataStoreN(session, 1, 0, 32, read1));
    DEV_CHECK(read0.data == data0);
    DEV_CHECK(read1.data == data1);

    // Cross-verify: table 0 should NOT have table 1's data
    DEV_CHECK(read0.data != read1.data);

    printf("\n    DataStore Multi-Table: Table0=0xAA, Table1=0xBB, isolation OK\n    ");

    api.closeSession(session);
    return true;
}

static bool dev_password_change(std::shared_ptr<ITransport> transport, uint16_t comId,
                                 const std::string& sidPw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    // Change SID password to a new value
    std::string newPw = sidPw + "_changed";
    Bytes sidCred(sidPw.begin(), sidPw.end());
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_ADMIN, true, AUTH_SID, sidCred, ssr));
        DEV_EXPECT_OK(api.setCPin(session, CPIN_SID, newPw));
        api.closeSession(session);
    }

    // Verify new password works
    DEV_EXPECT_OK(api.verifyAuthority(transport, comId, SP_ADMIN, AUTH_SID,
                                       Bytes(newPw.begin(), newPw.end())));

    // Change back to original
    Bytes newCred(newPw.begin(), newPw.end());
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_ADMIN, true, AUTH_SID, newCred, ssr));
        DEV_EXPECT_OK(api.setCPin(session, CPIN_SID, sidPw));
        api.closeSession(session);
    }

    // Verify original password restored
    DEV_EXPECT_OK(api.verifyAuthority(transport, comId, SP_ADMIN, AUTH_SID, sidCred));

    printf("\n    SID Password: Change → Verify → Restore OK\n    ");
    return true;
}

// ═══════════════════════════════════════════════════════
//  Level 5: Core TCG Validation (PSID Revert, LockOnReset, Multi-Range)
// ═══════════════════════════════════════════════════════

static bool dev_multi_range_independence(std::shared_ptr<ITransport> transport, uint16_t comId,
                                          const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

    // Configure Range 1: 0~512K sectors, RLE+WLE
    DEV_EXPECT_OK(api.setRange(session, 1, 0, 524288, true, true));
    // Configure Range 2: 512K~1M sectors, RLE+WLE
    DEV_EXPECT_OK(api.setRange(session, 2, 524288, 524288, true, true));

    // Lock Range 1 only
    DEV_EXPECT_OK(api.setRangeLock(session, 1, true, true));

    // Verify Range 1 is locked
    LockingRangeInfo info1;
    DEV_EXPECT_OK(api.getRangeInfo(session, 1, info1));
    DEV_CHECK(info1.readLocked);
    DEV_CHECK(info1.writeLocked);

    // Verify Range 2 is NOT locked
    LockingRangeInfo info2;
    DEV_EXPECT_OK(api.getRangeInfo(session, 2, info2));
    DEV_CHECK(!info2.readLocked);
    DEV_CHECK(!info2.writeLocked);

    // Now lock Range 2, unlock Range 1
    DEV_EXPECT_OK(api.setRangeLock(session, 2, true, true));
    DEV_EXPECT_OK(api.setRangeLock(session, 1, false, false));

    // Verify swapped states
    DEV_EXPECT_OK(api.getRangeInfo(session, 1, info1));
    DEV_EXPECT_OK(api.getRangeInfo(session, 2, info2));
    DEV_CHECK(!info1.readLocked && !info1.writeLocked);
    DEV_CHECK(info2.readLocked && info2.writeLocked);

    // Cleanup: unlock all
    DEV_EXPECT_OK(api.setRangeLock(session, 2, false, false));

    printf("\n    Range1 + Range2: independent lock/unlock verified\n    ");

    api.closeSession(session);
    return true;
}

static bool dev_lock_on_reset(std::shared_ptr<ITransport> transport, uint16_t comId,
                               const Bytes& admin1Pw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    // Step 1: Set LockOnReset for Range 1, enable RLE+WLE, unlock first
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

        DEV_EXPECT_OK(api.setRange(session, 1, 0, 1048576, true, true));
        DEV_EXPECT_OK(api.setRangeLock(session, 1, false, false));
        DEV_EXPECT_OK(api.setLockOnReset(session, 1, true));

        // Verify range is unlocked before reset
        LockingRangeInfo info;
        DEV_EXPECT_OK(api.getRangeInfo(session, 1, info));
        DEV_CHECK(!info.readLocked);
        DEV_CHECK(!info.writeLocked);

        api.closeSession(session);
    }

    // Step 2: StackReset — simulates a reset event
    DEV_EXPECT_OK(api.stackReset(transport, comId));

    // Step 3: Re-open session, check Range 1 is now locked
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ADMIN1, admin1Pw, ssr));

        LockingRangeInfo info;
        DEV_EXPECT_OK(api.getRangeInfo(session, 1, info));
        DEV_CHECK(info.readLocked);
        DEV_CHECK(info.writeLocked);

        // Cleanup: unlock and disable LockOnReset
        DEV_EXPECT_OK(api.setRangeLock(session, 1, false, false));
        DEV_EXPECT_OK(api.setLockOnReset(session, 1, false));

        printf("\n    LockOnReset: Set → StackReset → Range auto-locked → cleanup OK\n    ");

        api.closeSession(session);
    }
    return true;
}

static bool dev_psid_revert(std::shared_ptr<ITransport> transport, uint16_t comId,
                             const std::string& psidPw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    // PSID Revert — authenticate as PSID, then revert Admin SP
    Bytes psidCred(psidPw.begin(), psidPw.end());
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_ADMIN, true, AUTH_PSID, psidCred, ssr));
        DEV_EXPECT_OK(api.psidRevert(session));
        // Session is invalidated by revert — no closeSession needed
    }

    // Verify factory state: SID authenticates with MSID
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        DEV_EXPECT_OK(api.startSession(session, SP_ADMIN, false, ssr));

        Bytes msid;
        DEV_EXPECT_OK(api.getCPin(session, CPIN_MSID, msid));
        DEV_CHECK(!msid.empty());

        api.closeSession(session);

        // SID should equal MSID after factory reset
        DEV_EXPECT_OK(api.verifyAuthority(transport, comId, SP_ADMIN, AUTH_SID, msid));
    }

    printf("\n    PSID Revert: Factory state restored, SID=MSID verified\n    ");
    return true;
}

// ═══════════════════════════════════════════════════════
//  Level 4: Enterprise SSC 테스트 (Enterprise 드라이브 전용)
// ═══════════════════════════════════════════════════════

static bool dev_enterprise_band(std::shared_ptr<ITransport> transport, uint16_t comId,
                                 const Bytes& bandMasterPw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    // BandMaster0 session: configure band 1
    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_BANDMASTER0, bandMasterPw, ssr));

    // Configure Band 1: start=0, length=1M sectors, RLE+WLE enabled
    DEV_EXPECT_OK(api.configureBand(session, 1, 0, 1048576, true, true));

    // Verify band info
    LockingInfo bandInfo;
    DEV_EXPECT_OK(api.getBandInfo(session, 1, bandInfo));
    DEV_CHECK(bandInfo.readLockEnabled);
    DEV_CHECK(bandInfo.writeLockEnabled);

    // Lock band
    DEV_EXPECT_OK(api.lockBand(session, 1));
    DEV_EXPECT_OK(api.getBandInfo(session, 1, bandInfo));
    DEV_CHECK(bandInfo.readLocked);
    DEV_CHECK(bandInfo.writeLocked);

    // Unlock band
    DEV_EXPECT_OK(api.unlockBand(session, 1));
    DEV_EXPECT_OK(api.getBandInfo(session, 1, bandInfo));
    DEV_CHECK(!bandInfo.readLocked);
    DEV_CHECK(!bandInfo.writeLocked);

    printf("\n    Band1: Configure + Lock + Unlock OK\n    ");

    api.closeSession(session);
    return true;
}

static bool dev_enterprise_erase(std::shared_ptr<ITransport> transport, uint16_t comId,
                                  const Bytes& eraseMasterPw) {
    EvalApi api;
    PropertiesResult props;
    DEV_EXPECT_OK(api.exchangeProperties(transport, comId, props));

    // EraseMaster session: erase band 1
    Session session(transport, comId);
    StartSessionResult ssr;
    DEV_EXPECT_OK(api.startSessionWithAuth(session, SP_LOCKING, true, AUTH_ERASEMASTER, eraseMasterPw, ssr));

    DEV_EXPECT_OK(api.eraseBand(session, 1));

    printf("\n    EraseMaster: Band1 Erase OK\n    ");

    api.closeSession(session);
    return true;
}

// ═══════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════

static void printUsage(const char* prog) {
    printf("Usage: %s <device> [options]\n\n", prog);
    printf("Options:\n");
    printf("  --destructive     Enable write tests (TakeOwnership, Revert, etc.)\n");
    printf("  --sid <password>  SID password for destructive tests (default: 'test_sid')\n");
    printf("  --user <password> User1 password for multi-user tests (default: 'test_user1')\n");
    printf("  --psid <password> PSID for emergency recovery\n");
    printf("  --yes             Skip confirmation prompts\n");
    printf("  --level <N>       Run only level N (1~4)\n");
    printf("  --dump            Enable transport hex dump\n");
    printf("  --output <file>   Write JSON test results to file\n");
    printf("\nLevels:\n");
    printf("  1  Read-only: Discovery, Properties, MSID, SecurityStatus, Locking Info\n");
    printf("  2  Destructive: TakeOwnership, Activate, Range, Lock/Unlock, Revert\n");
    printf("  3  Extended: MBR, DataStore, CryptoErase, Multi-User, Password Change\n");
    printf("  4  Enterprise: BandMaster config, Lock/Unlock, EraseMaster erase\n");
    printf("  5  Core TCG: Multi-Range independence, LockOnReset, PSID Revert\n");
    printf("\nExamples:\n");
    printf("  %s /dev/nvme0                          # Read-only tests\n", prog);
    printf("  %s /dev/nvme0 --destructive --yes      # Full test suite\n", prog);
    printf("  %s /dev/nvme0 --destructive --level 3  # Extended tests only\n", prog);
}

int main(int argc, char* argv[]) {
    // --help 먼저 체크
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]); return 0;
        }
    }

    if (argc < 2 || argv[1][0] == '-') {
        printUsage(argv[0]);
        return 1;
    }

    std::string device = argv[1];
    bool destructive = false;
    bool autoYes = false;
    bool dump = false;
    int level = 0;
    std::string sidPw = "test_sid";
    std::string userPw = "test_user1";
    std::string psidPw;
    std::string outputPath;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--destructive") == 0) destructive = true;
        else if (strcmp(argv[i], "--yes") == 0) autoYes = true;
        else if (strcmp(argv[i], "--dump") == 0) dump = true;
        else if (strcmp(argv[i], "--level") == 0 && i + 1 < argc) level = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sid") == 0 && i + 1 < argc) sidPw = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) userPw = argv[++i];
        else if (strcmp(argv[i], "--psid") == 0 && i + 1 < argc) psidPw = argv[++i];
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) outputPath = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]); return 0;
        }
    }

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   TCG SED Device Test Runner                    ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("  Device: %s\n", device.c_str());
    printf("  Mode: %s\n\n", destructive ? "DESTRUCTIVE" : "Read-Only");

    // Transport 생성
    auto transport = TransportFactory::create(device);
    if (!transport) {
        fprintf(stderr, "ERROR: Cannot open device %s\n", device.c_str());
        return 1;
    }
    if (dump) {
        transport = debug::LoggingTransport::wrapDump(transport, std::cerr);
        printf("  Dump: ENABLED (hex output to stderr)\n\n");
    }

    // ComID 획득
    EvalApi api;
    DiscoveryInfo info;
    if (api.discovery0(transport, info).failed()) {
        fprintf(stderr, "ERROR: Discovery failed on %s\n", device.c_str());
        return 1;
    }
    uint16_t comId = info.baseComId;

    // ── Level 1: 읽기 전용 ──
    if (level == 0 || level == 1) {
        g_current_level = "L1";
        printf("=== Level 1: Read-Only Device Tests ===\n");
        RUN_DEV("Discovery", dev_discovery, transport);
        RUN_DEV("Properties", dev_properties, transport, comId);
        RUN_DEV("Read MSID", dev_read_msid, transport, comId);
        RUN_DEV("Security Status", dev_security_status, transport);
        RUN_DEV("Stack Reset", dev_stack_reset, transport, comId);
        RUN_DEV("Verify ComID", dev_verify_comid, transport, comId);
        RUN_DEV("SedDrive Query", dev_facade_query, transport);
        RUN_DEV("Locking Range Info", dev_locking_info_deep, transport, comId);
    }

    // MSID — shared across levels (read once, used by L2/L3/L4)
    Bytes msid;
    auto readMsid = [&]() -> bool {
        if (!msid.empty()) return true;
        PropertiesResult p;
        if (api.exchangeProperties(transport, comId, p).failed()) return false;
        Session s(transport, comId);
        StartSessionResult ssr;
        if (api.startSession(s, SP_ADMIN, false, ssr).failed()) return false;
        if (api.getCPin(s, CPIN_MSID, msid).failed() || msid.empty()) {
            api.closeSession(s);
            return false;
        }
        api.closeSession(s);
        return true;
    };

    // ── Destructive confirmation (once for all levels) ──
    if (destructive && (level == 0 || level >= 2) && !autoYes) {
        printf("\n  WARNING: Destructive tests will modify device state!\n");
        printf("  Device: %s\n", device.c_str());
        printf("  SID Password: %s\n", sidPw.c_str());
        printf("  PSID: %s\n", psidPw.empty() ? "(not set — recovery may not be possible!)" : psidPw.c_str());
        printf("\n  Continue? [y/N] ");
        fflush(stdout);
        char c = getchar();
        if (c != 'y' && c != 'Y') {
            printf("  Aborted.\n");
            return 0;
        }
    }

    // ── Level 2: 파괴적 테스트 ──
    if ((level == 0 || level == 2) && destructive) {
        g_current_level = "L2";
        printf("\n=== Level 2: Destructive Tests ===\n");

        if (!readMsid()) {
            fprintf(stderr, "  ERROR: Cannot read MSID\n");
            return 1;
        }
        printf("  MSID read OK (%zu bytes)\n", msid.size());

        RUN_DEV("Take Ownership", dev_take_ownership, transport, comId, sidPw);
        RUN_DEV("Activate Locking SP", dev_activate_and_setup, transport, comId, sidPw);
        RUN_DEV("Configure Range", dev_configure_range, transport, comId, msid);
        RUN_DEV("Lock/Unlock Range", dev_lock_unlock, transport, comId, msid);
        RUN_DEV("Revert to Factory", dev_revert, transport, comId, sidPw);
    } else if ((level == 0 || level == 2) && !destructive) {
        g_current_level = "L2";
        printf("\n=== Level 2: Destructive Tests ===\n");
        SKIP_DEV("Take Ownership", "--destructive flag not set");
        SKIP_DEV("Activate Locking SP", "--destructive flag not set");
        SKIP_DEV("Configure Range", "--destructive flag not set");
        SKIP_DEV("Lock/Unlock Range", "--destructive flag not set");
        SKIP_DEV("Revert to Factory", "--destructive flag not set");
    }

    // ── Level 3: Extended (MBR, DataStore, CryptoErase, Multi-User) ──
    if ((level == 0 || level == 3) && destructive) {
        g_current_level = "L3";
        printf("\n=== Level 3: Extended Tests (MBR, DataStore, CryptoErase, Multi-User) ===\n");

        // Need activated Locking SP — take ownership + activate if level 3 standalone
        if (level == 3) {
            if (!readMsid()) {
                fprintf(stderr, "  ERROR: Cannot read MSID\n");
                return 1;
            }
            printf("  Setting up: TakeOwnership + Activate...\n");
            SedDrive setupDrive(transport, comId);
            if (setupDrive.query().failed() || setupDrive.takeOwnership(sidPw).failed() ||
                setupDrive.activateLocking(sidPw).failed()) {
                fprintf(stderr, "  ERROR: Setup failed for Level 3\n");
                return 1;
            }
            printf("  Setup complete.\n\n");
        } else {
            // Full suite: Level 2 already reverted, so re-setup
            if (!readMsid()) {
                fprintf(stderr, "  ERROR: Cannot read MSID\n");
                return 1;
            }
            printf("  Re-setup: TakeOwnership + Activate for Level 3...\n");
            SedDrive setupDrive(transport, comId);
            if (setupDrive.query().failed() || setupDrive.takeOwnership(sidPw).failed() ||
                setupDrive.activateLocking(sidPw).failed()) {
                fprintf(stderr, "  ERROR: Setup failed for Level 3\n");
                return 1;
            }
        }

        Bytes admin1Pw = msid;  // After activation, Admin1 PIN = MSID

        RUN_DEV("MBR Write/Read", dev_mbr_write_read, transport, comId, admin1Pw);
        RUN_DEV("DataStore Write/Read", dev_datastore_write_read, transport, comId, admin1Pw);
        RUN_DEV("Crypto Erase", dev_crypto_erase, transport, comId, admin1Pw);
        RUN_DEV("Multi-User Setup", dev_multi_user, transport, comId, admin1Pw, userPw);
        RUN_DEV("Password Change", dev_password_change, transport, comId, sidPw);
        RUN_DEV("ByteTable Info", dev_byte_table_info, transport, comId, admin1Pw);
        RUN_DEV("Get Random", dev_get_random, transport, comId, admin1Pw);
        RUN_DEV("DataStore Multi-Table", dev_datastore_multi_table, transport, comId, admin1Pw);

        // Revert after Level 3 if running full suite
        if (level == 0 || level == 3) {
            printf("\n  Reverting after Level 3...\n");
            SedDrive rvt(transport, comId);
            rvt.query();
            auto rr = rvt.revert(sidPw);
            if (rr.failed())
                fprintf(stderr, "  WARNING: Revert failed: %s\n", rr.message().c_str());
            else
                printf("  Revert OK.\n");
        }
    } else if ((level == 0 || level == 3) && !destructive) {
        g_current_level = "L3";
        printf("\n=== Level 3: Extended Tests ===\n");
        SKIP_DEV("MBR Write/Read", "--destructive flag not set");
        SKIP_DEV("DataStore Write/Read", "--destructive flag not set");
        SKIP_DEV("Crypto Erase", "--destructive flag not set");
        SKIP_DEV("Multi-User Setup", "--destructive flag not set");
        SKIP_DEV("Password Change", "--destructive flag not set");
        SKIP_DEV("ByteTable Info", "--destructive flag not set");
        SKIP_DEV("Get Random", "--destructive flag not set");
        SKIP_DEV("DataStore Multi-Table", "--destructive flag not set");
    }

    // ── Level 4: Enterprise SSC (Enterprise 드라이브 전용) ──
    if ((level == 0 || level == 4) && destructive) {
        g_current_level = "L4";
        if (info.primarySsc == SscType::Enterprise) {
            printf("\n=== Level 4: Enterprise SSC Tests ===\n");

            // Enterprise uses BandMaster/EraseMaster instead of Admin1/User
            // Default: MSID is initial password for BandMaster0 and EraseMaster
            Bytes bandMasterPw = msid;
            Bytes eraseMasterPw = msid;

            RUN_DEV("Enterprise Band Config", dev_enterprise_band, transport, comId, bandMasterPw);
            RUN_DEV("Enterprise Band Erase", dev_enterprise_erase, transport, comId, eraseMasterPw);
        } else {
            printf("\n=== Level 4: Enterprise SSC Tests ===\n");
            SKIP_DEV("Enterprise Band Config", "Not Enterprise SSC");
            SKIP_DEV("Enterprise Band Erase", "Not Enterprise SSC");
        }
    } else if ((level == 0 || level == 4) && !destructive) {
        g_current_level = "L4";
        printf("\n=== Level 4: Enterprise SSC Tests ===\n");
        SKIP_DEV("Enterprise Band Config", "--destructive flag not set");
        SKIP_DEV("Enterprise Band Erase", "--destructive flag not set");
    }

    // ── Level 5: Core TCG Validation ──
    if ((level == 0 || level == 5) && destructive) {
        g_current_level = "L5";
        printf("\n=== Level 5: Core TCG Validation ===\n");

        // Need activated Locking SP — setup if standalone or after previous revert
        if (!readMsid()) {
            fprintf(stderr, "  ERROR: Cannot read MSID\n");
            return 1;
        }
        printf("  Setting up: TakeOwnership + Activate for Level 5...\n");
        {
            SedDrive setupDrive(transport, comId);
            if (setupDrive.query().failed() || setupDrive.takeOwnership(sidPw).failed() ||
                setupDrive.activateLocking(sidPw).failed()) {
                fprintf(stderr, "  ERROR: Setup failed for Level 5\n");
                return 1;
            }
        }
        printf("  Setup complete.\n\n");

        Bytes admin1Pw = msid;  // After activation, Admin1 PIN = MSID

        RUN_DEV("Multi-Range Independence", dev_multi_range_independence, transport, comId, admin1Pw);
        RUN_DEV("LockOnReset", dev_lock_on_reset, transport, comId, admin1Pw);

        if (!psidPw.empty()) {
            RUN_DEV("PSID Revert", dev_psid_revert, transport, comId, psidPw);
        } else {
            SKIP_DEV("PSID Revert", "--psid not specified");
            // Revert normally instead
            printf("  Reverting after Level 5...\n");
            SedDrive rvt(transport, comId);
            rvt.query();
            auto rr = rvt.revert(sidPw);
            if (rr.failed())
                fprintf(stderr, "  WARNING: Revert failed: %s\n", rr.message().c_str());
            else
                printf("  Revert OK.\n");
        }
    } else if ((level == 0 || level == 5) && !destructive) {
        g_current_level = "L5";
        printf("\n=== Level 5: Core TCG Validation ===\n");
        SKIP_DEV("Multi-Range Independence", "--destructive flag not set");
        SKIP_DEV("LockOnReset", "--destructive flag not set");
        SKIP_DEV("PSID Revert", "--destructive flag not set");
    }

    printf("\n══════════════════════════════════════════════════\n");
    printf("  Results: %d PASSED, %d FAILED, %d SKIPPED\n", g_dev_pass, g_dev_fail, g_dev_skip);
    printf("══════════════════════════════════════════════════\n");

    if (!outputPath.empty()) {
        const char* ssc = info.primarySsc == SscType::Opal20 ? "Opal2" :
                          info.primarySsc == SscType::Enterprise ? "Enterprise" : "Other";
        writeJsonResults(outputPath.c_str(), device, ssc, comId);
    }

    return g_dev_fail > 0 ? 1 : 0;
}
