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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace libsed;
using namespace libsed::uid;
using namespace libsed::eval;

// ═══════════════════════════════════════════════════════
//  Test result tracking
// ═══════════════════════════════════════════════════════

static int g_dev_pass = 0;
static int g_dev_fail = 0;
static int g_dev_skip = 0;

#define DEV_CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "  FAIL: %s (line %d)\n", #expr, __LINE__); return false; } } while(0)

#define DEV_EXPECT_OK(r) do { if ((r).failed()) { \
    fprintf(stderr, "  FAIL: %s (%s)\n", #r, (r).message().c_str()); return false; } } while(0)

#define RUN_DEV(name, fn, ...) do { \
    printf("  [DEV] " name " ... "); fflush(stdout); \
    if (fn(__VA_ARGS__)) { printf("PASS\n"); g_dev_pass++; } \
    else { printf("FAIL\n"); g_dev_fail++; } \
} while(0)

#define SKIP_DEV(name, reason) do { \
    printf("  [DEV] " name " ... SKIP (%s)\n", reason); g_dev_skip++; \
} while(0)

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
//  Main
// ═══════════════════════════════════════════════════════

static void printUsage(const char* prog) {
    printf("Usage: %s <device> [options]\n\n", prog);
    printf("Options:\n");
    printf("  --destructive     Enable write tests (TakeOwnership, Revert, etc.)\n");
    printf("  --sid <password>  SID password for destructive tests (default: 'test_sid')\n");
    printf("  --psid <password> PSID for emergency recovery\n");
    printf("  --yes             Skip confirmation prompts\n");
    printf("  --level <N>       Run only level N (1=read-only, 2=destructive)\n");
    printf("\nExamples:\n");
    printf("  %s /dev/nvme0                          # Read-only tests\n", prog);
    printf("  %s /dev/nvme0 --destructive --yes      # Full test suite\n", prog);
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
    int level = 0;
    std::string sidPw = "test_sid";
    std::string psidPw;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--destructive") == 0) destructive = true;
        else if (strcmp(argv[i], "--yes") == 0) autoYes = true;
        else if (strcmp(argv[i], "--level") == 0 && i + 1 < argc) level = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sid") == 0 && i + 1 < argc) sidPw = argv[++i];
        else if (strcmp(argv[i], "--psid") == 0 && i + 1 < argc) psidPw = argv[++i];
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
        printf("=== Level 1: Read-Only Device Tests ===\n");
        RUN_DEV("Discovery", dev_discovery, transport);
        RUN_DEV("Properties", dev_properties, transport, comId);
        RUN_DEV("Read MSID", dev_read_msid, transport, comId);
        RUN_DEV("Security Status", dev_security_status, transport);
        RUN_DEV("Stack Reset", dev_stack_reset, transport, comId);
        RUN_DEV("Verify ComID", dev_verify_comid, transport, comId);
        RUN_DEV("SedDrive Query", dev_facade_query, transport);
    }

    // ── Level 2: 파괴적 테스트 ──
    if ((level == 0 || level == 2) && destructive) {
        printf("\n=== Level 2: Destructive Tests ===\n");

        if (!autoYes) {
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

        Bytes msid;
        {
            // MSID 읽기 (Admin1 초기 비밀번호)
            PropertiesResult props;
            if (api.exchangeProperties(transport, comId, props).failed()) {
                fprintf(stderr, "  ERROR: Properties exchange failed\n");
                return 1;
            }
            Session s(transport, comId);
            StartSessionResult ssr;
            if (api.startSession(s, SP_ADMIN, false, ssr).failed()) {
                fprintf(stderr, "  ERROR: Cannot open anonymous session\n");
                return 1;
            }
            if (api.getCPin(s, CPIN_MSID, msid).failed() || msid.empty()) {
                fprintf(stderr, "  ERROR: Cannot read MSID\n");
                api.closeSession(s);
                return 1;
            }
            api.closeSession(s);
            printf("  MSID read OK (%zu bytes)\n", msid.size());
        }

        RUN_DEV("Take Ownership", dev_take_ownership, transport, comId, sidPw);
        RUN_DEV("Activate Locking SP", dev_activate_and_setup, transport, comId, sidPw);
        RUN_DEV("Configure Range", dev_configure_range, transport, comId, msid);
        RUN_DEV("Lock/Unlock Range", dev_lock_unlock, transport, comId, msid);
        RUN_DEV("Revert to Factory", dev_revert, transport, comId, sidPw);
    } else if ((level == 0 || level == 2) && !destructive) {
        printf("\n=== Level 2: Destructive Tests ===\n");
        SKIP_DEV("Take Ownership", "--destructive flag not set");
        SKIP_DEV("Activate Locking SP", "--destructive flag not set");
        SKIP_DEV("Configure Range", "--destructive flag not set");
        SKIP_DEV("Lock/Unlock Range", "--destructive flag not set");
        SKIP_DEV("Revert to Factory", "--destructive flag not set");
    }

    printf("\n══════════════════════════════════════════════════\n");
    printf("  Results: %d PASSED, %d FAILED, %d SKIPPED\n", g_dev_pass, g_dev_fail, g_dev_skip);
    printf("══════════════════════════════════════════════════\n");

    return g_dev_fail > 0 ? 1 : 0;
}
