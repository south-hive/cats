/// @file appnote_ns_locking.cpp
/// @brief TCG Storage Application Note: Configurable Namespace Locking 구현 예제.
///
/// NVMe 드라이브의 다중 Namespace 환경에서 TCG Locking Range를
/// Namespace 경계에 맞춰 구성하는 방법을 EvalApi로 구현합니다.
///
/// Configurable Namespace Locking 개요:
///   NVMe는 하나의 드라이브를 여러 Namespace(논리 디스크)로 분할할 수 있습니다.
///   TCG Locking Range를 각 Namespace의 LBA 범위에 맞춰 구성하면,
///   Namespace별로 독립적인 잠금/암호화 제어가 가능합니다.
///
/// 포함 시나리오:
///   1. Namespace별 잠금 범위 구성
///   2. Discovery 및 전체 Range 열거
///   3. 다중 Namespace-Range 매핑 및 NVMe Identify

#include <libsed/sed_library.h>
#include <libsed/cli/cli_common.h>
#include <iostream>
#include <iomanip>
#include <vector>

using namespace libsed;
using namespace libsed::eval;

// ── Helpers ─────────────────────────────────────────────

/// Parse NSZE (Namespace Size in LBAs) from NVMe Identify Namespace data
static uint64_t parseNsze(const Bytes& identData) {
    if (identData.size() < 8) return 0;
    uint64_t nsze = 0;
    for (int i = 7; i >= 0; i--)
        nsze = (nsze << 8) | identData[i];
    return nsze;
}

// ════════════════════════════════════════════════════════
//  1. Per-Namespace Locking Configuration
// ════════════════════════════════════════════════════════

/// @scenario Namespace별 잠금 범위 구성
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효, 다중 Range 지원
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. Range 1을 NS1 LBA 범위에 매핑 (rangeStart=ns1Start, rangeLength=ns1Len)
///   3. Range 2를 NS2 LBA 범위에 매핑 (rangeStart=ns2Start, rangeLength=ns2Len)
///   4. Range 1, 2 정보 조회하여 구성 확인
///   5. 세션 닫기
/// @expected
///   - Range 1: NS1 영역에 매핑됨 (RLE/WLE 활성화)
///   - Range 2: NS2 영역에 매핑됨 (RLE/WLE 활성화)
///   - 각 Range가 독립적으로 잠금/해제 가능
static bool ns_perNamespaceConfig(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& admin1Pw,
                                   uint64_t ns1Start, uint64_t ns1Len,
                                   uint64_t ns2Start, uint64_t ns2Len) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  1. Per-Namespace Locking Configuration   ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Configure Range 1 → NS1
    r = api.setRange(session, 1, ns1Start, ns1Len, true, true);
    step(2, "Configure Range 1 -> NS1 (start=" + std::to_string(ns1Start) +
            " len=" + std::to_string(ns1Len) + ")", r);

    // Configure Range 2 → NS2
    r = api.setRange(session, 2, ns2Start, ns2Len, true, true);
    step(3, "Configure Range 2 -> NS2 (start=" + std::to_string(ns2Start) +
            " len=" + std::to_string(ns2Len) + ")", r);

    // Verify both ranges
    for (uint32_t rangeId = 1; rangeId <= 2; rangeId++) {
        LockingInfo info;
        r = api.getLockingInfo(session, rangeId, info);
        std::cout << "    Range " << rangeId << ": start=" << info.rangeStart
                  << " len=" << info.rangeLength
                  << " RLE=" << info.readLockEnabled
                  << " WLE=" << info.writeLockEnabled << "\n";
    }
    step(4, "Verify Range 1 & 2 configuration", r);

    api.closeSession(session);
    step(5, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  2. Discovery and Range Enumeration
// ════════════════════════════════════════════════════════

/// @scenario Discovery 및 전체 Locking Range 열거
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효
/// @steps
///   1. Level 0 Discovery 수행 → TCG 옵션 확인
///   2. LockingSP에 Admin1 인증으로 읽기 세션 열기
///   3. 모든 Locking Range 정보 조회 (Global + Range 1~N)
///   4. Range별 상태 출력 (매핑 테이블)
///   5. 세션 닫기
/// @expected
///   - Global Range (0): 전체 드라이브 범위
///   - Range 1~N: 각 Namespace에 매핑된 범위
///   - 매핑 테이블로 NS-Range 대응 관계 확인
static bool ns_verifyTcgState(EvalApi& api,
                               std::shared_ptr<ITransport> transport,
                               uint16_t comId,
                               const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  2. Discovery & Range Enumeration         ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Discovery
    TcgOption opt;
    auto r = api.getTcgOption(transport, opt);
    step(1, "Discovery (getTcgOption)", r);
    std::cout << "    SSC: " << (int)opt.sscType
              << " Locking: " << (opt.lockingEnabled ? "enabled" : "disabled")
              << " MaxUsers: " << opt.maxLockingUsers << "\n";

    // Step 2: Open session
    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);
    Session session(transport, comId);
    StartSessionResult ssr;
    r = api.startSessionWithAuth(session, uid::SP_LOCKING, false,
                                  uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(2, "Admin1 auth (read-only)", r);
    if (r.failed()) return false;

    // Step 3: Enumerate all ranges
    const uint32_t maxRanges = 9;
    std::vector<LockingInfo> ranges;
    RawResult raw;
    r = api.getAllLockingInfo(session, ranges, maxRanges, raw);
    step(3, "Get all locking ranges (up to " + std::to_string(maxRanges) + ")", r);

    // Step 4: Print range table
    step(4, "Range mapping table", Result(ErrorCode::Success));
    std::cout << "\n    ┌───────┬──────────────┬──────────────┬─────┬─────┬────────┬────────┐\n";
    std::cout << "    │ Range │  Start LBA   │    Length    │ RLE │ WLE │ RdLock │ WrLock │\n";
    std::cout << "    ├───────┼──────────────┼──────────────┼─────┼─────┼────────┼────────┤\n";
    for (const auto& info : ranges) {
        printf("    │  %3u  │ %12lu │ %12lu │  %c  │  %c  │   %c    │   %c    │\n",
               info.rangeId,
               info.rangeStart,
               info.rangeLength,
               info.readLockEnabled ? 'Y' : 'N',
               info.writeLockEnabled ? 'Y' : 'N',
               info.readLocked ? 'Y' : 'N',
               info.writeLocked ? 'Y' : 'N');
    }
    std::cout << "    └───────┴──────────────┴──────────────┴─────┴─────┴────────┴────────┘\n";

    api.closeSession(session);
    step(5, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  3. Multi-Namespace Range Mapping with NVMe Identify
// ════════════════════════════════════════════════════════

/// @scenario 다중 Namespace 범위 매핑 (NVMe Identify 활용)
/// @precondition NVMe 디바이스, DI 모드 또는 NVMe 접근 가능
/// @steps
///   1. NVMe Identify Controller — 총 Namespace 수 확인
///   2. 각 Namespace에 대해 NVMe Identify Namespace — NSZE(크기) 조회
///   3. Namespace 경계 기반 Range 매핑 계획 출력
///   4. LockingSP 세션을 열어 실제 Range와 비교
///   5. 세션 닫기
/// @expected
///   - 각 Namespace의 크기(NSZE) 확인
///   - Namespace 경계에 맞춘 Range 매핑 계획 도출
///   - 실제 Range 구성과 Namespace 매핑 대조
static bool ns_multiNamespaceRangeMapping(EvalApi& api,
                                           std::shared_ptr<ITransport> transport,
                                           uint16_t comId,
                                           const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  3. Multi-NS Range Mapping (NVMe Identify)║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Identify Controller → get NN (Number of Namespaces)
    Bytes ctrlData;
    auto r = EvalApi::nvmeIdentify(transport, 1, 0, ctrlData);
    step(1, "NVMe Identify Controller", r);

    uint32_t numNamespaces = 1;
    if (r.ok() && ctrlData.size() >= 520) {
        // NN is at offset 516 (4 bytes, little-endian)
        numNamespaces = ctrlData[516] | (ctrlData[517] << 8) |
                        (ctrlData[518] << 16) | (ctrlData[519] << 24);
        std::cout << "    Number of Namespaces (NN): " << numNamespaces << "\n";
    }

    // Step 2: Identify each Namespace
    struct NsInfo {
        uint32_t nsid;
        uint64_t nsze;  // Namespace Size in LBAs
    };
    std::vector<NsInfo> namespaces;

    uint32_t maxNs = std::min(numNamespaces, (uint32_t)4);  // Limit to 4
    for (uint32_t nsid = 1; nsid <= maxNs; nsid++) {
        Bytes nsData;
        r = EvalApi::nvmeIdentify(transport, 0, nsid, nsData);
        if (r.ok()) {
            uint64_t nsze = parseNsze(nsData);
            namespaces.push_back({nsid, nsze});
            std::cout << "    NS" << nsid << ": NSZE=" << nsze << " LBAs\n";
        } else {
            std::cout << "    NS" << nsid << ": not available\n";
        }
    }
    step(2, "Identify Namespaces", Result(ErrorCode::Success));

    // Step 3: Propose range mapping
    step(3, "Proposed Range mapping", Result(ErrorCode::Success));
    uint64_t currentStart = 0;
    std::cout << "\n    Proposed NS → Range mapping:\n";
    for (size_t i = 0; i < namespaces.size(); i++) {
        auto& ns = namespaces[i];
        std::cout << "      Range " << (i + 1) << " → NS" << ns.nsid
                  << " [start=" << currentStart
                  << ", length=" << ns.nsze << "]\n";
        currentStart += ns.nsze;
    }

    // Step 4: Compare with actual range configuration
    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);
    Session session(transport, comId);
    StartSessionResult ssr;
    r = api.startSessionWithAuth(session, uid::SP_LOCKING, false,
                                  uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(4, "Open LockingSP and compare actual ranges", r);

    if (r.ok()) {
        for (size_t i = 0; i < namespaces.size() && i < 9; i++) {
            LockingInfo info;
            r = api.getLockingInfo(session, i + 1, info);
            if (r.ok()) {
                bool matchesNs = (info.rangeLength == namespaces[i].nsze);
                std::cout << "      Range " << (i + 1) << ": actual start="
                          << info.rangeStart << " len=" << info.rangeLength;
                if (info.rangeLength > 0) {
                    std::cout << " [" << (matchesNs ? "matches" : "differs from")
                              << " NS" << namespaces[i].nsid << "]";
                } else {
                    std::cout << " [not configured]";
                }
                std::cout << "\n";
            }
        }
        api.closeSession(session);
    }
    step(5, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <device> <admin1_pw>"
                  << " [ns1_start] [ns1_len] [ns2_start] [ns2_len] [--dump] [--log]\n\n";
        std::cerr << "TCG Configurable Namespace Locking Application Note.\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 admin123\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 admin123 0 1048576 1048576 1048576\n";
        return 1;
    }

    std::string device   = argv[1];
    std::string admin1Pw = argv[2];
    uint64_t ns1Start    = (argc > 3) ? std::stoull(argv[3]) : 0;
    uint64_t ns1Len      = (argc > 4) ? std::stoull(argv[4]) : 1048576;   // 512MB @ 512B sector
    uint64_t ns2Start    = (argc > 5) ? std::stoull(argv[5]) : 1048576;
    uint64_t ns2Len      = (argc > 6) ? std::stoull(argv[6]) : 1048576;

    cli::CliOptions cliOpts;
    cli::scanFlags(argc, argv, cliOpts);

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return 1;
    }
    transport = cli::applyLogging(transport, cliOpts);

    EvalApi api;

    TcgOption opt;
    api.getTcgOption(transport, opt);
    uint16_t comId = opt.baseComId;
    if (comId == 0) {
        std::cerr << "No valid ComID found\n";
        return 1;
    }

    PropertiesResult props;
    api.exchangeProperties(transport, comId, props);

    std::cout << "═══════════════════════════════════════════════\n";
    std::cout << " TCG Configurable Namespace Locking App Note\n";
    std::cout << " Device: " << device << "\n";
    std::cout << " ComID:  0x" << std::hex << comId << std::dec << "\n";
    std::cout << "═══════════════════════════════════════════════\n";

    struct { const char* name; bool pass; } results[] = {
        {"1. Per-Namespace Locking Config",       false},
        {"2. Discovery & Range Enumeration",      false},
        {"3. Multi-NS Range Mapping (NVMe ID)",   false},
    };

    results[0].pass = ns_perNamespaceConfig(api, transport, comId, admin1Pw,
                                              ns1Start, ns1Len, ns2Start, ns2Len);
    results[1].pass = ns_verifyTcgState(api, transport, comId, admin1Pw);
    results[2].pass = ns_multiNamespaceRangeMapping(api, transport, comId, admin1Pw);

    // Summary
    std::cout << "\n═══════════════════════════════════════════════\n";
    std::cout << " Summary\n";
    std::cout << "═══════════════════════════════════════════════\n";
    int passCount = 0;
    for (auto& r : results) {
        std::cout << "  " << (r.pass ? "[PASS]" : "[FAIL]") << " " << r.name << "\n";
        if (r.pass) passCount++;
    }
    std::cout << "\n  Total: " << passCount << "/3 passed\n";

    libsed::shutdown();
    return 0;
}
