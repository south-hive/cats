/// @file appnote_block_sid.cpp
/// @brief TCG Storage Application Note: Block SID Authentication 구현 예제.
///
/// Block SID는 NVMe Set Feature (Feature ID 0x0C)를 사용하여
/// SID 인증을 차단하는 보안 기능입니다. BIOS/UEFI가 부팅 시
/// Block SID를 설정하면, OS 수준에서 SID를 사용한 무단 소유권
/// 변경을 방지할 수 있습니다.
///
/// 포함 시나리오:
///   1. Block SID 설정 (NVMe Set Feature)
///   2. SID 차단 확인 (인증 시도)
///   3. Block SID 상태 확인 및 전원 사이클 안내

#include <libsed/sed_library.h>
#include <libsed/cli/cli_common.h>
#include <iostream>
#include <iomanip>

using namespace libsed;
using namespace libsed::eval;

/// NVMe TCG Block SID Feature ID
static constexpr uint8_t NVME_FEAT_TCG_BLOCK_SID = 0x0C;

// ════════════════════════════════════════════════════════
//  1. Set Block SID Feature
// ════════════════════════════════════════════════════════

/// @scenario Block SID 인증 설정 (NVMe Set Feature)
/// @precondition NVMe 디바이스가 Block SID Feature (0x0C)를 지원
/// @steps
///   1. NVMe Get Feature (0x0C)로 현재 Block SID 상태 확인
///   2. NVMe Set Feature (0x0C, CDW11 bit0=1)로 Block SID 활성화
///   3. NVMe Get Feature (0x0C)로 변경된 상태 확인
/// @expected
///   - Block SID 설정 후 SID 인증이 차단됨
///   - CDW11 bit0: SID Value Blocked (1=차단, 0=허용)
///   - CDW11 bit1: SID Authentication Blocked (HW pin 연동)
static bool blocksid_setFeature(EvalApi& api,
                                 std::shared_ptr<ITransport> transport) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  1. Set Block SID Feature                 ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Get current state
    uint32_t cdw0 = 0;
    Bytes data;
    auto r = EvalApi::nvmeGetFeature(transport, NVME_FEAT_TCG_BLOCK_SID, 0, cdw0, data);
    step(1, "Get Feature (Block SID)", r);
    if (r.ok()) {
        std::cout << "    CDW0: 0x" << std::hex << cdw0 << std::dec << "\n";
        std::cout << "    SID Value Blocked:  " << ((cdw0 & 0x01) ? "Yes" : "No") << "\n";
        std::cout << "    SID Auth Blocked:   " << ((cdw0 & 0x02) ? "Yes" : "No") << "\n";
    }

    // Step 2: Set Block SID (CDW11 bit0=1)
    r = EvalApi::nvmeSetFeature(transport, NVME_FEAT_TCG_BLOCK_SID, 0, 0x01);
    step(2, "Set Feature (Block SID, CDW11=0x01)", r);

    // Step 3: Verify
    cdw0 = 0;
    r = EvalApi::nvmeGetFeature(transport, NVME_FEAT_TCG_BLOCK_SID, 0, cdw0, data);
    step(3, "Get Feature (verify)", r);
    if (r.ok()) {
        std::cout << "    CDW0: 0x" << std::hex << cdw0 << std::dec << "\n";
        std::cout << "    SID Value Blocked:  " << ((cdw0 & 0x01) ? "Yes" : "No") << "\n";
        std::cout << "    SID Auth Blocked:   " << ((cdw0 & 0x02) ? "Yes" : "No") << "\n";
    }

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  2. Verify SID is Blocked
// ════════════════════════════════════════════════════════

/// @scenario SID 차단 확인
/// @precondition Block SID Feature가 설정됨
/// @steps
///   1. AdminSP에 SID 인증 시도 (MSID 또는 지정된 비밀번호)
///   2. 인증 결과 확인 — Block SID 활성 시 실패 예상
///   3. 익명 세션은 여전히 가능한지 확인
/// @expected
///   - SID 인증: 실패 (Block SID에 의해 차단됨)
///   - 익명 세션: 성공 (Block SID는 인증만 차단, 익명 접근은 허용)
static bool blocksid_verifySidBlocked(EvalApi& api,
                                       std::shared_ptr<ITransport> transport,
                                       uint16_t comId,
                                       const std::string& sidPw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  2. Verify SID is Blocked                 ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Try SID auth (expect failure)
    Bytes sidCred = HashPassword::passwordToBytes(sidPw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                       uid::AUTH_SID, sidCred, ssr);
    step(1, "SID auth attempt (expect blocked)", r);
    if (r.ok()) {
        std::cout << "    SID auth SUCCEEDED — Block SID may not be active\n";
        api.closeSession(session);
    } else {
        std::cout << "    SID auth BLOCKED as expected\n";
    }

    // Step 2: Auth result
    bool blocked = r.failed();
    step(2, "SID blocked?", blocked ? Result(ErrorCode::Success) : Result(ErrorCode::InvalidArgument));
    std::cout << "    SID blocked: " << (blocked ? "YES" : "NO") << "\n";

    // Step 3: Anonymous session should still work
    Session session2(transport, comId);
    StartSessionResult ssr2;
    r = api.startSession(session2, uid::SP_ADMIN, false, ssr2);
    step(3, "Anonymous session (should still work)", r);
    if (r.ok()) {
        std::cout << "    Anonymous access: OK (not affected by Block SID)\n";
        api.closeSession(session2);
    }

    return blocked;
}

// ════════════════════════════════════════════════════════
//  3. Check State and Power Cycle Info
// ════════════════════════════════════════════════════════

/// @scenario Block SID 상태 확인 및 전원 사이클 안내
/// @precondition NVMe 디바이스 접근 가능
/// @steps
///   1. NVMe Get Feature (0x0C)로 현재 Block SID 상태 확인
///   2. Block SID 해제 시도 (Set Feature CDW11=0)
///   3. 해제 후 상태 재확인
///   4. 전원 사이클 동작 안내 출력
/// @expected
///   - Block SID는 전원 사이클 시 자동으로 해제됨 (TCG spec)
///   - 소프트웨어적 해제는 드라이브에 따라 지원 여부가 다름
///   - BIOS/UEFI에서 매 부팅 시 설정하는 것이 일반적 사용 패턴
static bool blocksid_clearOnPowerCycle(EvalApi& api,
                                        std::shared_ptr<ITransport> transport) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  3. Block SID State & Power Cycle         ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Current state
    uint32_t cdw0 = 0;
    Bytes data;
    auto r = EvalApi::nvmeGetFeature(transport, NVME_FEAT_TCG_BLOCK_SID, 0, cdw0, data);
    step(1, "Get current Block SID state", r);
    if (r.ok()) {
        std::cout << "    SID Value Blocked:  " << ((cdw0 & 0x01) ? "Yes" : "No") << "\n";
        std::cout << "    SID Auth Blocked:   " << ((cdw0 & 0x02) ? "Yes" : "No") << "\n";
    }

    // Step 2: Try to clear Block SID (CDW11=0)
    r = EvalApi::nvmeSetFeature(transport, NVME_FEAT_TCG_BLOCK_SID, 0, 0x00);
    step(2, "Clear Block SID (Set Feature CDW11=0x00)", r);
    if (r.failed()) {
        std::cout << "    Note: Some drives require power cycle to clear Block SID\n";
    }

    // Step 3: Re-check
    cdw0 = 0;
    r = EvalApi::nvmeGetFeature(transport, NVME_FEAT_TCG_BLOCK_SID, 0, cdw0, data);
    step(3, "Get state after clear attempt", r);
    if (r.ok()) {
        std::cout << "    SID Value Blocked:  " << ((cdw0 & 0x01) ? "Yes" : "No") << "\n";
    }

    // Step 4: Power cycle information
    step(4, "Power cycle behavior notes", Result(ErrorCode::Success));
    std::cout << "\n";
    std::cout << "    ┌──────────────────────────────────────────────────────┐\n";
    std::cout << "    │ Block SID Power Cycle Behavior (per TCG spec):       │\n";
    std::cout << "    │                                                      │\n";
    std::cout << "    │  - Block SID is cleared on every power cycle         │\n";
    std::cout << "    │  - BIOS/UEFI sets it during each boot               │\n";
    std::cout << "    │  - Prevents OS-level SID takeover                    │\n";
    std::cout << "    │  - Does NOT block PSID (physical access recovery)    │\n";
    std::cout << "    │  - Does NOT block Admin1/User1 auth in Locking SP    │\n";
    std::cout << "    │                                                      │\n";
    std::cout << "    │ Typical flow:                                        │\n";
    std::cout << "    │  1. Power on                                         │\n";
    std::cout << "    │  2. BIOS: NVMe Set Feature 0x0C (CDW11=0x01)        │\n";
    std::cout << "    │  3. OS boots — SID auth blocked                      │\n";
    std::cout << "    │  4. Power off — Block SID auto-cleared               │\n";
    std::cout << "    └──────────────────────────────────────────────────────┘\n";

    return true;
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <device> [sid_password] [--dump] [--log]\n\n";
        std::cerr << "TCG Block SID Application Note.\n\n";
        std::cerr << "WARNING: This will block SID authentication on the drive!\n";
        std::cerr << "(Cleared on next power cycle)\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 mySID\n";
        return 1;
    }

    std::string device = argv[1];
    std::string sidPw  = (argc > 2) ? argv[2] : "";

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
    std::cout << " TCG Block SID Application Note\n";
    std::cout << " Device: " << device << "\n";
    std::cout << " ComID:  0x" << std::hex << comId << std::dec << "\n";
    std::cout << "═══════════════════════════════════════════════\n";

    struct { const char* name; bool pass; } results[] = {
        {"1. Set Block SID Feature",      false},
        {"2. Verify SID is Blocked",       false},
        {"3. Block SID State & Power Cycle", false},
    };

    results[0].pass = blocksid_setFeature(api, transport);

    if (!sidPw.empty()) {
        results[1].pass = blocksid_verifySidBlocked(api, transport, comId, sidPw);
    } else {
        // Try with empty SID (MSID) for demonstration
        results[1].pass = blocksid_verifySidBlocked(api, transport, comId, "");
    }

    results[2].pass = blocksid_clearOnPowerCycle(api, transport);

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
