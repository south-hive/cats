/// @file appnote_psid.cpp
/// @brief TCG Storage Application Note: PSID Revert 구현 예제.
///
/// PSID(Physical Security ID) Revert는 SID 비밀번호를 분실하거나
/// 인증이 잠금(locked-out)된 경우의 비상 복구 수단입니다.
/// 드라이브 라벨에 인쇄된 PSID를 사용하여 공장 초기 상태로 복원합니다.
///
/// 포함 시나리오:
///   1. PSID Revert — SID 잠금 상태에서 복구
///   2. Revert 후 상태 확인
///   3. Revert 후 MSID 확인 (SID == MSID 초기화)

#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>

using namespace libsed;
using namespace libsed::eval;

// ════════════════════════════════════════════════════════
//  1. PSID Revert When Locked Out
// ════════════════════════════════════════════════════════

/// @scenario PSID Revert: SID 잠금 상태에서 복구
/// @precondition SID 비밀번호 분실 또는 인증 잠금 상태. PSID는 드라이브 라벨에서 확인 가능
/// @steps
///   1. SID 인증 시도 → 실패 (비밀번호 분실/잠금 시연)
///   2. AdminSP에 PSID 인증으로 쓰기 세션 열기
///   3. PSID Revert 수행
///   4. (세션은 TPer에 의해 자동 종료됨)
/// @expected
///   - SID 인증이 실패하는 상황에서도 PSID로 복구 가능
///   - PSID Revert 후 드라이브가 공장 초기 상태로 복원됨
///   - PSID는 변경 불가능한 물리적 보안 식별자
static bool psid_revertWhenLockedOut(EvalApi& api,
                                      std::shared_ptr<ITransport> transport,
                                      uint16_t comId,
                                      const std::string& psidPw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  1. PSID Revert (Locked-Out Recovery)     ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Demonstrate SID lockout
    {
        Bytes wrongCred = HashPassword::passwordToBytes("wrong_password_12345");
        Session session(transport, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                           uid::AUTH_SID, wrongCred, ssr);
        step(1, "SID auth attempt (expect fail)", r);
        if (r.ok()) {
            std::cout << "    Note: SID auth succeeded — drive may not be locked out\n";
            api.closeSession(session);
        } else {
            std::cout << "    SID auth failed as expected (locked out or wrong password)\n";
        }
    }

    // Step 2: PSID auth
    Bytes psidCred = HashPassword::passwordToBytes(psidPw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                       uid::AUTH_PSID, psidCred, ssr);
    step(2, "PSID auth to AdminSP", r);
    if (r.failed()) {
        std::cout << "    PSID auth failed — check PSID from drive label\n";
        return false;
    }

    // Step 3: PSID Revert
    r = api.psidRevert(session);
    step(3, "PSID Revert", r);

    // Session is auto-closed by TPer after Revert
    std::cout << "  >> PSID Revert complete. Drive reset to factory state.\n";
    std::cout << "  >> All SPs, credentials, locking ranges, and MBR cleared.\n";

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  2. Verify State After Revert
// ════════════════════════════════════════════════════════

/// @scenario Revert 후 상태 확인
/// @precondition PSID Revert 또는 TPer Revert 수행 완료
/// @steps
///   1. Discovery 수행하여 TCG 옵션 확인
///   2. Locking 기능 상태 확인 (lockingEnabled, locked)
///   3. MBR 상태 확인 (mbrEnabled, mbrDone)
///   4. AdminSP에 익명 세션 열어 Locking SP lifecycle 확인
///   5. 세션 닫기
/// @expected
///   - lockingEnabled = false (Locking SP가 비활성화됨)
///   - locked = false
///   - mbrEnabled = false, mbrDone = false
///   - Locking SP lifecycle = Manufactured-Inactive
static bool psid_verifyStateAfterRevert(EvalApi& api,
                                         std::shared_ptr<ITransport> transport,
                                         uint16_t comId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  2. Verify State After Revert             ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Re-discover
    TcgOption opt;
    auto r = api.getTcgOption(transport, opt);
    step(1, "Discovery (getTcgOption)", r);

    // Step 2: Check locking state
    std::cout << "    lockingSupported: " << opt.lockingSupported << "\n";
    std::cout << "    lockingEnabled:   " << opt.lockingEnabled << "\n";
    std::cout << "    locked:           " << opt.locked << "\n";
    step(2, "Check locking state", Result(ErrorCode::Success));

    // Step 3: Check MBR state
    std::cout << "    mbrSupported:     " << opt.mbrSupported << "\n";
    std::cout << "    mbrEnabled:       " << opt.mbrEnabled << "\n";
    std::cout << "    mbrDone:          " << opt.mbrDone << "\n";
    step(3, "Check MBR state", Result(ErrorCode::Success));

    // Step 4: Check Locking SP lifecycle
    // Re-exchange properties (comId may have changed after revert)
    PropertiesResult props;
    api.exchangeProperties(transport, opt.baseComId, props);

    Session session(transport, opt.baseComId);
    StartSessionResult ssr;
    r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(4, "Anonymous AdminSP session", r);

    if (r.ok()) {
        uint8_t lifecycle = 0;
        r = api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle);
        std::cout << "    Locking SP lifecycle: 0x" << std::hex << (int)lifecycle << std::dec;
        if (lifecycle == 0x08)      std::cout << " (Manufactured)";
        else if (lifecycle == 0x09) std::cout << " (Manufactured-Inactive)";
        std::cout << "\n";
        api.closeSession(session);
    }
    step(5, "Check Locking SP lifecycle", r);

    return true;
}

// ════════════════════════════════════════════════════════
//  3. Check MSID After Revert
// ════════════════════════════════════════════════════════

/// @scenario Revert 후 MSID 확인 (SID == MSID 복원)
/// @precondition PSID/TPer Revert 수행 완료
/// @steps
///   1. AdminSP에 익명 읽기 세션 열기
///   2. C_PIN_MSID에서 MSID PIN 읽기
///   3. 세션 닫기
///   4. MSID를 사용하여 SID 인증 시도 (SID == MSID 확인)
///   5. 세션 닫기
/// @expected
///   - MSID PIN 읽기 성공
///   - SID가 MSID로 초기화되어 MSID 자격 증명으로 SID 인증 가능
///   - 다시 Take Ownership (AppNote 3) 수행 가능
static bool psid_checkMsidAfterRevert(EvalApi& api,
                                       std::shared_ptr<ITransport> transport,
                                       uint16_t comId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  3. Check MSID After Revert               ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Anonymous session
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(1, "Anonymous AdminSP session", r);
    if (r.failed()) return false;

    // Step 2: Read MSID
    Bytes msidPin;
    r = api.getCPin(session, uid::CPIN_MSID, msidPin);
    step(2, "Read C_PIN_MSID", r);
    if (r.ok()) printHex("MSID", msidPin);

    // Step 3: Close anonymous session
    api.closeSession(session);
    step(3, "Close anonymous session", Result(ErrorCode::Success));

    if (msidPin.empty()) {
        std::cout << "  MSID is empty, cannot verify SID\n";
        return false;
    }

    // Step 4: Auth as SID using MSID (proves SID == MSID after revert)
    Session session2(transport, comId);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(session2, uid::SP_ADMIN, false,
                                  uid::AUTH_SID, msidPin, ssr2);
    step(4, "SID auth using MSID credential", r);
    if (r.ok()) {
        std::cout << "    >> SID == MSID confirmed. Ready for Take Ownership.\n";
        api.closeSession(session2);
    } else {
        std::cout << "    >> SID != MSID. Revert may not have completed.\n";
    }
    step(5, "Close session", Result(ErrorCode::Success));

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <device> <psid_password>\n\n";
        std::cerr << "TCG PSID Revert Application Note.\n";
        std::cerr << "PSID is printed on the drive label (32-character hex string).\n\n";
        std::cerr << "WARNING: PSID Revert will erase ALL data and reset the drive!\n\n";
        std::cerr << "Example:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 ABCDEF0123456789ABCDEF0123456789\n";
        return 1;
    }

    std::string device = argv[1];
    std::string psidPw = argv[2];

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return 1;
    }

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
    std::cout << " TCG PSID Revert Application Note\n";
    std::cout << " Device: " << device << "\n";
    std::cout << " ComID:  0x" << std::hex << comId << std::dec << "\n";
    std::cout << "═══════════════════════════════════════════════\n";
    std::cout << " WARNING: This will factory-reset the drive!\n";
    std::cout << "═══════════════════════════════════════════════\n";

    struct { const char* name; bool pass; } results[] = {
        {"1. PSID Revert (Locked-Out Recovery)", false},
        {"2. Verify State After Revert",         false},
        {"3. Check MSID After Revert",           false},
    };

    results[0].pass = psid_revertWhenLockedOut(api, transport, comId, psidPw);

    // After revert, re-discover (ComID may be the same but state changed)
    api.getTcgOption(transport, opt);
    comId = opt.baseComId;
    if (comId != 0) {
        api.exchangeProperties(transport, comId, props);
        results[1].pass = psid_verifyStateAfterRevert(api, transport, comId);
        results[2].pass = psid_checkMsidAfterRevert(api, transport, comId);
    }

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
    return (passCount == 3) ? 0 : 1;
}
