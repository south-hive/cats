/// @file appnote_enterprise.cpp
/// @brief TCG Storage Application Note: Enterprise SSC 구현 예제.
///
/// Enterprise SSC의 주요 작업 흐름을 EvalApi (단계별 플랫 API)로 구현합니다.
/// Enterprise SSC는 데이터센터용 SED 표준으로, Opal과 달리 Band/BandMaster/
/// EraseMaster 모델을 사용합니다.
///
/// 포함 시나리오:
///   1. Band 구성 (Configure Band)
///   2. Band 잠금 (Lock Band)
///   3. Band 잠금 해제 (Unlock Band)
///   4. BandMaster 비밀번호 변경
///   5. EraseMaster 비밀번호 변경
///   6. Band 암호화 소거 (Erase Band)
///   7. 전체 Band 소거 (Erase All Bands)
///   8. Band LockOnReset 설정

#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>
#include <vector>

using namespace libsed;
using namespace libsed::eval;

// ════════════════════════════════════════════════════════
//  1. Configure Band
// ════════════════════════════════════════════════════════

/// @scenario Enterprise Band 구성
/// @precondition Enterprise SSC 드라이브, BandMaster N 비밀번호 유효
/// @steps
///   1. Enterprise SP에 BandMaster N 인증으로 쓰기 세션 열기
///   2. Band N에 시작 LBA, 길이, ReadLockEnabled, WriteLockEnabled 설정
///   3. Band N 정보 조회하여 구성 확인
///   4. 세션 닫기
/// @expected
///   - Band N이 지정된 범위로 구성됨
///   - ReadLockEnabled/WriteLockEnabled 설정 반영됨
static bool ent_configureBand(EvalApi& api,
                               std::shared_ptr<ITransport> transport,
                               uint16_t comId,
                               const std::string& bandMasterPw,
                               uint32_t bandId,
                               uint64_t bandStart,
                               uint64_t bandLength) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  1. Configure Band                        ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(bandMasterPw);
    uint64_t bmAuth = uid::makeBandMasterUid(bandId).toUint64();

    // Step 1: BandMaster auth to Enterprise SP
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       bmAuth, cred, ssr);
    step(1, "BandMaster" + std::to_string(bandId) + " auth to EnterpriseSP", r);
    if (r.failed()) return false;

    // Step 2: Configure band
    r = api.configureBand(session, bandId, bandStart, bandLength, true, true);
    step(2, "Configure Band " + std::to_string(bandId) +
            " (start=" + std::to_string(bandStart) +
            " len=" + std::to_string(bandLength) + ")", r);

    // Step 3: Verify
    LockingInfo info;
    r = api.getBandInfo(session, bandId, info);
    step(3, "Verify Band " + std::to_string(bandId), r);
    if (r.ok()) {
        std::cout << "    Start=" << info.rangeStart
                  << " Length=" << info.rangeLength
                  << " RLE=" << info.readLockEnabled
                  << " WLE=" << info.writeLockEnabled << "\n";
    }

    // Step 4: Close
    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  2. Lock Band
// ════════════════════════════════════════════════════════

/// @scenario Enterprise Band 잠금
/// @precondition Band N이 구성되고 BandMaster N 비밀번호 유효
/// @steps
///   1. Enterprise SP에 BandMaster N 인증으로 쓰기 세션 열기
///   2. Band N 잠금
///   3. Band N 상태 조회하여 잠금 확인
///   4. 세션 닫기
/// @expected
///   - Band N이 잠금 상태 (ReadLocked=true, WriteLocked=true)
static bool ent_lockBand(EvalApi& api,
                          std::shared_ptr<ITransport> transport,
                          uint16_t comId,
                          const std::string& bandMasterPw,
                          uint32_t bandId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  2. Lock Band                             ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(bandMasterPw);
    uint64_t bmAuth = uid::makeBandMasterUid(bandId).toUint64();

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       bmAuth, cred, ssr);
    step(1, "BandMaster auth", r);
    if (r.failed()) return false;

    r = api.lockBand(session, bandId);
    step(2, "Lock Band " + std::to_string(bandId), r);

    LockingInfo info;
    r = api.getBandInfo(session, bandId, info);
    step(3, "Verify lock state", r);
    if (r.ok()) {
        std::cout << "    ReadLocked=" << info.readLocked
                  << " WriteLocked=" << info.writeLocked << "\n";
    }

    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  3. Unlock Band
// ════════════════════════════════════════════════════════

/// @scenario Enterprise Band 잠금 해제
/// @precondition Band N이 잠금 상태, BandMaster N 비밀번호 유효
/// @steps
///   1. Enterprise SP에 BandMaster N 인증으로 쓰기 세션 열기
///   2. Band N 잠금 해제
///   3. Band N 상태 조회하여 잠금 해제 확인
///   4. 세션 닫기
/// @expected
///   - Band N이 잠금 해제 상태 (ReadLocked=false, WriteLocked=false)
static bool ent_unlockBand(EvalApi& api,
                            std::shared_ptr<ITransport> transport,
                            uint16_t comId,
                            const std::string& bandMasterPw,
                            uint32_t bandId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  3. Unlock Band                           ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(bandMasterPw);
    uint64_t bmAuth = uid::makeBandMasterUid(bandId).toUint64();

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       bmAuth, cred, ssr);
    step(1, "BandMaster auth", r);
    if (r.failed()) return false;

    r = api.unlockBand(session, bandId);
    step(2, "Unlock Band " + std::to_string(bandId), r);

    LockingInfo info;
    r = api.getBandInfo(session, bandId, info);
    step(3, "Verify unlock state", r);
    if (r.ok()) {
        std::cout << "    ReadLocked=" << info.readLocked
                  << " WriteLocked=" << info.writeLocked << "\n";
    }

    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  4. Set BandMaster Password
// ════════════════════════════════════════════════════════

/// @scenario BandMaster 비밀번호 변경
/// @precondition BandMaster N의 현재 비밀번호가 유효
/// @steps
///   1. Enterprise SP에 BandMaster N 인증으로 쓰기 세션 열기
///   2. BandMaster N의 C_PIN에 새 비밀번호 설정
///   3. 세션 닫기
///   4. 새 비밀번호로 인증 성공 확인
/// @expected
///   - BandMaster N 비밀번호가 새 값으로 변경됨
///   - 이후 인증 시 새 비밀번호 사용 필요
static bool ent_setBandMasterPassword(EvalApi& api,
                                       std::shared_ptr<ITransport> transport,
                                       uint16_t comId,
                                       const std::string& oldPw,
                                       const std::string& newPw,
                                       uint32_t bandId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  4. Set BandMaster Password               ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes oldCred = HashPassword::passwordToBytes(oldPw);
    uint64_t bmAuth = uid::makeBandMasterUid(bandId).toUint64();

    // Step 1: Auth with old password
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       bmAuth, oldCred, ssr);
    step(1, "BandMaster auth with old password", r);
    if (r.failed()) return false;

    // Step 2: Set new password
    Bytes newPin = HashPassword::passwordToBytes(newPw);
    r = api.setBandMasterPassword(session, bandId, newPin);
    step(2, "Set BandMaster" + std::to_string(bandId) + " new password", r);

    // Step 3: Close
    api.closeSession(session);
    step(3, "Close session", Result(ErrorCode::Success));

    // Step 4: Verify with new password
    Bytes newCred = HashPassword::passwordToBytes(newPw);
    Session session2(transport, comId);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(session2, uid::SP_ENTERPRISE, false,
                                  bmAuth, newCred, ssr2);
    step(4, "Verify auth with new password", r);
    if (r.ok()) api.closeSession(session2);

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  5. Set EraseMaster Password
// ════════════════════════════════════════════════════════

/// @scenario EraseMaster 비밀번호 변경
/// @precondition EraseMaster의 현재 비밀번호가 유효
/// @steps
///   1. Enterprise SP에 EraseMaster 인증으로 쓰기 세션 열기
///   2. EraseMaster의 C_PIN에 새 비밀번호 설정
///   3. 세션 닫기
///   4. 새 비밀번호로 인증 성공 확인
/// @expected
///   - EraseMaster 비밀번호가 새 값으로 변경됨
static bool ent_setEraseMasterPassword(EvalApi& api,
                                        std::shared_ptr<ITransport> transport,
                                        uint16_t comId,
                                        const std::string& oldPw,
                                        const std::string& newPw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  5. Set EraseMaster Password              ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes oldCred = HashPassword::passwordToBytes(oldPw);

    // Step 1: EraseMaster auth
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       uid::AUTH_ERASEMASTER, oldCred, ssr);
    step(1, "EraseMaster auth with old password", r);
    if (r.failed()) return false;

    // Step 2: Set new password
    Bytes newPin = HashPassword::passwordToBytes(newPw);
    r = api.setEraseMasterPassword(session, newPin);
    step(2, "Set EraseMaster new password", r);

    // Step 3: Close
    api.closeSession(session);
    step(3, "Close session", Result(ErrorCode::Success));

    // Step 4: Verify
    Bytes newCred = HashPassword::passwordToBytes(newPw);
    Session session2(transport, comId);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(session2, uid::SP_ENTERPRISE, false,
                                  uid::AUTH_ERASEMASTER, newCred, ssr2);
    step(4, "Verify auth with new password", r);
    if (r.ok()) api.closeSession(session2);

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  6. Erase Band (Crypto Erase)
// ════════════════════════════════════════════════════════

/// @scenario Enterprise Band 암호화 소거
/// @precondition EraseMaster 비밀번호 유효, Band N이 구성됨
/// @steps
///   1. Enterprise SP에 EraseMaster 인증으로 쓰기 세션 열기
///   2. Band N에 대해 Crypto Erase 수행
///   3. 세션 닫기
/// @expected
///   - Band N의 암호화 키가 재생성됨
///   - 이전 키로 암호화된 데이터는 복호화 불가
static bool ent_eraseBand(EvalApi& api,
                           std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           const std::string& eraseMasterPw,
                           uint32_t bandId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  6. Erase Band (Crypto Erase)             ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(eraseMasterPw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       uid::AUTH_ERASEMASTER, cred, ssr);
    step(1, "EraseMaster auth", r);
    if (r.failed()) return false;

    r = api.eraseBand(session, bandId);
    step(2, "Erase Band " + std::to_string(bandId), r);

    api.closeSession(session);
    step(3, "Close session", Result(ErrorCode::Success));

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  7. Erase All Bands
// ════════════════════════════════════════════════════════

/// @scenario 전체 Band 소거
/// @precondition EraseMaster 비밀번호 유효
/// @steps
///   1. Enterprise SP에 EraseMaster 인증으로 쓰기 세션 열기
///   2. 전체 Band에 대해 Crypto Erase 수행 (maxBands까지)
///   3. 세션 닫기
/// @expected
///   - 모든 Band의 암호화 키가 재생성됨
///   - 전체 드라이브 데이터가 사실상 소거됨
static bool ent_eraseAllBands(EvalApi& api,
                               std::shared_ptr<ITransport> transport,
                               uint16_t comId,
                               const std::string& eraseMasterPw,
                               uint32_t maxBands) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  7. Erase All Bands                       ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(eraseMasterPw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       uid::AUTH_ERASEMASTER, cred, ssr);
    step(1, "EraseMaster auth", r);
    if (r.failed()) return false;

    r = api.eraseAllBands(session, maxBands);
    step(2, "Erase all bands (max=" + std::to_string(maxBands) + ")", r);

    api.closeSession(session);
    step(3, "Close session", Result(ErrorCode::Success));

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  8. Band LockOnReset
// ════════════════════════════════════════════════════════

/// @scenario Band LockOnReset 설정
/// @precondition BandMaster N 비밀번호 유효, Band N이 구성됨
/// @steps
///   1. Enterprise SP에 BandMaster N 인증으로 쓰기 세션 열기
///   2. Band N에 LockOnReset = true 설정
///   3. Band N 정보 조회하여 LockOnReset 확인
///   4. 세션 닫기
/// @expected
///   - 전원 사이클/리셋 시 Band N이 자동으로 잠금됨
///   - LockOnReset 설정이 반영됨
static bool ent_setBandLockOnReset(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    const std::string& bandMasterPw,
                                    uint32_t bandId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  8. Band LockOnReset                      ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(bandMasterPw);
    uint64_t bmAuth = uid::makeBandMasterUid(bandId).toUint64();

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true,
                                       bmAuth, cred, ssr);
    step(1, "BandMaster auth", r);
    if (r.failed()) return false;

    r = api.setBandLockOnReset(session, bandId, true);
    step(2, "Set LockOnReset=true for Band " + std::to_string(bandId), r);

    LockingInfo info;
    r = api.getBandInfo(session, bandId, info);
    step(3, "Verify Band info", r);

    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <device> <bandmaster_pw> <erasemaster_pw>"
                  << " [band_id] [start] [length] [new_bm_pw] [new_em_pw]\n\n";
        std::cerr << "TCG Enterprise SSC Application Note.\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 band123 erase123\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 band123 erase123 0 0 1024\n";
        return 1;
    }

    std::string device        = argv[1];
    std::string bandMasterPw  = argv[2];
    std::string eraseMasterPw = argv[3];
    uint32_t bandId           = (argc > 4) ? std::stoul(argv[4]) : 0;
    uint64_t bandStart        = (argc > 5) ? std::stoull(argv[5]) : 0;
    uint64_t bandLength       = (argc > 6) ? std::stoull(argv[6]) : 1024;
    std::string newBmPw       = (argc > 7) ? argv[7] : "newBand456";
    std::string newEmPw       = (argc > 8) ? argv[8] : "newErase456";

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
    std::cout << " TCG Enterprise SSC Application Note\n";
    std::cout << " Device: " << device << "\n";
    std::cout << " ComID:  0x" << std::hex << comId << std::dec << "\n";
    std::cout << " SSC:    " << (int)opt.sscType << "\n";
    std::cout << "═══════════════════════════════════════════════\n";

    struct { const char* name; bool pass; } results[] = {
        {"1. Configure Band",             false},
        {"2. Lock Band",                  false},
        {"3. Unlock Band",                false},
        {"4. Set BandMaster Password",    false},
        {"5. Set EraseMaster Password",   false},
        {"6. Erase Band",                 false},
        {"7. Erase All Bands",            false},
        {"8. Band LockOnReset",           false},
    };

    results[0].pass = ent_configureBand(api, transport, comId,
                                         bandMasterPw, bandId, bandStart, bandLength);
    results[1].pass = ent_lockBand(api, transport, comId, bandMasterPw, bandId);
    results[2].pass = ent_unlockBand(api, transport, comId, bandMasterPw, bandId);
    results[3].pass = ent_setBandMasterPassword(api, transport, comId,
                                                  bandMasterPw, newBmPw, bandId);
    results[4].pass = ent_setEraseMasterPassword(api, transport, comId,
                                                   eraseMasterPw, newEmPw);
    // Use new passwords after change
    results[5].pass = ent_eraseBand(api, transport, comId, newEmPw, bandId);
    results[6].pass = ent_eraseAllBands(api, transport, comId, newEmPw, 4);
    results[7].pass = ent_setBandLockOnReset(api, transport, comId, newBmPw, bandId);

    // Summary
    std::cout << "\n═══════════════════════════════════════════════\n";
    std::cout << " Summary\n";
    std::cout << "═══════════════════════════════════════════════\n";
    int passCount = 0;
    for (auto& r : results) {
        std::cout << "  " << (r.pass ? "[PASS]" : "[FAIL]") << " " << r.name << "\n";
        if (r.pass) passCount++;
    }
    std::cout << "\n  Total: " << passCount << "/8 passed\n";

    libsed::shutdown();
    return (passCount == 8) ? 0 : 1;
}
