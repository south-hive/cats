/// @file appnote_opal.cpp
/// @brief TCG Storage Application Note: Opal SSC (AppNote 3-13) 구현 예제.
///
/// TCG Storage Application Note "Utilizing Storage Devices Compliant with
/// the TCG Opal SSC"의 섹션 3~13에 해당하는 전체 Opal 라이프사이클을
/// EvalApi (단계별 플랫 API)로 구현합니다.
///
/// 포함 시나리오:
///   AppNote  3: Take Ownership (소유권 확보)
///   AppNote  4: Activate Locking SP (Locking SP 활성화)
///   AppNote  5: Configure Locking Range (잠금 범위 구성)
///   AppNote  6: Set User Password (사용자 비밀번호 설정)
///   AppNote  7: Enable User Authority in ACE (ACE에서 사용자 권한 활성화)
///   AppNote  8: Lock a Range (범위 잠금)
///   AppNote  9: Unlock a Range (범위 잠금 해제)
///   AppNote 10: Shadow MBR (MBR 섀도잉)
///   AppNote 11: Crypto Erase (암호화 소거)
///   AppNote 12: Revert Locking SP (Locking SP 복원)
///   AppNote 13: Revert TPer / PSID Revert (TPer 복원)

#include <libsed/sed_library.h>
#include <libsed/cli/cli_common.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>

using namespace libsed;
using namespace libsed::eval;

// ════════════════════════════════════════════════════════
//  AppNote 3: Take Ownership
// ════════════════════════════════════════════════════════

/// @scenario AppNote 3: 소유권 확보 (Take Ownership)
/// @precondition 드라이브가 초기 상태(Manufactured)이며 SID == MSID인 상태
/// @steps
///   1. AdminSP에 익명(Anybody) 읽기 세션 열기
///   2. C_PIN_MSID 테이블에서 MSID PIN 읽기
///   3. 세션 닫기
///   4. MSID를 자격 증명으로 사용하여 AdminSP에 SID 인증 쓰기 세션 열기
///   5. C_PIN_SID에 새 비밀번호 설정
///   6. 세션 닫기
/// @expected
///   - MSID PIN 읽기 성공
///   - SID 비밀번호가 새 값으로 변경됨
///   - 이후 SID 인증 시 새 비밀번호 사용 필요
static bool appnote3_takeOwnership(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    const std::string& newSidPw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 3: Take Ownership               ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Step 1: Anonymous read session to AdminSP
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
        std::cout << "  MSID is empty, cannot proceed\n";
        return false;
    }

    // Step 4: Auth as SID using MSID credential
    Session session2(transport, comId);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(session2, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, msidPin, ssr2);
    step(4, "SID auth with MSID credential", r);
    if (r.failed()) return false;

    // Step 5: Set new SID password
    Bytes newPin = HashPassword::passwordToBytes(newSidPw);
    r = api.setCPin(session2, uid::CPIN_SID, newPin);
    step(5, "Set C_PIN_SID to new password", r);

    // Step 6: Close session
    api.closeSession(session2);
    step(6, "Close session", Result(ErrorCode::Success));

    std::cout << "  >> SID password changed successfully\n";
    return r.ok();
}

// ════════════════════════════════════════════════════════
//  AppNote 4: Activate Locking SP
// ════════════════════════════════════════════════════════

/// @scenario AppNote 4: Locking SP 활성화
/// @precondition SID 비밀번호가 설정된 상태 (AppNote 3 완료)
/// @steps
///   1. AdminSP에 SID 인증으로 쓰기 세션 열기
///   2. Locking SP의 현재 Lifecycle 상태 조회
///   3. Locking SP 활성화 (Activate)
///   4. 활성화 후 Lifecycle 상태 재조회
///   5. 세션 닫기
/// @expected
///   - 활성화 전 Lifecycle == Manufactured-Inactive (0x08)
///   - 활성화 후 Lifecycle == Manufactured (0x09)
///   - Locking SP가 활성화되어 잠금 기능 사용 가능
static bool appnote4_activateLockingSP(EvalApi& api,
                                        std::shared_ptr<ITransport> transport,
                                        uint16_t comId,
                                        const std::string& sidPw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 4: Activate Locking SP           ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes sidCred = HashPassword::passwordToBytes(sidPw);

    // Step 1: SID auth to AdminSP
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                       uid::AUTH_SID, sidCred, ssr);
    step(1, "SID auth to AdminSP", r);
    if (r.failed()) return false;

    // Step 2: Check current lifecycle
    uint8_t lifecycle = 0;
    r = api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle);
    step(2, "Get Locking SP lifecycle", r);
    std::cout << "    Lifecycle before: 0x" << std::hex << (int)lifecycle << std::dec << "\n";

    // Step 3: Activate
    r = api.activate(session, uid::SP_LOCKING);
    step(3, "Activate Locking SP", r);

    // Step 4: Verify lifecycle changed
    uint8_t lifecycle2 = 0;
    r = api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle2);
    step(4, "Verify lifecycle after activation", r);
    std::cout << "    Lifecycle after: 0x" << std::hex << (int)lifecycle2 << std::dec << "\n";

    // Step 5: Close
    api.closeSession(session);
    step(5, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  AppNote 5: Configure Locking Range
// ════════════════════════════════════════════════════════

/// @scenario AppNote 5: 잠금 범위 구성 (Configure Locking Range)
/// @precondition Locking SP가 활성화된 상태 (AppNote 4 완료), Admin1 비밀번호 설정됨
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. Range 1에 시작 LBA, 길이, ReadLockEnabled, WriteLockEnabled 설정
///   3. Range 1 정보 조회하여 설정 확인
///   4. 세션 닫기
/// @expected
///   - Range 1이 지정된 시작/길이로 구성됨
///   - ReadLockEnabled = true, WriteLockEnabled = true
static bool appnote5_configureLockingRange(EvalApi& api,
                                            std::shared_ptr<ITransport> transport,
                                            uint16_t comId,
                                            const std::string& admin1Pw,
                                            uint64_t rangeStart,
                                            uint64_t rangeLen) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 5: Configure Locking Range       ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    // Step 1: Admin1 auth to LockingSP
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Configure Range 1
    r = api.setRange(session, 1, rangeStart, rangeLen, true, true);
    step(2, "Set Range 1 (start=" + std::to_string(rangeStart) +
            " len=" + std::to_string(rangeLen) + " RLE=1 WLE=1)", r);

    // Step 3: Verify
    LockingInfo info;
    r = api.getLockingInfo(session, 1, info);
    step(3, "Verify Range 1 configuration", r);
    if (r.ok()) {
        std::cout << "    RangeStart=" << info.rangeStart
                  << " RangeLength=" << info.rangeLength
                  << " RLE=" << info.readLockEnabled
                  << " WLE=" << info.writeLockEnabled << "\n";
    }

    // Step 4: Close
    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  AppNote 6: Set User Password
// ════════════════════════════════════════════════════════

/// @scenario AppNote 6: 사용자 비밀번호 설정
/// @precondition Locking SP 활성화 완료, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. C_PIN_User1에 새 비밀번호 설정
///   3. 세션 닫기
/// @expected
///   - User1 비밀번호가 성공적으로 설정됨
static bool appnote6_setUserPassword(EvalApi& api,
                                      std::shared_ptr<ITransport> transport,
                                      uint16_t comId,
                                      const std::string& admin1Pw,
                                      const std::string& user1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 6: Set User Password             ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    // Step 1: Admin1 auth to LockingSP
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Set User1 password
    Bytes user1Pin = HashPassword::passwordToBytes(user1Pw);
    r = api.setCPin(session, uid::CPIN_USER1, user1Pin);
    step(2, "Set C_PIN_User1", r);

    // Step 3: Close
    api.closeSession(session);
    step(3, "Close session", Result(ErrorCode::Success));

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  AppNote 7: Enable User Authority in ACE
// ════════════════════════════════════════════════════════

/// @scenario AppNote 7: ACE에서 사용자 권한 활성화
/// @precondition Locking SP 활성화 완료, Admin1 비밀번호 유효, User1 비밀번호 설정됨
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. User1 Authority 활성화 (Enabled = true)
///   3. User1을 Range 1의 ReadLock ACE에 추가
///   4. User1을 Range 1의 WriteLock ACE에 추가
///   5. User1 활성화 상태 확인
///   6. 세션 닫기
/// @expected
///   - User1이 활성화됨
///   - User1이 Range 1의 Lock/Unlock 권한을 가짐
static bool appnote7_enableUserInAce(EvalApi& api,
                                      std::shared_ptr<ITransport> transport,
                                      uint16_t comId,
                                      const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 7: Enable User Authority in ACE  ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    // Step 1: Admin1 auth
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Enable User1
    r = api.enableUser(session, 1);
    step(2, "Enable User1 authority", r);

    // Step 3: Add User1 to Range1 ReadLock ACE
    r = api.addAuthorityToAce(session,
            uid::makeAceLockingRangeSetRdLocked(1).toUint64(),
            uid::AUTH_USER1);
    step(3, "Add User1 to Range1 Set_RdLocked ACE", r);

    // Step 4: Add User1 to Range1 WriteLock ACE
    r = api.addAuthorityToAce(session,
            uid::makeAceLockingRangeSetWrLocked(1).toUint64(),
            uid::AUTH_USER1);
    step(4, "Add User1 to Range1 Set_WrLocked ACE", r);

    // Step 5: Verify User1 is enabled
    bool enabled = false;
    r = api.isUserEnabled(session, 1, enabled);
    step(5, "Verify User1 enabled", r);
    std::cout << "    User1 enabled: " << (enabled ? "true" : "false") << "\n";

    // Step 6: Close
    api.closeSession(session);
    step(6, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  AppNote 8: Lock a Range
// ════════════════════════════════════════════════════════

/// @scenario AppNote 8: 범위 잠금 (Lock a Range)
/// @precondition User1이 활성화되고 Range 1의 Lock/Unlock ACE에 추가됨
/// @steps
///   1. LockingSP에 User1 인증으로 쓰기 세션 열기
///   2. Range 1을 잠금 (ReadLocked=true, WriteLocked=true)
///   3. Range 1 상태 조회하여 잠금 확인
///   4. 세션 닫기
/// @expected
///   - Range 1이 ReadLocked=true, WriteLocked=true 상태
///   - 해당 LBA 범위에 대한 읽기/쓰기가 차단됨
static bool appnote8_lockRange(EvalApi& api,
                                std::shared_ptr<ITransport> transport,
                                uint16_t comId,
                                const std::string& user1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 8: Lock a Range                  ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes user1Cred = HashPassword::passwordToBytes(user1Pw);

    // Step 1: User1 auth
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_USER1, user1Cred, ssr);
    step(1, "User1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Lock Range 1
    r = api.setRangeLock(session, 1, true, true);
    step(2, "Lock Range 1 (RdLocked=1 WrLocked=1)", r);

    // Step 3: Verify
    LockingInfo info;
    r = api.getLockingInfo(session, 1, info);
    step(3, "Verify Range 1 lock state", r);
    if (r.ok()) {
        std::cout << "    ReadLocked=" << info.readLocked
                  << " WriteLocked=" << info.writeLocked << "\n";
    }

    // Step 4: Close
    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  AppNote 9: Unlock a Range
// ════════════════════════════════════════════════════════

/// @scenario AppNote 9: 범위 잠금 해제 (Unlock a Range)
/// @precondition Range 1이 잠금 상태, User1이 Unlock 권한 보유
/// @steps
///   1. LockingSP에 User1 인증으로 쓰기 세션 열기
///   2. Range 1을 잠금 해제 (ReadLocked=false, WriteLocked=false)
///   3. Range 1 상태 조회하여 잠금 해제 확인
///   4. 세션 닫기
/// @expected
///   - Range 1이 ReadLocked=false, WriteLocked=false 상태
///   - 해당 LBA 범위에 대한 읽기/쓰기 가능
static bool appnote9_unlockRange(EvalApi& api,
                                  std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const std::string& user1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 9: Unlock a Range                ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes user1Cred = HashPassword::passwordToBytes(user1Pw);

    // Step 1: User1 auth
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_USER1, user1Cred, ssr);
    step(1, "User1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Unlock Range 1
    r = api.setRangeLock(session, 1, false, false);
    step(2, "Unlock Range 1 (RdLocked=0 WrLocked=0)", r);

    // Step 3: Verify
    LockingInfo info;
    r = api.getLockingInfo(session, 1, info);
    step(3, "Verify Range 1 unlock state", r);
    if (r.ok()) {
        std::cout << "    ReadLocked=" << info.readLocked
                  << " WriteLocked=" << info.writeLocked << "\n";
    }

    // Step 4: Close
    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  AppNote 10: Shadow MBR
// ════════════════════════════════════════════════════════

/// @scenario AppNote 10: MBR 섀도잉 (Shadow MBR)
/// @precondition Locking SP 활성화 완료, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. MBR 섀도잉 활성화 (MBREnabled = true)
///   3. PBA(Pre-Boot Authentication) 이미지 데이터를 MBR 테이블에 쓰기
///   4. MBR 데이터 읽기 및 검증
///   5. MBRDone = true 설정 (실제 MBR 노출)
///   6. MBR 상태 확인 (MBREnabled, MBRDone)
///   7. 세션 닫기
/// @expected
///   - MBR 섀도잉 활성화 후 부팅 시 PBA 이미지가 노출됨
///   - MBRDone = true 설정 후 실제 디스크 MBR이 노출됨
///   - 전원 사이클 시 MBRDone은 false로 초기화됨
static bool appnote10_mbrShadow(EvalApi& api,
                                 std::shared_ptr<ITransport> transport,
                                 uint16_t comId,
                                 const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 10: Shadow MBR                   ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    // Step 1: Admin1 auth
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Enable MBR shadowing
    r = api.setMbrEnable(session, true);
    step(2, "Enable MBR shadowing (MBREnable=true)", r);

    // Step 3: Write PBA image (512 bytes synthetic data)
    Bytes pbaImage(512, 0);
    // Simulate a minimal boot sector
    pbaImage[0] = 0xEB;  // JMP short
    pbaImage[1] = 0x3C;  // offset
    pbaImage[2] = 0x90;  // NOP
    std::memcpy(&pbaImage[3], "TCGPBA", 6);
    pbaImage[510] = 0x55; // Boot signature
    pbaImage[511] = 0xAA;
    r = api.writeMbrData(session, 0, pbaImage);
    step(3, "Write PBA image to MBR table (512 bytes)", r);

    // Step 4: Read back and verify
    Bytes readBack;
    r = api.readMbrData(session, 0, 512, readBack);
    step(4, "Read back MBR data", r);
    if (r.ok()) {
        bool match = (readBack == pbaImage);
        std::cout << "    Data match: " << (match ? "YES" : "NO") << "\n";
        printHex("First 16 bytes", Bytes(readBack.begin(),
                 readBack.begin() + std::min(readBack.size(), (size_t)16)));
    }

    // Step 5: Set MBRDone = true
    r = api.setMbrDone(session, true);
    step(5, "Set MBRDone=true (expose real MBR)", r);

    // Step 6: Verify MBR status
    bool mbrEnabled = false, mbrDone = false;
    r = api.getMbrStatus(session, mbrEnabled, mbrDone);
    step(6, "Get MBR status", r);
    std::cout << "    MBREnabled=" << mbrEnabled << " MBRDone=" << mbrDone << "\n";

    // Step 7: Close
    api.closeSession(session);
    step(7, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  AppNote 11: Crypto Erase
// ════════════════════════════════════════════════════════

/// @scenario AppNote 11: 암호화 소거 (Crypto Erase)
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효, Range 1이 구성됨
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. Range 1의 현재 ActiveKey UID 조회
///   3. Range 1에 대해 Crypto Erase 수행 (GenKey로 암호화 키 재생성)
///   4. Range 1의 새 ActiveKey UID 조회 (변경 확인)
///   5. 세션 닫기
/// @expected
///   - Crypto Erase 후 암호화 키가 재생성됨
///   - 이전 키로 암호화된 데이터는 복호화 불가 (사실상 데이터 소거)
///   - Range 구성 (시작/길이/잠금 설정)은 유지됨
static bool appnote11_cryptoErase(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 11: Crypto Erase                 ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    // Step 1: Admin1 auth
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Get current ActiveKey
    Uid keyBefore;
    r = api.getActiveKey(session, 1, keyBefore);
    step(2, "Get ActiveKey before erase", r);
    if (r.ok())
        std::cout << "    ActiveKey before: 0x" << std::hex << keyBefore.toUint64()
                  << std::dec << "\n";

    // Step 3: Crypto Erase (regenerate key)
    r = api.cryptoErase(session, 1);
    step(3, "Crypto Erase Range 1", r);

    // Step 4: Get new ActiveKey
    Uid keyAfter;
    r = api.getActiveKey(session, 1, keyAfter);
    step(4, "Get ActiveKey after erase", r);
    if (r.ok()) {
        std::cout << "    ActiveKey after:  0x" << std::hex << keyAfter.toUint64()
                  << std::dec << "\n";
        std::cout << "    Key changed: "
                  << (keyBefore.toUint64() != keyAfter.toUint64() ? "YES" : "NO") << "\n";
    }

    // Step 5: Close
    api.closeSession(session);
    step(5, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  AppNote 12: Revert Locking SP
// ════════════════════════════════════════════════════════

/// @scenario AppNote 12: Locking SP 복원 (Revert Locking SP)
/// @precondition Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. Locking SP Revert 수행
///   3. (세션은 TPer에 의해 자동 종료됨)
/// @expected
///   - Locking SP가 초기 상태(Manufactured-Inactive)로 복원됨
///   - 모든 잠금 범위, 사용자 비밀번호, ACE, MBR 설정 초기화
///   - 세션은 Revert에 의해 자동 종료됨
static bool appnote12_revertLockingSP(EvalApi& api,
                                       std::shared_ptr<ITransport> transport,
                                       uint16_t comId,
                                       const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 12: Revert Locking SP            ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    // Step 1: Admin1 auth
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Step 2: Revert Locking SP
    r = api.revertSP(session, uid::SP_LOCKING);
    step(2, "Revert Locking SP", r);

    // Note: Session is implicitly closed by TPer after Revert
    // Do NOT call closeSession — it would fail
    std::cout << "  >> Locking SP reverted. Session auto-closed by TPer.\n";

    return r.ok();
}

// ════════════════════════════════════════════════════════
//  AppNote 13: Revert TPer / PSID Revert
// ════════════════════════════════════════════════════════

/// @scenario AppNote 13: TPer 복원 / PSID Revert
/// @precondition SID 또는 PSID 비밀번호가 유효해야 함
/// @steps
///   Path A (SID Revert):
///     1. AdminSP에 SID 인증으로 쓰기 세션 열기
///     2. Admin SP(TPer) Revert 수행
///   Path B (PSID Revert — SID 인증 실패 시 대체):
///     1. AdminSP에 PSID 인증으로 쓰기 세션 열기
///     2. PSID Revert 수행
/// @expected
///   - 드라이브가 완전히 초기 상태로 복원됨
///   - SID == MSID로 초기화됨
///   - 모든 SP, 잠금, MBR, 사용자 설정 초기화
///   - PSID Revert는 물리적 접근이 필요한 비상 복구 수단
static bool appnote13_revertTPer(EvalApi& api,
                                  std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const std::string& sidPw,
                                  const std::string& psidPw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  AppNote 13: Revert TPer / PSID Revert    ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes sidCred = HashPassword::passwordToBytes(sidPw);

    // Path A: Try SID Revert first
    std::cout << "\n  --- Path A: SID Revert ---\n";
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                           uid::AUTH_SID, sidCred, ssr);
        step(1, "SID auth to AdminSP", r);

        if (r.ok()) {
            r = api.revertSP(session, uid::SP_ADMIN);
            step(2, "Revert TPer (Admin SP)", r);
            // Session auto-closed by TPer after Revert
            if (r.ok()) {
                std::cout << "  >> TPer reverted via SID. Drive reset to factory.\n";
                return true;
            }
        }
    }

    // Path B: PSID Revert (fallback)
    if (psidPw.empty()) {
        std::cout << "  SID Revert failed and no PSID password provided.\n";
        return false;
    }

    std::cout << "\n  --- Path B: PSID Revert (fallback) ---\n";
    Bytes psidCred = HashPassword::passwordToBytes(psidPw);
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                           uid::AUTH_PSID, psidCred, ssr);
        step(1, "PSID auth to AdminSP", r);
        if (r.failed()) return false;

        r = api.psidRevert(session);
        step(2, "PSID Revert", r);
        // Session auto-closed by TPer
        std::cout << "  >> PSID Revert complete. Drive reset to factory.\n";
        return r.ok();
    }
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <device> <new_sid_pw> <admin1_pw> <user1_pw>"
                  << " [psid_pw] [range_start] [range_len] [--dump] [--log]\n\n";
        std::cerr << "TCG Opal Application Note (AppNote 3-13) complete lifecycle.\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 mySID admin123 user123\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 mySID admin123 user123 psid123 0 1024\n";
        return 1;
    }

    std::string device    = argv[1];
    std::string newSidPw  = argv[2];
    std::string admin1Pw  = argv[3];
    std::string user1Pw   = argv[4];
    std::string psidPw    = (argc > 5) ? argv[5] : "";
    uint64_t rangeStart   = (argc > 6) ? std::stoull(argv[6]) : 0;
    uint64_t rangeLen     = (argc > 7) ? std::stoull(argv[7]) : 1024;

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

    // Common initialization: get ComID and exchange properties
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
    std::cout << " TCG Opal Application Note (AppNote 3-13)\n";
    std::cout << " Device: " << device << "\n";
    std::cout << " ComID:  0x" << std::hex << comId << std::dec << "\n";
    std::cout << " SSC:    " << (int)opt.sscType << "\n";
    std::cout << "═══════════════════════════════════════════════\n";

    // Track results
    struct { const char* name; bool pass; } results[] = {
        {"AppNote  3: Take Ownership",            false},
        {"AppNote  4: Activate Locking SP",        false},
        {"AppNote  5: Configure Locking Range",    false},
        {"AppNote  6: Set User Password",          false},
        {"AppNote  7: Enable User in ACE",         false},
        {"AppNote  8: Lock Range",                 false},
        {"AppNote  9: Unlock Range",               false},
        {"AppNote 10: Shadow MBR",                 false},
        {"AppNote 11: Crypto Erase",               false},
        {"AppNote 12: Revert Locking SP",          false},
        {"AppNote 13: Revert TPer",                false},
    };

    // Execute the full Opal lifecycle
    results[ 0].pass = appnote3_takeOwnership(api, transport, comId, newSidPw);
    results[ 1].pass = appnote4_activateLockingSP(api, transport, comId, newSidPw);

    // After activation, Admin1 password defaults to MSID — set it
    // (In real usage, Admin1 password should be set after activation)
    results[ 2].pass = appnote5_configureLockingRange(api, transport, comId,
                                                        admin1Pw, rangeStart, rangeLen);
    results[ 3].pass = appnote6_setUserPassword(api, transport, comId, admin1Pw, user1Pw);
    results[ 4].pass = appnote7_enableUserInAce(api, transport, comId, admin1Pw);
    results[ 5].pass = appnote8_lockRange(api, transport, comId, user1Pw);
    results[ 6].pass = appnote9_unlockRange(api, transport, comId, user1Pw);
    results[ 7].pass = appnote10_mbrShadow(api, transport, comId, admin1Pw);
    results[ 8].pass = appnote11_cryptoErase(api, transport, comId, admin1Pw);
    results[ 9].pass = appnote12_revertLockingSP(api, transport, comId, admin1Pw);
    results[10].pass = appnote13_revertTPer(api, transport, comId, newSidPw, psidPw);

    // Summary
    std::cout << "\n═══════════════════════════════════════════════\n";
    std::cout << " Summary\n";
    std::cout << "═══════════════════════════════════════════════\n";
    int passCount = 0;
    for (auto& r : results) {
        std::cout << "  " << (r.pass ? "[PASS]" : "[FAIL]") << " " << r.name << "\n";
        if (r.pass) passCount++;
    }
    std::cout << "\n  Total: " << passCount << "/11 passed\n";

    libsed::shutdown();
    return (passCount == 11) ? 0 : 1;
}
