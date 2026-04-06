/// @file test_sim_comprehensive.cpp
/// @brief SimTransport 종합 테스트 — L2~L5 시나리오를 실제 TPer 시뮬레이션으로 검증
///
/// MockTransport에서 검증 불가능했던 에러 응답, 권한 검사, 상태 전이를 검증.

#include "test_helper.h"
#include "libsed/transport/sim_transport.h"

using namespace libsed;
using namespace libsed::test;
using namespace libsed::uid;
using namespace libsed::eval;

// ── 편의: SimTransport로 Discovery + Properties 수행 후 comId 반환 ──
static uint16_t simSetup(EvalApi& api, std::shared_ptr<SimTransport> sim) {
    DiscoveryInfo info;
    api.discovery0(sim, info);
    PropertiesResult props;
    api.exchangeProperties(sim, info.baseComId, props);
    return info.baseComId;
}

// ═══════════════════════════════════════════════════════
//  L2: 표준 시퀀스 (SimTransport 버전)
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(SIM2, DataStoreRoundTrip) {
    // DataStore 쓰기 → 읽기 → 비교
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Activate Locking SP first
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }

    // DataStore 쓰기/읽기
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        Bytes testData = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        RawResult raw;
        EXPECT_OK(api.tcgWriteDataStore(s, 0, testData, raw));

        DataOpResult readResult;
        EXPECT_OK(api.tcgReadDataStore(s, 0, 8, readResult));
        CHECK(readResult.data == testData);

        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM2, MbrWriteRead) {
    // MBR 쓰기 → 읽기 → 비교
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Activate + Enable MBR
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        EXPECT_OK(api.setMbrEnable(s, true));

        Bytes pba = {0x55, 0xAA, 0x00, 0xFF, 0x01, 0x02, 0x03, 0x04};
        EXPECT_OK(api.writeMbrData(s, 0, pba));

        Bytes readBack;
        RawResult raw;
        EXPECT_OK(api.readMbrData(s, 0, 8, readBack, raw));
        CHECK(readBack == pba);

        EXPECT_OK(api.setMbrDone(s, true));

        bool mbrEn = false, mbrDn = false;
        EXPECT_OK(api.getMbrStatus(s, mbrEn, mbrDn));
        CHECK(mbrEn);
        CHECK(mbrDn);

        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM2, CryptoEraseKeyChange) {
    // CryptoErase 후 ActiveKey 변경 확인
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Setup
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        api.setRange(s, 1, 0, 1048576, true, true);

        // Key before
        Uid keyBefore;
        api.getActiveKey(s, 1, keyBefore);

        // CryptoErase
        EXPECT_OK(api.cryptoErase(s, 1));

        // Key after
        Uid keyAfter;
        api.getActiveKey(s, 1, keyAfter);

        // 키가 변경되었는지 확인
        CHECK_NE(keyBefore.toUint64(), keyAfter.toUint64());

        api.closeSession(s);
    }
    return true;
}

// ═══════════════════════════════════════════════════════
//  L3: 기능 간 연동 (SimTransport 버전)
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(SIM3, MultiUserRangeIsolation) {
    // User1은 Range1만, User2는 Range2만 제어 가능
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Activate
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }

    // Setup: Admin1 → 2 Ranges, 2 Users
    Bytes user1Pw = {'u', '1'};
    Bytes user2Pw = {'u', '2'};
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        api.setRange(s, 1, 0, 1048576, true, true);
        api.setRange(s, 2, 1048576, 1048576, true, true);

        api.enableUser(s, 1);
        api.setUserPassword(s, 1, user1Pw);
        api.assignUserToRange(s, 1, 1);

        api.enableUser(s, 2);
        api.setUserPassword(s, 2, user2Pw);
        api.assignUserToRange(s, 2, 2);

        api.closeSession(s);
    }

    // User1: Range1 lock OK
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER1, user1Pw, ssr);
        EXPECT_OK(api.setRangeLock(s, 1, true, true));
        EXPECT_OK(api.setRangeLock(s, 1, false, false));
        api.closeSession(s);
    }

    // User1: Range2 lock → NotAuthorized (ACE 격리)
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER1, user1Pw, ssr);
        RawResult raw;
        api.setRangeLock(s, 2, true, true, raw);
        CHECK(!raw.methodResult.isSuccess());  // NotAuthorized
        api.closeSession(s);
    }

    // User2: Range2 lock OK
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER2, user2Pw, ssr);
        EXPECT_OK(api.setRangeLock(s, 2, true, true));
        EXPECT_OK(api.setRangeLock(s, 2, false, false));
        api.closeSession(s);
    }

    // User2: Range1 lock → NotAuthorized
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER2, user2Pw, ssr);
        RawResult raw;
        api.setRangeLock(s, 1, true, true, raw);
        CHECK(!raw.methodResult.isSuccess());  // NotAuthorized
        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM3, PasswordRotation) {
    // 비밀번호 변경 후 새 비밀번호로만 인증 가능
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Change SID password
    Bytes newSid = {'n', 'e', 'w', '_', 's', 'i', 'd'};
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        EXPECT_OK(api.setCPin(s, CPIN_SID, newSid));
        api.closeSession(s);
    }

    // Old password fails
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        EXPECT_FAIL(r);
    }

    // New password works
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, newSid, ssr));
        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM3, LockOnResetSimulation) {
    // LockOnReset 설정 → StackReset → Range 자동 잠금
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Activate + Setup
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        api.setRange(s, 1, 0, 1048576, true, true);
        api.setLockOnReset(s, 1, true);

        // Unlock
        api.setRangeLock(s, 1, false, false);
        LockingRangeInfo info;
        api.getRangeInfo(s, 1, info);
        CHECK(!info.readLocked);

        api.closeSession(s);
    }

    // StackReset (power cycle simulation)
    EXPECT_OK(api.stackReset(sim, comId));

    // Re-setup properties after reset
    PropertiesResult props;
    api.exchangeProperties(sim, comId, props);

    // Range가 LockOnReset에 의해 자동 잠금되었는지 확인
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        LockingRangeInfo info;
        api.getRangeInfo(s, 1, info);
        CHECK(info.readLocked);   // LockOnReset으로 자동 잠금됨
        CHECK(info.writeLocked);

        api.closeSession(s);
    }
    return true;
}

// ═══════════════════════════════════════════════════════
//  L4: 오류/네거티브 (SimTransport 버전)
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(SIM4, WrongPasswordAuth) {
    // 잘못된 비밀번호 → 인증 실패
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);

    Session s(sim, comId);
    StartSessionResult ssr;
    Bytes wrongPw = {'w', 'r', 'o', 'n', 'g'};
    auto r = api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, wrongPw, ssr);
    EXPECT_FAIL(r);
    return true;
}

TEST_SCENARIO(SIM4, DoubleActivate) {
    // 이미 활성인 Locking SP 재활성화 → 에러
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);

        EXPECT_OK(api.activate(s, SP_LOCKING));

        // 두 번째 활성화 → method status 에러
        RawResult raw;
        api.activate(s, SP_LOCKING, raw);
        CHECK(!raw.methodResult.isSuccess());

        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM4, WriteInReadOnlySession) {
    // 읽기 전용 세션에서 쓰기 → NotAuthorized
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Activate first
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }

    // 읽기 전용 세션 → Set 시도
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSession(s, SP_LOCKING, false, ssr);

        RawResult raw;
        api.setRange(s, 1, 0, 1048576, true, true, raw);
        CHECK(!raw.methodResult.isSuccess());  // NotAuthorized (read-only session)

        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM4, SessionAfterClose) {
    // 세션 종료 후 메서드 호출 → SessionNotStarted
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);

    Session s(sim, comId);
    StartSessionResult ssr;
    api.startSession(s, SP_ADMIN, false, ssr);
    api.closeSession(s);

    Bytes pin;
    auto r = api.getCPin(s, CPIN_MSID, pin);
    EXPECT_FAIL(r);
    return true;
}

TEST_SCENARIO(SIM4, RevertWithoutAuth) {
    // 익명 세션에서 Revert → 실패
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);

    Session s(sim, comId);
    StartSessionResult ssr;
    api.startSession(s, SP_ADMIN, false, ssr);  // 익명 (write=false)

    RawResult raw;
    api.revertSP(s, SP_ADMIN, raw);
    CHECK(!raw.methodResult.isSuccess());  // read-only → NotAuthorized

    api.closeSession(s);
    return true;
}

TEST_SCENARIO(SIM4, DataStoreOverflow) {
    // DataStore 용량 초과 쓰기 → 에러
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        // 용량 초과 위치에 쓰기
        Bytes bigData(100, 0xAA);
        RawResult raw;
        api.tcgWriteDataStore(s, 65500, bigData, raw);
        // offset(65500) + size(100) > 65536 → method status 에러
        CHECK(!raw.methodResult.isSuccess());

        api.closeSession(s);
    }
    return true;
}

// ═══════════════════════════════════════════════════════
//  L5: 고급 시나리오 (SimTransport 버전)
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(SIM5, AgingCycle) {
    // 3 사이클 에이징: 매 사이클 SID pw 변경 + Range 재구성 + Lock/Unlock
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Initial setup
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }

    Bytes currentSidPw = msid;  // SID는 아직 MSID

    // Setup ranges + user once
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);
        api.setRange(s, 1, 0, 1024, true, true);
        api.enableUser(s, 1);
        Bytes user1Pw = {'u', '1'};
        api.setUserPassword(s, 1, user1Pw);
        api.assignUserToRange(s, 1, 1);
        api.closeSession(s);
    }

    for (int cycle = 0; cycle < 3; ++cycle) {
        // Change SID password
        Bytes newSidPw;
        for (char c : std::string("sid_v" + std::to_string(cycle)))
            newSidPw.push_back(static_cast<uint8_t>(c));

        {
            Session s(sim, comId);
            StartSessionResult ssr;
            auto r = api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, currentSidPw, ssr);
            if (r.failed()) { fprintf(stderr, "  Cycle %d: SID auth failed\n", cycle); return false; }
            api.setCPin(s, CPIN_SID, newSidPw);
            api.closeSession(s);
        }
        currentSidPw = newSidPw;

        // User1 Lock/Unlock
        Bytes user1Pw = {'u', '1'};
        {
            Session s(sim, comId);
            StartSessionResult ssr;
            api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER1, user1Pw, ssr);
            EXPECT_OK(api.setRangeLock(s, 1, true, true));
            EXPECT_OK(api.setRangeLock(s, 1, false, false));
            api.closeSession(s);
        }
    }

    // Verify final SID password works
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, currentSidPw, ssr));
        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM5, RevertAndResetState) {
    // Full lifecycle → Revert → Factory state 복원 확인
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Take ownership + activate
    Bytes sidPw = {'s', 'i', 'd'};
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.setCPin(s, CPIN_SID, sidPw);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }

    // Revert to factory
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sidPw, ssr);
        EXPECT_OK(api.revertSP(s, SP_ADMIN));
    }

    // Factory state: MSID == SID again
    Bytes newMsid = sim->msid();
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, newMsid, ssr));
        api.closeSession(s);
    }

    // Old SID password should fail
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sidPw, ssr);
        EXPECT_FAIL(r);
    }
    return true;
}

TEST_SCENARIO(SIM5, SessionStorm) {
    // 50회 빠른 세션 열기/닫기 — SimTransport 안정성
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);

    for (int i = 0; i < 50; ++i) {
        Session s(sim, comId);
        StartSessionResult ssr;
        auto r = api.startSession(s, SP_ADMIN, false, ssr);
        if (r.failed()) {
            fprintf(stderr, "  Session storm failed at %d\n", i);
            return false;
        }
        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM5, OwnershipTransfer) {
    // Owner A → Owner B 소유권 이전
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    Bytes ownerA = {'o', 'w', 'n', 'e', 'r', 'A'};
    Bytes ownerB = {'o', 'w', 'n', 'e', 'r', 'B'};

    // Owner A takes ownership
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.setCPin(s, CPIN_SID, ownerA);
        api.closeSession(s);
    }

    // Owner A transfers to Owner B
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, ownerA, ssr);
        api.setCPin(s, CPIN_SID, ownerB);
        api.closeSession(s);
    }

    // Owner A can't access anymore
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_FAIL(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, ownerA, ssr));
    }

    // Owner B can access
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, ownerB, ssr));
        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM5, PsidRevert) {
    // PSID로 공장 초기화 (SID 비밀번호 분실 시나리오)
    EvalApi api;
    SimConfig config;
    config.psid = {'P', 'S', 'I', 'D', '1', '2', '3', '4'};
    auto sim = std::make_shared<SimTransport>(config);
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // SID 비밀번호 변경 (소유권 획득)
    Bytes sidPw = {'m', 'y', '_', 's', 'i', 'd'};
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.setCPin(s, CPIN_SID, sidPw);
        api.closeSession(s);
    }

    // MSID로 SID 인증 실패 (비밀번호 변경됨)
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        EXPECT_FAIL(r);
    }

    // PSID Revert로 공장 초기화
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_PSID, config.psid, ssr));
        EXPECT_OK(api.revertSP(s, SP_ADMIN));
    }

    // 공장 상태 복원: MSID로 SID 인증 성공
    Bytes newMsid = sim->msid();
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, newMsid, ssr));
        api.closeSession(s);
    }
    return true;
}

TEST_SCENARIO(SIM5, MultiTableDataStore) {
    // DataStore 테이블 0과 1에 독립적으로 쓰고 읽기
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();
    uint16_t comId = simSetup(api, sim);
    Bytes msid = sim->msid();

    // Activate
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }

    // Write to table 0 and table 1
    Bytes dataA = {0xAA, 0xBB, 0xCC, 0xDD};
    Bytes dataB = {0x11, 0x22, 0x33, 0x44};
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        RawResult raw;
        EXPECT_OK(api.tcgWriteDataStoreN(s, 0, 0, dataA, raw));
        EXPECT_OK(api.tcgWriteDataStoreN(s, 1, 0, dataB, raw));

        // Read back table 0
        DataOpResult readA;
        EXPECT_OK(api.tcgReadDataStoreN(s, 0, 0, 4, readA));
        CHECK(readA.data == dataA);

        // Read back table 1
        DataOpResult readB;
        EXPECT_OK(api.tcgReadDataStoreN(s, 1, 0, 4, readB));
        CHECK(readB.data == dataB);

        // 테이블 격리 확인: table 0 != table 1
        CHECK(readA.data != readB.data);

        api.closeSession(s);
    }
    return true;
}

// ═══════════════════════════════════════════════════════
//  SedDrive Facade 통합
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(SIM_FACADE, FullLifecycle) {
    // SedDrive facade로 전체 수명 주기
    auto sim = std::make_shared<SimTransport>();
    SedDrive drive(sim);

    EXPECT_OK(drive.query());
    CHECK_EQ(drive.sscType(), SscType::Opal20);

    EXPECT_OK(drive.takeOwnership("sid_pw"));
    EXPECT_OK(drive.activateLocking("sid_pw"));
    // Note: Activate 후 Admin1 비밀번호는 MSID이므로 MSID 문자열로 전달해야 하지만,
    // SedDrive facade에서는 문자열을 바이트로 변환하므로 MSID 바이트와 일치하지 않을 수 있음.
    // 여기서는 Revert만 테스트
    EXPECT_OK(drive.revert("sid_pw"));
    return true;
}

// ═══════════════════════════════════════════════════════
//  Runner
// ═══════════════════════════════════════════════════════

void run_sim_comprehensive_tests() {
    printf("\n=== SimTransport Comprehensive Tests ===\n");

    // L2 시퀀스
    RUN_SCENARIO(SIM2, DataStoreRoundTrip);
    RUN_SCENARIO(SIM2, MbrWriteRead);
    RUN_SCENARIO(SIM2, CryptoEraseKeyChange);

    // L3 연동
    RUN_SCENARIO(SIM3, MultiUserRangeIsolation);
    RUN_SCENARIO(SIM3, PasswordRotation);
    RUN_SCENARIO(SIM3, LockOnResetSimulation);

    // L4 에러
    RUN_SCENARIO(SIM4, WrongPasswordAuth);
    RUN_SCENARIO(SIM4, DoubleActivate);
    RUN_SCENARIO(SIM4, WriteInReadOnlySession);
    RUN_SCENARIO(SIM4, SessionAfterClose);
    RUN_SCENARIO(SIM4, RevertWithoutAuth);
    RUN_SCENARIO(SIM4, DataStoreOverflow);

    // L5 고급
    RUN_SCENARIO(SIM5, AgingCycle);
    RUN_SCENARIO(SIM5, RevertAndResetState);
    RUN_SCENARIO(SIM5, SessionStorm);
    RUN_SCENARIO(SIM5, OwnershipTransfer);
    RUN_SCENARIO(SIM5, PsidRevert);
    RUN_SCENARIO(SIM5, MultiTableDataStore);

    // Facade
    RUN_SCENARIO(SIM_FACADE, FullLifecycle);
}
