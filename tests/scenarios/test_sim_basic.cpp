/// @file test_sim_basic.cpp
/// @brief SimTransport 기반 통합 테스트 — 실제 TPer 시뮬레이션으로 시나리오 검증
///
/// MockTransport와 달리 응답 큐잉 불필요 — SimTransport가 TCG 프로토콜을 시뮬레이션.

#include "test_helper.h"
#include "libsed/transport/sim_transport.h"

using namespace libsed;
using namespace libsed::test;
using namespace libsed::uid;
using namespace libsed::eval;

// ═══════════════════════════════════════════════════════
//  SimTransport 기본 테스트
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(SIM, Discovery) {
    // SimTransport Discovery0 — 실제 Feature Descriptor 생성
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    DiscoveryInfo info;
    auto r = api.discovery0(sim, info);
    EXPECT_OK(r);
    CHECK_EQ(info.primarySsc, SscType::Opal20);
    CHECK(info.baseComId != 0);
    CHECK(info.tperPresent);
    CHECK(info.lockingPresent);
    return true;
}

TEST_SCENARIO(SIM, Properties) {
    // SimTransport Properties 교환
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    PropertiesResult result;
    auto r = api.exchangeProperties(sim, 0x0001, result);
    EXPECT_OK(r);
    CHECK_GT(result.tperMaxComPacketSize, 0u);
    CHECK_GT(result.tperMaxPacketSize, 0u);
    return true;
}

TEST_SCENARIO(SIM, QueryFlow) {
    // 전체 Query Flow: Discovery → Properties → 익명 세션 → MSID 읽기 → 종료
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    // Discovery
    DiscoveryInfo info;
    EXPECT_OK(api.discovery0(sim, info));

    // Properties
    PropertiesResult props;
    EXPECT_OK(api.exchangeProperties(sim, info.baseComId, props));

    // 익명 세션
    Session session(sim, info.baseComId);
    StartSessionResult ssr;
    EXPECT_OK(api.startSession(session, SP_ADMIN, false, ssr));
    CHECK_GT(ssr.tperSessionNumber, 0u);

    // MSID 읽기
    Bytes msid;
    EXPECT_OK(api.getCPin(session, CPIN_MSID, msid));
    CHECK(!msid.empty());

    // MSID가 SimTransport의 공장 MSID와 일치
    CHECK(msid == sim->msid());

    // 세션 종료
    EXPECT_OK(api.closeSession(session));
    return true;
}

TEST_SCENARIO(SIM, TakeOwnership) {
    // 소유권 획득: MSID로 SID 인증 → SID PIN 변경
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    // MSID 읽기
    DiscoveryInfo info;
    EXPECT_OK(api.discovery0(sim, info));
    PropertiesResult props;
    EXPECT_OK(api.exchangeProperties(sim, info.baseComId, props));

    Session s1(sim, info.baseComId);
    StartSessionResult ssr;
    EXPECT_OK(api.startSession(s1, SP_ADMIN, false, ssr));
    Bytes msid;
    EXPECT_OK(api.getCPin(s1, CPIN_MSID, msid));
    api.closeSession(s1);

    // SID 인증 (MSID 사용) → SID PIN 변경
    Session s2(sim, info.baseComId);
    EXPECT_OK(api.startSessionWithAuth(s2, SP_ADMIN, true, AUTH_SID, msid, ssr));

    Bytes newSidPin = {'n', 'e', 'w', '_', 's', 'i', 'd'};
    EXPECT_OK(api.setCPin(s2, CPIN_SID, newSidPin));
    api.closeSession(s2);

    // 검증: 새 비밀번호로 SID 인증 성공
    Session s3(sim, info.baseComId);
    EXPECT_OK(api.startSessionWithAuth(s3, SP_ADMIN, true, AUTH_SID, newSidPin, ssr));
    api.closeSession(s3);

    // 검증: MSID로 SID 인증 실패
    Session s4(sim, info.baseComId);
    auto r = api.startSessionWithAuth(s4, SP_ADMIN, true, AUTH_SID, msid, ssr);
    EXPECT_FAIL(r);  // AuthFailed — MSID != new SID PIN

    return true;
}

TEST_SCENARIO(SIM, ActivateLockingSP) {
    // Locking SP 활성화
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    DiscoveryInfo info;
    api.discovery0(sim, info);
    PropertiesResult props;
    api.exchangeProperties(sim, info.baseComId, props);

    // SID 세션
    Session s(sim, info.baseComId);
    StartSessionResult ssr;
    EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sim->msid(), ssr));

    // Activate
    EXPECT_OK(api.activate(s, SP_LOCKING));

    api.closeSession(s);
    return true;
}

TEST_SCENARIO(SIM, FullOpalLifecycle) {
    // 전체 Opal 수명 주기: 소유권 → 활성화 → Range → User → Lock/Unlock → Revert
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    DiscoveryInfo info;
    api.discovery0(sim, info);
    uint16_t comId = info.baseComId;
    PropertiesResult props;
    api.exchangeProperties(sim, comId, props);

    Bytes msid = sim->msid();

    // 1. Take Ownership
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        Bytes sidPw = {'s', 'i', 'd', '_', 'p', 'w'};
        api.setCPin(s, CPIN_SID, sidPw);
        api.closeSession(s);
    }

    // 2. Activate Locking SP
    Bytes sidPw = {'s', 'i', 'd', '_', 'p', 'w'};
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sidPw, ssr);
        EXPECT_OK(api.activate(s, SP_LOCKING));
        api.closeSession(s);
    }

    // 3. Configure Range + User (Admin1은 MSID로 인증)
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr);

        EXPECT_OK(api.setRange(s, 1, 0, 1048576, true, true));
        EXPECT_OK(api.enableUser(s, 1));

        Bytes user1Pw = {'u', 's', 'e', 'r', '1'};
        EXPECT_OK(api.setUserPassword(s, 1, user1Pw));
        EXPECT_OK(api.assignUserToRange(s, 1, 1));

        api.closeSession(s);
    }

    // 4. User1 Lock/Unlock
    Bytes user1Pw = {'u', 's', 'e', 'r', '1'};
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER1, user1Pw, ssr);

        EXPECT_OK(api.setRangeLock(s, 1, true, true));

        LockingRangeInfo rangeInfo;
        api.getRangeInfo(s, 1, rangeInfo);
        CHECK(rangeInfo.readLocked);
        CHECK(rangeInfo.writeLocked);

        EXPECT_OK(api.setRangeLock(s, 1, false, false));
        api.closeSession(s);
    }

    // 5. Revert
    {
        Session s(sim, comId);
        StartSessionResult ssr;
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sidPw, ssr);
        EXPECT_OK(api.revertSP(s, SP_ADMIN));
        // 세션은 TPer에 의해 자동 종료 (factoryReset 호출)
    }

    // 6. 공장 상태 확인: MSID로 SID 인증 가능
    {
        Bytes newMsid = sim->msid();
        Session s(sim, comId);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, newMsid, ssr));
        api.closeSession(s);
    }

    return true;
}

TEST_SCENARIO(SIM, WrongPassword) {
    // 잘못된 비밀번호 → 인증 실패
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    DiscoveryInfo info;
    api.discovery0(sim, info);
    PropertiesResult props;
    api.exchangeProperties(sim, info.baseComId, props);

    Session s(sim, info.baseComId);
    StartSessionResult ssr;
    Bytes wrongPw = {'w', 'r', 'o', 'n', 'g'};
    auto r = api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, wrongPw, ssr);
    EXPECT_FAIL(r);
    return true;
}

TEST_SCENARIO(SIM, SedDriveFacade) {
    // SedDrive facade를 SimTransport와 함께 사용
    auto sim = std::make_shared<SimTransport>();
    SedDrive drive(sim);

    EXPECT_OK(drive.query());
    CHECK_EQ(drive.sscType(), SscType::Opal20);
    CHECK(!drive.msid().empty());
    CHECK(drive.msid() == sim->msid());

    return true;
}

// ═══════════════════════════════════════════════════════
//  Runner
// ═══════════════════════════════════════════════════════

void run_sim_tests() {
    printf("\n=== SimTransport Integration Tests ===\n");

    RUN_SCENARIO(SIM, Discovery);
    RUN_SCENARIO(SIM, Properties);
    RUN_SCENARIO(SIM, QueryFlow);
    RUN_SCENARIO(SIM, TakeOwnership);
    RUN_SCENARIO(SIM, ActivateLockingSP);
    RUN_SCENARIO(SIM, FullOpalLifecycle);
    RUN_SCENARIO(SIM, WrongPassword);
    RUN_SCENARIO(SIM, SedDriveFacade);
}
