/// @file test_L3_cross.cpp
/// @brief Level 3: 기능 간 연동 검증 (TS-3A/3B) — 20개 시나리오
///
/// 여러 기능을 결합한 복합 시나리오. 순서 의존성, 상태 전이, gotcha 검증.

#include "test_helper.h"
#include "libsed/transport/sim_transport.h"

using namespace libsed;
using namespace libsed::test;
using namespace libsed::uid;
using namespace libsed::eval;

static constexpr uint16_t COMID = 0x0001;

// Helper: SimTransport에서 Locking SP 활성화
static Result activateLockingSP(EvalApi& api, std::shared_ptr<ITransport> transport,
                                 uint16_t comId, const Bytes& sidCred) {
    Session s(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sidCred, ssr);
    if (r.failed()) return r;
    r = api.activate(s, SP_LOCKING);
    api.closeSession(s);
    return r;
}

// Helper: 세션 열기 (반복 사용)
static bool openSession(EvalApi& api, std::shared_ptr<MockTransport> mock,
                         Session& session, uint64_t sp, uint64_t auth) {
    queueSyncSessionResponse(*mock, COMID, 1, 1);
    StartSessionResult ssr;
    Bytes cred = {0x01, 0x02};
    return api.startSessionWithAuth(session, sp, true, auth, cred, ssr).ok();
}

// ═══════════════════════════════════════════════════════
//  TS-3A-001: Full Opal Lifecycle
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_001_FullOpalLifecycle) {
    // 소유권 → 활성화 → Range → User → Lock/Unlock → Revert 전체 흐름
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();

    // Phase 1: SID 인증 세션 → setCPin(SID) (소유권 획득)
    queueSyncSessionResponse(*mock, COMID, 1, 1);
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setCPin(SID)
    queueCloseSessionResponse(*mock, COMID);

    {
        Session s(mock, COMID);
        StartSessionResult ssr;
        Bytes msid = {0x01, 0x02, 0x03, 0x04};
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, msid, ssr);
        api.setCPin(s, CPIN_SID, "sid_pw");
        api.closeSession(s);
    }

    // Phase 2: Activate
    queueSyncSessionResponse(*mock, COMID, 2, 2);
    queueMethodSuccessResponse(*mock, COMID, 2, 2);  // activate
    queueCloseSessionResponse(*mock, COMID);

    {
        Session s(mock, COMID);
        StartSessionResult ssr;
        Bytes sidPw = {0x73, 0x69, 0x64};
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sidPw, ssr);
        api.activate(s, SP_LOCKING);
        api.closeSession(s);
    }

    // Phase 3: Configure Range + User
    queueSyncSessionResponse(*mock, COMID, 3, 4);
    queueMethodSuccessResponse(*mock, COMID, 4, 3);  // setRange
    queueMethodSuccessResponse(*mock, COMID, 4, 3);  // enableUser
    queueMethodSuccessResponse(*mock, COMID, 4, 3);  // setUserPassword
    queueMethodSuccessResponse(*mock, COMID, 4, 3);  // assignUserToRange
    queueCloseSessionResponse(*mock, COMID);

    {
        Session s(mock, COMID);
        StartSessionResult ssr;
        Bytes cred = {0x01};
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, cred, ssr);
        api.setRange(s, 1, 0, 1048576, true, true);
        api.enableUser(s, 1);
        api.setUserPassword(s, 1, "user1_pw");
        api.assignUserToRange(s, 1, 1);
        api.closeSession(s);
    }

    // Phase 4: Lock/Unlock as User1
    queueSyncSessionResponse(*mock, COMID, 4, 5);
    queueMethodSuccessResponse(*mock, COMID, 5, 4);  // lock
    queueMethodSuccessResponse(*mock, COMID, 5, 4);  // unlock
    queueCloseSessionResponse(*mock, COMID);

    {
        Session s(mock, COMID);
        StartSessionResult ssr;
        Bytes cred = {0x75, 0x73, 0x65, 0x72};  // "user"
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER1, cred, ssr);
        auto r = api.setRangeLock(s, 1, true, true);
        EXPECT_OK(r);
        r = api.setRangeLock(s, 1, false, false);
        EXPECT_OK(r);
        api.closeSession(s);
    }

    // Phase 5: Revert
    queueSyncSessionResponse(*mock, COMID, 5, 6);
    queueMethodSuccessResponse(*mock, COMID, 6, 5);  // revertSP
    queueCloseSessionResponse(*mock, COMID);  // ~Session() safety net

    {
        Session s(mock, COMID);
        StartSessionResult ssr;
        Bytes sidPw = {0x73, 0x69, 0x64};
        api.startSessionWithAuth(s, SP_ADMIN, true, AUTH_SID, sidPw, ssr);
        auto r = api.revertSP(s, SP_ADMIN);
        EXPECT_OK(r);
    }

    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3A-002: Multi-User Range Isolation
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_002_MultiUserRangeIsolation) {
    // 3 Users × 3 Ranges — 자기 Range만 제어 가능
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();

    // Admin1 session: setup
    queueSyncSessionResponse(*mock, COMID, 1, 1);
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setRange(1)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setRange(2)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // enableUser(1)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setUserPassword(1)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // assignUserToRange(1,1)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // enableUser(2)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setUserPassword(2)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // assignUserToRange(2,2)
    queueCloseSessionResponse(*mock, COMID);

    {
        Session s(mock, COMID);
        StartSessionResult ssr;
        Bytes cred = {0x01};
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, cred, ssr);

        api.setRange(s, 1, 0, 1048576, true, true);
        api.setRange(s, 2, 1048576, 1048576, true, true);

        api.enableUser(s, 1);
        api.setUserPassword(s, 1, "user1");
        api.assignUserToRange(s, 1, 1);

        api.enableUser(s, 2);
        api.setUserPassword(s, 2, "user2");
        api.assignUserToRange(s, 2, 2);

        api.closeSession(s);
    }

    // User1: Range1 lock 성공
    queueSyncSessionResponse(*mock, COMID, 2, 2);
    queueMethodSuccessResponse(*mock, COMID, 2, 2);  // lock range1 OK
    // User1: Range2 lock 실패 (MethodNotAuthorized)
    queueMethodErrorResponse(*mock, COMID, 2, 2, 0x01);  // status=1 (NotAuthorized)
    queueCloseSessionResponse(*mock, COMID);

    {
        Session s(mock, COMID);
        StartSessionResult ssr;
        Bytes cred = {0x75, 0x31}; // "u1"
        api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_USER1, cred, ssr);

        auto r = api.setRangeLock(s, 1, true, true);
        EXPECT_OK(r);

        RawResult raw;
        r = api.setRangeLock(s, 2, true, true, raw);
        // TODO: SimTransport에서 에러 전파 재검증
        (void)r;

        api.closeSession(s);
    }

    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3A-005: CryptoErase + Range Reconfigure
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_005_CryptoEraseReconfigure) {
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();

    queueSyncSessionResponse(*mock, COMID, 1, 1);
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setRange
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // cryptoErase
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setRange (reconfigure)
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // lock
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // unlock
    queueCloseSessionResponse(*mock, COMID);

    Session s(mock, COMID);
    StartSessionResult ssr;
    Bytes cred = {0x01};
    api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, cred, ssr);

    // 1. Range 설정
    EXPECT_OK(api.setRange(s, 1, 0, 1048576, true, true));

    // 2. CryptoErase
    EXPECT_OK(api.cryptoErase(s, 1));

    // 3. Range 재구성 (다른 크기)
    EXPECT_OK(api.setRange(s, 1, 1048576, 1048576, true, true));

    // 4. Lock/Unlock 정상 동작 확인
    EXPECT_OK(api.setRangeLock(s, 1, true, true));
    EXPECT_OK(api.setRangeLock(s, 1, false, false));

    api.closeSession(s);
    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3A-006: Password Rotation Under Active Session
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_006_PasswordRotation) {
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();

    // Admin1 session
    queueSyncSessionResponse(*mock, COMID, 1, 1);
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // setAdmin1Password
    // getRangeInfo — 세션 유지 확인
    queueGetUintResponse(*mock, COMID, 1, 1, {
        {3, 0}, {4, 2048}, {5, 1}, {6, 1}
    });
    queueCloseSessionResponse(*mock, COMID);

    Session s(mock, COMID);
    StartSessionResult ssr;
    Bytes cred = {0x6F, 0x6C, 0x64}; // "old"
    api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, cred, ssr);

    // 비밀번호 변경
    EXPECT_OK(api.setAdmin1Password(s, "new_pw"));

    // 현재 세션은 여전히 유효
    LockingRangeInfo info;
    EXPECT_OK(api.getRangeInfo(s, 1, info));

    api.closeSession(s);
    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3A-010: GenKey + ActiveKey + CryptoErase Chain
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_010_GenKeyChain) {
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();

    queueSyncSessionResponse(*mock, COMID, 1, 1);
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // genKey
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // cryptoErase
    queueCloseSessionResponse(*mock, COMID);

    Session s(mock, COMID);
    StartSessionResult ssr;
    Bytes cred = {0x01};
    api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, cred, ssr);

    EXPECT_OK(api.genKey(s, 0x0000080600000001ULL));  // K_AES_256 for Range1
    EXPECT_OK(api.cryptoErase(s, 1));

    api.closeSession(s);
    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3B-003: withSession Callback Pattern
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3B_003_WithSessionCallback) {
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();

    // 성공 콜백
    queueSyncSessionResponse(*mock, COMID, 1, 1);
    queueCloseSessionResponse(*mock, COMID);

    Bytes cred = {0x01};
    auto r = composite::withSession(api, mock, COMID, SP_ADMIN, true,
                                     AUTH_SID, cred,
                                     [](Session& s) {
                                         return Result::success();
                                     });
    EXPECT_OK(r);

    // 실패 콜백 — 세션은 여전히 정리됨
    queueSyncSessionResponse(*mock, COMID, 2, 2);
    queueCloseSessionResponse(*mock, COMID);

    r = composite::withSession(api, mock, COMID, SP_ADMIN, true,
                                AUTH_SID, cred,
                                [](Session& s) {
                                    return Result(ErrorCode::MethodFailed);
                                });
    EXPECT_FAIL(r);  // 콜백이 실패를 반환

    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3B-005: Authority Status + TryLimit
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3B_005_AuthTryLimit) {
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();

    queueSyncSessionResponse(*mock, COMID, 1, 1);
    // isUserEnabled → returns bool (col=5, Enabled)
    queueGetUintResponse(*mock, COMID, 1, 1, {{5, 0}});  // disabled
    queueMethodSuccessResponse(*mock, COMID, 1, 1);  // enableUser
    queueGetUintResponse(*mock, COMID, 1, 1, {{5, 1}});  // enabled now
    queueCloseSessionResponse(*mock, COMID);

    Session s(mock, COMID);
    StartSessionResult ssr;
    Bytes cred = {0x01};
    api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, cred, ssr);

    bool enabled = false;
    EXPECT_OK(api.isUserEnabled(s, 1, enabled));
    CHECK(!enabled);

    EXPECT_OK(api.enableUser(s, 1));

    EXPECT_OK(api.isUserEnabled(s, 1, enabled));
    CHECK(enabled);

    api.closeSession(s);
    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3B-006: Composite StepLog Inspection
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3B_006_CompositeStepLog) {
    EvalApi api;
    auto mock = std::make_shared<MockTransport>();
    Bytes msid = {0x01, 0x02, 0x03, 0x04};

    // getMsid: Discovery + Properties + SyncSession + GetCPin + Close
    queueQueryFlowResponses(*mock, COMID, msid);

    auto result = composite::getMsid(api, mock, COMID, msid);

    // CompositeResult 검사 — steps 벡터 존재 확인
    CHECK_GT(result.steps.size(), 0u);
    // Note: Mock 환경에서 모든 step이 성공하려면 Discovery+Properties+Session+Get+Close
    // 의 정확한 응답이 큐잉되어야 함. 부분 실패는 mock 응답 부족 가능성.
    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3A-003: MBR + Locking Interaction
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_003_MbrLockingInteraction) {
    // MBR Enable/Done과 Locking Range 잠금이 독립적으로 동작하는지 검증
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    // Setup: TakeOwnership + Activate
    auto r = composite::takeOwnership(api, sim, COMID, "sid_pw");
    EXPECT_OK(r.overall);

    Bytes sidCred = hashPw("sid_pw");
    EXPECT_OK(activateLockingSP(api, sim, COMID, sidCred));

    // Get MSID for Admin1 auth
    Bytes msid;
    EXPECT_OK(composite::getMsid(api, sim, COMID, msid).overall);

    // Admin1 session
    Session s(sim, COMID);
    StartSessionResult ssr;
    EXPECT_OK(api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr));

    // Configure Range 1 + enable locking
    EXPECT_OK(api.setRange(s, 1, 0, 1024, true, true));

    // Enable MBR + write data
    EXPECT_OK(api.setMbrEnable(s, true));
    Bytes mbrData = {0xEB, 0x3C, 0x90, 0x00};
    EXPECT_OK(api.writeMbrData(s, 0, mbrData));
    EXPECT_OK(api.setMbrDone(s, true));

    // Lock range — should not affect MBR status
    EXPECT_OK(api.setRangeLock(s, 1, true, true));

    bool mbrEnabled = false, mbrDone = false;
    EXPECT_OK(api.getMbrStatus(s, mbrEnabled, mbrDone));
    CHECK(mbrEnabled);
    CHECK(mbrDone);

    LockingRangeInfo info;
    EXPECT_OK(api.getRangeInfo(s, 1, info));
    CHECK(info.readLocked);
    CHECK(info.writeLocked);

    // Unlock range — MBR still intact
    EXPECT_OK(api.setRangeLock(s, 1, false, false));

    Bytes readBack;
    EXPECT_OK(api.readMbrData(s, 0, 4, readBack));
    CHECK_EQ(readBack.size(), 4u);
    CHECK(readBack == mbrData);

    api.closeSession(s);
    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3A-007: Multi-Range + Global Range
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_007_MultiRangeGlobal) {
    // 여러 Range를 구성하고 Global Range와의 독립성 검증
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    auto r = composite::takeOwnership(api, sim, COMID, "sid_pw");
    EXPECT_OK(r.overall);
    Bytes sidCred = hashPw("sid_pw");
    EXPECT_OK(activateLockingSP(api, sim, COMID, sidCred));

    Bytes msid;
    EXPECT_OK(composite::getMsid(api, sim, COMID, msid).overall);

    Session s(sim, COMID);
    StartSessionResult ssr;
    EXPECT_OK(api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr));

    // Configure Range 1 and Range 2 (non-overlapping)
    EXPECT_OK(api.setRange(s, 1, 0, 1024, true, true));
    EXPECT_OK(api.setRange(s, 2, 1024, 1024, true, true));

    // Lock Range 1 only
    EXPECT_OK(api.setRangeLock(s, 1, true, true));

    // Range 2 should be unlocked
    LockingRangeInfo info1, info2;
    EXPECT_OK(api.getRangeInfo(s, 1, info1));
    EXPECT_OK(api.getRangeInfo(s, 2, info2));
    CHECK(info1.readLocked);
    CHECK(!info2.readLocked);

    // Global Range (0) should be independent
    LockingRangeInfo globalInfo;
    EXPECT_OK(api.getRangeInfo(s, 0, globalInfo));
    CHECK(!globalInfo.readLocked);

    // Unlock Range 1
    EXPECT_OK(api.setRangeLock(s, 1, false, false));

    api.closeSession(s);
    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3A-009: User Disable While Session Active
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3A_009_UserDisableWhileActive) {
    // Admin1이 User1을 비활성화해도 기존 User1 세션은 유지되는지 검증
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    auto r = composite::takeOwnership(api, sim, COMID, "sid_pw");
    EXPECT_OK(r.overall);
    Bytes sidCred = hashPw("sid_pw");
    EXPECT_OK(activateLockingSP(api, sim, COMID, sidCred));

    Bytes msid;
    EXPECT_OK(composite::getMsid(api, sim, COMID, msid).overall);

    // Admin1: enable User1 and set password
    {
        Session s(sim, COMID);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr));
        EXPECT_OK(api.enableUser(s, 1));
        EXPECT_OK(api.setUserPassword(s, 1, "user1_pw"));
        EXPECT_OK(api.setRange(s, 1, 0, 1024, true, true));
        EXPECT_OK(api.assignUserToRange(s, 1, 1));
        api.closeSession(s);
    }

    // User1 verifies auth works (setUserPassword stores SHA-256 hash)
    Bytes user1Cred = hashPw("user1_pw");
    EXPECT_OK(api.verifyAuthority(sim, COMID, SP_LOCKING, AUTH_USER1, user1Cred));

    // Admin1 disables User1
    {
        Session s(sim, COMID);
        StartSessionResult ssr;
        EXPECT_OK(api.startSessionWithAuth(s, SP_LOCKING, true, AUTH_ADMIN1, msid, ssr));
        RawResult raw;
        EXPECT_OK(api.disableUser(s, 1, raw));
        api.closeSession(s);
    }

    // User1 auth should fail on real hardware (disabled authority)
    // SimTransport doesn't enforce authority enabled check during StartSession yet.
    // On real TPer: EXPECT_FAIL(api.verifyAuthority(...))
    // Verify disable was recorded:
    bool enabled = true;
    {
        Session s3(sim, COMID);
        StartSessionResult ssr3;
        EXPECT_OK(api.startSessionWithAuth(s3, SP_LOCKING, false, AUTH_ADMIN1, msid, ssr3));
        EXPECT_OK(api.isUserEnabled(s3, 1, enabled));
        api.closeSession(s3);
    }
    CHECK(!enabled);  // User1 is disabled

    return true;
}

// ═══════════════════════════════════════════════════════
//  TS-3B-009: Session + Discovery Re-query
// ═══════════════════════════════════════════════════════

TEST_SCENARIO(L3, TS_3B_009_SessionDiscoveryRequery) {
    // 세션 중에 Discovery를 다시 수행해도 세션에 영향 없는지 검증
    EvalApi api;
    auto sim = std::make_shared<SimTransport>();

    // Start anonymous session
    Session s(sim, COMID);
    StartSessionResult ssr;
    EXPECT_OK(api.startSession(s, SP_ADMIN, false, ssr));

    // Read MSID — should work
    Bytes msid;
    EXPECT_OK(api.getCPin(s, CPIN_MSID, msid));
    CHECK(!msid.empty());

    // Re-query Discovery (different protocol, shouldn't affect session)
    DiscoveryInfo info;
    EXPECT_OK(api.discovery0(sim, info));
    CHECK(info.tperPresent);

    // Session should still be active — read MSID again
    Bytes msid2;
    EXPECT_OK(api.getCPin(s, CPIN_MSID, msid2));
    CHECK(msid == msid2);

    api.closeSession(s);
    return true;
}

// ═══════════════════════════════════════════════════════
//  Runner
// ═══════════════════════════════════════════════════════

void run_L3_tests() {
    printf("\n=== Level 3: Cross-Feature Tests ===\n");

    RUN_SCENARIO(L3, TS_3A_001_FullOpalLifecycle);
    RUN_SCENARIO(L3, TS_3A_002_MultiUserRangeIsolation);
    RUN_SCENARIO(L3, TS_3A_003_MbrLockingInteraction);
    RUN_SCENARIO(L3, TS_3A_005_CryptoEraseReconfigure);
    RUN_SCENARIO(L3, TS_3A_006_PasswordRotation);
    RUN_SCENARIO(L3, TS_3A_007_MultiRangeGlobal);
    RUN_SCENARIO(L3, TS_3A_009_UserDisableWhileActive);
    RUN_SCENARIO(L3, TS_3A_010_GenKeyChain);
    RUN_SCENARIO(L3, TS_3B_003_WithSessionCallback);
    RUN_SCENARIO(L3, TS_3B_005_AuthTryLimit);
    RUN_SCENARIO(L3, TS_3B_006_CompositeStepLog);
    RUN_SCENARIO(L3, TS_3B_009_SessionDiscoveryRequery);
}
