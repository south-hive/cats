/// @file eval_composite.cpp
/// @brief EvalApi 기반 복합(Composite) 유틸리티 구현.

#include "libsed/eval/eval_composite.h"
#include "libsed/core/uid.h"

#include <chrono>
#include <thread>

namespace libsed {
namespace eval {
namespace composite {

// ── Internal helpers ────────────────────────────────

namespace {

/// 단계를 기록하고 결과 반환
void logStep(CompositeResult& cr, const std::string& name,
             Result r, const RawResult& raw = {}) {
    cr.steps.push_back({name, r, raw});
    cr.overall = r;
}

/// 패스워드 → Bytes
Bytes toBytes(const std::string& pw) {
    return HashPassword::passwordToBytes(pw);
}

constexpr int    MAX_SPBUSY_RETRIES     = 3;
constexpr int    SPBUSY_RETRY_DELAY_MS  = 50;

/// SpBusy(St=3) 응답을 받았을 때 StackReset 후 재시도하는 데코레이터.
/// fn() 은 세션을 여는 호출(가령 `api.startSessionWithAuth(...)`)이며 Result 반환.
/// MethodSpBusy 가 아닐 경우 즉시 패스스루.
template <typename Fn>
Result withSpBusyRetry(EvalApi& api,
                        std::shared_ptr<ITransport> transport,
                        uint16_t comId,
                        Fn&& fn) {
    Result r = fn();
    for (int attempt = 1;
         attempt <= MAX_SPBUSY_RETRIES &&
             r.code() == ErrorCode::MethodSpBusy;
         ++attempt) {
        api.stackReset(transport, comId);
        std::this_thread::sleep_for(std::chrono::milliseconds(SPBUSY_RETRY_DELAY_MS));
        r = fn();
    }
    return r;
}

} // anonymous

// ════════════════════════════════════════════════════════
//  1. getMsid
// ════════════════════════════════════════════════════════

CompositeResult getMsid(EvalApi& api,
                        std::shared_ptr<ITransport> transport,
                        uint16_t comId,
                        Bytes& msid) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    // Step 1: Anonymous AdminSP session
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    logStep(cr, "StartSession(AdminSP, Anybody)", r, ssr.raw);
    if (r.failed()) return cr;

    // Step 2: Get C_PIN_MSID
    RawResult raw;
    r = api.getCPin(session, uid::CPIN_MSID, msid, raw);
    logStep(cr, "Get C_PIN_MSID", r, raw);

    // Step 3: Close
    api.closeSession(session);
    logStep(cr, "CloseSession", ErrorCode::Success);

    return cr;
}

// ════════════════════════════════════════════════════════
//  2. takeOwnership
// ════════════════════════════════════════════════════════

CompositeResult takeOwnership(EvalApi& api,
                              std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const std::string& newSidPw) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    // Step 1: Read MSID
    Bytes msid;
    auto sub = getMsid(api, transport, comId, msid);
    for (auto& s : sub.steps) cr.steps.push_back(s);
    if (sub.failed()) { cr.overall = sub.overall; return cr; }

    // Step 2: SID auth with MSID (SpBusy 자동 복구).
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = withSpBusyRetry(api, transport, comId, [&]() {
        return api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                         uid::AUTH_SID, msid, ssr);
    });
    logStep(cr, "StartSession(AdminSP, SID=MSID, Write)", r, ssr.raw);

    // Step 2b: NotAuthorized → 이미 소유 상태일 가능성. 호출자의 새 비번으로 재시도.
    if (r.code() == ErrorCode::MethodNotAuthorized) {
        Bytes newPin = toBytes(newSidPw);
        Session probe(transport, comId);
        StartSessionResult probeSsr;
        auto rp = withSpBusyRetry(api, transport, comId, [&]() {
            return api.startSessionWithAuth(probe, uid::SP_ADMIN, true,
                                             uid::AUTH_SID, newPin, probeSsr);
        });
        if (rp.ok()) {
            // 새 비번으로 인증 성공 → 이미 동일 비번으로 소유됨. 멱등 no-op.
            api.closeSession(probe);
            logStep(cr, "Already owned (idempotent: new password matches)",
                    ErrorCode::Success, probeSsr.raw);
            cr.overall = ErrorCode::Success;
            return cr;
        }
        // 새 비번도 거절 → 다른 비번으로 이미 소유됨.
        logStep(cr, "Already owned with different credential",
                ErrorCode::AlreadyOwnedDifferentCredential, probeSsr.raw);
        return cr;
    }
    if (r.failed()) return cr;

    // Step 3: Set C_PIN_SID
    RawResult raw;
    Bytes newPin = toBytes(newSidPw);
    r = api.setCPin(session, uid::CPIN_SID, newPin, raw);
    logStep(cr, "SetCPin(C_PIN_SID)", r, raw);

    // Step 4: Close
    api.closeSession(session);
    logStep(cr, "CloseSession", ErrorCode::Success);

    return cr;
}

// ════════════════════════════════════════════════════════
//  3. revertToFactory
// ════════════════════════════════════════════════════════

CompositeResult revertToFactory(EvalApi& api,
                                std::shared_ptr<ITransport> transport,
                                uint16_t comId,
                                const std::string& sidPw,
                                const std::string& psidPw) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    // Try SID auth first (SpBusy 자동 복구)
    Bytes sidCred = toBytes(sidPw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = withSpBusyRetry(api, transport, comId, [&]() {
        return api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                         uid::AUTH_SID, sidCred, ssr);
    });
    logStep(cr, "StartSession(AdminSP, SID, Write)", r, ssr.raw);

    if (r.ok()) {
        // AdminSP.Revert() — sedutil-compat: SID 권한이 호출 가능한 메서드
        // (RevertSP 0x0011 은 AdminSP 에서 SID 로 호출 시 NotAuthorized 반환)
        RawResult raw;
        r = api.revert(session, uid::SP_ADMIN, raw);
        logStep(cr, "Revert(AdminSP)", r, raw);
        // Session auto-closed by TPer, do NOT call closeSession
        return cr;
    }

    // SID failed — try PSID fallback
    if (psidPw.empty()) {
        logStep(cr, "PSID fallback skipped (no PSID provided)", ErrorCode::AuthFailed);
        return cr;
    }

    Bytes psidCred = toBytes(psidPw);
    Session psidSession(transport, comId);
    r = api.startSessionWithAuth(psidSession, uid::SP_ADMIN, true,
                                  uid::AUTH_PSID, psidCred, ssr);
    logStep(cr, "StartSession(AdminSP, PSID, Write)", r, ssr.raw);
    if (r.failed()) return cr;

    RawResult raw;
    r = api.psidRevert(psidSession, raw);
    logStep(cr, "PsidRevert", r, raw);
    // Session auto-closed by TPer

    return cr;
}

// ════════════════════════════════════════════════════════
//  4. activateAndSetup
// ════════════════════════════════════════════════════════

CompositeResult activateAndSetup(EvalApi& api,
                                 std::shared_ptr<ITransport> transport,
                                 uint16_t comId,
                                 const std::string& sidPw,
                                 const std::string& admin1Pw,
                                 const std::string& user1Pw) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    Bytes sidCred = toBytes(sidPw);
    RawResult raw;

    // Step 1: SID auth → AdminSP session
    {
        Session session(transport, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                           uid::AUTH_SID, sidCred, ssr);
        logStep(cr, "StartSession(AdminSP, SID, Write)", r, ssr.raw);
        if (r.failed()) return cr;

        // Step 2: Check lifecycle and activate if needed
        uint8_t lifecycle = 0;
        r = api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle, raw);
        logStep(cr, "GetSpLifecycle(LockingSP)", r, raw);

        if (r.ok() && lifecycle == 0x08) {  // Manufactured-Inactive
            r = api.activate(session, uid::SP_LOCKING, raw);
            logStep(cr, "Activate(SP_LOCKING)", r, raw);
            if (r.failed()) { api.closeSession(session); return cr; }
        } else {
            logStep(cr, "Activate (already active)", ErrorCode::Success);
        }

        api.closeSession(session);
        logStep(cr, "CloseSession(AdminSP)", ErrorCode::Success);
    }

    // Step 3: Admin1 auth → LockingSP session
    {
        // Try MSID first for fresh admin1 auth
        Bytes msid;
        auto msidResult = getMsid(api, transport, comId, msid);

        Session session(transport, comId);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                           uid::AUTH_ADMIN1, msid, ssr);
        if (r.failed()) {
            // MSID didn't work, try admin1Pw
            Bytes admin1Cred = toBytes(admin1Pw);
            r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                          uid::AUTH_ADMIN1, admin1Cred, ssr);
        }
        logStep(cr, "StartSession(LockingSP, Admin1, Write)", r, ssr.raw);
        if (r.failed()) return cr;

        // Step 4: Set Admin1 password
        Bytes admin1Cred = toBytes(admin1Pw);
        r = api.setAdmin1Password(session, admin1Cred, raw);
        logStep(cr, "SetAdmin1Password", r, raw);

        // Step 5: Enable User1
        r = api.enableUser(session, 1, raw);
        logStep(cr, "EnableUser(1)", r, raw);

        // Step 6: Set User1 password
        Bytes user1Pin = toBytes(user1Pw);
        r = api.setCPin(session, uid::CPIN_USER1, user1Pin, raw);
        logStep(cr, "SetCPin(C_PIN_USER1)", r, raw);

        // Step 7-8: Add User1 to Range1 ACEs
        r = api.addAuthorityToAce(session,
                uid::makeAceLockingRangeSetRdLocked(1).toUint64(),
                uid::AUTH_USER1, raw);
        logStep(cr, "AddAuthorityToAce(Range1 RdLock, User1)", r, raw);

        r = api.addAuthorityToAce(session,
                uid::makeAceLockingRangeSetWrLocked(1).toUint64(),
                uid::AUTH_USER1, raw);
        logStep(cr, "AddAuthorityToAce(Range1 WrLock, User1)", r, raw);

        api.closeSession(session);
        logStep(cr, "CloseSession(LockingSP)", ErrorCode::Success);
    }

    return cr;
}

// ════════════════════════════════════════════════════════
//  5. withSession
// ════════════════════════════════════════════════════════

Result withSession(EvalApi& api,
                   std::shared_ptr<ITransport> transport,
                   uint16_t comId,
                   uint64_t spUid,
                   bool write,
                   uint64_t authUid,
                   const Bytes& credential,
                   std::function<Result(Session&)> fn) {
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, spUid, write,
                                       authUid, credential, ssr);
    if (r.failed()) return r;

    r = fn(session);

    // Always try to close — safe even if TPer already closed
    api.closeSession(session);

    return r;
}

Result withSession(EvalApi& api,
                   std::shared_ptr<ITransport> transport,
                   uint16_t comId,
                   uint64_t spUid,
                   bool write,
                   uint64_t authUid,
                   const std::string& password,
                   std::function<Result(Session&)> fn) {
    return withSession(api, transport, comId, spUid, write,
                       authUid, toBytes(password), fn);
}

Result withAnonymousSession(EvalApi& api,
                            std::shared_ptr<ITransport> transport,
                            uint16_t comId,
                            uint64_t spUid,
                            std::function<Result(Session&)> fn) {
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSession(session, spUid, false, ssr);
    if (r.failed()) return r;

    r = fn(session);
    api.closeSession(session);
    return r;
}

// ════════════════════════════════════════════════════════
//  6. psidRevertAndVerify
// ════════════════════════════════════════════════════════

CompositeResult psidRevertAndVerify(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    const std::string& psidPw) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    // Step 1: PSID auth
    Bytes psidCred = toBytes(psidPw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                       uid::AUTH_PSID, psidCred, ssr);
    logStep(cr, "StartSession(AdminSP, PSID, Write)", r, ssr.raw);
    if (r.failed()) return cr;

    // Step 2: PsidRevert
    RawResult raw;
    r = api.psidRevert(session, raw);
    logStep(cr, "PsidRevert", r, raw);
    if (r.failed()) return cr;
    // Session auto-closed by TPer

    // Step 3: Properties re-exchange (stack was reset by revert)
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    logStep(cr, "ExchangeProperties (post-revert)", r);

    // Step 4: Read MSID (post-revert)
    Bytes msid;
    auto msidResult = getMsid(api, transport, comId, msid);
    for (auto& s : msidResult.steps) cr.steps.push_back(s);
    if (msidResult.failed()) { cr.overall = msidResult.overall; return cr; }

    // Step 5: Verify SID == MSID
    r = api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, msid);
    logStep(cr, "VerifyAuthority(SID == MSID)", r);

    return cr;
}

// ════════════════════════════════════════════════════════
//  7. configureRangeAndLock
// ════════════════════════════════════════════════════════

CompositeResult configureRangeAndLock(EvalApi& api,
                                      std::shared_ptr<ITransport> transport,
                                      uint16_t comId,
                                      const std::string& admin1Pw,
                                      uint32_t rangeId,
                                      uint64_t start,
                                      uint64_t length) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    Bytes admin1Cred = toBytes(admin1Pw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    logStep(cr, "StartSession(LockingSP, Admin1, Write)", r, ssr.raw);
    if (r.failed()) return cr;

    RawResult raw;

    // Step 2: Configure range
    r = api.setRange(session, rangeId, start, length, true, true, raw);
    logStep(cr, "SetRange (RLE+WLE)", r, raw);

    // Step 3: Lock
    r = api.setRangeLock(session, rangeId, true, true, raw);
    logStep(cr, "SetRangeLock (locked)", r, raw);

    // Step 4: Unlock
    r = api.setRangeLock(session, rangeId, false, false, raw);
    logStep(cr, "SetRangeLock (unlocked)", r, raw);

    // Step 5: Verify
    LockingInfo li;
    r = api.getLockingInfo(session, rangeId, li, raw);
    logStep(cr, "GetLockingInfo (verify)", r, raw);

    api.closeSession(session);
    logStep(cr, "CloseSession", ErrorCode::Success);

    return cr;
}

// ════════════════════════════════════════════════════════
//  8. mbrWriteAndVerify
// ════════════════════════════════════════════════════════

CompositeResult mbrWriteAndVerify(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& admin1Pw,
                                   const Bytes& data) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    Bytes admin1Cred = toBytes(admin1Pw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    logStep(cr, "StartSession(LockingSP, Admin1, Write)", r, ssr.raw);
    if (r.failed()) return cr;

    RawResult raw;

    // Step 2: Enable MBR
    r = api.setMbrEnable(session, true, raw);
    logStep(cr, "SetMbrEnable(true)", r, raw);

    // Step 3: Write MBR data
    r = api.writeMbrData(session, 0, data, raw);
    logStep(cr, "WriteMbrData", r, raw);

    // Step 4: Read back
    Bytes readData;
    r = api.readMbrData(session, 0, (uint32_t)data.size(), readData, raw);
    logStep(cr, "ReadMbrData", r, raw);

    // Step 5: Compare
    if (r.ok() && readData != data) {
        logStep(cr, "Compare MBR data", ErrorCode::InvalidArgument);
    } else if (r.ok()) {
        logStep(cr, "Compare MBR data", ErrorCode::Success);
    }

    // Step 6: MBRDone
    r = api.setMbrDone(session, true, raw);
    logStep(cr, "SetMbrDone(true)", r, raw);

    api.closeSession(session);
    logStep(cr, "CloseSession", ErrorCode::Success);

    return cr;
}

// ════════════════════════════════════════════════════════
//  9. dataStoreRoundTrip
// ════════════════════════════════════════════════════════

CompositeResult dataStoreRoundTrip(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    const std::string& admin1Pw,
                                    uint32_t offset,
                                    const Bytes& data) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    Bytes admin1Cred = toBytes(admin1Pw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    logStep(cr, "StartSession(LockingSP, Admin1, Write)", r, ssr.raw);
    if (r.failed()) return cr;

    RawResult raw;

    // Step 2: Write
    r = api.tcgWriteDataStore(session, offset, data, raw);
    logStep(cr, "TcgWriteDataStore", r, raw);

    // Step 3: Read
    DataOpResult readResult;
    r = api.tcgReadDataStore(session, offset, (uint32_t)data.size(), readResult);
    logStep(cr, "TcgReadDataStore", r, readResult.raw);

    // Step 4: Compare
    DataOpResult cmpResult;
    r = api.tcgCompare(session, uid::TABLE_DATASTORE, offset, data, cmpResult);
    logStep(cr, "TcgCompare", r, cmpResult.raw);
    if (r.ok() && !cmpResult.compareMatch) {
        logStep(cr, "Compare match check", ErrorCode::InvalidArgument);
    }

    api.closeSession(session);
    logStep(cr, "CloseSession", ErrorCode::Success);

    return cr;
}

// ════════════════════════════════════════════════════════
//  10. blockSidAndVerify
// ════════════════════════════════════════════════════════

CompositeResult blockSidAndVerify(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& sidPw) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    // Step 1: Set Block SID (NVMe Feature 0x0C)
    auto r = EvalApi::nvmeSetFeature(transport, 0x0C, 0, 0x01);
    logStep(cr, "NVMe SetFeature BlockSID (CDW11=0x01)", r);
    if (r.failed()) return cr;

    // Step 2: Verify SID auth is blocked
    Bytes sidCred = toBytes(sidPw);
    Session session(transport, comId);
    StartSessionResult ssr;
    r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, sidCred, ssr);
    if (r.ok()) {
        // SID succeeded — Block SID didn't work
        api.closeSession(session);
        logStep(cr, "SID auth (expect blocked)", ErrorCode::InvalidArgument);
    } else {
        // SID blocked as expected
        logStep(cr, "SID auth blocked (expected)", ErrorCode::Success);
    }

    // Step 3: Clear Block SID
    r = EvalApi::nvmeSetFeature(transport, 0x0C, 0, 0x00);
    logStep(cr, "NVMe SetFeature BlockSID (clear)", r);

    return cr;
}

// ════════════════════════════════════════════════════════
//  11. cryptoEraseAndVerify
// ════════════════════════════════════════════════════════

CompositeResult cryptoEraseAndVerify(EvalApi& api,
                                      std::shared_ptr<ITransport> transport,
                                      uint16_t comId,
                                      const std::string& admin1Pw,
                                      uint32_t rangeId) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    Bytes admin1Cred = toBytes(admin1Pw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    logStep(cr, "StartSession(LockingSP, Admin1, Write)", r, ssr.raw);
    if (r.failed()) return cr;

    RawResult raw;

    // Step 2: Get ActiveKey before erase
    Uid keyBefore;
    r = api.getActiveKey(session, rangeId, keyBefore, raw);
    logStep(cr, "GetActiveKey (before)", r, raw);

    // Step 3: CryptoErase
    r = api.cryptoErase(session, rangeId, raw);
    logStep(cr, "CryptoErase", r, raw);

    // Step 4: Get ActiveKey after erase
    Uid keyAfter;
    r = api.getActiveKey(session, rangeId, keyAfter, raw);
    logStep(cr, "GetActiveKey (after)", r, raw);

    // Step 5: Verify key changed
    if (r.ok()) {
        bool changed = (keyBefore.toUint64() != keyAfter.toUint64());
        logStep(cr, "Key changed?",
                changed ? ErrorCode::Success : ErrorCode::InvalidArgument);
    }

    api.closeSession(session);
    logStep(cr, "CloseSession", ErrorCode::Success);

    return cr;
}

// ════════════════════════════════════════════════════════
//  12. revertLockingSP
// ════════════════════════════════════════════════════════

CompositeResult revertLockingSP(EvalApi& api,
                                std::shared_ptr<ITransport> transport,
                                uint16_t comId,
                                const std::string& admin1Pw) {
    CompositeResult cr;
    cr.overall = ErrorCode::Success;

    Bytes admin1Cred = toBytes(admin1Pw);
    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    logStep(cr, "StartSession(LockingSP, Admin1, Write)", r, ssr.raw);
    if (r.failed()) return cr;

    RawResult raw;
    r = api.revertSP(session, uid::SP_LOCKING, raw);
    logStep(cr, "RevertSP(SP_LOCKING)", r, raw);
    // Session auto-closed by TPer — do NOT call closeSession

    return cr;
}

} // namespace composite
} // namespace eval
} // namespace libsed
