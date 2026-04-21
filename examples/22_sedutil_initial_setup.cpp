/// @file 21_sedutil_initial_setup.cpp
/// @brief sedutil-cli --initialSetup 와 완전히 동일한 순서로 드라이브를 설정
///
/// sedutil-cli 의 `DtaDevOpal::initialSetup` 은 아래 5개의 하위 연산을 조합:
///
///   A. takeOwnership(newPw)
///      A1. StartSession(AdminSP, anon, read)
///      A2. Get(C_PIN_MSID, col=PIN)
///      A3. CloseSession
///      A4. StartSession(AdminSP, SID + MSID)
///      A5. Set(C_PIN_SID, PIN=newPw)
///      A6. CloseSession
///
///   B. activateLockingSP(newPw)
///      B1. StartSession(AdminSP, SID + newPw)
///      B2. Activate(LockingSP)
///      B3. CloseSession
///
///   C. configureLockingRange(0, DISABLELOCKING, newPw)
///      C1. StartSession(LockingSP, Admin1 + newPw)
///      C2. Set(LockingRange.Global, RLE=0, WLE=0)
///      C3. CloseSession
///
///   D. setLockingRange(0, READWRITE, newPw)
///      D1. StartSession(LockingSP, Admin1 + newPw)
///      D2. Set(LockingRange.Global, RL=0, WL=0)
///      D3. CloseSession
///
///   E. setMBREnable(0, newPw)
///      E1. StartSession(AdminSP, SID + newPw)
///      E2. Set(MBRControl, Enable=0)
///      E3. CloseSession
///
/// 본 예제는 각 sub-op 를 libsed EvalApi 의 개별 호출로 그대로 옮긴 것이며,
/// 참조로는 `tools/sed_compare/t1_initial_setup.cpp` 의 순서를 따릅니다.
///
/// WARNING: 드라이브를 공장 상태에서 Locking SP 활성화된 상태로 전환합니다.
/// 복구하려면 PSID Revert(`12_factory_reset --psid`) 가 필요합니다.
///
/// Usage: ./21_sedutil_initial_setup /dev/nvmeX [--password PW] [--force]

#include "example_common.h"

static std::string NEW_SID_PW;

// ── 작은 유틸 ───────────────────────────────────────────

static Session makeSession(std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           const PropertiesResult& props) {
    Session s(transport, comId);
    s.setMaxComPacketSize(props.tperMaxComPacketSize);
    return s;
}

// ── A. takeOwnership ───────────────────────────────────

static bool opA_takeOwnership(std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const PropertiesResult& props,
                              Bytes& msidOut) {
    scenario(1, "A. takeOwnership(newPw)");
    EvalApi api;

    // A1. StartSession(AdminSP, anon, read)
    Session anon = makeSession(transport, comId, props);
    StartSessionResult ssr;
    auto r = api.startSession(anon, uid::SP_ADMIN, false, ssr);
    step(1, "[A1] StartSession(AdminSP, anon, read)", r);
    if (r.failed()) return false;

    // A2. Get(C_PIN_MSID, col=PIN)
    r = api.getCPin(anon, uid::CPIN_MSID, msidOut);
    step(2, "[A2] Get(C_PIN_MSID, col=PIN)", r);
    if (r.failed() || msidOut.empty()) { api.closeSession(anon); return false; }
    printString("       MSID", msidOut);

    // A3. CloseSession
    r = api.closeSession(anon);
    step(3, "[A3] CloseSession", r);
    if (r.failed()) return false;

    // A4. StartSession(AdminSP, SID + MSID) — MSID 는 raw bytes(해시 X)
    Session auth = makeSession(transport, comId, props);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(auth, uid::SP_ADMIN, true,
                                 uid::AUTH_SID, msidOut, ssr2);
    step(4, "[A4] StartSession(AdminSP, SID + MSID)", r);
    if (r.failed()) return false;

    // A5. Set(C_PIN_SID, PIN=newPw) — 새 비밀번호는 pwBytes 해시
    r = api.setCPin(auth, uid::CPIN_SID, NEW_SID_PW);
    step(5, "[A5] Set(C_PIN_SID, PIN=newPw)", r);
    if (r.failed()) { api.closeSession(auth); return false; }

    // A6. CloseSession
    r = api.closeSession(auth);
    step(6, "[A6] CloseSession", r);
    return r.ok();
}

// ── B. activateLockingSP ───────────────────────────────

static bool opB_activateLockingSP(std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const PropertiesResult& props) {
    scenario(2, "B. activateLockingSP(newPw)");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pw = pwBytes(NEW_SID_PW);

    // B1. StartSession(AdminSP, SID + newPw)
    auto r = api.startSessionWithAuth(s, uid::SP_ADMIN, true,
                                      uid::AUTH_SID, pw, ssr);
    step(1, "[B1] StartSession(AdminSP, SID + newPw)", r);
    if (r.failed()) return false;

    // B2. Activate(LockingSP)
    RawResult raw;
    r = api.activate(s, uid::SP_LOCKING, raw);
    step(2, "[B2] Activate(LockingSP)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    // B3. CloseSession
    r = api.closeSession(s);
    step(3, "[B3] CloseSession", r);
    return r.ok();
}

// ── C. configureLockingRange (Global RLE=WLE=0) ────────

static bool opC_disableLocking(std::shared_ptr<ITransport> transport,
                               uint16_t comId,
                               const PropertiesResult& props) {
    scenario(3, "C. configureLockingRange(Global, DISABLELOCKING)");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pw = pwBytes(NEW_SID_PW);

    // C1. StartSession(LockingSP, Admin1 + newPw)
    auto r = api.startSessionWithAuth(s, uid::SP_LOCKING, true,
                                      uid::AUTH_ADMIN1, pw, ssr);
    step(1, "[C1] StartSession(LockingSP, Admin1 + newPw)", r);
    if (r.failed()) return false;

    // C2. Set(LockingRange.Global, RLE=0, WLE=0)
    std::vector<std::pair<uint32_t, Token>> cols = {
        { uid::col::READ_LOCK_EN,  Token::makeUint(0) },
        { uid::col::WRITE_LOCK_EN, Token::makeUint(0) },
    };
    RawResult raw;
    r = api.tableSet(s, uid::LOCKING_GLOBALRANGE, cols, raw);
    step(2, "[C2] Set(LockingRange.Global, RLE=0, WLE=0)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    // C3. CloseSession
    r = api.closeSession(s);
    step(3, "[C3] CloseSession", r);
    return r.ok();
}

// ── D. setLockingRange (Global RL=WL=0, 즉 Unlock) ────

static bool opD_unlockGlobal(std::shared_ptr<ITransport> transport,
                             uint16_t comId,
                             const PropertiesResult& props) {
    scenario(4, "D. setLockingRange(Global, READWRITE)");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pw = pwBytes(NEW_SID_PW);

    // D1. StartSession(LockingSP, Admin1 + newPw)
    auto r = api.startSessionWithAuth(s, uid::SP_LOCKING, true,
                                      uid::AUTH_ADMIN1, pw, ssr);
    step(1, "[D1] StartSession(LockingSP, Admin1 + newPw)", r);
    if (r.failed()) return false;

    // D2. Set(LockingRange.Global, RL=0, WL=0)
    std::vector<std::pair<uint32_t, Token>> cols = {
        { uid::col::READ_LOCKED,  Token::makeUint(0) },
        { uid::col::WRITE_LOCKED, Token::makeUint(0) },
    };
    RawResult raw;
    r = api.tableSet(s, uid::LOCKING_GLOBALRANGE, cols, raw);
    step(2, "[D2] Set(LockingRange.Global, RL=0, WL=0)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    // D3. CloseSession
    r = api.closeSession(s);
    step(3, "[D3] CloseSession", r);
    return r.ok();
}

// ── E. setMBREnable(0) ────────────────────────────────

static bool opE_disableMbr(std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           const PropertiesResult& props) {
    scenario(5, "E. setMBREnable(0)");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pw = pwBytes(NEW_SID_PW);

    // E1. StartSession(AdminSP, SID + newPw)
    auto r = api.startSessionWithAuth(s, uid::SP_ADMIN, true,
                                      uid::AUTH_SID, pw, ssr);
    step(1, "[E1] StartSession(AdminSP, SID + newPw)", r);
    if (r.failed()) return false;

    // E2. Set(MBRControl, Enable=0)
    RawResult raw;
    r = api.setMbrEnable(s, false, raw);
    step(2, "[E2] Set(MBRControl, Enable=0)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    // E3. CloseSession
    r = api.closeSession(s);
    step(3, "[E3] CloseSession", r);
    return r.ok();
}

// ── main ──────────────────────────────────────────────

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "sedutil-cli --initialSetup — exact wire-sequence replica");
    if (!transport) return 1;

    NEW_SID_PW = getPassword(opts);

    banner("21: sedutil-cli --initialSetup (exact order)");
    printf("  A. takeOwnership         (2 sessions)\n");
    printf("  B. activateLockingSP     (1 session)\n");
    printf("  C. configureLockingRange (1 session, Admin1)\n");
    printf("  D. setLockingRange       (1 session, Admin1)\n");
    printf("  E. setMBREnable(0)       (1 session, SID)\n");
    printf("  => 6 sessions total, must start from factory state.\n\n");

    if (!confirmDestructive(opts,
            "run initialSetup — PSID Revert required to recover"))
        return 0;

    EvalApi api;

    // Pre: Discovery + Properties (sedutil 와 동일: Discovery → StackReset → Properties)
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed: %s\n", r.message().c_str()); return 1; }

    PropertiesResult props;
    r = api.exchangeProperties(transport, info.baseComId, props);
    if (r.failed()) { printf("Properties failed: %s\n", r.message().c_str()); return 1; }

    // A ~ E 순차 실행. 어느 단계든 실패하면 중단.
    Bytes msid;
    if (!opA_takeOwnership(transport, info.baseComId, props, msid)) return 1;
    if (!opB_activateLockingSP(transport, info.baseComId, props))   return 1;
    if (!opC_disableLocking  (transport, info.baseComId, props))    return 1;
    if (!opD_unlockGlobal    (transport, info.baseComId, props))    return 1;
    if (!opE_disableMbr      (transport, info.baseComId, props))    return 1;

    printf("\n  initialSetup completed. SID=newPw, LockingSP active,\n");
    printf("  Global range locking disabled, range unlocked, MBR shadow off.\n");
    printf("  To revert: 12_factory_reset --psid (destructive).\n");
    return 0;
}
