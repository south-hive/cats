/// @file 23_sedutil_compat_setup.cpp
/// @brief sedutil-cli (DTA fork) 와 byte-identical 한 takeOwnership.
///
/// 22 (`22_sedutil_initial_setup`) 과 동일한 시퀀스를 따르되, password
/// 해시를 cats native (SHA-256) 가 아니라 sedutil-compatible
/// PBKDF2-HMAC-SHA1 (drive serial salt, 75000 iter, 32B output) 로 계산.
///
/// 결과: cats 의 wire bytes 가 sedutil-cli 와 byte-for-byte 동일해짐.
/// hardware capture 비교 (`golden_validator`) 시 mismatch 가 없어야 함.
///
/// 사용 시나리오:
///   - cats 와 sedutil 을 같은 드라이브에서 혼용해야 할 때
///   - cats 로 set 한 드라이브를 sedutil 로 auth 하거나 그 역
///   - byte-level wire compatibility 검증
///
/// WARNING:
///   드라이브를 공장 상태에서 SID 변경 + LockingSP 활성 상태로 전환합니다.
///   복구하려면 PSID Revert (`12_factory_reset --psid`) 필요.
///
/// Usage: ./23_sedutil_compat_setup /dev/nvmeX [--password PW] [--force]

#include "example_common.h"
#include <libsed/security/hash_password.h>

static std::string NEW_SID_PW;

// 22 와 동일하게 일부 펌웨어의 0x0F 회피용 post-start delay
static constexpr uint32_t POST_START_DELAY_MS = 50;

// ── 작은 유틸 ───────────────────────────────────────────

static Session makeSession(std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           const PropertiesResult& props) {
    Session s(transport, comId);
    s.setMaxComPacketSize(props.tperMaxComPacketSize);
    s.setPostStartDelay(POST_START_DELAY_MS);
    return s;
}

// ── A. takeOwnership ───────────────────────────────────

static bool opA_takeOwnership(std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const PropertiesResult& props,
                              const Bytes& driveSerial,
                              Bytes& msidOut) {
    scenario(1, "A. takeOwnership(newPw) — sedutil-compat hash");
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

    // A4. StartSession(AdminSP, SID + sedutilHash(MSID))
    //     sedutil 은 MSID 를 NUL-terminated string 으로 보고 PBKDF2 처리.
    //     따라서 raw MSID bytes 를 일단 string 으로 reinterpret 한 뒤 같은
    //     알고리즘으로 hash.
    std::string msidStr(msidOut.begin(), msidOut.end());
    Bytes msidHashed = HashPassword::sedutilHash(msidStr, driveSerial);

    Session auth = makeSession(transport, comId, props);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(auth, uid::SP_ADMIN, true,
                                 uid::AUTH_SID, msidHashed, ssr2);
    step(4, "[A4] StartSession(AdminSP, SID + PBKDF2(MSID))", r);
    if (r.failed()) return false;

    // A5. Set(C_PIN_SID, PIN = sedutilHash(newPw))
    Bytes newPin = HashPassword::sedutilHash(NEW_SID_PW, driveSerial);
    RawResult raw;
    r = api.setCPin(auth, uid::CPIN_SID, newPin, raw);
    step(5, "[A5] Set(C_PIN_SID, PIN=PBKDF2(newPw))", r);
    if (r.failed()) { api.closeSession(auth); return false; }

    // A6. CloseSession
    r = api.closeSession(auth);
    step(6, "[A6] CloseSession", r);
    return r.ok();
}

// ── B. activateLockingSP ───────────────────────────────

static bool opB_activateLockingSP(std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const PropertiesResult& props,
                                  const Bytes& driveSerial) {
    scenario(2, "B. activateLockingSP(newPw) — sedutil-compat hash");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pwHashed = HashPassword::sedutilHash(NEW_SID_PW, driveSerial);

    auto r = api.startSessionWithAuth(s, uid::SP_ADMIN, true,
                                      uid::AUTH_SID, pwHashed, ssr);
    step(1, "[B1] StartSession(AdminSP, SID + PBKDF2(newPw))", r);
    if (r.failed()) return false;

    RawResult raw;
    r = api.activate(s, uid::SP_LOCKING, raw);
    step(2, "[B2] Activate(LockingSP)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    r = api.closeSession(s);
    step(3, "[B3] CloseSession", r);
    return r.ok();
}

// ── C. configureLockingRange (Global RLE=WLE=0) ────────

static bool opC_disableLocking(std::shared_ptr<ITransport> transport,
                               uint16_t comId,
                               const PropertiesResult& props,
                               const Bytes& driveSerial) {
    scenario(3, "C. configureLockingRange(Global, DISABLELOCKING)");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pwHashed = HashPassword::sedutilHash(NEW_SID_PW, driveSerial);

    auto r = api.startSessionWithAuth(s, uid::SP_LOCKING, true,
                                      uid::AUTH_ADMIN1, pwHashed, ssr);
    step(1, "[C1] StartSession(LockingSP, Admin1 + PBKDF2(newPw))", r);
    if (r.failed()) return false;

    std::vector<std::pair<uint32_t, Token>> cols = {
        { uid::col::READ_LOCK_EN,  Token::makeUint(0) },
        { uid::col::WRITE_LOCK_EN, Token::makeUint(0) },
    };
    RawResult raw;
    r = api.tableSet(s, uid::LOCKING_GLOBALRANGE, cols, raw);
    step(2, "[C2] Set(LockingRange.Global, RLE=0, WLE=0)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    r = api.closeSession(s);
    step(3, "[C3] CloseSession", r);
    return r.ok();
}

// ── D. setLockingRange (Global RL=WL=0) ────────────────

static bool opD_unlockGlobal(std::shared_ptr<ITransport> transport,
                             uint16_t comId,
                             const PropertiesResult& props,
                             const Bytes& driveSerial) {
    scenario(4, "D. setLockingRange(Global, READWRITE)");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pwHashed = HashPassword::sedutilHash(NEW_SID_PW, driveSerial);

    auto r = api.startSessionWithAuth(s, uid::SP_LOCKING, true,
                                      uid::AUTH_ADMIN1, pwHashed, ssr);
    step(1, "[D1] StartSession(LockingSP, Admin1 + PBKDF2(newPw))", r);
    if (r.failed()) return false;

    std::vector<std::pair<uint32_t, Token>> cols = {
        { uid::col::READ_LOCKED,  Token::makeUint(0) },
        { uid::col::WRITE_LOCKED, Token::makeUint(0) },
    };
    RawResult raw;
    r = api.tableSet(s, uid::LOCKING_GLOBALRANGE, cols, raw);
    step(2, "[D2] Set(LockingRange.Global, RL=0, WL=0)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    r = api.closeSession(s);
    step(3, "[D3] CloseSession", r);
    return r.ok();
}

// ── E. setMBREnable(0) ────────────────────────────────

static bool opE_disableMbr(std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           const PropertiesResult& props,
                           const Bytes& driveSerial) {
    scenario(5, "E. setMBREnable(0)");
    EvalApi api;

    Session s = makeSession(transport, comId, props);
    StartSessionResult ssr;
    Bytes pwHashed = HashPassword::sedutilHash(NEW_SID_PW, driveSerial);

    auto r = api.startSessionWithAuth(s, uid::SP_ADMIN, true,
                                      uid::AUTH_SID, pwHashed, ssr);
    step(1, "[E1] StartSession(AdminSP, SID + PBKDF2(newPw))", r);
    if (r.failed()) return false;

    RawResult raw;
    r = api.setMbrEnable(s, false, raw);
    step(2, "[E2] Set(MBRControl, Enable=0)", r);
    if (r.failed()) { api.closeSession(s); return false; }

    r = api.closeSession(s);
    step(3, "[E3] CloseSession", r);
    return r.ok();
}

// ── main ──────────────────────────────────────────────

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "sedutil-compat initialSetup — byte-identical to sedutil-cli");
    if (!transport) return 1;

    NEW_SID_PW = getPassword(opts);

    banner("23: sedutil-compat initialSetup (PBKDF2-HMAC-SHA1)");
    printf("  hash      : PBKDF2-HMAC-SHA1(password, drive_serial, 75000, 32B)\n");
    printf("  wire form : sedutil-cli (DTA fork) 와 byte-identical\n");
    printf("\n");
    printf("  드라이브 상태 요건:\n");
    printf("    [OK]   factory 상태 (MSID 살아있음)\n");
    printf("    [OK]   sedutil 또는 본 예제(#23) 로 이미 set 된 상태\n");
    printf("    [FAIL] cats-native (SHA-256) 로 takeOwnership 된 상태\n");
    printf("           → SID auth 가 mismatch. 먼저 PSID Revert 필요.\n");
    printf("\n");
    printf("  완료 후: 같은 password 로 cats(#23) 와 sedutil-cli 모두 auth 가능.\n\n");

    if (!confirmDestructive(opts,
            "run sedutil-compat initialSetup — PSID Revert required to recover"))
        return 0;

    EvalApi api;

    // Pre-step 1: Discovery + Properties
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed: %s\n", r.message().c_str()); return 1; }

    PropertiesResult props;
    r = api.exchangeProperties(transport, info.baseComId, props);
    if (r.failed()) { printf("Properties failed: %s\n", r.message().c_str()); return 1; }

    // Pre-step 2: drive serial 추출 (sedutil PBKDF2 salt)
    Bytes driveSerial;
    r = api.getNvmeSerial(transport, driveSerial);
    if (r.failed()) {
        printf("getNvmeSerial failed: %s\n", r.message().c_str());
        printf("Note: this example requires NVMe transport (sedutil's salt source).\n");
        return 1;
    }
    printf("  drive serial (20 B, sedutil PBKDF2 salt): ");
    for (auto b : driveSerial) {
        if (b >= 0x20 && b < 0x7F) printf("%c", b);
        else printf(".");
    }
    printf("\n\n");

    // A ~ E 순차 실행. sedutil DtaDevOpal::initialSetup 과 동일 패턴.
    Bytes msid;
    if (!opA_takeOwnership   (transport, info.baseComId, props, driveSerial, msid)) return 1;
    if (!opB_activateLockingSP(transport, info.baseComId, props, driveSerial))      return 1;
    if (!opC_disableLocking  (transport, info.baseComId, props, driveSerial))       return 1;
    if (!opD_unlockGlobal    (transport, info.baseComId, props, driveSerial))       return 1;
    if (!opE_disableMbr      (transport, info.baseComId, props, driveSerial))       return 1;

    printf("\n  sedutil-compat initialSetup completed.\n");
    printf("  - SID password = PBKDF2-HMAC-SHA1(\"%s\", serial, 75000)\n",
           NEW_SID_PW.c_str());
    printf("  - LockingSP active, range unlocked, MBR shadow off.\n");
    printf("  - 이 시점부터 sedutil-cli 와 cats 모두 같은 password 로 auth 가능.\n");
    printf("  - Revert: 12_factory_reset --psid (destructive).\n");
    return 0;
}
