/// @file eval_full_demo.cpp
/// @brief Comprehensive demo of all EvalApi functions.
///
/// Covers: Discovery utils, split session, user management, enterprise ops,
/// ComID management, DataStore I/O, MBR, locking range, ACE, raw transport,
/// session state, password hashing, table enumeration, and more.

#include <libsed/sed_library.h>
#include <libsed/debug/debug.h>
#include <iostream>
#include <iomanip>

using namespace libsed;
using namespace libsed::eval;

// ── Helpers ─────────────────────────────────────────

static void ok(const std::string& step, Result r) {
    std::cout << "  [" << step << "] " << (r.ok() ? "OK" : "FAIL") << "\n";
}

static const char* sscStr(SscType s) {
    switch (s) {
        case SscType::Opal20:       return "Opal";
        case SscType::Enterprise: return "Enterprise";
        case SscType::Pyrite20:     return "Pyrite";
        default:                  return "Unknown";
    }
}

// ════════════════════════════════════════════════════════
//  Phase 1: No session required
// ════════════════════════════════════════════════════════

/// @scenario 세션 불필요 작업 전체 데모
/// @precondition NVMe 디바이스가 열려 있고 TCG SED를 지원해야 함
/// @steps
///   1. getTcgOption — Discovery 기반 드라이브 기능 요약 조회
///   2. getSecurityStatus — Feature 존재 여부 플래그 조회
///   3. getAllSecurityFeatures — 전체 Security Feature 열거
///   4. getSecurityFeature(0x0002) — 개별 Locking Feature 조회
///   5. discovery0Raw — Level 0 Discovery 원시 바이너리 수신
///   6. discovery0Custom(protocol=0xFF) — 잘못된 Protocol ID 네거티브 테스트
///   7. rawIfRecv — 원시 IF-RECV 호출
///   8. hashPassword / hashPasswordPbkdf2 — 비밀번호 해싱 유틸리티
///   9. stackReset / verifyComId — ComID 유효성 검증
///   10. verifyAuthority — 인증 자격 확인 (데모에서는 스킵)
/// @expected
///   - 모든 비세션 작업이 정상 완료됨
///   - Discovery, Feature 조회, 해싱 결과가 유효한 값 반환
///   - 유효한 ComID가 반환되어 후속 세션 작업에 사용 가능
static uint16_t phase1_noSession(EvalApi& api, std::shared_ptr<ITransport> tr) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  Phase 1: No Session Required             ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // 1. getTcgOption
    std::cout << "\n── 1. getTcgOption ──\n";
    TcgOption opt;
    ok("getTcgOption", api.getTcgOption(tr, opt));
    std::cout << "    SSC=" << sscStr(opt.sscType)
              << " ComID=0x" << std::hex << opt.baseComId << std::dec
              << " Locking=" << opt.lockingEnabled
              << " Locked=" << opt.locked
              << " MBR=" << opt.mbrEnabled << "/" << opt.mbrDone
              << " Users=" << opt.maxLockingUsers << "\n";

    // 2. getSecurityStatus
    std::cout << "\n── 2. getSecurityStatus ──\n";
    SecurityStatus ss;
    ok("getSecurityStatus", api.getSecurityStatus(tr, ss));
    std::cout << "    TPer=" << ss.tperPresent
              << " Opal2=" << ss.opalV2Present
              << " Ent=" << ss.enterprisePresent
              << " Pyrite2=" << ss.pyriteV2Present << "\n";

    // 3. getAllSecurityFeatures
    std::cout << "\n── 3. getAllSecurityFeatures ──\n";
    std::vector<SecurityFeatureInfo> feats;
    ok("getAllSecurityFeatures", api.getAllSecurityFeatures(tr, feats));
    for (auto& f : feats) {
        std::cout << "    0x" << std::hex << f.featureCode << std::dec
                  << " " << f.featureName << " v" << (int)f.version << "\n";
    }

    // 4. getSecurityFeature (single)
    std::cout << "\n── 4. getSecurityFeature(0x0002=Locking) ──\n";
    SecurityFeatureInfo lf;
    auto r = api.getSecurityFeature(tr, 0x0002, lf);
    if (r.ok()) std::cout << "    locked=" << lf.locked << " mbrDone=" << lf.mbrDone << "\n";
    else std::cout << "    Not found\n";

    // 5. discovery0Raw
    std::cout << "\n── 5. discovery0Raw ──\n";
    Bytes rawDisc;
    ok("discovery0Raw", api.discovery0Raw(tr, rawDisc));
    printHex("Raw L0 Discovery", rawDisc, 48);

    // 6. discovery0Custom (negative test)
    std::cout << "\n── 6. discovery0Custom(protocol=0xFF) ──\n";
    Bytes badDisc;
    ok("discovery0Custom", api.discovery0Custom(tr, 0xFF, 0x0001, badDisc));

    // 7. Raw IF-SEND / IF-RECV
    std::cout << "\n── 7. rawIfSend / rawIfRecv ──\n";
    Bytes rawRecv;
    ok("rawIfRecv(proto=1,comId=1)", api.rawIfRecv(tr, 0x01, 0x0001, rawRecv, 512));
    printHex("Raw recv", rawRecv, 16);

    // 8. Password hashing utilities
    std::cout << "\n── 8. hashPassword / hashPasswordPbkdf2 ──\n";
    Bytes h1 = EvalApi::hashPassword("test_password");
    printHex("hashPassword(\"test_password\")", h1, 32);
    Bytes salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    Bytes h2 = EvalApi::hashPasswordPbkdf2("test_password", salt, 1000);
    printHex("pbkdf2(salt, 1000 iters)", h2, 32);

    // 9. Stack Reset / Verify ComID
    std::cout << "\n── 9. stackReset / verifyComId ──\n";
    if (opt.baseComId != 0) {
        bool active = false;
        ok("verifyComId", api.verifyComId(tr, opt.baseComId, active));
        std::cout << "    ComID 0x" << std::hex << opt.baseComId << std::dec
                  << " active=" << active << "\n";
    }

    // 10. Verify authority (just checks if credential works)
    std::cout << "\n── 10. verifyAuthority ──\n";
    std::cout << "    (skipped — needs valid credential)\n";
    // auto r2 = api.verifyAuthority(tr, opt.baseComId, uid::SP_ADMIN, uid::AUTH_SID, "password");
    // ok("verifyAuthority(SID)", r2);

    return opt.baseComId;
}

// ════════════════════════════════════════════════════════
//  Phase 2: Split StartSession/SyncSession
// ════════════════════════════════════════════════════════

/// @scenario 분리된 세션 시작/동기화
/// @precondition NVMe 디바이스가 열려 있고 유효한 ComID가 있어야 함
/// @steps
///   1. Case A: AdminSP, Read-only, Anybody — sendStartSession + recvSyncSession
///   2. Case B: AdminSP, Write, SID Authority + challenge — sendStartSession + recvSyncSession
///   3. Case C: LockingSP, Write, Admin1 — startSyncSession으로 Session 객체 관리
/// @expected
///   - 3가지 Case 모두 정상 세션 열림
///   - Case A/B는 HSN/TSN, SP Challenge 등 SyncSession 응답 필드 확인 가능
///   - Case C는 Session 객체를 통한 세션 라이프사이클(열기/닫기) 정상 동작
static void phase2_splitSession(EvalApi& api, std::shared_ptr<ITransport> tr, uint16_t comId) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  Phase 2: Split StartSession/SyncSession  ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Case A: Read-only, Anybody
    std::cout << "\n── A: AdminSP, Read, Anybody ──\n";
    {
        StartSessionParams p;
        p.spUid = uid::SP_ADMIN;
        p.write = false;
        Bytes sent;
        auto r = api.sendStartSession(tr, comId, p, sent);
        ok("sendStartSession", r);
        printHex("Sent", sent, 32);

        if (r.ok()) {
            SyncSessionResult sr;
            r = api.recvSyncSession(tr, comId, sr);
            ok("recvSyncSession", r);
            if (r.ok()) {
                std::cout << "    HSN=" << sr.hostSessionNumber
                          << " TSN=" << sr.tperSessionNumber << "\n";
                if (!sr.spChallenge.empty()) printHex("SPChallenge", sr.spChallenge);
                printHex("Recv payload", sr.raw.rawRecvPayload, 32);
            }
        }
    }

    // Case B: Write, SID Authority
    std::cout << "\n── B: AdminSP, Write, SID + challenge ──\n";
    {
        StartSessionParams p;
        p.spUid = uid::SP_ADMIN;
        p.write = true;
        p.hostExchangeAuthority = uid::AUTH_SID;
        p.hostChallenge = {0xDE, 0xAD, 0xBE, 0xEF};
        Bytes sent;
        ok("sendStartSession(SID)", api.sendStartSession(tr, comId, p, sent));
        SyncSessionResult sr;
        api.recvSyncSession(tr, comId, sr);
        std::cout << "    TSN=" << sr.tperSessionNumber << "\n";
    }

    // Case C: Using Session object
    std::cout << "\n── C: startSyncSession (LockingSP, Admin1) ──\n";
    {
        StartSessionParams p;
        p.spUid = uid::SP_LOCKING;
        p.write = true;
        p.hostExchangeAuthority = uid::AUTH_ADMIN1;
        p.hostChallenge = HashPassword::passwordToBytes("admin1");
        Session sess(tr, comId);
        SyncSessionResult sr;
        auto r = api.startSyncSession(sess, p, sr);
        ok("startSyncSession", r);
        if (r.ok()) {
            auto info = EvalApi::getSessionInfo(sess);
            std::cout << "    active=" << info.active
                      << " HSN=" << info.hostSessionNumber
                      << " TSN=" << info.tperSessionNumber << "\n";
            api.closeSession(sess);
        }
    }
}

// ════════════════════════════════════════════════════════
//  Phase 3: Session-based operations
// ════════════════════════════════════════════════════════

/// @scenario 세션 기반 전체 작업 데모 (30+ 작업)
/// @precondition LockingSP(또는 AdminSP)에 인증된 세션이 열려 있어야 함
/// @steps
///   1. Session State 확인 및 타임아웃 설정
///   2. SP Lifecycle 조회 (getSpLifecycle)
///   3. Locking Info 조회 (getLockingInfo, getAllLockingInfo)
///   4. LockOnReset 설정 (setLockOnReset)
///   5. MBR 상태 조회 및 NSID=1 설정 (getMbrStatus, setMbrControlNsidOne)
///   6. User 관리 (isUserEnabled, enableUser, setUserPassword, setAdmin1Password, assignUserToRange)
///   7. Table Next — Authority 행 열거
///   8. tableGetColumn — 단일 컬럼 읽기
///   9. C_PIN 시도 횟수 조회 (getCPinTriesRemaining)
///   10. ByteTable/DataStore 정보 및 I/O (getByteTableInfo, tcgWriteDataStore, tcgReadDataStore, tcgCompare)
///   11. Generic Table Ops (tableSetUint, tableGet)
///   12. Crypto Erase (cryptoErase)
///   13. 난수 생성 (getRandom)
///   14. Raw Method 전송 (sendRawMethod)
///   15. ACL 조회 (getAcl)
///   16. 편의 컬럼 읽기 (tableGetUint, tableGetBool, tableGetBytes)
///   17. 다중 컬럼 설정 (tableSetMultiUint)
///   18. Clock 조회, DataStore Table N, ActiveKey, CreateRow/DeleteRow (스킵)
/// @expected
///   - SP lifecycle, Locking, MBR, User 관리, Table, Crypto, DataStore 등 모든 작업 정상 실행
///   - 각 작업의 OK/FAIL 상태 확인 가능
///   - DataStore Write → Read → Compare 결과 일치
static void phase3_sessionOps(EvalApi& api, Session& session) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  Phase 3: Session-Based Operations        ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    RawResult raw;

    // Session state
    std::cout << "\n── Session State ──\n";
    auto si = EvalApi::getSessionInfo(session);
    std::cout << "    active=" << si.active << " HSN=" << si.hostSessionNumber
              << " TSN=" << si.tperSessionNumber << "\n";
    EvalApi::setSessionTimeout(session, 60000);
    std::cout << "    Timeout set to 60s\n";

    // SP Lifecycle
    std::cout << "\n── SP Lifecycle ──\n";
    uint8_t lifecycle = 0;
    ok("getSpLifecycle(LockingSP)", api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle, raw));
    std::cout << "    lifecycle=" << (int)lifecycle << "\n";

    // Locking info
    std::cout << "\n── GetLockingInfo ──\n";
    LockingInfo li;
    ok("getLockingInfo(0)", api.getLockingInfo(session, 0, li, raw));
    std::cout << "    Range0: start=" << li.rangeStart << " len=" << li.rangeLength
              << " RLE=" << li.readLockEnabled << " WLE=" << li.writeLockEnabled
              << " key=0x" << std::hex << li.activeKey << std::dec << "\n";

    std::vector<LockingInfo> ranges;
    ok("getAllLockingInfo(8)", api.getAllLockingInfo(session, ranges, 8, raw));
    std::cout << "    Found " << ranges.size() << " ranges\n";

    // LockOnReset
    std::cout << "\n── SetLockOnReset ──\n";
    ok("setLockOnReset(0, true)", api.setLockOnReset(session, 0, true, raw));

    // MBR status
    std::cout << "\n── MBR Status ──\n";
    bool mbrEn = false, mbrDn = false;
    ok("getMbrStatus", api.getMbrStatus(session, mbrEn, mbrDn, raw));
    std::cout << "    Enable=" << mbrEn << " Done=" << mbrDn << "\n";

    // setMbrControlNsidOne
    ok("setMbrControlNsidOne", api.setMbrControlNsidOne(session, raw));

    // User management
    std::cout << "\n── User Management ──\n";
    bool enabled = false;
    ok("isUserEnabled(1)", api.isUserEnabled(session, 1, enabled, raw));
    std::cout << "    User1 enabled=" << enabled << "\n";

    ok("enableUser(1)", api.enableUser(session, 1, raw));
    ok("setUserPassword(1)", api.setUserPassword(session, 1, "user1_pass", raw));
    ok("setAdmin1Password", api.setAdmin1Password(session, "admin1_new", raw));
    ok("assignUserToRange(1, 0)", api.assignUserToRange(session, 1, 0, raw));

    // Table enumeration
    std::cout << "\n── Table Next (enumerate authority rows) ──\n";
    std::vector<Uid> rows;
    ok("tableNext(Authority)", api.tableNext(session, uid::TABLE_AUTHORITY, 0, rows, 10, raw));
    std::cout << "    Found " << rows.size() << " authority rows\n";
    for (size_t i = 0; i < rows.size() && i < 5; i++) {
        std::cout << "    [" << i << "] 0x" << std::hex << rows[i].toUint64() << std::dec << "\n";
    }

    // Get single column
    std::cout << "\n── tableGetColumn ──\n";
    Token val;
    ok("tableGetColumn(CPIN_SID, PIN)", api.tableGetColumn(session, uid::CPIN_SID, uid::col::PIN, val, raw));

    // C_PIN tries remaining
    std::cout << "\n── getCPinTriesRemaining ──\n";
    uint32_t tries = 0;
    ok("getCPinTriesRemaining(SID)", api.getCPinTriesRemaining(session, uid::CPIN_SID, tries, raw));
    std::cout << "    Remaining=" << tries << "\n";

    // DataStore info
    std::cout << "\n── ByteTable / DataStore ──\n";
    ByteTableInfo bti;
    ok("getByteTableInfo", api.getByteTableInfo(session, bti, raw));
    std::cout << "    MaxSize=" << bti.maxSize << " UsedSize=" << bti.usedSize << "\n";

    // DataStore I/O
    Bytes writeData = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
    ok("tcgWriteDataStore(0)", api.tcgWriteDataStore(session, 0, writeData, raw));

    DataOpResult dr;
    ok("tcgReadDataStore(0, 8)", api.tcgReadDataStore(session, 0, 8, dr));
    if (!dr.data.empty()) printHex("Read back", dr.data);

    DataOpResult cr;
    ok("tcgCompare(DS, 0)", api.tcgCompare(session, uid::TABLE_DATASTORE, 0, writeData, cr));
    std::cout << "    Match=" << cr.compareMatch << "\n";

    // Generic table ops
    std::cout << "\n── Generic Table Ops ──\n";
    ok("tableSetUint(Range0, RANGE_START, 0)", api.tableSetUint(session,
        uid::LOCKING_GLOBALRANGE, uid::col::RANGE_START, 0, raw));

    TableResult tr;
    ok("tableGet(Range0, 3..8)", api.tableGet(session, uid::LOCKING_GLOBALRANGE, 3, 8, tr));
    for (auto& [col, tok] : tr.columns) {
        std::cout << "    col " << col << " = " << tok.toString() << "\n";
    }

    // Crypto erase
    std::cout << "\n── Crypto Erase ──\n";
    ok("cryptoErase(0)", api.cryptoErase(session, 0, raw));

    // Random
    std::cout << "\n── getRandom ──\n";
    Bytes rnd;
    ok("getRandom(16)", api.getRandom(session, 16, rnd, raw));
    if (!rnd.empty()) printHex("Random", rnd, 16);

    // Raw method
    std::cout << "\n── sendRawMethod ──\n";
    Bytes rawTokens = EvalApi::buildMethodCall(uid::THIS_SP, method::RANDOM, {});
    ok("sendRawMethod", api.sendRawMethod(session, rawTokens, raw));

    // GetACL
    std::cout << "\n── GetACL ──\n";
    EvalApi::AclInfo acl;
    ok("getAcl(GlobalRange, GET)", api.getAcl(session, uid::LOCKING_GLOBALRANGE, method::GET, acl));
    std::cout << "    ACE count=" << acl.aceList.size() << "\n";

    // Convenience column reads
    std::cout << "\n── tableGetUint / tableGetBool / tableGetBytes ──\n";
    uint64_t uval = 0;
    ok("tableGetUint(Range0, RANGE_START)", api.tableGetUint(session, uid::LOCKING_GLOBALRANGE, uid::col::RANGE_START, uval, raw));
    std::cout << "    RANGE_START=" << uval << "\n";
    bool bval = false;
    ok("tableGetBool(Range0, READ_LOCK_EN)", api.tableGetBool(session, uid::LOCKING_GLOBALRANGE, uid::col::READ_LOCK_EN, bval, raw));
    std::cout << "    READ_LOCK_EN=" << bval << "\n";
    Bytes bdata;
    api.tableGetBytes(session, uid::CPIN_SID, uid::col::PIN, bdata, raw);

    // Multi-column set
    std::cout << "\n── tableSetMultiUint ──\n";
    ok("tableSetMultiUint(Range0)", api.tableSetMultiUint(session, uid::LOCKING_GLOBALRANGE,
        {{uid::col::READ_LOCK_EN, 1}, {uid::col::WRITE_LOCK_EN, 1}}, raw));

    // Revert (object level)
    std::cout << "\n── revert (object) ──\n";
    // Uncomment to actually revert: ok("revert", api.revert(session, someUid, raw));
    std::cout << "    (skipped — would reset object state)\n";

    // Clock
    std::cout << "\n── getClock ──\n";
    uint64_t clockVal = 0;
    ok("getClock", api.getClock(session, clockVal, raw));
    std::cout << "    Clock=" << clockVal << "\n";

    // DataStore with table number
    std::cout << "\n── DataStore Table N ──\n";
    Bytes dsData = {0x11, 0x22, 0x33, 0x44};
    ok("tcgWriteDataStoreN(0)", api.tcgWriteDataStoreN(session, 0, 0, dsData, raw));
    DataOpResult dsRead;
    ok("tcgReadDataStoreN(0)", api.tcgReadDataStoreN(session, 0, 0, 4, dsRead));
    if (!dsRead.data.empty()) printHex("DS[0] read", dsRead.data);

    // Active key
    std::cout << "\n── getActiveKey ──\n";
    Uid keyUid;
    ok("getActiveKey(0)", api.getActiveKey(session, 0, keyUid, raw));
    std::cout << "    KeyUID=0x" << std::hex << keyUid.toUint64() << std::dec << "\n";

    // CreateRow / DeleteRow (careful - changes table state)
    std::cout << "\n── tableCreateRow / tableDeleteRow ──\n";
    std::cout << "    (skipped — would modify table structure)\n";

    // Assign / Remove
    std::cout << "\n── tableAssign / tableRemove ──\n";
    std::cout << "    (skipped — would modify ACL)\n";

    // Discovery with raw
    std::cout << "\n── discovery0Parsed (with raw) ──\n";
    // Note: uses transport, not session
    // api.discovery0Parsed(transport, info, raw);
}

// ════════════════════════════════════════════════════════
//  Phase 4: Enterprise-specific (if applicable)
// ════════════════════════════════════════════════════════

/// @scenario Enterprise SSC 전체 작업 데모
/// @precondition Enterprise SSC 드라이브에 BandMaster 인증 세션이 열려 있어야 함
/// @steps
///   1. configureBand(1) — Band 1 구성 (ReadLockEnabled, WriteLockEnabled 활성화)
///   2. getBandInfo(1) — Band 1 상세 정보 조회
///   3. lockBand(1) — Band 1 잠금
///   4. unlockBand(1) — Band 1 잠금 해제
///   5. setBandMasterPassword(1) — BandMaster 1 비밀번호 변경
///   6. eraseBand(1) — Band 1 Crypto Erase
///   7. setBandLockOnReset(1, true) — Band 1 리셋 시 잠금 설정
///   8. eraseAllBands — 전체 Band 삭제 (파괴적이므로 스킵)
/// @expected
///   - Band 설정, 잠금, 해제, 비밀번호 변경, Erase, LockOnReset 등 모든 Enterprise 작업 정상 실행
///   - eraseAllBands는 파괴적 작업이므로 실행하지 않고 스킵 확인
static void phase4_enterprise(EvalApi& api, Session& session) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  Phase 4: Enterprise SSC Operations       ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    RawResult raw;

    // Configure band
    ok("configureBand(1)", api.configureBand(session, 1, 0, 0, true, true, raw));

    // Get band info
    LockingInfo bi;
    ok("getBandInfo(1)", api.getBandInfo(session, 1, bi, raw));
    std::cout << "    Band1: start=" << bi.rangeStart << " len=" << bi.rangeLength << "\n";

    // Lock/unlock band
    ok("lockBand(1)", api.lockBand(session, 1, raw));
    ok("unlockBand(1)", api.unlockBand(session, 1, raw));

    // Set BandMaster password
    Bytes newPin = HashPassword::passwordToBytes("bm1_new");
    ok("setBandMasterPassword(1)", api.setBandMasterPassword(session, 1, newPin, raw));

    // Erase band
    ok("eraseBand(1)", api.eraseBand(session, 1, raw));

    // LockOnReset for band
    ok("setBandLockOnReset(1, true)", api.setBandLockOnReset(session, 1, true, raw));

    // EraseAll (careful!)
    // ok("eraseAllBands(4)", api.eraseAllBands(session, 4, raw));
    std::cout << "    eraseAllBands skipped (destructive)\n";
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    std::string device = (argc > 1) ? argv[1] : "/dev/nvme0";
    std::string password = (argc > 2) ? argv[2] : "";
    bool isEnterprise = (argc > 3 && std::string(argv[3]) == "enterprise");

    libsed::initialize();

    auto tr = TransportFactory::createNvme(device);
    if (!tr || !tr->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return 1;
    }

    EvalApi api;

    // Phase 1: No session
    uint16_t comId = phase1_noSession(api, tr);
    if (comId == 0) {
        std::cerr << "No valid ComID\n";
        return 1;
    }

    // Phase 2: Split session
    phase2_splitSession(api, tr, comId);

    // Phase 3: Session ops (requires password)
    if (!password.empty()) {
        PropertiesResult props;
        api.exchangeProperties(tr, comId, props);

        Session session(tr, comId);
        session.setMaxComPacketSize(props.tperMaxComPacketSize);

        Bytes cred = HashPassword::passwordToBytes(password);
        uint64_t authUid = isEnterprise ? uid::AUTH_BANDMASTER0 : uid::AUTH_ADMIN1;
        uint64_t spUid   = isEnterprise ? uid::SP_ENTERPRISE : uid::SP_LOCKING;

        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, spUid, true, authUid, cred, ssr);
        if (r.ok()) {
            phase3_sessionOps(api, session);
            if (isEnterprise) phase4_enterprise(api, session);
            api.closeSession(session);
        } else {
            std::cerr << "Session failed: " << r.message() << "\n";
        }
    } else {
        std::cout << "\n  Pass password as 2nd arg for session-based demos.\n";
        std::cout << "  Usage: " << argv[0] << " <device> [password] [enterprise]\n";
    }

    libsed::shutdown();
    std::cout << "\n=== All demos complete ===\n";
    return 0;
}
