/// @file eval_tc_utils.cpp
/// @brief Example: TC Library style utility functions and split session usage.
///
/// Demonstrates the flat EvalApi equivalents of common TC Library functions:
///
///   getTcgOption            → api.getTcgOption()
///   GetClass0SecurityStatus → api.getSecurityStatus()
///   GetSecurityFeatureType  → api.getSecurityFeature() / getAllSecurityFeatures()
///   GetLockingInfo          → api.getLockingInfo() / getAllLockingInfo()
///   GetByteTableInfo        → api.getByteTableInfo()
///   SetMBRControlTableNsidOne → api.setMbrControlNsidOne()
///   TcgWrite                → api.tcgWrite() / tcgWriteDataStore()
///   TcgRead                 → api.tcgRead() / tcgReadDataStore()
///   TcgCompare              → api.tcgCompare()
///
/// Also shows split StartSession_REQ/OPT + SyncSession_REQ/OPT usage.

#include <libsed/sed_library.h>
#include <libsed/debug/debug.h>
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace libsed;
using namespace libsed::eval;
using namespace libsed::debug;

// ════════════════════════════════════════════════════════
//  1. getTcgOption — Drive capability summary
// ════════════════════════════════════════════════════════

/// @scenario Discovery 기반 드라이브 기능 요약 조회
/// @precondition NVMe 디바이스가 열려 있고 Level 0 Discovery가 가능해야 함
/// @steps
///   1. api.getTcgOption() 호출로 Discovery 수행 및 TcgOption 구조체 수신
///   2. SSC 타입, Base ComID, Locking 지원/활성화/잠금 상태 출력
///   3. MBR 지원/활성화/완료 상태 출력
///   4. 최대 Locking Admin/User 수, Initial/Reverted PIN 지시자 출력
/// @expected
///   - SSC 타입(Opal/Enterprise/Pyrite), ComID, Locking/MBR 상태 등 정상 반환
///   - TcgOption 구조체의 모든 필드가 유효한 값으로 채워짐
static void demo_getTcgOption(EvalApi& api, std::shared_ptr<ITransport> transport) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 1. getTcgOption — Drive Capability Summary\n";
    std::cout << "══════════════════════════════════════════\n";

    TcgOption opt;
    auto r = api.getTcgOption(transport, opt);
    step("getTcgOption", r);
    if (r.failed()) return;

    std::cout << "  SSC Type:            " << sscName(opt.sscType) << "\n";
    std::cout << "  Base ComID:          0x" << std::hex << opt.baseComId << std::dec << "\n";
    std::cout << "  Num ComIDs:          " << opt.numComIds << "\n";
    std::cout << "  Locking Supported:   " << (opt.lockingSupported ? "Yes" : "No") << "\n";
    std::cout << "  Locking Enabled:     " << (opt.lockingEnabled ? "Yes" : "No") << "\n";
    std::cout << "  Locked:              " << (opt.locked ? "Yes" : "No") << "\n";
    std::cout << "  MBR Supported:       " << (opt.mbrSupported ? "Yes" : "No") << "\n";
    std::cout << "  MBR Enabled:         " << (opt.mbrEnabled ? "Yes" : "No") << "\n";
    std::cout << "  MBR Done:            " << (opt.mbrDone ? "Yes" : "No") << "\n";
    std::cout << "  Media Encryption:    " << (opt.mediaEncryption ? "Yes" : "No") << "\n";
    std::cout << "  Max Locking Admins:  " << opt.maxLockingAdmins << "\n";
    std::cout << "  Max Locking Users:   " << opt.maxLockingUsers << "\n";
    std::cout << "  Initial PIN:         " << static_cast<int>(opt.initialPinIndicator) << "\n";
    std::cout << "  Reverted PIN:        " << static_cast<int>(opt.revertedPinIndicator) << "\n";
}

// ════════════════════════════════════════════════════════
//  2. GetClass0SecurityStatus — Feature presence
// ════════════════════════════════════════════════════════

/// @scenario Feature 존재 여부 플래그 조회
/// @precondition NVMe 디바이스가 열려 있고 Level 0 Discovery가 가능해야 함
/// @steps
///   1. api.getSecurityStatus() 호출
///   2. SecurityStatus 구조체에서 각 Feature 존재 플래그 확인
/// @expected
///   - TPer, Locking, Geometry, Opal v1/v2, Enterprise, Pyrite v1/v2 등 Feature 존재 플래그 정상 반환
///   - Primary SSC 타입이 올바르게 식별됨
static void demo_getSecurityStatus(EvalApi& api, std::shared_ptr<ITransport> transport) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 2. GetClass0SecurityStatus — Feature Presence\n";
    std::cout << "══════════════════════════════════════════\n";

    SecurityStatus ss;
    auto r = api.getSecurityStatus(transport, ss);
    step("getSecurityStatus", r);
    if (r.failed()) return;

    std::cout << "  TPer:       " << (ss.tperPresent ? "Present" : "Absent") << "\n";
    std::cout << "  Locking:    " << (ss.lockingPresent ? "Present" : "Absent") << "\n";
    std::cout << "  Geometry:   " << (ss.geometryPresent ? "Present" : "Absent") << "\n";
    std::cout << "  Opal v1:    " << (ss.opalV1Present ? "Present" : "Absent") << "\n";
    std::cout << "  Opal v2:    " << (ss.opalV2Present ? "Present" : "Absent") << "\n";
    std::cout << "  Enterprise: " << (ss.enterprisePresent ? "Present" : "Absent") << "\n";
    std::cout << "  Pyrite v1:  " << (ss.pyriteV1Present ? "Present" : "Absent") << "\n";
    std::cout << "  Pyrite v2:  " << (ss.pyriteV2Present ? "Present" : "Absent") << "\n";
    std::cout << "  Primary:    " << sscName(ss.primarySsc) << "\n";
}

// ════════════════════════════════════════════════════════
//  3. GetSecurityFeatureType — Per-feature details
// ════════════════════════════════════════════════════════

/// @scenario 전체 Security Feature 열거 및 개별 조회
/// @precondition NVMe 디바이스가 열려 있고 Level 0 Discovery가 가능해야 함
/// @steps
///   1. api.getAllSecurityFeatures() 호출로 전체 Feature 목록 수신
///   2. 각 Feature의 코드, 이름, 버전, 데이터 길이, ComID, Locking 상태 출력
///   3. api.getSecurityFeature(0x0002)로 Locking Feature 개별 조회
/// @expected
///   - 모든 Feature 목록이 정상 반환됨
///   - 개별 Feature(Locking) 상세 정보(locked, mbrDone 등) 조회 가능
///   - Feature가 없는 경우 "Not found" 처리
static void demo_getSecurityFeatures(EvalApi& api, std::shared_ptr<ITransport> transport) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 3. GetSecurityFeatureType — All Features\n";
    std::cout << "══════════════════════════════════════════\n";

    std::vector<SecurityFeatureInfo> features;
    auto r = api.getAllSecurityFeatures(transport, features);
    step("getAllSecurityFeatures", r);
    if (r.failed()) return;

    for (auto& f : features) {
        std::cout << "\n  Feature 0x" << std::hex << f.featureCode << std::dec
                  << " (" << f.featureName << ")\n";
        std::cout << "    Version:      " << static_cast<int>(f.version) << "\n";
        std::cout << "    Data Length:   " << f.dataLength << "\n";

        if (f.baseComId != 0) {
            std::cout << "    Base ComID:   0x" << std::hex << f.baseComId << std::dec << "\n";
            std::cout << "    Num ComIDs:   " << f.numComIds << "\n";
            std::cout << "    Range Cross:  " << (f.rangeCrossing ? "Yes" : "No") << "\n";
        }
        if (f.lockingSupported) {
            std::cout << "    Lock Support: Yes\n";
            std::cout << "    Lock Enabled: " << (f.lockingEnabled ? "Yes" : "No") << "\n";
            std::cout << "    Locked:       " << (f.locked ? "Yes" : "No") << "\n";
            std::cout << "    MBR Enabled:  " << (f.mbrEnabled ? "Yes" : "No") << "\n";
            std::cout << "    MBR Done:     " << (f.mbrDone ? "Yes" : "No") << "\n";
        }
        if (!f.rawFeatureData.empty()) {
            printHex("Raw Data", f.rawFeatureData, 16);
        }
    }

    // Query a single feature
    std::cout << "\n  --- Query single feature: Locking (0x0002) ---\n";
    SecurityFeatureInfo lockInfo;
    r = api.getSecurityFeature(transport, 0x0002, lockInfo);
    if (r.ok()) {
        std::cout << "    " << lockInfo.featureName
                  << " v" << static_cast<int>(lockInfo.version)
                  << " lockEnabled=" << lockInfo.lockingEnabled
                  << " locked=" << lockInfo.locked << "\n";
    } else {
        std::cout << "    Not found\n";
    }
}

// ════════════════════════════════════════════════════════
//  4. Split StartSession/SyncSession with REQ+OPT
// ════════════════════════════════════════════════════════

/// @scenario 분리된 StartSession/SyncSession (REQ+OPT)
/// @precondition NVMe 디바이스가 열려 있고 유효한 ComID가 있어야 함
/// @steps
///   1. Case A: AdminSP, Read-only, Anybody — sendStartSession → recvSyncSession (OPT 필드 없음)
///   2. Case B: AdminSP, Write, SID Authority + MSID challenge — sendStartSession → recvSyncSession (OPT: hostExchangeAuthority, hostChallenge)
///   3. Case C: LockingSP, Write, Admin1 — startSyncSession으로 Session 객체 관리 세션 시작
/// @expected
///   - Case A: SyncSession 응답에서 HSN/TSN 정상 수신
///   - Case B: SyncSession 응답에서 HSN/TSN, SP Challenge, Signed Hash 등 OPT 필드 확인
///   - Case C: Session 객체로 관리되는 세션 정상 열림 및 닫힘
///   - 각 Case의 Send/Recv 페이로드를 원시 바이트로 검사 가능
static void demo_splitSession(EvalApi& api,
                               std::shared_ptr<ITransport> transport,
                               uint16_t comId) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 4. Split StartSession/SyncSession\n";
    std::cout << "══════════════════════════════════════════\n";

    // ── Case A: AdminSP, Read-only, no auth ──
    std::cout << "\n  --- Case A: AdminSP, Read, Anybody ---\n";
    {
        StartSessionParams params;
        params.spUid = uid::SP_ADMIN;
        params.write = false;
        // No OPT fields → Anybody access

        Bytes sentPayload;
        auto r = api.sendStartSession(transport, comId, params, sentPayload);
        step("sendStartSession", r);
        printHex("Sent payload", sentPayload);

        if (r.ok()) {
            // Can inspect/corrupt sentPayload here before recv!

            SyncSessionResult syncResult;
            r = api.recvSyncSession(transport, comId, syncResult);
            step("recvSyncSession", r);

            if (r.ok()) {
                std::cout << "    HSN:  " << syncResult.hostSessionNumber << "\n";
                std::cout << "    TSN:  " << syncResult.tperSessionNumber << "\n";
                if (!syncResult.spChallenge.empty())
                    printHex("SP Challenge", syncResult.spChallenge);
                if (syncResult.transTimeout != 0)
                    std::cout << "    TransTimeout:    " << syncResult.transTimeout << "\n";
                if (syncResult.initialCredits != 0)
                    std::cout << "    InitialCredits:  " << syncResult.initialCredits << "\n";
            }
            printHex("Recv payload", syncResult.raw.rawRecvPayload);

            // Note: session is now open but unmanaged. For a full test,
            // you'd need to send CloseSession. For demo we skip.
        }
    }

    // ── Case B: AdminSP, Write, SID Authority + credential ──
    std::cout << "\n  --- Case B: AdminSP, Write, SID + MSID challenge ---\n";
    {
        // First get MSID for use as challenge
        // (In a real test, you'd do a read-only session first to get this)
        Bytes fakeMsid = {0x01, 0x02, 0x03, 0x04}; // placeholder

        StartSessionParams params;
        params.spUid = uid::SP_ADMIN;
        params.write = true;
        // StartSession_OPT fields:
        params.hostExchangeAuthority = uid::AUTH_SID;
        params.hostChallenge = fakeMsid;

        Bytes sentPayload;
        auto r = api.sendStartSession(transport, comId, params, sentPayload);
        step("sendStartSession (SID auth)", r);
        printHex("Sent payload", sentPayload, 64);

        if (r.ok()) {
            SyncSessionResult syncResult;
            r = api.recvSyncSession(transport, comId, syncResult);
            step("recvSyncSession", r);

            if (r.ok()) {
                std::cout << "    HSN:  " << syncResult.hostSessionNumber << "\n";
                std::cout << "    TSN:  " << syncResult.tperSessionNumber << "\n";
                if (!syncResult.spChallenge.empty())
                    printHex("SP Challenge", syncResult.spChallenge);
                if (!syncResult.signedHash.empty())
                    printHex("Signed Hash", syncResult.signedHash);
            }
        }
    }

    // ── Case C: LockingSP, Write, Admin1 Authority ──
    std::cout << "\n  --- Case C: LockingSP, Write, Admin1 (using Session) ---\n";
    {
        StartSessionParams params;
        params.spUid = uid::SP_LOCKING;
        params.write = true;
        params.hostExchangeAuthority = uid::AUTH_ADMIN1;
        params.hostChallenge = HashPassword::passwordToBytes("admin1_password");

        Session session(transport, comId);
        SyncSessionResult sr;
        auto r = api.startSyncSession(session, params, sr);
        step("startSyncSession (LockingSP, Admin1)", r);

        if (r.ok()) {
            std::cout << "    HSN: " << sr.hostSessionNumber
                      << "  TSN: " << sr.tperSessionNumber << "\n";
            api.closeSession(session);
        }
    }
}

// ════════════════════════════════════════════════════════
//  5. GetLockingInfo — Read locking range details
// ════════════════════════════════════════════════════════

/// @scenario Locking Range 상세 정보 조회
/// @precondition LockingSP에 인증된 세션이 열려 있어야 함
/// @steps
///   1. api.getLockingInfo(0)로 Global Range(Range 0) 상세 정보 조회
///   2. api.getAllLockingInfo(8)로 최대 8개 Range 전체 정보 조회
/// @expected
///   - 단일 Range: start, length, ReadLockEnabled, WriteLockEnabled, ReadLocked, WriteLocked, ActiveKey 정상 반환
///   - 전체 Range: 존재하는 모든 Range의 정보가 벡터로 반환됨
static void demo_getLockingInfo(EvalApi& api, Session& session) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 5. GetLockingInfo — Locking Range Details\n";
    std::cout << "══════════════════════════════════════════\n";

    // Single range
    std::cout << "\n  --- Global Range (0) ---\n";
    LockingInfo info;
    RawResult raw;
    auto r = api.getLockingInfo(session, 0, info, raw);
    step("getLockingInfo(0)", r);
    if (r.ok()) {
        std::cout << "    Start:           " << info.rangeStart << "\n";
        std::cout << "    Length:          " << info.rangeLength << "\n";
        std::cout << "    ReadLockEnabled: " << (info.readLockEnabled ? "Yes" : "No") << "\n";
        std::cout << "    WriteLockEnabled:" << (info.writeLockEnabled ? "Yes" : "No") << "\n";
        std::cout << "    ReadLocked:      " << (info.readLocked ? "Yes" : "No") << "\n";
        std::cout << "    WriteLocked:     " << (info.writeLocked ? "Yes" : "No") << "\n";
        std::cout << "    ActiveKey:       0x" << std::hex << info.activeKey << std::dec << "\n";
    }

    // All ranges
    std::cout << "\n  --- All Ranges (up to 8) ---\n";
    std::vector<LockingInfo> ranges;
    r = api.getAllLockingInfo(session, ranges, 8, raw);
    step("getAllLockingInfo", r);
    for (auto& ri : ranges) {
        std::cout << "    Range " << ri.rangeId
                  << ": start=" << ri.rangeStart
                  << " len=" << ri.rangeLength
                  << " RLE=" << ri.readLockEnabled
                  << " WLE=" << ri.writeLockEnabled
                  << " RL=" << ri.readLocked
                  << " WL=" << ri.writeLocked << "\n";
    }
}

// ════════════════════════════════════════════════════════
//  6. GetByteTableInfo — DataStore table properties
// ════════════════════════════════════════════════════════

/// @scenario DataStore 테이블 속성 조회
/// @precondition LockingSP에 인증된 세션이 열려 있어야 함
/// @steps
///   1. api.getByteTableInfo() 호출로 DataStore 테이블 속성 조회
///   2. Table UID, maxSize, usedSize 출력
/// @expected
///   - maxSize(최대 크기)와 usedSize(사용 크기)가 정상 반환됨
///   - Table UID가 유효한 DataStore 테이블 UID임
static void demo_getByteTableInfo(EvalApi& api, Session& session) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 6. GetByteTableInfo — DataStore Properties\n";
    std::cout << "══════════════════════════════════════════\n";

    ByteTableInfo info;
    RawResult raw;
    auto r = api.getByteTableInfo(session, info, raw);
    step("getByteTableInfo", r);
    if (r.ok()) {
        std::cout << "  Table UID:  0x" << std::hex << info.tableUid << std::dec << "\n";
        std::cout << "  Max Size:   " << info.maxSize << " bytes\n";
        std::cout << "  Used Size:  " << info.usedSize << " bytes\n";
    }
}

// ════════════════════════════════════════════════════════
//  7. TcgWrite / TcgRead / TcgCompare — DataStore I/O
// ════════════════════════════════════════════════════════

/// @scenario DataStore 입출력 작업 (Write/Read/Compare)
/// @precondition LockingSP에 인증된 세션이 열려 있고 DataStore 테이블에 쓰기 권한이 있어야 함
/// @steps
///   1. tcgWriteDataStore로 offset=0에 16바이트 테스트 패턴 기록
///   2. tcgReadDataStore로 offset=0에서 16바이트 읽기
///   3. tcgCompare로 offset=32에 8바이트 Write+Read+비교 수행
///   4. tcgWrite(generic)로 임의 테이블 UID에 offset=64, 4바이트 기록
///   5. tcgRead(generic)로 offset=64에서 4바이트 읽기
/// @expected
///   - Write 성공 후 Read 결과가 기록한 데이터와 일치
///   - Compare 매치 여부(compareMatch) 정상 확인
///   - Generic Write/Read도 정상 동작
static void demo_tcgDataOps(EvalApi& api, Session& session) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 7. TcgWrite / TcgRead / TcgCompare\n";
    std::cout << "══════════════════════════════════════════\n";

    RawResult raw;

    // Write test pattern to DataStore at offset 0
    Bytes writeData = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01,
                       0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

    std::cout << "\n  --- TcgWrite (DataStore, offset=0, 16 bytes) ---\n";
    auto r = api.tcgWriteDataStore(session, 0, writeData, raw);
    step("tcgWriteDataStore", r);
    printHex("Written", writeData);

    // Read back
    std::cout << "\n  --- TcgRead (DataStore, offset=0, 16 bytes) ---\n";
    DataOpResult readResult;
    r = api.tcgReadDataStore(session, 0, 16, readResult);
    step("tcgReadDataStore", r);
    if (r.ok()) {
        printHex("Read back", readResult.data);
    }

    // Compare (write + read + verify)
    std::cout << "\n  --- TcgCompare (DataStore, offset=32, 8 bytes) ---\n";
    Bytes compareData = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    DataOpResult cmpResult;
    r = api.tcgCompare(session, uid::TABLE_DATASTORE, 32, compareData, cmpResult);
    step("tcgCompare", r);
    if (r.ok()) {
        std::cout << "  Match: " << (cmpResult.compareMatch ? "YES" : "NO") << "\n";
        printHex("Expected", compareData);
        printHex("Actual  ", cmpResult.data);
    }

    // Write to arbitrary table UID (generic tcgWrite)
    std::cout << "\n  --- TcgWrite (generic, custom table) ---\n";
    Bytes customData = {0xAA, 0xBB, 0xCC, 0xDD};
    r = api.tcgWrite(session, uid::TABLE_DATASTORE, 64, customData, raw);
    step("tcgWrite(generic)", r);

    // Read from arbitrary table UID (generic tcgRead)
    std::cout << "\n  --- TcgRead (generic, offset=64, 4 bytes) ---\n";
    DataOpResult genRead;
    r = api.tcgRead(session, uid::TABLE_DATASTORE, 64, 4, genRead);
    step("tcgRead(generic)", r);
    if (r.ok()) {
        printHex("Read", genRead.data);
    }
}

// ════════════════════════════════════════════════════════
//  8. SetMBRControlTableNsidOne
// ════════════════════════════════════════════════════════

/// @scenario MBR Control 테이블 NSID=1 설정 및 검증
/// @precondition LockingSP에 인증된 세션이 열려 있고 MBR Control 테이블 쓰기 권한이 있어야 함
/// @steps
///   1. api.setMbrControlNsidOne() 호출로 MBR Control NSID=1 설정
///   2. tableGetAll(MBRCTRL_SET)로 MBR 상태 검증
///   3. MBR_ENABLE, MBR_DONE 컬럼 값 확인
/// @expected
///   - MBR 상태 변경 성공
///   - 검증 결과 MBR_ENABLE, MBR_DONE 값이 설정과 일치
static void demo_setMbrNsidOne(EvalApi& api, Session& session) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 8. SetMBRControlTableNsidOne\n";
    std::cout << "══════════════════════════════════════════\n";

    RawResult raw;
    auto r = api.setMbrControlNsidOne(session, raw);
    step("setMbrControlNsidOne", r);

    // Verify: read MBR control
    std::cout << "\n  --- Verify MBR state ---\n";
    TableResult mbrState;
    r = api.tableGetAll(session, uid::MBRCTRL_SET, mbrState);
    if (r.ok()) {
        for (auto& [col, tok] : mbrState.columns) {
            if (col == uid::col::MBR_ENABLE) {
                std::cout << "    MBR_ENABLE = " << tok.getUint() << "\n";
            }
            if (col == uid::col::MBR_DONE) {
                std::cout << "    MBR_DONE   = " << tok.getUint() << "\n";
            }
        }
    }
}

// ════════════════════════════════════════════════════════
//  9. Full eval flow with fault injection between steps
// ════════════════════════════════════════════════════════

/// @scenario 분리된 세션 단계 사이 Fault 주입
/// @precondition TestContext가 활성화 가능하고 NVMe 디바이스가 열려 있어야 함
/// @steps
///   1. TestContext 활성화 및 TestSession 생성
///   2. FaultBuilder로 AfterIfRecv 시점에 SyncSession 응답 바이트 8을 0xFF로 손상 설정
///   3. sendStartSession으로 StartSession 요청 전송
///   4. (Send와 Recv 사이 — Fault가 무장되어 다음 IF-RECV 시 발동)
///   5. recvSyncSession으로 손상된 SyncSession 응답 수신 시도
///   6. 트레이스 로그 및 카운터 확인
/// @expected
///   - SyncSession 응답이 손상되어 ComPacket 파싱 에러 발생
///   - 트레이스에 Fault 발동 기록이 남음
///   - transport.recv 카운터로 수신 횟수 확인 가능
static void demo_faultBetweenSteps(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId) {
    std::cout << "\n══════════════════════════════════════════\n";
    std::cout << " 9. Fault Injection Between Split Session Steps\n";
    std::cout << "══════════════════════════════════════════\n";

    auto& tc = TestContext::instance();
    tc.enable();
    TestSession ts("session_fault");

    // Arm fault: corrupt byte 8 of the SyncSession response (AfterIfRecv)
    ts.fault(
        FaultBuilder("corrupt_sync")
            .at(FaultPoint::AfterIfRecv)
            .corrupt(8, 0xFF)
            .once()
    );

    // Send StartSession
    StartSessionParams params;
    params.spUid = uid::SP_ADMIN;
    params.write = false;

    Bytes sent;
    auto r = api.sendStartSession(transport, comId, params, sent);
    step("sendStartSession", r);

    // Between Send and Recv — fault is armed and will fire on the next IF-RECV

    SyncSessionResult sr;
    r = api.recvSyncSession(transport, comId, sr);
    step("recvSyncSession (corrupted)", r);

    // Dump trace to see fault firing
    for (auto& ev : ts.trace()) {
        std::cout << "  [trace] " << ev.tag << ": " << ev.detail << "\n";
    }
    std::cout << "  transport.recv count = " << ts.counter("transport.recv") << "\n";

    tc.disable();
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    std::string device = (argc > 1) ? argv[1] : "/dev/nvme0";
    std::string sidPw  = (argc > 2) ? argv[2] : "";

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return 1;
    }

    EvalApi api;

    // ── Phase 1: No session required ──

    demo_getTcgOption(api, transport);
    demo_getSecurityStatus(api, transport);
    demo_getSecurityFeatures(api, transport);

    // Get ComID for session operations
    TcgOption opt;
    api.getTcgOption(transport, opt);
    uint16_t comId = opt.baseComId;

    if (comId == 0) {
        std::cerr << "No valid ComID found. Drive may not support TCG.\n";
        return 1;
    }

    // ── Phase 2: Split session demo ──

    demo_splitSession(api, transport, comId);

    // ── Phase 3: Session-based operations (require auth) ──

    if (!sidPw.empty()) {
        std::cout << "\n\n*** Session-based demos (authenticated) ***\n";

        // Exchange properties first
        PropertiesResult props;
        api.exchangeProperties(transport, comId, props);

        // Open a managed session to Locking SP as Admin1
        Session session(transport, comId);
        session.setMaxComPacketSize(props.tperMaxComPacketSize);

        Bytes credential = HashPassword::passwordToBytes(sidPw);
        StartSessionResult ssr;
        auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                           uid::AUTH_ADMIN1, credential, ssr);
        if (r.ok()) {
            demo_getLockingInfo(api, session);
            demo_getByteTableInfo(api, session);
            demo_tcgDataOps(api, session);
            demo_setMbrNsidOne(api, session);

            api.closeSession(session);
        } else {
            std::cout << "\n  Failed to open Locking SP session: " << r.message() << "\n";
            std::cout << "  Skipping session-based demos.\n";
        }
    } else {
        std::cout << "\n  (Pass SID password as 2nd arg to run session-based demos)\n";
    }

    // ── Phase 4: Fault injection demo ──

    demo_faultBetweenSteps(api, transport, comId);

    libsed::shutdown();
    std::cout << "\n=== Done ===\n";
    return 0;
}
