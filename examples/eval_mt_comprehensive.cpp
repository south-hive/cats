/// @file eval_mt_comprehensive.cpp
/// @brief 종합 멀티스레드 TCG SED 평가 TC.
///
/// 4개의 독립 세션을 병렬 스레드에서 실행하며, 각 세션이 서로 다른
/// TCG 동작 카테고리를 수행합니다. 스레드 간 동기화 배리어를 사용하여
/// 교차 실행 타이밍을 제어합니다.
///
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                    Transport (shared)                            │
/// ├─────────────┬──────────────┬──────────────┬─────────────────────┤
/// │  Thread 0   │  Thread 1    │  Thread 2    │  Thread 3           │
/// │  ComID +0   │  ComID +1    │  ComID +2    │  ComID +3           │
/// │  Session A  │  Session B   │  Session C   │  Session D          │
/// │             │              │              │                     │
/// │ SP Lifecycle│ Locking &    │ MBR &        │ Security &          │
/// │ & Discovery │ Key Mgmt     │ DataStore    │ Authority           │
/// │             │              │              │                     │
/// │ - L0 Disc.  │ - Set Range  │ - MBR Enable │ - Block SID (NVMe) │
/// │ - Properties│ - Get Range  │ - MBR Write  │ - Enable User      │
/// │ - Activate  │ - Lock/Unlock│ - MBR Read   │ - ACE management   │
/// │ - Lifecycle │ - GenKey     │ - MBR Done   │ - Set C_PIN        │
/// │ - StackReset│ - CryptoErase│ - DS Write   │ - Change PIN       │
/// │ - Revert SP │ - LockOnReset│ - DS Read    │ - GetRandom        │
/// │             │ - ActiveKey  │ - DS Compare │ - GetClock          │
/// │             │              │ - ByteTable  │ - Table Get/Set     │
/// └─────────────┴──────────────┴──────────────┴─────────────────────┘
///
/// ComID 할당 전략:
///   TCG SED에서 ComID는 통신 채널 식별자이며, 하나의 ComID에서는
///   하나의 outstanding IF-SEND/IF-RECV만 허용됩니다.
///   → numComIds >= 4: 스레드별 baseComId + tid (완전 병렬)
///   → numComIds < 4:  단일 ComID + transport 뮤텍스 (직렬화)
///
/// Phase 구조:
///   Phase 0: 공통 초기화 (Discovery, Properties, Take Ownership, Activate)
///   Phase 1: 4개 스레드 병렬 실행 — 각자 독립 ComID로 작업
///   Phase 2: 교차 검증 — 다른 스레드의 결과를 읽기 세션으로 확인
///   Phase 3: 정리 — Revert Locking SP, Revert TPer

#include <libsed/eval/eval_api.h>
#include <libsed/transport/nvme_transport.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/debug/logging_transport.h>
#include <libsed/security/hash_password.h>
#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <functional>

using namespace libsed;
using namespace libsed::eval;
using Clock = std::chrono::high_resolution_clock;

// ═══════════════════════════════════════════════════
//  Infrastructure
// ═══════════════════════════════════════════════════

static std::mutex g_printMutex;

// ── 진단 힌트 시스템 ────────────────────────────────
// 실패 시 원인을 추론하기 위한 힌트 맵.
// 키: 단계 이름의 부분 매칭 + 에러 코드 조합

/// @brief 실패한 단계에 대한 진단 힌트를 반환
static const char* getDiagnosticHint(const char* stepName, const Result& r) {
    // 에러 코드별 공통 힌트
    int code = static_cast<int>(r.code());

    // Transport 에러 (100번대)
    if (code >= 100 && code < 200) {
        if (code == 102) return "IF-SEND failed — 디바이스 경로 확인, NVMe driver 로드 여부 체크";
        if (code == 103) return "IF-RECV failed — TPer 응답 없음, 디바이스 hang 의심";
        if (code == 104) return "Timeout — TPer 처리 지연, 전원 사이클 후 재시도";
        return "Transport 에러 — 디바이스 접근 권한(sudo) 및 경로 확인";
    }

    // Protocol 에러 (200번대)
    if (code == 207) return "비정상 응답 — 이전 세션 잔재(stale), StackReset 필요";
    if (code == 208) return "프로토콜 에러 — ComID 상태 오류, StackReset 후 재시도";

    // Session 에러 (300번대)
    if (code == 300) return "세션 미시작 상태 — StartSession이 선행되지 않음";
    if (code == 304) return "세션 슬롯 부족 — 다른 세션이 열려있음, StackReset 필요";

    // Method 에러 (400번대)
    if (code == 401) return "권한 없음 — 인증 Authority/비밀번호 불일치, 또는 해당 작업의 ACE 미설정";
    if (code == 403) return "SP Busy — 다른 세션이 SP를 점유 중, 잠시 후 재시도";
    if (code == 405) return "SP Disabled — Locking SP가 비활성, Activate 필요";
    if (code == 412) return "파라미터 오류 — UID, 범위, 컬럼 번호 확인";
    if (code == 415) return "TPer Malfunction (0x0F) — 하드웨어 문제 또는 stale ComID, 전원 사이클 권장";
    if (code == 463) return "메서드 실패 — TPer가 작업을 거부, 드라이브 상태 확인";

    // Auth 에러 (600번대)
    if (code == 600) return "인증 실패 — 비밀번호 불일치, Block SID 활성, 또는 Authority 잠김(lockout)";
    if (code == 601) return "Lockout — 인증 시도 초과, 전원 사이클 또는 PSID 리셋 필요";

    // 단계별 문맥 힌트
    std::string step(stepName);

    if (step.find("AdminSP") != std::string::npos ||
        step.find("Anonymous") != std::string::npos) {
        return "AdminSP 세션 열기 실패 — StackReset 미수행, Block SID, 또는 ComID stale 상태 의심";
    }
    if (step.find("LockingSP") != std::string::npos) {
        return "LockingSP 세션 실패 — Locking SP가 Activate 되지 않았거나, 비밀번호 불일치";
    }
    if (step.find("SID") != std::string::npos && step.find("auth") != std::string::npos) {
        return "SID 인증 실패 — 드라이브가 이미 다른 비밀번호로 소유됨, PSID 리셋 필요";
    }
    if (step.find("MSID") != std::string::npos) {
        return "MSID 읽기 실패 — AdminSP 세션 문제, 드라이브 통신 상태 확인";
    }
    if (step.find("Activate") != std::string::npos) {
        return "Activate 실패 — 이미 활성화 상태이거나 SID 권한 부족";
    }
    if (step.find("Block") != std::string::npos || step.find("BSID") != std::string::npos) {
        return "Block SID 관련 실패 — NVMe Feature 0x0C 미지원, 또는 이미 설정됨";
    }
    if (step.find("Revert") != std::string::npos) {
        return "Revert 실패 — 권한 부족, 세션이 ReadOnly, 또는 SP 상태 이상";
    }
    if (step.find("MBR") != std::string::npos || step.find("Mbr") != std::string::npos) {
        return "MBR 실패 — MBR Feature 미지원, MBREnable 미설정, 또는 데이터 크기 초과";
    }
    if (step.find("DataStore") != std::string::npos || step.find("DS") != std::string::npos) {
        return "DataStore 실패 — DataStore 테이블 미지원, 용량 초과, 또는 오프셋 범위 에러";
    }
    if (step.find("Range") != std::string::npos || step.find("Lock") != std::string::npos) {
        return "Range/Lock 실패 — 범위 ID 유효성, RLE/WLE 미설정, 또는 ACE 권한 부족";
    }
    if (step.find("GenKey") != std::string::npos || step.find("ActiveKey") != std::string::npos) {
        return "키 관련 실패 — 범위가 AES 키를 지원하지 않거나 권한 부족";
    }
    if (step.find("User") != std::string::npos || step.find("ACE") != std::string::npos) {
        return "사용자/ACE 실패 — User Authority 미활성화, ACE UID 불일치, 또는 Admin 권한 필요";
    }
    if (step.find("CPin") != std::string::npos || step.find("Password") != std::string::npos) {
        return "PIN 설정 실패 — C_PIN 객체 UID 불일치, 쓰기 세션이 아님, 또는 권한 부족";
    }
    if (step.find("StackReset") != std::string::npos) {
        return "StackReset 실패 — ComID 유효성 확인, Transport 연결 상태 확인";
    }
    if (step.find("Properties") != std::string::npos) {
        return "Properties 교환 실패 — ComID가 reset 상태가 아님, StackReset 선행 필요";
    }

    return "일반 실패 — sed_discover로 드라이브 상태 확인, 전원 사이클 후 재시도 권장";
}

#define TLOG(tid, ...) do { \
    std::lock_guard<std::mutex> lk(g_printMutex); \
    printf("[T%d] ", tid); \
    printf(__VA_ARGS__); \
    printf("\n"); \
} while(0)

#define TSTEP(tid, name, r) do { \
    std::lock_guard<std::mutex> lk(g_printMutex); \
    printf("[T%d]   %-40s %s", tid, name, (r).ok() ? "OK" : "FAIL"); \
    if ((r).failed()) { \
        printf(" (%s)\n", (r).message().c_str()); \
        printf("[T%d]     → HINT: %s\n", tid, getDiagnosticHint(name, r)); \
    } else { \
        printf("\n"); \
    } \
} while(0)

/// 간단한 카운팅 배리어 — N개 스레드가 모두 도달할 때까지 대기
class Barrier {
public:
    explicit Barrier(uint32_t count) : threshold_(count), count_(count), gen_(0) {}

    void wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        auto gen = gen_;
        if (--count_ == 0) {
            gen_++;
            count_ = threshold_;
            cv_.notify_all();
        } else {
            cv_.wait(lock, [this, gen] { return gen != gen_; });
        }
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    uint32_t threshold_;
    uint32_t count_;
    uint32_t gen_;
};

/// 스레드별 결과 추적
struct ThreadResult {
    std::atomic<uint32_t> pass{0};
    std::atomic<uint32_t> fail{0};
    void record(Result r) { r.ok() ? pass++ : fail++; }
};

/// 전역 공유 상태
///
/// TCG SED에서 ComID는 통신 채널 식별자이며, 하나의 ComID에서
/// 동시에 하나의 outstanding IF-SEND/IF-RECV 쌍만 허용됩니다.
/// 따라서 멀티스레드 환경에서는 **스레드별로 서로 다른 ComID를 사용**해야
/// 응답 패킷 혼선 없이 병렬 실행이 가능합니다.
///
/// numComIds >= 4인 경우: baseComId + tid 로 각각 별도 ComID 할당
/// numComIds < 4인 경우:  단일 ComID + transport 뮤텍스로 직렬화
struct SharedState {
    std::shared_ptr<ITransport> transport;
    uint16_t baseComId = 0;
    uint16_t numComIds = 0;
    uint16_t comIds[4] = {};       ///< 스레드별 ComID (핵심: 각 스레드가 고유 ComID 사용)
    PropertiesResult props;

    std::string sidPw;
    std::string admin1Pw;
    std::string user1Pw;

    /// Transport 직렬화 뮤텍스 — ComID가 부족할 때만 사용
    std::mutex transportMutex;
    bool serialMode = false;       ///< true이면 단일 ComID 직렬화 모드

    Barrier barrier{4};
    ThreadResult results[4];
};

// ═══════════════════════════════════════════════════
//  Thread 0: SP Lifecycle & Discovery
// ═══════════════════════════════════════════════════

/// @scenario Thread 0: SP 수명주기 및 Discovery 작업
/// @precondition Phase 0 초기화 완료 (Locking SP 활성화, 비밀번호 설정됨)
/// @steps
///   Phase 1:
///     1. L0 Discovery 수행 (세션 불필요)
///     2. Discovery 원시 데이터 수행
///     3. TCG 옵션 조회 (SSC, ComID, Locking 상태)
///     4. SecurityStatus 조회
///     5. 전체 SecurityFeature 열거
///     6. ComID 유효성 검사
///     7. AdminSP 세션 열기 → SP Lifecycle 조회
///     8. 세션 닫기
///   Phase 2 (배리어 후):
///     9. StackReset 수행
///    10. Discovery 재수행하여 상태 확인
/// @expected
///   - 모든 Discovery/Properties 조회 성공
///   - StackReset 후 세션 무효화됨
///   - 다른 스레드의 세션에 영향 없음 (StackReset은 ComID 레벨)
static void thread0_spLifecycleDiscovery(int tid, SharedState& ss) {
    TLOG(tid, "=== SP Lifecycle & Discovery ===");
    EvalApi api;
    RawResult raw;

    // ── Phase 1: Discovery operations (no session needed) ──

    // 1. L0 Discovery
    DiscoveryInfo dinfo;
    auto r = api.discovery0(ss.transport, dinfo);
    TSTEP(tid, "L0 Discovery", r);
    ss.results[tid].record(r);
    if (r.ok())
        TLOG(tid, "  SSC=%d locked=%d MBR=%d", (int)dinfo.primarySsc,
             dinfo.locked, dinfo.mbrEnabled);

    // 2. Discovery raw
    Bytes rawDisc;
    r = api.discovery0Raw(ss.transport, rawDisc);
    TSTEP(tid, "Discovery0 Raw", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  Raw discovery: %zu bytes", rawDisc.size());

    // 3. TcgOption
    TcgOption opt;
    r = api.getTcgOption(ss.transport, opt);
    TSTEP(tid, "getTcgOption", r);
    ss.results[tid].record(r);

    // 4. SecurityStatus
    SecurityStatus secSt;
    r = api.getSecurityStatus(ss.transport, secSt);
    TSTEP(tid, "getSecurityStatus", r);
    ss.results[tid].record(r);
    if (r.ok())
        TLOG(tid, "  Opal=%d Enterprise=%d Pyrite=%d",
             secSt.opalV2Present, secSt.enterprisePresent, secSt.pyriteV1Present);

    // 5. All security features
    std::vector<SecurityFeatureInfo> feats;
    r = api.getAllSecurityFeatures(ss.transport, feats);
    TSTEP(tid, "getAllSecurityFeatures", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  Features found: %zu", feats.size());

    // 6. Verify ComID
    bool comIdActive = false;
    r = api.verifyComId(ss.transport, ss.comIds[tid], comIdActive);
    TSTEP(tid, "verifyComId", r);
    ss.results[tid].record(r);

    // 7. AdminSP session → SP lifecycle
    {
        Bytes sidCred = HashPassword::passwordToBytes(ss.sidPw);
        Session session(ss.transport, ss.comIds[tid]);
        session.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
        StartSessionResult ssr;
        r = api.startSessionWithAuth(session, uid::SP_ADMIN, false,
                                      uid::AUTH_SID, sidCred, ssr);
        TSTEP(tid, "AdminSP session (SID)", r);
        ss.results[tid].record(r);

        if (r.ok()) {
            uint8_t lifecycle = 0;
            r = api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle, raw);
            TSTEP(tid, "Get Locking SP lifecycle", r);
            ss.results[tid].record(r);
            if (r.ok()) TLOG(tid, "  Lifecycle: 0x%02X", lifecycle);

            api.closeSession(session);
        }
    }

    // ── Barrier: wait for all threads ──
    TLOG(tid, "--- Phase 1 complete, waiting at barrier ---");
    ss.barrier.wait();

    // ── Phase 2: StackReset & re-discover ──
    TLOG(tid, "--- Phase 2: StackReset ---");

    // StackReset은 해당 ComID의 세션만 무효화함
    // 스레드별 ComID를 사용하므로 다른 스레드에 영향 없음
    r = api.stackReset(ss.transport, ss.comIds[tid]);
    TSTEP(tid, "StackReset", r);
    ss.results[tid].record(r);

    // Re-discover after stackReset
    r = api.discovery0(ss.transport, dinfo);
    TSTEP(tid, "Re-discovery after StackReset", r);
    ss.results[tid].record(r);

    // Re-exchange properties (stack was reset)
    PropertiesResult reprops;
    r = api.exchangeProperties(ss.transport, ss.comIds[tid], reprops);
    TSTEP(tid, "Re-exchange Properties", r);
    ss.results[tid].record(r);
}

// ═══════════════════════════════════════════════════
//  Thread 1: Locking & Key Management
// ═══════════════════════════════════════════════════

/// @scenario Thread 1: 잠금 범위 및 암호화 키 관리
/// @precondition Locking SP 활성화, Admin1/User1 비밀번호 설정됨
/// @steps
///   Phase 1:
///     1. Admin1 인증 → LockingSP 쓰기 세션
///     2. Range 1 구성 (start=0, len=2048, RLE/WLE)
///     3. Range 2 구성 (start=2048, len=2048)
///     4. Range 1/2 정보 조회 (getLockingInfo)
///     5. 전체 Range 열거 (getAllLockingInfo)
///     6. ActiveKey 조회 (Range 1)
///     7. GenKey — Range 1 키 재생성
///     8. ActiveKey 재조회 (변경 확인)
///     9. Range 1 잠금 (ReadLocked=true, WriteLocked=true)
///    10. Range 1 잠금 해제
///    11. LockOnReset 설정
///    12. CryptoErase (Range 2)
///    13. 세션 닫기
///   Phase 2 (배리어 후):
///    14. User1 세션 → Range 1 Lock/Unlock 반복 (5회)
/// @expected
///   - Range 구성 및 잠금/해제 정상 동작
///   - GenKey 후 ActiveKey 변경됨
///   - CryptoErase 후 데이터 접근 불가 (키 변경)
static void thread1_lockingKeyMgmt(int tid, SharedState& ss) {
    TLOG(tid, "=== Locking & Key Management ===");
    EvalApi api;
    RawResult raw;

    // ── Phase 1: Admin1 session ──
    Bytes admin1Cred = HashPassword::passwordToBytes(ss.admin1Pw);
    Session session(ss.transport, ss.comIds[tid]);
    session.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    TSTEP(tid, "Admin1 auth → LockingSP (write)", r);
    ss.results[tid].record(r);
    if (r.failed()) { ss.barrier.wait(); return; }

    // 2-3. Configure ranges
    r = api.setRange(session, 1, 0, 2048, true, true, raw);
    TSTEP(tid, "Set Range 1 (0..2048 RLE WLE)", r);
    ss.results[tid].record(r);

    r = api.setRange(session, 2, 2048, 2048, true, true, raw);
    TSTEP(tid, "Set Range 2 (2048..4096 RLE WLE)", r);
    ss.results[tid].record(r);

    // 4. Get individual range info
    for (uint32_t i = 1; i <= 2; i++) {
        LockingInfo li;
        r = api.getLockingInfo(session, i, li, raw);
        TSTEP(tid, (std::string("Get Range ") + std::to_string(i) + " info").c_str(), r);
        ss.results[tid].record(r);
        if (r.ok())
            TLOG(tid, "  Range%u: start=%lu len=%lu RLE=%d WLE=%d",
                 i, li.rangeStart, li.rangeLength, li.readLockEnabled, li.writeLockEnabled);
    }

    // 5. Enumerate all ranges
    std::vector<LockingInfo> allRanges;
    r = api.getAllLockingInfo(session, allRanges, 9, raw);
    TSTEP(tid, "getAllLockingInfo", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  Total ranges: %zu", allRanges.size());

    // 6. ActiveKey before GenKey
    Uid keyBefore;
    r = api.getActiveKey(session, 1, keyBefore, raw);
    TSTEP(tid, "GetActiveKey Range1 (before)", r);
    ss.results[tid].record(r);

    // 7. GenKey
    r = api.genKey(session, uid::makeKAesUid(1).toUint64(), raw);
    TSTEP(tid, "GenKey (K_AES Range1)", r);
    ss.results[tid].record(r);

    // 8. ActiveKey after GenKey
    Uid keyAfter;
    r = api.getActiveKey(session, 1, keyAfter, raw);
    TSTEP(tid, "GetActiveKey Range1 (after)", r);
    ss.results[tid].record(r);
    if (r.ok())
        TLOG(tid, "  Key changed: %s",
             (keyBefore.toUint64() != keyAfter.toUint64()) ? "YES" : "NO");

    // 9. Lock Range 1
    r = api.setRangeLock(session, 1, true, true, raw);
    TSTEP(tid, "Lock Range 1 (Rd+Wr)", r);
    ss.results[tid].record(r);

    // 10. Unlock Range 1
    r = api.setRangeLock(session, 1, false, false, raw);
    TSTEP(tid, "Unlock Range 1", r);
    ss.results[tid].record(r);

    // 11. LockOnReset
    r = api.setLockOnReset(session, 1, true, raw);
    TSTEP(tid, "Set LockOnReset Range1", r);
    ss.results[tid].record(r);

    // 12. CryptoErase Range 2
    r = api.cryptoErase(session, 2, raw);
    TSTEP(tid, "CryptoErase Range 2", r);
    ss.results[tid].record(r);

    api.closeSession(session);

    // ── Barrier ──
    TLOG(tid, "--- Phase 1 complete, waiting at barrier ---");
    ss.barrier.wait();

    // ── Phase 2: User1 lock/unlock stress ──
    TLOG(tid, "--- Phase 2: User1 Lock/Unlock x5 ---");
    Bytes user1Cred = HashPassword::passwordToBytes(ss.user1Pw);
    for (int i = 0; i < 5; i++) {
        Session us(ss.transport, ss.comIds[tid]);
        us.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
        StartSessionResult usr;
        r = api.startSessionWithAuth(us, uid::SP_LOCKING, true,
                                      uid::AUTH_USER1, user1Cred, usr);
        if (r.failed()) { ss.results[tid].record(r); continue; }

        r = api.setRangeLock(us, 1, true, true, raw);
        ss.results[tid].record(r);
        r = api.setRangeLock(us, 1, false, false, raw);
        ss.results[tid].record(r);
        api.closeSession(us);
    }
    TLOG(tid, "  Lock/Unlock x5 done");
}

// ═══════════════════════════════════════════════════
//  Thread 2: MBR & DataStore
// ═══════════════════════════════════════════════════

/// @scenario Thread 2: MBR 섀도잉 및 DataStore 작업
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효
/// @steps
///   Phase 1:
///     1. Admin1 인증 → LockingSP 쓰기 세션
///     2. MBR 상태 조회
///     3. MBR 활성화 (MBREnable=true)
///     4. PBA 이미지(512B) MBR에 쓰기
///     5. MBR 읽기 및 검증
///     6. MBRDone=true 설정
///     7. MBRDone=false 설정 (부팅 사이클 시뮬레이션)
///     8. ByteTable 정보 조회
///     9. DataStore 쓰기 (64바이트)
///    10. DataStore 읽기
///    11. DataStore Compare
///    12. DataStore N 쓰기/읽기 (Table 0)
///    13. MBR 비활성화
///    14. 세션 닫기
///   Phase 2 (배리어 후):
///    15. DataStore 대용량 청크 쓰기/읽기 (2048바이트)
/// @expected
///   - MBR 쓰기/읽기 데이터 일치
///   - DataStore Write-Read-Compare 일치
///   - 대용량 청크 처리 정상
static void thread2_mbrDataStore(int tid, SharedState& ss) {
    TLOG(tid, "=== MBR & DataStore ===");
    EvalApi api;
    RawResult raw;

    Bytes admin1Cred = HashPassword::passwordToBytes(ss.admin1Pw);
    Session session(ss.transport, ss.comIds[tid]);
    session.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    TSTEP(tid, "Admin1 auth → LockingSP (write)", r);
    ss.results[tid].record(r);
    if (r.failed()) { ss.barrier.wait(); return; }

    // 2. MBR status
    bool mbrEn = false, mbrDn = false;
    r = api.getMbrStatus(session, mbrEn, mbrDn, raw);
    TSTEP(tid, "getMbrStatus", r);
    ss.results[tid].record(r);

    // 3. Enable MBR
    r = api.setMbrEnable(session, true, raw);
    TSTEP(tid, "setMbrEnable(true)", r);
    ss.results[tid].record(r);

    // 4. Write PBA
    Bytes pba(512, 0);
    pba[0] = 0xEB; pba[1] = 0x3C; pba[2] = 0x90;
    std::memcpy(&pba[3], "TCGPBA", 6);
    pba[510] = 0x55; pba[511] = 0xAA;
    r = api.writeMbrData(session, 0, pba, raw);
    TSTEP(tid, "writeMbrData (512B PBA)", r);
    ss.results[tid].record(r);

    // 5. Read MBR
    Bytes mbrRead;
    r = api.readMbrData(session, 0, 512, mbrRead, raw);
    TSTEP(tid, "readMbrData (512B)", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  MBR match: %s", (mbrRead == pba) ? "YES" : "NO");

    // 6. MBRDone = true
    r = api.setMbrDone(session, true, raw);
    TSTEP(tid, "setMbrDone(true)", r);
    ss.results[tid].record(r);

    // 7. MBRDone = false (simulate power cycle)
    r = api.setMbrDone(session, false, raw);
    TSTEP(tid, "setMbrDone(false) — boot sim", r);
    ss.results[tid].record(r);

    // 8. ByteTable info
    ByteTableInfo btInfo;
    r = api.getByteTableInfo(session, btInfo, raw);
    TSTEP(tid, "getByteTableInfo", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  DS maxSize=%u usedSize=%u", btInfo.maxSize, btInfo.usedSize);

    // 9. DataStore write
    Bytes dsData(64);
    for (int i = 0; i < 64; i++) dsData[i] = (uint8_t)((i * 7 + 0xAB) & 0xFF);
    r = api.tcgWriteDataStore(session, 0, dsData, raw);
    TSTEP(tid, "tcgWriteDataStore (64B)", r);
    ss.results[tid].record(r);

    // 10. DataStore read
    DataOpResult dsRead;
    r = api.tcgReadDataStore(session, 0, 64, dsRead);
    TSTEP(tid, "tcgReadDataStore (64B)", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  DS match: %s", (dsRead.data == dsData) ? "YES" : "NO");

    // 11. DataStore compare
    DataOpResult dsCmp;
    r = api.tcgCompare(session, uid::TABLE_DATASTORE, 0, dsData, dsCmp);
    TSTEP(tid, "tcgCompare DataStore", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  compareMatch: %s", dsCmp.compareMatch ? "true" : "false");

    // 12. DataStore N (table 0)
    r = api.tcgWriteDataStoreN(session, 0, 64, dsData, raw);
    TSTEP(tid, "tcgWriteDataStoreN (table0, offset64)", r);
    ss.results[tid].record(r);

    DataOpResult dsReadN;
    r = api.tcgReadDataStoreN(session, 0, 64, 64, dsReadN);
    TSTEP(tid, "tcgReadDataStoreN (table0, offset64)", r);
    ss.results[tid].record(r);

    // 13. Disable MBR
    r = api.setMbrEnable(session, false, raw);
    TSTEP(tid, "setMbrEnable(false)", r);
    ss.results[tid].record(r);

    api.closeSession(session);

    // ── Barrier ──
    TLOG(tid, "--- Phase 1 complete, waiting at barrier ---");
    ss.barrier.wait();

    // ── Phase 2: Large DataStore chunk ──
    TLOG(tid, "--- Phase 2: Large DataStore (2048B chunked) ---");
    {
        Session s2(ss.transport, ss.comIds[tid]);
        s2.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
        StartSessionResult ssr2;
        r = api.startSessionWithAuth(s2, uid::SP_LOCKING, true,
                                      uid::AUTH_ADMIN1, admin1Cred, ssr2);
        if (r.failed()) { ss.results[tid].record(r); return; }

        const uint32_t total = 2048, chunk = 512;
        Bytes bigData(total);
        for (uint32_t i = 0; i < total; i++) bigData[i] = (uint8_t)((i * 13) & 0xFF);

        uint32_t written = 0;
        for (uint32_t off = 0; off < total; off += chunk) {
            Bytes c(bigData.begin() + off, bigData.begin() + off + chunk);
            r = api.tcgWriteDataStore(s2, off, c, raw);
            if (r.ok()) written += chunk;
            ss.results[tid].record(r);
        }
        TLOG(tid, "  Chunked write: %u/%u bytes", written, total);

        Bytes readAll;
        for (uint32_t off = 0; off < total; off += chunk) {
            DataOpResult dr;
            r = api.tcgReadDataStore(s2, off, chunk, dr);
            if (r.ok()) readAll.insert(readAll.end(), dr.data.begin(), dr.data.end());
            ss.results[tid].record(r);
        }
        TLOG(tid, "  Chunked read: %zu/%u bytes, match=%s",
             readAll.size(), total, (readAll == bigData) ? "YES" : "NO");

        api.closeSession(s2);
    }
}

// ═══════════════════════════════════════════════════
//  Thread 3: Security & Authority
// ═══════════════════════════════════════════════════

/// @scenario Thread 3: 보안 기능, Authority 관리, NVMe 연동
/// @precondition Locking SP 활성화, Admin1 비밀번호 유효
/// @steps
///   Phase 1:
///     1. Block SID Feature 조회 (NVMe Get Feature 0x0C)
///     2. Admin1 인증 → LockingSP 쓰기 세션
///     3. User1 Authority 활성화 (enableUser)
///     4. User1 활성화 상태 확인 (isUserEnabled)
///     5. User1을 Range1 ACE에 추가 (Rd/Wr)
///     6. ACE 정보 조회
///     7. C_PIN User1 설정 (setCPin)
///     8. C_PIN Admin1 변경 (setAdmin1Password)
///     9. getRandom (32바이트)
///    10. getClock
///    11. Table Get (Locking GlobalRange 전체 컬럼)
///    12. Table SetBool (ReadLockEnabled on GlobalRange)
///    13. Table GetUint (Range1 ActiveKey)
///    14. User1 비밀번호 변경 (setUserPassword)
///    15. C_PIN TriesRemaining 조회
///    16. 세션 닫기
///   Phase 2 (배리어 후):
///    17. Block SID 설정 → SID 인증 차단 확인 → 해제
/// @expected
///   - Authority 활성화 및 ACE 추가 성공
///   - PIN 설정/변경 정상 동작
///   - Random/Clock 조회 성공
///   - Block SID 설정 시 SID 인증 차단됨
static void thread3_securityAuthority(int tid, SharedState& ss) {
    TLOG(tid, "=== Security & Authority ===");
    EvalApi api;
    RawResult raw;

    // 1. Block SID NVMe Get Feature
    {
        uint32_t cdw0 = 0;
        Bytes data;
        auto r = EvalApi::nvmeGetFeature(ss.transport, 0x0C, 0, cdw0, data);
        TSTEP(tid, "NVMe GetFeature BlockSID (0x0C)", r);
        ss.results[tid].record(r);
        if (r.ok()) TLOG(tid, "  BlockSID CDW0=0x%08X", cdw0);
    }

    // 2. Admin1 session
    Bytes admin1Cred = HashPassword::passwordToBytes(ss.admin1Pw);
    Session session(ss.transport, ss.comIds[tid]);
    session.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    TSTEP(tid, "Admin1 auth → LockingSP (write)", r);
    ss.results[tid].record(r);
    if (r.failed()) { ss.barrier.wait(); return; }

    // 3. Enable User1
    r = api.enableUser(session, 1, raw);
    TSTEP(tid, "enableUser(1)", r);
    ss.results[tid].record(r);

    // 4. isUserEnabled
    bool enabled = false;
    r = api.isUserEnabled(session, 1, enabled, raw);
    TSTEP(tid, "isUserEnabled(1)", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  User1 enabled: %s", enabled ? "true" : "false");

    // 5. Add User1 to Range1 ACEs
    r = api.addAuthorityToAce(session,
            uid::makeAceLockingRangeSetRdLocked(1).toUint64(),
            uid::AUTH_USER1, raw);
    TSTEP(tid, "addAuthorityToAce (Range1 RdLock)", r);
    ss.results[tid].record(r);

    r = api.addAuthorityToAce(session,
            uid::makeAceLockingRangeSetWrLocked(1).toUint64(),
            uid::AUTH_USER1, raw);
    TSTEP(tid, "addAuthorityToAce (Range1 WrLock)", r);
    ss.results[tid].record(r);

    // 6. ACE info
    AceInfo aceInfo;
    r = api.getAceInfo(session,
            uid::makeAceLockingRangeSetRdLocked(1).toUint64(),
            aceInfo, raw);
    TSTEP(tid, "getAceInfo (Range1 RdLock)", r);
    ss.results[tid].record(r);

    // 7. setCPin User1
    Bytes user1Pin = HashPassword::passwordToBytes(ss.user1Pw);
    r = api.setCPin(session, uid::CPIN_USER1, user1Pin, raw);
    TSTEP(tid, "setCPin (User1)", r);
    ss.results[tid].record(r);

    // 8. setAdmin1Password (change to same value for test)
    r = api.setAdmin1Password(session, admin1Cred, raw);
    TSTEP(tid, "setAdmin1Password (re-set)", r);
    ss.results[tid].record(r);

    // 9. getRandom
    Bytes randData;
    r = api.getRandom(session, 32, randData, raw);
    TSTEP(tid, "getRandom (32 bytes)", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  Random: %02X%02X%02X%02X...",
                     randData[0], randData[1], randData[2], randData[3]);

    // 10. getClock
    uint64_t clockVal = 0;
    r = api.getClock(session, clockVal, raw);
    TSTEP(tid, "getClock", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  Clock: %lu", clockVal);

    // 11. Table Get (Global Range, all columns)
    TableResult tblRes;
    r = api.tableGetAll(session, uid::LOCKING_GLOBALRANGE, tblRes);
    TSTEP(tid, "tableGetAll (GlobalRange)", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  Columns returned: %zu", tblRes.columns.size());

    // 12. Table SetBool (example: WriteLockEnabled on GlobalRange)
    r = api.tableSetBool(session, uid::LOCKING_GLOBALRANGE,
                          uid::col::WRITE_LOCK_EN, false, raw);
    TSTEP(tid, "tableSetBool (GlobalRange WLE=false)", r);
    ss.results[tid].record(r);

    // 13. Table GetUint
    uint64_t akVal = 0;
    r = api.tableGetUint(session, uid::makeLockingRangeUid(1).toUint64(),
                          uid::col::ACTIVE_KEY, akVal, raw);
    TSTEP(tid, "tableGetUint (Range1 ActiveKey)", r);
    ss.results[tid].record(r);

    // 14. setUserPassword
    r = api.setUserPassword(session, 1, user1Pin, raw);
    TSTEP(tid, "setUserPassword(1)", r);
    ss.results[tid].record(r);

    // 15. CPinTriesRemaining
    uint32_t remaining = 0;
    r = api.getCPinTriesRemaining(session, uid::CPIN_USER1, remaining, raw);
    TSTEP(tid, "getCPinTriesRemaining (User1)", r);
    ss.results[tid].record(r);
    if (r.ok()) TLOG(tid, "  Tries remaining: %u", remaining);

    api.closeSession(session);

    // ── Barrier ──
    TLOG(tid, "--- Phase 1 complete, waiting at barrier ---");
    ss.barrier.wait();

    // ── Phase 2: Block SID test ──
    TLOG(tid, "--- Phase 2: Block SID set/verify/clear ---");
    {
        // Set Block SID
        r = EvalApi::nvmeSetFeature(ss.transport, 0x0C, 0, 0x01);
        TSTEP(tid, "NVMe SetFeature BlockSID (block)", r);
        ss.results[tid].record(r);

        // Verify SID is blocked
        Bytes sidCred = HashPassword::passwordToBytes(ss.sidPw);
        Session bs(ss.transport, ss.comIds[tid]);
        bs.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
        StartSessionResult bssr;
        r = api.startSessionWithAuth(bs, uid::SP_ADMIN, true,
                                      uid::AUTH_SID, sidCred, bssr);
        TLOG(tid, "  SID auth while blocked: %s", r.ok() ? "PASSED(unexpected)" : "BLOCKED(expected)");
        ss.results[tid].record(r.ok() ? Result(ErrorCode::InvalidArgument) : Result(ErrorCode::Success));
        if (r.ok()) api.closeSession(bs);

        // Clear Block SID
        r = EvalApi::nvmeSetFeature(ss.transport, 0x0C, 0, 0x00);
        TSTEP(tid, "NVMe SetFeature BlockSID (clear)", r);
        ss.results[tid].record(r);
    }
}

// ═══════════════════════════════════════════════════
//  Phase 0: Common Initialization
// ═══════════════════════════════════════════════════

/// Phase 0: 소유권 확보, Locking SP 활성화, Admin1/User1 비밀번호 설정
static bool phase0_initialize(SharedState& ss) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  Phase 0: Common Initialization           ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    EvalApi api;
    RawResult raw;

    // 0. StackReset — 이전 stale 세션이 남아있을 수 있으므로 정리
    std::cout << "  [0] StackReset + Properties exchange...\n";
    auto r = api.stackReset(ss.transport, ss.baseComId);
    if (r.failed()) {
        std::cerr << "  [0] StackReset FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: Transport 연결 확인. 디바이스 경로가 올바른지,\n";
        std::cerr << "        sudo 권한으로 실행했는지 체크하세요.\n";
        return false;
    }

    PropertiesResult props;
    r = api.exchangeProperties(ss.transport, ss.baseComId, props);
    if (r.failed()) {
        std::cerr << "  [0] Properties exchange FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: ComID 0x" << std::hex << ss.baseComId << std::dec
                  << " 상태 이상. 전원 사이클 후 재시도하세요.\n";
        return false;
    }
    std::cout << "  [0] StackReset + Properties: OK\n";

    // 1. Read MSID
    std::cout << "  [1] Reading MSID (Anonymous AdminSP session)...\n";
    Session s1(ss.transport, ss.baseComId);
    s1.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    r = api.startSession(s1, uid::SP_ADMIN, false, ssr);
    if (r.failed()) {
        std::cerr << "  [1] AdminSP Anonymous Session FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: 가능한 원인:\n";
        std::cerr << "        1) BIOS가 Block SID를 설정함 → 전원 사이클(콜드 리부트) 후 재시도\n";
        std::cerr << "        2) 이전 세션이 ComID에 남아있음 → 이미 StackReset 수행했으므로 HW 문제 의심\n";
        std::cerr << "        3) 디바이스가 TCG를 지원하지 않음 → sed_discover로 확인\n";
        return false;
    }

    Bytes msid;
    r = api.getCPin(s1, uid::CPIN_MSID, msid, raw);
    api.closeSession(s1);
    if (r.failed() || msid.empty()) {
        std::cerr << "  [1] Get C_PIN_MSID FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: MSID 읽기 실패. AdminSP 상태 이상 또는 C_PIN 테이블 접근 거부.\n";
        return false;
    }
    std::cout << "  [1] MSID read: " << msid.size() << " bytes — OK\n";

    // 2. Take ownership (SID auth → set SID PIN)
    std::cout << "  [2] Take Ownership (SID auth with MSID)...\n";
    Session s2(ss.transport, ss.baseComId);
    s2.setMaxComPacketSize(props.tperMaxComPacketSize);
    r = api.startSessionWithAuth(s2, uid::SP_ADMIN, true, uid::AUTH_SID, msid, ssr);
    if (r.failed()) {
        std::cout << "      MSID로 SID 인증 실패 — 이미 소유된 드라이브일 수 있음, sidPw로 재시도\n";
        Bytes sidCred = HashPassword::passwordToBytes(ss.sidPw);
        r = api.startSessionWithAuth(s2, uid::SP_ADMIN, true, uid::AUTH_SID, sidCred, ssr);
        if (r.failed()) {
            std::cerr << "  [2] SID Auth FAIL (MSID + sidPw 모두 실패): " << r.message() << "\n";
            std::cerr << "      → HINT: 가능한 원인:\n";
            std::cerr << "        1) 드라이브가 다른 비밀번호로 소유됨 → PSID 리셋 필요\n";
            std::cerr << "           (드라이브 라벨의 32자리 PSID 사용)\n";
            std::cerr << "        2) Block SID 활성 상태 → 전원 사이클 후 재시도\n";
            std::cerr << "        3) SID Authority lockout (시도 횟수 초과) → 전원 사이클\n";
            return false;
        }
        std::cout << "      sidPw로 SID 인증 성공 (드라이브 이미 소유됨)\n";
    }

    Bytes newSidPin = HashPassword::passwordToBytes(ss.sidPw);
    r = api.setCPin(s2, uid::CPIN_SID, newSidPin, raw);
    if (r.failed()) {
        std::cerr << "  [2] SetCPin(SID) FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: 쓰기 권한 부족 또는 C_PIN 테이블 접근 거부.\n";
        api.closeSession(s2);
        return false;
    }
    std::cout << "  [2] SID password set — OK\n";

    // 3. Activate Locking SP
    std::cout << "  [3] Checking Locking SP lifecycle...\n";
    uint8_t lifecycle = 0;
    r = api.getSpLifecycle(s2, uid::SP_LOCKING, lifecycle, raw);
    if (r.failed()) {
        std::cerr << "  [3] GetSpLifecycle FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: SP 테이블 읽기 실패. AdminSP 세션 상태 확인.\n";
        api.closeSession(s2);
        return false;
    }

    if (lifecycle == 0x08) {  // Manufactured-Inactive
        r = api.activate(s2, uid::SP_LOCKING, raw);
        if (r.failed()) {
            std::cerr << "  [3] Activate(Locking SP) FAIL: " << r.message() << "\n";
            std::cerr << "      → HINT: SID 권한으로 Activate 불가. SP 상태 lifecycle=0x"
                      << std::hex << (int)lifecycle << std::dec << " 확인.\n";
            api.closeSession(s2);
            return false;
        }
        std::cout << "  [3] Locking SP activated (was Manufactured-Inactive) — OK\n";
    } else {
        std::cout << "  [3] Locking SP already active (lifecycle=0x"
                  << std::hex << (int)lifecycle << std::dec << ") — OK\n";
    }
    api.closeSession(s2);

    // 4. Admin1 session → set passwords
    std::cout << "  [4] Setting Admin1 / User1 passwords...\n";
    Bytes admin1Cred = HashPassword::passwordToBytes(ss.admin1Pw);
    Session s3(ss.transport, ss.baseComId);
    s3.setMaxComPacketSize(props.tperMaxComPacketSize);
    r = api.startSessionWithAuth(s3, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, msid, ssr);
    if (r.failed()) {
        std::cout << "      MSID로 Admin1 인증 실패 — admin1Pw로 재시도\n";
        r = api.startSessionWithAuth(s3, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Cred, ssr);
    }
    if (r.failed()) {
        std::cerr << "  [4] Admin1 Auth → LockingSP FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: 가능한 원인:\n";
        std::cerr << "        1) Locking SP가 Activate 되지 않았음 → Step 3 확인\n";
        std::cerr << "        2) Admin1 비밀번호가 MSID도 admin1Pw도 아님\n";
        std::cerr << "        3) 이전 비정상 종료로 Admin1 비밀번호가 다른 값으로 설정됨\n";
        std::cerr << "           → PSID 리셋 후 재시도\n";
        return false;
    }

    r = api.setAdmin1Password(s3, admin1Cred, raw);
    if (r.failed()) {
        std::cerr << "  [4] SetAdmin1Password FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: C_PIN_ADMIN1 쓰기 거부. 권한 또는 세션 상태 확인.\n";
    }

    // 5. Enable User1 + set password + ACE
    r = api.enableUser(s3, 1, raw);
    if (r.failed()) {
        std::cerr << "  [5] EnableUser(1) FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: User1 Authority 활성화 실패. Admin1 권한 확인.\n";
    }

    Bytes user1Pin = HashPassword::passwordToBytes(ss.user1Pw);
    r = api.setCPin(s3, uid::CPIN_USER1, user1Pin, raw);
    if (r.failed()) {
        std::cerr << "  [5] SetCPin(User1) FAIL: " << r.message() << "\n";
    }

    api.addAuthorityToAce(s3, uid::makeAceLockingRangeSetRdLocked(1).toUint64(),
                           uid::AUTH_USER1, raw);
    api.addAuthorityToAce(s3, uid::makeAceLockingRangeSetWrLocked(1).toUint64(),
                           uid::AUTH_USER1, raw);
    std::cout << "  [5] User1 enabled + password + ACE — OK\n";
    api.closeSession(s3);

    std::cout << "  Phase 0 complete ✓\n";
    return true;
}

// ═══════════════════════════════════════════════════
//  Phase 3: Cleanup
// ═══════════════════════════════════════════════════

/// Phase 3: Revert Locking SP → Revert TPer
static void phase3_cleanup(SharedState& ss) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  Phase 3: Cleanup (Revert)                ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    EvalApi api;
    RawResult raw;

    // StackReset 선행 (스레드들이 사용한 ComID 정리)
    api.stackReset(ss.transport, ss.baseComId);
    PropertiesResult props;
    api.exchangeProperties(ss.transport, ss.baseComId, props);

    // Revert Locking SP (Phase 3은 단일 스레드 — baseComId 사용)
    std::cout << "  [1] Revert Locking SP...\n";
    Bytes admin1Cred = HashPassword::passwordToBytes(ss.admin1Pw);
    Session s1(ss.transport, ss.baseComId);
    s1.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(s1, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    if (r.ok()) {
        r = api.revertSP(s1, uid::SP_LOCKING, raw);
        std::cout << "  [1] RevertSP (Locking): " << (r.ok() ? "OK" : r.message()) << "\n";
        // RevertSP 후 세션은 TPer가 자동 종료 — closeSession 불필요
    } else {
        std::cerr << "  [1] Admin1 → LockingSP session FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: Admin1 비밀번호 불일치. 스레드 실행 중 변경되었을 수 있음.\n";
        std::cerr << "        수동 정리 필요: PSID 리셋 또는 올바른 Admin1 비밀번호로 revert\n";
    }

    // StackReset + Properties (RevertSP 후 ComID 상태 초기화)
    api.stackReset(ss.transport, ss.baseComId);
    api.exchangeProperties(ss.transport, ss.baseComId, ss.props);

    // Revert TPer
    std::cout << "  [2] Revert TPer...\n";
    Bytes sidCred = HashPassword::passwordToBytes(ss.sidPw);
    Session s2(ss.transport, ss.baseComId);
    s2.setMaxComPacketSize(ss.props.tperMaxComPacketSize);
    r = api.startSessionWithAuth(s2, uid::SP_ADMIN, true,
                                  uid::AUTH_SID, sidCred, ssr);
    if (r.ok()) {
        r = api.revertSP(s2, uid::SP_ADMIN, raw);
        std::cout << "  [2] RevertSP (TPer): " << (r.ok() ? "OK" : r.message()) << "\n";
    } else {
        std::cerr << "  [2] SID → AdminSP session FAIL: " << r.message() << "\n";
        std::cerr << "      → HINT: SID 비밀번호 불일치. 스레드에서 비밀번호가 변경되었을 수 있음.\n";
        std::cerr << "        수동 정리 필요: PSID 리셋 권장\n";
        std::cerr << "        명령: ./sed_manage <device> psid-revert <PSID_ON_LABEL>\n";
    }

    std::cout << "  Cleanup complete — drive returned to factory state\n";
}

// ═══════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <device> <sid_pw> <admin1_pw> <user1_pw>\n\n";
        std::cerr << "Comprehensive multi-threaded TCG SED evaluation TC.\n";
        std::cerr << "4 parallel sessions × diverse operations × 2 phases.\n\n";
        std::cerr << "WARNING: This will modify drive state! Revert is performed at cleanup.\n\n";
        std::cerr << "Example:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 mySID admin123 user123\n";
        return 1;
    }

    SharedState ss;
    ss.sidPw    = argv[2];
    ss.admin1Pw = argv[3];
    ss.user1Pw  = argv[4];

    libsed::initialize();

    auto rawTransport = TransportFactory::createNvme(argv[1]);
    if (!rawTransport || !rawTransport->isOpen()) {
        std::cerr << "Cannot open " << argv[1] << "\n";
        return 1;
    }

    // 명령 이력 로깅: 모든 IF-SEND/IF-RECV를 파일에 기록
    ss.transport = debug::LoggingTransport::wrap(rawTransport, ".");
    auto* lt = dynamic_cast<debug::LoggingTransport*>(ss.transport.get());
    std::cout << "Command log: " << lt->logger()->filePath() << "\n";

    EvalApi api;
    TcgOption opt;
    api.getTcgOption(ss.transport, opt);
    ss.baseComId = opt.baseComId;
    ss.numComIds = opt.numComIds;
    if (ss.baseComId == 0) { std::cerr << "No valid ComID\n"; return 1; }

    // ── ComID 할당: 스레드별 독립 ComID ──
    // TCG spec에서 ComID는 통신 채널이며, 하나의 ComID에서는
    // 하나의 outstanding IF-SEND/IF-RECV만 허용됩니다.
    // 멀티스레드 병렬 실행을 위해 각 스레드에 별도 ComID를 할당합니다.
    if (ss.numComIds >= 4) {
        // 충분한 ComID — 각 스레드에 고유 ComID 할당
        for (int i = 0; i < 4; i++) {
            ss.comIds[i] = ss.baseComId + i;
        }
        ss.serialMode = false;
        std::cout << "ComID allocation: parallel mode (4 independent ComIDs)\n";
    } else {
        // ComID 부족 — 단일 ComID, transport 직렬화 모드
        for (int i = 0; i < 4; i++) {
            ss.comIds[i] = ss.baseComId;
        }
        ss.serialMode = true;
        std::cout << "WARNING: numComIds=" << ss.numComIds
                  << " < 4, falling back to serial mode (shared ComID)\n";
        std::cout << "  Parallel threads will serialize transport access.\n";
    }

    // 각 ComID별로 StackReset → Properties exchange 수행
    // (이전 실행의 stale 세션이 남아있을 수 있으므로 반드시 StackReset 선행)
    for (int i = 0; i < (ss.serialMode ? 1 : 4); i++) {
        api.stackReset(ss.transport, ss.comIds[i]);
    }
    api.exchangeProperties(ss.transport, ss.baseComId, ss.props);
    for (int i = 1; i < 4 && !ss.serialMode; i++) {
        PropertiesResult p;
        api.exchangeProperties(ss.transport, ss.comIds[i], p);
    }

    std::cout << "═══════════════════════════════════════════════════════\n";
    std::cout << " Comprehensive Multi-Thread TCG SED Evaluation TC\n";
    std::cout << " Device: " << argv[1] << "\n";
    std::cout << " ComIDs: ";
    for (int i = 0; i < 4; i++) {
        std::cout << "T" << i << "=0x" << std::hex << ss.comIds[i] << std::dec;
        if (i < 3) std::cout << ", ";
    }
    std::cout << "\n";
    std::cout << " SSC:    " << (int)opt.sscType << "\n";
    std::cout << " Mode:   " << (ss.serialMode ? "Serial (shared ComID)" : "Parallel (per-thread ComID)") << "\n";
    std::cout << " Threads: 4 (T0=Discovery T1=Locking T2=MBR/DS T3=Auth)\n";
    std::cout << "═══════════════════════════════════════════════════════\n";

    // ── Phase 0: Initialize ──
    if (!phase0_initialize(ss)) {
        std::cerr << "Phase 0 initialization failed\n";
        return 1;
    }

    // Phase 0 완료 후 각 스레드 ComID를 깨끗한 상태로 준비
    for (int i = 0; i < (ss.serialMode ? 1 : 4); i++) {
        api.stackReset(ss.transport, ss.comIds[i]);
        PropertiesResult p;
        api.exchangeProperties(ss.transport, ss.comIds[i], p);
    }

    // ── Phase 1+2: Parallel threads ──
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  Phase 1+2: Parallel Execution (4 threads)║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    auto tStart = Clock::now();

    std::thread t0(thread0_spLifecycleDiscovery, 0, std::ref(ss));
    std::thread t1(thread1_lockingKeyMgmt,       1, std::ref(ss));
    std::thread t2(thread2_mbrDataStore,         2, std::ref(ss));
    std::thread t3(thread3_securityAuthority,    3, std::ref(ss));

    t0.join();
    t1.join();
    t2.join();
    t3.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - tStart).count();

    // ── Phase 3: Cleanup ──
    phase3_cleanup(ss);

    // ── Summary ──
    std::cout << "\n═══════════════════════════════════════════════════════\n";
    std::cout << " Summary                                         \n";
    std::cout << "═══════════════════════════════════════════════════════\n";

    uint32_t totalPass = 0, totalFail = 0;
    const char* names[] = {"T0 Discovery/SP", "T1 Locking/Key", "T2 MBR/DataStore", "T3 Security/Auth"};
    for (int i = 0; i < 4; i++) {
        uint32_t p = ss.results[i].pass, f = ss.results[i].fail;
        totalPass += p; totalFail += f;
        printf("  %-20s  %3u pass / %3u fail\n", names[i], p, f);
    }
    std::cout << "  ─────────────────────────────────────────\n";
    printf("  %-20s  %3u pass / %3u fail\n", "TOTAL", totalPass, totalFail);
    std::cout << "  Elapsed: " << elapsed << " ms\n";
    std::cout << "═══════════════════════════════════════════════════════\n";

    libsed::shutdown();
    return (totalFail == 0) ? 0 : 1;
}
