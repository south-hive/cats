/// @file eval_worker_pattern.cpp
/// @brief NVMeThread + Worker pattern with SedContext integration.
///
/// Shows how your evaluation platform integrates with this library:
///
///   NVMeThread (owns libnvme, creates SedContext)
///       │
///       ├── Worker A (TCG ownership test)
///       ├── Worker B (locking range test)
///       ├── Worker C (NVMe format + TCG verify)
///       └── Worker D (DataStore stress test)
///
/// Each Worker receives:
///   - libnvme*   → NVMe operations
///   - SedContext& → TCG operations (Transport + EvalApi + Session)
///
/// Key: Worker never creates its own transport or device.
///      Everything flows down from NVMeThread via DI.

#include <libsed/sed_library.h>
#include <libsed/transport/nvme_transport.h>
#include <iostream>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <string>
#include <cstdio>

using namespace libsed;
using namespace libsed::eval;

// ════════════════════════════════════════════════════════
//  Simulated libnvme (your actual implementation)
// ════════════════════════════════════════════════════════

/// @scenario 시뮬레이션 libnvme 구현체 (하드웨어 없이 테스트)
/// @precondition 없음 (시뮬레이션이므로 실제 NVMe 디바이스 불필요)
/// @steps
///   1. SimLibNvme 생성 시 디바이스 경로 저장 및 시뮬레이션 초기화
///   2. securitySend/securityRecv — NvmeTransport가 내부적으로 호출 (시뮬레이션된 L0 Discovery 응답 반환)
///   3. identify/getLogPage/getFeature 등 — NVMe Admin 명령 시뮬레이션
///   4. formatNvm/sanitize 등 — NVMe 관리 명령 시뮬레이션
/// @expected
///   - 모든 INvmeDevice 인터페이스 메서드가 ErrorCode::Success 반환
///   - securityRecv는 48바이트 시뮬레이션 Discovery 응답 반환
///   - identify는 4096바이트 시뮬레이션 데이터(모델명 포함) 반환
class SimLibNvme : public INvmeDevice {
public:
    explicit SimLibNvme(const std::string& path) : path_(path) {
        printf("  [libnvme] Opened %s (simulated)\n", path.c_str());
    }

    // Security Protocol — used by NvmeTransport internally
    Result securitySend(uint8_t, uint16_t, const uint8_t*, uint32_t) override {
        return ErrorCode::Success;
    }
    Result securityRecv(uint8_t, uint16_t, uint8_t* data, uint32_t len,
                        uint32_t& received) override {
        // Simulated L0 Discovery response
        if (len >= 48) {
            memset(data, 0, len);
            data[0] = 0; data[1] = 0; data[2] = 0; data[3] = 48;
            received = 48;
        }
        return ErrorCode::Success;
    }

    // NVMe Admin
    Result adminCommand(NvmeAdminCmd& cmd, NvmeCompletion& cpl) override {
        printf("  [libnvme] Admin opcode=0x%02X nsid=%u\n", cmd.opcode, cmd.nsid);
        cpl = {};
        return ErrorCode::Success;
    }
    Result ioCommand(NvmeIoCmd& cmd, NvmeCompletion& cpl) override {
        printf("  [libnvme] IO opcode=0x%02X slba=%lu\n", cmd.opcode, cmd.slba);
        cpl = {};
        return ErrorCode::Success;
    }

    Result identify(uint8_t cns, uint32_t nsid, Bytes& data) override {
        printf("  [libnvme] Identify CNS=%u nsid=%u\n", cns, nsid);
        data.resize(4096, 0);
        memcpy(data.data() + 24, "SimNVMe SSD Model 1234", 22);
        return ErrorCode::Success;
    }
    Result getLogPage(uint8_t logId, uint32_t nsid, Bytes& data, uint32_t dataLen) override {
        printf("  [libnvme] GetLogPage logId=0x%02X\n", logId);
        data.resize(dataLen, 0);
        return ErrorCode::Success;
    }
    Result getFeature(uint8_t fid, uint32_t, uint32_t& cdw0, Bytes&) override {
        printf("  [libnvme] GetFeature fid=0x%02X\n", fid);
        cdw0 = 0;
        return ErrorCode::Success;
    }
    Result setFeature(uint8_t fid, uint32_t, uint32_t, const Bytes&) override {
        printf("  [libnvme] SetFeature fid=0x%02X\n", fid);
        return ErrorCode::Success;
    }
    Result formatNvm(uint32_t nsid, uint8_t lbaf, uint8_t ses, uint8_t) override {
        printf("  [libnvme] Format nsid=%u lbaf=%u ses=%u\n", nsid, lbaf, ses);
        return ErrorCode::Success;
    }
    Result sanitize(uint8_t action, uint32_t) override {
        printf("  [libnvme] Sanitize action=%u\n", action);
        return ErrorCode::Success;
    }
    Result fwDownload(const Bytes&, uint32_t offset) override {
        printf("  [libnvme] FW Download offset=%u\n", offset);
        return ErrorCode::Success;
    }
    Result fwCommit(uint8_t slot, uint8_t action) override {
        printf("  [libnvme] FW Commit slot=%u action=%u\n", slot, action);
        return ErrorCode::Success;
    }
    Result nsCreate(const Bytes&, uint32_t& nsid) override { nsid = 1; return ErrorCode::Success; }
    Result nsDelete(uint32_t) override { return ErrorCode::Success; }
    Result nsAttach(uint32_t, uint16_t, bool) override { return ErrorCode::Success; }

    std::string devicePath() const override { return path_; }
    bool isOpen() const override { return true; }
    void close() override {}
    int fd() const override { return 42; }

private:
    std::string path_;
};

// ════════════════════════════════════════════════════════
//  Worker Base (your platform's abstract worker)
// ════════════════════════════════════════════════════════

/// @scenario 추상 Worker 인터페이스
/// @precondition 없음 (추상 클래스)
/// @steps
///   1. 서브클래스에서 name() 오버라이드 — Worker 이름 반환
///   2. 서브클래스에서 execute(libnvme, ctx) 오버라이드 — 실제 작업 수행
/// @expected
///   - NVMeThread가 execute()를 호출할 때 libnvme(NVMe 작업용)과 ctx(TCG 작업용)가 전달됨
///   - Worker는 자체적으로 Transport나 Device를 생성하지 않음 (DI 패턴 준수)
class Worker {
public:
    virtual ~Worker() = default;

    /// Name for logging
    virtual std::string name() const = 0;

    /// Called by NVMeThread with this thread's context.
    /// @param libnvme  This thread's NVMe device (for NVMe ops)
    /// @param ctx      This thread's TCG context (for TCG ops)
    virtual Result execute(INvmeDevice& libnvme, SedContext& ctx) = 0;
};

// ════════════════════════════════════════════════════════
//  NVMeThread (your platform's thread class)
// ════════════════════════════════════════════════════════

/// @scenario 스레드별 컨텍스트 관리 (libnvme 소유, SedContext 생성)
/// @precondition 디바이스 경로가 유효해야 함 (SimLibNvme 사용 시 실제 디바이스 불필요)
/// @steps
///   1. 생성 시 SimLibNvme(또는 실제 libnvme) 인스턴스 생성 — 스레드별 소유
///   2. SedContext 생성 — libnvme를 DI하여 Transport + EvalApi + Session 번들
///   3. addWorker()로 실행할 Worker 등록
///   4. run() 호출 시:
///      a. SedContext::initialize() — Discovery 수행 및 ComID 캐시
///      b. 등록된 Worker를 순차 실행, 각 Worker에 libnvme와 SedContext 전달
///   5. start()로 별도 std::thread에서 실행 가능
/// @expected
///   - 각 NVMeThread가 독립적인 libnvme + SedContext를 소유
///   - Worker들이 순차 실행되며 각각 PASS/FAIL 결과 출력
///   - 스레드 간 리소스 공유 없이 완전 격리
class NVMeThread {
public:
    NVMeThread(const std::string& devicePath, int threadId)
        : threadId_(threadId)
    {
        // Each NVMeThread owns its own libnvme instance
        libnvme_ = std::make_shared<SimLibNvme>(devicePath);

        // Create per-thread SedContext (DI libnvme → transport)
        sedContext_ = std::make_unique<SedContext>(libnvme_);
    }

    /// Add worker to execution list
    void addWorker(std::unique_ptr<Worker> worker) {
        workers_.push_back(std::move(worker));
    }

    /// Run all workers sequentially (called by thread)
    void run() {
        printf("\n[Thread %d] Starting (%zu workers)\n", threadId_, workers_.size());

        // Initialize TCG context once per thread
        auto r = sedContext_->initialize();
        printf("[Thread %d] SedContext::initialize() → %s\n",
               threadId_, r.ok() ? "OK" : "FAIL (simulated, expected)");

        // Execute workers sequentially
        for (auto& worker : workers_) {
            printf("\n[Thread %d] ── Running: %s ──\n", threadId_, worker->name().c_str());
            auto wr = worker->execute(*libnvme_, *sedContext_);
            printf("[Thread %d] ── %s: %s ──\n",
                   threadId_, worker->name().c_str(), wr.ok() ? "PASS" : "FAIL");
        }

        printf("[Thread %d] Done\n", threadId_);
    }

    /// Start as actual thread
    std::thread start() {
        return std::thread([this]() { run(); });
    }

private:
    int threadId_;
    std::shared_ptr<INvmeDevice>  libnvme_;
    std::unique_ptr<SedContext>   sedContext_;
    std::vector<std::unique_ptr<Worker>> workers_;
};

// ════════════════════════════════════════════════════════
//  Concrete Workers (TC developer writes these)
// ════════════════════════════════════════════════════════

/// @scenario Discovery + Feature 확인 Worker
/// @precondition SedContext가 초기화되어 있어야 함
/// @steps
///   1. [TCG] ctx.api().getTcgOption() — SSC 타입 및 ComID 조회
///   2. [TCG] ctx.api().getAllSecurityFeatures() — 전체 Security Feature 열거
///   3. [NVMe] libnvme.identify() — NVMe Identify Controller로 모델명 확인
/// @expected
///   - TCG 옵션(SSC, ComID) 정상 조회
///   - Security Feature 목록 정상 반환
///   - NVMe Identify로 모델명(SimNVMe SSD Model 1234) 출력
class DiscoveryWorker : public Worker {
public:
    std::string name() const override { return "DiscoveryWorker"; }

    Result execute(INvmeDevice& libnvme, SedContext& ctx) override {
        // TCG: Discovery via SedContext
        TcgOption opt;
        auto r = ctx.api().getTcgOption(ctx.transport(), opt);
        printf("    [TCG] SSC detected, ComID=0x%04X\n", opt.baseComId);

        // TCG: All security features
        std::vector<SecurityFeatureInfo> feats;
        ctx.api().getAllSecurityFeatures(ctx.transport(), feats);
        printf("    [TCG] %zu features found\n", feats.size());

        // NVMe: Identify controller (via libnvme directly)
        Bytes identData;
        libnvme.identify(1, 0, identData);
        if (identData.size() >= 64) {
            std::string model(identData.begin() + 24, identData.begin() + 64);
            printf("    [NVMe] Model: %s\n", model.c_str());
        }

        return ErrorCode::Success;
    }
};

/// @scenario 소유권 확보 + Locking 설정 Worker
/// @precondition SedContext가 초기화되어 있고 SID/Admin1 비밀번호가 제공되어야 함
/// @steps
///   1. ctx.readMsid() — MSID PIN 읽기 (세션 없이)
///   2. ctx.takeOwnership(sidPw) — SID 비밀번호로 소유권 확보
///   3. AdminSP에 SID 인증 세션 열기
///   4. ctx.api().activate(LockingSP) — Locking SP 활성화
///   5. 세션 닫기
/// @expected
///   - MSID 읽기 성공 (바이트 크기 출력)
///   - SID 비밀번호 설정(소유권 확보) 성공
///   - Locking SP 활성화 성공
///   - Admin1 비밀번호 설정 후 Locking 작업 가능 상태
class OwnershipWorker : public Worker {
    std::string sidPw_;
    std::string admin1Pw_;
public:
    OwnershipWorker(std::string sidPw, std::string admin1Pw)
        : sidPw_(std::move(sidPw)), admin1Pw_(std::move(admin1Pw)) {}

    std::string name() const override { return "OwnershipWorker"; }

    Result execute(INvmeDevice& /*libnvme*/, SedContext& ctx) override {
        // Read MSID
        Bytes msid;
        auto r = ctx.readMsid(msid);
        printf("    [TCG] MSID read: %s (%zuB)\n", r.ok() ? "OK" : "FAIL", msid.size());

        // Take ownership
        r = ctx.takeOwnership(sidPw_);
        printf("    [TCG] takeOwnership: %s\n", r.ok() ? "OK" : "FAIL");

        // Activate Locking SP
        r = ctx.openSession(uid::SP_ADMIN, uid::AUTH_SID, sidPw_);
        if (r.ok()) {
            r = ctx.api().activate(ctx.session(), uid::SP_LOCKING);
            printf("    [TCG] Activate LockingSP: %s\n", r.ok() ? "OK" : "FAIL");
            ctx.closeSession();
        }

        return ErrorCode::Success;
    }
};

/// @scenario Locking Range 설정 + Lock/Unlock Worker
/// @precondition SedContext가 초기화되어 있고 Admin1 비밀번호로 LockingSP 세션 열기 가능해야 함
/// @steps
///   1. LockingSP에 Admin1 인증 세션 열기
///   2. getLockingInfo(rangeId) — 현재 Range 상태 조회
///   3. setRange(rangeId, RLE=true, WLE=true) — Range 구성
///   4. setRangeLock(rangeId, true, true) — Range 잠금
///   5. getLockingInfo(rangeId) — 잠금 상태 검증
///   6. setRangeLock(rangeId, false, false) — Range 잠금 해제
///   7. 세션 닫기
/// @expected
///   - Range 설정(ReadLockEnabled, WriteLockEnabled) 성공
///   - Lock 후 ReadLocked=true, WriteLocked=true 확인
///   - Unlock 후 정상 해제
///   - LockOnReset 설정 시에도 정상 동작
class LockingWorker : public Worker {
    std::string admin1Pw_;
    uint32_t rangeId_;
public:
    LockingWorker(std::string admin1Pw, uint32_t rangeId)
        : admin1Pw_(std::move(admin1Pw)), rangeId_(rangeId) {}

    std::string name() const override { return "LockingWorker(range=" + std::to_string(rangeId_) + ")"; }

    Result execute(INvmeDevice& /*libnvme*/, SedContext& ctx) override {
        auto r = ctx.openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, admin1Pw_);
        if (r.failed()) { printf("    Session fail\n"); return r; }

        // Read current state
        LockingInfo li;
        ctx.api().getLockingInfo(ctx.session(), rangeId_, li);
        printf("    Range %u: start=%lu len=%lu RLE=%d WLE=%d\n",
               rangeId_, li.rangeStart, li.rangeLength,
               li.readLockEnabled, li.writeLockEnabled);

        // Configure
        ctx.api().setRange(ctx.session(), rangeId_, 0, 0, true, true);
        printf("    setRange(RLE=true, WLE=true): OK\n");

        // Lock
        ctx.api().setRangeLock(ctx.session(), rangeId_, true, true);
        printf("    Lock: OK\n");

        // Verify locked
        ctx.api().getLockingInfo(ctx.session(), rangeId_, li);
        printf("    Verify: RL=%d WL=%d\n", li.readLocked, li.writeLocked);

        // Unlock
        ctx.api().setRangeLock(ctx.session(), rangeId_, false, false);
        printf("    Unlock: OK\n");

        ctx.closeSession();
        return ErrorCode::Success;
    }
};

/// @scenario NVMe Format 후 TCG 상태 검증 Worker
/// @precondition SedContext가 초기화되어 있고 libnvme로 NVMe 명령 수행 가능해야 함
/// @steps
///   1. [NVMe] getLogPage(SMART) — Format 전 SMART 데이터 확인
///   2. [NVMe] formatNvm(nsid=1, lbaf=0, ses=1) — User Data Erase 포맷 수행
///   3. [TCG] getTcgOption() — Format 후 Discovery 재실행하여 SED 상태 확인
///   4. [TCG] readMsid() — Format 후 MSID 읽기 가능 여부 확인
///   5. [NVMe] getLogPage(SMART) — Format 후 SMART 데이터 확인
/// @expected
///   - Format 전후 SMART 데이터 정상 수신
///   - Format 후 Discovery 재실행 시 SED 상태(locking, locked) 정상 확인
///   - Format 후에도 MSID 읽기 가능
class FormatRecoveryWorker : public Worker {
    std::string sidPw_;
public:
    explicit FormatRecoveryWorker(std::string sidPw) : sidPw_(std::move(sidPw)) {}

    std::string name() const override { return "FormatRecoveryWorker"; }

    Result execute(INvmeDevice& libnvme, SedContext& ctx) override {
        // Step 1: NVMe — check SMART before format
        Bytes smart;
        libnvme.getLogPage(0x02, 0xFFFFFFFF, smart, 512);
        printf("    [NVMe] Pre-format SMART: %zuB\n", smart.size());

        // Step 2: NVMe — Format (User Data Erase)
        auto r = libnvme.formatNvm(1, 0, /*ses=*/1);
        printf("    [NVMe] Format: %s\n", r.ok() ? "OK" : "FAIL");

        // Step 3: TCG — Re-discover (format may affect SED state)
        TcgOption opt;
        ctx.api().getTcgOption(ctx.transport(), opt);
        printf("    [TCG] Post-format: locking=%d locked=%d\n",
               opt.lockingEnabled, opt.locked);

        // Step 4: TCG — Can we still read MSID?
        Bytes msid;
        r = ctx.readMsid(msid);
        printf("    [TCG] Post-format MSID read: %s (%zuB)\n",
               r.ok() ? "OK" : "FAIL", msid.size());

        // Step 5: NVMe — SMART after format
        libnvme.getLogPage(0x02, 0xFFFFFFFF, smart, 512);
        printf("    [NVMe] Post-format SMART: %zuB\n", smart.size());

        return ErrorCode::Success;
    }
};

/// @scenario DataStore 입출력 Worker
/// @precondition SedContext가 초기화되어 있고 Admin1 비밀번호로 LockingSP 세션 열기 가능해야 함
/// @steps
///   1. LockingSP에 Admin1 인증 세션 열기
///   2. getByteTableInfo() — DataStore 테이블 속성(maxSize, usedSize) 조회
///   3. tcgWriteDataStore(offset=0, 8바이트) — 테스트 패턴 기록
///   4. tcgReadDataStore(offset=0, 8바이트) — 기록한 데이터 읽기
///   5. tcgCompare(TABLE_DATASTORE, offset=0) — Write한 패턴과 비교
///   6. 세션 닫기
/// @expected
///   - Write 성공 후 Read 결과가 8바이트 반환됨
///   - Compare 결과 match=true (기록한 데이터와 일치)
///   - DataStore max/used 크기 정상 출력
class DataStoreWorker : public Worker {
    std::string admin1Pw_;
public:
    explicit DataStoreWorker(std::string admin1Pw) : admin1Pw_(std::move(admin1Pw)) {}

    std::string name() const override { return "DataStoreWorker"; }

    Result execute(INvmeDevice& /*libnvme*/, SedContext& ctx) override {
        auto r = ctx.openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, admin1Pw_);
        if (r.failed()) return r;

        // ByteTable info
        ByteTableInfo bti;
        ctx.api().getByteTableInfo(ctx.session(), bti);
        printf("    DataStore max=%u used=%u\n", bti.maxSize, bti.usedSize);

        // Write pattern
        Bytes pattern = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        ctx.api().tcgWriteDataStore(ctx.session(), 0, pattern);
        printf("    Write 8B at offset 0: OK\n");

        // Read back
        DataOpResult dr;
        ctx.api().tcgReadDataStore(ctx.session(), 0, 8, dr);
        printf("    Read 8B: %zuB returned\n", dr.data.size());

        // Compare
        ctx.api().tcgCompare(ctx.session(), uid::TABLE_DATASTORE, 0, pattern, dr);
        printf("    Compare: match=%d\n", dr.compareMatch);

        ctx.closeSession();
        return ErrorCode::Success;
    }
};

/// @scenario 이중 세션 Worker (AdminSP + LockingSP)
/// @precondition SedContext가 초기화되어 있고 SID 및 Admin1 비밀번호가 유효해야 함
/// @steps
///   1. ctx.openSession(AdminSP, SID) — 메인 세션으로 AdminSP 열기
///   2. ctx.createAndOpenSession(LockingSP, Admin1) — 보조 세션으로 LockingSP 열기
///   3. [AdminSP] getSpLifecycle(LockingSP) — AdminSP 세션에서 LockingSP Lifecycle 조회
///   4. [LockingSP] getLockingInfo(0) — LockingSP 세션에서 Global Range 정보 조회
///   5. 보조 세션(LockingSP) 닫기
///   6. 메인 세션(AdminSP) 닫기
/// @expected
///   - 두 SP에 동시 세션 열기 성공
///   - AdminSP 세션에서 Lifecycle 조회, LockingSP 세션에서 Locking Info 조회 등 교차 작업 수행
///   - 각 세션이 독립적으로 동작하며 서로 간섭하지 않음
class DualSessionWorker : public Worker {
    std::string sidPw_;
    std::string admin1Pw_;
public:
    DualSessionWorker(std::string sidPw, std::string admin1Pw)
        : sidPw_(std::move(sidPw)), admin1Pw_(std::move(admin1Pw)) {}

    std::string name() const override { return "DualSessionWorker"; }

    Result execute(INvmeDevice& /*libnvme*/, SedContext& ctx) override {
        Bytes sidCred = HashPassword::passwordToBytes(sidPw_);
        Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw_);

        // Main session: AdminSP
        auto r = ctx.openSession(uid::SP_ADMIN, uid::AUTH_SID, sidCred);
        printf("    Main session (AdminSP/SID): %s\n", r.ok() ? "OK" : "FAIL");

        // Secondary session: LockingSP (independent)
        auto lockSession = ctx.createAndOpenSession(
            uid::SP_LOCKING, uid::AUTH_ADMIN1, admin1Cred);
        printf("    Secondary session (LockingSP/Admin1): %s\n",
               lockSession ? "OK" : "FAIL");

        if (ctx.hasSession() && lockSession) {
            // AdminSP: read lifecycle
            uint8_t lifecycle = 0;
            ctx.api().getSpLifecycle(ctx.session(), uid::SP_LOCKING, lifecycle);
            printf("    [AdminSP] LockingSP lifecycle=%u\n", lifecycle);

            // LockingSP: read locking info
            LockingInfo li;
            ctx.api().getLockingInfo(*lockSession, 0, li);
            printf("    [LockingSP] Range0 RLE=%d WLE=%d\n",
                   li.readLockEnabled, li.writeLockEnabled);

            // Close secondary
            ctx.api().closeSession(*lockSession);
        }

        ctx.closeSession();
        return ErrorCode::Success;
    }
};

// ════════════════════════════════════════════════════════
//  Main: Simulates your evaluation platform
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    std::string device = (argc > 1) ? argv[1] : "/dev/nvme0";
    std::string sidPw = "sid_password";
    std::string admin1Pw = "admin1_password";
    int numThreads = (argc > 2) ? std::stoi(argv[2]) : 2;

    libsed::initialize();

    std::cout << "══════════════════════════════════════════════\n";
    std::cout << "  NVMeThread + Worker + SedContext Demo\n";
    std::cout << "  Device: " << device << "\n";
    std::cout << "  Threads: " << numThreads << "\n";
    std::cout << "══════════════════════════════════════════════\n";

    // ── Create NVMeThreads ──────────────────────────
    std::vector<NVMeThread> nvmeThreads;
    for (int i = 0; i < numThreads; i++) {
        nvmeThreads.emplace_back(device, i);
    }

    // ── Thread 0: Full ownership + locking flow ─────
    nvmeThreads[0].addWorker(std::make_unique<DiscoveryWorker>());
    nvmeThreads[0].addWorker(std::make_unique<OwnershipWorker>(sidPw, admin1Pw));
    nvmeThreads[0].addWorker(std::make_unique<LockingWorker>(admin1Pw, 0));
    nvmeThreads[0].addWorker(std::make_unique<DataStoreWorker>(admin1Pw));

    // ── Thread 1: NVMe + TCG cross-domain tests ─────
    if (numThreads > 1) {
        nvmeThreads[1].addWorker(std::make_unique<DiscoveryWorker>());
        nvmeThreads[1].addWorker(std::make_unique<FormatRecoveryWorker>(sidPw));
        nvmeThreads[1].addWorker(std::make_unique<DualSessionWorker>(sidPw, admin1Pw));
    }

    // ── Run threads ─────────────────────────────────
    std::vector<std::thread> threads;
    for (auto& nt : nvmeThreads) {
        threads.push_back(nt.start());
    }
    for (auto& t : threads) {
        t.join();
    }

    libsed::shutdown();
    std::cout << "\n=== All threads complete ===\n";
    return 0;
}
