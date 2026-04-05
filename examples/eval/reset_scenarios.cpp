/// @file eval_reset_scenarios.cpp
/// @brief NVMe + TCG 복합 예외/리셋 시나리오 예제
///
/// 실제 드라이브 없이 SimLibNvme를 사용하여 Power Reset, NSSR,
/// Controller Reset 등 다양한 예외 상황을 시뮬레이션합니다.
///
/// 12개 시나리오:
///   1. Power Cycle 후 TCG 상태 확인
///   2. NSSR (Non-Synchronous Session Reset) 시뮬레이션
///   3. Controller Reset 후 세션 복구
///   4. LockOnReset 동작 검증
///   5. SP_BUSY 연속 발생 시 복구
///   6. Revert TPer 후 상태 검증
///   7. PSID Revert (Physical Presence)
///   8. 다중 세션 중 리셋
///   9. Timeout 시나리오
///  10. NVMe Sanitize 후 TCG 상태
///  11. 중간 실패 (다단계 설정 부분 실패)
///  12. MBR 리셋 시나리오

#include <libsed/sed_library.h>
#include <libsed/debug/test_context.h>
#include <libsed/debug/fault_builder.h>
#include <libsed/debug/test_session.h>
#include <libsed/transport/nvme_transport.h>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

using namespace libsed;
using namespace libsed::eval;
using namespace libsed::debug;

// ════════════════════════════════════════════════════════
//  SimLibNvme — 시뮬레이션된 NVMe 장치
//  실제 하드웨어 없이 NVMe 및 TCG Security Protocol을
//  시뮬레이션합니다.
// ════════════════════════════════════════════════════════

class SimLibNvme : public INvmeDevice {
public:
    explicit SimLibNvme(const std::string& path) : path_(path) {
        printf("  [SimLibNvme] Opened %s (simulated)\n", path.c_str());
    }

    // Security Protocol — NvmeTransport 내부에서 사용됨
    Result securitySend(uint8_t, uint16_t, const uint8_t*, uint32_t) override {
        return ErrorCode::Success;
    }

    Result securityRecv(uint8_t, uint16_t, uint8_t* data, uint32_t len,
                        uint32_t& received) override {
        // 시뮬레이션된 L0 Discovery 응답
        if (len >= 48) {
            memset(data, 0, len);
            data[0] = 0; data[1] = 0; data[2] = 0; data[3] = 48;
            received = 48;
        }
        return ErrorCode::Success;
    }

    // NVMe Admin 명령
    Result adminCommand(NvmeAdminCmd& cmd, NvmeCompletion& cpl) override {
        printf("  [SimLibNvme] Admin opcode=0x%02X nsid=%u\n", cmd.opcode, cmd.nsid);
        cpl = {};
        return ErrorCode::Success;
    }

    Result ioCommand(NvmeIoCmd& cmd, NvmeCompletion& cpl) override {
        printf("  [SimLibNvme] IO opcode=0x%02X slba=%lu\n", cmd.opcode, cmd.slba);
        cpl = {};
        return ErrorCode::Success;
    }

    Result identify(uint8_t cns, uint32_t nsid, Bytes& data) override {
        printf("  [SimLibNvme] Identify CNS=%u nsid=%u\n", cns, nsid);
        data.resize(4096, 0);
        memcpy(data.data() + 24, "SimNVMe Reset-Test SSD", 22);
        return ErrorCode::Success;
    }

    Result getLogPage(uint8_t logId, uint32_t nsid, Bytes& data, uint32_t dataLen) override {
        printf("  [SimLibNvme] GetLogPage logId=0x%02X\n", logId);
        data.resize(dataLen, 0);
        return ErrorCode::Success;
    }

    Result getFeature(uint8_t fid, uint32_t, uint32_t& cdw0, Bytes&) override {
        printf("  [SimLibNvme] GetFeature fid=0x%02X\n", fid);
        cdw0 = 0;
        return ErrorCode::Success;
    }

    Result setFeature(uint8_t fid, uint32_t, uint32_t, const Bytes&) override {
        printf("  [SimLibNvme] SetFeature fid=0x%02X\n", fid);
        return ErrorCode::Success;
    }

    Result formatNvm(uint32_t nsid, uint8_t lbaf, uint8_t ses, uint8_t) override {
        printf("  [SimLibNvme] Format nsid=%u lbaf=%u ses=%u\n", nsid, lbaf, ses);
        return ErrorCode::Success;
    }

    Result sanitize(uint8_t action, uint32_t) override {
        printf("  [SimLibNvme] Sanitize action=%u\n", action);
        return ErrorCode::Success;
    }

    Result fwDownload(const Bytes&, uint32_t offset) override {
        printf("  [SimLibNvme] FW Download offset=%u\n", offset);
        return ErrorCode::Success;
    }

    Result fwCommit(uint8_t slot, uint8_t action) override {
        printf("  [SimLibNvme] FW Commit slot=%u action=%u\n", slot, action);
        return ErrorCode::Success;
    }

    Result nsCreate(const Bytes&, uint32_t& nsid) override { nsid = 1; return ErrorCode::Success; }
    Result nsDelete(uint32_t) override { return ErrorCode::Success; }
    Result nsAttach(uint32_t, uint16_t, bool) override { return ErrorCode::Success; }

    std::string devicePath() const override { return path_; }
    bool isOpen() const override { return open_; }
    void close() override { open_ = false; }
    int fd() const override { return 42; }

    /// 시뮬레이션 전용: 장치를 다시 열기 (전원 복구 시뮬레이션)
    void reopen() { open_ = true; }

private:
    std::string path_;
    bool open_ = true;
};

// ════════════════════════════════════════════════════════
//  헬퍼: SedContext 생성 유틸리티
// ════════════════════════════════════════════════════════

/// @brief SimLibNvme 기반 SedContext를 생성하고 초기화
static std::unique_ptr<SedContext> createSimContext(
    std::shared_ptr<SimLibNvme>& nvme,
    const std::string& devicePath = "/dev/nvme0")
{
    nvme = std::make_shared<SimLibNvme>(devicePath);
    auto ctx = std::make_unique<SedContext>(
        std::static_pointer_cast<INvmeDevice>(nvme));
    auto r = ctx->initialize();
    printf("  SedContext::initialize() -> %s\n", r.ok() ? "OK" : "FAIL (simulated)");
    return ctx;
}

// ════════════════════════════════════════════════════════
//  시나리오 1: Power Cycle 후 TCG 상태 확인
// ════════════════════════════════════════════════════════

/// @scenario Power Cycle 후 TCG 상태 확인
/// @precondition 드라이브 Opal 2.0 지원, 초기 설정 완료
/// @steps
///   1. SedContext 초기화 및 Discovery 수행
///   2. Locking Range 설정 (LockOnReset=true)
///   3. Transport close (전원 차단 시뮬레이션)
///   4. Transport reopen (전원 복구 시뮬레이션)
///   5. Discovery 재실행
///   6. LockOnReset으로 인한 Range 잠금 상태 검증
/// @expected
///   - 전원 차단 전: Range 설정 성공
///   - 전원 복구 후: Discovery 정상, Range가 잠긴 상태
void scenario_power_cycle() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 1: Power Cycle 후 TCG 상태 확인         │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    // Step 1: SedContext 초기화 및 Discovery
    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 2: Locking Range 설정 시뮬레이션 (LockOnReset=true)
    auto r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_pw");
    printf("  [Pre-Reset] OpenSession(LockingSP/Admin1): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    if (ctx->hasSession()) {
        // Range 0 설정: RLE=true, WLE=true
        r = ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        printf("  [Pre-Reset] setRange(RLE=true, WLE=true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");

        // LockOnReset=true 설정
        r = ctx->api().setLockOnReset(ctx->session(), 0, true);
        printf("  [Pre-Reset] setLockOnReset(true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");

        ctx->closeSession();
    }

    // Step 3: 전원 차단 시뮬레이션 (Transport close)
    printf("  [Power-Off] Closing transport (simulating power loss)...\n");
    nvme->close();

    // Step 4: 전원 복구 시뮬레이션 (새 transport/context 생성)
    printf("  [Power-On] Creating new transport (simulating power restore)...\n");
    nvme->reopen();

    std::shared_ptr<SimLibNvme> nvme2;
    auto ctx2 = createSimContext(nvme2, "/dev/nvme0");

    // Step 5: Discovery 재실행
    TcgOption opt;
    r = ctx2->api().getTcgOption(ctx2->transport(), opt);
    printf("  [Post-Reset] Discovery: %s, ComID=0x%04X\n",
           r.ok() ? "OK" : "FAIL", opt.baseComId);

    // Step 6: LockOnReset으로 인한 Range 잠금 상태 검증
    printf("  [Post-Reset] LockOnReset=true이므로 Range가 잠겨 있어야 합니다\n");
    printf("  [Post-Reset] locked=%d (시뮬레이션: 실제 드라이브에서는 true 기대)\n",
           opt.locked);

    printf("  --> Scenario 1 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 2: NSSR (Non-Synchronous Session Reset) 시뮬레이션
// ════════════════════════════════════════════════════════

/// @scenario CloseSession 없이 StackReset으로 세션 강제 종료
/// @precondition SedContext 초기화 완료
/// @steps
///   1. 세션 열기 (AdminSP, SID 인증)
///   2. CloseSession 호출하지 않음
///   3. StackReset 실행 (Security Protocol 0x02)
///   4. 새 세션 시도
///   5. 상태 검증
/// @expected
///   - StackReset 성공
///   - 새 세션 정상 열림
void scenario_nssr() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 2: NSSR (StackReset) 시뮬레이션          │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 1: AdminSP 세션 열기 (SID 인증)
    auto r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_password");
    printf("  [Step 1] OpenSession(AdminSP/SID): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    // Step 2: CloseSession을 호출하지 않음 (의도적)
    printf("  [Step 2] CloseSession 건너뜀 (세션 열린 상태 유지)\n");

    // Step 3: StackReset 실행 (Security Protocol 0x02)
    printf("  [Step 3] StackReset 실행 (ComID=0x%04X)...\n", ctx->comId());
    r = ctx->api().stackReset(ctx->transport(), ctx->comId());
    printf("  [Step 3] StackReset: %s\n", r.ok() ? "OK" : "FAIL (simulated)");

    // 기존 세션 객체를 무효화 (StackReset 후에는 세션이 TPer 측에서 종료됨)
    // SedContext의 세션을 정리
    ctx->closeSession();

    // Step 4: 새 세션 열기 시도
    r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_password");
    printf("  [Step 4] 새 세션 시도: %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    // Step 5: 상태 검증
    if (ctx->hasSession()) {
        printf("  [Step 5] 새 세션이 정상적으로 열림 (StackReset 후 복구 성공)\n");
        ctx->closeSession();
    } else {
        printf("  [Step 5] 새 세션 실패 (시뮬레이션 환경에서는 정상)\n");
    }

    printf("  --> Scenario 2 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 3: Controller Reset 후 세션 복구
// ════════════════════════════════════════════════════════

/// @scenario Controller Reset 후 세션 복구
/// @precondition SedContext 초기화 완료
/// @steps
///   1. 활성 세션에서 작업 수행
///   2. Fault injection: DropPacket으로 Controller Reset 시뮬레이션
///   3. Transport 재연결
///   4. Discovery 재실행
///   5. 새 세션 열기
/// @expected
///   - Fault 주입으로 패킷 드롭
///   - 재연결 후 Discovery 성공
///   - 새 세션 정상 열림
void scenario_controller_reset() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 3: Controller Reset 후 세션 복구         │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    auto& tc = TestContext::instance();
    tc.enable();

    TestSession ts("ctrl_reset");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 1: 활성 세션에서 작업 수행
    auto r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_pw");
    printf("  [Step 1] OpenSession(LockingSP/Admin1): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    if (ctx->hasSession()) {
        LockingInfo li;
        ctx->api().getLockingInfo(ctx->session(), 0, li);
        printf("  [Step 1] Range 0 읽기: RLE=%d WLE=%d\n",
               li.readLockEnabled, li.writeLockEnabled);
    }

    // Step 2: Fault injection — DropPacket으로 Controller Reset 시뮬레이션
    ts.fault(
        FaultBuilder("ctrl_reset_drop")
            .at(FaultPoint::BeforeIfSend)
            .drop()
            .once()
    );
    printf("  [Step 2] Fault 장착: DropPacket (Controller Reset 시뮬)\n");

    // 패킷 드롭이 발생할 작업 시도
    if (ctx->hasSession()) {
        r = ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        printf("  [Step 2] 작업 시도 (드롭 예상): %s\n",
               r.ok() ? "OK" : "FAIL (패킷 드롭됨)");
    }

    // Step 3: Transport 재연결 (기존 세션 폐기)
    ctx->closeSession();
    printf("  [Step 3] Transport 재연결 (기존 세션 폐기)\n");

    // Step 4: Discovery 재실행
    TcgOption opt;
    r = ctx->api().getTcgOption(ctx->transport(), opt);
    printf("  [Step 4] Discovery 재실행: %s, ComID=0x%04X\n",
           r.ok() ? "OK" : "FAIL", opt.baseComId);

    // Step 5: 새 세션 열기
    r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_pw");
    printf("  [Step 5] 새 세션 열기: %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    if (ctx->hasSession()) {
        ctx->closeSession();
    }

    tc.disable();
    printf("  --> Scenario 3 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 4: LockOnReset 동작 검증
// ════════════════════════════════════════════════════════

/// @scenario LockOnReset 동작 검증
/// @precondition SedContext 초기화 완료, Locking SP 활성화됨
/// @steps
///   1. Range 설정 (LockOnReset=true, ReadLockEnabled/WriteLockEnabled=true)
///   2. 초기 상태: 잠금 해제
///   3. StackReset으로 리셋 시뮬레이션
///   4. Discovery 및 Range 상태 확인
/// @expected
///   - 리셋 전: ReadLocked=false, WriteLocked=false
///   - 리셋 후: ReadLocked=true, WriteLocked=true
void scenario_lock_on_reset() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 4: LockOnReset 동작 검증                │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 1: Range 설정 (LockOnReset=true)
    auto r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_pw");
    printf("  [Step 1] OpenSession(LockingSP/Admin1): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    if (ctx->hasSession()) {
        // ReadLockEnabled=true, WriteLockEnabled=true
        r = ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        printf("  [Step 1] setRange(RLE=true, WLE=true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");

        // LockOnReset=true
        r = ctx->api().setLockOnReset(ctx->session(), 0, true);
        printf("  [Step 1] setLockOnReset(true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");

        // Step 2: 초기 상태 확인 — 잠금 해제 상태
        LockingInfo li;
        ctx->api().getLockingInfo(ctx->session(), 0, li);
        printf("  [Step 2] 리셋 전: ReadLocked=%d WriteLocked=%d\n",
               li.readLocked, li.writeLocked);

        ctx->closeSession();
    }

    // Step 3: StackReset으로 리셋 시뮬레이션
    printf("  [Step 3] StackReset 실행...\n");
    r = ctx->api().stackReset(ctx->transport(), ctx->comId());
    printf("  [Step 3] StackReset: %s\n", r.ok() ? "OK" : "FAIL (simulated)");

    // Step 4: 리셋 후 상태 확인
    // 새 SedContext로 재초기화 (리셋 후 이전 상태 무효)
    std::shared_ptr<SimLibNvme> nvme2;
    auto ctx2 = createSimContext(nvme2);

    TcgOption opt;
    r = ctx2->api().getTcgOption(ctx2->transport(), opt);
    printf("  [Step 4] Discovery: %s\n", r.ok() ? "OK" : "FAIL");

    r = ctx2->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_pw");
    if (ctx2->hasSession()) {
        LockingInfo li;
        ctx2->api().getLockingInfo(ctx2->session(), 0, li);
        printf("  [Step 4] 리셋 후: ReadLocked=%d WriteLocked=%d\n",
               li.readLocked, li.writeLocked);
        printf("  [Step 4] (실제 드라이브: LockOnReset=true이면 둘 다 true 기대)\n");
        ctx2->closeSession();
    }

    printf("  --> Scenario 4 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 5: SP_BUSY 연속 발생 시 복구
// ════════════════════════════════════════════════════════

/// @scenario SP_BUSY 연속 발생 시 복구
/// @precondition SedContext 초기화 완료, TestContext 활성화
/// @steps
///   1. Fault injection: 처음 N회 SP_BUSY 에러 반환
///   2. Workaround 활성화 (RetryOnSpBusy)
///   3. 작업 수행
///   4. 재시도 로직으로 최종 성공 확인
/// @expected
///   - 처음 N회 SP_BUSY 발생
///   - 재시도 후 최종 성공
///   - 카운터로 재시도 횟수 확인
void scenario_sp_busy_recovery() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 5: SP_BUSY 연속 발생 시 복구             │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    auto& tc = TestContext::instance();
    tc.enable();

    TestSession ts("sp_busy_recovery");

    // Step 1: Fault injection — 처음 3회 SP_BUSY 에러 반환
    ts.fault(
        FaultBuilder("busy_3x")
            .at(FaultPoint::AfterRecvMethod)
            .returnError(ErrorCode::MethodSpBusy)
            .times(3)
    );
    printf("  [Step 1] Fault 장착: SP_BUSY x 3회\n");

    // Step 2: Workaround 활성화 (RetryOnSpBusy)
    ts.workaround(workaround::kRetryOnSpBusy);
    printf("  [Step 2] Workaround 활성화: RetryOnSpBusy\n");

    // Step 3: 작업 수행
    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    auto r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_password");
    printf("  [Step 3] OpenSession 시도: %s\n",
           r.ok() ? "OK (재시도 후 성공)" : "FAIL");

    // Step 4: 재시도 카운터 확인
    printf("  [Step 4] transport.send 카운터 = %lu\n",
           (unsigned long)ts.counter("transport.send"));
    printf("  [Step 4] transport.recv 카운터 = %lu\n",
           (unsigned long)ts.counter("transport.recv"));

    // 트레이스 이벤트 출력
    auto events = ts.trace();
    printf("  [Step 4] 트레이스 이벤트: %zu개\n", events.size());
    for (size_t i = 0; i < events.size() && i < 5; i++) {
        printf("    [%zu] %s : %s (rc=%d)\n",
               i, events[i].tag.c_str(), events[i].detail.c_str(),
               static_cast<int>(events[i].result));
    }

    if (ctx->hasSession()) {
        ctx->closeSession();
    }

    tc.disable();
    printf("  --> Scenario 5 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 6: Revert TPer 후 상태 검증
// ════════════════════════════════════════════════════════

/// @scenario Revert TPer 후 상태 검증
/// @precondition 소유권 확보 및 Locking SP 활성화됨
/// @steps
///   1. 소유권 확보 (SID 비밀번호 설정)
///   2. Locking SP 활성화
///   3. Locking Range 설정
///   4. RevertTPer 실행
///   5. Discovery 재실행
///   6. 초기 상태 확인 (SID==MSID 확인 가능)
/// @expected
///   - RevertTPer 성공
///   - Discovery 후 Locking SP 비활성화 확인
///   - 모든 설정이 공장 초기 상태로 복원
void scenario_revert_tper() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 6: Revert TPer 후 상태 검증              │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 1: 소유권 확보
    auto r = ctx->takeOwnership("new_sid_password");
    printf("  [Step 1] takeOwnership: %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    // Step 2: Locking SP 활성화
    r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "new_sid_password");
    printf("  [Step 2] OpenSession(AdminSP/SID): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    if (ctx->hasSession()) {
        r = ctx->api().activate(ctx->session(), uid::SP_LOCKING);
        printf("  [Step 2] Activate LockingSP: %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        ctx->closeSession();
    }

    // Step 3: Locking Range 설정
    r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "new_sid_password");
    if (ctx->hasSession()) {
        r = ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        printf("  [Step 3] setRange(RLE=true, WLE=true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        ctx->closeSession();
    }

    // Step 4: RevertTPer 실행 (AdminSP 세션으로)
    r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "new_sid_password");
    if (ctx->hasSession()) {
        // revertSP on AdminSP는 사실상 RevertTPer와 동등
        r = ctx->api().revertSP(ctx->session(), uid::SP_ADMIN);
        printf("  [Step 4] RevertTPer (revertSP/AdminSP): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        // Revert 후 세션이 자동으로 종료될 수 있음
        ctx->closeSession();
    }

    // Step 5: Discovery 재실행
    std::shared_ptr<SimLibNvme> nvme2;
    auto ctx2 = createSimContext(nvme2);

    TcgOption opt;
    r = ctx2->api().getTcgOption(ctx2->transport(), opt);
    printf("  [Step 5] Discovery: %s\n", r.ok() ? "OK" : "FAIL");
    printf("  [Step 5] lockingEnabled=%d locked=%d\n",
           opt.lockingEnabled, opt.locked);

    // Step 6: 초기 상태 확인
    Bytes msid;
    r = ctx2->readMsid(msid);
    printf("  [Step 6] MSID 읽기: %s (%zuB)\n",
           r.ok() ? "OK" : "FAIL (simulated)", msid.size());
    printf("  [Step 6] Revert 후: SID==MSID (공장 초기 상태 복원 기대)\n");

    printf("  --> Scenario 6 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 7: PSID Revert (Physical Presence)
// ════════════════════════════════════════════════════════

/// @scenario PSID Revert (Physical Presence)
/// @precondition 드라이브가 잠긴 상태, PSID가 알려져 있음
/// @steps
///   1. 드라이브를 잠긴 상태로 설정
///   2. PSID로 AdminSP 세션 열기
///   3. PSID Revert 실행
///   4. 초기 상태 복원 확인
/// @expected
///   - PSID Revert 성공
///   - 드라이브 초기 상태 복원
void scenario_psid_revert() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 7: PSID Revert (Physical Presence)      │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 1: 드라이브를 잠긴 상태로 설정 시뮬레이션
    auto r = ctx->takeOwnership("sid_locked");
    printf("  [Step 1] takeOwnership(locked): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_locked");
    if (ctx->hasSession()) {
        ctx->api().activate(ctx->session(), uid::SP_LOCKING);
        printf("  [Step 1] Activate LockingSP: %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        ctx->closeSession();
    }

    r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "sid_locked");
    if (ctx->hasSession()) {
        ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        ctx->api().setRangeLock(ctx->session(), 0, true, true);
        printf("  [Step 1] Range 잠금 설정 완료\n");
        ctx->closeSession();
    }

    // Step 2: PSID로 AdminSP 세션 열기
    // PSID는 드라이브 라벨에 인쇄된 32바이트 값 (시뮬레이션)
    std::string psidStr = "SIMULATED_PSID_VALUE_1234567890";
    Bytes psidCred = HashPassword::passwordToBytes(psidStr);

    r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_PSID, psidCred);
    printf("  [Step 2] OpenSession(AdminSP/PSID): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    // Step 3: PSID Revert 실행
    if (ctx->hasSession()) {
        r = ctx->api().psidRevert(ctx->session());
        printf("  [Step 3] PSID Revert: %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        ctx->closeSession();
    } else {
        printf("  [Step 3] PSID Revert 건너뜀 (세션 없음, 시뮬레이션 환경)\n");
    }

    // Step 4: 초기 상태 복원 확인
    std::shared_ptr<SimLibNvme> nvme2;
    auto ctx2 = createSimContext(nvme2);

    TcgOption opt;
    r = ctx2->api().getTcgOption(ctx2->transport(), opt);
    printf("  [Step 4] Discovery: %s\n", r.ok() ? "OK" : "FAIL");
    printf("  [Step 4] lockingEnabled=%d (Revert 후 false 기대)\n",
           opt.lockingEnabled);

    printf("  --> Scenario 7 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 8: 다중 세션 중 리셋
// ════════════════════════════════════════════════════════

/// @scenario 다중 세션 중 리셋
/// @precondition 소유권 확보, Locking SP 활성화됨
/// @steps
///   1. AdminSP 세션 + LockingSP 세션 동시 열기
///   2. 한 세션에서 RevertSP 실행
///   3. 다른 세션에서 상태 확인
/// @expected
///   - RevertSP 성공
///   - 다른 세션에서 에러 (SessionClosed 또는 유사 에러)
void scenario_concurrent_reset() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 8: 다중 세션 중 리셋                     │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // 소유권 확보 시뮬레이션
    ctx->takeOwnership("sid_concurrent");

    // Step 1: AdminSP 세션 + LockingSP 세션 동시 열기
    // 메인 세션: AdminSP
    auto r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_concurrent");
    printf("  [Step 1] Main session (AdminSP/SID): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    // 보조 세션: LockingSP (독립 세션)
    Bytes admin1Cred = HashPassword::passwordToBytes("admin1_concurrent");
    auto lockSession = ctx->createAndOpenSession(
        uid::SP_LOCKING, uid::AUTH_ADMIN1, admin1Cred);
    printf("  [Step 1] Secondary session (LockingSP/Admin1): %s\n",
           lockSession ? "OK" : "FAIL (simulated)");

    // Step 2: AdminSP 세션에서 Locking SP Revert 실행
    if (ctx->hasSession()) {
        r = ctx->api().revertSP(ctx->session(), uid::SP_LOCKING);
        printf("  [Step 2] RevertSP(LockingSP) via AdminSP: %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
    }

    // Step 3: LockingSP 세션에서 작업 시도 (세션이 무효화되어야 함)
    if (lockSession) {
        LockingInfo li;
        r = ctx->api().getLockingInfo(*lockSession, 0, li);
        printf("  [Step 3] LockingSP 세션으로 작업 시도: %s\n",
               r.ok() ? "OK (예상 외)" : "FAIL (예상됨: 세션 무효화)");
        printf("  [Step 3] 에러 코드: %s\n", r.message().c_str());

        // 보조 세션 정리
        ctx->api().closeSession(*lockSession);
    }

    ctx->closeSession();
    printf("  --> Scenario 8 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 9: Timeout 시나리오
// ════════════════════════════════════════════════════════

/// @scenario Timeout 시나리오
/// @precondition SedContext 초기화 완료, TestContext 활성화
/// @steps
///   1. Fault injection: DelayMs 주입 (큰 지연)
///   2. 짧은 타임아웃으로 작업 시도
///   3. 타임아웃 에러 확인
/// @expected
///   - TransportTimeout 에러 코드 발생
void scenario_timeout() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 9: Timeout 시나리오                      │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    auto& tc = TestContext::instance();
    tc.enable();

    TestSession ts("timeout_scenario");

    // Step 1: Fault injection — 큰 지연 주입
    // 참고: 실제로는 DelayMs가 스레드를 블록하므로 시뮬레이션 환경에서는
    // ReturnError(TransportTimeout)으로 대체
    ts.fault(
        FaultBuilder("timeout_inject")
            .at(FaultPoint::BeforeIfRecv)
            .returnError(ErrorCode::TransportTimeout)
            .once()
    );
    printf("  [Step 1] Fault 장착: TransportTimeout (IF-RECV 전)\n");

    // Step 2: 짧은 타임아웃으로 작업 시도
    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    auto r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_password");
    printf("  [Step 2] OpenSession 시도: %s\n",
           r.ok() ? "OK" : "FAIL");

    // Step 3: 타임아웃 에러 확인
    if (r.failed()) {
        printf("  [Step 3] 에러 코드: %s (code=%d)\n",
               r.message().c_str(), static_cast<int>(r.code()));
        bool isTimeout = (r.code() == ErrorCode::TransportTimeout);
        printf("  [Step 3] TransportTimeout 여부: %s\n",
               isTimeout ? "YES" : "NO (다른 에러)");
    } else {
        printf("  [Step 3] 세션이 열림 (Fault가 소비되지 않았을 수 있음)\n");
        ctx->closeSession();
    }

    // 트레이스 확인
    auto events = ts.trace();
    printf("  [Step 3] 트레이스 이벤트: %zu개\n", events.size());

    tc.disable();
    printf("  --> Scenario 9 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 10: NVMe Sanitize 후 TCG 상태
// ════════════════════════════════════════════════════════

/// @scenario NVMe Sanitize 후 TCG 상태
/// @precondition SedContext 초기화 완료, Locking Range 설정됨
/// @steps
///   1. TCG 설정 (Locking Range 등)
///   2. NVMe Sanitize 명령 실행
///   3. Discovery 재실행
///   4. SED 상태 변경 확인
/// @expected
///   - Sanitize 명령 성공
///   - Discovery 후 SED 상태 확인
void scenario_sanitize_tcg_state() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 10: NVMe Sanitize 후 TCG 상태           │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 1: TCG 설정 (Locking Range)
    auto r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_pw");
    printf("  [Step 1] OpenSession(LockingSP/Admin1): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    if (ctx->hasSession()) {
        r = ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        printf("  [Step 1] setRange(RLE=true, WLE=true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");

        r = ctx->api().setRangeLock(ctx->session(), 0, true, true);
        printf("  [Step 1] Lock Range 0: %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        ctx->closeSession();
    }

    // Step 2: NVMe Sanitize 명령 실행 (INvmeDevice 직접 사용)
    INvmeDevice* nvmeDev = ctx->nvme();
    if (nvmeDev) {
        // Sanitize action=2 (Block Erase)
        r = nvmeDev->sanitize(2, 0);
        printf("  [Step 2] NVMe Sanitize (Block Erase): %s\n",
               r.ok() ? "OK" : "FAIL");
    } else {
        printf("  [Step 2] NVMe device not available\n");
    }

    // Step 3: Discovery 재실행
    // Sanitize 후에는 NVMe 컨트롤러가 리셋될 수 있으므로 새 컨텍스트
    std::shared_ptr<SimLibNvme> nvme2;
    auto ctx2 = createSimContext(nvme2);

    TcgOption opt;
    r = ctx2->api().getTcgOption(ctx2->transport(), opt);
    printf("  [Step 3] Discovery: %s\n", r.ok() ? "OK" : "FAIL");

    // Step 4: SED 상태 확인
    printf("  [Step 4] lockingEnabled=%d locked=%d\n",
           opt.lockingEnabled, opt.locked);
    printf("  [Step 4] mbrEnabled=%d mbrDone=%d\n",
           opt.mbrEnabled, opt.mbrDone);
    printf("  [Step 4] 참고: NVMe Sanitize는 TCG 상태에 영향을 줄 수도 있고 아닐 수도 있음\n");
    printf("  [Step 4] (벤더 구현에 따라 다름 — TCG Core 스펙에서는 Sanitize 후\n");
    printf("           SED 상태 유지를 보장하지 않음)\n");

    printf("  --> Scenario 10 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 11: 중간 실패 (다단계 설정 부분 실패)
// ════════════════════════════════════════════════════════

/// @scenario 중간 실패 (다단계 설정 부분 실패)
/// @precondition SedContext 초기화 완료, TestContext 활성화
/// @steps
///   1. 다단계 설정 시작 (소유권 → 활성화 → Range 설정)
///   2. 중간 단계에서 Fault injection으로 실패 유도
///   3. 부분 상태 검증
///   4. 복구 시도
/// @expected
///   - 실패 시점까지의 상태만 적용됨
///   - 복구 시도 시 정상 상태 복원
void scenario_partial_failure() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 11: 중간 실패 (다단계 설정 부분 실패)      │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    auto& tc = TestContext::instance();
    tc.enable();

    TestSession ts("partial_failure");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // Step 1: 다단계 설정 시작
    // 1-a: 소유권 확보
    auto r = ctx->takeOwnership("sid_partial");
    printf("  [Step 1a] takeOwnership: %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    // 1-b: Locking SP 활성화
    r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_partial");
    if (ctx->hasSession()) {
        r = ctx->api().activate(ctx->session(), uid::SP_LOCKING);
        printf("  [Step 1b] Activate LockingSP: %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        ctx->closeSession();
    }

    // Step 2: Fault injection — Range 설정 단계에서 실패 유도
    // 3번째 메서드 호출 후 에러 반환 (setRange에서 실패 유도)
    ts.fault(
        FaultBuilder("partial_fail_at_range")
            .at(FaultPoint::AfterRecvMethod)
            .returnError(ErrorCode::MethodFailed)
            .once()
    );
    printf("  [Step 2] Fault 장착: MethodFailed (Range 설정 시 발동 예상)\n");

    // 1-c: Locking Range 설정 (여기서 실패 예상)
    r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "sid_partial");
    if (ctx->hasSession()) {
        // Admin1 비밀번호 설정 (성공해야 함)
        r = ctx->api().setAdmin1Password(ctx->session(), "admin1_partial");
        printf("  [Step 2] setAdmin1Password: %s\n",
               r.ok() ? "OK" : "FAIL");

        // Range 설정 (Fault로 인해 실패 예상)
        r = ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        printf("  [Step 2] setRange: %s\n",
               r.ok() ? "OK (Fault 미발동)" : "FAIL (Fault 발동됨)");

        ctx->closeSession();
    }

    // Step 3: 부분 상태 검증
    printf("  [Step 3] 부분 상태 검증:\n");
    printf("    - 소유권: 확보됨 (SID 비밀번호 변경됨)\n");
    printf("    - Locking SP: 활성화됨\n");
    printf("    - Range 설정: 실패 (Fault에 의해 중단)\n");

    r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_partial");
    if (ctx->hasSession()) {
        LockingInfo li;
        ctx->api().getLockingInfo(ctx->session(), 0, li);
        printf("  [Step 3] Range 0: RLE=%d WLE=%d (실패 후 상태)\n",
               li.readLockEnabled, li.writeLockEnabled);
        ctx->closeSession();
    }

    // Step 4: 복구 시도 (Fault 해제 후 재시도)
    ts.disarmAllFaults();
    printf("  [Step 4] Fault 해제, 복구 시도...\n");

    r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "admin1_partial");
    if (ctx->hasSession()) {
        r = ctx->api().setRange(ctx->session(), 0, 0, 0, true, true);
        printf("  [Step 4] 재시도 setRange(RLE=true, WLE=true): %s\n",
               r.ok() ? "OK (복구 성공)" : "FAIL");
        ctx->closeSession();
    }

    tc.disable();
    printf("  --> Scenario 11 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  시나리오 12: MBR 리셋 시나리오
// ════════════════════════════════════════════════════════

/// @scenario MBR 리셋 시나리오
/// @precondition Locking SP 활성화됨, Admin1 인증 가능
/// @steps
///   1. MBR Enable/Done 설정
///   2. MBR 데이터 쓰기
///   3. Revert 실행
///   4. MBR 상태 초기화 확인
/// @expected
///   - MBR Enable=true, Done=true 설정 성공
///   - Revert 후 MBR Enable=false, Done=false 복원
void scenario_mbr_reset() {
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│ Scenario 12: MBR 리셋 시나리오                    │\n");
    printf("└─────────────────────────────────────────────────┘\n");

    std::shared_ptr<SimLibNvme> nvme;
    auto ctx = createSimContext(nvme);

    // 사전 설정: 소유권 확보 + Locking SP 활성화
    ctx->takeOwnership("sid_mbr");
    auto r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_mbr");
    if (ctx->hasSession()) {
        ctx->api().activate(ctx->session(), uid::SP_LOCKING);
        ctx->closeSession();
    }

    // Step 1: MBR Enable/Done 설정
    r = ctx->openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "sid_mbr");
    printf("  [Step 1] OpenSession(LockingSP/Admin1): %s\n",
           r.ok() ? "OK" : "FAIL (simulated)");

    if (ctx->hasSession()) {
        // MBR Enable
        r = ctx->api().setMbrEnable(ctx->session(), true);
        printf("  [Step 1] setMbrEnable(true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");

        // MBR Done
        r = ctx->api().setMbrDone(ctx->session(), true);
        printf("  [Step 1] setMbrDone(true): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");

        // MBR 상태 확인
        bool mbrEnabled = false, mbrDone = false;
        r = ctx->api().getMbrStatus(ctx->session(), mbrEnabled, mbrDone);
        printf("  [Step 1] MBR 상태: Enable=%d Done=%d\n",
               mbrEnabled, mbrDone);

        // Step 2: MBR 데이터 쓰기
        Bytes mbrData = {
            0xEB, 0x5A, 0x90,    // JMP short (x86 부트 시그니처)
            0x4C, 0x49, 0x42,    // "LIB"
            0x53, 0x45, 0x44,    // "SED"
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        r = ctx->api().writeMbrData(ctx->session(), 0, mbrData);
        printf("  [Step 2] writeMbrData (%zuB): %s\n",
               mbrData.size(), r.ok() ? "OK" : "FAIL (simulated)");

        // MBR 데이터 읽기 확인
        Bytes readBack;
        r = ctx->api().readMbrData(ctx->session(), 0, 16, readBack);
        printf("  [Step 2] readMbrData: %s (%zuB)\n",
               r.ok() ? "OK" : "FAIL (simulated)", readBack.size());

        ctx->closeSession();
    }

    // Step 3: Revert 실행 (Locking SP 리버트)
    r = ctx->openSession(uid::SP_ADMIN, uid::AUTH_SID, "sid_mbr");
    if (ctx->hasSession()) {
        r = ctx->api().revertSP(ctx->session(), uid::SP_LOCKING);
        printf("  [Step 3] RevertSP(LockingSP): %s\n",
               r.ok() ? "OK" : "FAIL (simulated)");
        ctx->closeSession();
    }

    // Step 4: MBR 상태 초기화 확인
    // Revert 후 새 컨텍스트로 Discovery
    std::shared_ptr<SimLibNvme> nvme2;
    auto ctx2 = createSimContext(nvme2);

    TcgOption opt;
    r = ctx2->api().getTcgOption(ctx2->transport(), opt);
    printf("  [Step 4] Discovery: %s\n", r.ok() ? "OK" : "FAIL");
    printf("  [Step 4] mbrEnabled=%d mbrDone=%d\n",
           opt.mbrEnabled, opt.mbrDone);
    printf("  [Step 4] (Revert 후: mbrEnabled=false, mbrDone=false 기대)\n");

    printf("  --> Scenario 12 완료\n\n");
}

// ════════════════════════════════════════════════════════
//  main()
// ════════════════════════════════════════════════════════

int main() {
    printf("═══════════════════════════════════════════════════\n");
    printf("  NVMe + TCG 복합 예외/리셋 시나리오 (12개)\n");
    printf("  SimLibNvme 시뮬레이션 환경 (실제 드라이브 불필요)\n");
    printf("═══════════════════════════════════════════════════\n\n");

    libsed::initialize();

    scenario_power_cycle();
    scenario_nssr();
    scenario_controller_reset();
    scenario_lock_on_reset();
    scenario_sp_busy_recovery();
    scenario_revert_tper();
    scenario_psid_revert();
    scenario_concurrent_reset();
    scenario_timeout();
    scenario_sanitize_tcg_state();
    scenario_partial_failure();
    scenario_mbr_reset();

    // 전역 TestContext 정리
    TestContext::instance().reset();

    libsed::shutdown();

    printf("═══════════════════════════════════════════════════\n");
    printf("  모든 시나리오 완료 (12/12)\n");
    printf("═══════════════════════════════════════════════════\n");
    return 0;
}
