/// @file eval_multi_session.cpp
/// @brief Multi-session and multi-thread TCG SED evaluation example.
///
/// Demonstrates:
///   1. Multiple concurrent TCG sessions (Admin SP + Locking SP)
///   2. Multi-threaded evaluation with thread-safe session management
///   3. NVMe commands interleaved with TCG operations (via DI)
///   4. Parallel range configuration across threads
///   5. Stress testing with concurrent lock/unlock
///   6. Session pool pattern for eval frameworks

#include <libsed/sed_library.h>
#include <libsed/transport/nvme_transport.h>
#include <iostream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <functional>
#include <chrono>
#include <cassert>

using namespace libsed;
using namespace libsed::eval;
using Clock = std::chrono::high_resolution_clock;

static std::mutex g_printMutex;

#define TLOG(tid, ...) do { \
    std::lock_guard<std::mutex> lk(g_printMutex); \
    printf("[T%02d] ", tid); \
    printf(__VA_ARGS__); \
    printf("\n"); \
} while(0)

// ════════════════════════════════════════════════════════
//  1. Dual Session: AdminSP + LockingSP simultaneously
// ════════════════════════════════════════════════════════

/// @scenario 이중 세션 (AdminSP + LockingSP 동시 운용)
/// @precondition NVMe 디바이스가 열려 있고 SID 및 Admin1 비밀번호가 유효해야 함
/// @steps
///   1. Session A: AdminSP에 SID 인증으로 Write 세션 시작
///   2. Session B: LockingSP에 Admin1 인증으로 Write 세션 시작
///   3. Session A에서 SP Lifecycle 조회
///   4. Session B에서 Locking Info(Global Range) 조회
///   5. 두 세션 모두 활성 상태(active) 확인
///   6. 두 세션 순차 종료
/// @expected
///   - 두 세션이 동시에 활성 상태로 유지됨
///   - Session A(AdminSP)에서 Lifecycle 조회, Session B(LockingSP)에서 Locking Info 조회 등 교차 작업 정상 수행
///   - 각 세션의 HSN/TSN이 독립적으로 할당됨
static void demo_dualSession(EvalApi& api,
                              std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const std::string& sidPw,
                              const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  1. Dual Session: AdminSP + LockingSP     ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes sidCred = HashPassword::passwordToBytes(sidPw);
    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    // Session A: AdminSP as SID
    Session sessionA(transport, comId);
    StartSessionResult ssrA;
    auto rA = api.startSessionWithAuth(sessionA, uid::SP_ADMIN, true,
                                        uid::AUTH_SID, sidCred, ssrA);
    std::cout << "  SessionA (AdminSP/SID): "
              << (rA.ok() ? "OK" : "FAIL")
              << " HSN=" << ssrA.hostSessionNumber
              << " TSN=" << ssrA.tperSessionNumber << "\n";

    // Session B: LockingSP as Admin1
    Session sessionB(transport, comId);
    StartSessionResult ssrB;
    auto rB = api.startSessionWithAuth(sessionB, uid::SP_LOCKING, true,
                                        uid::AUTH_ADMIN1, admin1Cred, ssrB);
    std::cout << "  SessionB (LockingSP/Admin1): "
              << (rB.ok() ? "OK" : "FAIL")
              << " HSN=" << ssrB.hostSessionNumber
              << " TSN=" << ssrB.tperSessionNumber << "\n";

    if (rA.ok() && rB.ok()) {
        // Interleaved operations on both sessions
        // Read SP lifecycle from AdminSP
        uint8_t lifecycle = 0;
        api.getSpLifecycle(sessionA, uid::SP_LOCKING, lifecycle);
        std::cout << "  [A] Locking SP lifecycle = " << (int)lifecycle << "\n";

        // Read locking info from LockingSP
        LockingInfo li;
        api.getLockingInfo(sessionB, 0, li);
        std::cout << "  [B] GlobalRange: start=" << li.rangeStart
                  << " RLE=" << li.readLockEnabled << "\n";

        // Both sessions active simultaneously — different SPs
        auto infoA = EvalApi::getSessionInfo(sessionA);
        auto infoB = EvalApi::getSessionInfo(sessionB);
        std::cout << "  Both active: A=" << infoA.active << " B=" << infoB.active << "\n";
    }

    if (rA.ok()) api.closeSession(sessionA);
    if (rB.ok()) api.closeSession(sessionB);
}

// ════════════════════════════════════════════════════════
//  2. Multi-threaded: Parallel range query
// ════════════════════════════════════════════════════════

/// @scenario 멀티스레드 병렬 Range 조회
/// @precondition NVMe 디바이스가 열려 있고 Admin1 비밀번호가 유효해야 함
/// @steps
///   1. numRanges개 스레드 생성
///   2. 각 스레드가 독립적으로 LockingSP 세션 열기 (Read-only, Admin1 인증)
///   3. 각 스레드가 자신의 Range ID에 해당하는 Locking Info 조회
///   4. 모든 스레드 종료 후 성공/실패 카운트 및 소요 시간 출력
/// @expected
///   - 각 스레드가 독립 세션으로 병렬 Range 읽기 성공
///   - 스레드 간 세션 간섭 없음
///   - 전체 소요 시간이 순차 실행보다 단축됨
static void demo_parallelRangeQuery(EvalApi& api,
                                     std::shared_ptr<ITransport> transport,
                                     uint16_t comId,
                                     const std::string& admin1Pw,
                                     uint32_t numRanges) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  2. Multi-Thread: Parallel Range Query    ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(admin1Pw);
    std::vector<LockingInfo> results(numRanges);
    std::atomic<uint32_t> successCount{0};
    std::atomic<uint32_t> failCount{0};

    auto start = Clock::now();

    // Each thread opens its own session and reads one range
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < numRanges; i++) {
        threads.emplace_back([&, i]() {
            EvalApi threadApi;
            Session session(transport, comId);
            StartSessionResult ssr;

            auto r = threadApi.startSessionWithAuth(session, uid::SP_LOCKING, false,
                                                     uid::AUTH_ADMIN1, cred, ssr);
            if (r.failed()) {
                TLOG(i, "Session open FAIL: %s", r.message().c_str());
                failCount++;
                return;
            }

            r = threadApi.getLockingInfo(session, i, results[i]);
            if (r.ok()) {
                TLOG(i, "Range %u: start=%lu len=%lu RLE=%d",
                     i, results[i].rangeStart, results[i].rangeLength,
                     results[i].readLockEnabled);
                successCount++;
            } else {
                TLOG(i, "Range %u: FAIL %s", i, r.message().c_str());
                failCount++;
            }

            threadApi.closeSession(session);
        });
    }

    for (auto& t : threads) t.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();

    std::cout << "\n  Results: " << successCount << " success, "
              << failCount << " fail, " << elapsed << "ms\n";
}

// ════════════════════════════════════════════════════════
//  3. Stress test: Concurrent lock/unlock cycles
// ════════════════════════════════════════════════════════

/// @scenario 동시 Lock/Unlock 순환 스트레스 테스트
/// @precondition NVMe 디바이스가 열려 있고 User1 비밀번호가 유효하며 Range 0이 구성되어 있어야 함
/// @steps
///   1. numThreads개 스레드 생성
///   2. 각 스레드가 cyclesPerThread회 반복:
///      a. LockingSP에 User1 인증으로 Write 세션 열기
///      b. setRangeLock(0, true, true) — Range 0 잠금
///      c. setRangeLock(0, false, false) — Range 0 잠금 해제
///      d. 세션 닫기
///   3. 전체 성공/실패 카운트, 소요 시간, 처리량(ops/sec) 출력
/// @expected
///   - 높은 성공률의 Lock/Unlock 순환
///   - 처리량(ops/sec) 측정으로 성능 기준선 확보
///   - 동시 접근에도 프로토콜 오류 없이 안정적 동작
static void demo_lockUnlockStress(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& userPw,
                                   uint32_t numThreads,
                                   uint32_t cyclesPerThread) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  3. Stress: Concurrent Lock/Unlock        ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(userPw);
    std::atomic<uint32_t> lockOk{0}, lockFail{0};
    std::atomic<uint32_t> unlockOk{0}, unlockFail{0};

    auto start = Clock::now();

    std::vector<std::thread> threads;
    for (uint32_t t = 0; t < numThreads; t++) {
        threads.emplace_back([&, t]() {
            EvalApi threadApi;

            for (uint32_t c = 0; c < cyclesPerThread; c++) {
                Session session(transport, comId);
                StartSessionResult ssr;
                auto r = threadApi.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                                         uid::AUTH_USER1, cred, ssr);
                if (r.failed()) {
                    TLOG(t, "Cycle %u: session fail", c);
                    lockFail++;
                    continue;
                }

                // Lock
                r = threadApi.setRangeLock(session, 0, true, true);
                if (r.ok()) lockOk++; else lockFail++;

                // Unlock
                r = threadApi.setRangeLock(session, 0, false, false);
                if (r.ok()) unlockOk++; else unlockFail++;

                threadApi.closeSession(session);
            }
            TLOG(t, "Done %u cycles", cyclesPerThread);
        });
    }

    for (auto& t : threads) t.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();

    std::cout << "\n  Lock:   " << lockOk << " ok / " << lockFail << " fail\n";
    std::cout << "  Unlock: " << unlockOk << " ok / " << unlockFail << " fail\n";
    std::cout << "  Total:  " << (lockOk + unlockOk) << " ops in " << elapsed << "ms\n";
    if (elapsed > 0)
        std::cout << "  Rate:   " << ((lockOk + unlockOk) * 1000 / elapsed) << " ops/sec\n";
}

// ════════════════════════════════════════════════════════
//  4. NVMe + TCG interleaved operations
// ════════════════════════════════════════════════════════

/// @scenario NVMe + TCG 인터리브 작업
/// @precondition NVMe 디바이스가 열려 있고 Admin1 비밀번호가 유효해야 함. DI 패턴 사용 시 INvmeDevice가 주입되어 있어야 함
/// @steps
///   1. EvalApi::getNvmeDevice()로 DI된 INvmeDevice 존재 여부 확인
///   2. [NVMe] Identify Controller — 모델명 파싱
///   3. [TCG] Discovery — Level 0 Discovery 수행
///   4. [NVMe] Get Log Page (SMART) — Critical Warning 확인
///   5. [TCG] 세션 열기 → Locking Info 조회 → 세션 닫기
///   6. [NVMe] Get Feature (Power Management) — Power State 확인
/// @expected
///   - NVMe/TCG 명령이 교차 실행되어도 정상 완료
///   - DI 패턴으로 동일 디바이스에서 NVMe와 TCG 작업 공존 확인
///   - DI 미사용 시 API 패턴 안내 메시지 출력
static void demo_nvmeInterleaved(EvalApi& api,
                                  std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  4. NVMe + TCG Interleaved Operations     ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    // Check if NVMe device is available via DI
    INvmeDevice* nvme = EvalApi::getNvmeDevice(transport);
    if (!nvme) {
        std::cout << "  No INvmeDevice available (not DI mode).\n";
        std::cout << "  To use: construct NvmeTransport(shared_ptr<INvmeDevice>)\n";

        // Still demonstrate the API pattern
        std::cout << "\n  Pattern for NVMe + TCG:\n";
        std::cout << "    auto nvme = make_shared<YourLibNvme>(\"/dev/nvme0\");\n";
        std::cout << "    auto tr = make_shared<NvmeTransport>(nvme);\n";
        std::cout << "    // TCG:\n";
        std::cout << "    api.discovery0(tr, info);\n";
        std::cout << "    // NVMe:\n";
        std::cout << "    EvalApi::nvmeIdentify(tr, 1, 0, data);\n";
        return;
    }

    Bytes cred = HashPassword::passwordToBytes(admin1Pw);

    // Step 1: NVMe Identify Controller
    std::cout << "\n  [NVMe] Identify Controller\n";
    Bytes identData;
    auto r = EvalApi::nvmeIdentify(transport, 1, 0, identData);
    if (r.ok() && identData.size() >= 4096) {
        // Parse model name (bytes 24..63)
        std::string model(identData.begin() + 24, identData.begin() + 64);
        std::cout << "    Model: " << model << "\n";
    }

    // Step 2: TCG Discovery
    std::cout << "  [TCG] Discovery\n";
    DiscoveryInfo info;
    api.discovery0(transport, info);

    // Step 3: NVMe Get Log Page (SMART)
    std::cout << "  [NVMe] SMART Log\n";
    Bytes smartData;
    r = EvalApi::nvmeGetLogPage(transport, 0x02, 0xFFFFFFFF, smartData, 512);
    if (r.ok() && smartData.size() >= 2) {
        uint8_t critWarn = smartData[0];
        std::cout << "    Critical Warning: 0x" << std::hex << (int)critWarn << std::dec << "\n";
    }

    // Step 4: TCG Session — read locking state
    std::cout << "  [TCG] Open session, read locking info\n";
    Session session(transport, comId);
    StartSessionResult ssr;
    r = api.startSessionWithAuth(session, uid::SP_LOCKING, false,
                                  uid::AUTH_ADMIN1, cred, ssr);
    if (r.ok()) {
        LockingInfo li;
        api.getLockingInfo(session, 0, li);
        std::cout << "    GlobalRange locked=" << li.readLocked << "\n";
        api.closeSession(session);
    }

    // Step 5: NVMe Get Feature (Power Management)
    std::cout << "  [NVMe] Get Feature (Power Management)\n";
    uint32_t cdw0 = 0;
    Bytes featData;
    r = EvalApi::nvmeGetFeature(transport, 0x02, 0, cdw0, featData);
    if (r.ok()) {
        std::cout << "    Power State: " << (cdw0 & 0x1F) << "\n";
    }
}

// ════════════════════════════════════════════════════════
//  5. Session Pool pattern
// ════════════════════════════════════════════════════════

/// @scenario 세션 풀 패턴 데모
/// @precondition NVMe 디바이스가 열려 있고 Admin1 비밀번호가 유효해야 함
/// @steps
///   1. SessionPool 생성 — poolSize(4)개 세션을 미리 열어 둠
///   2. 8개 Worker 스레드가 각각 5개 작업을 수행
///   3. 각 Worker: acquire()로 세션 대여 → getLockingInfo 수행 → release()로 세션 반납
///   4. 전체 완료 후 총 작업 수 및 소요 시간 출력
/// @expected
///   - 다수 Worker(8개)가 제한된 세션(4개)을 공유하여 40개 작업 수행
///   - 세션 풀이 스레드 안전하게 동작 (acquire/release 경쟁 조건 없음)
///   - 모든 작업 완료 확인
class SessionPool {
public:
    SessionPool(std::shared_ptr<ITransport> transport, uint16_t comId,
                uint64_t spUid, uint64_t authUid, const Bytes& credential,
                uint32_t poolSize)
        : transport_(transport), comId_(comId), spUid_(spUid),
          authUid_(authUid), credential_(credential) {
        for (uint32_t i = 0; i < poolSize; i++) {
            auto session = std::make_unique<Session>(transport, comId);
            StartSessionResult ssr;
            auto r = api_.startSessionWithAuth(*session, spUid, true,
                                                authUid, credential, ssr);
            if (r.ok()) {
                std::lock_guard<std::mutex> lock(mutex_);
                pool_.push_back(std::move(session));
            }
        }
        std::cout << "  Pool created: " << pool_.size() << " sessions\n";
    }

    ~SessionPool() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& s : pool_) {
            api_.closeSession(*s);
        }
    }

    /// Borrow a session (blocks if none available)
    std::unique_ptr<Session> acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (pool_.empty()) {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            lock.lock();
        }
        auto session = std::move(pool_.back());
        pool_.pop_back();
        return session;
    }

    /// Return a session to the pool
    void release(std::unique_ptr<Session> session) {
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push_back(std::move(session));
    }

    EvalApi& api() { return api_; }

private:
    std::shared_ptr<ITransport> transport_;
    uint16_t comId_;
    uint64_t spUid_;
    uint64_t authUid_;
    Bytes credential_;
    EvalApi api_;
    std::mutex mutex_;
    std::vector<std::unique_ptr<Session>> pool_;
};

static void demo_sessionPool(std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  5. Session Pool: Pre-opened Sessions     ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(admin1Pw);

    SessionPool pool(transport, comId,
                     uid::SP_LOCKING, uid::AUTH_ADMIN1, cred,
                     4); // 4 pre-opened sessions

    std::atomic<uint32_t> completed{0};
    auto start = Clock::now();

    // 8 worker threads sharing 4 sessions
    std::vector<std::thread> workers;
    for (int i = 0; i < 8; i++) {
        workers.emplace_back([&, i]() {
            for (int j = 0; j < 5; j++) {
                auto session = pool.acquire();
                LockingInfo li;
                pool.api().getLockingInfo(*session, 0, li);
                TLOG(i, "Job %d: range0.start=%lu", j, li.rangeStart);
                pool.release(std::move(session));
                completed++;
            }
        });
    }

    for (auto& w : workers) w.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();
    std::cout << "\n  Completed " << completed << " jobs in " << elapsed << "ms\n";
}

// ════════════════════════════════════════════════════════
//  6. Concurrent TCG + NVMe on separate threads
// ════════════════════════════════════════════════════════

/// @scenario 별도 스레드에서 TCG/NVMe 동시 실행
/// @precondition NVMe 디바이스가 열려 있고 Admin1 비밀번호가 유효해야 함
/// @steps
///   1. Thread A (TCG): 10회 반복하여 LockingSP 세션 열기 → Locking Info 조회 → 세션 닫기
///   2. Thread B (NVMe): 10회 반복하여 SMART Log 또는 raw IF-RECV 수행
///   3. 두 스레드 동시 실행, 각 반복마다 짧은 대기
///   4. 두 스레드 모두 완료 후 종료
/// @expected
///   - 독립 스레드에서 TCG/NVMe 작업이 간섭 없이 완료
///   - TCG 스레드와 NVMe 스레드가 동일 디바이스에서 안전하게 공존
///   - 각 스레드의 반복 횟수가 정상 출력됨
static void demo_concurrentTcgNvme(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  6. Concurrent TCG + NVMe Threads         ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes cred = HashPassword::passwordToBytes(admin1Pw);
    std::atomic<bool> running{true};

    // Thread A: TCG operations
    std::thread tcgThread([&]() {
        EvalApi threadApi;
        int count = 0;
        while (running && count < 10) {
            Session session(transport, comId);
            StartSessionResult ssr;
            auto r = threadApi.startSessionWithAuth(session, uid::SP_LOCKING, false,
                                                     uid::AUTH_ADMIN1, cred, ssr);
            if (r.ok()) {
                LockingInfo li;
                threadApi.getLockingInfo(session, 0, li);
                TLOG(0, "[TCG] iter=%d locked=%d", count, li.readLocked);
                threadApi.closeSession(session);
            }
            count++;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        TLOG(0, "[TCG] Done (%d iterations)", count);
    });

    // Thread B: NVMe operations (if DI available)
    std::thread nvmeThread([&]() {
        INvmeDevice* nvme = EvalApi::getNvmeDevice(transport);
        int count = 0;
        while (running && count < 10) {
            if (nvme) {
                Bytes smartData;
                nvme->getLogPage(0x02, 0xFFFFFFFF, smartData, 512);
                TLOG(1, "[NVMe] iter=%d SMART=%zuB", count, smartData.size());
            } else {
                // Fallback: use transport-level raw recv
                Bytes rawData;
                transport->ifRecv(0x01, 0x0001, rawData, 512);
                TLOG(1, "[NVMe fallback] iter=%d disc=%zuB", count, rawData.size());
            }
            count++;
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        TLOG(1, "[NVMe] Done (%d iterations)", count);
    });

    tcgThread.join();
    running = false;
    nvmeThread.join();
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <device> <sid_password> <admin1_password>"
                  << " [user1_password] [num_ranges] [stress_threads]\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 sid123 admin123\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 sid123 admin123 user123 4 8\n";
        return 1;
    }

    std::string device   = argv[1];
    std::string sidPw    = argv[2];
    std::string admin1Pw = argv[3];
    std::string userPw   = (argc > 4) ? argv[4] : admin1Pw;
    uint32_t numRanges   = (argc > 5) ? std::stoul(argv[5]) : 4;
    uint32_t stressT     = (argc > 6) ? std::stoul(argv[6]) : 4;

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return 1;
    }

    EvalApi api;

    // Get ComID
    TcgOption opt;
    api.getTcgOption(transport, opt);
    uint16_t comId = opt.baseComId;
    if (comId == 0) {
        std::cerr << "No valid ComID\n";
        return 1;
    }

    // Exchange properties
    PropertiesResult props;
    api.exchangeProperties(transport, comId, props);

    std::cout << "Device: " << device << "\n";
    std::cout << "ComID:  0x" << std::hex << comId << std::dec << "\n";
    std::cout << "TPer MaxComPacket: " << props.tperMaxComPacketSize << "\n\n";

    // Run demos
    demo_dualSession(api, transport, comId, sidPw, admin1Pw);
    demo_parallelRangeQuery(api, transport, comId, admin1Pw, numRanges);
    demo_lockUnlockStress(api, transport, comId, userPw, stressT, 10);
    demo_nvmeInterleaved(api, transport, comId, admin1Pw);
    demo_sessionPool(transport, comId, admin1Pw);
    demo_concurrentTcgNvme(api, transport, comId, admin1Pw);

    libsed::shutdown();
    std::cout << "\n=== All multi-session demos complete ===\n";
    return 0;
}
