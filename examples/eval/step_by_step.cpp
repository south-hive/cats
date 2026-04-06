/// @file eval_step_by_step.cpp
/// @brief Example: Step-by-step TCG SED evaluation using EvalApi.
///
/// Shows how each protocol step can be executed independently
/// with fault injection between steps, raw payload inspection, etc.

#include <cats.h>
#include <libsed/debug/debug.h>
#include <iostream>
#include <iomanip>

using namespace libsed;
using namespace libsed::eval;
using namespace libsed::debug;

void dumpHex(const Bytes& data, size_t maxBytes = 64) {
    for (size_t i = 0; i < data.size() && i < maxBytes; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << "\n    ";
    }
    if (data.size() > maxBytes) std::cout << "... (" << std::dec << data.size() << " bytes total)";
    std::cout << std::dec << "\n";
}

/// @scenario 수동 단계별 TCG 프로토콜 평가
/// @precondition NVMe 디바이스가 열려 있고 TCG SED를 지원해야 함
/// @steps
///   1. Discovery(raw) — Level 0 Discovery 원시 바이너리 응답 수신
///   2. Discovery(parsed) — Level 0 Discovery 파싱하여 SSC 타입, ComID, Locking 상태 확인
///   3. Properties — Host/TPer 속성 교환 (MaxComPacketSize 등)
///   4. StartSession(AdminSP, RO, Anybody) — 인증 없이 AdminSP 읽기 전용 세션 시작
///   5. GetCPIN(MSID) — C_PIN 테이블에서 MSID PIN 읽기
///   6. CloseSession — 세션 종료
///   7. Discovery(잘못된 ProtocolID) — 잘못된 Protocol ID(0x05)로 Discovery 시도 (네거티브 테스트)
/// @expected
///   - 각 단계 성공하며 원시 페이로드(rawSendPayload/rawRecvPayload) 검증 가능
///   - MSID PIN이 정상적으로 읽힘
///   - 잘못된 Protocol ID는 에러 반환 또는 빈 응답
void manualStepByStep(const std::string& device, const cli::CliOptions& cliOpts) {
    std::cout << "\n=== Manual Step-by-Step Eval ===\n";

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return;
    }
    transport = cli::applyLogging(transport, cliOpts);

    EvalApi api;
    uint16_t comId = 0;

    // ── Step 1: Raw Discovery ──
    std::cout << "\n[Step 1] Level 0 Discovery (raw)\n";
    Bytes rawDiscovery;
    auto r = api.discovery0Raw(transport, rawDiscovery);
    std::cout << "  Result: " << r.message() << "\n";
    std::cout << "  Raw response (" << rawDiscovery.size() << " bytes):\n    ";
    dumpHex(rawDiscovery);

    // ── Step 1b: Parsed Discovery ──
    std::cout << "\n[Step 1b] Level 0 Discovery (parsed)\n";
    DiscoveryInfo info;
    r = api.discovery0(transport, info);
    std::cout << "  SSC type: " << static_cast<int>(info.primarySsc) << "\n";
    std::cout << "  Base ComID: 0x" << std::hex << info.baseComId << std::dec << "\n";
    std::cout << "  Locking enabled: " << info.lockingEnabled << "\n";
    std::cout << "  Locked: " << info.locked << "\n";
    comId = info.baseComId;

    // ── Step 2: Properties ──
    std::cout << "\n[Step 2] Properties Exchange\n";
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    std::cout << "  Result: " << r.message() << "\n";
    std::cout << "  TPer MaxComPacket: " << props.tperMaxComPacketSize << "\n";
    std::cout << "  TPer MaxPacket: " << props.tperMaxPacketSize << "\n";
    std::cout << "  Send payload (" << props.raw.rawSendPayload.size() << " bytes):\n    ";
    dumpHex(props.raw.rawSendPayload);

    // ── Step 3: StartSession (Admin SP, read-only, no auth) ──
    std::cout << "\n[Step 3] StartSession (Admin SP, read, Anybody)\n";
    Session session(transport, comId);
    session.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    std::cout << "  Result: " << r.message() << "\n";
    std::cout << "  HSN: " << ssr.hostSessionNumber << "\n";
    std::cout << "  TSN: " << ssr.tperSessionNumber << "\n";

    if (r.failed()) return;

    // ── Step 4: Read MSID (C_PIN table, no auth needed) ──
    std::cout << "\n[Step 4] Get C_PIN(MSID)\n";
    Bytes msidPin;
    r = api.getCPin(session, uid::CPIN_MSID, msidPin);
    std::cout << "  Result: " << r.message() << "\n";
    if (r.ok()) {
        std::cout << "  MSID PIN (" << msidPin.size() << " bytes):\n    ";
        dumpHex(msidPin);
    }

    // ── Step 5: Close session ──
    std::cout << "\n[Step 5] CloseSession\n";
    r = api.closeSession(session);
    std::cout << "  Result: " << r.message() << "\n";

    // ── Step 6: Custom negative test — Discovery with wrong protocol ID ──
    std::cout << "\n[Step 6] Discovery with wrong Protocol ID (negative test)\n";
    Bytes badDiscovery;
    r = api.discovery0Custom(transport, 0x05, 0x0001, badDiscovery);
    std::cout << "  Result: " << r.message() << "\n";
    std::cout << "  Response (" << badDiscovery.size() << " bytes):\n    ";
    dumpHex(badDiscovery);
}

/// @scenario Fault 주입을 포함한 단계별 평가
/// @precondition TestContext가 활성화되어 있고 NVMe 디바이스가 열려 있어야 함
/// @steps
///   1. TestContext 활성화 및 TestSession 생성
///   2. FaultBuilder로 AfterIfRecv 시점에 SyncSession 응답 바이트 12를 0xFF로 손상 주입 설정
///   3. Discovery 수행 (Fault 아직 미발동)
///   4. StartSession 호출 — SyncSession 응답이 손상된 상태로 수신
///   5. 트레이스 로그 확인
/// @expected
///   - Fault 주입으로 SyncSession 응답 파싱 실패
///   - StartSession 결과가 에러 코드 반환
///   - 트레이스에 Fault 발동 기록 남음
void faultInjectedEval(const std::string& device, const cli::CliOptions& cliOpts) {
    std::cout << "\n=== Fault-Injected Step-by-Step Eval ===\n";

    auto& tc = TestContext::instance();
    tc.enable();

    TestSession ts("fault_eval");

    // Arm: corrupt the 3rd IF-RECV (which should be the SyncSession response)
    ts.fault(
        FaultBuilder("corrupt_sync_session")
            .at(FaultPoint::AfterIfRecv)
            .corrupt(12, 0xFF)  // corrupt byte 12 of response
            .once()
    );

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) return;
    transport = cli::applyLogging(transport, cliOpts);

    EvalApi api;

    // Discovery works fine (fault not yet triggered if hitCountdown allows)
    DiscoveryInfo info;
    api.discovery0(transport, info);

    // StartSession — the SyncSession response will be corrupted
    Session session(transport, info.baseComId);
    StartSessionResult ssr;
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    std::cout << "  StartSession with corrupted SyncSession: " << r.message() << "\n";

    // Print trace
    for (auto& ev : ts.trace()) {
        std::cout << "  [trace] " << ev.tag << ": " << ev.detail << "\n";
    }

    tc.disable();
}

/// @scenario 관찰자 콜백을 사용한 소유권 확보 시퀀스
/// @precondition NVMe 디바이스가 열려 있고 Discovery가 성공해야 함
/// @steps
///   1. Discovery로 ComID 획득
///   2. takeOwnershipStepByStep 호출 시 observer 콜백 전달
///   3. 각 내부 단계(MSID 읽기, SID 설정 등)마다 observer가 호출됨
///   4. observer는 단계 이름, transportError, protocolError를 로깅
/// @expected
///   - 각 단계마다 observer 콜백이 호출되어 진행 상황 추적 가능
///   - 소유권 확보 시퀀스가 정상 완료
///   - observer가 false를 반환하면 중단 가능 (본 예제에서는 항상 true 반환)
void observedOwnership(const std::string& device, const cli::CliOptions& cliOpts) {
    std::cout << "\n=== Observed Ownership Sequence ===\n";

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) return;
    transport = cli::applyLogging(transport, cliOpts);

    DiscoveryInfo info;
    EvalApi api;
    api.discovery0(transport, info);

    sequence::takeOwnershipStepByStep(
        transport, info.baseComId, "new_password_123",
        [](const std::string& step, const RawResult& raw) -> bool {
            std::cout << "  [" << step << "] "
                      << "transport=" << static_cast<int>(raw.transportError)
                      << " protocol=" << static_cast<int>(raw.protocolError)
                      << "\n";
            return true; // continue to next step
        }
    );
}

int main(int argc, char* argv[]) {
    cli::CliOptions cliOpts;
    cli::scanFlags(argc, argv, cliOpts);

    std::string device;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg[0] != '-') { device = arg; break; }
    }
    if (device.empty()) device = "/dev/nvme0";

    libsed::initialize();

    manualStepByStep(device, cliOpts);

    if (!device.empty() && device != "/dev/nvme0") {
        faultInjectedEval(device, cliOpts);
        observedOwnership(device, cliOpts);
    }

    libsed::shutdown();
    return 0;
}
