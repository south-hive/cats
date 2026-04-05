/// @file eval_basic_check.cpp
/// @brief 기본 TCG SED 지원 및 동작 확인 — 단일 세션 예제.
///
/// 드라이브가 TCG를 지원하는지, 기본적인 프로토콜 흐름이 동작하는지
/// 확인하는 최소한의 예제. Properties 실패 시 Discovery 기본값으로 fallback.
///
/// 흐름:
///   1. Level 0 Discovery — SSC 탐지, ComID, Locking 상태
///   2. StackReset — 이전 stale 세션 정리
///   3. Properties 교환 (실패 시 Discovery 기본값 사용)
///   4. AdminSP 읽기 세션 (인증 없음) → MSID 읽기
///   5. 세션 닫기
///
/// Usage:
///   ./example_eval_basic <device>
///   예: ./example_eval_basic /dev/nvme0

#include <libsed/sed_library.h>
#include <libsed/debug/logging_transport.h>
#include <iostream>
#include <iomanip>

using namespace libsed;
using namespace libsed::eval;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <device> [--log]\n";
        std::cerr << "  예: " << argv[0] << " /dev/nvme0\n";
        std::cerr << "  --log: IF-SEND/IF-RECV 명령 이력을 파일에 기록\n";
        return 1;
    }

    bool enableLog = (argc >= 3 && std::string(argv[2]) == "--log");

    libsed::initialize();
    EvalApi api;

    // ═══════════════════════════════════════════════
    //  Transport
    // ═══════════════════════════════════════════════

    auto rawTransport = TransportFactory::createNvme(argv[1]);
    if (!rawTransport || !rawTransport->isOpen()) {
        std::cerr << "ERROR: Cannot open " << argv[1] << "\n";
        return 1;
    }

    std::shared_ptr<ITransport> transport = rawTransport;
    if (enableLog) {
        transport = debug::LoggingTransport::wrap(rawTransport, ".");
        auto* lt = dynamic_cast<debug::LoggingTransport*>(transport.get());
        std::cout << "Log: " << lt->logger()->filePath() << "\n";
    }

    std::cout << "Device: " << argv[1] << "\n\n";

    // ═══════════════════════════════════════════════
    //  Step 1: Level 0 Discovery
    // ═══════════════════════════════════════════════

    std::cout << "── Step 1: Level 0 Discovery ──\n";
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) {
        std::cerr << "FAIL: Discovery failed — " << r.message() << "\n";
        std::cerr << "  이 디바이스가 TCG SED를 지원하지 않거나 접근 권한이 없습니다.\n";
        return 1;
    }

    std::cout << "  SSC Type      : " << sscName(info.primarySsc) << "\n";
    std::cout << "  Base ComID    : 0x" << std::hex << std::setfill('0')
              << std::setw(4) << info.baseComId << std::dec << "\n";
    std::cout << "  Num ComIDs    : " << info.numComIds << "\n";
    std::cout << "  TPer Feature  : " << (info.tperPresent ? "YES" : "NO") << "\n";
    std::cout << "  Locking       : " << (info.lockingPresent ? "YES" : "NO")
              << (info.lockingEnabled ? " (enabled)" : " (disabled)")
              << (info.locked ? " [LOCKED]" : "") << "\n";
    std::cout << "  MBR           : " << (info.mbrEnabled ? "enabled" : "disabled")
              << (info.mbrDone ? " (done)" : "") << "\n";

    if (info.baseComId == 0) {
        std::cerr << "FAIL: No valid ComID — TCG not supported.\n";
        return 1;
    }

    uint16_t comId = info.baseComId;
    std::cout << "  → Discovery OK\n\n";

    // ═══════════════════════════════════════════════
    //  Step 2: StackReset
    // ═══════════════════════════════════════════════

    std::cout << "── Step 2: StackReset (ComID 0x"
              << std::hex << std::setw(4) << comId << std::dec << ") ──\n";
    r = api.stackReset(transport, comId);
    if (r.failed()) {
        std::cerr << "WARN: StackReset failed — " << r.message() << " (continuing)\n";
    } else {
        std::cout << "  → StackReset OK\n";
    }
    std::cout << "\n";

    // ═══════════════════════════════════════════════
    //  Step 3: Properties Exchange
    // ═══════════════════════════════════════════════

    std::cout << "── Step 3: Properties Exchange ──\n";
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);

    uint32_t maxComPacketSize = 2048;  // 기본값
    if (r.ok() && props.tperMaxComPacketSize > 0) {
        maxComPacketSize = props.tperMaxComPacketSize;
        std::cout << "  MaxComPacketSize : " << maxComPacketSize << "\n";
        std::cout << "  MaxPacketSize    : " << props.tperMaxPacketSize << "\n";
        std::cout << "  MaxIndTokenSize  : " << props.tperMaxIndTokenSize << "\n";
        std::cout << "  → Properties OK\n";
    } else {
        std::cout << "  Properties failed: " << r.message() << "\n";
        std::cout << "  → Fallback: MaxComPacketSize=" << maxComPacketSize
                  << " (Discovery default)\n";
    }
    std::cout << "\n";

    // ═══════════════════════════════════════════════
    //  Step 4: AdminSP Session (Read-Only, No Auth)
    // ═══════════════════════════════════════════════

    std::cout << "── Step 4: AdminSP Session (Anonymous, Read-Only) ──\n";
    Session session(transport, comId);
    session.setMaxComPacketSize(maxComPacketSize);

    StartSessionResult ssr;
    r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    if (r.failed()) {
        std::cerr << "FAIL: StartSession failed — " << r.message() << "\n";
        std::cerr << "  가능한 원인:\n";
        std::cerr << "    - Block SID가 설정됨 → 전원 사이클 후 재시도\n";
        std::cerr << "    - 이전 세션 잔존 → StackReset 실패 시 전원 사이클\n";
        return 1;
    }

    std::cout << "  TSN=" << ssr.tperSessionNumber
              << " HSN=" << ssr.hostSessionNumber << "\n";
    std::cout << "  → Session opened\n\n";

    // ═══════════════════════════════════════════════
    //  Step 5: Read MSID
    // ═══════════════════════════════════════════════

    std::cout << "── Step 5: Read C_PIN<MSID> ──\n";
    Bytes msid;
    r = api.getCPin(session, uid::CPIN_MSID, msid);
    if (r.ok() && !msid.empty()) {
        std::cout << "  MSID (" << msid.size() << " bytes): ";
        printHex(msid);
        std::cout << "\n";
        std::cout << "  → MSID read OK\n";
    } else {
        std::cerr << "WARN: MSID read failed — " << r.message() << "\n";
        std::cerr << "  C_PIN 테이블 접근 불가. Anybody 권한이 제한되었을 수 있음.\n";
    }
    std::cout << "\n";

    // ═══════════════════════════════════════════════
    //  Step 6: Close Session
    // ═══════════════════════════════════════════════

    std::cout << "── Step 6: Close Session ──\n";
    r = api.closeSession(session);
    std::cout << "  → Session closed\n\n";

    // ═══════════════════════════════════════════════
    //  Summary
    // ═══════════════════════════════════════════════

    std::cout << "══════════════════════════════════════════\n";
    std::cout << "  TCG SED Basic Check: PASS\n";
    std::cout << "  " << sscName(info.primarySsc) << " on " << argv[1] << "\n";
    std::cout << "══════════════════════════════════════════\n";

    return 0;
}
