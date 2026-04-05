/// @file query_flow.cpp
/// @brief TCG SED 기본 조회 플로우 — sedutil --query와 동일한 동작.
///
/// sedutil --query가 수행하는 전체 시퀀스를 libsed EvalApi로 재현합니다:
///   1. Level 0 Discovery + Feature Descriptor 출력
///   2. StackReset
///   3. Properties Exchange (TPer/Host Properties)
///   4. Anonymous AdminSP Session → MSID 읽기
///   5. Close Session
///
/// Options:
///   --sedutil-first  sedutil-cli --query를 먼저 실행하여 비교
///   --log            IF-SEND/IF-RECV 명령 이력 파일 기록
///
/// Usage: ./eval_query_flow <device> [--sedutil-first] [--log]

#include <libsed/sed_library.h>
#include <libsed/debug/logging_transport.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>

using namespace libsed;
using namespace libsed::eval;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <device> [--sedutil-first] [--log]\n";
        return 1;
    }

    std::string device = argv[1];
    bool enableLog = false;
    bool sedutilFirst = false;
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--log") enableLog = true;
        if (std::string(argv[i]) == "--sedutil-first") sedutilFirst = true;
    }

    // ═══════════════════════════════════════════════
    //  0. (선택) sedutil-cli --query 먼저 실행
    // ═══════════════════════════════════════════════
    if (sedutilFirst) {
        std::cout << "══════════════════════════════════════════\n";
        std::cout << "  sedutil-cli --query " << device << "\n";
        std::cout << "══════════════════════════════════════════\n";
        std::string cmd = "sedutil-cli --query " + device;
        int rc = system(cmd.c_str());
        std::cout << "\nsedutil-cli exit code: " << rc << "\n\n";
        if (rc != 0) {
            std::cerr << "sedutil-cli failed. Aborting.\n";
            return 1;
        }
        std::cout << "══════════════════════════════════════════\n";
        std::cout << "  Now running libsed equivalent...\n";
        std::cout << "══════════════════════════════════════════\n\n";
    }

    libsed::initialize();
    EvalApi api;

    // ── Transport ──
    auto rawTransport = TransportFactory::createNvme(device);
    if (!rawTransport || !rawTransport->isOpen()) {
        std::cerr << "ERROR: Cannot open " << device << "\n";
        return 1;
    }

    std::shared_ptr<ITransport> transport = rawTransport;
    if (enableLog) {
        transport = debug::LoggingTransport::wrap(rawTransport, ".");
        auto* lt = dynamic_cast<debug::LoggingTransport*>(transport.get());
        std::cout << "Log: " << lt->logger()->filePath() << "\n";
    }

    std::cout << "Device: " << device << "\n\n";
    int step = 0;

    // ═══════════════════════════════════════════════
    //  1. Level 0 Discovery + Feature Descriptors
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] Level 0 Discovery\n";
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) {
        std::cerr << "  FAIL: " << r.message() << "\n";
        std::cerr << "  이 디바이스가 TCG SED를 지원하지 않거나 접근 권한이 없습니다.\n";
        return 1;
    }

    DiscoveryInfo info = disc.buildInfo();
    std::cout << "  SSC        : " << sscName(info.primarySsc) << "\n";
    std::cout << "  ComID      : 0x" << std::hex << std::setfill('0')
              << std::setw(4) << info.baseComId << std::dec << "\n";
    std::cout << "  NumComIDs  : " << info.numComIds << "\n";
    std::cout << "  TPer       : " << (info.tperPresent ? "YES" : "NO") << "\n";
    std::cout << "  Locking    : " << (info.lockingPresent ? "YES" : "NO")
              << (info.lockingEnabled ? " (enabled)" : " (disabled)")
              << (info.locked ? " [LOCKED]" : "") << "\n";
    std::cout << "  MBR        : " << (info.mbrEnabled ? "enabled" : "disabled")
              << (info.mbrDone ? " (done)" : "") << "\n";

    std::cout << "\n  Feature Descriptors:\n";
    printFeatureDescriptors(disc);
    std::cout << "\n";

    if (info.baseComId == 0) {
        std::cerr << "  No valid ComID — TCG not supported.\n";
        return 1;
    }

    uint16_t comId = info.baseComId;

    // ═══════════════════════════════════════════════
    //  2. StackReset
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] StackReset\n";
    r = api.stackReset(transport, comId);
    if (r.failed()) {
        std::cout << "  WARN: " << r.message() << " (continuing)\n";
    } else {
        std::cout << "  OK\n";
    }
    std::cout << "\n";

    // ═══════════════════════════════════════════════
    //  3. Properties Exchange
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] Properties Exchange\n";

    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);

    uint32_t maxCPS = 2048;
    if (r.ok() && props.tperMaxComPacketSize > 0) {
        maxCPS = props.tperMaxComPacketSize;
        std::cout << "  TPer Properties:\n";
        std::cout << "    MaxComPacketSize = " << props.tperMaxComPacketSize << "\n";
        std::cout << "    MaxPacketSize    = " << props.tperMaxPacketSize << "\n";
        std::cout << "    MaxIndTokenSize  = " << props.tperMaxIndTokenSize << "\n";
        std::cout << "    MaxAggTokenSize  = " << props.tperMaxAggTokenSize << "\n";
        std::cout << "  Host Properties (echoed):\n";
        std::cout << "    MaxComPacketSize = 2048\n";
        std::cout << "    MaxPacketSize    = 2028\n";
        std::cout << "    MaxIndTokenSize  = 1992\n";
        std::cout << "  OK\n";
    } else {
        std::cout << "  FAIL: " << r.message() << "\n";
        std::cout << "  Fallback: MaxComPacketSize=" << maxCPS << "\n";
    }
    std::cout << "\n";

    // ═══════════════════════════════════════════════
    //  4. Anonymous AdminSP Session → MSID
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] AdminSP Session (Anonymous)\n";
    Session session(transport, comId);
    session.setMaxComPacketSize(maxCPS);

    StartSessionResult ssr;
    r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    if (r.failed()) {
        std::cerr << "  FAIL: " << r.message() << "\n";
        return 1;
    }
    std::cout << "  TSN=" << ssr.tperSessionNumber
              << " HSN=" << ssr.hostSessionNumber << "\n";

    // ── MSID 읽기 ──
    std::cout << "[" << ++step << "] Read MSID\n";
    Bytes msid;
    r = api.getCPin(session, uid::CPIN_MSID, msid);
    if (r.ok() && !msid.empty()) {
        std::cout << "  MSID (" << msid.size() << " bytes): ";
        printHex(msid);
        std::cout << "\n  OK\n";
    } else {
        std::cout << "  " << r.message() << " (may be restricted)\n";
    }
    std::cout << "\n";

    // ── Close ──
    std::cout << "[" << ++step << "] Close Session\n";
    api.closeSession(session);
    std::cout << "  OK\n\n";

    // ── Summary ──
    std::cout << "══════════════════════════════════════════\n";
    std::cout << "  " << sscName(info.primarySsc) << " on " << device << "\n";
    std::cout << "  ComID=0x" << std::hex << std::setfill('0')
              << std::setw(4) << comId << std::dec
              << "  MaxCPS=" << maxCPS << "\n";
    std::cout << "══════════════════════════════════════════\n";

    return 0;
}
