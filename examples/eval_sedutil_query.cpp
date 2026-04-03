/// @file eval_sedutil_query.cpp
/// @brief sedutil-cli --query 동일 동작 재현
///
/// sedutil --query가 수행하는 것과 동일한 시나리오:
///   1. Level 0 Discovery
///   2. Properties Exchange
///   3. Anonymous AdminSP Session → MSID 읽기
///   4. Close Session
///
/// Usage: ./example_sedutil_query <device> [--log]

#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/debug/logging_transport.h>
#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>

using namespace libsed;
using namespace libsed::eval;

static const char* sscName(SscType ssc) {
    switch (ssc) {
        case SscType::Opal20:     return "Opal 2.0";
        case SscType::Opal10:     return "Opal 1.0";
        case SscType::Enterprise: return "Enterprise";
        case SscType::Pyrite10:   return "Pyrite 1.0";
        case SscType::Pyrite20:   return "Pyrite 2.0";
        default:                  return "Unknown";
    }
}

static void printHex(const Bytes& data, size_t max = 32) {
    for (size_t i = 0; i < data.size() && i < max; i++)
        printf("%02X", data[i]);
    if (data.size() > max) printf("..(%zu bytes)", data.size());
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <device> [--log]\n";
        return 1;
    }

    std::string device = argv[1];
    bool enableLog = false;
    for (int i = 2; i < argc; i++)
        if (std::string(argv[i]) == "--log") enableLog = true;

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

    int step = 0;

    // ═══════════════════════════════════════════════
    //  1. Level 0 Discovery
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] Level 0 Discovery\n";
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) {
        std::cerr << "  FAIL: " << r.message() << "\n";
        return 1;
    }

    std::cout << "  SSC        : " << sscName(info.primarySsc) << "\n";
    std::cout << "  ComID      : 0x" << std::hex << std::setfill('0')
              << std::setw(4) << info.baseComId << std::dec << "\n";
    std::cout << "  NumComIDs  : " << info.numComIds << "\n";
    std::cout << "  Locking    : " << (info.lockingPresent ? "YES" : "NO")
              << (info.lockingEnabled ? " (enabled)" : " (disabled)")
              << (info.locked ? " [LOCKED]" : "") << "\n";
    std::cout << "  MBR        : " << (info.mbrEnabled ? "enabled" : "disabled")
              << (info.mbrDone ? " (done)" : "") << "\n";

    if (info.baseComId == 0) {
        std::cerr << "  No valid ComID\n";
        return 1;
    }

    uint16_t comId = info.baseComId;
    std::cout << "  OK\n\n";

    // ═══════════════════════════════════════════════
    //  2. StackReset
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] StackReset\n";
    r = api.stackReset(transport, comId);
    std::cout << "  " << (r.ok() ? "OK" : r.message()) << "\n\n";

    // ═══════════════════════════════════════════════
    //  3. Properties Exchange
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] Properties Exchange\n";
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    if (r.ok()) {
        std::cout << "  MaxComPacketSize : " << props.tperMaxComPacketSize << "\n";
        std::cout << "  MaxPacketSize    : " << props.tperMaxPacketSize << "\n";
        std::cout << "  MaxIndTokenSize  : " << props.tperMaxIndTokenSize << "\n";
        std::cout << "  OK\n";
    } else {
        std::cerr << "  FAIL: " << r.message() << "\n";
        std::cerr << "  Fallback: MaxComPacketSize=2048\n";
    }
    uint32_t maxCPS = (r.ok() && props.tperMaxComPacketSize > 0)
                      ? props.tperMaxComPacketSize : 2048;
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
    RawResult raw;
    r = api.getCPin(session, uid::CPIN_MSID, msid, raw);
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
