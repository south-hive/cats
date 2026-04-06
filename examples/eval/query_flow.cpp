/// @file query_flow.cpp
/// @brief TCG SED query flow — sedutil --query equivalent.
///
/// Replicates the full sedutil --query sequence using libsed EvalApi:
///   1. Level 0 Discovery + Feature Descriptor display
///   2. StackReset
///   3. Properties Exchange (TPer/Host Properties)
///   4. Anonymous AdminSP Session + MSID read
///   5. Close Session
///
/// Usage: ./eval_query_flow <device> [--dump] [--log]

#include <libsed/sed_library.h>
#include <libsed/cli/cli_common.h>
#include <iostream>
#include <iomanip>

using namespace libsed;
using namespace libsed::eval;

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    if (!cli::parseCommon(argc, argv, opts,
            "TCG SED query flow (sedutil --query equivalent)"))
        return 0;

    libsed::initialize();
    EvalApi api;

    // ── Transport ──
    auto rawTransport = TransportFactory::createNvme(opts.device);
    if (!rawTransport || !rawTransport->isOpen()) {
        std::cerr << "ERROR: Cannot open " << opts.device << "\n";
        return 1;
    }
    auto transport = cli::applyLogging(rawTransport, opts);

    std::cout << "Device: " << opts.device << "\n\n";
    int step = 0;

    // ═══════════════════════════════════════════════
    //  1. Level 0 Discovery + Feature Descriptors
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] Level 0 Discovery\n";
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) {
        std::cerr << "  FAIL: " << r.message() << "\n";
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
        std::cerr << "  No valid ComID.\n";
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
        std::cout << "  OK\n";
    } else {
        std::cout << "  FAIL: " << r.message() << "\n";
        std::cout << "  Fallback: MaxComPacketSize=" << maxCPS << "\n";
    }
    std::cout << "\n";

    // ═══════════════════════════════════════════════
    //  4. Anonymous AdminSP Session + MSID
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

    // ── Read MSID ──
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
    std::cout << "  " << sscName(info.primarySsc) << " on " << opts.device << "\n";
    std::cout << "  ComID=0x" << std::hex << std::setfill('0')
              << std::setw(4) << comId << std::dec
              << "  MaxCPS=" << maxCPS << "\n";
    std::cout << "══════════════════════════════════════════\n";

    return 0;
}
