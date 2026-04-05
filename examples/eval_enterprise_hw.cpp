/// @file eval_enterprise_hw.cpp
/// @brief Enterprise SSC hardware flow test — validates libsed on all ComIDs
///
/// Runs the basic query flow (Discovery -> Properties -> Session -> MSID -> Close)
/// on each ComID of an Enterprise SSC NVMe device to diagnose per-ComID behavior
/// (e.g., the 0x0C Properties InvalidParameter issue).
///
/// Usage: ./example_eval_ent_hw <device> [--log] [--comid <N>]
///   <device>     Parent PF device path (e.g., /dev/nvme0)
///   --log        Enable wire-level logging to current directory
///   --comid N    Test only ComID offset N (0-based from baseComId). Default: all.

#include <libsed/sed_library.h>
#include <libsed/debug/logging_transport.h>
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace libsed;
using namespace libsed::eval;

// ── Helpers ──────────────────────────────────────────

/// @brief Print raw payload hex for diagnostic (first N bytes)
static void printRawPayload(const char* label, const Bytes& data, size_t max = 128) {
    if (data.empty()) return;
    printf("    %s (%zu bytes): ", label, data.size());
    printHex(data, max);
    printf("\n");
}

// ── Per-ComID test ───────────────────────────────────

/// @return true if all steps passed for this ComID
static bool testComId(EvalApi& api, std::shared_ptr<ITransport> transport,
                      uint16_t comId, uint32_t maxCpsHint) {
    printf("\n[ComID 0x%04X] StackReset: ", comId);
    auto r = api.stackReset(transport, comId);
    if (r.failed()) {
        printf("FAIL - %s\n", r.message().c_str());
        return false;
    }
    printf("OK\n");

    // ── Properties ──
    printf("[ComID 0x%04X] Properties: ", comId);
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    uint32_t maxCPS = maxCpsHint;
    if (r.ok()) {
        maxCPS = (props.tperMaxComPacketSize > 0)
                 ? props.tperMaxComPacketSize : maxCpsHint;
        printf("OK (MaxCPS=%u, MaxPktSize=%u, MaxIndTok=%u, MaxAggTok=%u)\n",
               props.tperMaxComPacketSize, props.tperMaxPacketSize,
               props.tperMaxIndTokenSize, props.tperMaxAggTokenSize);
    } else {
        printf("FAIL - %s\n", r.message().c_str());
        printRawPayload("SendPayload", props.raw.rawSendPayload);
        printRawPayload("RecvPayload", props.raw.rawRecvPayload);
        // Continue — StartSession may still work
    }

    // ── StartSession (anonymous, read-only) ──
    printf("[ComID 0x%04X] StartSession: ", comId);
    Session session(transport, comId);
    session.setMaxComPacketSize(maxCPS);

    StartSessionResult ssr;
    r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    if (r.failed()) {
        printf("FAIL - %s\n", r.message().c_str());
        printRawPayload("SendPayload", ssr.raw.rawSendPayload);
        printRawPayload("RecvPayload", ssr.raw.rawRecvPayload);
        return false;
    }
    printf("OK (TSN=%u HSN=%u)\n", ssr.tperSessionNumber, ssr.hostSessionNumber);

    // ── MSID ──
    printf("[ComID 0x%04X] MSID: ", comId);
    Bytes msid;
    RawResult raw;
    r = api.getCPin(session, uid::CPIN_MSID, msid, raw);
    if (r.ok() && !msid.empty()) {
        printf("%zu bytes: ", msid.size());
        printHex(msid, 32);
        printf("\n");
    } else {
        printf("%s (may be restricted)\n", r.message().c_str());
    }

    // ── CloseSession ──
    printf("[ComID 0x%04X] CloseSession: ", comId);
    api.closeSession(session);
    printf("OK\n");

    printf("[ComID 0x%04X] PASS\n", comId);
    return true;
}

// ── Main ─────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <device> [--log] [--comid <N>]\n", argv[0]);
        fprintf(stderr, "  <device>     Parent PF device path (e.g., /dev/nvme0)\n");
        fprintf(stderr, "  --log        Enable wire-level logging\n");
        fprintf(stderr, "  --comid N    Test only ComID offset N (0-based). Default: all.\n");
        return 1;
    }

    std::string device = argv[1];
    bool enableLog = false;
    int  comIdFilter = -1;  // -1 = test all

    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--log") == 0) {
            enableLog = true;
        } else if (std::strcmp(argv[i], "--comid") == 0 && i + 1 < argc) {
            comIdFilter = std::atoi(argv[++i]);
        }
    }

    libsed::initialize();
    EvalApi api;

    // ── Transport ──
    auto rawTransport = TransportFactory::createNvme(device);
    if (!rawTransport || !rawTransport->isOpen()) {
        fprintf(stderr, "ERROR: Cannot open %s\n", device.c_str());
        return 1;
    }

    std::shared_ptr<ITransport> transport = rawTransport;
    if (enableLog) {
        transport = debug::LoggingTransport::wrap(rawTransport, ".");
        auto* lt = dynamic_cast<debug::LoggingTransport*>(transport.get());
        printf("Log: %s\n", lt->logger()->filePath().c_str());
    }

    // ═══════════════════════════════════════════════════
    //  Level 0 Discovery (shared across all ComIDs)
    // ═══════════════════════════════════════════════════
    printf("[Discovery] Level 0 Discovery\n");
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) {
        fprintf(stderr, "  FAIL: %s\n", r.message().c_str());
        return 1;
    }

    DiscoveryInfo info = disc.buildInfo();
    printf("  SSC        : %s\n", sscName(info.primarySsc));
    printf("  BaseComID  : 0x%04X\n", info.baseComId);
    printf("  NumComIDs  : %u\n", info.numComIds);
    printf("  Locking    : %s%s%s\n",
           info.lockingPresent ? "YES" : "NO",
           info.lockingEnabled ? " (enabled)" : " (disabled)",
           info.locked ? " [LOCKED]" : "");
    printf("  MBR        : %s%s\n",
           info.mbrEnabled ? "enabled" : "disabled",
           info.mbrDone ? " (done)" : "");

    printf("\n  Feature Descriptors:\n");
    printFeatureDescriptors(disc);

    if (info.baseComId == 0 || info.numComIds == 0) {
        fprintf(stderr, "\n  No valid ComID found\n");
        return 1;
    }

    if (info.primarySsc != SscType::Enterprise) {
        printf("\n  WARNING: Device is %s, not Enterprise SSC. Proceeding anyway.\n",
               sscName(info.primarySsc));
    }

    // ═══════════════════════════════════════════════════
    //  Test each ComID
    // ═══════════════════════════════════════════════════
    uint16_t baseComId = info.baseComId;
    uint16_t numComIds = info.numComIds;
    int passed = 0;
    int tested = 0;

    for (uint16_t offset = 0; offset < numComIds; offset++) {
        if (comIdFilter >= 0 && static_cast<int>(offset) != comIdFilter)
            continue;

        uint16_t comId = baseComId + offset;
        tested++;
        if (testComId(api, transport, comId, 2048))
            passed++;
    }

    // ═══════════════════════════════════════════════════
    //  Summary
    // ═══════════════════════════════════════════════════
    printf("\n");
    printf("================================================================\n");
    printf("  Summary: %d/%d ComIDs PASS", passed, tested);
    if (comIdFilter >= 0)
        printf("  (filtered: offset %d only)", comIdFilter);
    printf("\n");
    printf("  Device: %s  SSC: %s  BaseComID=0x%04X  NumComIDs=%u\n",
           device.c_str(), sscName(info.primarySsc), baseComId, numComIds);
    printf("================================================================\n");

    return (passed == tested) ? 0 : 1;
}
