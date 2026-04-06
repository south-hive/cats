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
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/endian.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cstring>

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

    // ── Hex dump helper ──
    auto hexDump = [](const char* label, const uint8_t* data, size_t len) {
        printf("  %s (%zu bytes):\n", label, len);
        for (size_t i = 0; i < len; i += 16) {
            printf("    %04zX: ", i);
            for (size_t j = 0; j < 16; j++) {
                if (i+j < len) printf("%02X ", data[i+j]);
                else printf("   ");
                if (j == 7) printf(" ");
            }
            printf(" |");
            for (size_t j = 0; j < 16 && (i+j) < len; j++) {
                uint8_t c = data[i+j];
                printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
            }
            printf("|\n");
        }
    };

    // ── Build sedutil-style Properties packet for comparison ──
    auto buildSedutilProps = [&comId]() -> Bytes {
        Bytes buf(2048, 0);
        size_t pos = 56;

        buf[pos++] = 0xF8;  // CALL
        // SMUID (00..00FF)
        buf[pos++] = 0xA8;
        buf[pos++]=0; buf[pos++]=0; buf[pos++]=0; buf[pos++]=0;
        buf[pos++]=0; buf[pos++]=0; buf[pos++]=0; buf[pos++]=0xFF;
        // SM_PROPERTIES (00..FF01)
        buf[pos++] = 0xA8;
        buf[pos++]=0; buf[pos++]=0; buf[pos++]=0; buf[pos++]=0;
        buf[pos++]=0; buf[pos++]=0; buf[pos++]=0xFF; buf[pos++]=0x01;

        buf[pos++] = 0xF0;  // STARTLIST
        buf[pos++] = 0xF2;  // STARTNAME

        auto addStr = [&](const char* s) {
            size_t len = strlen(s);
            if (len <= 15) {
                buf[pos++] = 0xA0 | (uint8_t)(len & 0x0F);
            } else {
                buf[pos++] = 0xD0 | (uint8_t)((len >> 8) & 0x07);
                buf[pos++] = (uint8_t)(len & 0xFF);
            }
            memcpy(&buf[pos], s, len); pos += len;
        };
        auto addProp = [&](const char* name, uint32_t value) {
            buf[pos++] = 0xF2;
            addStr(name);
            if (value < 64) {
                buf[pos++] = (uint8_t)(value & 0x3F);
            } else if (value < 0x100) {
                buf[pos++] = 0x81; buf[pos++] = (uint8_t)value;
            } else if (value < 0x10000) {
                buf[pos++] = 0x82; buf[pos++] = (uint8_t)(value>>8); buf[pos++] = (uint8_t)value;
            } else {
                buf[pos++] = 0x84;
                buf[pos++]=(uint8_t)(value>>24); buf[pos++]=(uint8_t)(value>>16);
                buf[pos++]=(uint8_t)(value>>8);  buf[pos++]=(uint8_t)value;
            }
            buf[pos++] = 0xF3;
        };

        addStr("HostProperties");
        buf[pos++] = 0xF0;  // STARTLIST
        addProp("MaxComPacketSize", 2048);
        addProp("MaxPacketSize",    2028);
        addProp("MaxIndTokenSize",  1992);
        addProp("MaxPackets",       1);
        addProp("MaxSubpackets",    1);
        addProp("MaxMethods",       1);
        buf[pos++] = 0xF1;  // ENDLIST
        buf[pos++] = 0xF3;  // ENDNAME
        buf[pos++] = 0xF1;  // ENDLIST

        buf[pos++] = 0xF9;  // EOD
        buf[pos++] = 0xF0; buf[pos++] = 0x00; buf[pos++] = 0x00;
        buf[pos++] = 0x00; buf[pos++] = 0xF1;

        size_t tokenLen = pos - 56;
        Endian::writeBe32(&buf[52], (uint32_t)tokenLen);
        while (pos % 4 != 0) pos++;
        Endian::writeBe32(&buf[40], (uint32_t)(pos - 44));
        Endian::writeBe16(&buf[4], comId);
        Endian::writeBe32(&buf[16], (uint32_t)(pos - 20));

        return buf;
    };

    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);

    // ── NVMe ioctl parameters (both sides identical) ──
    {
        size_t transferLen = 2048;  // both use 2048
        uint32_t cdw10_send = (uint32_t(0x01) << 24) | (uint32_t(comId) << 8);
        uint32_t cdw10_recv = (uint32_t(0x01) << 24) | (uint32_t(comId) << 8);
        printf("\n  ── NVMe ioctl parameters ──\n");
        printf("  IF-SEND: opcode=0x81  nsid=0  cdw10=0x%08X  cdw11=0x%08X  data_len=%zu\n",
               cdw10_send, (uint32_t)transferLen, transferLen);
        printf("  IF-RECV: opcode=0x82  nsid=0  cdw10=0x%08X  cdw11=0x%08X  data_len=%zu\n",
               cdw10_recv, (uint32_t)transferLen, transferLen);
        printf("  (cdw10 = protocolId=0x01 << 24 | comId=0x%04X << 8)\n\n", comId);
    }

    // ── libsed raw packet ──
    if (!props.raw.rawSendPayload.empty()) {
        hexDump("libsed IF-SEND (Properties)", props.raw.rawSendPayload.data(),
                props.raw.rawSendPayload.size());
    }
    if (!props.raw.rawRecvPayload.empty()) {
        hexDump("libsed IF-RECV (Properties)", props.raw.rawRecvPayload.data(),
                props.raw.rawRecvPayload.size());
    }

    // ── sedutil reference packet (built in memory) ──
    Bytes sedutilPkt = buildSedutilProps();
    printf("\n");
    hexDump("sedutil IF-SEND (Properties) [reference]", sedutilPkt.data(), sedutilPkt.size());

    // ── Byte diff ──
    if (!props.raw.rawSendPayload.empty()) {
        const auto& a = props.raw.rawSendPayload;
        const auto& b = sedutilPkt;
        size_t maxLen = std::max(a.size(), b.size());
        int diffs = 0;
        printf("\n  ── SEND Packet Diff (libsed vs sedutil) ──\n");
        for (size_t i = 0; i < maxLen; i++) {
            uint8_t av = (i < a.size()) ? a[i] : 0;
            uint8_t bv = (i < b.size()) ? b[i] : 0;
            if (av != bv) {
                printf("    offset 0x%04zX: libsed=0x%02X  sedutil=0x%02X", i, av, bv);
                if (av >= 0x20 && av <= 0x7E && bv >= 0x20 && bv <= 0x7E)
                    printf("  ('%c' vs '%c')", av, bv);
                printf("\n");
                if (++diffs >= 50) { printf("    ... (truncated)\n"); break; }
            }
        }
        if (diffs == 0) printf("    *** IDENTICAL ***\n");
        else printf("    Total diffs: %d\n", diffs);
        printf("\n");
    }

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
