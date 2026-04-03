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
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

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
    //  방법 A: api.exchangeProperties() (고수준)
    //  방법 B: 직접 ifSend/ifRecv (props_diff와 동일)
    // ═══════════════════════════════════════════════
    std::cout << "[" << ++step << "] Properties Exchange\n";

    // ── 방법 A: EvalApi 경유 ──
    std::cout << "  [A] via api.exchangeProperties()...\n";
    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    if (r.ok()) {
        std::cout << "  [A] OK: MaxCPS=" << props.tperMaxComPacketSize << "\n";
    } else {
        std::cout << "  [A] FAIL: " << r.message() << "\n";

        // StackReset 후 방법 B 시도
        api.stackReset(transport, comId);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        std::cout << "  [B] via direct ifSend/ifRecv...\n";

        // props_diff와 동일하게 패킷 직접 구성
        ParamEncoder::HostProperties hp;
        hp.maxComPacketSize = 2048;
        hp.maxPacketSize = 2028;
        hp.maxIndTokenSize = 1992;
        Bytes params = ParamEncoder::encodeProperties(hp);
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);
        PacketBuilder pb;
        pb.setComId(comId);
        Bytes sendData = pb.buildSessionManagerPacket(methodTokens);

        // Send
        r = transport->ifSend(0x01, comId, ByteSpan(sendData.data(), sendData.size()));
        if (r.ok()) {
            // Recv with polling
            Bytes recvBuf;
            for (int att = 0; att < 20; att++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                recvBuf.clear();
                r = transport->ifRecv(0x01, comId, recvBuf, 2048);
                if (r.failed()) break;
                if (recvBuf.size() >= 20) {
                    uint32_t cpLen = Endian::readBe32(recvBuf.data() + 16);
                    if (cpLen > 0) break;
                }
            }
            if (r.ok() && recvBuf.size() >= 56) {
                uint32_t tokenLen = Endian::readBe32(recvBuf.data() + 52);
                // 토큰에서 status 파싱
                // Status는 EOD 뒤 [ status 0 0 ]
                const uint8_t* toks = recvBuf.data() + 56;
                uint8_t status = 0xFF;
                for (size_t i = 0; i + 4 < tokenLen; i++) {
                    if (toks[i] == 0xF9) {  // EOD
                        // 다음: F0 status 00 00 F1
                        if (i + 3 < tokenLen && toks[i+1] == 0xF0)
                            status = toks[i+2];
                        break;
                    }
                }
                std::cout << "  [B] Recv " << recvBuf.size() << " bytes, St=" << (int)status;
                if (status == 0) std::cout << " (Success)";
                else std::cout << " (0x" << std::hex << (int)status << std::dec << ")";
                std::cout << "\n";

                // [A] send payload와 비교
                std::cout << "  [A vs B] Send size: A=" << props.raw.rawSendPayload.size()
                          << " B=" << sendData.size() << "\n";
                if (props.raw.rawSendPayload.size() == sendData.size()) {
                    bool same = (props.raw.rawSendPayload == sendData);
                    std::cout << "  [A vs B] Send payload: "
                              << (same ? "IDENTICAL" : "DIFFERENT") << "\n";
                    if (!same) {
                        for (size_t i = 0; i < sendData.size(); i++) {
                            if (props.raw.rawSendPayload[i] != sendData[i]) {
                                printf("    offset 0x%04zX: A=0x%02X B=0x%02X\n",
                                       i, props.raw.rawSendPayload[i], sendData[i]);
                            }
                        }
                    }
                } else {
                    std::cout << "  [A vs B] Send payload: SIZE MISMATCH\n";
                }
            }
        } else {
            std::cout << "  [B] Send FAIL: " << r.message() << "\n";
        }
    }

    uint32_t maxCPS = (props.tperMaxComPacketSize > 0)
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
