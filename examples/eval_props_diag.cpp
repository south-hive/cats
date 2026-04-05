/// @file eval_props_diag.cpp
/// @brief Properties 메서드만 집중 진단
///
/// Properties가 0x0C (InvalidParameter)를 반환하는 원인 격리:
///   시나리오 1: Properties WITHOUT HostProperties (TPer 속성만 조회)
///   시나리오 2: Properties WITH sedutil 기본 6개 파라미터
///   시나리오 3: Properties WITH 최소 파라미터 (MaxComPacketSize만)
///   시나리오 4: Properties 파라미터 없이 빈 리스트
///   시나리오 5: StackReset 없이 바로 Properties
///   시나리오 6: Discovery → Properties (StackReset 스킵)
///   시나리오 7: AdminSP Session (Properties 없이 직행)
///   시나리오 8: sedutil-cli --query 실행하여 비교
///
/// Usage: ./example_eval_props_diag <device> [--with-sedutil]

#include <libsed/sed_library.h>
#include <libsed/method/method_call.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/codec/token_encoder.h>
#include <libsed/codec/token_decoder.h>
#include <libsed/core/endian.h>
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cstring>

using namespace libsed;
using namespace libsed::eval;

/// @brief 직접 SM 패킷을 보내고 응답 status 파싱
struct DirectResult {
    int status = -1;         // TCG method status (0=success, 0x0C=InvalidParam, ...)
    size_t recvSize = 0;
    bool recvOk = false;
    std::string detail;
};

static DirectResult sendSmPacket(std::shared_ptr<ITransport> transport,
                                  uint16_t comId,
                                  const Bytes& methodTokens,
                                  const char* label) {
    DirectResult dr;

    PacketBuilder pb;
    pb.setComId(comId);
    Bytes sendData = pb.buildSessionManagerPacket(methodTokens);

    printf("  [%s] Send %zu bytes... ", label, sendData.size());

    auto r = transport->ifSend(0x01, comId, ByteSpan(sendData.data(), sendData.size()));
    if (r.failed()) {
        printf("SEND FAIL: %s\n", r.message().c_str());
        dr.detail = "send failed";
        return dr;
    }

    // Polling recv
    Bytes recvBuf;
    for (int att = 0; att < 30; att++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        recvBuf.clear();
        r = transport->ifRecv(0x01, comId, recvBuf, 2048);
        if (r.failed()) break;
        if (recvBuf.size() >= 20) {
            uint32_t cpLen = Endian::readBe32(recvBuf.data() + 16);
            if (cpLen > 0) break;
        }
    }

    if (r.failed()) {
        printf("RECV FAIL: %s\n", r.message().c_str());
        dr.detail = "recv failed";
        return dr;
    }

    dr.recvSize = recvBuf.size();
    dr.recvOk = true;

    // Parse status from token stream
    // ComPacket(20) + Packet(24) + SubPacket(12) = offset 56
    if (recvBuf.size() >= 56) {
        uint32_t subLen = Endian::readBe32(recvBuf.data() + 52);
        if (subLen > 0) {
            // Decode tokens for proper parsing
            TokenDecoder dec;
            Bytes tokenPayload(recvBuf.begin() + 56,
                              recvBuf.begin() + 56 + std::min((size_t)subLen, recvBuf.size() - 56));
            auto pr = dec.decode(tokenPayload);
            if (pr.ok()) {
                // Find EOD then status list
                const auto& tokens = dec.tokens();
                for (size_t i = 0; i < tokens.size(); i++) {
                    if (tokens[i].type == TokenType::EndOfData) {
                        // Next should be StartList, then status uint
                        if (i + 2 < tokens.size() &&
                            tokens[i+1].type == TokenType::StartList &&
                            tokens[i+2].isAtom()) {
                            dr.status = static_cast<int>(tokens[i+2].getUint());
                        }
                        break;
                    }
                }
            }
        }
    }

    if (dr.status == 0) printf("OK (status=0)\n");
    else if (dr.status >= 0) printf("status=0x%02X\n", dr.status);
    else printf("recv %zu bytes (no status parsed)\n", dr.recvSize);

    return dr;
}

static void stackReset(std::shared_ptr<ITransport> transport, uint16_t comId) {
    EvalApi api;
    auto r = api.stackReset(transport, comId);
    printf("  StackReset: %s\n", r.ok() ? "OK" : r.message().c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <device> [--with-sedutil]\n";
        return 1;
    }

    std::string device = argv[1];
    bool withSedutil = false;
    for (int i = 2; i < argc; i++)
        if (std::string(argv[i]) == "--with-sedutil") withSedutil = true;

    libsed::initialize();
    EvalApi api;

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "ERROR: Cannot open " << device << "\n";
        return 1;
    }

    // Discovery to get ComID
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed() || info.baseComId == 0) {
        std::cerr << "Discovery failed\n";
        return 1;
    }
    uint16_t comId = info.baseComId;
    printf("Device: %s  ComID=0x%04X\n\n", device.c_str(), comId);

    // ═══════════════════════════════════════════════
    //  시나리오 1: Properties WITHOUT HostProperties
    //  빈 파라미터 → TPer 속성만 조회 요청
    // ═══════════════════════════════════════════════
    printf("── Scenario 1: Properties with NO HostProperties (empty params) ──\n");
    stackReset(transport, comId);
    {
        // CALL SMUID SM_PROPERTIES STARTLIST ENDLIST EOD ...
        Bytes emptyParams; // no HostProperties block at all
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, emptyParams);
        sendSmPacket(transport, comId, methodTokens, "S1");
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 2: Properties with sedutil 기본 6개
    //  (우리 encodeProperties와 동일)
    // ═══════════════════════════════════════════════
    printf("── Scenario 2: Properties with sedutil 6 params (via encodeProperties) ──\n");
    stackReset(transport, comId);
    {
        ParamEncoder::HostProperties hp;
        hp.maxComPacketSize = 2048;
        hp.maxPacketSize = 2028;
        hp.maxIndTokenSize = 1992;
        hp.maxPackets = 1;
        hp.maxSubPackets = 1;
        hp.maxMethods = 1;
        Bytes params = ParamEncoder::encodeProperties(hp);
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);
        sendSmPacket(transport, comId, methodTokens, "S2");
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 3: Properties with 최소 1개 파라미터만
    //  MaxComPacketSize만 전송
    // ═══════════════════════════════════════════════
    printf("── Scenario 3: Properties with only MaxComPacketSize ──\n");
    stackReset(transport, comId);
    {
        TokenEncoder enc;
        enc.startName();
        enc.encodeString("HostProperties");
        enc.startList();
        enc.startName(); enc.encodeString("MaxComPacketSize");
        enc.encodeUint(2048); enc.endName();
        enc.endList();
        enc.endName();
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, enc.data());
        sendSmPacket(transport, comId, methodTokens, "S3");
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 4: Properties with 빈 HostProperties 리스트
    //  STARTNAME "HostProperties" STARTLIST ENDLIST ENDNAME
    // ═══════════════════════════════════════════════
    printf("── Scenario 4: Properties with empty HostProperties list ──\n");
    stackReset(transport, comId);
    {
        TokenEncoder enc;
        enc.startName();
        enc.encodeString("HostProperties");
        enc.startList();
        enc.endList();
        enc.endName();
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, enc.data());
        sendSmPacket(transport, comId, methodTokens, "S4");
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 5: StackReset 없이 바로 Properties
    //  (Discovery 직후)
    // ═══════════════════════════════════════════════
    printf("── Scenario 5: Properties WITHOUT StackReset (after Discovery) ──\n");
    // re-do discovery to reset state
    api.discovery0(transport, info);
    {
        ParamEncoder::HostProperties hp;
        hp.maxComPacketSize = 2048;
        hp.maxPacketSize = 2028;
        hp.maxIndTokenSize = 1992;
        Bytes params = ParamEncoder::encodeProperties(hp);
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);
        sendSmPacket(transport, comId, methodTokens, "S5");
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 6: EvalApi 고수준 경유 Properties
    // ═══════════════════════════════════════════════
    printf("── Scenario 6: Properties via api.exchangeProperties() ──\n");
    stackReset(transport, comId);
    {
        PropertiesResult props;
        r = api.exchangeProperties(transport, comId, props);
        if (r.ok()) {
            printf("  [S6] OK: TPerMaxCPS=%u TPerMaxPktSz=%u TPerMaxIndTok=%u\n",
                   props.tperMaxComPacketSize, props.tperMaxPacketSize,
                   props.tperMaxIndTokenSize);
        } else {
            printf("  [S6] FAIL: %s\n", r.message().c_str());
        }
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 7: AdminSP Session 직행 (Properties 스킵)
    //  → Properties 없어도 세션이 되는지 확인
    // ═══════════════════════════════════════════════
    printf("── Scenario 7: AdminSP Session WITHOUT Properties ──\n");
    stackReset(transport, comId);
    {
        Session session(transport, comId);
        session.setMaxComPacketSize(2048);
        StartSessionResult ssr;
        r = api.startSession(session, uid::SP_ADMIN, false, ssr);
        if (r.ok()) {
            printf("  [S7] Session OK: TSN=%u HSN=%u\n",
                   ssr.tperSessionNumber, ssr.hostSessionNumber);

            // MSID 읽기
            Bytes msid;
            r = api.getCPin(session, uid::CPIN_MSID, msid);
            if (r.ok() && !msid.empty()) {
                printf("  [S7] MSID (%zu bytes): ", msid.size());
                for (size_t i = 0; i < msid.size() && i < 32; i++)
                    printf("%02X", msid[i]);
                printf("\n");
            } else {
                printf("  [S7] MSID read: %s\n", r.message().c_str());
            }

            api.closeSession(session);
            printf("  [S7] Session closed\n");
        } else {
            printf("  [S7] Session FAIL: %s\n", r.message().c_str());
        }
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 8: Properties → Session 순서 (정상 플로우)
    // ═══════════════════════════════════════════════
    printf("── Scenario 8: Full flow (StackReset → Properties → Session → MSID) ──\n");
    stackReset(transport, comId);
    {
        PropertiesResult props;
        r = api.exchangeProperties(transport, comId, props);
        printf("  [S8] Properties: %s", r.ok() ? "OK" : r.message().c_str());
        if (r.ok())
            printf(" (TPerMaxCPS=%u)", props.tperMaxComPacketSize);
        printf("\n");

        uint32_t maxCPS = (props.tperMaxComPacketSize > 0)
                          ? props.tperMaxComPacketSize : 2048;

        Session session(transport, comId);
        session.setMaxComPacketSize(maxCPS);
        StartSessionResult ssr;
        r = api.startSession(session, uid::SP_ADMIN, false, ssr);
        if (r.ok()) {
            printf("  [S8] Session OK: TSN=%u HSN=%u\n",
                   ssr.tperSessionNumber, ssr.hostSessionNumber);

            Bytes msid;
            r = api.getCPin(session, uid::CPIN_MSID, msid);
            if (r.ok() && !msid.empty()) {
                printf("  [S8] MSID (%zu bytes): ", msid.size());
                for (size_t i = 0; i < msid.size() && i < 32; i++)
                    printf("%02X", msid[i]);
                printf("\n");
            } else {
                printf("  [S8] MSID: %s\n", r.message().c_str());
            }
            api.closeSession(session);
        } else {
            printf("  [S8] Session FAIL: %s\n", r.message().c_str());
        }
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 9: Properties를 2번 연속 호출
    //  (첫번째 실패 후 두번째도 실패하는지)
    // ═══════════════════════════════════════════════
    printf("── Scenario 9: Properties twice (StackReset between) ──\n");
    stackReset(transport, comId);
    {
        PropertiesResult props1;
        r = api.exchangeProperties(transport, comId, props1);
        printf("  [S9a] First:  %s\n", r.ok() ? "OK" : r.message().c_str());

        stackReset(transport, comId);

        PropertiesResult props2;
        r = api.exchangeProperties(transport, comId, props2);
        printf("  [S9b] Second: %s\n", r.ok() ? "OK" : r.message().c_str());
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  시나리오 10: Hex dump of Properties send packet
    //  (수동 검증용)
    // ═══════════════════════════════════════════════
    printf("── Scenario 10: Hex dump of Properties send packet (first 128 bytes) ──\n");
    {
        ParamEncoder::HostProperties hp;
        hp.maxComPacketSize = 2048;
        hp.maxPacketSize = 2028;
        hp.maxIndTokenSize = 1992;
        Bytes params = ParamEncoder::encodeProperties(hp);
        Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);

        PacketBuilder pb;
        pb.setComId(comId);
        Bytes sendData = pb.buildSessionManagerPacket(methodTokens);

        printf("  Total size: %zu bytes\n", sendData.size());
        printf("  Token payload size: %zu bytes\n", methodTokens.size());
        size_t dumpLen = std::min(sendData.size(), (size_t)128);
        for (size_t i = 0; i < dumpLen; i++) {
            if (i % 16 == 0) printf("  %04zX: ", i);
            printf("%02X ", sendData[i]);
            if (i % 16 == 15) printf("\n");
        }
        if (dumpLen % 16 != 0) printf("\n");

        // Token portion (after ComPacket+Packet+SubPacket headers = offset 56)
        printf("\n  Token bytes (offset 56):\n  ");
        for (size_t i = 56; i < 56 + methodTokens.size() && i < sendData.size(); i++)
            printf("%02X ", sendData[i]);
        printf("\n");
    }
    printf("\n");

    // ═══════════════════════════════════════════════
    //  (선택) sedutil-cli --query
    // ═══════════════════════════════════════════════
    if (withSedutil) {
        printf("══════════════════════════════════════════\n");
        printf("  sedutil-cli --query %s\n", device.c_str());
        printf("══════════════════════════════════════════\n");
        std::string cmd = "sedutil-cli --query " + device;
        int rc = system(cmd.c_str());
        printf("\nsedutil-cli exit code: %d\n", rc);
    }

    printf("\n══════════════════════════════════════════\n");
    printf("  Done. Review which scenarios returned status=0 vs 0x0C.\n");
    printf("══════════════════════════════════════════\n");

    return 0;
}
