/// @file props_diff.cpp
/// @brief libsed vs sedutil Properties 패킷 실제 비교 도구
///
/// 실제 디바이스에 두 가지 방식(libsed / sedutil)으로 Properties를 보내고
/// send/recv 패킷을 모두 캡처하여 byte-level diff를 출력한다.
///
/// Usage: ./props_diff <device> [comid]
///   device: NVMe 디바이스 경로 (예: /dev/nvme0)
///   comid:  ComID (생략 시 Discovery에서 자동 탐지)
///
/// 흐름:
///   1. Discovery → ComID 획득
///   2. StackReset
///   3. libsed 방식으로 Properties Send/Recv → 캡처
///   4. StackReset
///   5. sedutil 방식으로 Properties Send/Recv → 캡처
///   6. Send 패킷 비교 + Recv 패킷 비교

#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/codec/token_encoder.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/uid.h>
#include <libsed/core/endian.h>
#include <libsed/sed_library.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>
#include <chrono>
#include <thread>

using namespace libsed;
using namespace libsed::eval;

using Packet = std::vector<uint8_t>;

// ═══════════════════════════════════════════════════════
//  sedutil 방식 Properties 패킷 수동 구성
// ═══════════════════════════════════════════════════════

static Packet buildSedutilProperties(uint16_t comId) {
    Packet buf(2048, 0);
    size_t pos = 56;

    // CALL
    buf[pos++] = 0xF8;

    // SMUID
    buf[pos++] = 0xA8;
    buf[pos++]=0; buf[pos++]=0; buf[pos++]=0; buf[pos++]=0;
    buf[pos++]=0; buf[pos++]=0; buf[pos++]=0; buf[pos++]=0xFF;

    // SM_PROPERTIES
    buf[pos++] = 0xA8;
    buf[pos++]=0; buf[pos++]=0; buf[pos++]=0; buf[pos++]=0;
    buf[pos++]=0; buf[pos++]=0; buf[pos++]=0xFF; buf[pos++]=0x01;

    buf[pos++] = 0xF0;  // STARTLIST
    buf[pos++] = 0xF2;  // STARTNAME

    // "HostProperties"
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

    addStr("HostProperties");
    buf[pos++] = 0xF0;  // STARTLIST

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
}

// ═══════════════════════════════════════════════════════
//  libsed 방식 Properties 패킷
// ═══════════════════════════════════════════════════════

static Packet buildLibsedProperties(uint16_t comId) {
    ParamEncoder::HostProperties hp;
    hp.maxComPacketSize = 2048;
    hp.maxPacketSize = 2028;
    hp.maxIndTokenSize = 1992;
    hp.maxPackets = 1;
    hp.maxSubPackets = 1;
    hp.maxMethods = 1;

    Bytes params = ParamEncoder::encodeProperties(hp);
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);

    PacketBuilder pb;
    pb.setComId(comId);
    return pb.buildSessionManagerPacket(methodTokens);
}

// ═══════════════════════════════════════════════════════
//  출력
// ═══════════════════════════════════════════════════════

static void hexDump(const char* label, const uint8_t* data, size_t len, size_t maxBytes = 0) {
    printf("=== %s (%zu bytes) ===\n", label, len);
    size_t limit = (maxBytes > 0) ? std::min(len, maxBytes) : len;
    for (size_t i = 0; i < limit; i += 16) {
        printf("  %04zX: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i+j < limit) printf("%02X ", data[i+j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && (i+j) < limit; j++) {
            uint8_t c = data[i+j];
            printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        printf("|\n");
    }
    if (limit < len) printf("  ... (%zu more bytes)\n", len - limit);
    printf("\n");
}

static int diffPackets(const char* label,
                       const Packet& a, const char* aName,
                       const Packet& b, const char* bName) {
    printf("── %s Diff ──\n", label);
    size_t maxLen = std::max(a.size(), b.size());
    int diffs = 0;
    for (size_t i = 0; i < maxLen; i++) {
        uint8_t av = (i < a.size()) ? a[i] : 0;
        uint8_t bv = (i < b.size()) ? b[i] : 0;
        if (av != bv) {
            printf("  offset 0x%04zX: %s=0x%02X  %s=0x%02X", i, aName, av, bName, bv);
            // ASCII 차이면 ���자도 표시
            if (av >= 0x20 && av <= 0x7E && bv >= 0x20 && bv <= 0x7E)
                printf("  ('%c' vs '%c')", av, bv);
            printf("\n");
            diffs++;
            if (diffs >= 50) { printf("  ... (too many diffs)\n"); break; }
        }
    }
    if (a.size() != b.size())
        printf("  Size: %s=%zu  %s=%zu\n", aName, a.size(), bName, b.size());
    if (diffs == 0 && a.size() == b.size())
        printf("  *** IDENTICAL ***\n");
    else
        printf("  Total diffs: %d\n", diffs);
    printf("\n");
    return diffs;
}

static void tokenDump(const char* label, const uint8_t* data, size_t len) {
    printf("=== %s Tokens ===\n", label);
    size_t i = 0;
    while (i < len) {
        uint8_t b = data[i];
        if (b >= 0xF0 && b <= 0xFF) {
            const char* names[] = {
                "STARTLIST","ENDLIST","STARTNAME","ENDNAME",
                "??F4","??F5","??F6","??F7",
                "CALL","ENDOFDATA","ENDOFSESSION","STARTTXN",
                "ENDTXN","??FD","??FE","EMPTY"
            };
            printf("  [%04zX] %s\n", i, names[b - 0xF0]);
            i++;
        } else if ((b & 0xC0) == 0x00) {
            printf("  [%04zX] uint: %u\n", i, b & 0x3F); i++;
        } else if ((b & 0xC0) == 0x40) {
            printf("  [%04zX] int: %d\n", i, (int8_t)((b & 0x3F) | ((b & 0x20)?0xC0:0))); i++;
        } else if ((b & 0xC0) == 0x80) {
            bool isB = b & 0x20; size_t al = b & 0x0F; i++;
            if (isB) {
                bool p = true;
                for (size_t j = 0; j < al && (i+j) < len; j++)
                    if (data[i+j] < 0x20 || data[i+j] > 0x7E) { p = false; break; }
                if (p && al > 0) {
                    printf("  [%04zX] \"", i-1);
                    for (size_t j = 0; j < al; j++) printf("%c", data[i+j]);
                    printf("\"\n");
                } else {
                    printf("  [%04zX] bytes[%zu]: ", i-1, al);
                    for (size_t j = 0; j < al; j++) printf("%02X", data[i+j]);
                    printf("\n");
                }
            } else {
                uint64_t v = 0;
                for (size_t j = 0; j < al; j++) v = (v<<8) | data[i+j];
                printf("  [%04zX] uint: %llu\n", i-1, (unsigned long long)v);
            }
            i += al;
        } else if ((b & 0xE0) == 0xC0) {
            bool isB = b & 0x10;
            size_t al = ((size_t)(b & 0x07) << 8) | data[i+1]; i += 2;
            if (isB) {
                bool p = true;
                for (size_t j = 0; j < al && (i+j) < len; j++)
                    if (data[i+j] < 0x20 || data[i+j] > 0x7E) { p = false; break; }
                if (p && al > 0) {
                    printf("  [%04zX] \"", i-2);
                    for (size_t j = 0; j < al; j++) printf("%c", data[i+j]);
                    printf("\"\n");
                } else {
                    printf("  [%04zX] bytes[%zu]: ", i-2, al);
                    for (size_t j = 0; j < al; j++) printf("%02X", data[i+j]);
                    printf("\n");
                }
            } else {
                uint64_t v = 0;
                for (size_t j = 0; j < al; j++) v = (v<<8) | data[i+j];
                printf("  [%04zX] uint: %llu\n", i-2, (unsigned long long)v);
            }
            i += al;
        } else {
            printf("  [%04zX] ?? 0x%02X\n", i, b); i++;
        }
    }
    printf("\n");
}

// ═══════════════════════════════════════════════════════
//  메인
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <device> [comid]\n", argv[0]);
        fprintf(stderr, "  device: /dev/nvme0\n");
        fprintf(stderr, "  comid:  0x1004 (생략 시 Discovery에서 자동)\n");
        return 1;
    }

    std::string device = argv[1];
    uint16_t comId = 0;
    if (argc >= 3) comId = (uint16_t)strtol(argv[2], nullptr, 0);

    libsed::initialize();
    EvalApi api;

    // ── Transport ──
    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        fprintf(stderr, "ERROR: Cannot open %s\n", device.c_str());
        return 1;
    }

    // ── Discovery (ComID 자동 탐지) ──
    if (comId == 0) {
        DiscoveryInfo info;
        auto r = api.discovery0(transport, info);
        if (r.failed() || info.baseComId == 0) {
            fprintf(stderr, "ERROR: Discovery failed\n");
            return 1;
        }
        comId = info.baseComId;
        printf("Discovery: ComID=0x%04X\n\n", comId);
    }

    // ── 패킷 생성 (메모리에서) ──
    Packet libsedSend = buildLibsedProperties(comId);
    Packet sedutilSend = buildSedutilProperties(comId);

    // ══════════════════════════════════════════════
    //  Test 1: libsed 방식으로 Send/Recv
    // ══════════════════════════════════════════════
    printf("╔══════════════════════════════════════════╗\n");
    printf("��  Test 1: libsed Properties               ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    api.stackReset(transport, comId);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Packet libsedRecv;
    {
        auto r = transport->ifSend(0x01, comId,
                    ByteSpan(libsedSend.data(), libsedSend.size()));
        if (r.failed()) {
            fprintf(stderr, "libsed IF-SEND failed: %s\n", r.message().c_str());
            return 1;
        }
        printf("libsed: IF-SEND OK (%zu bytes)\n", libsedSend.size());

        // Recv with polling
        for (int attempt = 0; attempt < 20; attempt++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            libsedRecv.clear();
            r = transport->ifRecv(0x01, comId, libsedRecv, 2048);
            if (r.failed()) {
                fprintf(stderr, "libsed IF-RECV failed: %s\n", r.message().c_str());
                return 1;
            }
            if (libsedRecv.size() >= 20) {
                uint32_t cpLen = Endian::readBe32(libsedRecv.data() + 16);
                if (cpLen > 0) break;
            }
        }
        printf("libsed: IF-RECV OK (%zu bytes)\n\n", libsedRecv.size());
    }

    // ══════════════════════════════════════════════
    //  Test 2: sedutil 방식으로 Send/Recv
    // ══════════════════════════════════════════════
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  Test 2: sedutil Properties               ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    api.stackReset(transport, comId);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Packet sedutilRecv;
    {
        auto r = transport->ifSend(0x01, comId,
                    ByteSpan(sedutilSend.data(), sedutilSend.size()));
        if (r.failed()) {
            fprintf(stderr, "sedutil IF-SEND failed: %s\n", r.message().c_str());
            return 1;
        }
        printf("sedutil: IF-SEND OK (%zu bytes)\n", sedutilSend.size());

        for (int attempt = 0; attempt < 20; attempt++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            sedutilRecv.clear();
            r = transport->ifRecv(0x01, comId, sedutilRecv, 2048);
            if (r.failed()) {
                fprintf(stderr, "sedutil IF-RECV failed: %s\n", r.message().c_str());
                return 1;
            }
            if (sedutilRecv.size() >= 20) {
                uint32_t cpLen = Endian::readBe32(sedutilRecv.data() + 16);
                if (cpLen > 0) break;
            }
        }
        printf("sedutil: IF-RECV OK (%zu bytes)\n\n", sedutilRecv.size());
    }

    // ══════════════════════════════════════════════
    //  비교
    // ══════════════════════════════════════════════
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  Comparison Results                       ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    // Send 비교
    int sendDiffs = diffPackets("SEND", libsedSend, "libsed", sedutilSend, "sedutil");

    // Recv 비교
    int recvDiffs = diffPackets("RECV", libsedRecv, "libsed", sedutilRecv, "sedutil");

    // ── Send hex dumps ──
    uint32_t libSendTokenLen = 0, sedSendTokenLen = 0;
    if (libsedSend.size() >= 56) libSendTokenLen = Endian::readBe32(libsedSend.data() + 52);
    if (sedutilSend.size() >= 56) sedSendTokenLen = Endian::readBe32(sedutilSend.data() + 52);

    hexDump("libsed SEND", libsedSend.data(), libsedSend.size(), 256);
    hexDump("sedutil SEND", sedutilSend.data(), sedutilSend.size(), 256);

    // Send token streams
    if (libSendTokenLen > 0)
        tokenDump("libsed SEND", libsedSend.data() + 56, libSendTokenLen);
    if (sedSendTokenLen > 0)
        tokenDump("sedutil SEND", sedutilSend.data() + 56, sedSendTokenLen);

    // ── Recv hex dumps ──
    uint32_t libRecvTokenLen = 0, sedRecvTokenLen = 0;
    if (libsedRecv.size() >= 56) libRecvTokenLen = Endian::readBe32(libsedRecv.data() + 52);
    if (sedutilRecv.size() >= 56) sedRecvTokenLen = Endian::readBe32(sedutilRecv.data() + 52);

    hexDump("libsed RECV", libsedRecv.data(), libsedRecv.size(), 512);
    hexDump("sedutil RECV", sedutilRecv.data(), sedutilRecv.size(), 512);

    // Recv token streams
    if (libRecvTokenLen > 0)
        tokenDump("libsed RECV", libsedRecv.data() + 56, libRecvTokenLen);
    if (sedRecvTokenLen > 0)
        tokenDump("sedutil RECV", sedutilRecv.data() + 56, sedRecvTokenLen);

    // ── Summary ──
    printf("══════════════════════════════════════════\n");
    printf("  SEND diffs: %d\n", sendDiffs);
    printf("  RECV diffs: %d\n", recvDiffs);
    if (sendDiffs == 0 && recvDiffs == 0)
        printf("  Result: IDENTICAL\n");
    else
        printf("  Result: DIFFERENCES FOUND\n");
    printf("══════════════════════════════════════════\n");

    // Cleanup
    api.stackReset(transport, comId);

    return (sendDiffs > 0 || recvDiffs > 0) ? 1 : 0;
}
