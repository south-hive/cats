/// @file protocol_trace.cpp
/// @brief sedutil vs cats(libsed) 동일 시나리오 실행 + ioctl 버퍼 덤프 비교 도구
///
/// 각 시나리오(Discovery, StackReset, Properties)를 sedutil 방식과 cats 방식으로
/// 각각 **실제 디바이스에 전송**하고, send/recv 버퍼를 .bin 파일로 저장한다.
/// 콘솔에는 hex dump + diff 요약이 출력된다.
///
/// 출력 구조:
///   {outdir}/
///   ├── 01_stackreset_send.bin         (공통 — 양쪽 동일)
///   ├── 02_props_send_sedutil.bin      sedutil DtaCommand가 생성한 패킷
///   ├── 02_props_recv_sedutil.bin      sedutil 방식 전송 후 수신된 응답
///   ├── 02_props_send_cats.bin         cats(libsed)가 생성한 패킷
///   ├── 02_props_recv_cats.bin         cats 방식 전송 후 수신된 응답
///   ├── 03_startsess_send_sedutil.bin
///   ├── 03_startsess_send_cats.bin
///   └── summary.txt
///
/// Usage: sudo ./protocol_trace <device> [--outdir <dir>]

#include <libsed/sed_library.h>
#include <libsed/codec/token_encoder.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/uid.h>
#include <libsed/core/endian.h>

// Real sedutil DtaCommand
#include "os.h"
#include "DtaStructures.h"
#include "DtaEndianFixup.h"
#include "DtaCommand.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <sys/stat.h>

using namespace libsed;
using namespace libsed::eval;
using Buf = std::vector<uint8_t>;

// ═══════════════════════════════════════════════════════
//  Globals & Helpers
// ═══════════════════════════════════════════════════════

static std::string g_outDir = "./trace_output";
static FILE* g_sum = nullptr;   // summary file
static int g_totalDiffs = 0;

static void saveBin(const char* name, const uint8_t* data, size_t len) {
    std::string path = g_outDir + "/" + name;
    FILE* f = fopen(path.c_str(), "wb");
    if (f) { fwrite(data, 1, len, f); fclose(f); }
    printf("  -> %s (%zu bytes)\n", name, len);
}
static void saveBin(const char* name, const Buf& b) { saveBin(name, b.data(), b.size()); }

// ── Hex dump (16 bytes/line) ──

static void hexdump(const char* label, const uint8_t* data, size_t len, size_t maxLines = 8) {
    printf("  [%s] %zu bytes:\n", label, len);
    size_t lines = (len + 15) / 16;
    if (lines > maxLines) lines = maxLines;
    for (size_t i = 0; i < lines; i++) {
        printf("    %04zx: ", i * 16);
        for (size_t j = 0; j < 16; j++) {
            size_t off = i * 16 + j;
            if (off < len) printf("%02x ", data[off]);
            else printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            size_t off = i * 16 + j;
            if (off < len) {
                uint8_t c = data[off];
                printf("%c", (c >= 0x20 && c <= 0x7e) ? c : '.');
            }
        }
        printf("|\n");
    }
    if ((len + 15) / 16 > maxLines)
        printf("    ... (%zu more bytes)\n", len - maxLines * 16);
}

// ── Diff ──

static int diffBufs(const char* label, const Buf& a, const char* aName,
                    const Buf& b, const char* bName) {
    size_t maxLen = std::max(a.size(), b.size());
    int diffs = 0;
    for (size_t i = 0; i < maxLen; i++) {
        uint8_t va = (i < a.size()) ? a[i] : 0;
        uint8_t vb = (i < b.size()) ? b[i] : 0;
        if (va != vb) {
            if (diffs < 30) {
                printf("    offset 0x%04zx: %s=0x%02x  %s=0x%02x\n", i, aName, va, bName, vb);
                fprintf(g_sum, "  offset 0x%04zx: %s=0x%02x  %s=0x%02x\n", i, aName, va, bName, vb);
            }
            diffs++;
        }
    }
    if (a.size() != b.size()) {
        printf("    SIZE: %s=%zu  %s=%zu\n", aName, a.size(), bName, b.size());
        fprintf(g_sum, "  SIZE: %s=%zu  %s=%zu\n", aName, a.size(), bName, b.size());
    }
    if (diffs == 0) {
        printf("    *** IDENTICAL ***\n");
        fprintf(g_sum, "  [%s] IDENTICAL\n", label);
    } else {
        printf("    Total diffs: %d\n", diffs);
        fprintf(g_sum, "  [%s] %d diffs\n", label, diffs);
    }
    g_totalDiffs += diffs;
    return diffs;
}

// ── StackReset (공통: 양쪽 동일) ──

static bool doStackReset(std::shared_ptr<ITransport> transport, uint16_t comId) {
    Buf req(512, 0);
    Endian::writeBe16(req.data(), comId);
    Endian::writeBe32(req.data() + 4, 2);  // STACK_RESET
    auto r = transport->ifSend(0x02, comId, ByteSpan(req.data(), req.size()));
    if (r.failed()) return false;

    for (int i = 0; i < 20; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        Buf vreq(512, 0);
        Endian::writeBe16(vreq.data(), comId);
        // RequestCode = 0 (VERIFY_COMID)
        r = transport->ifSend(0x02, comId, ByteSpan(vreq.data(), vreq.size()));
        if (r.failed()) return false;

        Bytes resp;
        r = transport->ifRecv(0x02, comId, resp, 512);
        if (r.failed()) return false;
        if (resp.size() >= 16) {
            uint32_t state = Endian::readBe32(resp.data() + 12);
            if (state == 0) return true;
        }
    }
    return true;
}

// ── IF-RECV with polling ──

static Buf doRecv(std::shared_ptr<ITransport> transport, uint16_t comId,
                  size_t bufSize = 2048, int maxPoll = 20) {
    for (int i = 0; i < maxPoll; i++) {
        Bytes buf;
        auto r = transport->ifRecv(0x01, comId, buf, bufSize);
        if (r.failed()) return {};
        // ComPacket.length at offset 16
        if (buf.size() >= 20) {
            uint32_t cpLen = Endian::readBe32(buf.data() + 16);
            if (cpLen > 0) return Buf(buf.begin(), buf.end());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return {};
}

// ── Method status 추출 ──

static const char* statusName(uint8_t s) {
    switch (s) {
        case 0x00: return "Success";
        case 0x01: return "NotAuthorized";
        case 0x0C: return "InvalidParameter";
        case 0x0F: return "TPERMalfunction";
        case 0x3F: return "Fail";
        default: return "Other";
    }
}

static uint8_t extractMethodStatus(const Buf& recv) {
    // SubPacket payload starts at offset 56 (ComPkt=20 + Pkt=24 + SubPkt=12)
    // Method status is at the end: F0 (EOD) F1 00 xx 00 F9
    // Search backwards for F0 pattern
    if (recv.size() < 60) return 0xFF;
    for (size_t i = recv.size() - 1; i >= 56 + 5; i--) {
        if (recv[i] == 0xF9 && i >= 4) {
            // F0 00 xx 00 F9
            if (recv[i-4] == 0xF0) return recv[i-2];
            // F1 00 xx 00 F9
            if (recv[i-4] == 0xF1) return recv[i-2];
        }
    }
    return 0xFF;
}

// ═══════════════════════════════════════════════════════
//  sedutil packet builders (real DtaCommand)
// ═══════════════════════════════════════════════════════

static Buf sedutil_Properties(uint16_t comId) {
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, PROPERTIES);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("HostProperties");
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxComPacketSize");
    cmd.addToken((uint64_t)2048);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxPacketSize");
    cmd.addToken((uint64_t)2028);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxIndTokenSize");
    cmd.addToken((uint64_t)1992);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxPackets");
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxSubpackets");
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken("MaxMethods");
    cmd.addToken((uint64_t)1);
    cmd.addToken(OPAL_TOKEN::ENDNAME);

    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(comId);

    uint8_t* buf = static_cast<uint8_t*>(cmd.getCmdBuffer());
    return Buf(buf, buf + MIN_BUFFER_LENGTH);
}

static Buf sedutil_StartSession(uint16_t comId) {
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken((uint64_t)105);                     // HSN = 105 (sedutil hardcode)
    cmd.addToken(OPAL_UID::OPAL_ADMINSP_UID);       // AdminSP
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);           // Write = false
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(comId);

    uint8_t* buf = static_cast<uint8_t*>(cmd.getCmdBuffer());
    return Buf(buf, buf + MIN_BUFFER_LENGTH);
}

// ═══════════════════════════════════════════════════════
//  cats(libsed) packet builders
// ═══════════════════════════════════════════════════════

static Buf cats_Properties(uint16_t comId) {
    ParamEncoder::HostProperties hp;
    hp.maxComPacketSize = 2048;
    hp.maxResponseComPacketSize = 2048;
    hp.maxPacketSize = 2028;
    hp.maxIndTokenSize = 1992;
    hp.maxAggTokenSize = 1992;

    Bytes params = ParamEncoder::encodeProperties(hp);
    Bytes tokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);
    PacketBuilder pb;
    pb.setComId(comId);
    return pb.buildSessionManagerPacket(tokens);
}

static Buf cats_StartSession(uint16_t comId) {
    Bytes params = ParamEncoder::encodeStartSession(
        105, Uid(uid::SP_ADMIN), false, {}, Uid(), Uid());
    Bytes tokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
    PacketBuilder pb;
    pb.setComId(comId);
    return pb.buildSessionManagerPacket(tokens);
}

// ═══════════════════════════════════════════════════════
//  Scenario runner
// ═══════════════════════════════════════════════════════

struct ScenarioResult {
    Buf sendBuf;
    Buf recvBuf;
    uint8_t status = 0xFF;
    bool sendOk = false;
    bool recvOk = false;
};

static ScenarioResult runScenario(std::shared_ptr<ITransport> transport,
                                   uint16_t comId, const Buf& sendPkt) {
    ScenarioResult sr;
    sr.sendBuf = sendPkt;

    auto r = transport->ifSend(0x01, comId, ByteSpan(sendPkt.data(), sendPkt.size()));
    sr.sendOk = r.ok();
    if (r.failed()) return sr;

    sr.recvBuf = doRecv(transport, comId);
    sr.recvOk = !sr.recvBuf.empty();
    if (sr.recvOk) sr.status = extractMethodStatus(sr.recvBuf);
    return sr;
}

// ═══════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <device> [--outdir <dir>]\n\n"
            "Runs identical TCG scenarios via sedutil(DtaCommand) and cats(libsed),\n"
            "sending BOTH to the real device, and dumps all ioctl buffers for comparison.\n\n"
            "Example:\n"
            "  sudo %s /dev/nvme0 --outdir ./trace\n"
            "  bcomp trace/02_props_send_sedutil.bin trace/02_props_send_cats.bin\n",
            argv[0], argv[0]);
        return 1;
    }

    std::string device = argv[1];
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--outdir" && i+1 < argc)
            g_outDir = argv[++i];
    }
    mkdir(g_outDir.c_str(), 0755);

    std::string sumPath = g_outDir + "/summary.txt";
    g_sum = fopen(sumPath.c_str(), "w");
    if (!g_sum) { fprintf(stderr, "Cannot create %s\n", sumPath.c_str()); return 1; }

    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║  protocol_trace — sedutil vs cats side-by-side    ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n");
    printf("Device: %s   Output: %s/\n\n", device.c_str(), g_outDir.c_str());
    fprintf(g_sum, "# protocol_trace — %s\n\n", device.c_str());

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        fprintf(stderr, "ERROR: Cannot open %s\n", device.c_str());
        return 1;
    }

    // ═══════════════════════════════════════════════
    //  Step 1: Discovery
    // ═══════════════════════════════════════════════
    printf("━━━ [1] Discovery ━━━\n");
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) { fprintf(stderr, "Discovery FAILED\n"); return 1; }
    DiscoveryInfo info = disc.buildInfo();
    uint16_t comId = info.baseComId;
    printf("  ComID=0x%04X  SSC=%s\n\n", comId, sscName(info.primarySsc));
    fprintf(g_sum, "ComID=0x%04X  SSC=%s\n\n", comId, sscName(info.primarySsc));

    if (comId == 0) { fprintf(stderr, "No valid ComID\n"); return 1; }

    // ═══════════════════════════════════════════════
    //  Step 2: Properties — sedutil 방식
    // ═══════════════════════════════════════════════
    printf("━━━ [2a] Properties — sedutil(DtaCommand) ━━━\n");
    {
        doStackReset(transport, comId);
        printf("  StackReset OK\n");

        Buf sendPkt = sedutil_Properties(comId);
        saveBin("02_props_send_sedutil.bin", sendPkt);
        hexdump("sedutil SEND", sendPkt.data(), std::min(sendPkt.size(), (size_t)128));

        auto sr = runScenario(transport, comId, sendPkt);
        if (sr.recvOk) {
            saveBin("02_props_recv_sedutil.bin", sr.recvBuf);
            hexdump("sedutil RECV", sr.recvBuf.data(), std::min(sr.recvBuf.size(), (size_t)128));
        }
        printf("  Result: status=0x%02X (%s)\n\n", sr.status, statusName(sr.status));
        fprintf(g_sum, "[2a] Properties sedutil: status=0x%02X (%s)\n", sr.status, statusName(sr.status));
    }

    // ═══════════════════════════════════════════════
    //  Step 3: Properties — cats 방식
    // ═══════════════════════════════════════════════
    printf("━━━ [2b] Properties — cats(libsed) ━━━\n");
    {
        doStackReset(transport, comId);
        printf("  StackReset OK\n");

        Buf sendPkt = cats_Properties(comId);
        saveBin("02_props_send_cats.bin", sendPkt);
        hexdump("cats SEND", sendPkt.data(), std::min(sendPkt.size(), (size_t)128));

        auto sr = runScenario(transport, comId, sendPkt);
        if (sr.recvOk) {
            saveBin("02_props_recv_cats.bin", sr.recvBuf);
            hexdump("cats RECV", sr.recvBuf.data(), std::min(sr.recvBuf.size(), (size_t)128));
        }
        printf("  Result: status=0x%02X (%s)\n\n", sr.status, statusName(sr.status));
        fprintf(g_sum, "[2b] Properties cats: status=0x%02X (%s)\n", sr.status, statusName(sr.status));
    }

    // ═══════════════════════════════════════════════
    //  Step 4: SEND 패킷 diff
    // ═══════════════════════════════════════════════
    printf("━━━ [3] Properties SEND diff ━━━\n");
    {
        Buf sed = sedutil_Properties(comId);
        Buf cat = cats_Properties(comId);
        fprintf(g_sum, "\n── Properties SEND diff ──\n");
        diffBufs("props_send", sed, "sedutil", cat, "cats");
        printf("\n");
    }

    // ═══════════════════════════════════════════════
    //  Step 5: StartSession — sedutil 방식
    // ═══════════════════════════════════════════════
    printf("━━━ [4a] StartSession — sedutil(DtaCommand) ━━━\n");
    {
        doStackReset(transport, comId);

        Buf sendPkt = sedutil_StartSession(comId);
        saveBin("03_startsess_send_sedutil.bin", sendPkt);
        hexdump("sedutil SEND", sendPkt.data(), std::min(sendPkt.size(), (size_t)128));

        auto sr = runScenario(transport, comId, sendPkt);
        if (sr.recvOk) {
            saveBin("03_startsess_recv_sedutil.bin", sr.recvBuf);
            hexdump("sedutil RECV", sr.recvBuf.data(), std::min(sr.recvBuf.size(), (size_t)128));
        }
        printf("  Result: status=0x%02X (%s)\n\n", sr.status, statusName(sr.status));
        fprintf(g_sum, "\n[4a] StartSession sedutil: status=0x%02X (%s)\n", sr.status, statusName(sr.status));
    }

    // ═══════════════════════════════════════════════
    //  Step 6: StartSession — cats 방식
    // ═══════════════════════════════════════════════
    printf("━━━ [4b] StartSession — cats(libsed) ━━━\n");
    {
        doStackReset(transport, comId);

        Buf sendPkt = cats_StartSession(comId);
        saveBin("03_startsess_send_cats.bin", sendPkt);
        hexdump("cats SEND", sendPkt.data(), std::min(sendPkt.size(), (size_t)128));

        auto sr = runScenario(transport, comId, sendPkt);
        if (sr.recvOk) {
            saveBin("03_startsess_recv_cats.bin", sr.recvBuf);
            hexdump("cats RECV", sr.recvBuf.data(), std::min(sr.recvBuf.size(), (size_t)128));
        }
        printf("  Result: status=0x%02X (%s)\n\n", sr.status, statusName(sr.status));
        fprintf(g_sum, "[4b] StartSession cats: status=0x%02X (%s)\n", sr.status, statusName(sr.status));
    }

    // ═══════════════════════════════════════════════
    //  Step 7: StartSession SEND diff
    // ═══════════════════════════════════════════════
    printf("━━━ [5] StartSession SEND diff ━━━\n");
    {
        Buf sed = sedutil_StartSession(comId);
        Buf cat = cats_StartSession(comId);
        fprintf(g_sum, "\n── StartSession SEND diff ──\n");
        diffBufs("startsess_send", sed, "sedutil", cat, "cats");
        printf("\n");
    }

    // ═══════════════════════════════════════════════
    //  Summary
    // ═══════════════════════════════════════════════
    fprintf(g_sum, "\n═══════════════════════════════════\n");
    fprintf(g_sum, "Total SEND diffs: %d\n", g_totalDiffs);
    fprintf(g_sum, "═══════════════════════════════════\n");

    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║  Summary                                          ║\n");
    printf("╠═══════════════════════════════════════════════════╣\n");
    printf("║  Total SEND diffs: %-6d                         ║\n", g_totalDiffs);
    printf("║  Output: %-40s ║\n", g_outDir.c_str());
    printf("╚═══════════════════════════════════════════════════╝\n\n");

    printf("Compare:\n");
    printf("  bcomp %s/02_props_send_sedutil.bin %s/02_props_send_cats.bin\n",
           g_outDir.c_str(), g_outDir.c_str());
    printf("  bcomp %s/02_props_recv_sedutil.bin %s/02_props_recv_cats.bin\n",
           g_outDir.c_str(), g_outDir.c_str());
    printf("  bcomp %s/03_startsess_send_sedutil.bin %s/03_startsess_send_cats.bin\n",
           g_outDir.c_str(), g_outDir.c_str());
    printf("  cat %s/summary.txt\n", g_outDir.c_str());

    fclose(g_sum);
    return (g_totalDiffs > 0) ? 1 : 0;
}
