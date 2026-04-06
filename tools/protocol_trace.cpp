/// @file protocol_trace.cpp
/// @brief sedutil vs cats(libsed) 동일 시나리오 실행 + ioctl 버퍼 덤프 비교 도구
///
/// Usage:
///   sudo ./protocol_trace <device> --mode sedutil [--outdir <dir>]
///   sudo ./protocol_trace <device> --mode cats    [--outdir <dir>]
///   sudo ./protocol_trace <device> --mode both    [--outdir <dir>]
///   sudo ./protocol_trace <device>                [--outdir <dir>]   ← default: both
///
/// 각 모드에서 Discovery → StackReset → Properties → StartSession을
/// 실제 디바이스에 전송하고, send/recv 버퍼를 .bin 파일 + hex dump로 출력.
/// --mode both 이면 양쪽을 순차 실행 후 diff까지 수행.

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

enum class Mode { Sedutil, Cats, Both };

// ═══════════════════════════════════════════════════════
//  Globals & Helpers
// ═══════════════════════════════════════════════════════

static std::string g_outDir = "./trace_output";
static FILE* g_sum = nullptr;
static int g_totalDiffs = 0;

static void saveBin(const char* name, const uint8_t* data, size_t len) {
    std::string path = g_outDir + "/" + name;
    FILE* f = fopen(path.c_str(), "wb");
    if (f) { fwrite(data, 1, len, f); fclose(f); }
    printf("  -> %s (%zu bytes)\n", name, len);
}
static void saveBin(const char* name, const Buf& b) { saveBin(name, b.data(), b.size()); }

static void hexdump(const char* label, const uint8_t* data, size_t len, size_t maxLines = 8) {
    printf("  [%s] %zu bytes:\n", label, len);
    size_t lines = std::min((len + 15) / 16, maxLines);
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

// ── StackReset ──

static bool doStackReset(std::shared_ptr<ITransport> transport, uint16_t comId) {
    Buf req(512, 0);
    Endian::writeBe16(req.data(), comId);
    Endian::writeBe32(req.data() + 4, 2);
    auto r = transport->ifSend(0x02, comId, ByteSpan(req.data(), req.size()));
    if (r.failed()) return false;

    for (int i = 0; i < 20; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        Buf vreq(512, 0);
        Endian::writeBe16(vreq.data(), comId);
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
        if (buf.size() >= 20) {
            uint32_t cpLen = Endian::readBe32(buf.data() + 16);
            if (cpLen > 0) return Buf(buf.begin(), buf.end());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return {};
}

// ── Method status 추출 (TCG: ... F9 F0 status 00 00 F1) ──

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
    // TCG method status format: F9(EndOfData) F0(StartList) status 00 00 F1(EndList)
    if (recv.size() < 62) return 0xFF;
    for (size_t i = 56; i + 5 < recv.size(); i++) {
        if (recv[i] == 0xF9 && recv[i+1] == 0xF0 && recv[i+4] == 0x00 && recv[i+5] == 0xF1) {
            return recv[i+2];
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
    // sedutil wraps with STARTNAME uint(0) STARTLIST ... ENDLIST ENDNAME
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxComPacketSize");
    cmd.addToken((uint64_t)2048); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxPacketSize");
    cmd.addToken((uint64_t)2028); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxIndTokenSize");
    cmd.addToken((uint64_t)1992); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxPackets");
    cmd.addToken((uint64_t)1); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxSubpackets");
    cmd.addToken((uint64_t)1); cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME); cmd.addToken("MaxMethods");
    cmd.addToken((uint64_t)1); cmd.addToken(OPAL_TOKEN::ENDNAME);

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
    cmd.addToken((uint64_t)105);
    cmd.addToken(OPAL_UID::OPAL_ADMINSP_UID);
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);
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

// ── 단일 모드 실행: Properties + StartSession ──

static void runSingle(const char* tag,
                       std::shared_ptr<ITransport> transport, uint16_t comId,
                       Buf (*buildProps)(uint16_t),
                       Buf (*buildSS)(uint16_t),
                       Buf* outPropsSend = nullptr, Buf* outSSSend = nullptr) {
    // Properties
    printf("━━━ Properties — %s ━━━\n", tag);
    doStackReset(transport, comId);
    printf("  StackReset OK\n");

    Buf propsPkt = buildProps(comId);
    char fname[128];
    snprintf(fname, sizeof(fname), "02_props_send_%s.bin", tag);
    saveBin(fname, propsPkt);
    hexdump("SEND", propsPkt.data(), std::min(propsPkt.size(), (size_t)128));

    auto sr = runScenario(transport, comId, propsPkt);
    if (sr.recvOk) {
        snprintf(fname, sizeof(fname), "02_props_recv_%s.bin", tag);
        saveBin(fname, sr.recvBuf);
        hexdump("RECV", sr.recvBuf.data(), std::min(sr.recvBuf.size(), (size_t)128));
    }
    printf("  Result: status=0x%02X (%s)\n\n", sr.status, statusName(sr.status));
    fprintf(g_sum, "Properties %s: status=0x%02X (%s)\n", tag, sr.status, statusName(sr.status));
    if (outPropsSend) *outPropsSend = propsPkt;

    // StartSession
    printf("━━━ StartSession — %s ━━━\n", tag);
    doStackReset(transport, comId);

    Buf ssPkt = buildSS(comId);
    snprintf(fname, sizeof(fname), "03_startsess_send_%s.bin", tag);
    saveBin(fname, ssPkt);
    hexdump("SEND", ssPkt.data(), std::min(ssPkt.size(), (size_t)128));

    sr = runScenario(transport, comId, ssPkt);
    if (sr.recvOk) {
        snprintf(fname, sizeof(fname), "03_startsess_recv_%s.bin", tag);
        saveBin(fname, sr.recvBuf);
        hexdump("RECV", sr.recvBuf.data(), std::min(sr.recvBuf.size(), (size_t)128));
    }
    printf("  Result: status=0x%02X (%s)\n\n", sr.status, statusName(sr.status));
    fprintf(g_sum, "StartSession %s: status=0x%02X (%s)\n", tag, sr.status, statusName(sr.status));
    if (outSSSend) *outSSSend = ssPkt;

    // CloseSession (StackReset to clean up)
    doStackReset(transport, comId);
}

// ═══════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <device> [--mode sedutil|cats|both] [--outdir <dir>]\n\n"
            "Runs TCG query flow scenarios and dumps all ioctl buffers.\n\n"
            "Modes:\n"
            "  sedutil  — Run using sedutil(DtaCommand) packets only\n"
            "  cats     — Run using cats(libsed) packets only\n"
            "  both     — Run both and diff (default)\n\n"
            "Examples:\n"
            "  sudo %s /dev/nvme0 --mode sedutil\n"
            "  sudo %s /dev/nvme0 --mode cats\n"
            "  sudo %s /dev/nvme0 --mode both --outdir ./trace\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    std::string device = argv[1];
    Mode mode = Mode::Both;
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--outdir" && i+1 < argc)
            g_outDir = argv[++i];
        else if (std::string(argv[i]) == "--mode" && i+1 < argc) {
            std::string m = argv[++i];
            if (m == "sedutil") mode = Mode::Sedutil;
            else if (m == "cats") mode = Mode::Cats;
            else if (m == "both") mode = Mode::Both;
            else { fprintf(stderr, "Unknown mode: %s\n", m.c_str()); return 1; }
        }
    }
    mkdir(g_outDir.c_str(), 0755);

    std::string sumPath = g_outDir + "/summary.txt";
    g_sum = fopen(sumPath.c_str(), "w");
    if (!g_sum) { fprintf(stderr, "Cannot create %s\n", sumPath.c_str()); return 1; }

    const char* modeStr = (mode == Mode::Sedutil) ? "sedutil"
                        : (mode == Mode::Cats) ? "cats" : "both";
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║  protocol_trace — mode: %-25s  ║\n", modeStr);
    printf("╚═══════════════════════════════════════════════════╝\n");
    printf("Device: %s   Output: %s/\n\n", device.c_str(), g_outDir.c_str());
    fprintf(g_sum, "# protocol_trace — %s — mode: %s\n\n", device.c_str(), modeStr);

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        fprintf(stderr, "ERROR: Cannot open %s\n", device.c_str());
        return 1;
    }

    // Discovery (공통)
    printf("━━━ Discovery ━━━\n");
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) { fprintf(stderr, "Discovery FAILED\n"); return 1; }
    DiscoveryInfo info = disc.buildInfo();
    uint16_t comId = info.baseComId;
    printf("  ComID=0x%04X  SSC=%s\n\n", comId, sscName(info.primarySsc));
    fprintf(g_sum, "ComID=0x%04X  SSC=%s\n\n", comId, sscName(info.primarySsc));
    if (comId == 0) { fprintf(stderr, "No valid ComID\n"); return 1; }

    Buf sedPropsSend, sedSSSend, catPropsSend, catSSSend;

    if (mode == Mode::Sedutil || mode == Mode::Both) {
        runSingle("sedutil", transport, comId,
                  sedutil_Properties, sedutil_StartSession,
                  &sedPropsSend, &sedSSSend);
    }

    if (mode == Mode::Cats || mode == Mode::Both) {
        runSingle("cats", transport, comId,
                  cats_Properties, cats_StartSession,
                  &catPropsSend, &catSSSend);
    }

    // Diff (both 모드에서만)
    if (mode == Mode::Both) {
        printf("━━━ SEND Packet Diff ━━━\n");
        fprintf(g_sum, "\n── Properties SEND diff ──\n");
        diffBufs("props_send", sedPropsSend, "sedutil", catPropsSend, "cats");
        printf("\n");
        fprintf(g_sum, "\n── StartSession SEND diff ──\n");
        diffBufs("startsess_send", sedSSSend, "sedutil", catSSSend, "cats");
        printf("\n");
    }

    // Summary
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║  Done.  Output: %-33s ║\n", g_outDir.c_str());
    if (mode == Mode::Both)
        printf("║  SEND diffs: %-6d                               ║\n", g_totalDiffs);
    printf("╚═══════════════════════════════════════════════════╝\n");

    fclose(g_sum);
    return (mode == Mode::Both && g_totalDiffs > 0) ? 1 : 0;
}
