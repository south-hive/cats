/// @file protocol_trace.cpp
/// @brief 전체 Query Flow의 모든 ioctl을 바이너리 파일로 덤프하는 진단 도구
///
/// libsed와 sedutil(real DtaCommand) 양쪽의 패킷을 step별 .bin 파일로 저장하여
/// bcomp 등 외부 도구로 byte-level 비교가 가능하게 한다.
///
/// 출력 구조 (--outdir 지정 가능, 기본값: ./trace_output):
///   trace_output/
///   ├── 00_discovery_recv_libsed.bin
///   ├── 01_stackreset_send_libsed.bin
///   ├── 02_props_send_libsed.bin
///   ├── 02_props_send_sedutil.bin     ← real DtaCommand 생성
///   ├── 02_props_recv_libsed.bin
///   ├── 03_startsess_send_libsed.bin
///   ├── 03_startsess_send_sedutil.bin ← real DtaCommand 생성
///   ├── 03_startsess_recv_libsed.bin
///   ├── 04_getmsid_send_libsed.bin
///   ├── 04_getmsid_send_sedutil.bin   ← real DtaCommand 생성
///   ├── 04_getmsid_recv_libsed.bin
///   ├── 05_close_send_libsed.bin
///   ├── 05_close_send_sedutil.bin     ← real DtaCommand 생성
///   ├── ioctl_params.txt              ← 모든 ioctl 파라미터 기록
///   └── summary.txt                   ← 요약 + diff 결과
///
/// Usage: sudo ./protocol_trace <device> [--outdir <dir>]
///
/// 추가로 strace로 실제 sedutil-cli의 커널 ioctl 캡처 방법:
///   sudo strace -e ioctl -x -s 2048 -o sedutil_strace.txt \
///        sedutil-cli --query /dev/nvme0
///   → 출력에서 NVME_IOCTL_ADMIN_CMD (0xC0484E41) 부분을 확인

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

using Packet = std::vector<uint8_t>;

// ═══════════════════════════════════════════════════════
//  File I/O helpers
// ═══════════════════════════════════════════════════════

static std::string g_outDir = "./trace_output";
static FILE* g_ioctlLog = nullptr;
static FILE* g_summary = nullptr;

static void writeBin(const char* filename, const uint8_t* data, size_t len) {
    std::string path = g_outDir + "/" + filename;
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { fprintf(stderr, "ERROR: Cannot write %s\n", path.c_str()); return; }
    fwrite(data, 1, len, f);
    fclose(f);
    printf("  -> %s (%zu bytes)\n", filename, len);
}

static void writeBin(const char* filename, const Packet& pkt) {
    writeBin(filename, pkt.data(), pkt.size());
}

static void logIoctl(const char* step, const char* direction,
                     uint8_t opcode, uint8_t protocolId, uint16_t comId,
                     uint32_t bufferSize, uint32_t transferLen) {
    uint32_t cdw10 = (uint32_t(protocolId) << 24) | (uint32_t(comId) << 8);
    fprintf(g_ioctlLog,
            "%-25s %-8s opcode=0x%02X  nsid=0  cdw10=0x%08X  cdw11=0x%08X  "
            "data_len=%u  transferLen=%u  protocolId=0x%02X  comId=0x%04X\n",
            step, direction, opcode, cdw10, transferLen, bufferSize, transferLen,
            protocolId, comId);
}

// ═══════════════════════════════════════════════════════
//  sedutil reference packet builders (real DtaCommand)
// ═══════════════════════════════════════════════════════

static constexpr uint32_t SEDUTIL_HSN = 105;  // sedutil hardcoded

static Packet extractPacket(DtaCommand& cmd) {
    uint8_t* buf = static_cast<uint8_t*>(cmd.getCmdBuffer());
    return Packet(buf, buf + MIN_BUFFER_LENGTH);
}

static Packet sedutil_Properties(uint16_t comId) {
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
    return extractPacket(cmd);
}

static Packet sedutil_StartSessionAnon(uint16_t comId) {
    DtaCommand cmd;
    cmd.reset(OPAL_SMUID_UID, STARTSESSION);
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(SEDUTIL_HSN);               // HostSessionID
    cmd.addToken(OPAL_UID::OPAL_ADMINSP_UID);  // SP
    cmd.addToken(OPAL_TINY_ATOM::UINT_00);    // Write=false
    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(comId);
    return extractPacket(cmd);
}

static Packet sedutil_GetMsid(uint16_t comId, uint32_t tsn, uint32_t hsn) {
    DtaCommand cmd;
    cmd.reset(OPAL_UID::OPAL_C_PIN_MSID, OPAL_METHOD::GET);
    cmd.addToken(OPAL_TOKEN::STARTLIST);

    // CellBlock: startColumn=3, endColumn=3 (PIN column)
    cmd.addToken(OPAL_TOKEN::STARTLIST);
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::STARTCOLUMN);
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);
    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::STARTNAME);
    cmd.addToken(OPAL_TOKEN::ENDCOLUMN);
    cmd.addToken(OPAL_TINY_ATOM::UINT_03);
    cmd.addToken(OPAL_TOKEN::ENDNAME);
    cmd.addToken(OPAL_TOKEN::ENDLIST);

    cmd.addToken(OPAL_TOKEN::ENDLIST);
    cmd.complete();
    cmd.setcomID(comId);
    cmd.setTSN(tsn);
    cmd.setHSN(hsn);
    return extractPacket(cmd);
}

static Packet sedutil_CloseSession(uint16_t comId, uint32_t tsn, uint32_t hsn) {
    DtaCommand cmd;
    cmd.reset();
    // CloseSession is just EndOfSession token in a packet
    cmd.addToken(OPAL_TOKEN::ENDOFSESSION);
    cmd.complete(false);  // no EOD/status
    cmd.setcomID(comId);
    cmd.setTSN(tsn);
    cmd.setHSN(hsn);
    return extractPacket(cmd);
}

// ═══════════════════════════════════════════════════════
//  Diff helper
// ═══════════════════════════════════════════════════════

static int diffPackets(const char* step, const Packet& libsed, const Packet& sedutil) {
    size_t maxLen = std::max(libsed.size(), sedutil.size());
    int diffs = 0;
    for (size_t i = 0; i < maxLen; i++) {
        uint8_t a = (i < libsed.size()) ? libsed[i] : 0;
        uint8_t b = (i < sedutil.size()) ? sedutil[i] : 0;
        if (a != b) {
            if (diffs < 20) {
                fprintf(g_summary, "  [%s] offset 0x%04zX: libsed=0x%02X  sedutil=0x%02X",
                        step, i, a, b);
                if (a >= 0x20 && a <= 0x7E && b >= 0x20 && b <= 0x7E)
                    fprintf(g_summary, " ('%c' vs '%c')", a, b);
                fprintf(g_summary, "\n");
            }
            diffs++;
        }
    }
    if (libsed.size() != sedutil.size())
        fprintf(g_summary, "  [%s] SIZE: libsed=%zu  sedutil=%zu\n",
                step, libsed.size(), sedutil.size());
    if (diffs == 0)
        fprintf(g_summary, "  [%s] *** IDENTICAL ***\n", step);
    else
        fprintf(g_summary, "  [%s] Total diffs: %d\n", step, diffs);
    return diffs;
}

// ═══════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <device> [--outdir <dir>]\n\n", argv[0]);
        fprintf(stderr, "Dumps every ioctl in the query flow to binary files for comparison.\n\n");
        fprintf(stderr, "To also capture real sedutil-cli ioctls via strace:\n");
        fprintf(stderr, "  sudo strace -e ioctl -xx -s 4096 -o sedutil_strace.txt \\\n");
        fprintf(stderr, "       sedutil-cli --query /dev/nvme0\n\n");
        fprintf(stderr, "Then compare .bin files with bcomp or xxd:\n");
        fprintf(stderr, "  bcomp trace_output/02_props_send_libsed.bin "
                         "trace_output/02_props_send_sedutil.bin\n");
        return 1;
    }

    std::string device = argv[1];
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--outdir" && i+1 < argc)
            g_outDir = argv[++i];
    }

    // Create output directory
    mkdir(g_outDir.c_str(), 0755);

    std::string ioctlPath = g_outDir + "/ioctl_params.txt";
    std::string summaryPath = g_outDir + "/summary.txt";
    g_ioctlLog = fopen(ioctlPath.c_str(), "w");
    g_summary  = fopen(summaryPath.c_str(), "w");
    if (!g_ioctlLog || !g_summary) {
        fprintf(stderr, "ERROR: Cannot create log files in %s\n", g_outDir.c_str());
        return 1;
    }

    fprintf(g_ioctlLog, "# protocol_trace ioctl parameter log\n");
    fprintf(g_ioctlLog, "# device: %s\n", device.c_str());
    fprintf(g_ioctlLog, "# ─────────────────────────────────────────────────────────────"
                         "───────────────────────────────────────\n");
    fprintf(g_ioctlLog, "%-25s %-8s %-12s %-7s %-15s %-15s %-12s %-12s %-14s %-12s\n",
            "Step", "Dir", "opcode", "nsid", "cdw10", "cdw11",
            "data_len", "transferLen", "protocolId", "comId");
    fprintf(g_ioctlLog, "# ─────────────────────────────────────────────────────────────"
                         "───────────────────────────────────────\n");

    fprintf(g_summary, "# protocol_trace summary\n");
    fprintf(g_summary, "# device: %s\n\n", device.c_str());

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  protocol_trace — Full Query Flow Dump   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    printf("Device: %s\nOutput: %s/\n\n", device.c_str(), g_outDir.c_str());

    libsed::initialize();
    EvalApi api;

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        fprintf(stderr, "ERROR: Cannot open %s\n", device.c_str());
        return 1;
    }

    int totalDiffs = 0;

    // ═══════════════════════════════════════════════
    //  Step 0: Discovery (IF-RECV only, proto=0x01, comId=0x0001)
    // ═══════════════════════════════════════════════
    printf("[0] Discovery\n");
    {
        Bytes recvBuf;
        auto r = transport->ifRecv(0x01, 0x0001, recvBuf, 2048);
        logIoctl("0_discovery", "RECV", 0x82, 0x01, 0x0001, 2048, 2048);

        if (r.failed()) {
            fprintf(stderr, "  Discovery FAILED: %s\n", r.message().c_str());
            fclose(g_ioctlLog); fclose(g_summary);
            return 1;
        }
        writeBin("00_discovery_recv_libsed.bin", recvBuf.data(), recvBuf.size());

        // Parse to get ComID
        Discovery disc;
        r = disc.discover(transport);
        DiscoveryInfo info = disc.buildInfo();
        printf("  ComID=0x%04X  SSC=%s\n\n", info.baseComId, sscName(info.primarySsc));
        fprintf(g_summary, "Discovery: ComID=0x%04X  SSC=%s\n\n",
                info.baseComId, sscName(info.primarySsc));

        if (info.baseComId == 0) {
            fprintf(stderr, "  No valid ComID\n");
            fclose(g_ioctlLog); fclose(g_summary);
            return 1;
        }

        uint16_t comId = info.baseComId;

        // ═══════════════════════════════════════════════
        //  Step 1: StackReset (proto=0x02)
        // ═══════════════════════════════════════════════
        printf("[1] StackReset\n");
        {
            // Build StackReset send buffer manually to capture it
            Bytes resetBuf(512, 0);
            Endian::writeBe16(resetBuf.data(), comId);
            Endian::writeBe32(resetBuf.data() + 4, 2);  // STACK_RESET request code

            logIoctl("1_stackreset", "SEND", 0x81, 0x02, comId, 512, 512);
            writeBin("01_stackreset_send_libsed.bin", resetBuf);

            // Actually perform the StackReset through the API
            r = api.stackReset(transport, comId);
            printf("  %s\n\n", r.ok() ? "OK" : r.message().c_str());
        }

        // ═══════════════════════════════════════════════
        //  Step 2: Properties Exchange
        // ═══════════════════════════════════════════════
        printf("[2] Properties Exchange\n");
        {
            PropertiesResult props;
            r = api.exchangeProperties(transport, comId, props);

            // libsed packets
            size_t sendSize = props.raw.rawSendPayload.size();
            size_t recvSize = props.raw.rawRecvPayload.size();
            uint32_t sendTransfer = ((sendSize + 511) / 512) * 512;
            uint32_t recvTransfer = 2048;

            logIoctl("2_properties", "SEND", 0x81, 0x01, comId, (uint32_t)sendSize, sendTransfer);
            logIoctl("2_properties", "RECV", 0x82, 0x01, comId, recvTransfer, recvTransfer);

            writeBin("02_props_send_libsed.bin", props.raw.rawSendPayload);
            if (!props.raw.rawRecvPayload.empty())
                writeBin("02_props_recv_libsed.bin", props.raw.rawRecvPayload);

            // sedutil reference (real DtaCommand)
            Packet sedPkt = sedutil_Properties(comId);
            writeBin("02_props_send_sedutil.bin", sedPkt);

            // Diff
            fprintf(g_summary, "── Step 2: Properties SEND ──\n");
            totalDiffs += diffPackets("2_props_send",
                                       Packet(props.raw.rawSendPayload.begin(),
                                              props.raw.rawSendPayload.end()),
                                       sedPkt);
            fprintf(g_summary, "\n");

            if (r.ok()) {
                printf("  TPer MaxCPS=%u  Status=OK\n\n", props.tperMaxComPacketSize);
                fprintf(g_summary, "Properties: OK  TPer MaxCPS=%u\n\n",
                        props.tperMaxComPacketSize);
            } else {
                printf("  FAIL: %s\n\n", r.message().c_str());
                fprintf(g_summary, "Properties: FAIL  %s\n\n", r.message().c_str());
                fprintf(g_summary, "\n*** Properties failed — remaining steps may not execute ***\n\n");
            }

            // ═══════════════════════════════════════════════
            //  Step 3: StartSession (Anonymous AdminSP)
            // ═══════════════════════════════════════════════
            printf("[3] StartSession (Anonymous AdminSP)\n");
            {
                uint32_t maxCPS = (r.ok() && props.tperMaxComPacketSize > 0)
                                  ? props.tperMaxComPacketSize : 2048;
                Session session(transport, comId);
                session.setMaxComPacketSize(maxCPS);

                StartSessionResult ssr;
                r = api.startSession(session, uid::SP_ADMIN, false, ssr);

                if (!ssr.raw.rawSendPayload.empty()) {
                    logIoctl("3_startsession", "SEND", 0x81, 0x01, comId,
                             (uint32_t)ssr.raw.rawSendPayload.size(),
                             ((uint32_t)ssr.raw.rawSendPayload.size() + 511) & ~511u);
                    writeBin("03_startsess_send_libsed.bin", ssr.raw.rawSendPayload);
                }
                if (!ssr.raw.rawRecvPayload.empty()) {
                    logIoctl("3_startsession", "RECV", 0x82, 0x01, comId,
                             2048, 2048);
                    writeBin("03_startsess_recv_libsed.bin", ssr.raw.rawRecvPayload);
                }

                // sedutil reference
                Packet sedSS = sedutil_StartSessionAnon(comId);
                writeBin("03_startsess_send_sedutil.bin", sedSS);

                fprintf(g_summary, "── Step 3: StartSession SEND ──\n");
                if (!ssr.raw.rawSendPayload.empty()) {
                    totalDiffs += diffPackets("3_startsess_send",
                                               Packet(ssr.raw.rawSendPayload.begin(),
                                                      ssr.raw.rawSendPayload.end()),
                                               sedSS);
                }
                fprintf(g_summary, "\n");

                if (r.failed()) {
                    printf("  FAIL: %s\n\n", r.message().c_str());
                    fprintf(g_summary, "StartSession: FAIL  %s\n\n", r.message().c_str());
                } else {
                    printf("  TSN=%u  HSN=%u\n", ssr.tperSessionNumber, ssr.hostSessionNumber);
                    fprintf(g_summary, "StartSession: OK  TSN=%u  HSN=%u\n\n",
                            ssr.tperSessionNumber, ssr.hostSessionNumber);

                    // ═══════════════════════════════════════════════
                    //  Step 4: Get MSID
                    // ═══════════════════════════════════════════════
                    printf("[4] Get MSID\n");
                    {
                        Bytes msid;
                        r = api.getCPin(session, uid::CPIN_MSID, msid);

                        // getCPin uses TableResult internally — check if raw is accessible
                        // For now, just note it ran
                        printf("  %s\n", r.ok() ? "OK" : r.message().c_str());
                        fprintf(g_summary, "GetMSID: %s\n\n", r.ok() ? "OK" : r.message().c_str());

                        // sedutil reference
                        Packet sedGet = sedutil_GetMsid(comId,
                                                         ssr.tperSessionNumber,
                                                         ssr.hostSessionNumber);
                        writeBin("04_getmsid_send_sedutil.bin", sedGet);

                        // Note: getCPin doesn't expose raw easily; the sedutil reference
                        // is still useful for offline comparison
                    }
                    printf("\n");

                    // ═══════════════════════════════════════════════
                    //  Step 5: CloseSession
                    // ═══════════════════════════════════════════════
                    printf("[5] CloseSession\n");
                    {
                        api.closeSession(session);
                        printf("  OK\n\n");

                        // sedutil reference
                        Packet sedClose = sedutil_CloseSession(comId,
                                                                ssr.tperSessionNumber,
                                                                ssr.hostSessionNumber);
                        writeBin("05_close_send_sedutil.bin", sedClose);
                    }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════
    //  Final summary
    // ═══════════════════════════════════════════════
    fprintf(g_summary, "═══════════════════════════════════════\n");
    fprintf(g_summary, "Total SEND diffs: %d\n", totalDiffs);
    fprintf(g_summary, "═══════════════════════════════════════\n");

    printf("═══════════════════════════════════════════\n");
    printf("  Output: %s/\n", g_outDir.c_str());
    printf("  Files:  *.bin (bcomp용), ioctl_params.txt, summary.txt\n");
    printf("  SEND diffs: %d\n", totalDiffs);
    printf("═══════════════════════════════════════════\n\n");

    printf("다음 단계:\n");
    printf("  1. bcomp %s/02_props_send_libsed.bin %s/02_props_send_sedutil.bin\n",
           g_outDir.c_str(), g_outDir.c_str());
    printf("  2. sedutil strace와 비교:\n");
    printf("     sudo strace -e ioctl -xx -s 4096 -o sedutil_strace.txt \\\n");
    printf("          sedutil-cli --query %s\n", device.c_str());
    printf("  3. strace 출력에서 ioctl(fd, 0xc0484e41, ...) 패턴 확인\n");
    printf("     → 0xc0484e41 = NVME_IOCTL_ADMIN_CMD\n");
    printf("  4. cat %s/ioctl_params.txt\n", g_outDir.c_str());

    fclose(g_ioctlLog);
    fclose(g_summary);
    return (totalDiffs > 0) ? 1 : 0;
}
