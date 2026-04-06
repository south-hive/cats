/// @file props_diag.cpp
/// @brief Properties Invalid Parameter 집중 진단 도구
///
/// 5가지 시나리오로 Properties 실패 원인을 격리합니다:
///   A: Discovery → StackReset 1회 → Properties    (sedutil 동일 플로우)
///   B: Discovery → StackReset 2회 → Properties    (현재 libsed 동작)
///   C: Discovery → StackReset 없이 → Properties   (Reset 필요성 확인)
///   D: Discovery → StackReset 1회 → 100ms → Properties  (타이밍)
///   E: sedutil-cli 실행 후 → StackReset 1회 → Properties
///
/// 모든 ioctl을 IoctlTracer로 추적: 타이밍, 파라미터, 버퍼, 결과.
///
/// Usage: sudo ./props_diag <device> [--outdir <dir>] [--scenario A|B|C|D|E|ALL]
///
/// 핵심 가설: exchangeProperties()가 내부에서 stackReset()을 호출하므로,
/// query_flow의 명시적 stackReset()과 합쳐 2회 연속 Reset이 발생.
/// sedutil은 1회만 수행.

#include <libsed/sed_library.h>
#include <libsed/transport/i_transport.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/endian.h>
#include <libsed/core/uid.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <sys/stat.h>

using namespace libsed;
using Clock = std::chrono::steady_clock;

// ═══════════════════════════════════════════════════════
//  TraceEntry — 단일 ioctl 호출 기록
// ═══════════════════════════════════════════════════════

struct TraceEntry {
    uint32_t    seq;
    enum Dir { SEND, RECV } dir;
    uint8_t     protocolId;
    uint16_t    comId;
    uint32_t    cdw10;
    uint32_t    cdw11;
    size_t      payloadSize;    // 원본 크기
    size_t      transferLen;    // 512-aligned 크기
    uintptr_t   bufAddr;        // 버퍼 주소
    size_t      bufAlign;       // 버퍼 정렬 (lowest set bit)
    bool        ok;             // inner 호출 성공?
    int         savedErrno;     // errno after call
    double      timeMs;         // 시나리오 시작부터 경과 ms
    Bytes       snapshot;       // 버퍼 전체 복사
    const char* label;

    // proto=0x02 RECV
    uint32_t    comIdState;     // offset 12: 0=Issued, 1=Associated, 2=StackResetInProgress
    // proto=0x01 RECV
    uint32_t    comPktLen;      // ComPacket.length at offset 16
    uint8_t     methodStatus;   // 0x00=OK, 0x0C=InvalidParam, etc.
    bool        hasStatus;
};

// ═══════════════════════════════════════════════════════
//  IoctlTracer — ITransport 데코레이터
// ═══════════════════════════════════════════════════════

class IoctlTracer : public ITransport {
public:
    IoctlTracer(std::shared_ptr<ITransport> inner, const std::string& outDir)
        : inner_(std::move(inner)), outDir_(outDir) { reset(""); }

    using ITransport::ifRecv;  // expose convenience overload

    void reset(const char* scenarioTag) {
        tag_ = scenarioTag;
        trace_.clear();
        seq_ = 0;
        epoch_ = Clock::now();
    }

    const std::vector<TraceEntry>& trace() const { return trace_; }

    // ── ITransport ──

    Result ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) override {
        TraceEntry e = {};
        e.seq = ++seq_;
        e.dir = TraceEntry::SEND;
        e.protocolId = protocolId;
        e.comId = comId;
        e.payloadSize = payload.size();
        e.transferLen = ((payload.size() + 511) / 512) * 512;
        e.cdw10 = (uint32_t(protocolId) << 24) | (uint32_t(comId) << 8);
        e.cdw11 = (uint32_t)e.transferLen;
        e.bufAddr = (uintptr_t)payload.data();
        e.bufAlign = e.bufAddr ? (e.bufAddr & (-(intptr_t)e.bufAddr)) : 0;
        e.timeMs = elapsed();
        e.snapshot.assign(payload.data(), payload.data() + payload.size());
        e.label = labelFor(protocolId, comId, TraceEntry::SEND, payload);
        e.comIdState = 0; e.comPktLen = 0; e.methodStatus = 0; e.hasStatus = false;

        errno = 0;
        auto r = inner_->ifSend(protocolId, comId, payload);
        e.savedErrno = errno;
        e.ok = r.ok();

        trace_.push_back(std::move(e));
        return r;
    }

    Result ifRecv(uint8_t protocolId, uint16_t comId,
                  MutableByteSpan buffer, size_t& bytesReceived) override {
        TraceEntry e = {};
        e.seq = ++seq_;
        e.dir = TraceEntry::RECV;
        e.protocolId = protocolId;
        e.comId = comId;
        e.payloadSize = buffer.size();
        e.transferLen = ((buffer.size() + 511) / 512) * 512;
        e.cdw10 = (uint32_t(protocolId) << 24) | (uint32_t(comId) << 8);
        e.cdw11 = (uint32_t)e.transferLen;
        e.bufAddr = (uintptr_t)buffer.data();
        e.bufAlign = e.bufAddr ? (e.bufAddr & (-(intptr_t)e.bufAddr)) : 0;
        e.timeMs = elapsed();
        e.label = "";
        e.comIdState = 0; e.comPktLen = 0; e.methodStatus = 0; e.hasStatus = false;

        errno = 0;
        auto r = inner_->ifRecv(protocolId, comId, buffer, bytesReceived);
        e.savedErrno = errno;
        e.ok = r.ok();

        // 버퍼 스냅샷
        e.snapshot.assign(buffer.data(), buffer.data() + std::min(bytesReceived, buffer.size()));

        // proto=0x02 RECV: ComID state
        if (protocolId == 0x02 && bytesReceived >= 16) {
            e.comIdState = Endian::readBe32(buffer.data() + 12);
            e.label = "VERIFY_COMID response";
        }

        // proto=0x01 RECV: ComPacket.length + method status
        if (protocolId == 0x01 && bytesReceived >= 20) {
            e.comPktLen = Endian::readBe32(buffer.data() + 16);
            if (e.comPktLen > 0) {
                e.label = "Properties response";
                // Parse method status: search for EOD (0xF9) + STARTLIST + status bytes
                if (bytesReceived >= 56) {
                    uint32_t subPktLen = 0;
                    if (bytesReceived >= 56)
                        subPktLen = Endian::readBe32(buffer.data() + 52);
                    size_t tokenStart = 56;
                    size_t tokenEnd = tokenStart + subPktLen;
                    if (tokenEnd > bytesReceived) tokenEnd = bytesReceived;
                    // Find EOD (0xF9) then status in STARTLIST
                    for (size_t i = tokenStart; i + 5 < tokenEnd; i++) {
                        if (buffer.data()[i] == 0xF9 &&
                            buffer.data()[i+1] == 0xF0) {
                            e.methodStatus = buffer.data()[i+2];
                            e.hasStatus = true;
                            break;
                        }
                    }
                }
            } else {
                e.label = "empty response (polling)";
            }
        }

        trace_.push_back(std::move(e));
        return r;
    }

    TransportType type() const override { return inner_->type(); }
    std::string devicePath() const override { return inner_->devicePath(); }
    bool isOpen() const override { return inner_->isOpen(); }
    void close() override { inner_->close(); }

    // ── 출력 ──

    void dumpTrace() const {
        for (auto& e : trace_) {
            printf("  #%03u %s proto=0x%02X comId=0x%04X cdw10=0x%08X cdw11=0x%08X "
                   "len=%zu xfer=%zu align=%zu t=%.1fms\n",
                   e.seq, e.dir == TraceEntry::SEND ? "SEND" : "RECV",
                   e.protocolId, e.comId, e.cdw10, e.cdw11,
                   e.payloadSize, e.transferLen, e.bufAlign, e.timeMs);

            printf("       -> %s errno=%d", e.ok ? "OK" : "FAIL", e.savedErrno);

            if (e.dir == TraceEntry::RECV && e.protocolId == 0x02) {
                const char* stateNames[] = {"Issued(idle)", "Associated", "StackResetInProgress"};
                const char* sn = (e.comIdState < 3) ? stateNames[e.comIdState] : "Unknown";
                printf("  state=%u(%s)", e.comIdState, sn);
            }
            if (e.dir == TraceEntry::RECV && e.protocolId == 0x01) {
                printf("  ComPkt.len=%u", e.comPktLen);
                if (e.hasStatus) {
                    printf("  Status=0x%02X(%s)", e.methodStatus,
                           statusName(e.methodStatus));
                }
            }
            if (e.label && e.label[0])
                printf("  [%s]", e.label);
            printf("\n");
        }
    }

    void saveBinFiles() const {
        for (auto& e : trace_) {
            if (e.snapshot.empty()) continue;
            char fname[128];
            snprintf(fname, sizeof(fname), "%s_%03u_%s.bin",
                     tag_, e.seq, e.dir == TraceEntry::SEND ? "send" : "recv");
            std::string path = outDir_ + "/" + fname;
            FILE* f = fopen(path.c_str(), "wb");
            if (f) {
                fwrite(e.snapshot.data(), 1, e.snapshot.size(), f);
                fclose(f);
            }
        }
    }

    // Properties 결과 요약
    int propertiesStatus() const {
        for (auto it = trace_.rbegin(); it != trace_.rend(); ++it) {
            if (it->dir == TraceEntry::RECV && it->protocolId == 0x01 && it->hasStatus)
                return it->methodStatus;
        }
        return -1;  // 응답 없음
    }

private:
    std::shared_ptr<ITransport> inner_;
    std::string outDir_;
    const char* tag_ = "";
    std::vector<TraceEntry> trace_;
    uint32_t seq_ = 0;
    Clock::time_point epoch_;

    double elapsed() const {
        auto now = Clock::now();
        return std::chrono::duration<double, std::milli>(now - epoch_).count();
    }

    static const char* statusName(uint8_t s) {
        switch (s) {
            case 0x00: return "Success";
            case 0x01: return "NotAuthorized";
            case 0x02: return "Obsolete";
            case 0x03: return "SPBusy";
            case 0x04: return "SPFailed";
            case 0x05: return "SPDisabled";
            case 0x06: return "SPFrozen";
            case 0x07: return "NoSessionsAvailable";
            case 0x08: return "UniquenessConflict";
            case 0x09: return "InsufficientSpace";
            case 0x0A: return "InsufficientRows";
            case 0x0C: return "InvalidParameter";
            case 0x0F: return "TPERMalfunction";
            case 0x10: return "TransactionFailure";
            case 0x12: return "AuthorityLockedOut";
            case 0x3F: return "Fail";
            default: return "Unknown";
        }
    }

    static const char* labelFor(uint8_t proto, uint16_t comId,
                                 TraceEntry::Dir dir, ByteSpan payload) {
        if (proto == 0x02) {
            if (payload.size() >= 8) {
                uint32_t reqCode = Endian::readBe32(payload.data() + 4);
                if (reqCode == 2) return "StackReset";
                if (reqCode == 0) return "VERIFY_COMID";
            }
            return "Proto0x02";
        }
        if (proto == 0x01 && dir == TraceEntry::SEND)
            return "Properties IF-SEND";
        return "";
    }

};

// ═══════════════════════════════════════════════════════
//  Helper: StackReset (수동 구현, EvalApi 안 거침)
// ═══════════════════════════════════════════════════════

static bool doStackReset(IoctlTracer& tr, uint16_t comId) {
    // STACK_RESET 전송
    Bytes req(512, 0);
    Endian::writeBe16(req.data(), comId);
    Endian::writeBe32(req.data() + 4, 2);  // RequestCode = STACK_RESET

    auto r = tr.ifSend(0x02, comId, ByteSpan(req.data(), req.size()));
    if (r.failed()) return false;

    // VERIFY_COMID 폴링
    for (int attempt = 0; attempt < 20; attempt++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        Bytes vreq(512, 0);
        Endian::writeBe16(vreq.data(), comId);
        Endian::writeBe32(vreq.data() + 4, 0);  // RequestCode = VERIFY_COMID

        r = tr.ifSend(0x02, comId, ByteSpan(vreq.data(), vreq.size()));
        if (r.failed()) return false;

        Bytes resp;
        r = tr.ifRecv(0x02, comId, resp, 512);
        if (r.failed()) return false;

        if (resp.size() >= 16) {
            uint32_t state = Endian::readBe32(resp.data() + 12);
            if (state == 0) return true;  // Issued(idle)
        }
    }
    return true;  // 타임아웃이어도 진행
}

// ═══════════════════════════════════════════════════════
//  Helper: Properties 전송 + 수신
// ═══════════════════════════════════════════════════════

static int doProperties(IoctlTracer& tr, uint16_t comId) {
    // 패킷 생성
    ParamEncoder::HostProperties hp;
    hp.maxComPacketSize = 2048;
    hp.maxPacketSize    = 2028;
    hp.maxIndTokenSize  = 1992;
    hp.maxPackets       = 1;
    hp.maxSubPackets    = 1;
    hp.maxMethods       = 1;

    Bytes params = ParamEncoder::encodeProperties(hp);
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);

    PacketBuilder pb;
    pb.setComId(comId);
    Bytes packet = pb.buildSessionManagerPacket(methodTokens);

    // IF-SEND
    auto r = tr.ifSend(0x01, comId, ByteSpan(packet.data(), packet.size()));
    if (r.failed()) return -1;

    // IF-RECV 폴링
    for (int attempt = 0; attempt < 20; attempt++) {
        Bytes resp;
        r = tr.ifRecv(0x01, comId, resp, 2048);
        if (r.failed()) return -1;

        if (resp.size() >= 20) {
            uint32_t cpLen = Endian::readBe32(resp.data() + 16);
            if (cpLen > 0) {
                return tr.propertiesStatus();
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return -1;  // 응답 없음
}

// ═══════════════════════════════════════════════════════
//  시나리오 함수들
// ═══════════════════════════════════════════════════════

static int runScenarioA(IoctlTracer& tr, uint16_t comId) {
    // A: StackReset 1회 → Properties (sedutil 동일)
    doStackReset(tr, comId);
    return doProperties(tr, comId);
}

static int runScenarioB(IoctlTracer& tr, uint16_t comId) {
    // B: StackReset 2회 연속 → Properties (현재 libsed 동작)
    doStackReset(tr, comId);
    doStackReset(tr, comId);
    return doProperties(tr, comId);
}

static int runScenarioC(IoctlTracer& tr, uint16_t comId) {
    // C: StackReset 없이 → Properties
    return doProperties(tr, comId);
}

static int runScenarioD(IoctlTracer& tr, uint16_t comId) {
    // D: StackReset 1회 → 100ms 대기 → Properties
    doStackReset(tr, comId);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return doProperties(tr, comId);
}

static int runScenarioE(IoctlTracer& tr, uint16_t comId, const std::string& device) {
    // E: sedutil-cli 실행 후 → StackReset 1회 → Properties
    std::string cmd = "sedutil-cli --query " + device + " > /dev/null 2>&1";
    int rc = system(cmd.c_str());
    printf("  (sedutil-cli exit code: %d)\n", rc);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    doStackReset(tr, comId);
    return doProperties(tr, comId);
}

// ═══════════════════════════════════════════════════════
//  메인
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <device> [--outdir <dir>] [--scenario A|B|C|D|E|ALL]\n\n", argv[0]);
        fprintf(stderr, "Scenarios:\n");
        fprintf(stderr, "  A: StackReset x1 -> Properties     (sedutil equivalent)\n");
        fprintf(stderr, "  B: StackReset x2 -> Properties     (current libsed behavior)\n");
        fprintf(stderr, "  C: No StackReset -> Properties      (reset necessity test)\n");
        fprintf(stderr, "  D: StackReset x1 -> 100ms -> Props  (timing test)\n");
        fprintf(stderr, "  E: sedutil-cli -> Reset -> Props    (after sedutil success)\n");
        fprintf(stderr, "  ALL: Run all scenarios (default)\n");
        return 1;
    }

    std::string device = argv[1];
    std::string outDir = "./props_diag_output";
    std::string scenario = "ALL";

    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--outdir" && i+1 < argc) outDir = argv[++i];
        if (std::string(argv[i]) == "--scenario" && i+1 < argc) scenario = argv[++i];
    }

    mkdir(outDir.c_str(), 0755);

    libsed::initialize();

    // ── Transport ──
    auto rawTransport = TransportFactory::createNvme(device);
    if (!rawTransport || !rawTransport->isOpen()) {
        fprintf(stderr, "ERROR: Cannot open %s\n", device.c_str());
        return 1;
    }

    // ── Discovery (untraced) ──
    printf("Discovery on %s...\n", device.c_str());
    eval::EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(rawTransport, info);
    if (r.failed() || info.baseComId == 0) {
        fprintf(stderr, "ERROR: Discovery failed\n");
        return 1;
    }
    uint16_t comId = info.baseComId;
    printf("  ComID=0x%04X  SSC=%s\n\n", comId, eval::sscName(info.primarySsc));

    // ── Tracer ──
    auto tracer = std::make_shared<IoctlTracer>(rawTransport, outDir);

    // ── 시나리오 실행 ──
    struct ScenarioDef {
        const char* id;
        const char* name;
        std::function<int()> run;
    };

    std::vector<ScenarioDef> scenarios = {
        {"A", "Single StackReset -> Properties (sedutil equivalent)",
         [&]() { return runScenarioA(*tracer, comId); }},
        {"B", "Double StackReset -> Properties (current libsed behavior)",
         [&]() { return runScenarioB(*tracer, comId); }},
        {"C", "No StackReset -> Properties",
         [&]() { return runScenarioC(*tracer, comId); }},
        {"D", "Single StackReset -> 100ms delay -> Properties",
         [&]() { return runScenarioD(*tracer, comId); }},
        {"E", "After sedutil-cli -> StackReset -> Properties",
         [&]() { return runScenarioE(*tracer, comId, device); }},
    };

    int passCount = 0, failCount = 0;
    std::vector<std::pair<std::string, int>> results;

    for (auto& s : scenarios) {
        if (scenario != "ALL" && scenario != s.id) continue;

        printf("================================================================\n");
        printf("=== Scenario %s: %s ===\n", s.id, s.name);
        printf("================================================================\n");

        // 시나리오 간 ComID 리셋 (untraced)
        api.stackReset(rawTransport, comId);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        tracer->reset(s.id);
        int status = s.run();

        printf("\n  ── Trace ──\n");
        tracer->dumpTrace();
        tracer->saveBinFiles();

        const char* resultStr;
        if (status == 0x00) {
            resultStr = "OK";
            passCount++;
        } else if (status < 0) {
            resultStr = "NO RESPONSE";
            failCount++;
        } else {
            resultStr = "FAIL";
            failCount++;
        }

        printf("\n  RESULT: Properties %s", resultStr);
        if (status > 0)
            printf(" (Status=0x%02X %s)", status,
                   status == 0x0C ? "Invalid Parameter" : "Error");
        printf("\n\n");

        results.push_back({s.id, status});
    }

    // ── 요약 ──
    printf("================================================================\n");
    printf("=== SUMMARY ===\n");
    printf("================================================================\n");
    for (auto& [id, st] : results) {
        printf("  Scenario %s: %s", id.c_str(),
               st == 0 ? "OK" : (st < 0 ? "NO RESPONSE" : "FAIL"));
        if (st > 0) printf(" (0x%02X)", st);
        printf("\n");
    }
    printf("\n  Pass: %d  Fail: %d\n", passCount, failCount);

    // ── 진단 힌트 ──
    // A 성공 + B 실패 = Double StackReset이 원인
    int statusA = -999, statusB = -999;
    for (auto& [id, st] : results) {
        if (id == "A") statusA = st;
        if (id == "B") statusB = st;
    }
    if (statusA == 0 && statusB != 0) {
        printf("\n  >>> DIAGNOSIS: Double StackReset is the root cause!\n");
        printf("  >>> Fix: Remove explicit stackReset() in query_flow.cpp\n");
        printf("  >>>       (exchangeProperties already calls it internally)\n");
    } else if (statusA != 0 && statusB != 0) {
        printf("\n  >>> Both A and B failed — issue is NOT double StackReset.\n");
        printf("  >>> Check: ioctl parameters, buffer alignment, device path.\n");
        printf("  >>> Try: strace -e ioctl -xx sedutil-cli --query %s\n", device.c_str());
    }

    printf("\n  Output: %s/\n", outDir.c_str());
    printf("================================================================\n");

    return (failCount > 0) ? 1 : 0;
}
