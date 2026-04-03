/// @file eval_session_loop.cpp
/// @brief StartSession → Authenticate → Revert 반복 예제.
///
/// 단일 ComID에서 세션 열기/인증/Revert를 N회 반복하여
/// 세션 라이프사이클 안정성을 검증한다.
///
/// 흐름 (매 반복):
///   1. StartSession (AdminSP, Write, SID auth)
///   2. Authenticate (SID)
///   3. RevertSP (Locking SP) 또는 Get SP Lifecycle
///   4. CloseSession
///
/// Usage:
///   ./example_eval_session_loop <device> <sid_pw> [count] [--log]
///   예: ./example_eval_session_loop /dev/nvme0 myPassword 10 --log

#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/debug/logging_transport.h>
#include <libsed/security/hash_password.h>
#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>
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

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <device> <sid_pw> [count] [--log]\n";
        std::cerr << "  count: 반복 횟수 (기본: 5)\n";
        std::cerr << "  --log: 명령 이력 기록\n";
        std::cerr << "\n예: " << argv[0] << " /dev/nvme0 myPassword 10 --log\n";
        return 1;
    }

    std::string device = argv[1];
    std::string sidPw = argv[2];
    int count = 5;
    bool enableLog = false;

    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--log") enableLog = true;
        else count = std::stoi(arg);
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

    // ── Step 0: Discovery ──
    std::cout << "── Discovery ──\n";
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed() || info.baseComId == 0) {
        std::cerr << "FAIL: Discovery — " << r.message() << "\n";
        return 1;
    }

    uint16_t comId = info.baseComId;
    std::cout << "  " << sscName(info.primarySsc) << " ComID=0x"
              << std::hex << std::setfill('0') << std::setw(4) << comId
              << std::dec << "\n\n";

    // ── Step 1: StackReset + Properties ──
    std::cout << "── StackReset + Properties ──\n";
    api.stackReset(transport, comId);

    PropertiesResult props;
    r = api.exchangeProperties(transport, comId, props);
    uint32_t maxCPS = 2048;
    if (r.ok() && props.tperMaxComPacketSize > 0) {
        maxCPS = props.tperMaxComPacketSize;
        std::cout << "  Properties OK, MaxComPacketSize=" << maxCPS << "\n";
    } else {
        std::cout << "  Properties failed, fallback MaxComPacketSize=" << maxCPS << "\n";
    }
    std::cout << "\n";

    // ── Step 2: MSID 읽기 (SID 초기 비밀번호 확인) ──
    std::cout << "── MSID Check ──\n";
    {
        Session s(transport, comId);
        s.setMaxComPacketSize(maxCPS);
        StartSessionResult ssr;
        r = api.startSession(s, uid::SP_ADMIN, false, ssr);
        if (r.failed()) {
            std::cerr << "FAIL: Anonymous session — " << r.message() << "\n";
            return 1;
        }

        Bytes msid;
        RawResult raw;
        r = api.getCPin(s, uid::CPIN_MSID, msid, raw);
        api.closeSession(s);

        if (r.ok() && !msid.empty()) {
            std::cout << "  MSID: " << msid.size() << " bytes\n";
        } else {
            std::cout << "  MSID read failed (may be restricted)\n";
        }
    }
    std::cout << "\n";

    // ── Credential 준비 ──
    Bytes sidCred = HashPassword::passwordToBytes(sidPw);

    // ═══════════════════════════════════════════════
    //  Main Loop: StartSession → Auth → Operation → Close
    // ═══════════════════════════════════════════════

    int pass = 0, fail = 0;
    auto totalStart = std::chrono::steady_clock::now();

    for (int i = 0; i < count; i++) {
        std::cout << "── Iteration " << (i + 1) << "/" << count << " ──\n";
        auto iterStart = std::chrono::steady_clock::now();

        // 1. StartSession (AdminSP, Write=true, SID auth)
        Session session(transport, comId);
        session.setMaxComPacketSize(maxCPS);
        StartSessionResult ssr;
        r = api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                                      uid::AUTH_SID, sidCred, ssr);
        if (r.failed()) {
            std::cerr << "  [" << (i+1) << "] StartSession FAIL: " << r.message() << "\n";
            fail++;

            // StackReset 후 재시도
            api.stackReset(transport, comId);
            continue;
        }
        std::cout << "  Session: TSN=" << ssr.tperSessionNumber
                  << " HSN=" << ssr.hostSessionNumber << "\n";

        // 2. SP Lifecycle 조회 (AdminSP 세션에서 Locking SP 상태 확인)
        RawResult raw;
        uint8_t lifecycle = 0;
        r = api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle, raw);
        if (r.ok()) {
            std::cout << "  Locking SP lifecycle: 0x"
                      << std::hex << std::setfill('0') << std::setw(2)
                      << (int)lifecycle << std::dec;
            if (lifecycle == 0x08) std::cout << " (Manufactured-Inactive)";
            else if (lifecycle == 0x09) std::cout << " (Manufactured)";
            else if (lifecycle == 0x0A) std::cout << " (Manufactured-Disabled)";
            std::cout << "\n";
        } else {
            std::cout << "  Lifecycle query: " << r.message() << "\n";
        }

        // 3. MSID 읽기 (SID 권한으로 C_PIN_MSID 접근)
        Bytes msidVal;
        r = api.getCPin(session, uid::CPIN_MSID, msidVal, raw);
        if (r.ok() && !msidVal.empty()) {
            std::cout << "  MSID: " << msidVal.size() << " bytes\n";
        } else {
            std::cout << "  MSID read: " << r.message() << "\n";
        }

        // 4. CloseSession
        api.closeSession(session);

        auto iterEnd = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(iterEnd - iterStart).count();
        std::cout << "  → OK (" << ms << "ms)\n\n";
        pass++;
    }

    auto totalEnd = std::chrono::steady_clock::now();
    auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(totalEnd - totalStart).count();

    // ── Summary ──
    std::cout << "══════════════════════════════════════════\n";
    std::cout << "  Session Loop: " << pass << " pass / " << fail << " fail"
              << " (" << count << " total, " << totalMs << "ms)\n";
    std::cout << "  " << sscName(info.primarySsc) << " on " << device << "\n";
    std::cout << "══════════════════════════════════════════\n";

    return (fail > 0) ? 1 : 0;
}
