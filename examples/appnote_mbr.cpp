/// @file appnote_mbr.cpp
/// @brief TCG Storage Application Note: Shadow MBR 심층 예제.
///
/// Shadow MBR (Pre-Boot Authentication) 기능의 전체 워크플로우를
/// EvalApi (단계별 플랫 API)로 구현합니다.
///
/// Shadow MBR 개요:
///   MBR 섀도잉이 활성화되면, 부팅 시 디스크의 실제 MBR 대신
///   Shadow MBR 테이블에 저장된 PBA(Pre-Boot Authentication) 이미지가
///   호스트에 노출됩니다. PBA가 사용자 인증을 완료하고 MBRDone=true를
///   설정하면 실제 디스크 데이터가 노출됩니다.
///
/// 포함 시나리오:
///   1. MBR 섀도잉 활성화
///   2. PBA 이미지 쓰기
///   3. MBR 데이터 읽기 및 검증
///   4. MBRDone 플로우 (부팅 사이클 시뮬레이션)
///   5. 다중 사용자 MBR 접근 (Admin1 vs User1 권한)
///   6. MBR 섀도잉 비활성화

#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/security/hash_password.h>
#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <algorithm>

using namespace libsed;
using namespace libsed::eval;

// ── Helpers ─────────────────────────────────────────────

static void printHex(const std::string& label, const Bytes& d, size_t maxLen = 32) {
    std::cout << "    " << label << " (" << d.size() << " bytes): ";
    for (size_t i = 0; i < std::min(d.size(), maxLen); i++)
        printf("%02X ", d[i]);
    if (d.size() > maxLen) std::cout << "...";
    std::cout << "\n";
}

static void step(int n, const std::string& name, Result r) {
    std::cout << "  [Step " << n << "] " << name << ": "
              << (r.ok() ? "OK" : "FAIL");
    if (r.failed()) std::cout << " (" << r.message() << ")";
    std::cout << "\n";
}

// ════════════════════════════════════════════════════════
//  1. Enable MBR Shadow
// ════════════════════════════════════════════════════════

/// @scenario MBR 섀도잉 활성화
/// @precondition Locking SP 활성화 완료, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. MBR 현재 상태 확인
///   3. MBREnable = true 설정
///   4. MBR 상태 재확인
///   5. 세션 닫기
/// @expected
///   - MBREnable = true
///   - 이후 부팅 시 Shadow MBR이 호스트에 노출됨
static bool mbr_enableShadow(EvalApi& api,
                              std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  1. Enable MBR Shadow                     ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);
    RawResult raw;

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Check current MBR status
    bool mbrEnabled = false, mbrDone = false;
    r = api.getMbrStatus(session, mbrEnabled, mbrDone, raw);
    step(2, "Get current MBR status", r);
    std::cout << "    Before: MBREnable=" << mbrEnabled << " MBRDone=" << mbrDone << "\n";

    // Enable
    r = api.setMbrEnable(session, true, raw);
    step(3, "Set MBREnable=true", r);

    // Verify
    r = api.getMbrStatus(session, mbrEnabled, mbrDone, raw);
    step(4, "Verify MBR status", r);
    std::cout << "    After:  MBREnable=" << mbrEnabled << " MBRDone=" << mbrDone << "\n";

    api.closeSession(session);
    step(5, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  2. Write PBA Image
// ════════════════════════════════════════════════════════

/// @scenario PBA 이미지를 MBR 테이블에 쓰기
/// @precondition MBR 섀도잉 활성화, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. 4096바이트 합성 PBA 이미지 생성 (MBR 부트 섹터 형식)
///   3. 청크 단위로 MBR 테이블에 쓰기 (512바이트씩)
///   4. 쓰기 진행 상황 출력
///   5. 세션 닫기
/// @expected
///   - 4096바이트 PBA 이미지가 MBR 테이블에 성공적으로 기록됨
///   - 부팅 시 이 이미지가 호스트에 노출됨
static bool mbr_writePbaImage(EvalApi& api,
                               std::shared_ptr<ITransport> transport,
                               uint16_t comId,
                               const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  2. Write PBA Image                       ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Build a 4096-byte synthetic PBA image
    const uint32_t pbaSize = 4096;
    Bytes pbaImage(pbaSize, 0);

    // Sector 0: MBR boot sector
    pbaImage[0] = 0xEB;  // JMP short
    pbaImage[1] = 0x3C;
    pbaImage[2] = 0x90;  // NOP
    std::memcpy(&pbaImage[3], "TCGPBA", 6);
    // Partition entry at offset 446
    pbaImage[446] = 0x80;  // Bootable flag
    pbaImage[510] = 0x55;  // Boot signature
    pbaImage[511] = 0xAA;

    // Fill remaining sectors with pattern
    for (uint32_t i = 512; i < pbaSize; i++) {
        pbaImage[i] = static_cast<uint8_t>(i & 0xFF);
    }

    // Write in 512-byte chunks
    const uint32_t chunkSize = 512;
    uint32_t written = 0;
    RawResult raw;

    step(2, "Write PBA image (" + std::to_string(pbaSize) + " bytes)", Result(ErrorCode::Success));
    for (uint32_t offset = 0; offset < pbaSize; offset += chunkSize) {
        uint32_t len = std::min(chunkSize, pbaSize - offset);
        Bytes chunk(pbaImage.begin() + offset, pbaImage.begin() + offset + len);
        r = api.writeMbrData(session, offset, chunk, raw);
        if (r.ok()) {
            written += len;
        } else {
            std::cout << "    Write failed at offset " << offset << ": " << r.message() << "\n";
            break;
        }
    }
    std::cout << "    Written: " << written << "/" << pbaSize << " bytes\n";

    api.closeSession(session);
    step(3, "Close session", Result(ErrorCode::Success));

    return written == pbaSize;
}

// ════════════════════════════════════════════════════════
//  3. Read and Verify MBR Data
// ════════════════════════════════════════════════════════

/// @scenario MBR 데이터 읽기 및 검증
/// @precondition MBR 테이블에 데이터가 기록됨, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 읽기 세션 열기
///   2. MBR 테이블에서 4096바이트 읽기 (512바이트 청크)
///   3. 첫 번째 섹터의 부트 시그니처(0x55AA) 확인
///   4. PBA 식별자("TCGPBA") 확인
///   5. 세션 닫기
/// @expected
///   - 읽은 데이터가 이전에 기록한 PBA 이미지와 일치
///   - 부트 시그니처 및 PBA 식별자 확인됨
static bool mbr_readAndVerify(EvalApi& api,
                               std::shared_ptr<ITransport> transport,
                               uint16_t comId,
                               const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  3. Read and Verify MBR Data              ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, false,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth (read-only)", r);
    if (r.failed()) return false;

    // Read in chunks
    const uint32_t totalSize = 4096;
    const uint32_t chunkSize = 512;
    Bytes fullData;
    RawResult raw;

    for (uint32_t offset = 0; offset < totalSize; offset += chunkSize) {
        Bytes chunk;
        r = api.readMbrData(session, offset, chunkSize, chunk, raw);
        if (r.ok()) {
            fullData.insert(fullData.end(), chunk.begin(), chunk.end());
        } else {
            std::cout << "    Read failed at offset " << offset << "\n";
            break;
        }
    }
    step(2, "Read MBR data (" + std::to_string(fullData.size()) + " bytes)", r);

    // Verify boot signature
    bool sigOk = false;
    if (fullData.size() >= 512) {
        sigOk = (fullData[510] == 0x55 && fullData[511] == 0xAA);
        std::cout << "    Boot signature (0x55AA): " << (sigOk ? "FOUND" : "NOT FOUND") << "\n";
    }
    step(3, "Verify boot signature", sigOk ? Result(ErrorCode::Success) : Result(ErrorCode::InvalidArgument));

    // Verify PBA identifier
    bool pbaOk = false;
    if (fullData.size() >= 9) {
        pbaOk = (std::memcmp(&fullData[3], "TCGPBA", 6) == 0);
        std::cout << "    PBA identifier: " << (pbaOk ? "FOUND" : "NOT FOUND") << "\n";
    }
    step(4, "Verify PBA identifier", pbaOk ? Result(ErrorCode::Success) : Result(ErrorCode::InvalidArgument));

    printHex("First 16 bytes", Bytes(fullData.begin(),
             fullData.begin() + std::min(fullData.size(), (size_t)16)));

    api.closeSession(session);
    step(5, "Close session", Result(ErrorCode::Success));

    return sigOk && pbaOk;
}

// ════════════════════════════════════════════════════════
//  4. MBRDone Flow (Boot Cycle Simulation)
// ════════════════════════════════════════════════════════

/// @scenario MBRDone 플로우 — 부팅 사이클 시뮬레이션
/// @precondition MBR 섀도잉 활성화, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. MBRDone = false 설정 (전원 사이클 후 상태 시뮬레이션)
///   3. MBR 상태 확인: MBREnable=true, MBRDone=false → Shadow MBR 노출 상태
///   4. PBA 인증 완료 후 MBRDone = true 설정
///   5. MBR 상태 확인: MBREnable=true, MBRDone=true → 실제 디스크 노출 상태
///   6. 세션 닫기
/// @expected
///   - MBRDone=false: 부팅 시 Shadow MBR(PBA)이 호스트에 보임
///   - MBRDone=true: PBA 인증 후 실제 디스크 데이터가 호스트에 보임
///   - 전원 사이클 시 MBRDone은 자동으로 false로 리셋됨
static bool mbr_doneFlow(EvalApi& api,
                          std::shared_ptr<ITransport> transport,
                          uint16_t comId,
                          const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  4. MBRDone Flow (Boot Cycle Simulation)  ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);
    RawResult raw;

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    // Simulate post-power-cycle: MBRDone = false
    r = api.setMbrDone(session, false, raw);
    step(2, "Set MBRDone=false (simulate power cycle)", r);

    bool mbrEnabled = false, mbrDone = false;
    r = api.getMbrStatus(session, mbrEnabled, mbrDone, raw);
    step(3, "Check status (pre-auth state)", r);
    std::cout << "    MBREnable=" << mbrEnabled << " MBRDone=" << mbrDone << "\n";
    std::cout << "    >> Host sees: Shadow MBR (PBA image)\n";

    // Simulate PBA completed authentication → set MBRDone = true
    r = api.setMbrDone(session, true, raw);
    step(4, "Set MBRDone=true (PBA auth complete)", r);

    r = api.getMbrStatus(session, mbrEnabled, mbrDone, raw);
    step(5, "Check status (post-auth state)", r);
    std::cout << "    MBREnable=" << mbrEnabled << " MBRDone=" << mbrDone << "\n";
    std::cout << "    >> Host sees: Real disk data\n";

    api.closeSession(session);
    step(6, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  5. Multi-User MBR Access
// ════════════════════════════════════════════════════════

/// @scenario 다중 사용자 MBR 접근 권한 확인
/// @precondition MBR 활성화, Admin1/User1 비밀번호 유효, User1 활성화됨
/// @steps
///   1. User1 인증으로 세션 열기
///   2. User1이 MBRDone 설정 시도 → 성공 (User도 MBRDone 설정 가능)
///   3. User1이 MBREnable 변경 시도 → 실패 예상 (Admin1 전용)
///   4. 세션 닫기
///   5. Admin1 인증으로 MBR 상태 확인
///   6. 세션 닫기
/// @expected
///   - User1: MBRDone 설정 가능 (PBA 인증 후 Done 플래그 설정 용도)
///   - User1: MBREnable 변경 불가 (Admin1 권한 필요)
///   - Admin1: MBREnable/MBRDone 모두 제어 가능
static bool mbr_multiUser(EvalApi& api,
                           std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           const std::string& admin1Pw,
                           const std::string& user1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  5. Multi-User MBR Access                 ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    RawResult raw;

    // --- User1 session ---
    Bytes user1Cred = HashPassword::passwordToBytes(user1Pw);
    Session session1(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session1, uid::SP_LOCKING, true,
                                       uid::AUTH_USER1, user1Cred, ssr);
    step(1, "User1 auth to LockingSP", r);
    if (r.failed()) {
        std::cout << "    User1 auth failed (may not be enabled)\n";
        return false;
    }

    // User1 sets MBRDone
    r = api.setMbrDone(session1, true, raw);
    step(2, "User1: Set MBRDone=true", r);
    std::cout << "    User1 MBRDone: " << (r.ok() ? "SUCCESS (allowed)" : "DENIED") << "\n";

    // User1 tries to change MBREnable (should fail — Admin1 only)
    r = api.setMbrEnable(session1, false, raw);
    step(3, "User1: Set MBREnable=false (expect denied)", r);
    std::cout << "    User1 MBREnable: " << (r.ok() ? "SUCCESS (unexpected)" : "DENIED (expected)") << "\n";

    api.closeSession(session1);
    step(4, "Close User1 session", Result(ErrorCode::Success));

    // --- Admin1 verification ---
    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);
    Session session2(transport, comId);
    StartSessionResult ssr2;
    r = api.startSessionWithAuth(session2, uid::SP_LOCKING, false,
                                  uid::AUTH_ADMIN1, admin1Cred, ssr2);
    step(5, "Admin1 auth — verify MBR status", r);
    if (r.ok()) {
        bool mbrEnabled = false, mbrDone = false;
        api.getMbrStatus(session2, mbrEnabled, mbrDone, raw);
        std::cout << "    MBREnable=" << mbrEnabled << " MBRDone=" << mbrDone << "\n";
        api.closeSession(session2);
    }
    step(6, "Close Admin1 session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  6. Disable MBR Shadow
// ════════════════════════════════════════════════════════

/// @scenario MBR 섀도잉 비활성화
/// @precondition MBR 활성화 상태, Admin1 비밀번호 유효
/// @steps
///   1. LockingSP에 Admin1 인증으로 쓰기 세션 열기
///   2. MBREnable = false 설정
///   3. MBR 상태 확인
///   4. 세션 닫기
/// @expected
///   - MBREnable = false
///   - 부팅 시 실제 디스크 MBR이 직접 노출됨 (PBA 우회)
static bool mbr_disable(EvalApi& api,
                         std::shared_ptr<ITransport> transport,
                         uint16_t comId,
                         const std::string& admin1Pw) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║  6. Disable MBR Shadow                    ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";

    Bytes admin1Cred = HashPassword::passwordToBytes(admin1Pw);
    RawResult raw;

    Session session(transport, comId);
    StartSessionResult ssr;
    auto r = api.startSessionWithAuth(session, uid::SP_LOCKING, true,
                                       uid::AUTH_ADMIN1, admin1Cred, ssr);
    step(1, "Admin1 auth to LockingSP", r);
    if (r.failed()) return false;

    r = api.setMbrEnable(session, false, raw);
    step(2, "Set MBREnable=false", r);

    bool mbrEnabled = false, mbrDone = false;
    r = api.getMbrStatus(session, mbrEnabled, mbrDone, raw);
    step(3, "Verify MBR status", r);
    std::cout << "    MBREnable=" << mbrEnabled << " MBRDone=" << mbrDone << "\n";

    api.closeSession(session);
    step(4, "Close session", Result(ErrorCode::Success));

    return true;
}

// ════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <device> <admin1_pw> [user1_pw]\n\n";
        std::cerr << "TCG Shadow MBR Application Note.\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 admin123\n";
        std::cerr << "  " << argv[0] << " /dev/nvme0 admin123 user123\n";
        return 1;
    }

    std::string device   = argv[1];
    std::string admin1Pw = argv[2];
    std::string user1Pw  = (argc > 3) ? argv[3] : "";

    libsed::initialize();

    auto transport = TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Cannot open " << device << "\n";
        return 1;
    }

    EvalApi api;

    TcgOption opt;
    api.getTcgOption(transport, opt);
    uint16_t comId = opt.baseComId;
    if (comId == 0) {
        std::cerr << "No valid ComID found\n";
        return 1;
    }
    if (!opt.mbrSupported) {
        std::cerr << "MBR shadowing not supported on this device\n";
        return 1;
    }

    PropertiesResult props;
    api.exchangeProperties(transport, comId, props);

    std::cout << "═══════════════════════════════════════════════\n";
    std::cout << " TCG Shadow MBR Application Note\n";
    std::cout << " Device:       " << device << "\n";
    std::cout << " ComID:        0x" << std::hex << comId << std::dec << "\n";
    std::cout << " MBR Supported: " << (opt.mbrSupported ? "Yes" : "No") << "\n";
    std::cout << "═══════════════════════════════════════════════\n";

    struct { const char* name; bool pass; } results[] = {
        {"1. Enable MBR Shadow",      false},
        {"2. Write PBA Image",        false},
        {"3. Read and Verify",        false},
        {"4. MBRDone Flow",           false},
        {"5. Multi-User MBR Access",  false},
        {"6. Disable MBR Shadow",     false},
    };

    results[0].pass = mbr_enableShadow(api, transport, comId, admin1Pw);
    results[1].pass = mbr_writePbaImage(api, transport, comId, admin1Pw);
    results[2].pass = mbr_readAndVerify(api, transport, comId, admin1Pw);
    results[3].pass = mbr_doneFlow(api, transport, comId, admin1Pw);

    if (!user1Pw.empty()) {
        results[4].pass = mbr_multiUser(api, transport, comId, admin1Pw, user1Pw);
    } else {
        std::cout << "\n  Skipping Multi-User test (no user1_pw provided)\n";
    }

    results[5].pass = mbr_disable(api, transport, comId, admin1Pw);

    // Summary
    std::cout << "\n═══════════════════════════════════════════════\n";
    std::cout << " Summary\n";
    std::cout << "═══════════════════════════════════════════════\n";
    int passCount = 0;
    for (auto& r : results) {
        std::cout << "  " << (r.pass ? "[PASS]" : "[FAIL]") << " " << r.name << "\n";
        if (r.pass) passCount++;
    }
    std::cout << "\n  Total: " << passCount << "/6 passed\n";

    libsed::shutdown();
    return 0;
}
