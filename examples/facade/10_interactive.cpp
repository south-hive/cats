/// @file 10_interactive.cpp
/// @brief Interactive SED Drive Explorer — Event-Driven 방식의 종합 TC 예제
///
/// 다양한 SED 기능을 대화형으로 실험할 수 있습니다.
/// 명령어를 입력하면서 드라이브 상태를 확인하고,
/// 각 단계별 결과를 실시간으로 관찰합니다.
///
/// 사용법: ./facade_interactive /dev/nvme0 [--dump]

#include <cats.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <functional>
#include <map>

using namespace libsed;

// ═══════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════

static SedDrive* g_drive = nullptr;
static bool g_dumpEnabled = false;

// ── 토큰 분리 ──
static std::vector<std::string> split(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);
    return tokens;
}

// ── 결과 출력 ──
static void printResult(const char* op, Result r) {
    if (r.ok())
        printf("  ✓ %s 성공\n", op);
    else
        printf("  ✗ %s 실패: %s\n", op, r.message().c_str());
}

// ═══════════════════════════════════════════════════════
//  Commands
// ═══════════════════════════════════════════════════════

static void cmdHelp(const std::vector<std::string>&) {
    printf("\n");
    printf("── 조회 ──────────────────────────────────────\n");
    printf("  query                          드라이브 조회 (Discovery + Properties + MSID)\n");
    printf("  info                           현재 드라이브 정보 출력\n");
    printf("  msid                           MSID 출력\n");
    printf("  dump                           패킷 hex dump 토글\n");
    printf("\n");
    printf("── 소유권 ────────────────────────────────────\n");
    printf("  take-ownership <pw>            소유권 확보 (MSID → SID PIN 변경)\n");
    printf("  activate <sid_pw>              Locking SP 활성화\n");
    printf("\n");
    printf("── Range ─────────────────────────────────────\n");
    printf("  configure-range <id> <start> <len> <admin1_pw>\n");
    printf("                                 Range 설정\n");
    printf("  lock <id> <pw> [user]          Range 잠금 (기본 user=1)\n");
    printf("  unlock <id> <pw> [user]        Range 잠금 해제\n");
    printf("  range-info <id> <pw> [user]    Range 정보 조회\n");
    printf("\n");
    printf("── User ──────────────────────────────────────\n");
    printf("  setup-user <uid> <pw> <range> <admin1_pw>\n");
    printf("                                 User 활성화 + 비밀번호 + Range 할당\n");
    printf("\n");
    printf("── 세션 ──────────────────────────────────────\n");
    printf("  login-admin <sid_pw>           AdminSP/SID 세션 열기\n");
    printf("  login-locking <pw> [user]      LockingSP 세션 열기 (기본 Admin1)\n");
    printf("  login-user <pw> <user_id>      LockingSP/UserN 세션 열기\n");
    printf("  session-info                   현재 세션 정보\n");
    printf("  close                          현재 세션 닫기\n");
    printf("\n");
    printf("── 세션 내 작업 ──────────────────────────────\n");
    printf("  set-pin <cpin> <new_pw>        PIN 변경 (cpin: sid/admin1/userN)\n");
    printf("  get-range <id>                 Range 정보 조회 (세션 필요)\n");
    printf("  s-lock <id>                    Range 잠금 (세션 필요)\n");
    printf("  s-unlock <id>                  Range 잠금 해제 (세션 필요)\n");
    printf("  mbr-enable <0|1>               MBR 활성화/비활성화\n");
    printf("  mbr-done <0|1>                 MBR Done 설정\n");
    printf("  ds-write <offset> <hex>        DataStore 쓰기 (예: ds-write 0 48656C6C6F)\n");
    printf("  ds-read <offset> <len>         DataStore 읽기\n");
    printf("\n");
    printf("── MBR / Crypto ──────────────────────────────\n");
    printf("  set-mbr-enable <0|1> <admin1_pw>  MBR 활성화/비활성화 (편의)\n");
    printf("  crypto-erase <range> <admin1_pw>  Crypto Erase\n");
    printf("\n");
    printf("── Enterprise Band ───────────────────────────\n");
    printf("  configure-band <id> <start> <len> <bm_pw>\n");
    printf("  lock-band <id> <bm_pw>\n");
    printf("  unlock-band <id> <bm_pw>\n");
    printf("\n");
    printf("── 초기화 ────────────────────────────────────\n");
    printf("  revert <sid_pw>                SID Revert (공장 초기화)\n");
    printf("  psid-revert <psid>             PSID Revert\n");
    printf("\n");
    printf("── 기타 ──────────────────────────────────────\n");
    printf("  full-setup <sid> <adm1> <usr1> 전체 설정 (소유권→활성화→Range→User)\n");
    printf("  verify-auth <pw>               SID 인증 테스트 (비밀번호 검증용)\n");
    printf("  help                           이 도움말\n");
    printf("  quit                           종료\n");
    printf("\n");
}

static void cmdQuery(const std::vector<std::string>&) {
    auto r = g_drive->query();
    printResult("query", r);
    if (r.ok()) {
        printf("  SSC:    %s\n", g_drive->sscName());
        printf("  ComID:  0x%04X (%d개)\n", g_drive->comId(), g_drive->numComIds());
        printf("  MaxCPS: %u\n", g_drive->maxComPacketSize());
    }
}

static void cmdInfo(const std::vector<std::string>&) {
    const auto& info = g_drive->info();
    printf("  SSC:      %s\n", g_drive->sscName());
    printf("  ComID:    0x%04X (%d개)\n", g_drive->comId(), g_drive->numComIds());
    printf("  MaxCPS:   %u\n", g_drive->maxComPacketSize());
    printf("  TPer:     %s\n", info.tperPresent ? "있음" : "없음");
    printf("  Locking:  %s\n", info.lockingPresent ? "있음" : "없음");
    printf("  Enabled:  %s\n", info.lockingEnabled ? "예" : "아니오");
    printf("  Locked:   %s\n", info.locked ? "예" : "아니오");
    printf("  MBR:      %s%s\n",
        info.mbrEnabled ? "활성" : "비활성",
        info.mbrDone ? " (done)" : "");
    if (!g_drive->msid().empty())
        printf("  MSID:     %s (%zu bytes)\n",
            g_drive->msidString().c_str(), g_drive->msid().size());
}

static void cmdMsid(const std::vector<std::string>&) {
    if (g_drive->msid().empty()) {
        printf("  MSID 없음 (읽기 제한 또는 query 미실행)\n");
        return;
    }
    printf("  MSID: %s (%zu bytes)\n",
        g_drive->msidString().c_str(), g_drive->msid().size());
    printf("  Hex: ");
    for (auto b : g_drive->msid()) printf("%02X", b);
    printf("\n");
}

static void cmdDump(const std::vector<std::string>&) {
    g_dumpEnabled = !g_dumpEnabled;
    if (g_dumpEnabled)
        g_drive->enableDump();
    printf("  Dump %s\n", g_dumpEnabled ? "ON" : "OFF (다음 query부터 적용)");
}

// ── Ownership ──

static void cmdTakeOwnership(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: take-ownership <new_pw>\n"); return; }
    printResult("takeOwnership", g_drive->takeOwnership(args[1]));
}

static void cmdActivate(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: activate <sid_pw>\n"); return; }
    printResult("activateLocking", g_drive->activateLocking(args[1]));
}

// ── Range (convenience) ──

static void cmdConfigureRange(const std::vector<std::string>& args) {
    if (args.size() < 5) {
        printf("  사용법: configure-range <id> <start> <len> <admin1_pw>\n");
        return;
    }
    auto r = g_drive->configureRange(
        std::stoul(args[1]), std::stoull(args[2]),
        std::stoull(args[3]), args[4]);
    printResult("configureRange", r);
}

static void cmdLock(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: lock <range> <pw> [user]\n"); return; }
    uint32_t user = (args.size() > 3) ? std::stoul(args[3]) : 1;
    printResult("lockRange", g_drive->lockRange(std::stoul(args[1]), args[2], user));
}

static void cmdUnlock(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: unlock <range> <pw> [user]\n"); return; }
    uint32_t user = (args.size() > 3) ? std::stoul(args[3]) : 1;
    printResult("unlockRange", g_drive->unlockRange(std::stoul(args[1]), args[2], user));
}

static void cmdRangeInfo(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: range-info <range> <pw> [user]\n"); return; }
    uint32_t user = (args.size() > 3) ? std::stoul(args[3]) : 1;
    auto s = g_drive->login(Uid(uid::SP_LOCKING), args[2],
                             uid::makeUserUid(user));
    if (s.failed()) {
        printf("  로그인 실패: %s\n", s.openResult().message().c_str());
        return;
    }
    LockingRangeInfo info;
    auto r = s.getRangeInfo(std::stoul(args[1]), info);
    if (r.ok()) {
        printf("  Range %u:\n", info.rangeId);
        printf("    Start:        %lu\n", (unsigned long)info.rangeStart);
        printf("    Length:       %lu\n", (unsigned long)info.rangeLength);
        printf("    ReadLockEn:   %s\n", info.readLockEnabled ? "예" : "아니오");
        printf("    WriteLockEn:  %s\n", info.writeLockEnabled ? "예" : "아니오");
        printf("    ReadLocked:   %s\n", info.readLocked ? "예" : "아니오");
        printf("    WriteLocked:  %s\n", info.writeLocked ? "예" : "아니오");
    } else {
        printf("  조회 실패: %s\n", r.message().c_str());
    }
}

// ── User ──

static void cmdSetupUser(const std::vector<std::string>& args) {
    if (args.size() < 5) {
        printf("  사용법: setup-user <user_id> <user_pw> <range> <admin1_pw>\n");
        return;
    }
    auto r = g_drive->setupUser(
        std::stoul(args[1]), args[2], std::stoul(args[3]), args[4]);
    printResult("setupUser", r);
}

// ── Session-based commands ──

static std::unique_ptr<SedSession> g_session;

static void cmdLoginAdmin(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: login-admin <sid_pw>\n"); return; }
    g_session = std::make_unique<SedSession>(
        g_drive->login(Uid(uid::SP_ADMIN), args[1], Uid(uid::AUTH_SID)));
    if (g_session->ok()) {
        printf("  ✓ AdminSP/SID 세션 열림 (TSN=%u, HSN=%u)\n",
            g_session->raw().tperSessionNumber(),
            g_session->raw().hostSessionNumber());
    } else {
        printf("  ✗ 로그인 실패: %s\n", g_session->openResult().message().c_str());
        g_session.reset();
    }
}

static void cmdLoginLocking(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: login-locking <pw> [user]\n"); return; }
    Uid authUid = (args.size() > 2)
        ? uid::makeUserUid(std::stoul(args[2]))
        : Uid(uid::AUTH_ADMIN1);
    g_session = std::make_unique<SedSession>(
        g_drive->login(Uid(uid::SP_LOCKING), args[1], authUid));
    if (g_session->ok()) {
        printf("  ✓ LockingSP 세션 열림 (TSN=%u, HSN=%u)\n",
            g_session->raw().tperSessionNumber(),
            g_session->raw().hostSessionNumber());
    } else {
        printf("  ✗ 로그인 실패: %s\n", g_session->openResult().message().c_str());
        g_session.reset();
    }
}

static void cmdLoginUser(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: login-user <pw> <user_id>\n"); return; }
    g_session = std::make_unique<SedSession>(
        g_drive->login(Uid(uid::SP_LOCKING), args[1],
                       uid::makeUserUid(std::stoul(args[2]))));
    if (g_session->ok()) {
        printf("  ✓ LockingSP/User%s 세션 열림 (TSN=%u)\n",
            args[2].c_str(), g_session->raw().tperSessionNumber());
    } else {
        printf("  ✗ 로그인 실패: %s\n", g_session->openResult().message().c_str());
        g_session.reset();
    }
}

static void cmdSessionInfo(const std::vector<std::string>&) {
    if (!g_session || !g_session->isActive()) {
        printf("  활성 세션 없음\n");
        return;
    }
    printf("  TSN: %u\n", g_session->raw().tperSessionNumber());
    printf("  HSN: %u\n", g_session->raw().hostSessionNumber());
}

static void cmdClose(const std::vector<std::string>&) {
    if (!g_session) { printf("  세션 없음\n"); return; }
    g_session->close();
    g_session.reset();
    printf("  ✓ 세션 닫힘\n");
}

// ── Session operations ──

static bool requireSession() {
    if (!g_session || !g_session->isActive()) {
        printf("  세션이 필요합니다. login-admin / login-locking / login-user 먼저 실행\n");
        return false;
    }
    return true;
}

static Uid parseCpinUid(const std::string& name) {
    if (name == "sid")    return Uid(uid::CPIN_SID);
    if (name == "admin1") return Uid(uid::CPIN_ADMIN1);
    if (name == "msid")   return Uid(uid::CPIN_MSID);
    // userN → C_PIN_UserN
    if (name.substr(0, 4) == "user") {
        uint32_t n = std::stoul(name.substr(4));
        return uid::makeCpinUserUid(n);
    }
    printf("  알 수 없는 C_PIN: %s (sid/admin1/msid/user1..N)\n", name.c_str());
    return Uid(0);
}

static void cmdSetPin(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: set-pin <cpin> <new_pw>\n"); return; }
    if (!requireSession()) return;
    auto cpinUid = parseCpinUid(args[1]);
    if (cpinUid.toUint64() == 0) return;
    printResult("setPin", g_session->setPin(cpinUid, args[2]));
}

static void cmdGetRange(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: get-range <id>\n"); return; }
    if (!requireSession()) return;
    LockingRangeInfo info;
    auto r = g_session->getRangeInfo(std::stoul(args[1]), info);
    if (r.ok()) {
        printf("  Range %u: start=%lu len=%lu R=%s W=%s\n",
            info.rangeId, (unsigned long)info.rangeStart,
            (unsigned long)info.rangeLength,
            info.readLocked ? "잠김" : "열림",
            info.writeLocked ? "잠김" : "열림");
    } else {
        printf("  실패: %s\n", r.message().c_str());
    }
}

static void cmdSLock(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: s-lock <range>\n"); return; }
    if (!requireSession()) return;
    printResult("lockRange", g_session->lockRange(std::stoul(args[1])));
}

static void cmdSUnlock(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: s-unlock <range>\n"); return; }
    if (!requireSession()) return;
    printResult("unlockRange", g_session->unlockRange(std::stoul(args[1])));
}

static void cmdMbrEnable(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: mbr-enable <0|1>\n"); return; }
    if (!requireSession()) return;
    printResult("setMbrEnable", g_session->setMbrEnable(args[1] == "1"));
}

static void cmdMbrDone(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: mbr-done <0|1>\n"); return; }
    if (!requireSession()) return;
    printResult("setMbrDone", g_session->setMbrDone(args[1] == "1"));
}

static Bytes hexToBytes(const std::string& hex) {
    Bytes result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        result.push_back(static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return result;
}

static void cmdDsWrite(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: ds-write <offset> <hex_data>\n"); return; }
    if (!requireSession()) return;
    auto data = hexToBytes(args[2]);
    printResult("writeDataStore",
        g_session->writeDataStore(std::stoull(args[1]), data));
    printf("  %zu bytes 전송\n", data.size());
}

static void cmdDsRead(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: ds-read <offset> <len>\n"); return; }
    if (!requireSession()) return;
    Bytes data;
    auto r = g_session->readDataStore(std::stoull(args[1]), std::stoul(args[2]), data);
    if (r.ok()) {
        printf("  %zu bytes: ", data.size());
        for (auto b : data) printf("%02X ", b);
        printf("\n  ASCII: ");
        for (auto b : data) printf("%c", (b >= 0x20 && b < 0x7F) ? b : '.');
        printf("\n");
    } else {
        printf("  실패: %s\n", r.message().c_str());
    }
}

// ── MBR / Crypto (convenience) ──

static void cmdSetMbrEnable(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: set-mbr-enable <0|1> <admin1_pw>\n"); return; }
    printResult("setMbrEnable", g_drive->setMbrEnable(args[1] == "1", args[2]));
}

static void cmdCryptoErase(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: crypto-erase <range> <admin1_pw>\n"); return; }
    printResult("cryptoErase",
        g_drive->cryptoErase(std::stoul(args[1]), args[2]));
}

// ── Enterprise Band ──

static void cmdConfigureBand(const std::vector<std::string>& args) {
    if (args.size() < 5) {
        printf("  사용법: configure-band <id> <start> <len> <bm_pw>\n");
        return;
    }
    printResult("configureBand",
        g_drive->configureBand(std::stoul(args[1]),
            std::stoull(args[2]), std::stoull(args[3]), args[4]));
}

static void cmdLockBand(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: lock-band <id> <bm_pw>\n"); return; }
    printResult("lockBand", g_drive->lockBand(std::stoul(args[1]), args[2]));
}

static void cmdUnlockBand(const std::vector<std::string>& args) {
    if (args.size() < 3) { printf("  사용법: unlock-band <id> <bm_pw>\n"); return; }
    printResult("unlockBand", g_drive->unlockBand(std::stoul(args[1]), args[2]));
}

// ── Revert ──

static void cmdRevert(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: revert <sid_pw>\n"); return; }
    printResult("revert", g_drive->revert(args[1]));
}

static void cmdPsidRevert(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: psid-revert <psid>\n"); return; }
    printResult("psidRevert", g_drive->psidRevert(args[1]));
}

// ── Full setup ──

static void cmdFullSetup(const std::vector<std::string>& args) {
    if (args.size() < 4) {
        printf("  사용법: full-setup <sid_pw> <admin1_pw> <user1_pw>\n");
        return;
    }
    const auto& sid = args[1];
    const auto& adm = args[2];
    const auto& usr = args[3];

    printf("  [1/5] 소유권 확보...\n");
    auto r = g_drive->takeOwnership(sid);
    if (r.failed()) { printf("    실패: %s\n", r.message().c_str()); return; }

    printf("  [2/5] Locking SP 활성화...\n");
    r = g_drive->activateLocking(sid);
    if (r.failed()) { printf("    실패: %s\n", r.message().c_str()); return; }

    printf("  [3/5] Range 1 설정 (0~1M)...\n");
    r = g_drive->configureRange(1, 0, 1048576, adm);
    if (r.failed()) { printf("    실패: %s\n", r.message().c_str()); return; }

    printf("  [4/5] User1 설정...\n");
    r = g_drive->setupUser(1, usr, 1, adm);
    if (r.failed()) { printf("    실패: %s\n", r.message().c_str()); return; }

    printf("  [5/5] 잠금 테스트...\n");
    r = g_drive->lockRange(1, usr, 1);
    if (r.ok()) {
        printf("    잠금 OK → ");
        r = g_drive->unlockRange(1, usr, 1);
        printf("해제 %s\n", r.ok() ? "OK" : "실패");
    } else {
        printf("    잠금 실패: %s\n", r.message().c_str());
    }

    printf("  ✓ 전체 설정 완료\n");
}

// ── Verify auth ──

static void cmdVerifyAuth(const std::vector<std::string>& args) {
    if (args.size() < 2) { printf("  사용법: verify-auth <sid_pw>\n"); return; }
    printf("  AdminSP/SID 인증 시도...\n");
    auto s = g_drive->login(Uid(uid::SP_ADMIN), args[1], Uid(uid::AUTH_SID));
    if (s.ok()) {
        printf("  ✓ 인증 성공 (TSN=%u)\n", s.raw().tperSessionNumber());
        s.close();
    } else {
        printf("  ✗ 인증 실패: %s\n", s.openResult().message().c_str());
        printf("  비밀번호가 맞는지 확인하세요.\n");
        printf("  sedutil-cli로 설정했다면 PBKDF2 해싱 차이일 수 있습니다.\n");
    }
}

// ═══════════════════════════════════════════════════════
//  Command Table
// ═══════════════════════════════════════════════════════

struct Command {
    const char* name;
    void (*handler)(const std::vector<std::string>&);
};

static const Command commands[] = {
    {"help",            cmdHelp},
    {"query",           cmdQuery},
    {"info",            cmdInfo},
    {"msid",            cmdMsid},
    {"dump",            cmdDump},
    {"take-ownership",  cmdTakeOwnership},
    {"activate",        cmdActivate},
    {"configure-range", cmdConfigureRange},
    {"lock",            cmdLock},
    {"unlock",          cmdUnlock},
    {"range-info",      cmdRangeInfo},
    {"setup-user",      cmdSetupUser},
    {"login-admin",     cmdLoginAdmin},
    {"login-locking",   cmdLoginLocking},
    {"login-user",      cmdLoginUser},
    {"session-info",    cmdSessionInfo},
    {"close",           cmdClose},
    {"set-pin",         cmdSetPin},
    {"get-range",       cmdGetRange},
    {"s-lock",          cmdSLock},
    {"s-unlock",        cmdSUnlock},
    {"mbr-enable",      cmdMbrEnable},
    {"mbr-done",        cmdMbrDone},
    {"ds-write",        cmdDsWrite},
    {"ds-read",         cmdDsRead},
    {"set-mbr-enable",  cmdSetMbrEnable},
    {"crypto-erase",    cmdCryptoErase},
    {"configure-band",  cmdConfigureBand},
    {"lock-band",       cmdLockBand},
    {"unlock-band",     cmdUnlockBand},
    {"revert",          cmdRevert},
    {"psid-revert",     cmdPsidRevert},
    {"full-setup",      cmdFullSetup},
    {"verify-auth",     cmdVerifyAuth},
};
static const int NUM_COMMANDS = sizeof(commands) / sizeof(commands[0]);

// ═══════════════════════════════════════════════════════
//  Main REPL
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("사용법: %s <device> [--dump]\n", argv[0]);
        printf("\nInteractive SED Drive Explorer\n");
        printf("명령어를 입력하면서 드라이브를 제어합니다.\n");
        return 1;
    }

    SedDrive drive(argv[1]);
    g_drive = &drive;

    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--dump") == 0) {
            drive.enableDump();
            g_dumpEnabled = true;
        }
    }

    printf("═══ Interactive SED Explorer ═══\n");
    printf("디바이스: %s\n", argv[1]);

    // 자동 query
    auto r = drive.query();
    if (r.ok()) {
        printf("SSC: %s, ComID: 0x%04X\n", drive.sscName(), drive.comId());
        if (!drive.msid().empty())
            printf("MSID: %s\n", drive.msidString().c_str());
    } else {
        printf("조회 실패: %s\n", r.message().c_str());
        printf("'query' 명령으로 재시도하거나 디바이스를 확인하세요.\n");
    }

    printf("\n'help'로 명령어 목록 확인. 'quit'로 종료.\n\n");

    // REPL
    char line[1024];
    while (true) {
        printf("sed> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin))
            break;

        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

        auto tokens = split(line);
        if (tokens.empty()) continue;

        const auto& cmd = tokens[0];
        if (cmd == "quit" || cmd == "exit" || cmd == "q") break;

        bool found = false;
        for (int i = 0; i < NUM_COMMANDS; i++) {
            if (cmd == commands[i].name) {
                commands[i].handler(tokens);
                found = true;
                break;
            }
        }

        if (!found) {
            printf("  알 수 없는 명령: %s ('help' 입력)\n", cmd.c_str());
        }
    }

    // 세션 정리
    if (g_session) {
        g_session->close();
        g_session.reset();
    }

    printf("종료.\n");
    return 0;
}
