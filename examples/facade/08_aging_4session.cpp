/// @file 08_aging_4session.cpp
/// @brief 4-Session Aging Test — 반복적 세션 스트레스 테스트
///
/// 4개의 세션을 활용하여 드라이브를 반복적으로 스트레스 테스트합니다.
///
///   세션 1 (AdminSP/SID)     — SID PIN 변경 (round-trip)
///   세션 2 (LockingSP/Admin1) — Range 설정 + User 관리 + MBR + DataStore
///   세션 3 (LockingSP/User1)  — Range 1 Lock/Unlock 반복
///   세션 4 (LockingSP/User2)  — Range 2 Lock/Unlock 반복
///
/// 매 사이클마다 4개 세션을 열고, 작업 후 닫습니다.
/// 드라이브 상태 변경을 수반하므로, 초기 설정과 최종 정리를 포함합니다.
///
/// 사용법: ./facade_aging /dev/nvme0 <cycles> [--dump]
///
/// 주의: 이 테스트는 드라이브 상태를 변경합니다!
///       테스트 종료 시 공장 초기화(revert)를 수행합니다.

#include <cats.h>
#include <cstdio>
#include <cstring>
#include <chrono>

using namespace libsed;

// ── 테스트 설정 ──
static const char* SID_PW      = "aging_sid_001";
static const char* SID_PW_ALT  = "aging_sid_002";
static const char* ADMIN1_PW   = "aging_adm1_001";
static const char* USER1_PW    = "aging_usr1_001";
static const char* USER2_PW    = "aging_usr2_001";

struct Stats {
    int cycles     = 0;
    int s1_pass    = 0;  // AdminSP SID
    int s2_pass    = 0;  // LockingSP Admin1
    int s3_pass    = 0;  // LockingSP User1
    int s4_pass    = 0;  // LockingSP User2
    int s1_fail    = 0;
    int s2_fail    = 0;
    int s3_fail    = 0;
    int s4_fail    = 0;

    int totalPass() const { return s1_pass + s2_pass + s3_pass + s4_pass; }
    int totalFail() const { return s1_fail + s2_fail + s3_fail + s4_fail; }

    void print(double elapsed) const {
        printf("\n══════════════════════════════════════════\n");
        printf("  Aging 결과: %d cycles (%.1f초)\n", cycles, elapsed);
        printf("──────────────────────────────────────────\n");
        printf("  S1 AdminSP/SID:      %4d pass / %d fail\n", s1_pass, s1_fail);
        printf("  S2 LockingSP/Admin1: %4d pass / %d fail\n", s2_pass, s2_fail);
        printf("  S3 LockingSP/User1:  %4d pass / %d fail\n", s3_pass, s3_fail);
        printf("  S4 LockingSP/User2:  %4d pass / %d fail\n", s4_pass, s4_fail);
        printf("──────────────────────────────────────────\n");
        printf("  Total: %d pass / %d fail\n", totalPass(), totalFail());
        if (cycles > 0)
            printf("  Throughput: %.1f sessions/sec\n", totalPass() / elapsed);
        printf("══════════════════════════════════════════\n");
    }
};

// ── 세션 1: AdminSP/SID — PIN round-trip ──
// SID 비밀번호를 A→B→A로 변경 (매 사이클)
static bool runSession1(SedDrive& drive, int cycle) {
    const char* curPw = (cycle % 2 == 0) ? SID_PW : SID_PW_ALT;
    const char* newPw = (cycle % 2 == 0) ? SID_PW_ALT : SID_PW;

    auto s = drive.login(Uid(uid::SP_ADMIN), curPw, Uid(uid::AUTH_SID));
    if (s.failed()) {
        printf("    S1 login fail: %s\n", s.openResult().message().c_str());
        return false;
    }

    // SID PIN 변경
    auto r = s.setPin(Uid(uid::CPIN_SID), newPw);
    if (r.failed()) {
        printf("    S1 setPin fail: %s\n", r.message().c_str());
        return false;
    }

    s.close();
    return true;
}

// ── 세션 2: LockingSP/Admin1 — Range/MBR/DataStore 관리 ──
// Range 재설정 + MBR toggle + DataStore 읽기/쓰기
static bool runSession2(SedDrive& drive, int cycle) {
    auto s = drive.login(Uid(uid::SP_LOCKING), ADMIN1_PW, Uid(uid::AUTH_ADMIN1));
    if (s.failed()) {
        printf("    S2 login fail: %s\n", s.openResult().message().c_str());
        return false;
    }

    // Range 1 재설정 (크기 변경)
    uint64_t len1 = 1048576 + (cycle % 16) * 65536;  // 1M + 가변
    auto r = s.setRange(1, 0, len1);
    if (r.failed()) {
        printf("    S2 setRange(1) fail: %s\n", r.message().c_str());
        return false;
    }

    // Range 2 재설정
    uint64_t len2 = 2097152 + (cycle % 8) * 131072;  // 2M + 가변
    r = s.setRange(2, len1, len2);
    if (r.failed()) {
        printf("    S2 setRange(2) fail: %s\n", r.message().c_str());
        return false;
    }

    // Range 정보 조회 (검증)
    LockingRangeInfo info;
    r = s.getRangeInfo(1, info);
    if (r.failed()) {
        printf("    S2 getRangeInfo fail: %s\n", r.message().c_str());
        return false;
    }

    // MBR Done toggle
    r = s.setMbrDone(cycle % 2 == 0);
    if (r.failed()) {
        // MBR 미지원 드라이브 — 무시
    }

    // DataStore 쓰기/읽기
    Bytes writeData(32);
    for (size_t i = 0; i < writeData.size(); i++)
        writeData[i] = static_cast<uint8_t>((cycle + i) & 0xFF);

    r = s.writeDataStore(0, writeData);
    if (r.ok()) {
        Bytes readData;
        r = s.readDataStore(0, 32, readData);
        if (r.ok() && readData != writeData) {
            printf("    S2 DataStore mismatch!\n");
            return false;
        }
    }
    // DataStore 미지원 시 무시

    s.close();
    return true;
}

// ── 세션 3: LockingSP/User1 — Range 1 Lock/Unlock ──
static bool runSession3(SedDrive& drive, int cycle) {
    auto s = drive.login(Uid(uid::SP_LOCKING), USER1_PW, uid::makeUserUid(1));
    if (s.failed()) {
        printf("    S3 login fail: %s\n", s.openResult().message().c_str());
        return false;
    }

    // Lock
    auto r = s.lockRange(1);
    if (r.failed()) {
        printf("    S3 lock fail: %s\n", r.message().c_str());
        return false;
    }

    // 잠금 상태 확인
    LockingRangeInfo info;
    r = s.getRangeInfo(1, info);
    if (r.ok() && (!info.readLocked || !info.writeLocked)) {
        printf("    S3 lock verify fail (R=%d W=%d)\n",
            info.readLocked, info.writeLocked);
        return false;
    }

    // Unlock
    r = s.unlockRange(1);
    if (r.failed()) {
        printf("    S3 unlock fail: %s\n", r.message().c_str());
        return false;
    }

    // 해제 상태 확인
    r = s.getRangeInfo(1, info);
    if (r.ok() && (info.readLocked || info.writeLocked)) {
        printf("    S3 unlock verify fail (R=%d W=%d)\n",
            info.readLocked, info.writeLocked);
        return false;
    }

    s.close();
    return true;
}

// ── 세션 4: LockingSP/User2 — Range 2 Lock/Unlock ──
static bool runSession4(SedDrive& drive, int cycle) {
    auto s = drive.login(Uid(uid::SP_LOCKING), USER2_PW, uid::makeUserUid(2));
    if (s.failed()) {
        printf("    S4 login fail: %s\n", s.openResult().message().c_str());
        return false;
    }

    // Lock
    auto r = s.lockRange(2);
    if (r.failed()) {
        printf("    S4 lock fail: %s\n", r.message().c_str());
        return false;
    }

    // Unlock
    r = s.unlockRange(2);
    if (r.failed()) {
        printf("    S4 unlock fail: %s\n", r.message().c_str());
        return false;
    }

    s.close();
    return true;
}

// ═══════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("사용법: %s <device> <cycles> [--dump]\n", argv[0]);
        printf("\n");
        printf("4개 세션을 사용한 aging 스트레스 테스트:\n");
        printf("  S1: AdminSP/SID     — SID PIN round-trip\n");
        printf("  S2: LockingSP/Admin1 — Range 재설정 + MBR + DataStore\n");
        printf("  S3: LockingSP/User1  — Range 1 Lock/Unlock\n");
        printf("  S4: LockingSP/User2  — Range 2 Lock/Unlock\n");
        printf("\n주의: 드라이브 상태를 변경합니다! 종료 시 revert 수행.\n");
        return 1;
    }

    const char* device = argv[1];
    int maxCycles = std::atoi(argv[2]);
    bool dump = false;
    for (int i = 3; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) dump = true;

    // ── 드라이브 열기 ──
    SedDrive drive(device);
    if (dump) drive.enableDump();

    printf("═══ 4-Session Aging Test ═══\n");
    printf("디바이스: %s\n", device);
    printf("사이클:   %d\n\n", maxCycles);

    auto r = drive.query();
    if (r.failed()) {
        printf("조회 실패: %s\n", r.message().c_str());
        return 1;
    }
    printf("SSC: %s, ComID: 0x%04X\n", drive.sscName(), drive.comId());

    // ── 초기 설정: 소유권 → 활성화 → Range → User ──
    printf("\n── 초기 설정 ──\n");

    printf("  소유권 확보...\n");
    r = drive.takeOwnership(SID_PW);
    if (r.failed()) {
        printf("  실패: %s\n", r.message().c_str());
        return 1;
    }

    printf("  Locking SP 활성화...\n");
    r = drive.activateLocking(SID_PW);
    if (r.failed()) {
        printf("  실패: %s\n", r.message().c_str());
        return 1;
    }

    printf("  Range 1 설정...\n");
    r = drive.configureRange(1, 0, 1048576, ADMIN1_PW);
    if (r.failed()) {
        printf("  실패: %s\n", r.message().c_str());
        return 1;
    }

    printf("  Range 2 설정...\n");
    r = drive.configureRange(2, 1048576, 2097152, ADMIN1_PW);
    if (r.failed()) {
        printf("  실패: %s\n", r.message().c_str());
        return 1;
    }

    printf("  User1 설정 (Range 1)...\n");
    r = drive.setupUser(1, USER1_PW, 1, ADMIN1_PW);
    if (r.failed()) {
        printf("  실패: %s\n", r.message().c_str());
        return 1;
    }

    printf("  User2 설정 (Range 2)...\n");
    r = drive.setupUser(2, USER2_PW, 2, ADMIN1_PW);
    if (r.failed()) {
        printf("  실패: %s\n", r.message().c_str());
        return 1;
    }

    printf("  초기 설정 완료\n\n");

    // ── Aging 루프 ──
    printf("── Aging 시작 (%d cycles) ──\n", maxCycles);
    Stats stats;
    auto startTime = std::chrono::steady_clock::now();

    for (int cycle = 0; cycle < maxCycles; cycle++) {
        stats.cycles = cycle + 1;
        printf("[%d/%d] ", cycle + 1, maxCycles);

        // S1: AdminSP/SID — PIN round-trip
        if (runSession1(drive, cycle)) {
            stats.s1_pass++;
            printf("S1:OK ");
        } else {
            stats.s1_fail++;
            printf("S1:NG ");
        }

        // S2: LockingSP/Admin1 — Range/MBR/DataStore
        if (runSession2(drive, cycle)) {
            stats.s2_pass++;
            printf("S2:OK ");
        } else {
            stats.s2_fail++;
            printf("S2:NG ");
        }

        // S3: LockingSP/User1 — Range 1 Lock/Unlock
        if (runSession3(drive, cycle)) {
            stats.s3_pass++;
            printf("S3:OK ");
        } else {
            stats.s3_fail++;
            printf("S3:NG ");
        }

        // S4: LockingSP/User2 — Range 2 Lock/Unlock
        if (runSession4(drive, cycle)) {
            stats.s4_pass++;
            printf("S4:OK ");
        } else {
            stats.s4_fail++;
            printf("S4:NG ");
        }

        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - startTime).count();
        printf("(%.1fs)\n", elapsed);

        // 연속 실패 시 중단
        if (stats.s1_fail > 3 || stats.s2_fail > 3 ||
            stats.s3_fail > 3 || stats.s4_fail > 3) {
            printf("\n연속 실패 — aging 중단\n");
            break;
        }
    }

    auto endTime = std::chrono::steady_clock::now();
    double totalElapsed = std::chrono::duration<double>(endTime - startTime).count();

    // ── 정리: SID PIN 복원 → Revert ──
    printf("\n── 정리 ──\n");

    // SID PIN이 현재 어느 상태인지 결정
    const char* finalSidPw = (stats.cycles % 2 == 0) ? SID_PW : SID_PW_ALT;

    printf("  Revert (SID: %s)...\n", finalSidPw);
    r = drive.revert(finalSidPw);
    if (r.failed()) {
        printf("  Revert 실패: %s\n", r.message().c_str());
        printf("  다른 SID PIN으로 재시도...\n");
        const char* altPw = (finalSidPw == SID_PW) ? SID_PW_ALT : SID_PW;
        r = drive.revert(altPw);
        if (r.failed()) {
            printf("  Revert 재시도 실패: %s\n", r.message().c_str());
        }
    }
    if (r.ok()) printf("  공장 초기화 완료\n");

    // ── 결과 ──
    stats.print(totalElapsed);

    return (stats.totalFail() == 0) ? 0 : 1;
}
