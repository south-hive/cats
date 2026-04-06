/// @file 03_opal_full_setup.cpp
/// @brief Opal 전체 설정 — 소유권 → 활성화 → Range 설정 → User 설정
///
/// Opal 드라이브를 공장 초기 상태에서 완전히 설정합니다.
/// AppNote 3~7에 해당하는 전체 플로우입니다.
///
/// 사용법: ./facade_opal_setup /dev/nvme0 <sid_pw> <admin1_pw> <user1_pw> [--dump]

#include <cats.h>
#include <cstdio>
#include <cstring>

using namespace libsed;

int main(int argc, char* argv[]) {
    if (argc < 5) {
        printf("사용법: %s <device> <sid_pw> <admin1_pw> <user1_pw> [--dump]\n", argv[0]);
        return 1;
    }

    const char* device   = argv[1];
    const char* sidPw    = argv[2];
    const char* admin1Pw = argv[3];
    const char* user1Pw  = argv[4];

    SedDrive drive(device);
    for (int i = 5; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    auto r = drive.query();
    if (r.failed()) { printf("조회 실패: %s\n", r.message().c_str()); return 1; }
    printf("디바이스: %s (%s)\n\n", device, drive.sscName());

    // 1. 소유권 확보
    printf("[1/5] 소유권 확보...\n");
    r = drive.takeOwnership(sidPw);
    if (r.failed()) { printf("  실패: %s\n", r.message().c_str()); return 1; }
    printf("  완료\n");

    // 2. Locking SP 활성화
    printf("[2/5] Locking SP 활성화...\n");
    r = drive.activateLocking(sidPw);
    if (r.failed()) { printf("  실패: %s\n", r.message().c_str()); return 1; }
    printf("  완료\n");

    // 3. Admin1 비밀번호 설정 + Range 설정
    printf("[3/5] Range 1 설정 (0~1M sectors)...\n");
    r = drive.configureRange(1, 0, 1048576, admin1Pw);
    if (r.failed()) { printf("  실패: %s\n", r.message().c_str()); return 1; }
    printf("  완료\n");

    // 4. User1 설정 (활성화 + 비밀번호 + Range 할당)
    printf("[4/5] User1 설정...\n");
    r = drive.setupUser(1, user1Pw, 1, admin1Pw);
    if (r.failed()) { printf("  실패: %s\n", r.message().c_str()); return 1; }
    printf("  완료\n");

    // 5. 잠금 테스트
    printf("[5/5] Range 1 잠금 테스트...\n");
    r = drive.lockRange(1, user1Pw, 1);
    if (r.failed()) { printf("  잠금 실패: %s\n", r.message().c_str()); return 1; }
    printf("  잠금 완료\n");

    r = drive.unlockRange(1, user1Pw, 1);
    if (r.failed()) { printf("  해제 실패: %s\n", r.message().c_str()); return 1; }
    printf("  해제 완료\n");

    printf("\nOpal 설정 완료!\n");
    return 0;
}
