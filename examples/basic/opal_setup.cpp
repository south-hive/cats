/// @file opal_setup.cpp
/// Example: Full initial Opal setup (take ownership + activate + configure)

#include <cats.h>
#include <cstdio>

/// @scenario Opal 2.0 드라이브 초기 설정 (소유권 확보부터 잠금 활성화까지)
/// @precondition Opal 2.0 지원 드라이브, 공장 초기 상태 (SID == MSID)
/// @steps
///   1. 소유권 확보 — MSID로 인증하여 SID 비밀번호 변경
///   2. Locking SP 활성화 — AdminSP에서 Locking SP를 Active 상태로 전환
///   3. Range 1 설정 — 잠금 영역 구성
///   4. User1 설정 — Range 1에 대한 사용자 생성
/// @expected 모든 단계 완료 후 드라이브가 잠금 가능 상태
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <device> <new_sid_password> [--dump]\n", argv[0]);
        return 1;
    }

    const char* device = argv[1];
    const char* sidPw  = argv[2];

    libsed::SedDrive drive(device);
    for (int i = 3; i < argc; i++)
        if (std::string(argv[i]) == "--dump") drive.enableDump();

    auto r = drive.query();
    if (r.failed()) {
        printf("Discovery failed: %s\n", r.message().c_str());
        return 1;
    }

    printf("Device: %s (SSC: %s)\n\n", device, drive.sscName());

    // 1. Take ownership
    printf("[1/4] Taking ownership...\n");
    r = drive.takeOwnership(sidPw);
    if (r.failed()) {
        printf("Take ownership failed: %s\n", r.message().c_str());
        return 1;
    }

    // 2. Activate Locking SP
    printf("[2/4] Activating Locking SP...\n");
    r = drive.activateLocking(sidPw);
    if (r.failed()) {
        printf("Activate failed: %s\n", r.message().c_str());
        return 1;
    }

    // 3. Configure Range 1 (0 ~ 1M sectors)
    printf("[3/4] Configuring Range 1...\n");
    r = drive.configureRange(1, 0, 1048576, sidPw);
    if (r.failed()) {
        printf("Configure range failed: %s\n", r.message().c_str());
        return 1;
    }

    // 4. Setup User1 for Range 1
    printf("[4/4] Setting up User1...\n");
    r = drive.setupUser(1, "user1_password", 1, sidPw);
    if (r.failed()) {
        printf("Setup user failed: %s\n", r.message().c_str());
        return 1;
    }

    printf("\nOpal setup complete!\n");
    return 0;
}
