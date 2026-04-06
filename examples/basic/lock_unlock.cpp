/// @file lock_unlock.cpp
/// Example: Lock and unlock an Opal drive

#include <cats.h>
#include <cstdio>
#include <cstring>

/// @scenario Opal 드라이브의 잠금 및 잠금 해제 작업
/// @precondition Opal 설정 완료 (소유권 확보, Locking SP 활성화, User 설정됨)
/// @steps
///   1. 커맨드 라인에서 장치 경로, 액션(lock/unlock), 비밀번호 파싱
///   2. SedDrive로 드라이브 조회
///   3. lock/unlock 실행
///   4. Range 정보 조회하여 현재 잠금 상태 출력
/// @expected lock → ReadLocked=true/WriteLocked=true, unlock → false/false
int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <device> <lock|unlock> <password> [range] [user] [--dump]\n", argv[0]);
        return 1;
    }

    const char* device   = argv[1];
    const char* action   = argv[2];
    const char* password = argv[3];
    uint32_t rangeId = (argc > 4) ? std::stoul(argv[4]) : 0;
    uint32_t userId  = (argc > 5) ? std::stoul(argv[5]) : 1;

    libsed::SedDrive drive(device);
    for (int i = 4; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    auto r = drive.query();
    if (r.failed()) {
        printf("Discovery failed: %s\n", r.message().c_str());
        return 1;
    }

    if (std::strcmp(action, "lock") == 0) {
        printf("Locking range %u...\n", rangeId);
        r = drive.lockRange(rangeId, password, userId);
    } else if (std::strcmp(action, "unlock") == 0) {
        printf("Unlocking range %u...\n", rangeId);
        r = drive.unlockRange(rangeId, password, userId);
    } else {
        printf("Unknown action: %s (use 'lock' or 'unlock')\n", action);
        return 1;
    }

    if (r.failed()) {
        printf("Operation failed: %s\n", r.message().c_str());
        return 1;
    }

    printf("Success!\n");

    // Show range info via session
    auto s = drive.login(libsed::Uid(libsed::uid::SP_LOCKING), password,
                         libsed::uid::makeUserUid(userId));
    if (s.ok()) {
        libsed::LockingRangeInfo info;
        if (s.getRangeInfo(rangeId, info).ok()) {
            printf("Range %u status:\n", rangeId);
            printf("  ReadLocked:  %s\n", info.readLocked ? "yes" : "no");
            printf("  WriteLocked: %s\n", info.writeLocked ? "yes" : "no");
        }
    }

    return 0;
}
