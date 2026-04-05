/// @file lock_unlock.cpp
/// Example: Lock and unlock an Opal drive

#include <libsed/sed_library.h>
#include <iostream>
#include <string>

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " <device> <lock|unlock> <password> [range_id] [user_id]\n";
}

/// @scenario Opal 드라이브의 잠금 및 잠금 해제 작업
/// @precondition Opal 2.0 설정 완료 (소유권 확보, Locking SP 활성화, Admin1 비밀번호 설정됨)
/// @steps
///   1. 커맨드 라인에서 장치 경로, 액션(lock/unlock), 비밀번호 파싱
///   2. Transport 열기 및 고수준 API를 통한 세션 시작
///   3. lock 시: Global Range ReadLocked=true, WriteLocked=true 설정
///      unlock 시: Global Range ReadLocked=false, WriteLocked=false 설정
///   4. Range 정보 조회하여 현재 잠금 상태 출력
/// @expected
///   - lock 액션: ReadLocked=true, WriteLocked=true로 전환
///   - unlock 액션: ReadLocked=false, WriteLocked=false로 전환
///   - 잘못된 액션 입력 시 사용법 출력
int main(int argc, char* argv[]) {
    if (argc < 4) { printUsage(argv[0]); return 1; }

    const std::string device   = argv[1];
    const std::string action   = argv[2];
    const std::string password = argv[3];
    uint32_t rangeId = (argc > 4) ? std::stoul(argv[4]) : 0;
    uint32_t userId  = (argc > 5) ? std::stoul(argv[5]) : 1;

    libsed::initialize();

    auto sed = libsed::SedDevice::open(device);
    if (!sed) {
        std::cerr << "Failed to open device\n";
        return 1;
    }

    libsed::Result r;
    if (action == "lock") {
        std::cout << "Locking range " << rangeId << "...\n";
        r = sed->lockRange(rangeId, password, userId);
    } else if (action == "unlock") {
        std::cout << "Unlocking range " << rangeId << "...\n";
        r = sed->unlockRange(rangeId, password, userId);
    } else {
        printUsage(argv[0]);
        return 1;
    }

    if (r.failed()) {
        std::cerr << "Operation failed: " << r.message() << "\n";
        return 1;
    }

    std::cout << "Success!\n";

    // Show range info
    libsed::LockingRangeInfo info;
    r = sed->getRangeInfo(rangeId, info, password, userId);
    if (r.ok()) {
        std::cout << "Range " << rangeId << " status:\n"
                  << "  ReadLocked:  " << (info.readLocked ? "yes" : "no") << "\n"
                  << "  WriteLocked: " << (info.writeLocked ? "yes" : "no") << "\n";
    }

    libsed::shutdown();
    return 0;
}
