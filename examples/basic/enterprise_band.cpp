/// @file enterprise_band.cpp
/// Example: Enterprise SSC band management

#include <cats.h>
#include <cstdio>
#include <cstring>

/// @scenario Enterprise SSC 드라이브의 Band 관리 (잠금/해제/정보 조회)
/// @precondition Enterprise SSC 지원 드라이브, BandMaster 비밀번호 설정됨
/// @steps
///   1. 커맨드 라인에서 장치 경로, Band ID, 비밀번호, 액션 파싱
///   2. SedDrive로 드라이브 조회 후 Enterprise SSC 확인
///   3. lock/unlock/info 실행
/// @expected Enterprise SSC가 아닌 경우 에러, 그 외 정상 동작
int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <device> <band_id> <password> [lock|unlock|info] [--dump]\n", argv[0]);
        return 1;
    }

    const char* device   = argv[1];
    uint32_t bandId      = std::stoul(argv[2]);
    const char* password = argv[3];
    const char* action   = (argc > 4) ? argv[4] : "info";

    libsed::SedDrive drive(device);
    for (int i = 4; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    auto r = drive.query();
    if (r.failed()) {
        printf("Discovery failed: %s\n", r.message().c_str());
        return 1;
    }

    if (drive.sscType() != libsed::SscType::Enterprise) {
        printf("Device is not Enterprise SSC (SSC: %s)\n", drive.sscName());
        return 1;
    }

    printf("Device: %s (Enterprise SSC)\n\n", device);

    if (std::strcmp(action, "lock") == 0) {
        r = drive.lockBand(bandId, password);
        printf("%s\n", r.ok() ? "Band locked" : "Lock failed");
    } else if (std::strcmp(action, "unlock") == 0) {
        r = drive.unlockBand(bandId, password);
        printf("%s\n", r.ok() ? "Band unlocked" : "Unlock failed");
    } else {
        // Info: use session to get band details
        auto s = drive.login(libsed::Uid(libsed::uid::SP_LOCKING), password,
                             libsed::uid::makeBandMasterUid(bandId));
        if (s.failed()) {
            printf("Login failed: %s\n", s.openResult().message().c_str());
            return 1;
        }

        libsed::LockingRangeInfo info;
        r = s.getRangeInfo(bandId, info);
        if (r.ok()) {
            printf("Band %u:\n", bandId);
            printf("  Start:  %lu\n", (unsigned long)info.rangeStart);
            printf("  Length: %lu\n", (unsigned long)info.rangeLength);
            printf("  Locked: %s\n", (info.readLocked || info.writeLocked) ? "yes" : "no");
        }
    }

    if (r.failed()) {
        printf("Error: %s\n", r.message().c_str());
        return 1;
    }

    return 0;
}
