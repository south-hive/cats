/// @file 06_enterprise_band.cpp
/// @brief Enterprise SSC Band 제어 예제
///
/// Enterprise SSC 드라이브의 Band를 설정하고 잠금/해제합니다.
/// Opal의 Locking Range와 유사하지만, BandMaster/EraseMaster 인증 체계를 사용합니다.
///
/// 사용법: ./facade_enterprise /dev/nvme0 <bandmaster_pw>

#include <cats.h>
#include <cstdio>

using namespace libsed;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("사용법: %s <device> <bandmaster_pw>\n", argv[0]);
        return 1;
    }

    SedDrive drive(argv[1]);
    auto r = drive.query();
    if (r.failed()) { printf("조회 실패: %s\n", r.message().c_str()); return 1; }

    if (drive.sscType() != SscType::Enterprise) {
        printf("이 드라이브는 Enterprise SSC가 아닙니다 (%s)\n", drive.sscName());
        return 1;
    }

    const char* bmPw = argv[2];

    // Band 0 설정 (0~1M sectors)
    printf("[1/3] Band 0 설정...\n");
    r = drive.configureBand(0, 0, 1048576, bmPw);
    if (r.failed()) { printf("  실패: %s\n", r.message().c_str()); return 1; }
    printf("  완료\n");

    // Band 0 잠금
    printf("[2/3] Band 0 잠금...\n");
    r = drive.lockBand(0, bmPw);
    if (r.failed()) { printf("  실패: %s\n", r.message().c_str()); return 1; }
    printf("  완료\n");

    // Band 0 잠금 해제
    printf("[3/3] Band 0 잠금 해제...\n");
    r = drive.unlockBand(0, bmPw);
    if (r.failed()) { printf("  실패: %s\n", r.message().c_str()); return 1; }
    printf("  완료\n");

    return 0;
}
