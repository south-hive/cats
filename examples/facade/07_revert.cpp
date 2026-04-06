/// @file 07_revert.cpp
/// @brief 공장 초기화 — SID Revert 또는 PSID Revert
///
/// 드라이브를 공장 초기 상태로 되돌립니다.
/// SID 비밀번호를 알면 revert(), 모르면 psidRevert()를 사용합니다.
///
/// 주의: 모든 설정과 데이터가 삭제됩니다!
///
/// 사용법:
///   ./facade_revert /dev/nvme0 sid <sid_password> [--dump]
///   ./facade_revert /dev/nvme0 psid <psid_from_label> [--dump]

#include <cats.h>
#include <cstdio>
#include <cstring>

using namespace libsed;

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("사용법:\n");
        printf("  %s <device> sid <sid_password> [--dump]\n", argv[0]);
        printf("  %s <device> psid <psid_from_label> [--dump]\n", argv[0]);
        return 1;
    }

    const char* device = argv[1];
    const std::string mode = argv[2];
    const char* password = argv[3];

    SedDrive drive(device);
    for (int i = 4; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    auto r = drive.query();
    if (r.failed()) { printf("조회 실패: %s\n", r.message().c_str()); return 1; }

    printf("디바이스: %s (%s)\n", device, drive.sscName());

    if (mode == "sid") {
        printf("SID Revert 실행 중...\n");
        r = drive.revert(password);
    } else if (mode == "psid") {
        printf("PSID Revert 실행 중...\n");
        r = drive.psidRevert(password);
    } else {
        printf("알 수 없는 모드: %s (sid 또는 psid)\n", mode.c_str());
        return 1;
    }

    if (r.failed()) {
        printf("Revert 실패: %s\n", r.message().c_str());
        return 1;
    }

    printf("공장 초기화 완료!\n");
    return 0;
}
