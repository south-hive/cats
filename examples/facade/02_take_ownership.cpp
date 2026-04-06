/// @file 02_take_ownership.cpp
/// @brief 소유권 확보 — MSID 읽기 → SID 비밀번호 변경
///
/// 공장 초기 상태의 드라이브에서 SID 비밀번호를 설정합니다.
/// drive.takeOwnership() 한 줄로 완료됩니다.
///
/// 사용법: ./facade_take_ownership /dev/nvme0 <new_password> [--dump]

#include <cats.h>
#include <cstdio>
#include <cstring>

using namespace libsed;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("사용법: %s <device> <new_password> [--dump]\n", argv[0]);
        return 1;
    }

    SedDrive drive(argv[1]);
    for (int i = 3; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    auto r = drive.query();
    if (r.failed()) {
        printf("조회 실패: %s\n", r.message().c_str());
        return 1;
    }
    printf("SSC: %s, MSID: %s\n", drive.sscName(), drive.msidString().c_str());

    // 소유권 확보 (내부: MSID 읽기 → SID 인증 → SID PIN 변경)
    r = drive.takeOwnership(argv[2]);
    if (r.failed()) {
        printf("소유권 확보 실패: %s\n", r.message().c_str());
        return 1;
    }
    printf("소유권 확보 완료! SID 비밀번호가 변경되었습니다.\n");

    return 0;
}
