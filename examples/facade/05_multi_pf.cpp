/// @file 05_multi_pf.cpp
/// @brief Multi-PF 예제 — 여러 ComID를 가진 드라이브 제어
///
/// NVMe 디바이스는 여러 Physical Function(PF)을 가질 수 있습니다.
/// 각 PF는 별도의 ComID를 사용합니다.
/// Discovery에서 baseComId와 numComIds를 확인한 후,
/// setComId()로 특정 PF를 선택할 수 있습니다.
///
/// 사용법: ./facade_multi_pf /dev/nvme0

#include <cats.h>
#include <cstdio>

using namespace libsed;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("사용법: %s <device>\n", argv[0]);
        return 1;
    }

    SedDrive drive(argv[1]);
    auto r = drive.query();
    if (r.failed()) { printf("조회 실패: %s\n", r.message().c_str()); return 1; }

    printf("디바이스: %s (%s)\n", argv[1], drive.sscName());
    printf("Base ComID: 0x%04X\n", drive.comId());
    printf("NumComIDs:  %d\n\n", drive.numComIds());

    if (drive.numComIds() <= 1) {
        printf("이 드라이브는 단일 ComID만 사용합니다.\n");
        return 0;
    }

    // 각 ComID에 대해 StackReset 시도
    uint16_t base = drive.comId();
    for (uint16_t i = 0; i < drive.numComIds(); i++) {
        uint16_t cid = base + i;
        printf("ComID 0x%04X: ", cid);

        drive.setComId(cid);
        r = drive.api().stackReset(drive.transport(), cid);
        printf("StackReset %s\n", r.ok() ? "OK" : r.message().c_str());
    }

    // 원래 ComID로 복원
    drive.setComId(base);

    // 또는 생성 시 명시적 ComID 지정:
    // SedDrive pf1(argv[1], 0x0002);  // PF1 전용

    return 0;
}
