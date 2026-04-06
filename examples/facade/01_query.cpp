/// @file 01_query.cpp
/// @brief 드라이브 조회 — Discovery + Properties + MSID 읽기
///
/// SedDrive의 가장 기본적인 사용법입니다.
/// 드라이브를 열고, query()로 모든 정보를 한 번에 조회합니다.
///
/// 사용법: ./facade_query /dev/nvme0 [--dump]

#include <cats.h>
#include <cstdio>

using namespace libsed;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("사용법: %s <device> [--dump]\n", argv[0]);
        return 1;
    }

    // 드라이브 열기
    SedDrive drive(argv[1]);

    // --dump 옵션이 있으면 패킷 hex dump 활성화
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--dump") drive.enableDump();
    }

    // 조회 (Discovery + Properties + MSID)
    auto r = drive.query();
    if (r.failed()) {
        printf("조회 실패: %s\n", r.message().c_str());
        return 1;
    }

    // 결과 출력
    printf("디바이스: %s\n", argv[1]);
    printf("SSC:      %s\n", drive.sscName());
    printf("ComID:    0x%04X (%d개 사용 가능)\n", drive.comId(), drive.numComIds());
    printf("MaxCPS:   %u bytes\n", drive.maxComPacketSize());
    printf("TPer:     %s\n", drive.info().tperPresent ? "있음" : "없음");
    printf("Locking:  %s%s%s\n",
        drive.info().lockingPresent ? "있음" : "없음",
        drive.info().lockingEnabled ? " (활성)" : " (비활성)",
        drive.info().locked ? " [잠김]" : "");
    printf("MBR:      %s%s\n",
        drive.info().mbrEnabled ? "활성" : "비활성",
        drive.info().mbrDone ? " (done)" : "");

    if (!drive.msid().empty()) {
        printf("MSID:     %s (%zu bytes)\n",
            drive.msidString().c_str(), drive.msid().size());
    } else {
        printf("MSID:     읽기 제한됨\n");
    }

    return 0;
}
