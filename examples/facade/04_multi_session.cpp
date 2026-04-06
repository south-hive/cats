/// @file 04_multi_session.cpp
/// @brief Multi-Session 예제 — 두 개의 세션을 동시에 열어서 사용
///
/// SedSession은 RAII 패턴으로, 소멸 시 자동으로 세션을 닫습니다.
/// 여러 세션을 동시에 열 수 있어 복잡한 TC 시나리오를 구현할 수 있습니다.
///
/// 사용법: ./facade_multi_session /dev/nvme0 <sid_pw> <admin1_pw> [--dump]

#include <cats.h>
#include <cstdio>
#include <cstring>

using namespace libsed;

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("사용법: %s <device> <sid_pw> <admin1_pw> [--dump]\n", argv[0]);
        return 1;
    }

    SedDrive drive(argv[1]);
    for (int i = 4; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    auto r = drive.query();
    if (r.failed()) { printf("조회 실패: %s\n", r.message().c_str()); return 1; }

    // 세션 1: AdminSP에 SID로 로그인
    printf("세션 1: AdminSP (SID 인증)...\n");
    auto s1 = drive.login(Uid(uid::SP_ADMIN), argv[2], Uid(uid::AUTH_SID));
    if (s1.failed()) {
        printf("  세션 1 열기 실패: %s\n", s1.openResult().message().c_str());
        return 1;
    }
    printf("  세션 1 열림 (TSN=%u)\n", s1.raw().tperSessionNumber());

    // 세션 1에서 작업...
    // s1.setPin(Uid(uid::CPIN_SID), "new_password");

    // 세션 1 닫기
    s1.close();
    printf("  세션 1 닫힘\n");

    // 세션 2: LockingSP에 Admin1으로 로그인
    printf("세션 2: LockingSP (Admin1 인증)...\n");
    auto s2 = drive.login(Uid(uid::SP_LOCKING), argv[3], Uid(uid::AUTH_ADMIN1));
    if (s2.failed()) {
        printf("  세션 2 열기 실패: %s\n", s2.openResult().message().c_str());
        return 1;
    }
    printf("  세션 2 열림 (TSN=%u)\n", s2.raw().tperSessionNumber());

    // 세션 2에서 Range 정보 조회
    LockingRangeInfo info;
    r = s2.getRangeInfo(0, info);  // Global Range
    if (r.ok()) {
        printf("  Global Range: ReadLocked=%s, WriteLocked=%s\n",
            info.readLocked ? "yes" : "no",
            info.writeLocked ? "yes" : "no");
    }

    // 세션 2는 소멸자가 자동으로 닫음
    printf("세션 2 자동 닫힘 (소멸자)\n");

    return 0;
}
