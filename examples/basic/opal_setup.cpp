/// @file opal_setup.cpp
/// Example: Full initial Opal setup (take ownership + activate + configure)

#include <libsed/sed_library.h>
#include <iostream>
#include <string>

/// @scenario Opal 2.0 드라이브 초기 설정 (소유권 확보부터 잠금 활성화까지)
/// @precondition Opal 2.0 지원 드라이브, 공장 초기 상태 (SID == MSID)
/// @steps
///   1. 소유권 확보 — MSID로 인증하여 SID 비밀번호 변경
///   2. Locking SP 활성화 — AdminSP에서 Locking SP를 Active 상태로 전환
///   3. Admin1 비밀번호 설정 — Locking SP의 관리자 비밀번호 변경
///   4. 전역 잠금 활성화 — Global Range의 ReadLockEnabled/WriteLockEnabled 설정
/// @expected
///   - Step 1: SID 비밀번호 변경 성공 (MethodStatus::Success)
///   - Step 2: Locking SP 활성화 성공
///   - Step 3: Admin1 비밀번호 설정 성공
///   - Step 4: 전역 잠금 활성화 성공
///   - 모든 단계 완료 후 드라이브가 잠금 가능 상태로 전환됨
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <device> <new_sid_password>\n";
        return 1;
    }

    const std::string device = argv[1];
    const std::string sidPassword = argv[2];

    libsed::initialize();

    auto sed = libsed::SedDevice::open(device);
    if (!sed) {
        std::cerr << "Failed to open device\n";
        return 1;
    }

    auto* opal = sed->asOpal();
    if (!opal) {
        std::cerr << "Device is not Opal\n";
        return 1;
    }

    // 1. Take ownership
    std::cout << "[1/4] Taking ownership...\n";
    auto r = opal->takeOwnership(sidPassword);
    if (r.failed()) {
        std::cerr << "Take ownership failed: " << r.message() << "\n";
        return 1;
    }

    // 2. Activate Locking SP
    std::cout << "[2/4] Activating Locking SP...\n";
    r = opal->activateLockingSP(sidPassword);
    if (r.failed()) {
        std::cerr << "Activate failed: " << r.message() << "\n";
        return 1;
    }

    // 3. Set Admin1 password (same as SID for simplicity)
    std::cout << "[3/4] Setting Admin1 password...\n";
    r = opal->user().setAdmin1Password(sidPassword, sidPassword);
    if (r.failed()) {
        std::cerr << "Set Admin1 password failed: " << r.message() << "\n";
        return 1;
    }

    // 4. Enable global locking
    std::cout << "[4/4] Enabling global locking...\n";
    r = opal->locking().setLockEnabled(sidPassword, 0, true, true);
    if (r.failed()) {
        std::cerr << "Enable locking failed: " << r.message() << "\n";
        return 1;
    }

    std::cout << "Opal setup complete!\n";
    libsed::shutdown();
    return 0;
}
