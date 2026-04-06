/// @file enterprise_band.cpp
/// Example: Enterprise SSC band management

#include <cats.h>
#include <iostream>

/// @scenario Enterprise SSC 드라이브의 Band 관리 (잠금/해제/정보 조회)
/// @precondition Enterprise SSC 지원 드라이브, BandMaster 비밀번호 설정됨
/// @steps
///   1. 커맨드 라인에서 장치 경로, Band ID, 액션(lock/unlock/info), 비밀번호 파싱
///   2. Transport 열기 및 Enterprise SSC 타입 확인
///   3. lock 시: 지정된 Band의 ReadLocked/WriteLocked=true 설정
///      unlock 시: 지정된 Band의 ReadLocked/WriteLocked=false 설정
///      info 시: Band의 Start, Length, Locked 상태 출력
/// @expected
///   - Enterprise SSC가 아닌 경우 에러 메시지 출력
///   - lock/unlock: Band 잠금 상태 변경 성공
///   - info: Band 시작 LBA, 길이, 현재 잠금 상태 정상 출력
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <device> <band_id> <password> [lock|unlock|info] [--dump] [--log]\n";
        return 1;
    }

    libsed::cli::CliOptions cliOpts;
    libsed::cli::scanFlags(argc, argv, cliOpts);

    const std::string device   = argv[1];
    uint32_t bandId            = std::stoul(argv[2]);
    const std::string password = argv[3];
    const std::string action   = (argc > 4) ? argv[4] : "info";

    libsed::initialize();

    auto rawTransport = libsed::TransportFactory::createNvme(device);
    if (!rawTransport || !rawTransport->isOpen()) {
        std::cerr << "Failed to open device: " << device << "\n";
        return 1;
    }
    auto transport = libsed::cli::applyLogging(rawTransport, cliOpts);
    auto sed = libsed::SedDevice::open(transport);
    if (!sed) {
        std::cerr << "Not a TCG SED device: " << device << "\n";
        return 1;
    }

    auto* ent = sed->asEnterprise();
    if (!ent) {
        std::cerr << "Device is not Enterprise SSC\n";
        return 1;
    }

    libsed::Result r;

    if (action == "lock") {
        r = ent->lockBand(password, bandId);
        std::cout << (r.ok() ? "Band locked" : "Lock failed") << "\n";
    } else if (action == "unlock") {
        r = ent->unlockBand(password, bandId);
        std::cout << (r.ok() ? "Band unlocked" : "Unlock failed") << "\n";
    } else {
        libsed::enterprise::BandInfo info;
        r = ent->band().getBandInfo(password, bandId, info);
        if (r.ok()) {
            std::cout << "Band " << bandId << ":\n"
                      << "  Start:  " << info.rangeStart << "\n"
                      << "  Length: " << info.rangeLength << "\n"
                      << "  Locked: " << (info.locked ? "yes" : "no") << "\n";
        }
    }

    if (r.failed()) {
        std::cerr << "Error: " << r.message() << "\n";
        return 1;
    }

    libsed::shutdown();
    return 0;
}
