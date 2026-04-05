/// @file discovery.cpp
/// Example: Perform Level 0 Discovery and display drive information

#include <libsed/sed_library.h>
#include <iostream>
#include <iomanip>

/// @scenario Level 0 Discovery를 수행하여 드라이브 정보 표시
/// @precondition TCG SED를 지원하는 NVMe/ATA/SCSI 드라이브가 연결되어 있어야 함
/// @steps
///   1. 커맨드 라인에서 장치 경로를 받아 Transport 열기
///   2. Level 0 Discovery 실행 (Protocol 0x01, ComID 0x0001)
///   3. Discovery 응답 파싱하여 DiscoveryInfo 생성
///   4. 드라이브 정보 출력 (전송 타입, SSC 타입, ComID, 잠금 상태, MBR 상태 등)
/// @expected
///   - Transport 열기 성공
///   - Discovery 응답 정상 수신 및 파싱
///   - SSC 타입 (Opal 2.0/1.0, Enterprise, Pyrite) 정상 감지
///   - TPer, Locking Feature 존재 확인
///   - baseComId, numComIds 유효한 값 반환
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <device>\n"
                  << "Example: " << argv[0] << " /dev/sda\n";
        return 1;
    }

    libsed::initialize();

    auto device = libsed::SedDevice::open(argv[1]);
    if (!device) {
        std::cerr << "Failed to open device: " << argv[1] << "\n";
        return 1;
    }

    const auto& info = device->discovery();

    std::cout << "=== TCG SED Drive Discovery ===\n";
    std::cout << "Device:    " << argv[1] << "\n";
    std::cout << "Transport: ";
    switch (device->transportType()) {
        case libsed::TransportType::ATA:  std::cout << "ATA"; break;
        case libsed::TransportType::NVMe: std::cout << "NVMe"; break;
        case libsed::TransportType::SCSI: std::cout << "SCSI"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << "\n";

    std::cout << "SSC Type:  ";
    switch (info.primarySsc) {
        case libsed::SscType::Opal20:     std::cout << "Opal 2.0"; break;
        case libsed::SscType::Opal10:     std::cout << "Opal 1.0"; break;
        case libsed::SscType::Enterprise: std::cout << "Enterprise"; break;
        case libsed::SscType::Pyrite10:   std::cout << "Pyrite 1.0"; break;
        case libsed::SscType::Pyrite20:   std::cout << "Pyrite 2.0"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << "\n";

    std::cout << "Base ComID: 0x" << std::hex << std::setw(4) << std::setfill('0')
              << info.baseComId << std::dec << "\n";
    std::cout << "TPer:       " << (info.tperPresent ? "yes" : "no") << "\n";
    std::cout << "Locking:    " << (info.lockingPresent ? "yes" : "no") << "\n";
    std::cout << "  Enabled:  " << (info.lockingEnabled ? "yes" : "no") << "\n";
    std::cout << "  Locked:   " << (info.locked ? "yes" : "no") << "\n";
    std::cout << "MBR:        " << (info.mbrEnabled ? "enabled" : "disabled") << "\n";
    std::cout << "  Done:     " << (info.mbrDone ? "yes" : "no") << "\n";

    libsed::shutdown();
    return 0;
}
