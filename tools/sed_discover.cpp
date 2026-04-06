/// @file sed_discover.cpp
/// CLI tool: Discover and list SED-capable drives

#include <cats.h>
#include <iostream>
#include <iomanip>

int main(int argc, char* argv[]) {
    libsed::cli::CliOptions cliOpts;
    libsed::cli::scanFlags(argc, argv, cliOpts);

    // Find device positional arg (skip flags)
    std::string deviceArg;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg[0] == '-') { if (arg == "--logdir") i++; continue; }
        deviceArg = arg;
        break;
    }

    libsed::initialize();

    if (deviceArg.empty()) {
        // Enumerate all devices
        std::cout << "Scanning for SED-capable drives...\n\n";
        auto devices = libsed::TransportFactory::enumerateDevices();

        if (devices.empty()) {
            std::cout << "No block devices found. Run with a device path: "
                      << argv[0] << " /dev/sda\n";
            return 0;
        }

        for (const auto& dev : devices) {
            std::cout << dev.path;
            if (!dev.model.empty()) std::cout << "  " << dev.model;
            std::cout << "  [";
            switch (dev.type) {
                case libsed::TransportType::ATA:  std::cout << "ATA"; break;
                case libsed::TransportType::NVMe: std::cout << "NVMe"; break;
                case libsed::TransportType::SCSI: std::cout << "SCSI"; break;
                default: std::cout << "?"; break;
            }
            std::cout << "]\n";
        }
    } else {
        // Discover specific device
        auto transport = libsed::TransportFactory::createNvme(deviceArg);
        if (!transport || !transport->isOpen()) {
            std::cerr << "Failed to open " << deviceArg << "\n";
            return 1;
        }
        transport = libsed::cli::applyLogging(transport, cliOpts);

        auto device = libsed::SedDevice::open(transport);
        if (!device) {
            std::cerr << "Failed to discover " << deviceArg << "\n";
            return 1;
        }

        const auto& info = device->discovery();

        std::cout << "Device: " << deviceArg << "\n";
        std::cout << "SSC:    ";
        switch (info.primarySsc) {
            case libsed::SscType::Opal20:     std::cout << "Opal 2.0"; break;
            case libsed::SscType::Opal10:     std::cout << "Opal 1.0"; break;
            case libsed::SscType::Enterprise: std::cout << "Enterprise"; break;
            case libsed::SscType::Pyrite10:   std::cout << "Pyrite 1.0"; break;
            case libsed::SscType::Pyrite20:   std::cout << "Pyrite 2.0"; break;
            default: std::cout << "Not supported"; break;
        }
        std::cout << "\nComID:  0x" << std::hex << std::setw(4) << std::setfill('0')
                  << info.baseComId << std::dec
                  << "\nLocking: " << (info.lockingEnabled ? "enabled" : "disabled")
                  << " (" << (info.locked ? "locked" : "unlocked") << ")\n";
    }

    libsed::shutdown();
    return 0;
}
