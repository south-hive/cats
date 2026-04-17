/// @file sed_discover.cpp
/// CLI tool: Discover and display SED drive information

#include <cats.h>
#include <cstdio>
#include <cstring>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <device> [--dump|--dump2]\n", argv[0]);
        return 1;
    }

    const char* device = argv[1];
    libsed::SedDrive drive(device);
    int dumpLevel = 0;
    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--dump") == 0 && dumpLevel < 1) dumpLevel = 1;
        else if (std::strcmp(argv[i], "--dump2") == 0) dumpLevel = 2;
    }
    if (dumpLevel > 0) drive.enableDump(std::cerr, dumpLevel);

    auto r = drive.query();
    if (r.failed()) {
        printf("Discovery failed: %s\n", r.message().c_str());
        return 1;
    }

    const auto& info = drive.info();

    printf("=== TCG SED Drive Discovery ===\n");
    printf("Device:   %s\n", device);
    printf("SSC:      %s\n", drive.sscName());
    printf("ComID:    0x%04X (%d available)\n", drive.comId(), drive.numComIds());
    printf("MaxCPS:   %u\n", drive.maxComPacketSize());
    printf("TPer:     %s\n", info.tperPresent ? "yes" : "no");
    printf("Locking:  %s\n", info.lockingPresent ? "yes" : "no");
    printf("  Enabled: %s\n", info.lockingEnabled ? "yes" : "no");
    printf("  Locked:  %s\n", info.locked ? "yes" : "no");
    printf("MBR:      %s%s\n",
        info.mbrEnabled ? "enabled" : "disabled",
        info.mbrDone ? " (done)" : "");

    if (!drive.msid().empty())
        printf("MSID:     %s (%zu bytes)\n", drive.msidString().c_str(), drive.msid().size());

    return 0;
}
