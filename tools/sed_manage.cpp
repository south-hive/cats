/// @file sed_manage.cpp
/// CLI tool: Manage SED drives (ownership, locking, user management, revert)

#include <libsed/sed_library.h>
#include <libsed/cli/cli_common.h>
#include <iostream>
#include <string>
#include <cstring>

static void printUsage(const char* prog) {
    std::cerr
        << "TCG SED Management Tool v" << LIBSED_VERSION_STRING << "\n\n"
        << "Usage: " << prog << " <device> <command> [options]\n\n"
        << "Commands:\n"
        << "  take-ownership <new_password>          Set SID password (reads MSID automatically)\n"
        << "  activate <sid_password>                Activate Locking SP\n"
        << "  setup <sid_password> [admin1_password]  Full initial setup\n"
        << "  lock <password> [range] [user]          Lock a range\n"
        << "  unlock <password> [range] [user]        Unlock a range\n"
        << "  range-info <password> [range] [user]    Show range info\n"
        << "  configure-range <admin1_pw> <range> <start> <length>  Configure range\n"
        << "  enable-user <admin1_pw> <user_id>      Enable a user\n"
        << "  set-password <auth_pw> <user_id> <new_pw>  Set user password\n"
        << "  crypto-erase <admin1_pw> [range]       Crypto-erase a range\n"
        << "  revert <sid_password>                  Revert TPer (factory reset)\n"
        << "  psid-revert <psid>                     Emergency PSID revert\n\n"
        << "Flags:\n"
        << "  --dump      Show IF-SEND/IF-RECV packets on stderr\n"
        << "  --log       Write command log to file\n"
        << "  --logdir D  Log file directory (default: .)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) { printUsage(argv[0]); return 1; }

    libsed::cli::CliOptions cliOpts;
    libsed::cli::scanFlags(argc, argv, cliOpts);

    const std::string device = argv[1];
    const std::string command = argv[2];

    libsed::initialize();

    auto transport = libsed::TransportFactory::createNvme(device);
    if (!transport || !transport->isOpen()) {
        std::cerr << "Failed to open: " << device << "\n";
        return 1;
    }
    transport = libsed::cli::applyLogging(transport, cliOpts);

    auto sed = libsed::SedDevice::open(transport);
    if (!sed) {
        std::cerr << "Failed to discover: " << device << "\n";
        return 1;
    }

    const auto& info = sed->discovery();
    std::cout << "Device: " << device << " (SSC: "
              << static_cast<int>(info.primarySsc) << ")\n\n";

    libsed::Result r;

    // ── Commands ─────────────────────────────────────
    if (command == "take-ownership") {
        if (argc < 4) { std::cerr << "Missing password\n"; return 1; }
        r = sed->takeOwnership(argv[3]);
        std::cout << (r.ok() ? "Ownership taken.\n" : "Failed.\n");

    } else if (command == "activate") {
        if (argc < 4) { std::cerr << "Missing SID password\n"; return 1; }
        auto* opal = sed->asOpal();
        if (!opal) { std::cerr << "Not Opal\n"; return 1; }
        r = opal->activateLockingSP(argv[3]);
        std::cout << (r.ok() ? "Locking SP activated.\n" : "Failed.\n");

    } else if (command == "setup") {
        if (argc < 4) { std::cerr << "Missing SID password\n"; return 1; }
        std::string admin1 = (argc > 4) ? argv[4] : argv[3];
        auto* opal = sed->asOpal();
        if (!opal) { std::cerr << "Not Opal\n"; return 1; }
        r = opal->initialSetup(argv[3], admin1);
        std::cout << (r.ok() ? "Setup complete.\n" : "Setup failed.\n");

    } else if (command == "lock") {
        if (argc < 4) { std::cerr << "Missing password\n"; return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        uint32_t user  = (argc > 5) ? std::stoul(argv[5]) : 1;
        r = sed->lockRange(range, argv[3], user);
        std::cout << (r.ok() ? "Locked.\n" : "Lock failed.\n");

    } else if (command == "unlock") {
        if (argc < 4) { std::cerr << "Missing password\n"; return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        uint32_t user  = (argc > 5) ? std::stoul(argv[5]) : 1;
        r = sed->unlockRange(range, argv[3], user);
        std::cout << (r.ok() ? "Unlocked.\n" : "Unlock failed.\n");

    } else if (command == "range-info") {
        if (argc < 4) { std::cerr << "Missing password\n"; return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        uint32_t user  = (argc > 5) ? std::stoul(argv[5]) : 1;
        libsed::LockingRangeInfo ri;
        r = sed->getRangeInfo(range, ri, argv[3], user);
        if (r.ok()) {
            std::cout << "Range " << ri.rangeId << ":\n"
                      << "  Start:          " << ri.rangeStart << "\n"
                      << "  Length:         " << ri.rangeLength << "\n"
                      << "  ReadLockEn:     " << ri.readLockEnabled << "\n"
                      << "  WriteLockEn:    " << ri.writeLockEnabled << "\n"
                      << "  ReadLocked:     " << ri.readLocked << "\n"
                      << "  WriteLocked:    " << ri.writeLocked << "\n";
        } else {
            std::cerr << "Failed to get range info.\n";
        }

    } else if (command == "configure-range") {
        if (argc < 7) { std::cerr << "Usage: configure-range <pw> <range> <start> <len>\n"; return 1; }
        r = sed->configureRange(std::stoul(argv[4]),
                                 std::stoull(argv[5]), std::stoull(argv[6]),
                                 argv[3]);
        std::cout << (r.ok() ? "Range configured.\n" : "Failed.\n");

    } else if (command == "enable-user") {
        if (argc < 5) { std::cerr << "Usage: enable-user <admin1_pw> <user_id>\n"; return 1; }
        auto* opal = sed->asOpal();
        if (!opal) { std::cerr << "Not Opal\n"; return 1; }
        r = opal->user().enableUser(argv[3], std::stoul(argv[4]));
        std::cout << (r.ok() ? "User enabled.\n" : "Failed.\n");

    } else if (command == "set-password") {
        if (argc < 6) { std::cerr << "Usage: set-password <auth_pw> <user_id> <new_pw>\n"; return 1; }
        auto* opal = sed->asOpal();
        if (!opal) { std::cerr << "Not Opal\n"; return 1; }
        r = opal->user().setUserPassword(argv[3], std::stoul(argv[4]), argv[5], true);
        std::cout << (r.ok() ? "Password set.\n" : "Failed.\n");

    } else if (command == "crypto-erase") {
        if (argc < 4) { std::cerr << "Missing admin1 password\n"; return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        auto* opal = sed->asOpal();
        if (!opal) { std::cerr << "Not Opal\n"; return 1; }
        r = opal->locking().cryptoErase(argv[3], range);
        std::cout << (r.ok() ? "Crypto-erased.\n" : "Failed.\n");

    } else if (command == "revert") {
        if (argc < 4) { std::cerr << "Missing SID password\n"; return 1; }
        r = sed->revert(argv[3]);
        std::cout << (r.ok() ? "Reverted to factory state.\n" : "Revert failed.\n");

    } else if (command == "psid-revert") {
        if (argc < 4) { std::cerr << "Missing PSID\n"; return 1; }
        auto* opal = sed->asOpal();
        if (!opal) { std::cerr << "Not Opal\n"; return 1; }
        r = opal->admin().psidRevert(argv[3]);
        std::cout << (r.ok() ? "PSID revert complete.\n" : "PSID revert failed.\n");

    } else {
        std::cerr << "Unknown command: " << command << "\n";
        printUsage(argv[0]);
        return 1;
    }

    if (r.failed()) {
        std::cerr << "Error: " << r.message() << "\n";
    }

    libsed::shutdown();
    return r.ok() ? 0 : 1;
}
