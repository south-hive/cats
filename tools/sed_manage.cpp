/// @file sed_manage.cpp
/// CLI tool: Manage SED drives (ownership, locking, user management, revert)

#include <cats.h>
#include <cstdio>
#include <cstring>
#include <string>

static void printUsage(const char* prog) {
    printf("TCG SED Management Tool\n\n");
    printf("Usage: %s <device> <command> [options] [--dump]\n\n", prog);
    printf("Commands:\n");
    printf("  take-ownership <new_password>          Set SID password (reads MSID automatically)\n");
    printf("  activate <sid_password>                Activate Locking SP\n");
    printf("  setup <sid_pw> <admin1_pw>             Full initial setup\n");
    printf("  lock <password> [range] [user]          Lock a range\n");
    printf("  unlock <password> [range] [user]        Unlock a range\n");
    printf("  range-info <password> [range] [user]    Show range info\n");
    printf("  configure-range <admin1_pw> <range> <start> <length>  Configure range\n");
    printf("  setup-user <admin1_pw> <user_id> <user_pw> <range>    Setup user\n");
    printf("  crypto-erase <admin1_pw> [range]       Crypto-erase a range\n");
    printf("  revert <sid_password>                  Revert TPer (factory reset)\n");
    printf("  psid-revert <psid>                     Emergency PSID revert\n\n");
    printf("Flags:\n");
    printf("  --dump    Show IF-SEND/IF-RECV packets on stderr\n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) { printUsage(argv[0]); return 1; }

    const char* device  = argv[1];
    const char* command = argv[2];

    libsed::SedDrive drive(device);
    for (int i = 3; i < argc; i++)
        if (std::strcmp(argv[i], "--dump") == 0) drive.enableDump();

    auto r = drive.query();
    if (r.failed()) {
        printf("Discovery failed: %s\n", r.message().c_str());
        return 1;
    }

    printf("Device: %s (SSC: %s)\n\n", device, drive.sscName());

    // ── Commands ─────────────────────────────────────
    if (std::strcmp(command, "take-ownership") == 0) {
        if (argc < 4) { printf("Missing password\n"); return 1; }
        r = drive.takeOwnership(argv[3]);
        printf("%s\n", r.ok() ? "Ownership taken." : "Failed.");

    } else if (std::strcmp(command, "activate") == 0) {
        if (argc < 4) { printf("Missing SID password\n"); return 1; }
        r = drive.activateLocking(argv[3]);
        printf("%s\n", r.ok() ? "Locking SP activated." : "Failed.");

    } else if (std::strcmp(command, "setup") == 0) {
        if (argc < 5) { printf("Usage: setup <sid_pw> <admin1_pw>\n"); return 1; }
        const char* sidPw = argv[3];
        const char* admin1Pw = argv[4];
        r = drive.takeOwnership(sidPw);
        if (r.ok()) r = drive.activateLocking(sidPw);
        if (r.ok()) r = drive.configureRange(1, 0, 1048576, admin1Pw);
        printf("%s\n", r.ok() ? "Setup complete." : "Setup failed.");

    } else if (std::strcmp(command, "lock") == 0) {
        if (argc < 4) { printf("Missing password\n"); return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        uint32_t user  = (argc > 5) ? std::stoul(argv[5]) : 1;
        r = drive.lockRange(range, argv[3], user);
        printf("%s\n", r.ok() ? "Locked." : "Lock failed.");

    } else if (std::strcmp(command, "unlock") == 0) {
        if (argc < 4) { printf("Missing password\n"); return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        uint32_t user  = (argc > 5) ? std::stoul(argv[5]) : 1;
        r = drive.unlockRange(range, argv[3], user);
        printf("%s\n", r.ok() ? "Unlocked." : "Unlock failed.");

    } else if (std::strcmp(command, "range-info") == 0) {
        if (argc < 4) { printf("Missing password\n"); return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        uint32_t user  = (argc > 5) ? std::stoul(argv[5]) : 1;
        auto s = drive.login(libsed::Uid(libsed::uid::SP_LOCKING), argv[3],
                             libsed::uid::makeUserUid(user));
        if (s.failed()) {
            printf("Login failed: %s\n", s.openResult().message().c_str());
            return 1;
        }
        libsed::LockingRangeInfo ri;
        r = s.getRangeInfo(range, ri);
        if (r.ok()) {
            printf("Range %u:\n", ri.rangeId);
            printf("  Start:        %lu\n", (unsigned long)ri.rangeStart);
            printf("  Length:       %lu\n", (unsigned long)ri.rangeLength);
            printf("  ReadLockEn:   %d\n", ri.readLockEnabled);
            printf("  WriteLockEn:  %d\n", ri.writeLockEnabled);
            printf("  ReadLocked:   %d\n", ri.readLocked);
            printf("  WriteLocked:  %d\n", ri.writeLocked);
        }

    } else if (std::strcmp(command, "configure-range") == 0) {
        if (argc < 7) { printf("Usage: configure-range <pw> <range> <start> <len>\n"); return 1; }
        r = drive.configureRange(std::stoul(argv[4]),
                                  std::stoull(argv[5]), std::stoull(argv[6]),
                                  argv[3]);
        printf("%s\n", r.ok() ? "Range configured." : "Failed.");

    } else if (std::strcmp(command, "setup-user") == 0) {
        if (argc < 7) { printf("Usage: setup-user <admin1_pw> <user_id> <user_pw> <range>\n"); return 1; }
        r = drive.setupUser(std::stoul(argv[4]), argv[5],
                             std::stoul(argv[6]), argv[3]);
        printf("%s\n", r.ok() ? "User setup complete." : "Failed.");

    } else if (std::strcmp(command, "crypto-erase") == 0) {
        if (argc < 4) { printf("Missing admin1 password\n"); return 1; }
        uint32_t range = (argc > 4) ? std::stoul(argv[4]) : 0;
        r = drive.cryptoErase(range, argv[3]);
        printf("%s\n", r.ok() ? "Crypto-erased." : "Failed.");

    } else if (std::strcmp(command, "revert") == 0) {
        if (argc < 4) { printf("Missing SID password\n"); return 1; }
        r = drive.revert(argv[3]);
        printf("%s\n", r.ok() ? "Reverted to factory state." : "Revert failed.");

    } else if (std::strcmp(command, "psid-revert") == 0) {
        if (argc < 4) { printf("Missing PSID\n"); return 1; }
        r = drive.psidRevert(argv[3]);
        printf("%s\n", r.ok() ? "PSID revert complete." : "PSID revert failed.");

    } else {
        printf("Unknown command: %s\n", command);
        printUsage(argv[0]);
        return 1;
    }

    if (r.failed()) {
        printf("Error: %s\n", r.message().c_str());
    }

    return r.ok() ? 0 : 1;
}
