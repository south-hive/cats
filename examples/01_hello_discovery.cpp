/// @file 01_hello_discovery.cpp
/// @brief Level 0 Discovery — What Your Drive Supports
///
/// TCG SPEC CONTEXT:
/// Every TCG SED drive must respond to a "Level 0 Discovery" request.
/// This is the very first step in any SED interaction — before sessions,
/// before authentication, before anything. The drive reports which Security
/// Subsystem Classes (SSC) it supports (Opal, Enterprise, Pyrite), its
/// communication parameters (ComID, max packet sizes), and whether features
/// like Locking and MBR shadow are present.
///
/// Discovery uses IF-RECV with Protocol ID=0x01, ComID=0x0001.
/// The response is NOT a ComPacket — it has its own binary format:
///   [4B length][2B major][2B minor][8B reserved][48B header total]
///   followed by Feature Descriptor entries (variable length each).
///
/// API LAYER: SedDrive (facade) for convenience, then EvalApi for raw access.
/// PREREQUISITES: None — this is the starting point.
///
/// Usage: ./01_hello_discovery /dev/nvmeX [--dump]

#include "example_common.h"

// ── Scenario 1: Quick Discovery via SedDrive facade ──
//
// SedDrive::query() bundles Discovery + Properties + MSID in one call.
// For a first look at the drive, this is the easiest approach.

static bool scenario1_facadeQuery(const char* device, cli::CliOptions& opts) {
    scenario(1, "Quick Discovery via SedDrive");

    // SedDrive wraps transport creation internally
    SedDrive drive(device);
    if (opts.dump) drive.enableDump();

    // query() performs: Discovery -> Properties Exchange -> Read MSID
    auto r = drive.query();
    step(1, "SedDrive::query()", r);
    if (r.failed()) return false;

    // ── Print what we learned ──
    printf("\n  Drive Information:\n");
    printf("    SSC Type:     %s\n", drive.sscName());
    printf("    Base ComID:   0x%04X\n", drive.comId());
    printf("    Num ComIDs:   %u\n", drive.numComIds());
    printf("    Max ComPkt:   %u bytes\n", drive.maxComPacketSize());

    // Discovery tells us about the drive's feature set
    const auto& info = drive.info();
    printf("\n  Feature Set:\n");
    printf("    TPer:         %s\n", info.tperPresent ? "Yes" : "No");
    printf("    Locking:      %s", info.lockingPresent ? "Yes" : "No");
    if (info.lockingPresent) {
        printf(" (enabled=%s, locked=%s)",
               info.lockingEnabled ? "yes" : "no",
               info.locked ? "yes" : "no");
    }
    printf("\n");
    printf("    MBR Shadow:   enabled=%s, done=%s\n",
           info.mbrEnabled ? "yes" : "no",
           info.mbrDone ? "yes" : "no");

    // MSID is the factory credential — needed later for Take Ownership
    if (!drive.msid().empty()) {
        printString("MSID", drive.msid());
    } else {
        printf("    MSID:         (restricted — drive may be owned)\n");
    }

    return true;
}

// ── Scenario 2: Raw Discovery via EvalApi ──
//
// EvalApi::discovery0() gives you direct access to the parsed Discovery
// response, including individual Feature Descriptors. This is what you
// use when you need to inspect specific features or extract raw data.

static bool scenario2_rawDiscovery(std::shared_ptr<ITransport> transport) {
    scenario(2, "Raw Discovery via EvalApi");

    EvalApi api;
    DiscoveryInfo info;

    // discovery0() sends IF-RECV(protocol=0x01, comId=0x0001) and parses
    // the binary Feature Descriptor format.
    auto r = api.discovery0(transport, info);
    step(1, "EvalApi::discovery0()", r);
    if (r.failed()) return false;

    printf("\n  Parsed Discovery Response:\n");
    printf("    Version:      %u.%u\n", info.majorVersion, info.minorVersion);
    printf("    Primary SSC:  %s\n",
           info.primarySsc == SscType::Opal20 ? "Opal 2.0" :
           info.primarySsc == SscType::Enterprise ? "Enterprise" :
           info.primarySsc == SscType::Pyrite10 ? "Pyrite 1.0" :
           info.primarySsc == SscType::Pyrite20 ? "Pyrite 2.0" :
           "Unknown");

    return true;
}

// ── Scenario 3: Raw Discovery bytes ──
//
// For advanced debugging, you can get the raw Discovery response bytes
// and inspect them yourself. This is useful for:
//   - Verifying Feature Descriptor parsing
//   - Checking for vendor-specific features (feature code >= 0xC000)
//   - Comparing with sedutil output

static bool scenario3_rawBytes(std::shared_ptr<ITransport> transport) {
    scenario(3, "Raw Discovery Bytes");

    EvalApi api;
    Bytes rawResponse;

    auto r = api.discovery0Raw(transport, rawResponse);
    step(1, "EvalApi::discovery0Raw()", r);
    if (r.failed()) return false;

    printf("  Response size: %zu bytes\n", rawResponse.size());

    // Discovery header: first 48 bytes
    //   [0..3]   Total Length (big-endian, excludes these 4 bytes)
    //   [4..5]   Major Version
    //   [6..7]   Minor Version
    //   [8..47]  Reserved
    if (rawResponse.size() >= 48) {
        uint32_t totalLen = (rawResponse[0] << 24) | (rawResponse[1] << 16) |
                            (rawResponse[2] << 8) | rawResponse[3];
        printf("  Header Length field: %u (total response = %u bytes)\n",
               totalLen, totalLen + 4);
        dumpHex("Discovery Header (48B)", rawResponse.data(), 48);

        // Walk Feature Descriptors starting at offset 48
        printf("\n  Feature Descriptors:\n");
        size_t offset = 48;
        while (offset + 4 <= rawResponse.size() && offset < totalLen + 4) {
            uint16_t featureCode = (rawResponse[offset] << 8) | rawResponse[offset + 1];
            // Byte 2 bits 0-3 = version, bit 4 = reserved
            uint8_t version = rawResponse[offset + 2] & 0x0F;
            uint8_t descLen = rawResponse[offset + 3];

            const char* name = "Unknown";
            if (featureCode == 0x0001) name = "TPer";
            else if (featureCode == 0x0002) name = "Locking";
            else if (featureCode == 0x0003) name = "Geometry";
            else if (featureCode == 0x0200) name = "Opal SSC v1.0";
            else if (featureCode == 0x0203) name = "Opal SSC v2.0";
            else if (featureCode == 0x0100) name = "Enterprise SSC";
            else if (featureCode == 0x0302) name = "Pyrite SSC v1.0";
            else if (featureCode == 0x0303) name = "Pyrite SSC v2.0";
            else if (featureCode == 0x0402) name = "Block SID Auth";
            else if (featureCode == 0x0403) name = "NS Locking";
            else if (featureCode >= 0xC000) name = "Vendor-Specific";

            printf("    Feature 0x%04X: %-20s  version=%u  length=%u\n",
                   featureCode, name, version, descLen);

            offset += 4 + descLen;
        }
    }

    return true;
}

// ── Main ────────────────────────────────────────────

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Level 0 Discovery — inspect what your SED drive supports");
    if (!transport) return 1;

    banner("01: Hello Discovery");

    bool ok = true;
    ok &= scenario1_facadeQuery(opts.device.c_str(), opts);
    ok &= scenario2_rawDiscovery(transport);
    ok &= scenario3_rawBytes(transport);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
