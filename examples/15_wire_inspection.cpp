/// @file 15_wire_inspection.cpp
/// @brief Wire Inspection — ComPacket Structure and Token Encoding
///
/// TCG SPEC CONTEXT:
/// Every TCG SED command/response travels as a layered binary structure:
///
///   ComPacket (20 bytes header):
///     [4B reserved][2B comId][2B comIdExt][4B outstandingData][4B minTransfer][4B length]
///
///   Packet (24 bytes header, inside ComPacket payload):
///     [4B tperSessionNumber][4B hostSessionNumber][4B seqNumber]
///     [2B reserved][2B ackType][4B acknowledgement][4B length]
///
///   SubPacket (12 bytes header, inside Packet payload):
///     [6B reserved][2B kind][4B length]
///
///   Token Payload (inside SubPacket):
///     Binary-encoded method calls and responses using TCG's token format:
///       - Tiny atoms: 1 byte, value 0-63
///       - Short atoms: 2-16 bytes (1-byte header + data)
///       - Medium atoms: up to 2KB (2-byte header + data)
///       - Long atoms: up to 16MB (4-byte header + data)
///       - Tokens: STARTLIST(0xF0), ENDLIST(0xF1), STARTNAME(0xF2),
///                 ENDNAME(0xF3), CALL(0xF8), ENDOFDATA(0xF9),
///                 ENDOFSESSION(0xFA), STARTTRANSACTION(0xFB),
///                 ENDTRANSACTION(0xFC), EMPTYATOM(0xFF)
///
/// Understanding the wire format is essential for debugging protocol issues.
/// The --dump flag on most examples enables hex dump of all traffic.
///
/// API LAYER: EvalApi raw methods + LoggingTransport
/// PREREQUISITES: 01-04
///
/// Usage: ./15_wire_inspection /dev/nvmeX [--dump]

#include "example_common.h"
#include "libsed/debug/logging_transport.h"
#include "libsed/debug/command_logger.h"
#include "libsed/packet/com_packet.h"

// ── Scenario 1: Inspect a Properties Exchange on the wire ──

static bool scenario1_propertiesWire(std::shared_ptr<ITransport> transport,
                                      uint16_t comId) {
    scenario(1, "Properties Exchange — Wire Format");

    // Wrap transport with logging to capture raw packets
    auto loggingTransport = debug::LoggingTransport::wrapDump(transport);

    EvalApi api;
    PropertiesResult props;

    printf("    Sending Properties Exchange (watch the hex dump)...\n\n");
    auto r = api.exchangeProperties(loggingTransport, comId, props);
    step(1, "Properties exchange with dump", r);

    printf("\n    Wire format breakdown:\n");
    printf("    ┌─ ComPacket (20B header) ──────────────────┐\n");
    printf("    │  [0..3]   Reserved / ExtComID              │\n");
    printf("    │  [4..5]   ComID (0x%04X)                   │\n", comId);
    printf("    │  [6..7]   ComID Extension                  │\n");
    printf("    │  [8..11]  Outstanding Data                 │\n");
    printf("    │  [12..15] Min Transfer                     │\n");
    printf("    │  [16..19] Length (payload bytes)            │\n");
    printf("    ├─ Packet (24B header) ─────────────────────┤\n");
    printf("    │  [0..3]   TSN (0 for SM)                   │\n");
    printf("    │  [4..7]   HSN (0 for SM)                   │\n");
    printf("    │  [8..11]  Sequence Number                  │\n");
    printf("    │  [20..23] Payload Length                    │\n");
    printf("    ├─ SubPacket (12B header) ──────────────────┤\n");
    printf("    │  [6..7]   Kind (0x0000 = Data)             │\n");
    printf("    │  [8..11]  Payload Length                    │\n");
    printf("    ├─ Token Payload ───────────────────────────┤\n");
    printf("    │  F8 = CALL token                           │\n");
    printf("    │  A0 xx xx xx xx xx xx xx xx = UID (8 bytes)│\n");
    printf("    │  A0 xx xx xx xx xx xx xx xx = Method UID   │\n");
    printf("    │  F0 = STARTLIST (parameters)               │\n");
    printf("    │  ...parameter tokens...                    │\n");
    printf("    │  F1 = ENDLIST                              │\n");
    printf("    │  F9 = ENDOFDATA                            │\n");
    printf("    │  F0 F0 00 F1 F1 = Status list (Success)   │\n");
    printf("    └──────────────────────────────────────────┘\n");

    return r.ok();
}

// ── Scenario 2: Inspect Session StartSession/SyncSession ──

static bool scenario2_sessionWire(std::shared_ptr<ITransport> transport,
                                   uint16_t comId) {
    scenario(2, "StartSession/SyncSession — Wire Format");

    auto loggingTransport = debug::LoggingTransport::wrapDump(transport);

    EvalApi api;
    Session session(loggingTransport, comId);
    StartSessionResult ssr;

    printf("    Opening anonymous session (watch TSN/HSN in packets)...\n\n");
    auto r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    step(1, "StartSession", r);
    if (r.ok()) {
        printf("\n    After SyncSession:\n");
        printf("      TSN=%u (assigned by TPer, goes in every Packet header)\n",
               session.tperSessionNumber());
        printf("      HSN=%u (proposed by Host)\n", session.hostSessionNumber());
    }

    printf("\n    Closing session...\n\n");
    api.closeSession(session);

    return r.ok();
}

// ── Scenario 3: Raw send/receive inspection ──

static bool scenario3_rawSendRecv(std::shared_ptr<ITransport> transport,
                                   uint16_t comId) {
    scenario(3, "Raw Discovery Response Bytes");

    EvalApi api;
    Bytes rawResp;
    auto r = api.discovery0Raw(transport, rawResp);
    step(1, "Raw Discovery", r);
    if (r.failed()) return false;

    // Parse the Discovery response header manually
    if (rawResp.size() >= 48) {
        printf("\n    Discovery Response Header (NOT a ComPacket!):\n");
        printf("      [0..3]  Total Length: %u\n",
               (rawResp[0]<<24)|(rawResp[1]<<16)|(rawResp[2]<<8)|rawResp[3]);
        printf("      [4..5]  Major Version: %u\n",
               (rawResp[4]<<8)|rawResp[5]);
        printf("      [6..7]  Minor Version: %u\n",
               (rawResp[6]<<8)|rawResp[7]);
        printf("      [8..47] Reserved (40 bytes)\n");
        printf("      [48..]  Feature Descriptors start\n");

        // Show first Feature Descriptor
        if (rawResp.size() > 52) {
            uint16_t fc = (rawResp[48]<<8)|rawResp[49];
            uint8_t ver = rawResp[50] & 0x0F;
            uint8_t len = rawResp[51];
            printf("\n    First Feature Descriptor:\n");
            printf("      Feature Code: 0x%04X\n", fc);
            printf("      Version: %u\n", ver);
            printf("      Length: %u bytes\n", len);
            dumpHex("Feature data", rawResp.data()+48, std::min((size_t)(4+len), rawResp.size()-48));
        }
    }

    return true;
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Wire Inspection — ComPacket/Packet/SubPacket structure and tokens");
    if (!transport) return 1;

    banner("15: Wire Inspection");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_propertiesWire(transport, info.baseComId);
    ok &= scenario2_sessionWire(transport, info.baseComId);
    ok &= scenario3_rawSendRecv(transport, info.baseComId);

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
