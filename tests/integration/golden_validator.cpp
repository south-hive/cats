/// @file golden_validator.cpp
/// @brief Validates libsed packet encoding against golden fixtures from real hardware.
///
/// Unlike ioctl_validator (which compares libsed vs sedutil DtaCommand),
/// this validator compares against actual packets captured from a real TPer.
/// This breaks the circular validation problem where both implementations
/// share the same spec interpretation.
///
/// Fixture files (.bin) are 2048-byte raw ioctl buffers captured via
/// `sedutil-cli -vvvvv`. Missing fixtures → SKIP (not FAIL).
///
/// Usage: ./golden_validator

#include <libsed/codec/token_encoder.h>
#include <libsed/method/method_call.h>
#include <libsed/method/method_uids.h>
#include <libsed/method/param_encoder.h>
#include <libsed/packet/packet_builder.h>
#include <libsed/core/uid.h>

#include "packet_diff.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <functional>
#include <fstream>

using namespace libsed;
using namespace libsed::test;

// ═══════════════════════════════════════════════════════
//  Constants — matching sedutil defaults
// ═══════════════════════════════════════════════════════

static constexpr uint16_t COMID = 0x0001;
static constexpr uint32_t HSN   = 105;
static constexpr uint32_t TSN_A = 1;

// ═══════════════════════════════════════════════════════
//  Fixture loader
// ═══════════════════════════════════════════════════════

#ifndef GOLDEN_FIXTURE_DIR
#define GOLDEN_FIXTURE_DIR "tests/fixtures/golden"
#endif

static Packet loadFixture(const char* filename) {
    std::string path = std::string(GOLDEN_FIXTURE_DIR) + "/" + filename;
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {};
    return Packet(std::istreambuf_iterator<char>(f),
                  std::istreambuf_iterator<char>());
}

// ═══════════════════════════════════════════════════════
//  libsed packet builders (same as ioctl_validator)
// ═══════════════════════════════════════════════════════

static Packet buildLibsed_A1_Properties() {
    ParamEncoder::HostProperties hp;
    hp.maxComPacketSize = 2048;
    hp.maxPacketSize    = 2028;
    hp.maxIndTokenSize  = 1992;
    hp.maxPackets       = 1;
    hp.maxSubPackets    = 1;
    hp.maxMethods       = 1;

    Bytes params = ParamEncoder::encodeProperties(hp);
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_PROPERTIES, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildLibsed_A2_StartSessionAnon() {
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), false, {}, Uid(), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);

    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

static Packet buildLibsed_A3_GetMsid() {
    CellBlock cb;
    cb.startColumn = 3;  // PIN column
    cb.endColumn   = 3;

    Bytes methodTokens = MethodCall::buildGet(Uid(uid::CPIN_MSID), cb);

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_A, HSN);
    return pb.buildComPacket(methodTokens);
}

static Packet buildLibsed_A4_CloseSession() {
    TokenEncoder enc;
    enc.endOfSession();

    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_A, HSN);
    return pb.buildComPacket(enc.data());
}

// ═══════════════════════════════════════════════════════
//  Test structure
// ═══════════════════════════════════════════════════════

struct GoldenTest {
    const char* name;
    const char* fixture;              // e.g. "A1_properties.bin"
    std::function<Packet()> build;    // libsed packet builder
};

// ═══════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════

int main() {
    struct Sequence {
        const char* name;
        const char* description;
        std::vector<GoldenTest> steps;
    };

    Sequence sequences[] = {
        { "A", "Query Flow (sedutil --query)", {
            { "A.1 Properties (SM, TSN=0/HSN=0)",
              "A1_properties.bin", buildLibsed_A1_Properties },
            { "A.2 StartSession anon AdminSP (SM, TSN=0/HSN=0)",
              "A2_start_session.bin", buildLibsed_A2_StartSessionAnon },
            { "A.3 Get C_PIN_MSID (TSN=1/HSN=105)",
              "A3_get_msid.bin", buildLibsed_A3_GetMsid },
            { "A.4 CloseSession (TSN=1/HSN=105)",
              "A4_close_session.bin", buildLibsed_A4_CloseSession },
        }},
    };

    int totalTests = 0, totalPassed = 0, totalSkipped = 0;
    int seqCount = static_cast<int>(sizeof(sequences) / sizeof(sequences[0]));

    printf("golden_validator: libsed vs hardware-captured golden fixtures\n");
    printf("Fixture dir: %s\n\n", GOLDEN_FIXTURE_DIR);

    for (int s = 0; s < seqCount; s++) {
        auto& seq = sequences[s];
        printf("── Golden Sequence %s: %s ──\n", seq.name, seq.description);

        int seqPassed = 0, seqSkipped = 0;
        int seqTotal = static_cast<int>(seq.steps.size());

        for (int i = 0; i < seqTotal; i++) {
            auto& t = seq.steps[i];
            totalTests++;

            Packet golden = loadFixture(t.fixture);
            if (golden.empty()) {
                printf("  [SKIP] %s (fixture missing: %s)\n", t.name, t.fixture);
                seqSkipped++;
                totalSkipped++;
                continue;
            }

            Packet libsed = t.build();

            int diffs = diffPackets("libsed", libsed, golden);
            if (diffs == 0) {
                printf("  [PASS] %s\n", t.name);
                seqPassed++;
                totalPassed++;
            } else {
                printf("  [FAIL] %s (%d byte diffs)\n", t.name, diffs);
                dumpFailDiagnostics("libsed", "golden", libsed, golden);
            }
        }

        printf("  ── %s result: %d/%d (skipped %d) ──\n\n",
               seq.name, seqPassed, seqTotal - seqSkipped, seqSkipped);
    }

    printf("════════════════════════════════════════\n");
    printf("  Total: %d/%d PASS, %d SKIP\n", totalPassed, totalTests - totalSkipped, totalSkipped);
    printf("════════════════════════════════════════\n");

    // Return 0 if all non-skipped tests pass
    int ran = totalTests - totalSkipped;
    return (ran == 0 || totalPassed == ran) ? 0 : 1;
}
