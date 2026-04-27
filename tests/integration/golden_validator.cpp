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
#include <libsed/codec/token_list.h>
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

// 다세션 시퀀스용 placeholder TSN — 헤더 비교를 안 하므로 값 자체는 무관
// (token-only diff 가 default).
static constexpr uint32_t TSN_PLACEHOLDER = 1;

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
//  initialSetup builders (B-E)
//  fixture 캡쳐 시점의 TSN 이 무엇이든 token payload 만 비교하므로 placeholder 사용.
// ═══════════════════════════════════════════════════════

// 30바이트 실 MSID 캡쳐값을 fixture 와 함께 제공해야 wire 일치.
// 환경변수 LIBSED_GOLDEN_MSID_HEX 로 주입 (없으면 기본 32바이트 0x00 sentinel).
static Bytes goldenMsid() {
    if (const char* env = std::getenv("LIBSED_GOLDEN_MSID_HEX")) {
        Bytes out;
        size_t n = std::strlen(env);
        for (size_t i = 0; i + 1 < n; i += 2) {
            char buf[3] = { env[i], env[i+1], 0 };
            out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
        }
        return out;
    }
    return Bytes(32, 0x00);
}

// 새 SID 비밀번호도 fixture 와 동일해야 함. LIBSED_GOLDEN_NEWPW_HEX 로 주입.
static Bytes goldenNewPw() {
    if (const char* env = std::getenv("LIBSED_GOLDEN_NEWPW_HEX")) {
        Bytes out;
        size_t n = std::strlen(env);
        for (size_t i = 0; i + 1 < n; i += 2) {
            char buf[3] = { env[i], env[i+1], 0 };
            out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
        }
        return out;
    }
    return Bytes(32, 0x00);
}

// B1. StartSession(AdminSP, SID + MSID)
static Packet buildLibsed_B1_StartSessionSidWithMsid() {
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), true, goldenMsid(), Uid(uid::AUTH_SID), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

// B2. Set(C_PIN_SID, PIN=newPw)
static Packet buildLibsed_B2_SetCPinSid() {
    TokenList values;
    values.addBytes(uid::col::PIN, goldenNewPw());
    Bytes methodTokens = MethodCall::buildSet(Uid(uid::CPIN_SID), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_PLACEHOLDER, HSN);
    return pb.buildComPacket(methodTokens);
}

// C1. StartSession(AdminSP, SID + newPw)
static Packet buildLibsed_C1_StartSessionSidWithNewPw() {
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_ADMIN), true, goldenNewPw(), Uid(uid::AUTH_SID), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

// C2. Activate(LockingSP)
static Packet buildLibsed_C2_ActivateLockingSP() {
    Bytes methodTokens = MethodCall::buildActivate(Uid(uid::SP_LOCKING));
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_PLACEHOLDER, HSN);
    return pb.buildComPacket(methodTokens);
}

// D1. StartSession(LockingSP, Admin1 + newPw)
static Packet buildLibsed_D1_StartSessionAdmin1() {
    Bytes params = ParamEncoder::encodeStartSession(
        HSN, Uid(uid::SP_LOCKING), true, goldenNewPw(), Uid(uid::AUTH_ADMIN1), Uid());
    Bytes methodTokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
    PacketBuilder pb;
    pb.setComId(COMID);
    return pb.buildSessionManagerPacket(methodTokens);
}

// D2. Set(LockingRange.Global, RLE=0, WLE=0)
static Packet buildLibsed_D2_DisableLocking() {
    TokenList values;
    values.addUint(uid::col::READ_LOCK_EN, 0);
    values.addUint(uid::col::WRITE_LOCK_EN, 0);
    Bytes methodTokens = MethodCall::buildSet(Uid(uid::LOCKING_GLOBALRANGE), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_PLACEHOLDER, HSN);
    return pb.buildComPacket(methodTokens);
}

// D2'. Set(LockingRange.Global, RL=0, WL=0)
static Packet buildLibsed_D2b_UnlockGlobal() {
    TokenList values;
    values.addUint(uid::col::READ_LOCKED, 0);
    values.addUint(uid::col::WRITE_LOCKED, 0);
    Bytes methodTokens = MethodCall::buildSet(Uid(uid::LOCKING_GLOBALRANGE), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_PLACEHOLDER, HSN);
    return pb.buildComPacket(methodTokens);
}

// E2. Set(MBRControl, Enable=0)
static Packet buildLibsed_E2_DisableMbr() {
    TokenList values;
    values.addUint(uid::col::MBR_ENABLE, 0);
    Bytes methodTokens = MethodCall::buildSet(Uid(uid::MBRCTRL_SET), values);
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_PLACEHOLDER, HSN);
    return pb.buildComPacket(methodTokens);
}

// 모든 in-session CloseSession 은 동일 (TSN 만 placeholder)
static Packet buildLibsed_GenericCloseSession() {
    TokenEncoder enc;
    enc.endOfSession();
    PacketBuilder pb;
    pb.setComId(COMID);
    pb.setSessionNumbers(TSN_PLACEHOLDER, HSN);
    return pb.buildComPacket(enc.data());
}

// ═══════════════════════════════════════════════════════
//  Test structure
// ═══════════════════════════════════════════════════════

enum class DiffMode {
    Full,         // 전체 byte-exact 비교 (헤더 포함)
    TokensOnly,   // token payload (offset 56+) 만 비교, 헤더 무시
};

struct GoldenTest {
    const char* name;
    const char* fixture;              // e.g. "A1_properties.bin"
    std::function<Packet()> build;    // libsed packet builder
    DiffMode mode = DiffMode::Full;
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

    // SM 패킷(StartSession/Properties)은 TSN=0/HSN=0 고정이라 Full diff 가능.
    // in-session 패킷(Get/Set/Activate/CloseSession)은 TSN 이 가변이라
    // TokensOnly 모드 사용.
    Sequence sequences[] = {
        { "A", "Query Flow (sedutil --query)", {
            { "A.1 Properties",
              "A1_properties.bin", buildLibsed_A1_Properties, DiffMode::Full },
            { "A.2 StartSession anon AdminSP",
              "A2_start_session.bin", buildLibsed_A2_StartSessionAnon, DiffMode::Full },
            { "A.3 Get C_PIN_MSID",
              "A3_get_msid.bin", buildLibsed_A3_GetMsid, DiffMode::TokensOnly },
            { "A.4 CloseSession",
              "A4_close_session.bin", buildLibsed_A4_CloseSession, DiffMode::TokensOnly },
        }},

        // sedutil --initialSetup 의 6 세션 시퀀스. fixture 명명 규칙은
        // tests/fixtures/golden/README.md 참조. MSID/newPw 가 hex env 로
        // 주입되어야 wire bytes 가 일치 (LIBSED_GOLDEN_MSID_HEX,
        // LIBSED_GOLDEN_NEWPW_HEX). 미주입 시 placeholder 라 TokensOnly
        // diff 도 fail 할 수 있음 — fixture 제공자가 동일 값으로 캡쳐 권장.
        { "B", "takeOwnership session 2 (SID + MSID)", {
            { "B.1 StartSession AdminSP+SID+MSID",
              "B1_start_session_sid_msid.bin",
              buildLibsed_B1_StartSessionSidWithMsid, DiffMode::Full },
            { "B.2 Set C_PIN_SID = newPw",
              "B2_set_cpin_sid.bin",
              buildLibsed_B2_SetCPinSid, DiffMode::TokensOnly },
            { "B.3 CloseSession",
              "B3_close_session.bin",
              buildLibsed_GenericCloseSession, DiffMode::TokensOnly },
        }},
        { "C", "activateLockingSP", {
            { "C.1 StartSession AdminSP+SID+newPw",
              "C1_start_session_sid_newpw.bin",
              buildLibsed_C1_StartSessionSidWithNewPw, DiffMode::Full },
            { "C.2 Activate(SP_LOCKING)",
              "C2_activate_locking.bin",
              buildLibsed_C2_ActivateLockingSP, DiffMode::TokensOnly },
            { "C.3 CloseSession",
              "C3_close_session.bin",
              buildLibsed_GenericCloseSession, DiffMode::TokensOnly },
        }},
        { "D", "configureLockingRange + setLockingRange (Global)", {
            { "D.1 StartSession LockingSP+Admin1",
              "D1_start_session_admin1.bin",
              buildLibsed_D1_StartSessionAdmin1, DiffMode::Full },
            { "D.2 Set Global Range RLE=WLE=0",
              "D2_disable_locking.bin",
              buildLibsed_D2_DisableLocking, DiffMode::TokensOnly },
            { "D.3 CloseSession (after disable)",
              "D3_close_session.bin",
              buildLibsed_GenericCloseSession, DiffMode::TokensOnly },
            { "D.4 StartSession LockingSP+Admin1 (2)",
              "D4_start_session_admin1.bin",
              buildLibsed_D1_StartSessionAdmin1, DiffMode::Full },
            { "D.5 Set Global Range RL=WL=0",
              "D5_unlock_global.bin",
              buildLibsed_D2b_UnlockGlobal, DiffMode::TokensOnly },
            { "D.6 CloseSession (after unlock)",
              "D6_close_session.bin",
              buildLibsed_GenericCloseSession, DiffMode::TokensOnly },
        }},
        { "E", "setMBREnable(0)", {
            { "E.1 StartSession AdminSP+SID+newPw",
              "E1_start_session_sid_newpw.bin",
              buildLibsed_C1_StartSessionSidWithNewPw, DiffMode::Full },
            { "E.2 Set MBRControl Enable=0",
              "E2_disable_mbr.bin",
              buildLibsed_E2_DisableMbr, DiffMode::TokensOnly },
            { "E.3 CloseSession",
              "E3_close_session.bin",
              buildLibsed_GenericCloseSession, DiffMode::TokensOnly },
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

            int diffs = (t.mode == DiffMode::TokensOnly)
                ? diffTokenPayload("libsed", libsed, golden)
                : diffPackets("libsed", libsed, golden);
            if (diffs == 0) {
                const char* tag = (t.mode == DiffMode::TokensOnly)
                    ? "[PASS tokens]" : "[PASS]";
                printf("  %s %s\n", tag, t.name);
                seqPassed++;
                totalPassed++;
            } else {
                printf("  [FAIL] %s (%d diffs, mode=%s)\n",
                       t.name, diffs,
                       (t.mode == DiffMode::TokensOnly) ? "tokens" : "full");
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
