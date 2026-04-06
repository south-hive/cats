#pragma once

/// @file test_helper.h
/// @brief 테스트 시나리오용 공용 헬퍼 — MockTransport 응답 빌더, 매크로 등

#include "libsed/eval/eval_api.h"
#include "libsed/eval/eval_composite.h"
#include "libsed/facade/sed_drive.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/packet/packet_builder.h"
#include "libsed/method/method_call.h"
#include "libsed/method/method_uids.h"
#include "libsed/core/uid.h"
#include "libsed/core/endian.h"
#include "libsed/debug/fault_builder.h"
#include "libsed/debug/test_context.h"
#include "mock/mock_transport.h"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <string>
#include <vector>
#include <functional>

// ═══════════════════════════════════════════════════════
//  Minimal Test Framework (Google Test 없을 때 대비)
// ═══════════════════════════════════════════════════════

#ifndef TEST_SCENARIO
#define TEST_SCENARIO(suite, name) static bool test_##suite##_##name()
#define RUN_SCENARIO(suite, name) do { \
    printf("  [TS] " #suite "." #name " ... "); \
    fflush(stdout); \
    if (test_##suite##_##name()) { \
        printf("PASS\n"); ++g_passed; \
    } else { \
        printf("FAIL\n"); ++g_failed; \
    } \
} while(0)
#endif

#define EXPECT_OK(r) do { if ((r).failed()) { \
    fprintf(stderr, "    FAIL at %s:%d: expected Success, got %s\n", \
            __FILE__, __LINE__, (r).message().c_str()); return false; } } while(0)

#define EXPECT_FAIL(r) do { if ((r).ok()) { \
    fprintf(stderr, "    FAIL at %s:%d: expected failure, got Success\n", \
            __FILE__, __LINE__); return false; } } while(0)

#define EXPECT_ERR(r, code) do { \
    if ((r).errorCode() != libsed::ErrorCode::code) { \
        fprintf(stderr, "    FAIL at %s:%d: expected %s, got %s\n", \
                __FILE__, __LINE__, #code, (r).message().c_str()); return false; } \
    } while(0)

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "    FAIL at %s:%d: %s\n", __FILE__, __LINE__, #expr); return false; } } while(0)

#define CHECK_EQ(a, b) do { if ((a) != (b)) { \
    fprintf(stderr, "    FAIL at %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); return false; } } while(0)

#define CHECK_NE(a, b) do { if ((a) == (b)) { \
    fprintf(stderr, "    FAIL at %s:%d: %s == %s (expected !=)\n", __FILE__, __LINE__, #a, #b); return false; } } while(0)

#define CHECK_GT(a, b) do { if (!((a) > (b))) { \
    fprintf(stderr, "    FAIL at %s:%d: %s not > %s\n", __FILE__, __LINE__, #a, #b); return false; } } while(0)

// Global counters (defined in scenario_main.cpp)
extern int g_passed;
extern int g_failed;

namespace libsed {
namespace test {

/// @brief 테스트용 MockTransport 생성 — 큐가 비면 즉시 에러 반환 (30초 timeout 방지)
inline std::shared_ptr<MockTransport> makeMock() {
    auto mock = std::make_shared<MockTransport>();
    // 큐가 비었을 때 empty 응답 대신 EndOfSession 토큰을 반환하여
    // Session 소멸자의 closeSession()이 빠르게 완료되도록 함
    // (기본 동작: bytesReceived=0 → 30초 polling timeout)
    return mock;
}

using eval::EvalApi;
using eval::PropertiesResult;
using eval::StartSessionResult;
using eval::SyncSessionResult;
using eval::StartSessionParams;
using eval::RawResult;
using eval::TableResult;
using eval::LockingInfo;
using eval::ByteTableInfo;
using eval::DataOpResult;
using eval::AceInfo;

// ═══════════════════════════════════════════════════════
//  Mock Response Builder — 유효한 TCG 응답 패킷 생성
// ═══════════════════════════════════════════════════════

/// SM(Session Manager) 패킷 응답을 빌드 (TSN=0, HSN=0)
inline Bytes buildSmResponse(uint16_t comId, const Bytes& tokenPayload) {
    PacketBuilder builder;
    builder.setComId(comId);
    builder.setSessionNumbers(0, 0);
    return builder.buildSessionManagerPacket(tokenPayload);
}

/// In-session 패킷 응답을 빌드 (주어진 TSN/HSN)
inline Bytes buildSessionResponse(uint16_t comId, uint32_t tsn, uint32_t hsn,
                                   const Bytes& tokenPayload) {
    PacketBuilder builder;
    builder.setComId(comId);
    builder.setSessionNumbers(tsn, hsn);
    return builder.buildComPacket(tokenPayload);
}

/// 성공 Status 토큰 생성: EndOfData + [ 0, 0, 0 ]
inline Bytes buildStatusTokens(uint8_t statusCode = 0) {
    TokenEncoder enc;
    enc.endOfData();
    enc.startList();
    enc.encodeUint(statusCode);
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();
    return enc.data();
}

/// Properties 응답 토큰 생성
inline Bytes buildPropertiesResponseTokens(
    uint32_t maxComPkt = 2048, uint32_t maxPkt = 2028,
    uint32_t maxIndToken = 2016, uint32_t maxAggToken = 2016,
    uint32_t maxMethods = 1, uint32_t maxSubPkts = 1)
{
    TokenEncoder enc;
    // CALL header (SM method)
    enc.call();
    enc.encodeUid(uid::SMUID);                             // SM UID
    enc.encodeUid(method::SM_PROPERTIES);                  // Method UID
    enc.startList();

    // TPerProperties
    enc.startName();
    enc.encodeString("TPerProperties");
    enc.startList();
    enc.encodeString("MaxMethods");        enc.encodeUint(maxMethods);
    enc.encodeString("MaxSubpackets");     enc.encodeUint(maxSubPkts);
    enc.encodeString("MaxPackets");        enc.encodeUint(1);
    enc.encodeString("MaxComPacketSize");  enc.encodeUint(maxComPkt);
    enc.encodeString("MaxPacketSize");     enc.encodeUint(maxPkt);
    enc.encodeString("MaxIndTokenSize");   enc.encodeUint(maxIndToken);
    enc.encodeString("MaxAggTokenSize");   enc.encodeUint(maxAggToken);
    enc.encodeString("ContinuedTokens");   enc.encodeUint(0);
    enc.encodeString("SequenceNumbers");   enc.encodeUint(0);
    enc.encodeString("AckNak");            enc.encodeUint(0);
    enc.encodeString("Async");             enc.encodeUint(0);
    enc.endList();
    enc.endName();

    // HostProperties (echo back)
    enc.startName();
    enc.encodeString("HostProperties");
    enc.startList();
    enc.encodeString("MaxComPacketSize");  enc.encodeUint(maxComPkt);
    enc.encodeString("MaxPacketSize");     enc.encodeUint(maxPkt);
    enc.encodeString("MaxIndTokenSize");   enc.encodeUint(maxIndToken);
    enc.endList();
    enc.endName();

    enc.endList();

    auto status = buildStatusTokens(0);
    auto data = enc.data();
    data.insert(data.end(), status.begin(), status.end());
    return data;
}

/// SyncSession 응답 토큰 생성
inline Bytes buildSyncSessionTokens(uint32_t hsn, uint32_t tsn) {
    TokenEncoder enc;
    // CALL header
    enc.call();
    enc.encodeUid(uid::SMUID);
    enc.encodeUid(method::SM_SYNC_SESSION);
    enc.startList();
    enc.encodeUint(hsn);
    enc.encodeUint(tsn);
    enc.endList();

    auto status = buildStatusTokens(0);
    auto data = enc.data();
    data.insert(data.end(), status.begin(), status.end());
    return data;
}

/// 성공 메서드 응답 (빈 결과) — Set, Activate, Revert 등에 사용
inline Bytes buildEmptyMethodResponse() {
    TokenEncoder enc;
    enc.startList();
    enc.endList();

    auto status = buildStatusTokens(0);
    auto data = enc.data();
    data.insert(data.end(), status.begin(), status.end());
    return data;
}

/// Get 메서드 응답 — 컬럼-값 쌍 포함
inline Bytes buildGetResponseTokens(
    const std::vector<std::pair<uint32_t, Bytes>>& columnValues)
{
    TokenEncoder enc;
    enc.startList();
    for (const auto& [col, val] : columnValues) {
        enc.startName();
        enc.encodeUint(col);
        enc.encodeBytes(val.data(), val.size());
        enc.endName();
    }
    enc.endList();

    auto status = buildStatusTokens(0);
    auto data = enc.data();
    data.insert(data.end(), status.begin(), status.end());
    return data;
}

/// Get 메서드 응답 — uint 컬럼-값 쌍
inline Bytes buildGetUintResponseTokens(
    const std::vector<std::pair<uint32_t, uint64_t>>& columnValues)
{
    TokenEncoder enc;
    enc.startList();
    for (const auto& [col, val] : columnValues) {
        enc.startName();
        enc.encodeUint(col);
        enc.encodeUint(val);
        enc.endName();
    }
    enc.endList();

    auto status = buildStatusTokens(0);
    auto data = enc.data();
    data.insert(data.end(), status.begin(), status.end());
    return data;
}

/// Get 메서드 응답 — bool 컬럼-값 쌍
inline Bytes buildGetBoolResponseTokens(
    const std::vector<std::pair<uint32_t, bool>>& columnValues)
{
    TokenEncoder enc;
    enc.startList();
    for (const auto& [col, val] : columnValues) {
        enc.startName();
        enc.encodeUint(col);
        enc.encodeUint(val ? 1 : 0);
        enc.endName();
    }
    enc.endList();

    auto status = buildStatusTokens(0);
    auto data = enc.data();
    data.insert(data.end(), status.begin(), status.end());
    return data;
}

/// 에러 상태 메서드 응답
inline Bytes buildErrorMethodResponse(uint8_t statusCode) {
    TokenEncoder enc;
    enc.startList();
    enc.endList();

    auto status = buildStatusTokens(statusCode);
    auto data = enc.data();
    data.insert(data.end(), status.begin(), status.end());
    return data;
}

// ═══════════════════════════════════════════════════════
//  MockTransport에 전체 시퀀스 큐잉 헬퍼
// ═══════════════════════════════════════════════════════

/// StackReset 응답 큐잉 (빈 응답)
inline void queueStackResetResponse(MockTransport& mock) {
    mock.queueRecvData(Bytes(2048, 0));
}

/// Properties 응답 큐잉 (StackReset + Properties 결과)
inline void queuePropertiesResponse(MockTransport& mock, uint16_t comId) {
    queueStackResetResponse(mock);
    auto tokens = buildPropertiesResponseTokens();
    mock.queueRecvData(buildSmResponse(comId, tokens));
}

/// SyncSession 응답 큐잉 (+ auto-close 응답 포함)
/// autoClose=true (기본): 소멸자에서 closeSession 호출 시 timeout 방지를 위해
/// CloseSession 응답도 함께 큐잉. 테스트에서 명시적 close를 하는 경우 false 사용.
inline void queueSyncSessionResponse(MockTransport& mock, uint16_t comId,
                                       uint32_t hsn = 1, uint32_t tsn = 1,
                                       bool autoClose = false) {
    auto tokens = buildSyncSessionTokens(hsn, tsn);
    mock.queueRecvData(buildSmResponse(comId, tokens));
    // Note: autoClose는 마지막에 큐잉해야 하므로 호출자가 관리
}

/// 성공 메서드 응답 큐잉 (in-session, Set/Activate 등)
inline void queueMethodSuccessResponse(MockTransport& mock, uint16_t comId,
                                         uint32_t tsn = 1, uint32_t hsn = 1) {
    auto tokens = buildEmptyMethodResponse();
    mock.queueRecvData(buildSessionResponse(comId, tsn, hsn, tokens));
}

/// Get 메서드 응답 큐잉 (bytes 컬럼)
inline void queueGetBytesResponse(MockTransport& mock, uint16_t comId,
                                    uint32_t tsn, uint32_t hsn,
                                    uint32_t col, const Bytes& value) {
    auto tokens = buildGetResponseTokens({{col, value}});
    mock.queueRecvData(buildSessionResponse(comId, tsn, hsn, tokens));
}

/// Get 메서드 응답 큐잉 (uint 컬럼들)
inline void queueGetUintResponse(MockTransport& mock, uint16_t comId,
                                   uint32_t tsn, uint32_t hsn,
                                   const std::vector<std::pair<uint32_t, uint64_t>>& cols) {
    auto tokens = buildGetUintResponseTokens(cols);
    mock.queueRecvData(buildSessionResponse(comId, tsn, hsn, tokens));
}

/// CloseSession 응답 큐잉 (빈 SM 패킷)
inline void queueCloseSessionResponse(MockTransport& mock, uint16_t comId) {
    // CloseSession 응답은 EndOfSession 토큰 (0xFA) — SM 패킷
    TokenEncoder enc;
    enc.endOfSession();
    mock.queueRecvData(buildSmResponse(comId, enc.data()));
}

/// 에러 메서드 응답 큐잉
inline void queueMethodErrorResponse(MockTransport& mock, uint16_t comId,
                                       uint32_t tsn, uint32_t hsn,
                                       uint8_t statusCode) {
    auto tokens = buildErrorMethodResponse(statusCode);
    mock.queueRecvData(buildSessionResponse(comId, tsn, hsn, tokens));
}

// ═══════════════════════════════════════════════════════
//  전체 시퀀스 큐잉 (여러 응답을 한 번에 설정)
// ═══════════════════════════════════════════════════════

/// Query Flow 전체 응답 큐잉: Discovery + Properties + SyncSession + Get(MSID) + Close
inline void queueQueryFlowResponses(MockTransport& mock, uint16_t comId,
                                      const Bytes& msidValue) {
    // 1. Discovery
    mock.queueDiscoveryResponse(SscType::Opal20);
    // 2. Properties (StackReset + Properties)
    queuePropertiesResponse(mock, comId);
    // 3. SyncSession (anonymous)
    queueSyncSessionResponse(mock, comId, 1, 1);
    // 4. Get CPIN_MSID → returns PIN column (col 3 = PIN)
    queueGetBytesResponse(mock, comId, 1, 1, 3, msidValue);
    // 5. CloseSession
    queueCloseSessionResponse(mock, comId);
}

/// TakeOwnership 응답 큐잉 (getMsid + Auth session + SetCPin + Close)
inline void queueTakeOwnershipResponses(MockTransport& mock, uint16_t comId,
                                          const Bytes& msidValue) {
    // getMsid part
    queueQueryFlowResponses(mock, comId, msidValue);
    // Auth session (SID with MSID credential)
    queueSyncSessionResponse(mock, comId, 2, 2);
    // SetCPin(SID, newPw) success
    queueMethodSuccessResponse(mock, comId, 2, 2);
    // CloseSession
    queueCloseSessionResponse(mock, comId);
}

} // namespace test
} // namespace libsed
