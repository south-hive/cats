#include "libsed/session/session.h"
#include "libsed/session/session_manager.h"
#include "libsed/packet/packet_builder.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/codec/token.h"
#include "libsed/core/uid.h"
#include "libsed/eval/eval_api.h"
#include "mock/mock_transport.h"
#include <cassert>
#include <cstdio>

#ifndef TEST
#define TEST(suite, name) void test_##suite##_##name()
#define EXPECT_EQ(a, b) assert((a) == (b))
#define EXPECT_TRUE(a) assert(a)
#define EXPECT_FALSE(a) assert(!(a))
#define RUN_TEST(suite, name) do { printf("  " #suite "." #name "..."); test_##suite##_##name(); printf(" OK\n"); } while(0)
#endif

using namespace libsed;
using namespace libsed::test;

static Bytes buildSyncSessionResponse(uint32_t hsn, uint32_t tsn, uint16_t comId) {
    // Build a valid SyncSession response packet
    TokenEncoder enc;
    enc.startList();
    enc.encodeUint(hsn);
    enc.encodeUint(tsn);
    enc.endList();
    enc.endOfData();
    enc.startList();
    enc.encodeUint(0); // SUCCESS
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();

    PacketBuilder builder;
    builder.setComId(comId);
    builder.setSessionNumbers(0, 0); // SM packet

    return builder.buildSessionManagerPacket(enc.data());
}

TEST(Session, MockTransportBasic) {
    auto mock = std::make_shared<MockTransport>();
    EXPECT_TRUE(mock->isOpen());
    EXPECT_EQ(mock->type(), TransportType::ATA);
}

TEST(Session, MockSendRecord) {
    auto mock = std::make_shared<MockTransport>();
    Bytes data = {1, 2, 3, 4};
    mock->ifSend(1, 0x0001, ByteSpan(data.data(), data.size()));

    EXPECT_EQ(mock->sendHistory().size(), 1u);
    EXPECT_EQ(mock->sendHistory()[0].protocolId, 1u);
    EXPECT_EQ(mock->sendHistory()[0].comId, 0x0001);
}

TEST(Session, MockRecvQueue) {
    auto mock = std::make_shared<MockTransport>();
    Bytes testData = {0xAA, 0xBB, 0xCC};
    mock->queueRecvData(testData);

    Bytes buffer(10, 0);
    size_t received = 0;
    auto r = mock->ifRecv(1, 0x0001, MutableByteSpan(buffer.data(), buffer.size()), received);

    EXPECT_TRUE(r.ok());
    EXPECT_EQ(received, 3u);
    EXPECT_EQ(buffer[0], 0xAA);
    EXPECT_EQ(buffer[1], 0xBB);
    EXPECT_EQ(buffer[2], 0xCC);
}

TEST(Session, MockDiscoveryResponse) {
    auto mock = std::make_shared<MockTransport>();
    mock->queueDiscoveryResponse(SscType::Opal20);

    Bytes buffer(2048, 0);
    size_t received = 0;
    auto r = mock->ifRecv(1, 0, MutableByteSpan(buffer.data(), buffer.size()), received);

    EXPECT_TRUE(r.ok());
    EXPECT_TRUE(received > 48); // At least the discovery header
}

TEST(Session, PacketBuilderRoundtrip) {
    PacketBuilder builder;
    builder.setComId(0x0001);
    builder.setSessionNumbers(100, 200);

    TokenEncoder enc;
    enc.encodeUint(42);
    Bytes payload = enc.data();

    auto packet = builder.buildComPacket(payload);
    EXPECT_TRUE(packet.size() >= 512);

    PacketBuilder::ParsedResponse resp;
    auto r = builder.parseResponse(packet.data(), packet.size(), resp);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(resp.tokenPayload.size(), payload.size());
}

// ── Transaction token wire format ──────────────────────────────────

TEST(TxToken, StartTransactionSingleByte) {
    TokenEncoder enc;
    enc.startTransaction();
    auto d = enc.data();
    EXPECT_EQ(d.size(), 1u);
    EXPECT_EQ(d[0], static_cast<uint8_t>(TokenType::StartTransaction));
    EXPECT_EQ(d[0], uint8_t{0xFB});
}

TEST(TxToken, EndTransactionCommit) {
    TokenEncoder enc;
    enc.endTransaction(true);
    auto d = enc.data();
    EXPECT_EQ(d.size(), 2u);
    EXPECT_EQ(d[0], uint8_t{0xFC});
    EXPECT_EQ(d[1], uint8_t{0x00}); // commit
}

TEST(TxToken, EndTransactionAbort) {
    TokenEncoder enc;
    enc.endTransaction(false);
    auto d = enc.data();
    EXPECT_EQ(d.size(), 2u);
    EXPECT_EQ(d[0], uint8_t{0xFC});
    EXPECT_EQ(d[1], uint8_t{0x01}); // abort
}

TEST(TxToken, EndTransactionDefaultsToCommit) {
    // Default argument must behave as commit — matches the intent of
    // backward-compatible callers who upgrade without touching signatures.
    TokenEncoder enc;
    enc.endTransaction();
    auto d = enc.data();
    EXPECT_EQ(d.size(), 2u);
    EXPECT_EQ(d[1], uint8_t{0x00});
}

// ── EvalApi transaction boundaries → MockTransport round-trip ──────
//
// Drives a fully active Session against MockTransport, then calls each
// transaction boundary. Verifies that the token payload that hit the
// wire carried exactly the expected bytes and that RawResult captured
// them in rawSendPayload.

static void primeSessionActive(Session& session,
                                std::shared_ptr<MockTransport> mock,
                                uint32_t hsn, uint32_t tsn,
                                uint16_t comId) {
    // Queue a SyncSession response so startSession transitions to Active.
    mock->queueRecvData(buildSyncSessionResponse(hsn, tsn, comId));
    auto r = session.startSession(uid::SP_ADMIN, /*write=*/false);
    (void)r;
    // Also queue an empty response for the upcoming sendTokenPayload calls.
}

static Bytes buildEmptyStatusComPacket(uint16_t comId) {
    // Minimal ComPacket with an empty token payload so recvRaw has
    // something valid to hand back.
    TokenEncoder enc;
    enc.startList(); enc.endList();
    PacketBuilder b;
    b.setComId(comId);
    b.setSessionNumbers(0, 0);
    return b.buildSessionManagerPacket(enc.data());
}

TEST(TxApi, StartTransactionPayload) {
    auto mock = std::make_shared<MockTransport>();
    Session session(mock, 0x0001);
    primeSessionActive(session, mock, 105, 1, 0x0001);

    // Queue an empty-response packet so sendRecv has something to receive.
    mock->queueRecvData(buildEmptyStatusComPacket(0x0001));

    eval::EvalApi api;
    eval::RawResult raw;
    api.startTransaction(session, raw);

    EXPECT_EQ(raw.rawSendPayload.size(), 1u);
    EXPECT_EQ(raw.rawSendPayload[0], uint8_t{0xFB});
}

TEST(TxApi, CommitTransactionPayload) {
    auto mock = std::make_shared<MockTransport>();
    Session session(mock, 0x0001);
    primeSessionActive(session, mock, 105, 1, 0x0001);
    mock->queueRecvData(buildEmptyStatusComPacket(0x0001));

    eval::EvalApi api;
    eval::RawResult raw;
    api.commitTransaction(session, raw);

    EXPECT_EQ(raw.rawSendPayload.size(), 2u);
    EXPECT_EQ(raw.rawSendPayload[0], uint8_t{0xFC});
    EXPECT_EQ(raw.rawSendPayload[1], uint8_t{0x00});
}

TEST(TxApi, RollbackTransactionPayload) {
    auto mock = std::make_shared<MockTransport>();
    Session session(mock, 0x0001);
    primeSessionActive(session, mock, 105, 1, 0x0001);
    mock->queueRecvData(buildEmptyStatusComPacket(0x0001));

    eval::EvalApi api;
    eval::RawResult raw;
    api.rollbackTransaction(session, raw);

    EXPECT_EQ(raw.rawSendPayload.size(), 2u);
    EXPECT_EQ(raw.rawSendPayload[0], uint8_t{0xFC});
    EXPECT_EQ(raw.rawSendPayload[1], uint8_t{0x01});
}

#ifndef GTEST_INCLUDE_GTEST_GTEST_H_
void run_session_tests() {
    printf("Session tests:\n");
    RUN_TEST(Session, MockTransportBasic);
    RUN_TEST(Session, MockSendRecord);
    RUN_TEST(Session, MockRecvQueue);
    RUN_TEST(Session, MockDiscoveryResponse);
    RUN_TEST(Session, PacketBuilderRoundtrip);
    RUN_TEST(TxToken, StartTransactionSingleByte);
    RUN_TEST(TxToken, EndTransactionCommit);
    RUN_TEST(TxToken, EndTransactionAbort);
    RUN_TEST(TxToken, EndTransactionDefaultsToCommit);
    RUN_TEST(TxApi, StartTransactionPayload);
    RUN_TEST(TxApi, CommitTransactionPayload);
    RUN_TEST(TxApi, RollbackTransactionPayload);
    printf("  All Session tests passed!\n\n");
}
#endif
