#include "libsed/method/method_call.h"
#include "libsed/method/method_result.h"
#include "libsed/method/method_uids.h"
#include "libsed/method/param_encoder.h"
#include "libsed/codec/token_decoder.h"
#include "libsed/codec/token_stream.h"
#include "libsed/core/uid.h"
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

TEST(MethodCall, BuildGet) {
    Uid objectUid(0x0000080200030001ULL); // Locking range 1
    CellBlock cb;
    cb.startColumn = 3;
    cb.endColumn = 7;

    auto tokens = MethodCall::buildGet(objectUid, cb);
    EXPECT_TRUE(!tokens.empty());

    // Decode and verify structure
    TokenDecoder dec;
    auto r = dec.decode(tokens);
    EXPECT_TRUE(r.ok());

    // Should start with CALL token
    EXPECT_EQ(dec[0].type, TokenType::Call);

    // Invoking ID (8 bytes)
    EXPECT_TRUE(dec[1].isByteSequence);
    EXPECT_EQ(dec[1].getBytes().size(), 8u);

    // Method ID (8 bytes) - GET = 0x0000000600000006
    EXPECT_TRUE(dec[2].isByteSequence);
    EXPECT_EQ(dec[2].getBytes().size(), 8u);
}

TEST(MethodCall, BuildAuthenticate) {
    Uid authority(uid::AUTH_SID);
    Bytes credential = {0x70, 0x61, 0x73, 0x73}; // "pass"

    auto tokens = MethodCall::buildAuthenticate(authority, credential);
    EXPECT_TRUE(!tokens.empty());

    TokenDecoder dec;
    auto r = dec.decode(tokens);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(dec[0].type, TokenType::Call);
}

TEST(MethodCall, BuildStartSession) {
    auto params = ParamEncoder::encodeStartSession(105, Uid(uid::SP_ADMIN), false);
    auto tokens = MethodCall::buildSmCall(method::SM_START_SESSION, params);
    EXPECT_TRUE(!tokens.empty());

    TokenDecoder dec;
    auto r = dec.decode(tokens);
    EXPECT_TRUE(r.ok());
}

TEST(MethodResult, ParseSuccess) {
    // Simulate: StartList, val=42, EndList, EndOfData, StartList, 0, 0, 0, EndList
    TokenEncoder enc;
    enc.startList();
    enc.encodeUint(42);
    enc.endList();
    enc.endOfData();
    enc.startList();
    enc.encodeUint(0); // SUCCESS
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();

    MethodResult result;
    auto r = result.parse(enc.data());
    EXPECT_TRUE(r.ok());
    EXPECT_TRUE(result.isSuccess());
    EXPECT_EQ(result.status(), MethodStatus::Success);
}

TEST(MethodResult, ParseFailure) {
    TokenEncoder enc;
    enc.startList();
    enc.endList();
    enc.endOfData();
    enc.startList();
    enc.encodeUint(1); // NOT_AUTHORIZED
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();

    MethodResult result;
    auto r = result.parse(enc.data());
    EXPECT_TRUE(r.ok()); // Parse succeeded
    EXPECT_FALSE(result.isSuccess()); // But method failed
    EXPECT_EQ(result.status(), MethodStatus::NotAuthorized);
}

TEST(MethodResult, RecvCloseSessionMethodForm) {
    // TPer 가 0xFA 대신 SessionManager.CloseSession() method-form 으로 응답하는 케이스.
    // CALL + SMUID + SM_CLOSE_SESSION + StartList ENDList + EOD + status[0,0,0]
    TokenEncoder enc;
    enc.call();
    Bytes smuid(8, 0); smuid[7] = 0xff;
    enc.encodeBytes(smuid);                  // InvokingUID = SMUID
    Bytes muid(8, 0); muid[6] = 0xff; muid[7] = 0x06;
    enc.encodeBytes(muid);                   // MethodUID = 0x...FF06
    enc.startList();
    enc.endList();
    enc.endOfData();
    enc.startList();
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.encodeUint(0);
    enc.endList();

    MethodResult result;
    auto r = result.parse(enc.data());
    EXPECT_TRUE(r.ok());
    EXPECT_TRUE(result.isSuccess());
    EXPECT_EQ(result.recvMethodUid(), method::SM_CLOSE_SESSION);
    EXPECT_EQ(result.methodName(), std::string("CloseSession"));
}

TEST(ParamEncoder, StartSession) {
    auto data = ParamEncoder::encodeStartSession(105, Uid(uid::SP_ADMIN), false);
    EXPECT_TRUE(!data.empty());

    TokenDecoder dec;
    auto r = dec.decode(data);
    EXPECT_TRUE(r.ok());
    EXPECT_TRUE(dec.count() >= 2); // HSN + SP UID at minimum
}

TEST(ParamEncoder, CellBlock) {
    CellBlock cb;
    cb.startColumn = 3;
    cb.endColumn = 7;

    TokenEncoder enc;
    ParamEncoder::encodeCellBlock(enc, cb);
    auto data = enc.data();
    EXPECT_TRUE(!data.empty());
}

// ── SSC-aware method UID selection ─────────────────────────────────
// buildGet/Set/Authenticate emit Opal GET/SET/AUTHENTICATE by default,
// and EGET/ESET/EAUTHENTICATE when the Enterprise method UID is passed.
// Method UID lives at bytes 10..17 of the built token stream (1 CALL +
// 9-byte invoking-UID atom + 1-byte atom header for the method UID).

static uint64_t extractMethodUid(const Bytes& tokens) {
    // CALL (1) + invoking atom (1 hdr + 8 bytes) = offset 10 starts the
    // method-UID atom payload. Preceded by 1 header byte (0xA8).
    uint64_t uid = 0;
    for (int i = 0; i < 8; ++i) uid = (uid << 8) | tokens[11 + i];
    return uid;
}

TEST(MethodCall, OpalDefaults) {
    TokenList values;
    values.addUint(uid::col::PIN, 42);

    auto getTokens = MethodCall::buildGet(Uid(uid::CPIN_SID));
    auto setTokens = MethodCall::buildSet(Uid(uid::CPIN_SID), values);
    auto authTokens = MethodCall::buildAuthenticate(Uid(uid::AUTH_SID),
                                                     Bytes{'p','w'});

    EXPECT_EQ(extractMethodUid(getTokens),  method::GET);           // 0x16
    EXPECT_EQ(extractMethodUid(setTokens),  method::SET);           // 0x17
    EXPECT_EQ(extractMethodUid(authTokens), method::AUTHENTICATE);  // 0x1C
}

TEST(MethodCall, EnterpriseOverride) {
    TokenList values;
    values.addUint(uid::col::PIN, 42);

    auto getTokens = MethodCall::buildGet(Uid(uid::CPIN_SID), CellBlock{},
                                           method::EGET);
    auto setTokens = MethodCall::buildSet(Uid(uid::CPIN_SID), values,
                                           method::ESET);
    auto authTokens = MethodCall::buildAuthenticate(Uid(uid::AUTH_SID),
                                                     Bytes{'p','w'},
                                                     method::EAUTHENTICATE);

    EXPECT_EQ(extractMethodUid(getTokens),  method::EGET);           // 0x06
    EXPECT_EQ(extractMethodUid(setTokens),  method::ESET);           // 0x07
    EXPECT_EQ(extractMethodUid(authTokens), method::EAUTHENTICATE);  // 0x0C
}

TEST(MethodCall, SscUidSelectors) {
    EXPECT_EQ(method::getUidFor(SscType::Opal20),     method::GET);
    EXPECT_EQ(method::getUidFor(SscType::Pyrite20),   method::GET);
    EXPECT_EQ(method::getUidFor(SscType::Enterprise), method::EGET);

    EXPECT_EQ(method::setUidFor(SscType::Opal20),     method::SET);
    EXPECT_EQ(method::setUidFor(SscType::Enterprise), method::ESET);

    EXPECT_EQ(method::authenticateUidFor(SscType::Opal20),     method::AUTHENTICATE);
    EXPECT_EQ(method::authenticateUidFor(SscType::Enterprise), method::EAUTHENTICATE);
}

#ifndef GTEST_INCLUDE_GTEST_GTEST_H_
void run_method_tests() {
    printf("Method tests:\n");
    RUN_TEST(MethodCall, BuildGet);
    RUN_TEST(MethodCall, BuildAuthenticate);
    RUN_TEST(MethodCall, BuildStartSession);
    RUN_TEST(MethodCall, OpalDefaults);
    RUN_TEST(MethodCall, EnterpriseOverride);
    RUN_TEST(MethodCall, SscUidSelectors);
    RUN_TEST(MethodResult, ParseSuccess);
    RUN_TEST(MethodResult, ParseFailure);
    RUN_TEST(MethodResult, RecvCloseSessionMethodForm);
    RUN_TEST(ParamEncoder, StartSession);
    RUN_TEST(ParamEncoder, CellBlock);
    printf("  All Method tests passed!\n\n");
}
#endif
