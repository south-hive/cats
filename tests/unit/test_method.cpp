#include "libsed/method/method_call.h"
#include "libsed/method/method_result.h"
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

#ifndef GTEST_INCLUDE_GTEST_GTEST_H_
void run_method_tests() {
    printf("Method tests:\n");
    RUN_TEST(MethodCall, BuildGet);
    RUN_TEST(MethodCall, BuildAuthenticate);
    RUN_TEST(MethodCall, BuildStartSession);
    RUN_TEST(MethodResult, ParseSuccess);
    RUN_TEST(MethodResult, ParseFailure);
    RUN_TEST(ParamEncoder, StartSession);
    RUN_TEST(ParamEncoder, CellBlock);
    printf("  All Method tests passed!\n\n");
}
#endif
