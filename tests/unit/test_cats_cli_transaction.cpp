// Unit tests for cats-cli transaction script parser (parseTxScript).
//
// smoke 테스트는 실제 바이너리를 실행해 exit code로 확인한다. 여기서는 parser
// 레벨에서 스키마 위반이 먼저 정확히 걸러지는지를 바이트 단위로 검증한다 —
// smoke가 보장하지 못하는 negative path 커버리지.

#include "tools/cats-cli/transaction.h"

#include <libsed/core/uid.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

#ifndef TEST
#define TEST(suite, name) void test_##suite##_##name()
#define EXPECT_EQ(a, b) assert((a) == (b))
#define EXPECT_TRUE(a) assert(a)
#define EXPECT_FALSE(a) assert(!(a))
#define RUN_TEST(suite, name) do { printf("  " #suite "." #name "..."); test_##suite##_##name(); printf(" OK\n"); } while(0)
#endif

using namespace catscli;
using namespace libsed;

static std::string getenvStub(const char* name) {
    // Provide deterministic env lookups for tests regardless of host.
    if (std::strcmp(name, "CATS_TEST_PW") == 0) return "secret";
    if (std::strcmp(name, "CATS_TEST_EMPTY") == 0) return "";
    return {};
}

// ── Positive cases (fixtures) ────────────────────────────────────────────────

TEST(TxParse, PositiveReadAnonymous) {
    const std::string script = R"({
  "version": 1,
  "session": { "sp": "Admin", "authority": "Anybody" },
  "ops": [
    { "op": "get", "object": "C_PIN_MSID", "columns": [3, 3] }
  ]
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_TRUE(err.empty());
    EXPECT_EQ(out.version, 1);
    EXPECT_EQ(out.spUid, uid::SP_ADMIN);
    EXPECT_TRUE(out.anonymous);
    EXPECT_FALSE(out.write);                   // Anybody forces write=false
    EXPECT_EQ(out.ops.size(), (size_t)1);
    EXPECT_EQ(out.ops[0].op, std::string("get"));
    EXPECT_EQ(out.ops[0].objectUid, uid::CPIN_MSID);
    EXPECT_EQ(out.ops[0].colStart, (uint32_t)3);
    EXPECT_EQ(out.ops[0].colEnd,   (uint32_t)3);
}

TEST(TxParse, PositiveTxnWithPwEnv) {
    const std::string script = R"({
  "version": 1,
  "session": { "sp": "Locking", "authority": "Admin1", "pw_env": "CATS_TEST_PW" },
  "ops": [
    { "op": "start_transaction" },
    { "op": "set", "object": "LockingRange1",
      "values": { "RangeStart": 0, "RangeLength": 1024,
                  "ReadLockEnabled": true, "WriteLockEnabled": true } },
    { "op": "get", "object": "LockingRange1", "columns": [0, 10] },
    { "op": "commit" }
  ],
  "on_error": "rollback"
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_TRUE(err.empty());
    EXPECT_EQ(out.spUid, uid::SP_LOCKING);
    EXPECT_EQ(out.authUid, uid::AUTH_ADMIN1);
    EXPECT_FALSE(out.anonymous);
    EXPECT_TRUE(out.write);
    EXPECT_EQ(out.credential.size(), (size_t)6);  // "secret"
    EXPECT_EQ(out.onError, std::string("rollback"));
    EXPECT_EQ(out.ops.size(), (size_t)4);
    EXPECT_EQ(out.ops[0].op, std::string("start_transaction"));
    EXPECT_EQ(out.ops[1].op, std::string("set"));
    EXPECT_EQ(out.ops[1].values.size(), (size_t)4);
    EXPECT_EQ(out.ops[3].op, std::string("commit"));
}

TEST(TxParse, PositiveGenKey) {
    const std::string script = R"({
  "version": 1,
  "session": { "sp": "Locking", "authority": "Admin1", "pw": "hunter2" },
  "ops": [
    { "op": "genkey", "object": "LockingRange1" }
  ]
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_TRUE(err.empty());
    EXPECT_EQ(out.ops.size(), (size_t)1);
    EXPECT_EQ(out.ops[0].op, std::string("genkey"));
    EXPECT_EQ(out.ops[0].objectLabel, std::string("LockingRange1"));
    // Inline pw is preserved as-is — actual SHA-256 happens at runTxScript.
    EXPECT_EQ(out.credential.size(), (size_t)7);
}

// ── Negative cases ───────────────────────────────────────────────────────────

TEST(TxParse, RejectMissingVersion) {
    const std::string script = R"({ "session": {"sp":"Admin","authority":"Anybody"}, "ops": [] })";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("version") != std::string::npos);
}

TEST(TxParse, RejectUnsupportedVersion) {
    const std::string script = R"({ "version": 2, "session": {"sp":"Admin","authority":"Anybody"}, "ops": [] })";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("version") != std::string::npos);
}

TEST(TxParse, RejectUnknownSP) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Bogus", "authority": "Admin1", "pw": "x" }, "ops": []
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("unknown session.sp") != std::string::npos);
}

TEST(TxParse, RejectUnknownAuthority) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Admin", "authority": "Napoleon", "pw": "x" }, "ops": []
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("unknown session.authority") != std::string::npos);
}

TEST(TxParse, RejectUnknownObject) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Admin", "authority": "Anybody" },
  "ops": [ { "op": "get", "object": "WhoKnows" } ]
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("unknown object") != std::string::npos);
}

TEST(TxParse, RejectUnknownColumn) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Locking", "authority": "Admin1", "pw": "x" },
  "ops": [ { "op": "set", "object": "LockingRange1",
             "values": { "MysteryCol": 1 } } ]
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("unknown column") != std::string::npos);
}

TEST(TxParse, RejectTwoPasswordSources) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Locking", "authority": "Admin1",
                              "pw": "a", "pw_env": "CATS_TEST_PW" },
  "ops": []
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("use only one of pw") != std::string::npos);
}

TEST(TxParse, RejectAnybodyWithPassword) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Admin", "authority": "Anybody", "pw": "x" },
  "ops": []
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("Anybody") != std::string::npos);
}

TEST(TxParse, RejectEmptyEnvCredential) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Locking", "authority": "Admin1",
                              "pw_env": "CATS_TEST_EMPTY" },
  "ops": []
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("CATS_TEST_EMPTY") != std::string::npos);
}

TEST(TxParse, RejectMissingCredentialForNamedAuth) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Locking", "authority": "Admin1" },
  "ops": []
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("requires pw") != std::string::npos);
}

TEST(TxParse, RejectBadOnError) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Admin", "authority": "Anybody" },
  "ops": [], "on_error": "panic"
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("on_error") != std::string::npos);
}

TEST(TxParse, RejectUnknownOp) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Admin", "authority": "Anybody" },
  "ops": [ { "op": "launch_missiles" } ]
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("unknown op") != std::string::npos);
}

TEST(TxParse, RejectSleepMissingMs) {
    const std::string script = R"({
  "version": 1, "session": { "sp": "Admin", "authority": "Anybody" },
  "ops": [ { "op": "sleep" } ]
})";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("sleep") != std::string::npos);
}

TEST(TxParse, RejectMalformedJson) {
    const std::string script = R"({ "version": 1, "session": { "sp": "Admin" )";
    TxScript out;
    auto err = parseTxScript(script, out, getenvStub);
    EXPECT_FALSE(err.empty());
    EXPECT_TRUE(err.find("JSON parse error") != std::string::npos);
}

void run_cats_cli_transaction_tests() {
    printf("\n▶ cats-cli transaction parser tests\n");
    RUN_TEST(TxParse, PositiveReadAnonymous);
    RUN_TEST(TxParse, PositiveTxnWithPwEnv);
    RUN_TEST(TxParse, PositiveGenKey);
    RUN_TEST(TxParse, RejectMissingVersion);
    RUN_TEST(TxParse, RejectUnsupportedVersion);
    RUN_TEST(TxParse, RejectUnknownSP);
    RUN_TEST(TxParse, RejectUnknownAuthority);
    RUN_TEST(TxParse, RejectUnknownObject);
    RUN_TEST(TxParse, RejectUnknownColumn);
    RUN_TEST(TxParse, RejectTwoPasswordSources);
    RUN_TEST(TxParse, RejectAnybodyWithPassword);
    RUN_TEST(TxParse, RejectEmptyEnvCredential);
    RUN_TEST(TxParse, RejectMissingCredentialForNamedAuth);
    RUN_TEST(TxParse, RejectBadOnError);
    RUN_TEST(TxParse, RejectUnknownOp);
    RUN_TEST(TxParse, RejectSleepMissingMs);
    RUN_TEST(TxParse, RejectMalformedJson);
}
