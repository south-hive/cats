#include "libsed/debug/debug.h"
#include <cassert>
#include <cstdio>

using namespace libsed;
using namespace libsed::debug;

void test_global_config() {
    printf("  config_global...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    tc.setGlobalConfig("max_retries", int64_t{5});
    tc.setGlobalConfig("verbose", true);
    tc.setGlobalConfig("label", std::string{"test_run_001"});

    assert(tc.configInt("max_retries") == 5);
    assert(tc.configBool("verbose") == true);
    assert(tc.configStr("label") == "test_run_001");
    assert(tc.configInt("nonexistent", "", 42) == 42); // default

    tc.disable();
    printf(" OK\n");
}

void test_session_config_override() {
    printf("  config_session_override...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    tc.setGlobalConfig("timeout_ms", uint64_t{5000});
    tc.setConfig("timeout_ms", "sess_A", ConfigValue(uint64_t{30000}));

    // Session A gets its own value
    assert(tc.configUint("timeout_ms", "sess_A") == 30000);
    // Session B falls back to global
    assert(tc.configUint("timeout_ms", "sess_B") == 5000);
    // Global directly
    assert(tc.configUint("timeout_ms") == 5000);

    tc.disable();
    printf(" OK\n");
}

void test_fault_return_error() {
    printf("  fault_return_error...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    FaultBuilder("fail_send")
        .at(FaultPoint::BeforeIfSend)
        .returnError(ErrorCode::TransportSendFailed)
        .once()
        .arm();

    Bytes payload = {1, 2, 3};
    auto r = tc.checkFault(FaultPoint::BeforeIfSend, payload);
    assert(r.failed());
    assert(r.code() == ErrorCode::TransportSendFailed);

    // Second call should pass (once = auto-disarm)
    r = tc.checkFault(FaultPoint::BeforeIfSend, payload);
    assert(r.ok());

    tc.disable();
    printf(" OK\n");
}

void test_fault_corrupt() {
    printf("  fault_corrupt...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    FaultBuilder("corrupt_byte0")
        .at(FaultPoint::AfterIfRecv)
        .corrupt(0, 0xFF)
        .once()
        .arm();

    Bytes payload = {0x00, 0xAA, 0xBB};
    auto r = tc.checkFault(FaultPoint::AfterIfRecv, payload);
    assert(r.ok()); // corruption doesn't fail, just mutates
    assert(payload[0] == 0xFF); // 0x00 ^ 0xFF
    assert(payload[1] == 0xAA); // untouched

    tc.disable();
    printf(" OK\n");
}

void test_fault_replace() {
    printf("  fault_replace...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    Bytes replacement = {0xDE, 0xAD};
    FaultBuilder("replace_recv")
        .at(FaultPoint::AfterIfRecv)
        .replaceWith(replacement)
        .once()
        .arm();

    Bytes payload = {1, 2, 3, 4, 5};
    tc.checkFault(FaultPoint::AfterIfRecv, payload);
    assert(payload.size() == 2);
    assert(payload[0] == 0xDE);

    tc.disable();
    printf(" OK\n");
}

void test_fault_callback() {
    printf("  fault_callback...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    bool called = false;
    FaultBuilder("custom_cb")
        .at(FaultPoint::BeforeSendMethod)
        .callback([&](Bytes& p) -> Result {
            called = true;
            p.push_back(0xFF); // append a byte
            return ErrorCode::Success;
        })
        .once()
        .arm();

    Bytes payload = {1};
    tc.checkFault(FaultPoint::BeforeSendMethod, payload);
    assert(called);
    assert(payload.size() == 2);
    assert(payload.back() == 0xFF);

    tc.disable();
    printf(" OK\n");
}

void test_fault_hit_count() {
    printf("  fault_hit_count...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    FaultBuilder("fail_3_times")
        .at(FaultPoint::BeforeIfSend)
        .returnError(ErrorCode::TransportSendFailed)
        .times(3)
        .arm();

    Bytes p;
    assert(tc.checkFault(FaultPoint::BeforeIfSend, p).failed()); // 1
    assert(tc.checkFault(FaultPoint::BeforeIfSend, p).failed()); // 2
    assert(tc.checkFault(FaultPoint::BeforeIfSend, p).failed()); // 3
    assert(tc.checkFault(FaultPoint::BeforeIfSend, p).ok());     // spent

    tc.disable();
    printf(" OK\n");
}

void test_workaround() {
    printf("  workaround...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    assert(!tc.isWorkaroundActive(workaround::kRetryOnSpBusy));

    tc.activateWorkaround(workaround::kRetryOnSpBusy);
    assert(tc.isWorkaroundActive(workaround::kRetryOnSpBusy));

    // Session override
    tc.activateWorkaround(workaround::kExtendTimeout, "sess_X");
    assert(tc.isWorkaroundActive(workaround::kExtendTimeout, "sess_X"));
    assert(!tc.isWorkaroundActive(workaround::kExtendTimeout, "sess_Y")); // not for Y

    tc.deactivateWorkaround(workaround::kRetryOnSpBusy);
    assert(!tc.isWorkaroundActive(workaround::kRetryOnSpBusy));

    tc.disable();
    printf(" OK\n");
}

void test_counters() {
    printf("  counters...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    tc.bumpCounter("transport.send");
    tc.bumpCounter("transport.send");
    tc.bumpCounter("transport.send", 3);
    assert(tc.getCounter("transport.send") == 5);

    tc.bumpCounter("session.started", 1, "sess_A");
    assert(tc.getCounter("session.started", "sess_A") == 1);
    assert(tc.getCounter("session.started") == 0); // global is separate

    tc.resetCounter("transport.send");
    assert(tc.getCounter("transport.send") == 0);

    tc.disable();
    printf(" OK\n");
}

void test_trace() {
    printf("  trace...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    tc.trace(FaultPoint::BeforeIfSend, "IF-SEND", "comId=0x0001", {}, ErrorCode::Success);
    tc.trace(FaultPoint::AfterIfRecv, "IF-RECV", "size=512", {}, ErrorCode::Success);

    auto events = tc.getTrace();
    assert(events.size() == 2);
    assert(events[0].tag == "IF-SEND");
    assert(events[1].tag == "IF-RECV");

    tc.clearTrace();
    assert(tc.getTrace().empty());

    tc.disable();
    printf(" OK\n");
}

void test_trace_observer() {
    printf("  trace_observer...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    int observerCount = 0;
    tc.addTraceObserver([&](const TraceEvent& ev) {
        observerCount++;
    });

    tc.trace(FaultPoint::BeforeIfSend, "A", "", {}, ErrorCode::Success);
    tc.trace(FaultPoint::AfterIfRecv, "B", "", {}, ErrorCode::Success);

    assert(observerCount == 2);

    tc.disable();
    printf(" OK\n");
}

void test_session_lifecycle() {
    printf("  session_lifecycle...");
    auto& tc = TestContext::instance();
    tc.reset();
    tc.enable();

    {
        TestSession ts("opal_test_1");
        ts.config("force_error", true);
        ts.workaround(workaround::kRelaxTokenValidation);
        ts.fault(FaultBuilder("inject_err")
                     .at(FaultPoint::BeforeOpalOp)
                     .returnError(ErrorCode::MethodFailed)
                     .once());

        assert(tc.hasSession("opal_test_1"));
        assert(tc.configBool("force_error", "opal_test_1") == true);
        assert(tc.isWorkaroundActive(workaround::kRelaxTokenValidation, "opal_test_1"));
    }

    // Session destroyed on scope exit
    assert(!tc.hasSession("opal_test_1"));

    tc.disable();
    printf(" OK\n");
}

void test_disabled_noop() {
    printf("  disabled_noop...");
    auto& tc = TestContext::instance();
    tc.reset();
    // NOT enabled

    tc.setGlobalConfig("key", int64_t{99});
    assert(tc.configInt("key") == 0); // returns default when disabled

    FaultBuilder("should_not_fire")
        .at(FaultPoint::BeforeIfSend)
        .returnError(ErrorCode::InternalError)
        .arm();

    Bytes p;
    auto r = tc.checkFault(FaultPoint::BeforeIfSend, p);
    assert(r.ok()); // disabled, so no fault fires

    printf(" OK\n");
}

void run_debug_layer_tests() {
    printf("=== Debug Layer Tests ===\n");

    test_global_config();
    test_session_config_override();
    test_fault_return_error();
    test_fault_corrupt();
    test_fault_replace();
    test_fault_callback();
    test_fault_hit_count();
    test_workaround();
    test_counters();
    test_trace();
    test_trace_observer();
    test_session_lifecycle();
    test_disabled_noop();

    printf("  Debug layer: all passed\n");
}
