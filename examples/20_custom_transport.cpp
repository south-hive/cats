/// @file 20_custom_transport.cpp
/// @brief Custom Transport — Implementing the ITransport Interface
///
/// TCG SPEC CONTEXT:
/// The ITransport interface is the boundary between libsed and the hardware.
/// All TCG communication goes through two methods:
///
///   ifSend(protocolId, comId, payload) — send data to the TPer
///   ifRecv(protocolId, comId, buffer, bytesReceived) — receive from the TPer
///
/// These map directly to the TCG spec's IF-SEND and IF-RECV primitives,
/// which in turn map to:
///   - NVMe: Security Send (opcode 0x81) / Security Receive (opcode 0x82)
///   - SCSI: Security Protocol Out (0xB5) / Security Protocol In (0xA2)
///   - ATA: Trusted Send (0x5E) / Trusted Receive (0x5C)
///
/// Protocol IDs:
///   0x01 = TCG ComID management (Discovery, session traffic)
///   0x02 = Stack Reset (reset ComID state)
///
/// By implementing ITransport, you can:
///   - Add logging/tracing layers (see LoggingTransport)
///   - Create test doubles (see SimTransport)
///   - Support new transport types (USB, remote, etc.)
///   - Implement protocol proxies or MITM debugging tools
///
/// API LAYER: ITransport interface
/// PREREQUISITES: 01 (understanding of Discovery and basic protocol flow)
///
/// Usage: ./20_custom_transport /dev/nvmeX [--dump]

#include "example_common.h"

// ── Scenario 1: Counting Transport (Decorator) ──
//
// A transport wrapper that counts all sends and receives.
// This demonstrates the decorator pattern for ITransport.

class CountingTransport : public ITransport {
public:
    explicit CountingTransport(std::shared_ptr<ITransport> inner)
        : inner_(std::move(inner)) {}

    Result ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) override {
        sendCount_++;
        totalBytesSent_ += payload.size();
        printf("    [CountingTransport] ifSend #%u: proto=0x%02X comId=0x%04X %zu bytes\n",
               sendCount_, protocolId, comId, payload.size());
        return inner_->ifSend(protocolId, comId, payload);
    }

    Result ifRecv(uint8_t protocolId, uint16_t comId,
                  MutableByteSpan buffer, size_t& bytesReceived) override {
        recvCount_++;
        auto r = inner_->ifRecv(protocolId, comId, buffer, bytesReceived);
        totalBytesRecv_ += bytesReceived;
        printf("    [CountingTransport] ifRecv #%u: proto=0x%02X comId=0x%04X %zu bytes\n",
               recvCount_, protocolId, comId, bytesReceived);
        return r;
    }

    TransportType type() const override { return inner_->type(); }
    std::string devicePath() const override { return inner_->devicePath(); }
    bool isOpen() const override { return inner_->isOpen(); }
    void close() override { inner_->close(); }

    void printStats() const {
        printf("    Transport Statistics:\n");
        printf("      Sends: %u (%zu bytes total)\n", sendCount_, totalBytesSent_);
        printf("      Recvs: %u (%zu bytes total)\n", recvCount_, totalBytesRecv_);
    }

private:
    std::shared_ptr<ITransport> inner_;
    uint32_t sendCount_ = 0;
    uint32_t recvCount_ = 0;
    size_t totalBytesSent_ = 0;
    size_t totalBytesRecv_ = 0;
};

static bool scenario1_countingTransport(std::shared_ptr<ITransport> transport,
                                         uint16_t comId) {
    scenario(1, "Counting Transport (Decorator Pattern)");

    // Wrap the real transport with our counter
    auto counting = std::make_shared<CountingTransport>(transport);

    EvalApi api;
    DiscoveryInfo info;

    // Run some operations through the counting transport
    auto r = api.discovery0(counting, info);
    step(1, "Discovery via CountingTransport", r);

    PropertiesResult props;
    r = api.exchangeProperties(counting, comId, props);
    step(2, "Properties via CountingTransport", r);

    // Read MSID
    Session session(counting, comId);
    StartSessionResult ssr;
    r = api.startSession(session, uid::SP_ADMIN, false, ssr);
    if (r.ok()) {
        Bytes msid;
        api.getCPin(session, uid::CPIN_MSID, msid);
        api.closeSession(session);
    }
    step(3, "MSID read via CountingTransport", r);

    printf("\n");
    counting->printStats();

    return true;
}

// ── Scenario 2: Filtering Transport ──
//
// A transport that blocks specific protocol IDs — useful for testing
// what happens when certain operations are unavailable.

class FilteringTransport : public ITransport {
public:
    FilteringTransport(std::shared_ptr<ITransport> inner, uint8_t blockProtocol)
        : inner_(std::move(inner)), blockProtocol_(blockProtocol) {}

    Result ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) override {
        if (protocolId == blockProtocol_) {
            printf("    [Filter] Blocked ifSend proto=0x%02X\n", protocolId);
            return ErrorCode::TransportSendFailed;
        }
        return inner_->ifSend(protocolId, comId, payload);
    }

    Result ifRecv(uint8_t protocolId, uint16_t comId,
                  MutableByteSpan buffer, size_t& bytesReceived) override {
        if (protocolId == blockProtocol_) {
            printf("    [Filter] Blocked ifRecv proto=0x%02X\n", protocolId);
            bytesReceived = 0;
            return ErrorCode::TransportRecvFailed;
        }
        return inner_->ifRecv(protocolId, comId, buffer, bytesReceived);
    }

    TransportType type() const override { return inner_->type(); }
    std::string devicePath() const override { return inner_->devicePath(); }
    bool isOpen() const override { return inner_->isOpen(); }
    void close() override { inner_->close(); }

private:
    std::shared_ptr<ITransport> inner_;
    uint8_t blockProtocol_;
};

static bool scenario2_filteringTransport(std::shared_ptr<ITransport> transport) {
    scenario(2, "Filtering Transport (Block Stack Reset)");

    // Block protocol 0x02 (Stack Reset) while allowing everything else
    auto filtering = std::make_shared<FilteringTransport>(transport, 0x02);

    EvalApi api;

    // Discovery should work (uses protocol 0x01)
    DiscoveryInfo info;
    auto r = api.discovery0(filtering, info);
    step(1, "Discovery (proto 0x01) — should work", r);

    // Stack Reset should fail (uses protocol 0x02)
    EvalApi stackApi;
    r = stackApi.stackReset(filtering, info.baseComId);
    step(2, "StackReset (proto 0x02) — should be blocked", r.failed());

    return true;
}

// ── Scenario 3: The ITransport Interface Contract ──

static bool scenario3_interfaceDoc() {
    scenario(3, "ITransport Interface Reference");

    printf("    ITransport has exactly 2 methods to implement:\n\n");

    printf("    Result ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload)\n");
    printf("      - protocolId: 0x01 (TCG), 0x02 (StackReset)\n");
    printf("      - comId: from Discovery (e.g., 0x07FE for Opal)\n");
    printf("      - payload: padded to 512-byte boundary\n\n");

    printf("    Result ifRecv(uint8_t protocolId, uint16_t comId,\n");
    printf("                  MutableByteSpan buffer, size_t& bytesReceived)\n");
    printf("      - Same protocolId/comId as the matching ifSend\n");
    printf("      - buffer: pre-allocated receive buffer\n");
    printf("      - bytesReceived: actual bytes returned by TPer\n\n");

    printf("    Built-in implementations:\n");
    printf("      NvmeTransport  — NVMe Security Send/Receive (or DI via INvmeDevice)\n");
    printf("      AtaTransport   — ATA Trusted Send/Receive via SG_IO\n");
    printf("      ScsiTransport  — SCSI Security Protocol In/Out via SG_IO\n");
    printf("      SimTransport   — Software SED simulator (no hardware)\n");
    printf("      LoggingTransport — Decorator for packet dumping/logging\n");

    return true;
}

int main(int argc, char* argv[]) {
    cli::CliOptions opts;
    auto transport = initTransport(argc, argv, opts,
        "Custom Transport — implementing and decorating ITransport");
    if (!transport) return 1;

    banner("20: Custom Transport");

    EvalApi api;
    DiscoveryInfo info;
    auto r = api.discovery0(transport, info);
    if (r.failed()) { printf("Discovery failed\n"); return 1; }

    bool ok = true;
    ok &= scenario1_countingTransport(transport, info.baseComId);
    ok &= scenario2_filteringTransport(transport);
    ok &= scenario3_interfaceDoc();

    printf("\n%s\n", ok ? "All scenarios passed." : "Some scenarios failed.");
    return ok ? 0 : 1;
}
