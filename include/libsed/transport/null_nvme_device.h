#pragma once
#include "i_nvme_device.h"
#include <string>

namespace libsed {

/// Null/stub NVMe device — every operation returns TransportNotAvailable.
/// Intended as a base class: subclass and override the methods you support
/// by forwarding to your NVMe backend (libnvme, ioctl, etc.).
class NullNvmeDevice : public INvmeDevice {
public:
    explicit NullNvmeDevice(const std::string& device_path = "")
        : device_path_(device_path) {}
    ~NullNvmeDevice() override = default;

    Result securitySend(uint8_t, uint16_t, const uint8_t*, uint32_t) override {
        return ErrorCode::TransportNotAvailable; // Override in your subclass to forward to libnvme
    }
    Result securityRecv(uint8_t, uint16_t, uint8_t*, uint32_t, uint32_t& r) override {
        r = 0; return ErrorCode::TransportNotAvailable; // Override in your subclass to forward to libnvme
    }
    Result adminCommand(NvmeAdminCmd&, NvmeCompletion& c) override {
        c = {}; return ErrorCode::TransportNotAvailable; // Override in your subclass to forward to libnvme
    }
    Result ioCommand(NvmeIoCmd&, NvmeCompletion& c) override {
        c = {}; return ErrorCode::TransportNotAvailable; // Override in your subclass to forward to libnvme
    }
    Result identify(uint8_t, uint32_t, Bytes& d) override {
        d.clear(); return ErrorCode::TransportNotAvailable;
    }
    Result getLogPage(uint8_t, uint32_t, Bytes& d, uint32_t) override {
        d.clear(); return ErrorCode::TransportNotAvailable;
    }
    Result getFeature(uint8_t, uint32_t, uint32_t& c, Bytes&) override {
        c = 0; return ErrorCode::TransportNotAvailable;
    }
    Result setFeature(uint8_t, uint32_t, uint32_t, const Bytes&) override {
        return ErrorCode::TransportNotAvailable;
    }
    Result formatNvm(uint32_t, uint8_t, uint8_t, uint8_t) override {
        return ErrorCode::TransportNotAvailable;
    }
    Result sanitize(uint8_t, uint32_t) override { return ErrorCode::TransportNotAvailable; }
    Result fwDownload(const Bytes&, uint32_t) override { return ErrorCode::TransportNotAvailable; }
    Result fwCommit(uint8_t, uint8_t) override { return ErrorCode::TransportNotAvailable; }
    Result nsCreate(const Bytes&, uint32_t& n) override { n=0; return ErrorCode::TransportNotAvailable; }
    Result nsDelete(uint32_t) override { return ErrorCode::TransportNotAvailable; }
    Result nsAttach(uint32_t, uint16_t, bool) override { return ErrorCode::TransportNotAvailable; }

    std::string devicePath() const override { return device_path_; }
    bool isOpen() const override { return false; }
    void close() override {}
    int fd() const override { return -1; }
private:
    std::string device_path_;
};

} // namespace libsed
