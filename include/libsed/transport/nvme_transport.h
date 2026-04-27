#pragma once

#include "i_transport.h"
#include "i_nvme_device.h"
#include <string>
#include <memory>

namespace libsed {

/// NVMe transport via Security Send/Receive admin commands.
///
/// Two construction modes:
///   1. NvmeTransport(devicePath) — opens device directly (legacy)
///   2. NvmeTransport(nvmeDevice) — DI with your libnvme facade
///
/// When using DI mode, the caller can retrieve the INvmeDevice* to
/// issue arbitrary NVMe commands alongside TCG operations.
class NvmeTransport : public ITransport {
public:
    /// Legacy: open device directly
    explicit NvmeTransport(const std::string& devicePath);

    /// DI: inject your existing libnvme device
    explicit NvmeTransport(std::shared_ptr<INvmeDevice> nvmeDevice);

    ~NvmeTransport() override;

    Result ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) override;
    Result ifRecv(uint8_t protocolId, uint16_t comId,
                  MutableByteSpan buffer, size_t& bytesReceived) override;

    TransportType type() const override { return TransportType::NVMe; }
    std::string devicePath() const override;
    bool isOpen() const override;
    void close() override;

    /// Access the underlying INvmeDevice (DI mode only)
    /// Returns nullptr if constructed with devicePath (legacy mode).
    INvmeDevice* nvmeDevice() const { return nvmeDevice_.get(); }

    /// Get shared_ptr to INvmeDevice
    std::shared_ptr<INvmeDevice> nvmeDeviceShared() const { return nvmeDevice_; }

    /// NVMe Identify Controller (CNS=0x01, NSID=0). Works in BOTH modes:
    ///   - DI mode: delegates to INvmeDevice::identify
    ///   - Legacy fd mode: issues NVME_IOCTL_ADMIN_CMD directly
    /// Returns 4096-byte Identify Controller data on success.
    Result identifyController(Bytes& out);

private:
    Result openDirect();

    std::string devicePath_;
    int fd_ = -1;
    std::shared_ptr<INvmeDevice> nvmeDevice_;  ///< DI'd device (may be null)
};

} // namespace libsed
