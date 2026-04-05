#include "libsed/transport/nvme_transport.h"
#include "libsed/core/log.h"
#include "libsed/core/endian.h"

#if defined(__linux__) && !defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <cstring>
#endif

namespace libsed {

// ── Legacy constructor ──────────────────────────────

NvmeTransport::NvmeTransport(const std::string& devicePath)
    : devicePath_(devicePath) {
    auto r = openDirect();
    if (r.failed()) {
        LIBSED_ERROR("Failed to open NVMe device: %s", devicePath.c_str());
    }
}

// ── DI constructor ──────────────────────────────────

NvmeTransport::NvmeTransport(std::shared_ptr<INvmeDevice> nvmeDevice)
    : nvmeDevice_(std::move(nvmeDevice)) {
    if (nvmeDevice_) {
        devicePath_ = nvmeDevice_->devicePath();
        LIBSED_INFO("NvmeTransport created via DI for %s", devicePath_.c_str());
    }
}

NvmeTransport::~NvmeTransport() {
    close();
}

std::string NvmeTransport::devicePath() const {
    return devicePath_;
}

bool NvmeTransport::isOpen() const {
    if (nvmeDevice_) return nvmeDevice_->isOpen();
    return fd_ >= 0;
}

void NvmeTransport::close() {
    if (nvmeDevice_) {
        // Don't close DI'd device — the owner manages its lifetime
        return;
    }
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
#endif
}

Result NvmeTransport::openDirect() {
#if defined(__linux__) && !defined(__ANDROID__)
    fd_ = ::open(devicePath_.c_str(), O_RDWR);
    if (fd_ < 0) {
        LIBSED_ERROR("open(%s) failed: %s", devicePath_.c_str(), strerror(errno));
        return ErrorCode::TransportOpenFailed;
    }
    return ErrorCode::Success;
#else
    return ErrorCode::TransportNotAvailable;
#endif
}

// ── IF-SEND ─────────────────────────────────────────

Result NvmeTransport::ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) {
    // DI mode: delegate to INvmeDevice
    if (nvmeDevice_) {
        return nvmeDevice_->securitySend(protocolId, comId,
                                          payload.data(),
                                          static_cast<uint32_t>(payload.size()));
    }

    // Legacy mode: direct ioctl
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ < 0) return ErrorCode::TransportNotAvailable;

    size_t transferLen = ((payload.size() + 511) / 512) * 512;
    std::vector<uint8_t> buffer(transferLen, 0);
    std::memcpy(buffer.data(), payload.data(), payload.size());

    struct nvme_admin_cmd cmd = {};
    cmd.opcode = 0x81;  // Security Send
    cmd.nsid = 0;
    cmd.addr = reinterpret_cast<uint64_t>(buffer.data());
    cmd.data_len = static_cast<uint32_t>(buffer.size());
    cmd.cdw10 = (static_cast<uint32_t>(protocolId) << 24) |
                (static_cast<uint32_t>(comId) << 8);
    cmd.cdw11 = static_cast<uint32_t>(buffer.size());

    int ret = ioctl(fd_, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (ret < 0) {
        LIBSED_ERROR("NVMe Security Send failed: %s", strerror(errno));
        return ErrorCode::TransportSendFailed;
    }

    return ErrorCode::Success;
#else
    (void)protocolId; (void)comId; (void)payload;
    return ErrorCode::TransportNotAvailable;
#endif
}

// ── IF-RECV ─────────────────────────────────────────

Result NvmeTransport::ifRecv(uint8_t protocolId, uint16_t comId,
                               MutableByteSpan buffer, size_t& bytesReceived) {
    // DI mode: delegate to INvmeDevice
    if (nvmeDevice_) {
        uint32_t received = 0;
        auto r = nvmeDevice_->securityRecv(protocolId, comId,
                                            buffer.data(),
                                            static_cast<uint32_t>(buffer.size()),
                                            received);
        bytesReceived = received;
        return r;
    }

    // Legacy mode: direct ioctl
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ < 0) return ErrorCode::TransportNotAvailable;

    size_t transferLen = ((buffer.size() + 511) / 512) * 512;
    std::vector<uint8_t> recvBuf(transferLen, 0);

    struct nvme_admin_cmd cmd = {};
    cmd.opcode = 0x82;  // Security Receive
    cmd.nsid = 0;
    cmd.addr = reinterpret_cast<uint64_t>(recvBuf.data());
    cmd.data_len = static_cast<uint32_t>(recvBuf.size());
    cmd.cdw10 = (static_cast<uint32_t>(protocolId) << 24) |
                (static_cast<uint32_t>(comId) << 8);
    cmd.cdw11 = static_cast<uint32_t>(recvBuf.size());

    int ret = ioctl(fd_, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (ret < 0) {
        LIBSED_ERROR("NVMe Security Receive failed: %s", strerror(errno));
        return ErrorCode::TransportRecvFailed;
    }

    size_t copyLen = std::min(recvBuf.size(), buffer.size());
    std::memcpy(buffer.data(), recvBuf.data(), copyLen);

    // Extract actual payload size from ComPacket header (Rosetta Stone §1).
    // NVMe ioctl doesn't report actual bytes — must parse ComPacket.length
    // at offset 16-19 to determine real payload size.
    if (copyLen >= 20) {
        uint32_t comPacketLen = Endian::readBe32(buffer.data() + 16);
        bytesReceived = std::min(static_cast<size_t>(comPacketLen + 20), copyLen);
    } else {
        bytesReceived = copyLen;
    }

    return ErrorCode::Success;
#else
    (void)protocolId; (void)comId; (void)buffer; (void)bytesReceived;
    return ErrorCode::TransportNotAvailable;
#endif
}

} // namespace libsed
