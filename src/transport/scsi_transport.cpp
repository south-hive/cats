#include "libsed/transport/scsi_transport.h"
#include "libsed/core/log.h"
#include "libsed/core/endian.h"

#if defined(__linux__) && !defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <cstring>
#endif

namespace libsed {

ScsiTransport::ScsiTransport(const std::string& devicePath)
    : devicePath_(devicePath) {
    auto r = open();
    if (r.failed()) {
        LIBSED_ERROR("Failed to open SCSI device: %s", devicePath.c_str());
    }
}

ScsiTransport::~ScsiTransport() {
    close();
}

Result ScsiTransport::open() {
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

void ScsiTransport::close() {
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
#endif
}

Result ScsiTransport::ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) {
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ < 0) return ErrorCode::TransportNotAvailable;

    // SCSI SECURITY PROTOCOL OUT (opcode 0xB5)
    size_t transferLen = ((payload.size() + 511) / 512) * 512;
    std::vector<uint8_t> buffer(transferLen, 0);
    std::memcpy(buffer.data(), payload.data(), payload.size());

    uint8_t cdb[12] = {};
    cdb[0] = 0xB5;          // SECURITY PROTOCOL OUT
    cdb[1] = protocolId;    // Security Protocol
    cdb[2] = static_cast<uint8_t>((comId >> 8) & 0xFF);  // Security Protocol Specific (MSB)
    cdb[3] = static_cast<uint8_t>(comId & 0xFF);          // Security Protocol Specific (LSB)
    cdb[4] = 0x80;          // INC_512 = 1
    // Transfer Length (sectors when INC_512=1)
    uint32_t sectors = static_cast<uint32_t>(transferLen / 512);
    cdb[6] = static_cast<uint8_t>((sectors >> 24) & 0xFF);
    cdb[7] = static_cast<uint8_t>((sectors >> 16) & 0xFF);
    cdb[8] = static_cast<uint8_t>((sectors >> 8) & 0xFF);
    cdb[9] = static_cast<uint8_t>(sectors & 0xFF);

    sg_io_hdr_t io_hdr = {};
    uint8_t senseBuf[32] = {};

    io_hdr.interface_id = 'S';
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.cmd_len = sizeof(cdb);
    io_hdr.mx_sb_len = sizeof(senseBuf);
    io_hdr.dxfer_len = static_cast<unsigned int>(buffer.size());
    io_hdr.dxferp = buffer.data();
    io_hdr.cmdp = cdb;
    io_hdr.sbp = senseBuf;
    io_hdr.timeout = 30000;

    int ret = ioctl(fd_, SG_IO, &io_hdr);
    if (ret < 0) {
        LIBSED_ERROR("SG_IO SECURITY_PROTOCOL_OUT failed: %s", strerror(errno));
        return ErrorCode::TransportSendFailed;
    }

    if (io_hdr.status != 0) {
        LIBSED_ERROR("SCSI SECURITY_PROTOCOL_OUT error: status=%d", io_hdr.status);
        return ErrorCode::TransportSendFailed;
    }

    return ErrorCode::Success;
#else
    (void)protocolId; (void)comId; (void)payload;
    return ErrorCode::TransportNotAvailable;
#endif
}

Result ScsiTransport::ifRecv(uint8_t protocolId, uint16_t comId,
                               MutableByteSpan buffer, size_t& bytesReceived) {
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ < 0) return ErrorCode::TransportNotAvailable;

    // SCSI SECURITY PROTOCOL IN (opcode 0xA2)
    size_t transferLen = ((buffer.size() + 511) / 512) * 512;
    std::vector<uint8_t> recvBuf(transferLen, 0);

    uint8_t cdb[12] = {};
    cdb[0] = 0xA2;          // SECURITY PROTOCOL IN
    cdb[1] = protocolId;
    cdb[2] = static_cast<uint8_t>((comId >> 8) & 0xFF);
    cdb[3] = static_cast<uint8_t>(comId & 0xFF);
    cdb[4] = 0x80;          // INC_512 = 1
    uint32_t sectors = static_cast<uint32_t>(transferLen / 512);
    cdb[6] = static_cast<uint8_t>((sectors >> 24) & 0xFF);
    cdb[7] = static_cast<uint8_t>((sectors >> 16) & 0xFF);
    cdb[8] = static_cast<uint8_t>((sectors >> 8) & 0xFF);
    cdb[9] = static_cast<uint8_t>(sectors & 0xFF);

    sg_io_hdr_t io_hdr = {};
    uint8_t senseBuf[32] = {};

    io_hdr.interface_id = 'S';
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.cmd_len = sizeof(cdb);
    io_hdr.mx_sb_len = sizeof(senseBuf);
    io_hdr.dxfer_len = static_cast<unsigned int>(recvBuf.size());
    io_hdr.dxferp = recvBuf.data();
    io_hdr.cmdp = cdb;
    io_hdr.sbp = senseBuf;
    io_hdr.timeout = 30000;

    int ret = ioctl(fd_, SG_IO, &io_hdr);
    if (ret < 0) {
        LIBSED_ERROR("SG_IO SECURITY_PROTOCOL_IN failed: %s", strerror(errno));
        return ErrorCode::TransportRecvFailed;
    }

    if (io_hdr.status != 0) {
        LIBSED_ERROR("SCSI SECURITY_PROTOCOL_IN error: status=%d", io_hdr.status);
        return ErrorCode::TransportRecvFailed;
    }

    size_t copyLen = std::min(recvBuf.size(), buffer.size());
    std::memcpy(buffer.data(), recvBuf.data(), copyLen);

    // Discovery (protocol 0x01, comId 0x0001) and StackReset (protocol 0x02)
    // responses are NOT ComPackets — return full buffer for those.
    bool isDiscovery = (protocolId == 0x01 && comId == 0x0001);
    bool isStackReset = (protocolId == 0x02);
    if (!isDiscovery && !isStackReset && copyLen >= 20) {
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
