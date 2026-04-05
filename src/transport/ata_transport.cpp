#include "libsed/transport/ata_transport.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"

#if defined(__linux__) && !defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <cstring>
#endif

namespace libsed {

AtaTransport::AtaTransport(const std::string& devicePath)
    : devicePath_(devicePath) {
    auto r = open();
    if (r.failed()) {
        LIBSED_ERROR("Failed to open ATA device: %s", devicePath.c_str());
    }
}

AtaTransport::~AtaTransport() {
    close();
}

Result AtaTransport::open() {
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

void AtaTransport::close() {
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
#endif
}

Result AtaTransport::ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) {
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ < 0) return ErrorCode::TransportNotAvailable;

    // Build ATA TRUSTED SEND command via SG_IO (ATA pass-through 12)
    // CDB: ATA Pass-Through(12) for TRUSTED SEND
    uint8_t cdb[12] = {};
    cdb[0] = 0xA1;          // ATA Pass-Through(12) SCSI opcode
    cdb[1] = (5 << 1);      // Protocol: PIO Data-Out (5)
    cdb[2] = 0x06;          // T_LENGTH=2 (sector count), BYT_BLOK=1, T_DIR=0(out)
    cdb[3] = protocolId;    // Features (Security Protocol)
    cdb[4] = static_cast<uint8_t>((payload.size() + 511) / 512); // Sector Count
    cdb[5] = static_cast<uint8_t>((comId >> 8) & 0xFF);  // LBA Low
    cdb[6] = static_cast<uint8_t>(comId & 0xFF);          // LBA Mid
    cdb[7] = 0;              // LBA High
    cdb[8] = 0;              // Device
    cdb[9] = 0x5E;           // ATA Command: TRUSTED SEND

    // Pad payload to sector boundary
    size_t transferLen = ((payload.size() + 511) / 512) * 512;
    std::vector<uint8_t> buffer(transferLen, 0);
    std::memcpy(buffer.data(), payload.data(), payload.size());

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
    io_hdr.timeout = 30000; // 30 seconds

    int ret = ioctl(fd_, SG_IO, &io_hdr);
    if (ret < 0) {
        LIBSED_ERROR("SG_IO TRUSTED_SEND failed: %s", strerror(errno));
        return ErrorCode::TransportSendFailed;
    }

    if (io_hdr.status != 0 || io_hdr.host_status != 0 || io_hdr.driver_status != 0) {
        LIBSED_ERROR("ATA TRUSTED_SEND error: status=%d host=%d driver=%d",
                     io_hdr.status, io_hdr.host_status, io_hdr.driver_status);
        return ErrorCode::TransportSendFailed;
    }

    return ErrorCode::Success;
#else
    (void)protocolId; (void)comId; (void)payload;
    return ErrorCode::TransportNotAvailable;
#endif
}

Result AtaTransport::ifRecv(uint8_t protocolId, uint16_t comId,
                              MutableByteSpan buffer, size_t& bytesReceived) {
#if defined(__linux__) && !defined(__ANDROID__)
    if (fd_ < 0) return ErrorCode::TransportNotAvailable;

    // Build ATA TRUSTED RECEIVE command via SG_IO
    uint8_t cdb[12] = {};
    cdb[0] = 0xA1;          // ATA Pass-Through(12)
    cdb[1] = (4 << 1);      // Protocol: PIO Data-In (4)
    cdb[2] = 0x0E;          // T_LENGTH=2, BYT_BLOK=1, T_DIR=1(in)
    cdb[3] = protocolId;    // Features (Security Protocol)
    cdb[4] = static_cast<uint8_t>((buffer.size() + 511) / 512); // Sector Count
    cdb[5] = static_cast<uint8_t>((comId >> 8) & 0xFF);
    cdb[6] = static_cast<uint8_t>(comId & 0xFF);
    cdb[7] = 0;
    cdb[8] = 0;
    cdb[9] = 0x5C;           // ATA Command: TRUSTED RECEIVE

    size_t transferLen = ((buffer.size() + 511) / 512) * 512;
    std::vector<uint8_t> recvBuf(transferLen, 0);

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
        LIBSED_ERROR("SG_IO TRUSTED_RECEIVE failed: %s", strerror(errno));
        return ErrorCode::TransportRecvFailed;
    }

    if (io_hdr.status != 0 || io_hdr.host_status != 0 || io_hdr.driver_status != 0) {
        LIBSED_ERROR("ATA TRUSTED_RECEIVE error: status=%d host=%d driver=%d",
                     io_hdr.status, io_hdr.host_status, io_hdr.driver_status);
        return ErrorCode::TransportRecvFailed;
    }

    size_t copyLen = std::min(recvBuf.size(), buffer.size());
    std::memcpy(buffer.data(), recvBuf.data(), copyLen);

    // Extract actual payload size from ComPacket header (Rosetta Stone §1)
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
