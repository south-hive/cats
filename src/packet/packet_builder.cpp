#include "libsed/packet/packet_builder.h"
#include "libsed/core/log.h"

namespace libsed {

void PacketBuilder::padTo4(Bytes& buf) {
    size_t pad = (4 - (buf.size() % 4)) % 4;
    for (size_t i = 0; i < pad; ++i) {
        buf.push_back(0);
    }
}

Bytes PacketBuilder::buildComPacket(const Bytes& tokenPayload) {
    Bytes result;
    result.reserve(ComPacketHeader::HEADER_SIZE +
                   PacketHeader::HEADER_SIZE +
                   SubPacketHeader::HEADER_SIZE +
                   tokenPayload.size() + 4);

    // SubPacket
    SubPacketHeader subHdr;
    subHdr.kind = SubPacketHeader::KIND_DATA;
    subHdr.length = static_cast<uint32_t>(tokenPayload.size());

    // Build SubPacket data (header + payload + padding)
    Bytes subPacketData;
    subHdr.serialize(subPacketData);
    subPacketData.insert(subPacketData.end(), tokenPayload.begin(), tokenPayload.end());
    padTo4(subPacketData);

    // Packet
    PacketHeader pktHdr;
    pktHdr.tperSessionNumber = tsn_;
    pktHdr.hostSessionNumber = hsn_;
    pktHdr.seqNumber = 0;  // sedutil always sends 0 (buffer zeroed per command)
    pktHdr.length = static_cast<uint32_t>(subPacketData.size());

    Bytes packetData;
    pktHdr.serialize(packetData);
    packetData.insert(packetData.end(), subPacketData.begin(), subPacketData.end());

    // ComPacket
    ComPacketHeader comHdr;
    comHdr.comId = comId_;
    comHdr.comIdExtension = comIdExtension_;
    comHdr.length = static_cast<uint32_t>(packetData.size());

    comHdr.serialize(result);
    result.insert(result.end(), packetData.begin(), packetData.end());

    // Pad to minimum 2048 bytes (sedutil IO_BUFFER_LENGTH).
    // Some TPers reject packets smaller than their default buffer size.
    static constexpr size_t MIN_COMPACKET_SIZE = 2048;
    if (result.size() < MIN_COMPACKET_SIZE) {
        result.resize(MIN_COMPACKET_SIZE, 0);
    } else {
        // Pad to 512-byte boundary
        while (result.size() % 512 != 0) {
            result.push_back(0);
        }
    }

    return result;
}

Bytes PacketBuilder::buildSessionManagerPacket(const Bytes& tokenPayload) {
    uint32_t savedTsn = tsn_;
    uint32_t savedHsn = hsn_;
    tsn_ = 0;
    hsn_ = 0;

    auto result = buildComPacket(tokenPayload);

    tsn_ = savedTsn;
    hsn_ = savedHsn;

    return result;
}

Result PacketBuilder::parseResponse(const uint8_t* data, size_t len,
                                      ParsedResponse& out) {
    if (len < ComPacketHeader::HEADER_SIZE) {
        return ErrorCode::BufferTooSmall;
    }

    // Parse ComPacket header
    auto r = ComPacketHeader::deserialize(data, len, out.comPacketHeader);
    if (r.failed()) return r;

    lastOutstandingData_ = out.comPacketHeader.outstandingData;

    size_t offset = ComPacketHeader::HEADER_SIZE;

    // If no payload, return empty (empty response / polling)
    if (out.comPacketHeader.length == 0) {
        out.tokenPayload.clear();
        return ErrorCode::Success;
    }

    // Parse Packet header
    if (offset + PacketHeader::HEADER_SIZE > len) {
        return ErrorCode::BufferTooSmall;
    }
    r = PacketHeader::deserialize(data + offset, len - offset, out.packetHeader);
    if (r.failed()) return r;
    offset += PacketHeader::HEADER_SIZE;

    // Parse SubPacket header
    if (offset + SubPacketHeader::HEADER_SIZE > len) {
        return ErrorCode::BufferTooSmall;
    }
    r = SubPacketHeader::deserialize(data + offset, len - offset, out.subPacketHeader);
    if (r.failed()) return r;
    offset += SubPacketHeader::HEADER_SIZE;

    // Extract token payload
    uint32_t payloadLen = out.subPacketHeader.length;
    if (offset + payloadLen > len) {
        LIBSED_WARN("SubPacket payload truncated: need %u, have %zu",
                     payloadLen, len - offset);
        payloadLen = static_cast<uint32_t>(len - offset);
    }

    out.tokenPayload.assign(data + offset, data + offset + payloadLen);

    return ErrorCode::Success;
}

} // namespace libsed
