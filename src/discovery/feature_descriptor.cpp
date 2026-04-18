#include "libsed/discovery/feature_descriptor.h"
#include "libsed/core/endian.h"

namespace libsed {

void TPerFeature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 8) return;

    uint8_t flags = data[4];
    syncSupported       = (flags & 0x01) != 0;
    asyncSupported      = (flags & 0x02) != 0;
    ackNakSupported     = (flags & 0x04) != 0;
    bufferMgmtSupported = (flags & 0x08) != 0;
    streamingSupported  = (flags & 0x10) != 0;
    comIdMgmtSupported  = (flags & 0x40) != 0;
}

void LockingFeature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 8) return;

    uint8_t flags = data[4];
    lockingSupported = (flags & 0x01) != 0;
    lockingEnabled   = (flags & 0x02) != 0;
    locked           = (flags & 0x04) != 0;
    mediaEncryption  = (flags & 0x08) != 0;
    mbrEnabled       = (flags & 0x10) != 0;
    mbrDone          = (flags & 0x20) != 0;
    mbrSupported     = (flags & 0x40) != 0;
}

void GeometryFeature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 20) return;

    align = (data[4] & 0x01) != 0;
    // Bytes 8-11: Logical Block Size
    logicalBlockSize = Endian::readBe32(data + 8);
    // Bytes 12-19: Alignment Granularity
    alignmentGranularity = Endian::readBe64(data + 12);
    // Bytes 20-27: Lowest Aligned LBA
    if (len >= 28) {
        lowestAlignedLBA = Endian::readBe64(data + 20);
    }
}

void OpalV1Feature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 16) return;

    baseComId    = Endian::readBe16(data + 4);
    numComIds    = Endian::readBe16(data + 6);
    rangeCrossing = (data[8] & 0x01) != 0;
}

void OpalV2Feature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 16) return;

    baseComId    = Endian::readBe16(data + 4);
    numComIds    = Endian::readBe16(data + 6);
    rangeCrossing = (data[8] & 0x01) != 0;

    if (len >= 12) {
        numLockingSPAdminsSupported = Endian::readBe16(data + 10);
    }
    if (len >= 14) {
        numLockingSPUsersSupported = Endian::readBe16(data + 12);
    }
    if (len >= 15) {
        initialPinIndicator = data[14];
    }
    if (len >= 16) {
        revertedPinIndicator = data[15];
    }
}

void EnterpriseFeature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 12) return;

    baseComId    = Endian::readBe16(data + 4);
    numComIds    = Endian::readBe16(data + 6);
    rangeCrossing = (data[8] & 0x01) != 0;
}

void PyriteV1Feature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 12) return;

    baseComId    = Endian::readBe16(data + 4);
    numComIds    = Endian::readBe16(data + 6);
    if (len >= 10) {
        initialPinIndicator  = data[8];
        revertedPinIndicator = data[9];
    }
}

void PyriteV2Feature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len < 12) return;

    baseComId    = Endian::readBe16(data + 4);
    numComIds    = Endian::readBe16(data + 6);
    if (len >= 10) {
        initialPinIndicator  = data[8];
        revertedPinIndicator = data[9];
    }
}

void UnknownFeature::parse(const uint8_t* data, size_t len) {
    parseHeader(data);
    if (len > 4) {
        rawData.assign(data + 4, data + len);
    }
}

} // namespace libsed
