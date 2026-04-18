#include "libsed/discovery/discovery.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"
#include <algorithm>

namespace libsed {

Result Discovery::discover(std::shared_ptr<ITransport> transport) {
    if (!transport || !transport->isOpen()) {
        return ErrorCode::TransportNotAvailable;
    }

    // Send Level 0 Discovery request via IF-RECV
    Bytes response;
    auto r = transport->ifRecv(PROTOCOL_ID, COMID, response, 2048);
    if (r.failed()) {
        LIBSED_ERROR("Level 0 Discovery IF-RECV failed");
        return ErrorCode::DiscoveryFailed;
    }

    return parse(response);
}

Result Discovery::parse(const uint8_t* data, size_t len) {
    features_.clear();

    // Discovery header: 48 bytes minimum
    // Bytes 0-3: Length of response (excluding this field)
    // Bytes 4-7: Major version, Minor version
    // Bytes 8-47: Reserved
    if (len < 48) {
        LIBSED_ERROR("Discovery response too short: %zu bytes", len);
        return ErrorCode::DiscoveryInvalidData;
    }

    headerLength_ = Endian::readBe32(data);
    majorVersion_ = Endian::readBe16(data + 4);
    minorVersion_ = Endian::readBe16(data + 6);

    LIBSED_DEBUG("Discovery header: length=%u, version=%u.%u",
                 headerLength_, majorVersion_, minorVersion_);

    // Parse feature descriptors starting at offset 48
    size_t offset = 48;
    size_t totalLen = std::min(static_cast<size_t>(headerLength_) + 4, len);

    while (offset + 4 <= totalLen) {
        auto r = parseFeature(data, totalLen, offset);
        if (r.failed()) {
            LIBSED_WARN("Failed to parse feature at offset %zu", offset);
            break;
        }
    }

    LIBSED_INFO("Discovery parsed %zu features", features_.size());
    return ErrorCode::Success;
}

Result Discovery::parseFeature(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 4 > len) return ErrorCode::DiscoveryInvalidData;

    uint16_t featureCode = Endian::readBe16(data + offset);
    uint8_t  version     = (data[offset + 2] >> 4) & 0x0F;
    uint16_t dataLength  = data[offset + 3];
    (void)version;

    size_t totalFeatureLen = 4 + dataLength;
    if (offset + totalFeatureLen > len) {
        LIBSED_WARN("Feature 0x%04X truncated at offset %zu", featureCode, offset);
        return ErrorCode::DiscoveryInvalidData;
    }

    std::unique_ptr<FeatureDescriptor> feature;

    switch (featureCode) {
        case 0x0001: feature = std::make_unique<TPerFeature>(); break;
        case 0x0002: feature = std::make_unique<LockingFeature>(); break;
        case 0x0003: feature = std::make_unique<GeometryFeature>(); break;
        case 0x0200: feature = std::make_unique<OpalV1Feature>(); break;
        case 0x0203: feature = std::make_unique<OpalV2Feature>(); break;
        case 0x0100: feature = std::make_unique<EnterpriseFeature>(); break;
        case 0x0302: feature = std::make_unique<PyriteV1Feature>(); break;
        case 0x0303: feature = std::make_unique<PyriteV2Feature>(); break;
        default:     feature = std::make_unique<UnknownFeature>(); break;
    }

    feature->parse(data + offset, totalFeatureLen);
    LIBSED_DEBUG("Feature: %s (0x%04X)", feature->name().c_str(), featureCode);

    features_.push_back(std::move(feature));
    offset += totalFeatureLen;

    return ErrorCode::Success;
}

const FeatureDescriptor* Discovery::findFeature(uint16_t featureCode) const {
    for (const auto& f : features_) {
        if (f->featureCode() == featureCode) return f.get();
    }
    return nullptr;
}

SscType Discovery::detectSsc() const {
    // Priority: Opal 2.0 > Opal 1.0 > Enterprise > Pyrite 2.0 > Pyrite 1.0
    if (hasOpalV2Feature())      return SscType::Opal20;
    if (hasOpalV1Feature())      return SscType::Opal10;
    if (hasEnterpriseFeature())  return SscType::Enterprise;
    if (hasPyriteV2Feature())    return SscType::Pyrite20;
    if (hasPyriteV1Feature())    return SscType::Pyrite10;
    return SscType::Unknown;
}

uint16_t Discovery::baseComId() const {
    if (auto* f = dynamic_cast<const OpalV2Feature*>(findFeature(0x0203)))
        return f->baseComId;
    if (auto* f = dynamic_cast<const OpalV1Feature*>(findFeature(0x0200)))
        return f->baseComId;
    if (auto* f = dynamic_cast<const EnterpriseFeature*>(findFeature(0x0100)))
        return f->baseComId;
    if (auto* f = dynamic_cast<const PyriteV2Feature*>(findFeature(0x0303)))
        return f->baseComId;
    if (auto* f = dynamic_cast<const PyriteV1Feature*>(findFeature(0x0302)))
        return f->baseComId;
    return 0;
}

DiscoveryInfo Discovery::buildInfo() const {
    DiscoveryInfo info;
    info.majorVersion = majorVersion_;
    info.minorVersion = minorVersion_;
    info.primarySsc = detectSsc();
    info.baseComId = baseComId();

    if (dynamic_cast<const TPerFeature*>(findFeature(0x0001))) {
        info.tperPresent = true;
    }

    if (auto* locking = dynamic_cast<const LockingFeature*>(findFeature(0x0002))) {
        info.lockingPresent = true;
        info.lockingEnabled = locking->lockingEnabled;
        info.locked = locking->locked;
        info.mbrSupported = locking->mbrSupported;
        info.mbrEnabled = locking->mbrEnabled;
        info.mbrDone = locking->mbrDone;
    }

    if (auto* opal = dynamic_cast<const OpalV2Feature*>(findFeature(0x0203))) {
        info.numComIds = opal->numComIds;
    }

    return info;
}

} // namespace libsed
