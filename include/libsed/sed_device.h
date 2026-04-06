#pragma once

#include "core/types.h"
#include "core/error.h"
#include "transport/i_transport.h"
#include "discovery/discovery.h"
#include "ssc/opal/opal_device.h"
#include "ssc/enterprise/enterprise_device.h"
#include "ssc/pyrite/pyrite_device.h"
#include <memory>
#include <string>

namespace libsed {

/// @deprecated Use SedDrive instead. SedDevice will be removed in a future version.
///
/// SedDrive provides the same functionality with a simpler API:
///   SedDrive drive("/dev/nvme0");
///   drive.query();
///   drive.takeOwnership("password");
///
/// See docs/tc_dev_guide.md for migration guide.
class [[deprecated("Use SedDrive instead — see docs/tc_dev_guide.md")]] SedDevice {
public:
    /// Open a device by path, auto-detect transport and SSC
    static std::unique_ptr<SedDevice> open(const std::string& devicePath);

    /// Open with explicit transport
    static std::unique_ptr<SedDevice> open(std::shared_ptr<ITransport> transport);

    ~SedDevice();

    // ── Device information ───────────────────────────

    SscType sscType() const { return discoveryInfo_.primarySsc; }
    const DiscoveryInfo& discovery() const { return discoveryInfo_; }
    TransportType transportType() const { return transport_->type(); }
    std::string devicePath() const { return transport_->devicePath(); }

    // ── Re-discover ──────────────────────────────────

    Result rediscover();

    // ── Common operations (SSC-agnostic) ─────────────

    /// Take ownership (set SID password)
    Result takeOwnership(const std::string& newSidPassword);

    /// Revert to factory state
    Result revert(const std::string& password);

    /// Lock a range
    Result lockRange(uint32_t rangeId, const std::string& password,
                      uint32_t authId = 1);

    /// Unlock a range
    Result unlockRange(uint32_t rangeId, const std::string& password,
                        uint32_t authId = 1);

    /// Configure a locking range
    Result configureRange(uint32_t rangeId,
                           uint64_t rangeStart, uint64_t rangeLength,
                           const std::string& adminPassword);

    /// Get locking range info
    Result getRangeInfo(uint32_t rangeId, LockingRangeInfo& info,
                         const std::string& password, uint32_t authId = 1);

    // ── SSC-specific access ──────────────────────────

    OpalDevice* asOpal() { return opalDevice_.get(); }
    EnterpriseDevice* asEnterprise() { return enterpriseDevice_.get(); }
    PyriteDevice* asPyrite() { return pyriteDevice_.get(); }

    const OpalDevice* asOpal() const { return opalDevice_.get(); }
    const EnterpriseDevice* asEnterprise() const { return enterpriseDevice_.get(); }
    const PyriteDevice* asPyrite() const { return pyriteDevice_.get(); }

private:
    SedDevice() = default;
    Result initialize();

    std::shared_ptr<ITransport> transport_;
    Discovery discoveryParser_;
    DiscoveryInfo discoveryInfo_;

    std::unique_ptr<OpalDevice> opalDevice_;
    std::unique_ptr<EnterpriseDevice> enterpriseDevice_;
    std::unique_ptr<PyriteDevice> pyriteDevice_;
};

} // namespace libsed
