#pragma once

#include "../core/types.h"
#include "../core/error.h"
#include "../transport/i_transport.h"
#include <memory>

namespace libsed {

/// Manages ComID allocation and verification
class ComIdManager {
public:
    explicit ComIdManager(std::shared_ptr<ITransport> transport);

    /// Verify a ComID is valid and usable
    Result verifyComId(uint16_t comId);

    /// Request a dynamic ComID (Opal)
    Result requestComId(uint16_t& comId);

    /// Release a dynamically allocated ComID
    Result releaseComId(uint16_t comId);

    /// Perform Stack Reset on a ComID
    Result stackReset(uint16_t comId);

    /// Get the protocol ID for IF-SEND/IF-RECV
    static constexpr uint8_t PROTOCOL_ID_LEVEL0 = 0x01;  ///< Level 0 Discovery
    static constexpr uint8_t PROTOCOL_ID_LEVEL1 = 0x01;  ///< Level 1 TCG data (IF-SEND/IF-RECV)
    static constexpr uint8_t PROTOCOL_ID_COMID_MGMT = 0x02;  ///< ComID Management

private:
    std::shared_ptr<ITransport> transport_;
};

} // namespace libsed
