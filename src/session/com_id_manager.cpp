#include "libsed/session/com_id_manager.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"
#include <thread>
#include <chrono>

namespace libsed {

ComIdManager::ComIdManager(std::shared_ptr<ITransport> transport)
    : transport_(std::move(transport)) {}

Result ComIdManager::verifyComId(uint16_t comId) {
    // Send a VERIFY_COMID request via IF-SEND protocol 0x02
    // The response indicates if the ComID is valid and in use
    Bytes request(512, 0);
    Endian::writeBe16(request.data(), comId);
    Endian::writeBe16(request.data() + 2, 0); // extension
    Endian::writeBe32(request.data() + 4, 0); // request code = verify

    auto r = transport_->ifSend(PROTOCOL_ID_COMID_MGMT, comId,
                                 ByteSpan(request.data(), request.size()));
    if (r.failed()) return r;

    Bytes response;
    r = transport_->ifRecv(PROTOCOL_ID_COMID_MGMT, comId, response, 512);
    if (r.failed()) return r;

    if (response.size() < 12) return ErrorCode::MalformedResponse;

    // Check response state
    uint32_t state = Endian::readBe32(response.data() + 4);
    if (state == 0) {
        LIBSED_DEBUG("ComID 0x%04X is valid (idle)", comId);
    } else if (state == 1) {
        LIBSED_DEBUG("ComID 0x%04X is valid (associated)", comId);
    } else {
        LIBSED_WARN("ComID 0x%04X invalid state: %u", comId, state);
        return ErrorCode::ProtocolError;
    }

    return ErrorCode::Success;
}

Result ComIdManager::requestComId(uint16_t& comId) {
    // For Opal: dynamically request a ComID
    Bytes request(512, 0);
    Endian::writeBe32(request.data() + 4, 1); // request code = request_comid

    auto r = transport_->ifSend(PROTOCOL_ID_COMID_MGMT, 0,
                                 ByteSpan(request.data(), request.size()));
    if (r.failed()) return r;

    Bytes response;
    r = transport_->ifRecv(PROTOCOL_ID_COMID_MGMT, 0, response, 512);
    if (r.failed()) return r;

    if (response.size() < 8) return ErrorCode::MalformedResponse;

    comId = Endian::readBe16(response.data());
    LIBSED_INFO("Requested dynamic ComID: 0x%04X", comId);

    return ErrorCode::Success;
}

Result ComIdManager::releaseComId(uint16_t comId) {
    return stackReset(comId);
}

Result ComIdManager::stackReset(uint16_t comId) {
    Bytes request(512, 0);
    Endian::writeBe16(request.data(), comId);
    Endian::writeBe16(request.data() + 2, 0);
    Endian::writeBe32(request.data() + 4, 2); // request code = stack_reset

    auto r = transport_->ifSend(PROTOCOL_ID_COMID_MGMT, comId,
                                 ByteSpan(request.data(), request.size()));
    if (r.failed()) return r;

    // StackReset 완료 대기 — IF-RECV로 ComID 상태를 polling
    // TCG Core Spec: reset 후 ComID 상태가 idle(0)이 될 때까지 대기
    for (int attempt = 0; attempt < 20; attempt++) {
        Bytes response;
        r = transport_->ifRecv(PROTOCOL_ID_COMID_MGMT, comId, response, 512);
        if (r.failed()) {
            LIBSED_WARN("StackReset poll failed for ComID 0x%04X: %s",
                         comId, r.message().c_str());
            return r;
        }

        if (response.size() >= 8) {
            uint32_t state = Endian::readBe32(response.data() + 4);
            if (state == 0) {
                // idle — reset 완료
                LIBSED_INFO("Stack reset complete for ComID 0x%04X", comId);
                return ErrorCode::Success;
            }
            LIBSED_DEBUG("StackReset poll: ComID 0x%04X state=%u, retrying",
                          comId, state);
        }

        // 짧은 대기 후 재시도
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    LIBSED_WARN("StackReset timeout for ComID 0x%04X", comId);
    return ErrorCode::Success;  // 타임아웃이어도 진행 허용
}

} // namespace libsed
