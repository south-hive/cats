#include "libsed/eval/eval_api.h"
#include "libsed/method/method_call.h"
#include "libsed/method/method_result.h"
#include "libsed/method/method_uids.h"
#include "libsed/method/param_encoder.h"
#include "libsed/method/param_decoder.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/codec/token_decoder.h"
#include "libsed/packet/packet_builder.h"
#include "libsed/transport/nvme_transport.h"
#include "libsed/core/uid.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"

namespace libsed {
namespace eval {

// ════════════════════════════════════════════════════════
//  NVMe Device Access
// ════════════════════════════════════════════════════════

INvmeDevice* EvalApi::getNvmeDevice(std::shared_ptr<ITransport> transport) {
    if (!transport || transport->type() != TransportType::NVMe) return nullptr;
    auto* nvmeTr = dynamic_cast<NvmeTransport*>(transport.get());
    return nvmeTr ? nvmeTr->nvmeDevice() : nullptr;
}

Result EvalApi::nvmeIdentify(std::shared_ptr<ITransport> transport,
                              uint8_t cns, uint32_t nsid, Bytes& data) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->identify(cns, nsid, data);
}

Result EvalApi::getNvmeSerial(std::shared_ptr<ITransport> transport,
                                Bytes& serial) {
    // NVMe Identify Controller (CNS=0x01) layout:
    //   bytes [0..3]   VID (Vendor ID)
    //   bytes [4..23]  SN (Serial Number, 20 ASCII bytes, space-padded)
    //   bytes [24..63] MN (Model Number, 40 bytes)
    //   ...
    //
    // sedutil-cli uses these 20 bytes verbatim as the salt for
    // PBKDF2-HMAC-SHA1, including any trailing 0x20 (space) padding.
    Bytes id;
    auto r = nvmeIdentify(transport, /*cns*/0x01, /*nsid*/0, id);
    if (r.failed()) return r;
    if (id.size() < 24) return ErrorCode::MalformedResponse;
    serial.assign(id.begin() + 4, id.begin() + 24);
    return ErrorCode::Success;
}

Result EvalApi::nvmeGetLogPage(std::shared_ptr<ITransport> transport,
                                uint8_t logId, uint32_t nsid,
                                Bytes& data, uint32_t dataLen) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->getLogPage(logId, nsid, data, dataLen);
}

Result EvalApi::nvmeGetFeature(std::shared_ptr<ITransport> transport,
                                uint8_t featureId, uint32_t nsid,
                                uint32_t& cdw0, Bytes& data) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->getFeature(featureId, nsid, cdw0, data);
}

Result EvalApi::nvmeSetFeature(std::shared_ptr<ITransport> transport,
                                uint8_t featureId, uint32_t nsid,
                                uint32_t cdw11, const Bytes& data) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->setFeature(featureId, nsid, cdw11, data);
}

Result EvalApi::nvmeFormat(std::shared_ptr<ITransport> transport,
                            uint32_t nsid, uint8_t lbaf,
                            uint8_t ses, uint8_t pi) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->formatNvm(nsid, lbaf, ses, pi);
}

Result EvalApi::nvmeAdminCmd(std::shared_ptr<ITransport> transport,
                              NvmeAdminCmd& cmd, NvmeCompletion& cpl) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->adminCommand(cmd, cpl);
}

Result EvalApi::nvmeIoCmd(std::shared_ptr<ITransport> transport,
                           NvmeIoCmd& cmd, NvmeCompletion& cpl) {
    auto* dev = getNvmeDevice(transport);
    if (!dev) return ErrorCode::TransportNotAvailable;
    return dev->ioCommand(cmd, cpl);
}

} // namespace eval
} // namespace libsed
