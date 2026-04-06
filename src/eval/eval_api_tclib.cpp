#include "libsed/eval/eval_api.h"
#include "libsed/method/method_call.h"
#include "libsed/method/method_result.h"
#include "libsed/method/method_uids.h"
#include "libsed/method/param_encoder.h"
#include "libsed/method/param_decoder.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/codec/token_decoder.h"
#include "libsed/packet/packet_builder.h"
#include "libsed/core/uid.h"
#include "libsed/core/endian.h"
#include "libsed/core/log.h"
#include "eval_api_internal.h"

namespace libsed {
namespace eval {

// ════════════════════════════════════════════════════════
//  TC Library Util: getTcgOption
// ════════════════════════════════════════════════════════

Result EvalApi::getTcgOption(std::shared_ptr<ITransport> transport,
                              TcgOption& option) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    option.sscType = disc.detectSsc();
    option.baseComId = disc.baseComId();

    // Locking feature
    auto* locking = dynamic_cast<const LockingFeature*>(disc.findFeature(0x0002));
    if (locking) {
        option.lockingSupported = locking->lockingSupported;
        option.lockingEnabled   = locking->lockingEnabled;
        option.locked           = locking->locked;
        option.mediaEncryption  = locking->mediaEncryption;
        option.mbrSupported     = true;
        option.mbrEnabled       = locking->mbrEnabled;
        option.mbrDone          = locking->mbrDone;
    }

    // SSC-specific fields
    auto* opalV2 = dynamic_cast<const OpalV2Feature*>(disc.findFeature(0x0203));
    if (opalV2) {
        option.numComIds            = opalV2->numComIds;
        option.maxLockingAdmins     = opalV2->numLockingSPAdminsSupported;
        option.maxLockingUsers      = opalV2->numLockingSPUsersSupported;
        option.initialPinIndicator  = opalV2->initialPinIndicator;
        option.revertedPinIndicator = opalV2->revertedPinIndicator;
    }

    auto* opalV1 = dynamic_cast<const OpalV1Feature*>(disc.findFeature(0x0200));
    if (opalV1 && !opalV2) {
        option.numComIds = opalV1->numComIds;
    }

    auto* enterprise = dynamic_cast<const EnterpriseFeature*>(disc.findFeature(0x0100));
    if (enterprise) {
        option.numComIds = enterprise->numComIds;
    }

    auto* pyriteV2 = dynamic_cast<const PyriteV2Feature*>(disc.findFeature(0x0303));
    if (pyriteV2) {
        option.numComIds            = pyriteV2->numComIds;
        option.initialPinIndicator  = pyriteV2->initialPinIndicator;
        option.revertedPinIndicator = pyriteV2->revertedPinIndicator;
    }

    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getSecurityStatus
// ════════════════════════════════════════════════════════

Result EvalApi::getSecurityStatus(std::shared_ptr<ITransport> transport,
                                   SecurityStatus& status) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    status.tperPresent       = disc.hasTPerFeature();
    status.lockingPresent    = disc.hasLockingFeature();
    status.geometryPresent   = disc.hasGeometryFeature();
    status.opalV1Present     = disc.hasOpalV1Feature();
    status.opalV2Present     = disc.hasOpalV2Feature();
    status.enterprisePresent = disc.hasEnterpriseFeature();
    status.pyriteV1Present   = disc.hasPyriteV1Feature();
    status.pyriteV2Present   = disc.hasPyriteV2Feature();
    status.primarySsc        = disc.detectSsc();

    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getSecurityFeature / getAllSecurityFeatures
// ════════════════════════════════════════════════════════

static SecurityFeatureInfo featureToInfo(const FeatureDescriptor& fd) {
    SecurityFeatureInfo info;
    info.featureCode = fd.featureCode();
    info.featureName = fd.name();
    info.version     = fd.version();
    info.dataLength  = fd.dataLength();

    // Extract SSC-specific fields
    if (auto* opal = dynamic_cast<const OpalV2Feature*>(&fd)) {
        info.baseComId    = opal->baseComId;
        info.numComIds    = opal->numComIds;
        info.rangeCrossing = opal->rangeCrossing;
    } else if (auto* opal1 = dynamic_cast<const OpalV1Feature*>(&fd)) {
        info.baseComId    = opal1->baseComId;
        info.numComIds    = opal1->numComIds;
        info.rangeCrossing = opal1->rangeCrossing;
    } else if (auto* ent = dynamic_cast<const EnterpriseFeature*>(&fd)) {
        info.baseComId    = ent->baseComId;
        info.numComIds    = ent->numComIds;
        info.rangeCrossing = ent->rangeCrossing;
    } else if (auto* pyr2 = dynamic_cast<const PyriteV2Feature*>(&fd)) {
        info.baseComId    = pyr2->baseComId;
        info.numComIds    = pyr2->numComIds;
    } else if (auto* pyr1 = dynamic_cast<const PyriteV1Feature*>(&fd)) {
        info.baseComId    = pyr1->baseComId;
        info.numComIds    = pyr1->numComIds;
    }

    if (auto* lock = dynamic_cast<const LockingFeature*>(&fd)) {
        info.lockingSupported = lock->lockingSupported;
        info.lockingEnabled   = lock->lockingEnabled;
        info.locked           = lock->locked;
        info.mbrEnabled       = lock->mbrEnabled;
        info.mbrDone          = lock->mbrDone;
    }

    if (auto* unk = dynamic_cast<const UnknownFeature*>(&fd)) {
        info.rawFeatureData = unk->rawData;
    }

    return info;
}

Result EvalApi::getSecurityFeature(std::shared_ptr<ITransport> transport,
                                    uint16_t featureCode,
                                    SecurityFeatureInfo& info) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    auto* fd = disc.findFeature(featureCode);
    if (!fd) return ErrorCode::FeatureNotFound;

    info = featureToInfo(*fd);
    return ErrorCode::Success;
}

Result EvalApi::getAllSecurityFeatures(std::shared_ptr<ITransport> transport,
                                       std::vector<SecurityFeatureInfo>& features) {
    Discovery disc;
    auto r = disc.discover(transport);
    if (r.failed()) return r;

    features.clear();
    for (auto& fd : disc.features()) {
        features.push_back(featureToInfo(*fd));
    }
    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getLockingInfo
// ════════════════════════════════════════════════════════

Result EvalApi::getLockingInfo(Session& session, uint32_t rangeId,
                                LockingInfo& info, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    Bytes tokens = MethodCall::buildGet(Uid(rangeUid));
    auto r = sendMethod(session, tokens, result);
    if (r.failed()) return r;

    if (result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);

        info.rangeId = rangeId;
        auto getU = [&](uint32_t col) -> uint64_t {
            auto it = values.find(col);
            return (it != values.end()) ? it->second.getUint() : 0;
        };
        auto getB = [&](uint32_t col) -> bool {
            return getU(col) != 0;
        };

        info.rangeStart       = getU(uid::col::RANGE_START);
        info.rangeLength      = getU(uid::col::RANGE_LENGTH);
        info.readLockEnabled  = getB(uid::col::READ_LOCK_EN);
        info.writeLockEnabled = getB(uid::col::WRITE_LOCK_EN);
        info.readLocked       = getB(uid::col::READ_LOCKED);
        info.writeLocked      = getB(uid::col::WRITE_LOCKED);
        info.activeKey        = getU(uid::col::ACTIVE_KEY);
    }
    return r;
}

Result EvalApi::getAllLockingInfo(Session& session,
                                   std::vector<LockingInfo>& ranges,
                                   uint32_t maxRanges,
                                   RawResult& result) {
    ranges.clear();

    // Range 0 = Global Range
    for (uint32_t i = 0; i <= maxRanges; i++) {
        LockingInfo info;
        auto r = getLockingInfo(session, i, info, result);
        if (r.failed()) {
            // If we fail reading a range, we've likely hit the end
            if (i > 0) break;
            return r;
        }
        ranges.push_back(info);
    }
    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: getByteTableInfo
// ════════════════════════════════════════════════════════

Result EvalApi::getByteTableInfo(Session& session, ByteTableInfo& info,
                                  RawResult& result) {
    info.tableUid = uid::TABLE_DATASTORE;

    // Read DataStore table descriptor to get size info
    TableResult tr;
    auto r = tableGetAll(session, uid::TABLE_DATASTORE, tr);
    result = tr.raw;
    if (r.failed()) return r;

    for (auto& [col, tok] : tr.columns) {
        if (!tok.isByteSequence && !tok.isSigned) {
            // Heuristic: column values from table descriptor
            switch (col) {
                case 3: info.maxSize  = static_cast<uint32_t>(tok.getUint()); break;
                case 4: info.usedSize = static_cast<uint32_t>(tok.getUint()); break;
            }
        }
    }
    return ErrorCode::Success;
}

// ════════════════════════════════════════════════════════
//  TC Library Util: TcgWrite / TcgRead / TcgCompare
// ════════════════════════════════════════════════════════

Result EvalApi::tcgWrite(Session& session, uint64_t tableUid,
                          uint32_t offset, const Bytes& data,
                          RawResult& result) {
    // Build Set method with Where=offset, Values=data
    TokenEncoder enc;
    enc.startList();
    enc.namedUint(0, offset);    // Where
    enc.namedBytes(1, data);     // Values
    enc.endList();

    Bytes tokens = buildMethodCall(tableUid, method::SET, enc.data());
    return sendMethod(session, tokens, result);
}

Result EvalApi::tcgRead(Session& session, uint64_t tableUid,
                         uint32_t offset, uint32_t length,
                         DataOpResult& result) {
    CellBlock cb;
    cb.startRow = offset;
    cb.endRow = offset + length - 1;

    Bytes tokens = MethodCall::buildGet(Uid(tableUid), cb);
    auto r = sendMethod(session, tokens, result.raw);
    if (r.ok() && result.raw.methodResult.isSuccess()) {
        auto stream = result.raw.methodResult.resultStream();
        if (stream.hasMore() && stream.peek()->isByteSequence) {
            result.data = stream.next()->getBytes();
        }
    }
    return r;
}

Result EvalApi::tcgCompare(Session& session, uint64_t tableUid,
                            uint32_t offset, const Bytes& expected,
                            DataOpResult& result) {
    // Write
    RawResult writeRaw;
    auto r = tcgWrite(session, tableUid, offset, expected, writeRaw);
    if (r.failed()) { result.raw = writeRaw; return r; }

    // Read back
    r = tcgRead(session, tableUid, offset,
                static_cast<uint32_t>(expected.size()), result);
    if (r.failed()) return r;

    // Compare
    result.compareMatch = (result.data == expected);
    return ErrorCode::Success;
}

Result EvalApi::tcgWriteDataStore(Session& session, uint32_t offset,
                                   const Bytes& data, RawResult& result) {
    return tcgWrite(session, uid::TABLE_DATASTORE, offset, data, result);
}

Result EvalApi::tcgReadDataStore(Session& session, uint32_t offset,
                                  uint32_t length, DataOpResult& result) {
    return tcgRead(session, uid::TABLE_DATASTORE, offset, length, result);
}

// ════════════════════════════════════════════════════════
//  DataStore with Table Number
// ════════════════════════════════════════════════════════

Result EvalApi::tcgWriteDataStoreN(Session& session, uint32_t tableNumber,
                                    uint32_t offset, const Bytes& data,
                                    RawResult& result) {
    uint64_t dsUid = uid::TABLE_DATASTORE + tableNumber + 1;
    return tcgWrite(session, dsUid, offset, data, result);
}

Result EvalApi::tcgReadDataStoreN(Session& session, uint32_t tableNumber,
                                   uint32_t offset, uint32_t length,
                                   DataOpResult& result) {
    uint64_t dsUid = uid::TABLE_DATASTORE + tableNumber + 1;
    return tcgRead(session, dsUid, offset, length, result);
}

// ══════════════════════════════════════════════════════════
//  Simplified overloads (RawResult omitted)
// ══════════════════════════════════════════════════════════

Result EvalApi::getLockingInfo(Session& session, uint32_t rangeId, LockingInfo& info) {
    RawResult raw;
    return getLockingInfo(session, rangeId, info, raw);
}

Result EvalApi::getAllLockingInfo(Session& session, std::vector<LockingInfo>& ranges, uint32_t maxRanges) {
    RawResult raw;
    return getAllLockingInfo(session, ranges, maxRanges, raw);
}

Result EvalApi::getByteTableInfo(Session& session, ByteTableInfo& info) {
    RawResult raw;
    return getByteTableInfo(session, info, raw);
}

Result EvalApi::tcgWriteDataStore(Session& session, uint32_t offset, const Bytes& data) {
    RawResult raw;
    return tcgWriteDataStore(session, offset, data, raw);
}

Result EvalApi::tcgWriteDataStoreN(Session& session, uint32_t tableNumber, uint32_t offset, const Bytes& data) {
    RawResult raw;
    return tcgWriteDataStoreN(session, tableNumber, offset, data, raw);
}

} // namespace eval
} // namespace libsed
