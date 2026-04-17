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
//  Enterprise SSC
// ════════════════════════════════════════════════════════
//
// These functions delegate to the general setRange/getLockingInfo/setCPin/
// erase helpers, which route to the correct method UIDs via session.sscType():
//   Opal/Pyrite:  GET=0x16 / SET=0x17 / AUTHENTICATE=0x1C
//   Enterprise:   EGET=0x06 / ESET=0x07 / EAUTHENTICATE=0x0C
//
// Callers MUST mark the session as Enterprise before invoking these methods —
// use EnterpriseSession (which sets it automatically) or call
// session.setSscType(SscType::Enterprise) after startSession. See
// rosetta_stone.md §13 for the full method UID table.

Result EvalApi::configureBand(Session& session, uint32_t bandId,
                               uint64_t bandStart, uint64_t bandLength,
                               bool readLockEnabled, bool writeLockEnabled,
                               RawResult& result) {
    return setRange(session, bandId, bandStart, bandLength,
                    readLockEnabled, writeLockEnabled, result);
}

Result EvalApi::lockBand(Session& session, uint32_t bandId, RawResult& result) {
    return setRangeLock(session, bandId, true, true, result);
}

Result EvalApi::unlockBand(Session& session, uint32_t bandId, RawResult& result) {
    return setRangeLock(session, bandId, false, false, result);
}

Result EvalApi::getBandInfo(Session& session, uint32_t bandId,
                             LockingInfo& info, RawResult& result) {
    return getLockingInfo(session, bandId, info, result);
}

Result EvalApi::setBandMasterPassword(Session& session, uint32_t bandId,
                                       const Bytes& newPin, RawResult& result) {
    uint64_t cpinUid = uid::makeCpinBandMasterUid(bandId).toUint64();
    return setCPin(session, cpinUid, newPin, result);
}

Result EvalApi::setEraseMasterPassword(Session& session, const Bytes& newPin,
                                        RawResult& result) {
    return setCPin(session, uid::CPIN_ERASEMASTER, newPin, result);
}

Result EvalApi::eraseBand(Session& session, uint32_t bandId, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(bandId).toUint64();
    return erase(session, rangeUid, result);
}

// ════════════════════════════════════════════════════════
//  Enterprise Band Extended
// ════════════════════════════════════════════════════════

Result EvalApi::setBandLockOnReset(Session& session, uint32_t bandId,
                                    bool lockOnReset, RawResult& result) {
    uint64_t bandUid = uid::makeLockingRangeUid(bandId).toUint64();
    return tableSetBool(session, bandUid, uid::col::LOCK_ON_RESET, lockOnReset, result);
}

Result EvalApi::eraseAllBands(Session& session, uint32_t maxBands, RawResult& result) {
    Result r;
    for (uint32_t i = 0; i < maxBands; i++) {
        r = eraseBand(session, i, result);
        if (r.failed()) return r;
    }
    return r;
}

// ══════════════════════════════════════════════════════════
//  Simplified overloads (RawResult omitted)
// ══════════════════════════════════════════════════════════

Result EvalApi::configureBand(Session& session, uint32_t bandId, uint64_t bandStart,
                              uint64_t bandLength, bool readLockEnabled, bool writeLockEnabled) {
    RawResult raw;
    return configureBand(session, bandId, bandStart, bandLength, readLockEnabled, writeLockEnabled, raw);
}

Result EvalApi::lockBand(Session& session, uint32_t bandId) {
    RawResult raw;
    return lockBand(session, bandId, raw);
}

Result EvalApi::unlockBand(Session& session, uint32_t bandId) {
    RawResult raw;
    return unlockBand(session, bandId, raw);
}

Result EvalApi::getBandInfo(Session& session, uint32_t bandId, LockingInfo& info) {
    RawResult raw;
    return getBandInfo(session, bandId, info, raw);
}

Result EvalApi::setBandMasterPassword(Session& session, uint32_t bandId, const Bytes& newPin) {
    RawResult raw;
    return setBandMasterPassword(session, bandId, newPin, raw);
}

Result EvalApi::setEraseMasterPassword(Session& session, const Bytes& newPin) {
    RawResult raw;
    return setEraseMasterPassword(session, newPin, raw);
}

Result EvalApi::eraseBand(Session& session, uint32_t bandId) {
    RawResult raw;
    return eraseBand(session, bandId, raw);
}

Result EvalApi::eraseAllBands(Session& session, uint32_t maxBands) {
    RawResult raw;
    return eraseAllBands(session, maxBands, raw);
}

Result EvalApi::setBandLockOnReset(Session& session, uint32_t bandId, bool lockOnReset) {
    RawResult raw;
    return setBandLockOnReset(session, bandId, lockOnReset, raw);
}

} // namespace eval
} // namespace libsed
