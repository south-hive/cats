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
#include "libsed/security/hash_password.h"
#include "eval_api_internal.h"

namespace libsed {
namespace eval {

// ════════════════════════════════════════════════════════
//  C_PIN
// ════════════════════════════════════════════════════════

Result EvalApi::getCPin(Session& session, uint64_t cpinUid,
                         Bytes& pin, RawResult& result) {
    CellBlock cb;
    cb.startColumn = uid::col::PIN;
    cb.endColumn = uid::col::PIN;
    Bytes tokens = MethodCall::buildGet(Uid(cpinUid), cb);
    auto r = sendMethod(session, tokens, result);
    if (r.failed()) return r;

    if (result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);
        auto it = values.find(uid::col::PIN);
        if (it != values.end()) {
            pin = it->second.getBytes();
        }
    }
    return r;
}

Result EvalApi::setCPin(Session& session, uint64_t cpinUid,
                         const Bytes& newPin, RawResult& result) {
    TokenList values;
    values.addBytes(uid::col::PIN, newPin);
    Bytes tokens = MethodCall::buildSet(Uid(cpinUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::setCPin(Session& session, uint64_t cpinUid,
                         const std::string& newPassword, RawResult& result) {
    Bytes pin = HashPassword::passwordToBytes(newPassword);
    return setCPin(session, cpinUid, pin, result);
}

// ════════════════════════════════════════════════════════
//  MBR
// ════════════════════════════════════════════════════════

Result EvalApi::setMbrEnable(Session& session, bool enable, RawResult& result) {
    return tableSetBool(session, uid::MBRCTRL_SET, uid::col::MBR_ENABLE, enable, result);
}

Result EvalApi::setMbrDone(Session& session, bool done, RawResult& result) {
    return tableSetBool(session, uid::MBRCTRL_SET, uid::col::MBR_DONE, done, result);
}

Result EvalApi::writeMbrData(Session& session, uint32_t offset,
                              const Bytes& data, RawResult& result) {
    // MBR table write with Where = offset
    TokenEncoder enc;
    enc.startList();
    enc.namedUint(0, offset);  // Where
    enc.namedBytes(1, data);   // Values
    enc.endList();

    // Build Set call on MBR table
    Bytes tokens = buildMethodCall(uid::TABLE_MBR, method::SET, enc.data());
    return sendMethod(session, tokens, result);
}

Result EvalApi::readMbrData(Session& session, uint32_t offset, uint32_t length,
                             Bytes& data, RawResult& result) {
    CellBlock cb;
    cb.startRow = offset;
    cb.endRow = offset + length - 1;
    Bytes tokens = MethodCall::buildGet(Uid(uid::TABLE_MBR), cb);
    auto r = sendMethod(session, tokens, result);
    if (r.ok() && result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        // Extract raw bytes from response
        if (stream.hasMore() && stream.peek()->isByteSequence) {
            data = stream.next()->getBytes();
        }
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  MBR Control NSID=1
// ════════════════════════════════════════════════════════

Result EvalApi::setMbrControlNsidOne(Session& session, RawResult& result) {
    // Set MBR Control table: Enable=1, Done=0, then Done=1 for NSID=1
    auto r = setMbrEnable(session, true, result);
    if (r.failed()) return r;
    return setMbrDone(session, true, result);
}

// ════════════════════════════════════════════════════════
//  MBR Extended
// ════════════════════════════════════════════════════════

Result EvalApi::getMbrStatus(Session& session, bool& mbrEnabled,
                              bool& mbrDone, RawResult& result) {
    TableResult tr;
    auto r = tableGetAll(session, uid::MBRCTRL_SET, tr);
    result = tr.raw;
    if (r.ok()) {
        for (auto& [col, tok] : tr.columns) {
            if (col == uid::col::MBR_ENABLE) mbrEnabled = (tok.getUint() != 0);
            if (col == uid::col::MBR_DONE) mbrDone = (tok.getUint() != 0);
        }
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Locking Range
// ════════════════════════════════════════════════════════

Result EvalApi::setRange(Session& session, uint32_t rangeId,
                          uint64_t rangeStart, uint64_t rangeLength,
                          bool readLockEnabled, bool writeLockEnabled,
                          RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();

    TokenList values;
    values.addUint(uid::col::RANGE_START, rangeStart);
    values.addUint(uid::col::RANGE_LENGTH, rangeLength);
    values.addUint(uid::col::READ_LOCK_EN, readLockEnabled ? 1 : 0);
    values.addUint(uid::col::WRITE_LOCK_EN, writeLockEnabled ? 1 : 0);

    Bytes tokens = MethodCall::buildSet(Uid(rangeUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::setRangeLock(Session& session, uint32_t rangeId,
                              bool readLocked, bool writeLocked,
                              RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();

    TokenList values;
    values.addUint(uid::col::READ_LOCKED, readLocked ? 1 : 0);
    values.addUint(uid::col::WRITE_LOCKED, writeLocked ? 1 : 0);

    Bytes tokens = MethodCall::buildSet(Uid(rangeUid), values);
    return sendMethod(session, tokens, result);
}

Result EvalApi::getRangeInfo(Session& session, uint32_t rangeId,
                              LockingRangeInfo& info, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    Bytes tokens = MethodCall::buildGet(Uid(rangeUid));
    auto r = sendMethod(session, tokens, result);
    if (r.failed()) return r;

    if (result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        ParamDecoder::ColumnValues values;
        ParamDecoder::decodeGetResponse(stream, values);
        info.rangeId = rangeId;
        ParamDecoder::decodeLockingRange(values, info);
    }
    return r;
}

// ════════════════════════════════════════════════════════
//  Locking Range Extended
// ════════════════════════════════════════════════════════

Result EvalApi::setLockOnReset(Session& session, uint32_t rangeId,
                                bool lockOnReset, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    return tableSetBool(session, rangeUid, uid::col::LOCK_ON_RESET, lockOnReset, result);
}

Result EvalApi::cryptoErase(Session& session, uint32_t rangeId, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    return genKey(session, rangeUid, result);
}

// ════════════════════════════════════════════════════════
//  Crypto / Key
// ════════════════════════════════════════════════════════

Result EvalApi::genKey(Session& session, uint64_t objectUid, RawResult& result) {
    Bytes tokens = MethodCall::buildGenKey(Uid(objectUid));
    return sendMethod(session, tokens, result);
}

Result EvalApi::getRandom(Session& session, uint32_t count,
                           Bytes& randomData, RawResult& result) {
    TokenEncoder paramEnc;
    paramEnc.encodeUint(count);

    Bytes tokens = buildMethodCall(uid::THIS_SP, method::RANDOM, paramEnc.data());
    auto r = sendMethod(session, tokens, result);
    if (r.ok() && result.methodResult.isSuccess()) {
        auto stream = result.methodResult.resultStream();
        if (stream.hasMore() && stream.peek()->isByteSequence) {
            randomData = stream.next()->getBytes();
        }
    }
    return r;
}

Result EvalApi::erase(Session& session, uint64_t objectUid, RawResult& result) {
    Bytes tokens = MethodCall::buildErase(Uid(objectUid));
    return sendMethod(session, tokens, result);
}

// ════════════════════════════════════════════════════════
//  Active Key
// ════════════════════════════════════════════════════════

Result EvalApi::getActiveKey(Session& session, uint32_t rangeId,
                              Uid& keyUid, RawResult& result) {
    uint64_t rangeUid = uid::makeLockingRangeUid(rangeId).toUint64();
    Token val;
    auto r = tableGetColumn(session, rangeUid, uid::col::ACTIVE_KEY, val, result);
    if (r.ok() && val.isByteSequence && val.getBytes().size() == 8) {
        keyUid = Uid(val.getBytes());
    }
    return r;
}

// ══════════════════════════════════════════════════════════
//  Simplified overloads (RawResult omitted)
// ══════════════════════════════════════════════════════════

Result EvalApi::getCPin(Session& session, uint64_t cpinUid, Bytes& pin) {
    RawResult raw;
    return getCPin(session, cpinUid, pin, raw);
}

Result EvalApi::setCPin(Session& session, uint64_t cpinUid, const Bytes& newPin) {
    RawResult raw;
    return setCPin(session, cpinUid, newPin, raw);
}

Result EvalApi::setCPin(Session& session, uint64_t cpinUid, const std::string& newPassword) {
    RawResult raw;
    return setCPin(session, cpinUid, newPassword, raw);
}

Result EvalApi::setRange(Session& session, uint32_t rangeId, uint64_t rangeStart,
                         uint64_t rangeLength, bool readLockEnabled, bool writeLockEnabled) {
    RawResult raw;
    return setRange(session, rangeId, rangeStart, rangeLength, readLockEnabled, writeLockEnabled, raw);
}

Result EvalApi::setRangeLock(Session& session, uint32_t rangeId, bool readLocked, bool writeLocked) {
    RawResult raw;
    return setRangeLock(session, rangeId, readLocked, writeLocked, raw);
}

Result EvalApi::getRangeInfo(Session& session, uint32_t rangeId, LockingRangeInfo& info) {
    RawResult raw;
    return getRangeInfo(session, rangeId, info, raw);
}

Result EvalApi::setMbrEnable(Session& session, bool enable) {
    RawResult raw;
    return setMbrEnable(session, enable, raw);
}

Result EvalApi::setMbrDone(Session& session, bool done) {
    RawResult raw;
    return setMbrDone(session, done, raw);
}

Result EvalApi::writeMbrData(Session& session, uint32_t offset, const Bytes& data) {
    RawResult raw;
    return writeMbrData(session, offset, data, raw);
}

Result EvalApi::readMbrData(Session& session, uint32_t offset, uint32_t length, Bytes& data) {
    RawResult raw;
    return readMbrData(session, offset, length, data, raw);
}

Result EvalApi::getMbrStatus(Session& session, bool& mbrEnabled, bool& mbrDone) {
    RawResult raw;
    return getMbrStatus(session, mbrEnabled, mbrDone, raw);
}

Result EvalApi::setMbrControlNsidOne(Session& session) {
    RawResult raw;
    return setMbrControlNsidOne(session, raw);
}

Result EvalApi::setLockOnReset(Session& session, uint32_t rangeId, bool lockOnReset) {
    RawResult raw;
    return setLockOnReset(session, rangeId, lockOnReset, raw);
}

Result EvalApi::cryptoErase(Session& session, uint32_t rangeId) {
    RawResult raw;
    return cryptoErase(session, rangeId, raw);
}

Result EvalApi::genKey(Session& session, uint64_t objectUid) {
    RawResult raw;
    return genKey(session, objectUid, raw);
}

Result EvalApi::getActiveKey(Session& session, uint32_t rangeId, Uid& keyUid) {
    RawResult raw;
    return getActiveKey(session, rangeId, keyUid, raw);
}

Result EvalApi::getRandom(Session& session, uint32_t count, Bytes& randomData) {
    RawResult raw;
    return getRandom(session, count, randomData, raw);
}

} // namespace eval
} // namespace libsed
