#include "libsed/method/param_encoder.h"
#include "libsed/core/uid.h"

namespace libsed {

Bytes ParamEncoder::encodeStartSession(uint32_t hostSessionId,
                                         const Uid& spUid,
                                         bool write,
                                         const Bytes& hostChallenge,
                                         const Uid& hostExchangeAuth,
                                         const Uid& hostSignAuth) {
    TokenEncoder enc;

    // Parameter 0: Host Session ID
    enc.encodeUint(hostSessionId);

    // Parameter 1: SP UID
    enc.encodeUid(spUid);

    // Parameter 2: Write (boolean)
    enc.encodeBool(write);

    // Optional: Host Challenge
    if (!hostChallenge.empty()) {
        enc.startName();
        enc.encodeUint(0); // HostChallenge
        enc.encodeBytes(hostChallenge);
        enc.endName();
    }

    // Optional: HostExchangeAuthority (TCG Core Spec Table 225, named param index 1)
    if (!hostExchangeAuth.isNull()) {
        enc.startName();
        enc.encodeUint(1); // HostExchangeAuthority
        enc.encodeUid(hostExchangeAuth);
        enc.endName();
    }

    // Optional: HostSigningAuthority (TCG Core Spec Table 225, named param index 2)
    if (!hostSignAuth.isNull()) {
        enc.startName();
        enc.encodeUint(2); // HostSigningAuthority
        enc.encodeUid(hostSignAuth);
        enc.endName();
    }

    return enc.data();
}

Bytes ParamEncoder::encodeProperties(const HostProperties& props) {
    TokenEncoder enc;

    // Host properties list
    enc.startList();

    enc.startName(); enc.encodeString("MaxMethods");
    enc.encodeUint(props.maxMethods); enc.endName();

    enc.startName(); enc.encodeString("MaxSubPackets");
    enc.encodeUint(props.maxSubPackets); enc.endName();

    enc.startName(); enc.encodeString("MaxPackets");
    enc.encodeUint(props.maxPackets); enc.endName();

    enc.startName(); enc.encodeString("MaxComPacketSize");
    enc.encodeUint(props.maxComPacketSize); enc.endName();

    enc.startName(); enc.encodeString("MaxResponseComPacketSize");
    enc.encodeUint(props.maxResponseComPacketSize); enc.endName();

    enc.startName(); enc.encodeString("MaxPacketSize");
    enc.encodeUint(props.maxPacketSize); enc.endName();

    enc.startName(); enc.encodeString("MaxIndTokenSize");
    enc.encodeUint(props.maxIndTokenSize); enc.endName();

    enc.startName(); enc.encodeString("MaxAggTokenSize");
    enc.encodeUint(props.maxAggTokenSize); enc.endName();

    enc.startName(); enc.encodeString("ContinuedTokens");
    enc.encodeUint(props.continuedTokens); enc.endName();

    enc.startName(); enc.encodeString("SequenceNumbers");
    enc.encodeUint(props.sequenceNumbers); enc.endName();

    enc.startName(); enc.encodeString("AckNak");
    enc.encodeUint(props.ackNak); enc.endName();

    enc.startName(); enc.encodeString("Async");
    enc.encodeUint(props.async); enc.endName();

    enc.endList();

    return enc.data();
}

void ParamEncoder::encodeCellBlock(TokenEncoder& enc, const CellBlock& cb) {
    if (cb.startColumn) {
        enc.startName();
        enc.encodeUint(0); // startColumn
        enc.encodeUint(*cb.startColumn);
        enc.endName();
    }
    if (cb.endColumn) {
        enc.startName();
        enc.encodeUint(1); // endColumn
        enc.encodeUint(*cb.endColumn);
        enc.endName();
    }
    if (cb.startRow) {
        enc.startName();
        enc.encodeUint(2); // startRow
        enc.encodeUint(*cb.startRow);
        enc.endName();
    }
    if (cb.endRow) {
        enc.startName();
        enc.encodeUint(3); // endRow
        enc.encodeUint(*cb.endRow);
        enc.endName();
    }
}

Bytes ParamEncoder::encodeAuthenticate(const Uid& authority, const Bytes& challenge) {
    TokenEncoder enc;
    enc.encodeUid(authority);

    if (!challenge.empty()) {
        enc.startName();
        enc.encodeUint(0); // Challenge
        enc.encodeBytes(challenge);
        enc.endName();
    }

    return enc.data();
}

Bytes ParamEncoder::encodeLockingRangeSet(
    std::optional<uint64_t> rangeStart,
    std::optional<uint64_t> rangeLength,
    std::optional<bool> readLockEnabled,
    std::optional<bool> writeLockEnabled,
    std::optional<bool> readLocked,
    std::optional<bool> writeLocked) {

    return encodeSetValues([&](TokenEncoder& enc) {
        if (rangeStart)      enc.namedUint(uid::col::RANGE_START, *rangeStart);
        if (rangeLength)     enc.namedUint(uid::col::RANGE_LENGTH, *rangeLength);
        if (readLockEnabled) enc.namedBool(uid::col::READ_LOCK_EN, *readLockEnabled);
        if (writeLockEnabled)enc.namedBool(uid::col::WRITE_LOCK_EN, *writeLockEnabled);
        if (readLocked)      enc.namedBool(uid::col::READ_LOCKED, *readLocked);
        if (writeLocked)     enc.namedBool(uid::col::WRITE_LOCKED, *writeLocked);
    });
}

Bytes ParamEncoder::encodeMbrControl(std::optional<bool> enable,
                                       std::optional<bool> done) {
    return encodeSetValues([&](TokenEncoder& enc) {
        if (enable) enc.namedBool(uid::col::MBR_ENABLE, *enable);
        if (done)   enc.namedBool(uid::col::MBR_DONE, *done);
    });
}

Bytes ParamEncoder::encodePinSet(const Bytes& newPin) {
    return encodeSetValues([&](TokenEncoder& enc) {
        enc.namedBytes(uid::col::PIN, newPin);
    });
}

Bytes ParamEncoder::encodePinSet(const std::string& newPin) {
    Bytes pinBytes(newPin.begin(), newPin.end());
    return encodePinSet(pinBytes);
}

Bytes ParamEncoder::encodeAuthorityEnable(bool enabled) {
    return encodeSetValues([&](TokenEncoder& enc) {
        enc.namedBool(uid::col::AUTH_ENABLED, enabled);
    });
}

Bytes ParamEncoder::encodeSetValues(
    const std::function<void(TokenEncoder&)>& valueWriter) {
    TokenEncoder enc;

    // Where (empty)
    // Values
    enc.startName();
    enc.encodeUint(1); // "Values"
    enc.startList();
    valueWriter(enc);
    enc.endList();
    enc.endName();

    return enc.data();
}

} // namespace libsed
