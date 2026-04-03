#include "libsed/method/param_decoder.h"
#include "libsed/core/uid.h"
#include "libsed/core/log.h"

namespace libsed {

Result ParamDecoder::decodeSyncSession(TokenStream& stream, SessionParams& out) {
    // SyncSession response: HSN TSN [ optional named params ]
    // The response is inside a list from the method result

    auto hsn = stream.readUint();
    if (!hsn) return ErrorCode::MalformedResponse;
    out.hostSessionNumber = static_cast<uint32_t>(*hsn);

    auto tsn = stream.readUint();
    if (!tsn) return ErrorCode::MalformedResponse;
    out.tperSessionNumber = static_cast<uint32_t>(*tsn);

    // Optional named parameters
    while (stream.hasMore() && stream.isStartName()) {
        stream.expectStartName();
        auto name = stream.readUint();
        if (!name) break;

        switch (*name) {
            case 0: { // SPChallenge
                auto val = stream.readBytes();
                if (val) out.spChallenge = *val;
                break;
            }
            case 1: { // TransTimeout
                auto val = stream.readUint();
                if (val) out.tperTransTimeout = static_cast<uint32_t>(*val);
                break;
            }
            case 2: { // InitialTimeout
                auto val = stream.readUint();
                if (val) out.tperInitialTimeout = static_cast<uint32_t>(*val);
                break;
            }
            default:
                stream.skip(); // skip unknown value
                break;
        }
        stream.expectEndName();
    }

    return ErrorCode::Success;
}

Result ParamDecoder::decodeProperties(TokenStream& stream, TPerProperties& out) {
    // Properties response: [ Name1, Value1, Name2, Value2, ... ]
    // Each pair is just two tokens: a String name and a Uint value.
    // They are NOT enclosed in STARTNAME/ENDNAME.

    while (stream.hasMore()) {
        if (stream.isEndList()) break;

        auto nameStr = stream.readString();
        if (!nameStr) continue; // readString already consumed one token

        auto val = stream.readUint();
        if (!val) continue; // readUint already consumed one token

        uint32_t v = static_cast<uint32_t>(*val);

        if (*nameStr == "MaxMethods")              out.maxMethods = v;
        else if (*nameStr == "MaxSubpackets")      out.maxSubPackets = v;
        else if (*nameStr == "MaxPackets")         out.maxPackets = v;
        else if (*nameStr == "MaxComPacketSize")   out.maxComPacketSize = v;
        else if (*nameStr == "MaxResponseComPacketSize") out.maxResponseComPacketSize = v;
        else if (*nameStr == "MaxPacketSize")      out.maxPacketSize = v;
        else if (*nameStr == "MaxIndTokenSize")    out.maxIndTokenSize = v;
        else if (*nameStr == "MaxAggTokenSize")    out.maxAggTokenSize = v;
        else if (*nameStr == "ContinuedTokens")    out.continuedTokens = v;
        else if (*nameStr == "SequenceNumbers")    out.sequenceNumbers = v;
        else if (*nameStr == "AckNak")             out.ackNak = v;
        else if (*nameStr == "Async")              out.async = v;
    }

    return ErrorCode::Success;
}

Result ParamDecoder::decodeGetResponse(TokenStream& stream, ColumnValues& out) {
    out.clear();

    // Get response: [ { col = val } { col = val } ... ]
    while (stream.hasMore()) {
        if (stream.isStartName()) {
            stream.expectStartName();
            auto col = stream.readUint();
            if (!col) { stream.skipNamedValue(); continue; }

            const Token* valToken = stream.next();
            if (valToken) {
                out[static_cast<uint32_t>(*col)] = *valToken;
            }
            stream.expectEndName();
        } else if (stream.isEndList() || stream.isEndOfData()) {
            break;
        } else {
            stream.skip();
        }
    }

    return ErrorCode::Success;
}

Result ParamDecoder::decodeLockingRange(const ColumnValues& values,
                                          LockingRangeInfo& out) {
    auto rs = extractUint(values, uid::col::RANGE_START);
    if (rs) out.rangeStart = *rs;

    auto rl = extractUint(values, uid::col::RANGE_LENGTH);
    if (rl) out.rangeLength = *rl;

    auto rle = extractBool(values, uid::col::READ_LOCK_EN);
    if (rle) out.readLockEnabled = *rle;

    auto wle = extractBool(values, uid::col::WRITE_LOCK_EN);
    if (wle) out.writeLockEnabled = *wle;

    auto rlk = extractBool(values, uid::col::READ_LOCKED);
    if (rlk) out.readLocked = *rlk;

    auto wlk = extractBool(values, uid::col::WRITE_LOCKED);
    if (wlk) out.writeLocked = *wlk;

    return ErrorCode::Success;
}

std::optional<uint64_t> ParamDecoder::extractUint(const ColumnValues& values,
                                                     uint32_t col) {
    auto it = values.find(col);
    if (it == values.end() || !it->second.isAtom() || it->second.isByteSequence)
        return std::nullopt;
    return it->second.getUint();
}

std::optional<bool> ParamDecoder::extractBool(const ColumnValues& values,
                                                 uint32_t col) {
    auto val = extractUint(values, col);
    if (!val) return std::nullopt;
    return *val != 0;
}

std::optional<Bytes> ParamDecoder::extractBytes(const ColumnValues& values,
                                                   uint32_t col) {
    auto it = values.find(col);
    if (it == values.end() || !it->second.isByteSequence)
        return std::nullopt;
    return it->second.getBytes();
}

std::optional<std::string> ParamDecoder::extractString(const ColumnValues& values,
                                                          uint32_t col) {
    auto bytes = extractBytes(values, col);
    if (!bytes) return std::nullopt;
    return std::string(bytes->begin(), bytes->end());
}

} // namespace libsed
