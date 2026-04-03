#include "libsed/method/method_result.h"
#include "libsed/core/log.h"

namespace libsed {

Result MethodResult::parse(const Bytes& tokenData) {
    TokenDecoder decoder;
    auto r = decoder.decode(tokenData);
    if (r.failed()) return r;
    return parse(decoder.tokens());
}

Result MethodResult::parse(const std::vector<Token>& tokens) {
    resultTokens_.clear();
    status_ = MethodStatus::Fail;

    if (tokens.empty()) {
        return ErrorCode::MalformedResponse;
    }

    // Find EndOfData token - everything before it is result data
    size_t eodIndex = tokens.size();
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::EndOfData) {
            eodIndex = i;
            break;
        }
    }

    // Skip CALL header if present: CALL InvokingUID MethodUID
    // SM method responses (SyncSession, etc.) include the CALL block
    size_t startIdx = 0;
    if (startIdx < eodIndex && tokens[startIdx].type == TokenType::Call) {
        ++startIdx;  // skip CALL
        // skip InvokingUID (byte-sequence atom)
        if (startIdx < eodIndex && tokens[startIdx].isAtom() && tokens[startIdx].isByteSequence)
            ++startIdx;
        // skip MethodUID (byte-sequence atom)
        if (startIdx < eodIndex && tokens[startIdx].isAtom() && tokens[startIdx].isByteSequence)
            ++startIdx;
    }

    // Collect result tokens (skip outer StartList/EndList if present)
    size_t endIdx = eodIndex;

    if (startIdx < endIdx && tokens[startIdx].type == TokenType::StartList) {
        ++startIdx;
        if (endIdx > 0 && tokens[endIdx - 1].type == TokenType::EndList) {
            --endIdx;
        }
    }

    for (size_t i = startIdx; i < endIdx; ++i) {
        resultTokens_.push_back(tokens[i]);
    }

    // Parse status list after EndOfData: [ status_code reserved reserved ]
    if (eodIndex + 1 < tokens.size()) {
        size_t statusStart = eodIndex + 1;
        // Expect StartList
        if (statusStart < tokens.size() &&
            tokens[statusStart].type == TokenType::StartList) {
            ++statusStart;
        }
        if (statusStart < tokens.size() && tokens[statusStart].isAtom()) {
            status_ = static_cast<MethodStatus>(tokens[statusStart].getUint() & 0xFF);
        }
    }

    // Check for EndOfSession
    for (size_t i = eodIndex; i < tokens.size(); ++i) {
        if (tokens[i].type == TokenType::EndOfSession) {
            LIBSED_DEBUG("EndOfSession found in response");
            break;
        }
    }

    if (status_ != MethodStatus::Success) {
        LIBSED_WARN("Method returned status: 0x%02X", static_cast<int>(status_));
    }

    return ErrorCode::Success;
}

std::unordered_map<uint32_t, Token> MethodResult::getNamedValues() const {
    std::unordered_map<uint32_t, Token> result;
    TokenStream stream(resultTokens_);

    while (stream.hasMore()) {
        if (stream.isStartName()) {
            stream.expectStartName();
            auto name = stream.readUint();
            if (!name) break;

            const Token* valToken = stream.next();
            if (!valToken) break;

            result[static_cast<uint32_t>(*name)] = *valToken;

            stream.expectEndName();
        } else {
            stream.skip();
        }
    }

    return result;
}

std::optional<uint64_t> MethodResult::getUint(uint32_t name) const {
    auto values = getNamedValues();
    auto it = values.find(name);
    if (it == values.end() || !it->second.isAtom() || it->second.isByteSequence)
        return std::nullopt;
    return it->second.getUint();
}

std::optional<Bytes> MethodResult::getBytes(uint32_t name) const {
    auto values = getNamedValues();
    auto it = values.find(name);
    if (it == values.end() || !it->second.isByteSequence)
        return std::nullopt;
    return it->second.getBytes();
}

std::optional<bool> MethodResult::getBool(uint32_t name) const {
    auto val = getUint(name);
    if (!val) return std::nullopt;
    return *val != 0;
}

Result MethodResult::toResult() const {
    switch (status_) {
        case MethodStatus::Success:           return ErrorCode::Success;
        case MethodStatus::NotAuthorized:     return ErrorCode::MethodNotAuthorized;
        case MethodStatus::SpBusy:            return ErrorCode::MethodSpBusy;
        case MethodStatus::SpFailed:          return ErrorCode::MethodSpFailed;
        case MethodStatus::SpDisabled:        return ErrorCode::MethodSpDisabled;
        case MethodStatus::SpFrozen:          return ErrorCode::MethodSpFrozen;
        case MethodStatus::InvalidParameter:  return ErrorCode::MethodInvalidParam;
        case MethodStatus::TPerMalfunction:   return ErrorCode::MethodTPerMalfunction;
        case MethodStatus::AuthorityLockedOut:return ErrorCode::AuthLockedOut;
        default:                              return ErrorCode::MethodFailed;
    }
}

std::string MethodResult::statusMessage() const {
    switch (status_) {
        case MethodStatus::Success:           return "Success";
        case MethodStatus::NotAuthorized:     return "Not Authorized";
        case MethodStatus::SpBusy:            return "SP Busy";
        case MethodStatus::SpFailed:          return "SP Failed";
        case MethodStatus::SpDisabled:        return "SP Disabled";
        case MethodStatus::SpFrozen:          return "SP Frozen";
        case MethodStatus::NoSessionsAvailable: return "No Sessions Available";
        case MethodStatus::InvalidParameter:  return "Invalid Parameter";
        case MethodStatus::TPerMalfunction:   return "TPer Malfunction";
        case MethodStatus::AuthorityLockedOut:return "Authority Locked Out";
        case MethodStatus::Fail:              return "General Failure";
        default:                              return "Unknown Status";
    }
}

} // namespace libsed
