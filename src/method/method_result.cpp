#include "libsed/method/method_result.h"
#include "libsed/method/method_uids.h"
#include "libsed/core/log.h"
#include <cstring>
#include <cstdio>

namespace libsed {

/// @brief MethodUID를 사람이 읽을 수 있는 이름으로 변환 (디버그 로그용)
static const char* methodUidName(uint64_t uid) {
    if (uid == method::GET)             return "Get";
    if (uid == method::SET)             return "Set";
    if (uid == method::AUTHENTICATE)    return "Authenticate";
    if (uid == method::REVERT)          return "Revert";
    if (uid == method::REVERTSP)        return "RevertSP";
    if (uid == method::ACTIVATE)        return "Activate";
    if (uid == method::NEXT)            return "Next";
    if (uid == method::ERASE)           return "Erase";
    if (uid == method::GENKEY)          return "GenKey";
    if (uid == method::RANDOM)          return "Random";
    if (uid == method::SM_PROPERTIES)   return "Properties";
    if (uid == method::SM_START_SESSION)return "StartSession";
    if (uid == method::SM_SYNC_SESSION) return "SyncSession";
    if (uid == method::SM_CLOSE_SESSION)return "CloseSession";
    return nullptr;
}

/// @brief 8-byte Token에서 uint64_t UID 추출
static uint64_t tokenToUid(const Token& tok) {
    auto bytes = tok.getBytes();
    if (bytes.size() != 8) return 0;
    uint64_t uid = 0;
    for (size_t i = 0; i < 8; i++)
        uid = (uid << 8) | bytes[i];
    return uid;
}

Result MethodResult::parse(const Bytes& tokenData) {
    TokenDecoder decoder;
    auto r = decoder.decode(tokenData);
    if (r.failed()) return r;
    return parse(decoder.tokens());
}

Result MethodResult::parse(const std::vector<Token>& tokens) {
    resultTokens_.clear();
    status_ = MethodStatus::Fail;
    methodName_.clear();

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
    // Also extract method name for logging
    size_t startIdx = 0;
    if (startIdx < eodIndex && tokens[startIdx].type == TokenType::Call) {
        ++startIdx;  // skip CALL
        // skip InvokingUID (byte-sequence atom)
        if (startIdx < eodIndex && tokens[startIdx].isAtom() && tokens[startIdx].isByteSequence)
            ++startIdx;
        // extract MethodUID for logging, then skip
        if (startIdx < eodIndex && tokens[startIdx].isAtom() && tokens[startIdx].isByteSequence) {
            uint64_t muid = tokenToUid(tokens[startIdx]);
            const char* name = methodUidName(muid);
            if (name) {
                methodName_ = name;
            } else {
                char buf[24];
                snprintf(buf, sizeof(buf), "UID(0x%016llX)",
                         static_cast<unsigned long long>(muid));
                methodName_ = buf;
            }
            ++startIdx;
        }
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
        if (!methodName_.empty()) {
            LIBSED_WARN("%s returned status: 0x%02X (%s)",
                        methodName_.c_str(),
                        static_cast<int>(status_),
                        statusMessage().c_str());
        } else {
            LIBSED_WARN("Method returned status: 0x%02X (%s)",
                        static_cast<int>(status_),
                        statusMessage().c_str());
        }
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
        case MethodStatus::UniquenessConflict:return "Uniqueness Conflict";
        case MethodStatus::InsufficientSpace: return "Insufficient Space";
        case MethodStatus::InsufficientRows:  return "Insufficient Rows";
        case MethodStatus::InvalidParameter:  return "Invalid Parameter";
        case MethodStatus::TPerMalfunction:   return "TPer Malfunction";
        case MethodStatus::TransactionFailure:return "Transaction Failure";
        case MethodStatus::ResponseOverflow:  return "Response Overflow";
        case MethodStatus::AuthorityLockedOut:return "Authority Locked Out";
        case MethodStatus::Fail:              return "Fail";
        default: {
            char buf[32];
            snprintf(buf, sizeof(buf), "Unknown(0x%02X)", static_cast<int>(status_));
            return buf;
        }
    }
}

void MethodResult::setSendMethodUid(uint64_t uid) {
    if (!methodName_.empty()) return;  // 응답 CALL에서 이미 설정됨
    const char* name = methodUidName(uid);
    if (name) {
        methodName_ = name;
    } else {
        char buf[24];
        snprintf(buf, sizeof(buf), "UID(0x%016llX)",
                 static_cast<unsigned long long>(uid));
        methodName_ = buf;
    }
}

} // namespace libsed
