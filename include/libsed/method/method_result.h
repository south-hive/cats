#pragma once

#include "../core/types.h"
#include "../core/error.h"
#include "../codec/token.h"
#include "../codec/token_decoder.h"
#include "../codec/token_stream.h"
#include <vector>
#include <optional>
#include <unordered_map>

namespace libsed {

/// Parsed method result from TPer response
class MethodResult {
public:
    MethodResult() = default;

    /// Parse token stream from a method response
    /// Expected structure: [ result_data ] EndOfData [ status_code 0 0 ]
    Result parse(const Bytes& tokenData);
    Result parse(const std::vector<Token>& tokens);

    /// Get method status code
    MethodStatus status() const { return status_; }
    bool isSuccess() const { return status_ == MethodStatus::Success; }

    /// Get result tokens (between StartList/EndList, before EndOfData)
    const std::vector<Token>& resultTokens() const { return resultTokens_; }

    /// Get result as a TokenStream for easy reading
    TokenStream resultStream() const { return TokenStream(resultTokens_); }

    /// Get result as named value map (column_num → Token)
    /// Useful for Get method responses
    std::unordered_map<uint32_t, Token> getNamedValues() const;

    /// Get a specific named uint value
    std::optional<uint64_t> getUint(uint32_t name) const;

    /// Get a specific named bytes value
    std::optional<Bytes> getBytes(uint32_t name) const;

    /// Get a specific named bool value
    std::optional<bool> getBool(uint32_t name) const;

    /// Convert MethodStatus to Result
    Result toResult() const;

    /// Error message
    std::string statusMessage() const;

    /// 응답에서 추출된 메서드 이름 (CALL 헤더가 있는 경우)
    const std::string& methodName() const { return methodName_; }

    /// 응답 CALL 헤더에서 추출한 method UID (없으면 0).
    /// SM_CLOSE_SESSION 등 server-initiated close 감지에 사용.
    uint64_t recvMethodUid() const { return recvMethodUid_; }

    /// send 토큰에서 추출한 메서드 UID 설정 (일반 메서드용)
    void setSendMethodUid(uint64_t uid);

private:
    MethodStatus status_ = MethodStatus::Fail;
    std::vector<Token> resultTokens_;
    std::string methodName_;
    uint64_t    recvMethodUid_ = 0;
};

} // namespace libsed
