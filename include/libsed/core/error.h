#pragma once

#include <cstdint>
#include <string>
#include <system_error>
#include <stdexcept>

namespace libsed {

/// @brief TCG SED 라이브러리 에러 코드
///
/// 라이브러리 전체에서 사용되는 에러 코드 열거형이다.
/// 범위별로 분류되어 있어 에러의 발생 계층을 빠르게 파악할 수 있다.
enum class ErrorCode : int {
    Success = 0,  ///< 성공 (에러 없음)

    // ── 전송 계층 에러 (100-199) ──────────────────────
    TransportNotAvailable = 100,   ///< 전송 인터페이스를 사용할 수 없음
    TransportOpenFailed   = 101,   ///< 전송 인터페이스 열기 실패 (디바이스 접근 불가)
    TransportSendFailed   = 102,   ///< IF-SEND 명령 전송 실패
    TransportRecvFailed   = 103,   ///< IF-RECV 명령 수신 실패
    TransportTimeout      = 104,   ///< 전송 타임아웃 (응답 시간 초과)
    TransportInvalidDevice = 105,  ///< 유효하지 않은 디바이스

    // ── 프로토콜 에러 (200-299) ───────────────────────
    InvalidToken          = 200,   ///< 유효하지 않은 TCG 토큰
    InvalidPacket         = 201,   ///< 유효하지 않은 패킷 구조
    InvalidSubPacket      = 202,   ///< 유효하지 않은 서브패킷 구조
    InvalidComPacket      = 203,   ///< 유효하지 않은 ComPacket 구조
    BufferTooSmall        = 204,   ///< 버퍼 크기 부족 (데이터를 담기에 너무 작음)
    BufferOverflow        = 205,   ///< 버퍼 오버플로우 (데이터가 버퍼 경계를 초과)
    UnexpectedToken       = 206,   ///< 예상하지 못한 토큰 수신
    MalformedResponse     = 207,   ///< 비정상적인 응답 형식
    ProtocolError         = 208,   ///< 일반적인 프로토콜 에러

    // ── 세션 에러 (300-399) ───────────────────────────
    SessionNotStarted     = 300,   ///< 세션이 시작되지 않은 상태에서 작업 시도
    SessionAlreadyActive  = 301,   ///< 이미 활성화된 세션이 존재함
    SessionClosed         = 302,   ///< 세션이 이미 종료됨
    SessionSyncFailed     = 303,   ///< 세션 동기화 실패 (TSN/HSN 불일치)
    NoSessionAvailable    = 304,   ///< 사용 가능한 세션 슬롯 없음

    // ── 메서드 에러 (400-499) ─────────────────────────
    MethodNotAuthorized   = 401,   ///< 메서드 호출 권한 없음 (인증 필요)
    MethodSpBusy          = 403,   ///< SP가 사용 중 (다른 세션 처리 중)
    MethodSpFailed        = 404,   ///< SP 내부 오류로 메서드 실패
    MethodSpDisabled      = 405,   ///< SP가 비활성화 상태
    MethodSpFrozen        = 406,   ///< SP가 동결 상태
    MethodInvalidParam    = 412,   ///< 메서드에 전달된 파라미터가 유효하지 않음
    MethodTPerMalfunction = 415,   ///< TPer 하드웨어/펌웨어 오작동
    MethodFailed          = 463,   ///< 메서드 실행 일반 실패

    // ── Discovery 에러 (500-599) ──────────────────────
    DiscoveryFailed       = 500,   ///< Level 0 Discovery 수행 실패
    DiscoveryInvalidData  = 501,   ///< Discovery 응답 데이터 파싱 실패 (형식 오류)
    UnsupportedSsc        = 502,   ///< 지원되지 않는 SSC 타입
    FeatureNotFound       = 503,   ///< 요청한 Feature Descriptor를 찾을 수 없음

    // ── 인증 에러 (600-699) ───────────────────────────
    AuthFailed            = 600,   ///< 인증 실패 (비밀번호 불일치 등)
    AuthLockedOut         = 601,   ///< 인증 시도 초과로 Authority 잠김
    InvalidCredential     = 602,   ///< 유효하지 않은 인증 정보 (형식 오류 등)
    AlreadyOwnedDifferentCredential = 603,  ///< 드라이브가 이미 소유 상태이며 SID 비번이 호출자의 것과 다름 (멱등성 take_ownership 실패)

    // ── 일반 에러 (900-999) ───────────────────────────
    NotImplemented        = 900,   ///< 아직 구현되지 않은 기능
    InvalidArgument       = 901,   ///< 유효하지 않은 인수
    InternalError         = 999,   ///< 내부 에러 (예상치 못한 상황)
};

/// @brief TCG SED std::error_category 구현
///
/// C++ 표준 라이브러리의 std::error_code 체계와 통합하기 위한 에러 카테고리이다.
/// ErrorCode를 사람이 읽을 수 있는 영문 메시지로 변환하는 기능을 제공한다.
class SedErrorCategory : public std::error_category {
public:
    /// @brief 에러 카테고리 이름을 반환한다
    /// @return "libsed" 문자열
    const char* name() const noexcept override { return "libsed"; }

    /// @brief 에러 코드에 해당하는 영문 메시지를 반환한다
    /// @param ev 에러 코드 정수값
    /// @return 에러를 설명하는 영문 문자열
    std::string message(int ev) const override {
        switch (static_cast<ErrorCode>(ev)) {
            case ErrorCode::Success:               return "Success";
            // Transport (100-199)
            case ErrorCode::TransportNotAvailable:  return "Transport not available";
            case ErrorCode::TransportOpenFailed:    return "Failed to open transport";
            case ErrorCode::TransportSendFailed:    return "IF-SEND failed";
            case ErrorCode::TransportRecvFailed:    return "IF-RECV failed";
            case ErrorCode::TransportTimeout:       return "Transport timeout";
            // Protocol (200-299)
            case ErrorCode::InvalidToken:           return "Invalid token";
            case ErrorCode::InvalidPacket:          return "Invalid packet";
            case ErrorCode::BufferTooSmall:         return "Buffer too small";
            case ErrorCode::BufferOverflow:         return "Buffer overflow";
            case ErrorCode::UnexpectedToken:        return "Unexpected token";
            case ErrorCode::MalformedResponse:      return "Malformed response";
            case ErrorCode::ProtocolError:          return "Protocol error";
            // Session (300-399)
            case ErrorCode::SessionNotStarted:      return "Session not started";
            case ErrorCode::SessionAlreadyActive:   return "Session already active";
            case ErrorCode::SessionClosed:          return "Session closed";
            case ErrorCode::SessionSyncFailed:      return "Session sync failed";
            case ErrorCode::NoSessionAvailable:     return "No session available";
            // Method (400-499)
            case ErrorCode::MethodNotAuthorized:    return "Method not authorized";
            case ErrorCode::MethodSpBusy:           return "SP busy";
            case ErrorCode::MethodSpFailed:         return "SP failed";
            case ErrorCode::MethodSpDisabled:       return "SP disabled";
            case ErrorCode::MethodSpFrozen:         return "SP frozen";
            case ErrorCode::MethodInvalidParam:     return "Invalid parameter";
            case ErrorCode::MethodTPerMalfunction:  return "TPer malfunction";
            case ErrorCode::MethodFailed:           return "Method failed";
            // Discovery (500-599)
            case ErrorCode::DiscoveryFailed:        return "Discovery failed";
            case ErrorCode::DiscoveryInvalidData:   return "Discovery invalid data";
            case ErrorCode::UnsupportedSsc:         return "Unsupported SSC";
            case ErrorCode::FeatureNotFound:        return "Feature not found";
            // Auth (600-699)
            case ErrorCode::AuthFailed:             return "Authentication failed";
            case ErrorCode::AuthLockedOut:          return "Authority locked out";
            case ErrorCode::InvalidCredential:      return "Invalid credential";
            case ErrorCode::AlreadyOwnedDifferentCredential:
                                                    return "Drive already owned with different SID password";
            // General (900-999)
            case ErrorCode::NotImplemented:         return "Not implemented";
            case ErrorCode::InvalidArgument:        return "Invalid argument";
            case ErrorCode::InternalError:          return "Internal error";
            default:                                return "Unknown error (code=" + std::to_string(ev) + ")";
        }
    }

    /// @brief 싱글톤 인스턴스를 반환한다
    /// @return SedErrorCategory의 정적 인스턴스 참조
    static const SedErrorCategory& instance() {
        static SedErrorCategory cat;
        return cat;
    }
};

/// @brief ErrorCode를 std::error_code로 변환하는 헬퍼 함수
/// @param e 변환할 ErrorCode
/// @return 대응하는 std::error_code
inline std::error_code make_error_code(ErrorCode e) {
    return {static_cast<int>(e), SedErrorCategory::instance()};
}

/// @brief 에러 코드를 감싸는 결과 타입
///
/// 함수의 성공/실패 여부를 나타내는 경량 래퍼이다.
/// 예외 대신 반환 값으로 에러를 처리하는 패턴에 사용된다.
class Result {
public:
    /// @brief 성공 상태의 Result를 기본 생성한다
    Result() : code_(ErrorCode::Success) {}

    /// @brief 지정된 에러 코드로 Result를 생성한다
    /// @param code 에러 코드
    Result(ErrorCode code) : code_(code) {}

    /// @brief 성공 여부를 확인한다
    /// @return 에러 코드가 Success이면 true
    bool ok() const { return code_ == ErrorCode::Success; }

    /// @brief 실패 여부를 확인한다
    /// @return 에러 코드가 Success가 아니면 true
    bool failed() const { return code_ != ErrorCode::Success; }

    /// @brief bool로의 명시적 변환 (if문에서 사용 가능)
    /// @return ok()와 동일
    explicit operator bool() const { return ok(); }

    /// @brief 내부 에러 코드를 반환한다
    /// @return ErrorCode 열거형 값
    ErrorCode code() const { return code_; }

    /// @brief 에러 코드에 해당하는 영문 메시지를 반환한다
    /// @return 에러 설명 문자열
    std::string message() const { return SedErrorCategory::instance().message(static_cast<int>(code_)); }

    /// @brief 성공 상태의 Result를 생성하는 정적 팩토리 메서드
    /// @return ErrorCode::Success를 포함하는 Result
    static Result success() { return Result(ErrorCode::Success); }

private:
    ErrorCode code_;
};

/// @brief 치명적 실패 시 사용되는 예외 클래스
///
/// 복구 불가능한 에러 상황에서 throw된다.
/// ErrorCode와 선택적 상세 메시지를 함께 전달할 수 있다.
class SedException : public std::runtime_error {
public:
    /// @brief 에러 코드만으로 예외를 생성한다
    /// @param code 에러 코드 (자동으로 영문 메시지로 변환됨)
    explicit SedException(ErrorCode code)
        : std::runtime_error(SedErrorCategory::instance().message(static_cast<int>(code)))
        , code_(code) {}

    /// @brief 에러 코드와 상세 메시지로 예외를 생성한다
    /// @param code 에러 코드
    /// @param detail 추가 상세 설명 문자열
    SedException(ErrorCode code, const std::string& detail)
        : std::runtime_error(SedErrorCategory::instance().message(static_cast<int>(code)) + ": " + detail)
        , code_(code) {}

    /// @brief 예외에 포함된 에러 코드를 반환한다
    /// @return ErrorCode 열거형 값
    ErrorCode code() const { return code_; }

private:
    ErrorCode code_;
};

} // namespace libsed

/// @brief ErrorCode를 std::error_code 호환 타입으로 등록
template<>
struct std::is_error_code_enum<libsed::ErrorCode> : std::true_type {};
