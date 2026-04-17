#pragma once

#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <vector>
#include <string>
#include <optional>
#include <variant>
#include <array>
#include <memory>
#include <functional>
#include <unordered_map>

namespace libsed {

/// @brief 원시 바이트 버퍼 (std::vector<uint8_t> 별칭)
using Bytes = std::vector<uint8_t>;

/// @brief 연속 바이트에 대한 읽기 전용 비소유 뷰 (C++17 std::span 대체)
///
/// 데이터를 복사하지 않고 기존 바이트 배열을 참조하는 경량 래퍼이다.
/// 참조하는 데이터의 수명이 ByteSpan보다 길어야 한다.
class ByteSpan {
public:
    /// @brief 빈 ByteSpan을 기본 생성한다
    constexpr ByteSpan() noexcept : data_(nullptr), size_(0) {}

    /// @brief 원시 포인터와 크기로 ByteSpan을 생성한다
    /// @param data 바이트 데이터의 시작 포인터
    /// @param size 바이트 수
    constexpr ByteSpan(const uint8_t* data, size_t size) noexcept : data_(data), size_(size) {}

    /// @brief Bytes 벡터로부터 ByteSpan을 생성한다
    /// @param v 참조할 바이트 벡터
    ByteSpan(const Bytes& v) noexcept : data_(v.data()), size_(v.size()) {}

    /// @brief 내부 데이터 포인터를 반환한다
    /// @return 바이트 데이터의 const 포인터
    constexpr const uint8_t* data() const noexcept { return data_; }

    /// @brief 바이트 수를 반환한다
    /// @return 뷰가 참조하는 바이트 수
    constexpr size_t size() const noexcept { return size_; }

    /// @brief 뷰가 비어 있는지 확인한다
    /// @return 크기가 0이면 true
    constexpr bool empty() const noexcept { return size_ == 0; }

    /// @brief 범위 기반 for 루프를 위한 시작 반복자를 반환한다
    /// @return 첫 번째 바이트에 대한 const 포인터
    constexpr const uint8_t* begin() const noexcept { return data_; }

    /// @brief 범위 기반 for 루프를 위한 끝 반복자를 반환한다
    /// @return 마지막 바이트 다음 위치에 대한 const 포인터
    constexpr const uint8_t* end()   const noexcept { return data_ + size_; }

    /// @brief 인덱스로 바이트에 접근한다 (경계 검사 없음)
    /// @param i 바이트 인덱스
    /// @return 해당 위치의 바이트 참조
    constexpr const uint8_t& operator[](size_t i) const { return data_[i]; }

private:
    const uint8_t* data_;
    size_t size_;
};

/// @brief 연속 바이트에 대한 쓰기 가능 비소유 뷰
///
/// ByteSpan과 동일하지만 참조하는 데이터를 수정할 수 있다.
class MutableByteSpan {
public:
    /// @brief 빈 MutableByteSpan을 기본 생성한다
    constexpr MutableByteSpan() noexcept : data_(nullptr), size_(0) {}

    /// @brief 원시 포인터와 크기로 MutableByteSpan을 생성한다
    /// @param data 바이트 데이터의 시작 포인터
    /// @param size 바이트 수
    constexpr MutableByteSpan(uint8_t* data, size_t size) noexcept : data_(data), size_(size) {}

    /// @brief Bytes 벡터로부터 MutableByteSpan을 생성한다
    /// @param v 참조할 바이트 벡터 (비const)
    MutableByteSpan(Bytes& v) noexcept : data_(v.data()), size_(v.size()) {}

    /// @brief 내부 데이터 포인터를 반환한다
    /// @return 바이트 데이터의 수정 가능 포인터
    constexpr uint8_t* data() const noexcept { return data_; }

    /// @brief 바이트 수를 반환한다
    /// @return 뷰가 참조하는 바이트 수
    constexpr size_t size() const noexcept { return size_; }

    /// @brief 뷰가 비어 있는지 확인한다
    /// @return 크기가 0이면 true
    constexpr bool empty() const noexcept { return size_ == 0; }

    /// @brief 범위 기반 for 루프를 위한 시작 반복자를 반환한다
    /// @return 첫 번째 바이트에 대한 수정 가능 포인터
    constexpr uint8_t* begin() const noexcept { return data_; }

    /// @brief 범위 기반 for 루프를 위한 끝 반복자를 반환한다
    /// @return 마지막 바이트 다음 위치에 대한 수정 가능 포인터
    constexpr uint8_t* end()   const noexcept { return data_ + size_; }

    /// @brief 인덱스로 바이트에 접근한다 (경계 검사 없음)
    /// @param i 바이트 인덱스
    /// @return 해당 위치의 바이트에 대한 수정 가능 참조
    constexpr uint8_t& operator[](size_t i) const { return data_[i]; }

private:
    uint8_t* data_;
    size_t size_;
};

/// @brief TCG SED 전체에서 사용되는 8바이트 고유 식별자 (UID)
///
/// SP, Authority, 테이블, 행 등 모든 TCG 객체를 식별하는 데 사용된다.
/// 빅엔디안 바이트 순서로 저장되며, uint64_t와 상호 변환이 가능하다.
struct Uid {
    std::array<uint8_t, 8> bytes{};  ///< 빅엔디안 순서의 8바이트 UID 데이터

    /// @brief 모든 바이트가 0인 null UID를 기본 생성한다
    Uid() = default;

    /// @brief 64비트 정수 값으로 UID를 생성한다 (implicit).
    /// @param val 빅엔디안으로 변환될 64비트 정수
    ///
    /// `uid::*` 상수들(SP_ADMIN, AUTH_SID, CPIN_SID 등)이 모두 uint64_t로
    /// 정의되어 있어, 이 변환을 implicit으로 두어 호출부에서 다음처럼 자연스럽게
    /// 쓸 수 있게 한다:
    /// @code
    ///   drive.login(uid::SP_ADMIN, "pw", uid::AUTH_SID);   // 명시적 Uid() 불필요
    ///   session.setPin(uid::CPIN_SID, "new-pw");
    /// @endcode
    /// Bytes 오버로드는 여전히 explicit (Bytes↔uint64_t 혼동 방지).
    Uid(uint64_t val) {
        for (int i = 7; i >= 0; --i) {
            bytes[i] = static_cast<uint8_t>(val & 0xFF);
            val >>= 8;
        }
    }

    /// @brief 이니셜라이저 리스트로 UID를 생성한다
    /// @param init 최대 8개의 바이트 값 리스트
    Uid(std::initializer_list<uint8_t> init) {
        size_t i = 0;
        for (auto b : init) {
            if (i < 8) bytes[i++] = b;
        }
    }

    /// @brief 바이트 벡터로 UID를 생성한다
    /// @param data 최대 8바이트까지 복사할 바이트 벡터
    explicit Uid(const Bytes& data) {
        size_t len = std::min(data.size(), size_t(8));
        std::copy(data.begin(), data.begin() + len, bytes.begin());
    }

    /// @brief UID를 64비트 정수로 변환한다
    /// @return 빅엔디안 바이트를 합친 uint64_t 값
    uint64_t toUint64() const {
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val = (val << 8) | bytes[i];
        }
        return val;
    }

    /// @brief 두 UID가 같은지 비교한다
    bool operator==(const Uid& other) const { return bytes == other.bytes; }

    /// @brief 두 UID가 다른지 비교한다
    bool operator!=(const Uid& other) const { return bytes != other.bytes; }

    /// @brief 사전순 비교 (정렬용)
    bool operator<(const Uid& other) const { return bytes < other.bytes; }

    /// @brief UID가 모두 0인 null 상태인지 확인한다
    /// @return 모든 바이트가 0이면 true
    bool isNull() const {
        for (auto b : bytes) if (b != 0) return false;
        return true;
    }
};

/// @brief Uid를 unordered_map에서 사용하기 위한 해시 함수 객체
struct UidHash {
    /// @brief UID의 해시 값을 계산한다
    /// @param uid 해시할 UID
    /// @return std::hash<uint64_t>를 사용한 해시 값
    size_t operator()(const Uid& uid) const {
        return std::hash<uint64_t>{}(uid.toUint64());
    }
};

/// @brief 일부 컨텍스트에서 사용되는 4바이트 Half-UID
///
/// 세션 매니저 호출 등 특정 프로토콜 상황에서 사용되는 축약형 UID이다.
struct HalfUid {
    std::array<uint8_t, 4> bytes{};  ///< 빅엔디안 순서의 4바이트 Half-UID 데이터

    /// @brief 32비트 정수 값으로 Half-UID를 생성한다
    /// @param val 빅엔디안으로 변환될 32비트 정수
    explicit HalfUid(uint32_t val) {
        for (int i = 3; i >= 0; --i) {
            bytes[i] = static_cast<uint8_t>(val & 0xFF);
            val >>= 8;
        }
    }
};

/// @brief 지원되는 SSC(Security Subsystem Class) 타입
///
/// 드라이브가 지원하는 TCG SSC 프로파일을 나타낸다.
/// Level 0 Discovery를 통해 탐지된다.
enum class SscType : uint8_t {
    Unknown     = 0,  ///< 알 수 없는 SSC 타입
    Enterprise  = 1,  ///< Enterprise SSC (데이터센터용, BandMaster 기반)
    Opal10      = 2,  ///< Opal 1.0 SSC (초기 클라이언트 SED 표준)
    Opal20      = 3,  ///< Opal 2.0 SSC (현재 클라이언트 SED 주류 표준)
    Pyrite10    = 4,  ///< Pyrite 1.0 SSC (암호화 없는 액세스 제어 전용)
    Pyrite20    = 5,  ///< Pyrite 2.0 SSC (Pyrite 1.0의 개정판)
};

/// @brief 전송 인터페이스 타입
///
/// TCG 명령을 드라이브에 전달하는 물리적/논리적 인터페이스를 나타낸다.
enum class TransportType : uint8_t {
    Unknown = 0,  ///< 알 수 없는 전송 타입
    ATA     = 1,  ///< ATA (Trusted Send/Receive via ATA 명령)
    NVMe    = 2,  ///< NVMe (Security Send/Receive via NVMe Admin 명령)
    SCSI    = 3,  ///< SCSI (Security Protocol In/Out via SCSI 명령)
};

/// @brief TCG Core 스펙 메서드 상태 코드
///
/// TCG 메서드 호출의 결과로 TPer가 반환하는 상태 코드이다.
/// TCG Core Specification의 Table 166에 정의되어 있다.
enum class MethodStatus : uint8_t {
    Success             = 0x00,  ///< 메서드가 성공적으로 완료됨
    NotAuthorized       = 0x01,  ///< 현재 인증 상태로는 해당 작업이 허용되지 않음
    Obsolete            = 0x02,  ///< 더 이상 사용되지 않는 상태 코드 (예약됨)
    SpBusy              = 0x03,  ///< SP가 다른 세션을 처리 중이어서 사용 불가
    SpFailed            = 0x04,  ///< SP 내부 오류 발생
    SpDisabled          = 0x05,  ///< SP가 비활성화 상태
    SpFrozen            = 0x06,  ///< SP가 동결 상태 (리셋 필요)
    NoSessionsAvailable = 0x07,  ///< 사용 가능한 세션 슬롯이 없음
    UniquenessConflict  = 0x08,  ///< 고유성 제약 위반 (중복 값)
    InsufficientSpace   = 0x09,  ///< 저장 공간 부족
    InsufficientRows    = 0x0A,  ///< 테이블에 사용 가능한 행이 부족
    InvalidParameter    = 0x0C,  ///< 잘못된 파라미터 전달
    Obsolete2           = 0x0D,  ///< 더 이상 사용되지 않는 상태 코드 (예약됨)
    Obsolete3           = 0x0E,  ///< 더 이상 사용되지 않는 상태 코드 (예약됨)
    TPerMalfunction     = 0x0F,  ///< TPer 하드웨어/펌웨어 오작동
    TransactionFailure  = 0x10,  ///< 트랜잭션 처리 실패
    ResponseOverflow    = 0x11,  ///< 응답 데이터가 버퍼 크기를 초과
    AuthorityLockedOut  = 0x12,  ///< 인증 시도 초과로 Authority 잠김
    Fail                = 0x3F,  ///< 일반적인 실패 (구체적 원인 미분류)
};

/// @brief 테이블 읽기/쓰기용 셀 블록 범위 지정자
///
/// Get/Set 메서드에서 읽거나 쓸 열과 행의 범위를 지정한다.
/// 각 필드가 nullopt이면 해당 제약 조건을 적용하지 않는다.
struct CellBlock {
    std::optional<uint32_t> startColumn;  ///< 시작 열 번호 (포함)
    std::optional<uint32_t> endColumn;    ///< 종료 열 번호 (포함)
    std::optional<uint32_t> startRow;     ///< 시작 행 번호 (포함)
    std::optional<uint32_t> endRow;       ///< 종료 행 번호 (포함)
};

/// @brief Locking Range 상태 정보
///
/// Locking 테이블에서 읽어온 개별 잠금 범위의 구성 및 상태를 나타낸다.
struct LockingRangeInfo {
    uint32_t rangeId = 0;             ///< 잠금 범위 식별자 (0=GlobalRange)
    uint64_t rangeStart = 0;          ///< 범위 시작 LBA (Logical Block Address)
    uint64_t rangeLength = 0;         ///< 범위 길이 (LBA 단위)
    bool readLockEnabled = false;     ///< 읽기 잠금 활성화 여부
    bool writeLockEnabled = false;    ///< 쓰기 잠금 활성화 여부
    bool readLocked = false;          ///< 현재 읽기 잠금 상태
    bool writeLocked = false;         ///< 현재 쓰기 잠금 상태
};

/// @brief Level 0 Discovery 요약 정보
///
/// Level 0 Discovery 응답에서 파싱한 드라이브의 주요 기능 정보를 담는다.
/// TPer 기능, Locking 기능, SSC 타입, 통신 파라미터 등을 포함한다.
struct DiscoveryInfo {
    uint32_t majorVersion = 0;            ///< Level 0 Discovery 메이저 버전
    uint32_t minorVersion = 0;            ///< Level 0 Discovery 마이너 버전
    SscType  primarySsc = SscType::Unknown;  ///< 기본 SSC 타입 (Opal/Enterprise/Pyrite 등)
    bool     tperPresent = false;         ///< TPer 기능 디스크립터 존재 여부
    bool     lockingPresent = false;      ///< Locking 기능 디스크립터 존재 여부
    bool     lockingEnabled = false;      ///< Locking 기능 활성화 여부
    bool     locked = false;              ///< 현재 잠금 상태 여부
    bool     mbrEnabled = false;          ///< MBR 섀도잉 활성화 여부
    bool     mbrDone = false;             ///< MBR Done 플래그 상태
    uint16_t baseComId = 0;               ///< 기본 ComID (통신 식별자)
    uint16_t numComIds = 0;               ///< 사용 가능한 ComID 수
    uint32_t maxResponseSize = 0;         ///< 최대 응답 크기 (바이트)
    uint32_t maxPacketSize = 0;           ///< 최대 패킷 크기 (바이트)
};

} // namespace libsed
