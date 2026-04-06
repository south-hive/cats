#pragma once

/// @file eval_types.h
/// @brief EvalApi에서 사용되는 구조체/타입 정의.

#include "libsed/core/types.h"
#include "libsed/core/error.h"
#include "libsed/core/uid.h"
#include "libsed/method/method_result.h"
#include "libsed/codec/token_encoder.h"

#include <string>
#include <vector>
#include <utility>

namespace libsed {
namespace eval {

/// @brief 토큰 수준의 전체 접근이 가능한 원시 메서드 결과 구조체
struct RawResult {
    MethodResult   methodResult;     ///< 파싱된 메서드 응답
    Bytes          rawSendPayload;   ///< 와이어에 전송된 정확한 바이트
    Bytes          rawRecvPayload;   ///< 와이어에서 수신된 정확한 바이트
    ErrorCode      transportError = ErrorCode::Success;  ///< 전송 계층 오류 코드
    ErrorCode      protocolError  = ErrorCode::Success;  ///< 프로토콜 계층 오류 코드
};

/// @brief StartSession 요청 파라미터 (필수(REQ) + 선택(OPT) 필드)
struct StartSessionParams {
    uint32_t hostSessionId          = 0;  ///< 호스트 세션 ID (0이면 자동 생성)
    uint64_t spUid                  = 0;  ///< 열려는 SP의 UID
    bool     write                  = false;  ///< 쓰기 세션 여부

    // StartSession 선택(OPT) 필드
    Bytes    hostChallenge;                ///< 인증을 위한 호스트 챌린지
    uint64_t hostExchangeAuthority  = 0;   ///< Authority UID (SID, Admin1 등)
    Bytes    hostExchangeCert;             ///< 호스트 인증서
    uint64_t hostSigningAuthority   = 0;   ///< 서명 Authority
};

/// @brief SyncSession 응답 상세 정보 (필수(REQ) + 선택(OPT) 필드)
struct SyncSessionResult {
    uint32_t tperSessionNumber      = 0;  ///< TPer 세션 번호
    uint32_t hostSessionNumber      = 0;  ///< 호스트 세션 번호
    uint64_t spUid                  = 0;  ///< SP UID
    uint16_t spSessionTimeout       = 0;  ///< SP 세션 타임아웃 (초)

    // SyncSession 선택(OPT) 필드
    Bytes    spChallenge;                  ///< SP 챌린지
    Bytes    spExchangeCert;               ///< SP 교환 인증서
    Bytes    spSigningCert;                ///< SP 서명 인증서
    uint64_t transTimeout           = 0;   ///< 트랜잭션 타임아웃
    uint64_t initialCredits         = 0;   ///< 초기 크레딧
    Bytes    signedHash;                   ///< 서명된 해시

    RawResult raw;                         ///< 원시 결과 데이터
};

/// @brief StartSession / SyncSession 결합 결과 (하위 호환용)
struct StartSessionResult {
    uint32_t  hostSessionNumber  = 0;  ///< 호스트 세션 번호
    uint32_t  tperSessionNumber  = 0;  ///< TPer 세션 번호
    uint16_t  spSessionTimeout   = 0;  ///< SP 세션 타임아웃 (초)
    RawResult raw;                     ///< 원시 결과 데이터
};

/// @brief Properties 교환 응답 상세 정보
struct PropertiesResult {
    uint32_t tperMaxComPacketSize = 0;  ///< TPer 최대 ComPacket 크기
    uint32_t tperMaxPacketSize    = 0;  ///< TPer 최대 Packet 크기
    uint32_t tperMaxIndTokenSize  = 0;  ///< TPer 최대 개별 토큰 크기
    uint32_t tperMaxAggTokenSize  = 0;  ///< TPer 최대 집합 토큰 크기
    uint32_t tperMaxMethods       = 0;  ///< TPer 최대 메서드 수
    uint32_t tperMaxSubPackets    = 0;  ///< TPer 최대 서브패킷 수
    RawResult raw;                      ///< 원시 결과 데이터
};

/// @brief Get/Set 연산 결과 (컬럼 값 포함)
struct TableResult {
    std::vector<std::pair<uint32_t, Token>> columns;  ///< 컬럼 ID와 토큰 값의 쌍 목록
    RawResult raw;                                     ///< 원시 결과 데이터
};

/// @brief ACE (접근 제어 요소) 정보 구조체
struct AceInfo {
    Uid       aceUid;                  ///< ACE의 UID
    Bytes     booleanExpr;             ///< 불리언 표현식 (원시 바이트)
    std::vector<Uid> authorities;      ///< 연관된 Authority 목록
};

// ════════════════════════════════════════════════════════
//  TC Library 유틸리티 구조체
//  (getTcgOption, GetClass0SecurityStatus 등에 대응)
// ════════════════════════════════════════════════════════

/// @brief TCG 드라이브 옵션/기능 요약 정보 (getTcgOption에 대응)
struct TcgOption {
    SscType  sscType         = SscType::Unknown;   ///< SSC 유형 (Opal, Enterprise 등)
    uint16_t baseComId       = 0;                  ///< 기본 ComID
    uint16_t numComIds       = 0;                  ///< ComID 개수
    bool     lockingSupported = false;             ///< 잠금 기능 지원 여부
    bool     lockingEnabled  = false;              ///< 잠금 기능 활성화 여부
    bool     locked          = false;              ///< 현재 잠금 상태
    bool     mbrSupported    = false;              ///< MBR 섀도잉 지원 여부
    bool     mbrEnabled      = false;              ///< MBR 활성화 여부
    bool     mbrDone         = false;              ///< MBR Done 플래그
    bool     mediaEncryption = false;              ///< 미디어 암호화 지원 여부
    uint16_t maxLockingAdmins = 0;                 ///< 최대 잠금 관리자 수
    uint16_t maxLockingUsers  = 0;                 ///< 최대 잠금 사용자 수
    uint8_t  initialPinIndicator  = 0;             ///< 초기 PIN 표시자
    uint8_t  revertedPinIndicator = 0;             ///< Revert 후 PIN 표시자
};

/// @brief Class 0 보안 상태 (GetClass0SecurityStatus에 대응)
struct SecurityStatus {
    bool     tperPresent     = false;              ///< TPer 기능 존재 여부
    bool     lockingPresent  = false;              ///< Locking 기능 존재 여부
    bool     geometryPresent = false;              ///< Geometry 기능 존재 여부
    bool     opalV1Present   = false;              ///< Opal V1 SSC 존재 여부
    bool     opalV2Present   = false;              ///< Opal V2 SSC 존재 여부
    bool     enterprisePresent = false;            ///< Enterprise SSC 존재 여부
    bool     pyriteV1Present = false;              ///< Pyrite V1 SSC 존재 여부
    bool     pyriteV2Present = false;              ///< Pyrite V2 SSC 존재 여부
    SscType  primarySsc      = SscType::Unknown;   ///< 주 SSC 유형
};

/// @brief 보안 기능별 상세 정보 (GetSecurityFeatureType에 대응)
struct SecurityFeatureInfo {
    uint16_t featureCode     = 0;                  ///< 기능 코드
    std::string featureName;                       ///< 기능 이름
    uint8_t  version         = 0;                  ///< 기능 버전
    uint16_t dataLength      = 0;                  ///< 데이터 길이
    Bytes    rawFeatureData;                       ///< 원시 기능 데이터
    // 디코딩된 필드 (기능별로 상이)
    uint16_t baseComId       = 0;                  ///< 기본 ComID
    uint16_t numComIds       = 0;                  ///< ComID 개수
    bool     rangeCrossing   = false;              ///< 범위 교차 지원 여부
    // Locking 관련 필드
    bool     lockingSupported = false;             ///< 잠금 기능 지원 여부
    bool     lockingEnabled  = false;              ///< 잠금 기능 활성화 여부
    bool     locked          = false;              ///< 현재 잠금 상태
    bool     mbrEnabled      = false;              ///< MBR 활성화 여부
    bool     mbrDone         = false;              ///< MBR Done 플래그
};

/// @brief 잠금 범위 정보 (GetLockingInfo에 대응)
struct LockingInfo {
    uint32_t rangeId          = 0;                 ///< 잠금 범위 ID
    uint64_t rangeStart       = 0;                 ///< 범위 시작 LBA
    uint64_t rangeLength      = 0;                 ///< 범위 길이 (섹터 수)
    bool     readLockEnabled  = false;             ///< 읽기 잠금 활성화 여부
    bool     writeLockEnabled = false;             ///< 쓰기 잠금 활성화 여부
    bool     readLocked       = false;             ///< 현재 읽기 잠금 상태
    bool     writeLocked      = false;             ///< 현재 쓰기 잠금 상태
    uint64_t activeKey        = 0;                 ///< 활성 키 UID
};

/// @brief 바이트 테이블 (DataStore) 속성 정보 (GetByteTableInfo에 대응)
struct ByteTableInfo {
    uint64_t tableUid         = 0;                 ///< 테이블 UID
    uint32_t maxSize          = 0;                 ///< 최대 크기 (바이트)
    uint32_t usedSize         = 0;                 ///< 사용 중인 크기 (바이트)
};

/// @brief TcgWrite/Read/Compare 연산 결과
struct DataOpResult {
    Bytes    data;                                 ///< 읽기/쓰기된 데이터
    bool     compareMatch     = false;             ///< 비교 일치 여부
    RawResult raw;                                 ///< 원시 결과 데이터
};

} // namespace eval
} // namespace libsed
