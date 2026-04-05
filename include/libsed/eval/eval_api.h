#pragma once

/// @file eval_api.h
/// @brief TCG SED 평가 플랫폼을 위한 단계별(Flat) API.
///
/// 고수준 API (OpalAdmin, OpalLocking 등)가 여러 프로토콜 단계를 하나의 호출로
/// 묶는 것과 달리, EvalApi는 모든 개별 단계를 독립적인 함수로 노출합니다.
/// 이를 통해 다음이 가능합니다:
///
///   - 각 프로토콜 단계를 독립적으로 테스트
///   - 단계 사이에 결함(Fault) 주입
///   - 중간 상태 검증 (예: StartSession 이후 Auth 이전 상태)
///   - 의도적으로 잘못된 형식이나 순서가 틀린 명령 전송
///   - 표준 흐름에서 다루지 않는 커스텀 테스트 시퀀스 구성
///
/// 모든 함수는 호출자가 관리하는 명시적 Session (또는 Transport)에 대해
/// 동작합니다. 암묵적으로 열리거나 닫히는 것은 없습니다.
///
/// 사용 패턴:
/// @code
///   EvalApi api;
///   auto transport = TransportFactory::createNvme("/dev/nvme0");
///
///   // 단계 1: Level 0 Discovery
///   DiscoveryInfo info;
///   api.discovery0(transport, info);
///
///   // 단계 2: Properties 교환
///   EvalApi::PropertiesResult props;
///   api.exchangeProperties(transport, comId, props);
///
///   // 단계 3: StartSession (원시 SyncSession 응답 획득)
///   Session session(transport, comId);
///   EvalApi::StartSessionResult ssr;
///   api.startSession(session, uid::SP_ADMIN, true, uid::AUTH_SID, credential, ssr);
///
///   // 단계 4: 인증 (세션 시작과 분리)
///   api.authenticate(session, uid::AUTH_ADMIN1, password);
///
///   // 단계 5: C_PIN 설정
///   api.setCPin(session, uid::CPIN_SID, newPin);
///
///   // ... 각 단계를 독립적으로 테스트 가능
/// @endcode

#include "libsed/core/types.h"
#include "libsed/core/error.h"
#include "libsed/core/uid.h"
#include "libsed/transport/i_transport.h"
#include "libsed/session/session.h"
#include "libsed/discovery/discovery.h"
#include "libsed/discovery/feature_descriptor.h"
#include "libsed/method/method_result.h"
#include "libsed/codec/token_encoder.h"
#include "libsed/packet/packet_builder.h"
#include "libsed/transport/i_nvme_device.h"

#include <memory>
#include <string>
#include <vector>
#include <functional>

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

// ════════════════════════════════════════════════════════
//  단계별 평가용 플랫(Flat) API
// ════════════════════════════════════════════════════════

/// @brief TCG SED 프로토콜의 모든 개별 단계를 독립 함수로 노출하는 평가용 API 클래스.
///
/// EvalApi는 상태를 가지지 않으며(stateless) 스레드 안전합니다.
/// 모든 결과에는 rawSendPayload/rawRecvPayload가 포함되어 와이어 수준의 검사가 가능합니다.
class EvalApi {
public:
    EvalApi() = default;

    // ── Discovery ────────────────────────────────────

    /// @brief Level 0 Discovery 수행 (Security Protocol 0x01, ComID 0x0001)
    /// @param transport 전송 인터페이스
    /// @param info Discovery 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result discovery0(std::shared_ptr<ITransport> transport,
                      DiscoveryInfo& info);

    /// @brief Level 0 Discovery 수행 후 원시 응답 바이트 반환
    /// @param transport 전송 인터페이스
    /// @param rawResponse 원시 응답 데이터가 저장될 버퍼
    /// @return 성공 또는 오류 코드
    Result discovery0Raw(std::shared_ptr<ITransport> transport,
                         Bytes& rawResponse);

    /// @brief 커스텀 프로토콜 ID/ComID로 Level 0 Discovery 수행 (네거티브 테스트용)
    /// @param transport 전송 인터페이스
    /// @param protocolId 사용할 보안 프로토콜 ID
    /// @param comId 사용할 ComID
    /// @param rawResponse 원시 응답 데이터가 저장될 버퍼
    /// @return 성공 또는 오류 코드
    Result discovery0Custom(std::shared_ptr<ITransport> transport,
                            uint8_t protocolId, uint16_t comId,
                            Bytes& rawResponse);

    // ── Properties ───────────────────────────────────

    /// @brief TPer와 Properties 교환 수행 (SM 수준, 세션 불필요)
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param result Properties 교환 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result exchangeProperties(std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              PropertiesResult& result);

    /// @brief 커스텀 호스트 값으로 Properties 교환 수행
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param maxComPacketSize 호스트 최대 ComPacket 크기
    /// @param maxPacketSize 호스트 최대 Packet 크기
    /// @param maxIndTokenSize 호스트 최대 개별 토큰 크기
    /// @param result Properties 교환 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result exchangePropertiesCustom(std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    uint32_t maxComPacketSize,
                                    uint32_t maxPacketSize,
                                    uint32_t maxIndTokenSize,
                                    PropertiesResult& result);

    // ── 세션 수명 주기 (결합) ─────────────────────────

    /// @brief StartSession + SyncSession을 한 번의 호출로 수행
    /// @param session 세션 객체
    /// @param spUid 열려는 SP의 UID
    /// @param write 쓰기 세션 여부
    /// @param result 세션 시작 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result startSession(Session& session,
                        uint64_t spUid,
                        bool write,
                        StartSessionResult& result);

    /// @brief 인라인 인증이 포함된 StartSession + SyncSession
    /// @param session 세션 객체
    /// @param spUid 열려는 SP의 UID
    /// @param write 쓰기 세션 여부
    /// @param authorityUid 인증 Authority UID (SID, Admin1 등)
    /// @param credential 인증 자격 증명 (패스워드 바이트)
    /// @param result 세션 시작 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result startSessionWithAuth(Session& session,
                                uint64_t spUid,
                                bool write,
                                uint64_t authorityUid,
                                const Bytes& credential,
                                StartSessionResult& result);

    /// @brief 세션 종료
    /// @param session 종료할 세션 객체
    /// @return 성공 또는 오류 코드
    Result closeSession(Session& session);

    // ── 세션 수명 주기 (분리된 REQ/OPT) ────────────────

    /// @brief StartSession만 구성하여 전송 (REQ + OPT 필드 사용)
    /// @details SyncSession 응답을 기다리지 않습니다.
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param params StartSession 요청 파라미터
    /// @param rawSentPayload 전송된 원시 페이로드가 저장될 버퍼
    /// @return 성공 또는 오류 코드
    Result sendStartSession(std::shared_ptr<ITransport> transport,
                            uint16_t comId,
                            const StartSessionParams& params,
                            Bytes& rawSentPayload);

    /// @brief SyncSession 응답 수신 및 파싱
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param result SyncSession 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result recvSyncSession(std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           SyncSessionResult& result);

    /// @brief 전체 파라미터 제어가 가능한 StartSession 전송 + SyncSession 수신
    /// @param session 세션 객체
    /// @param params StartSession 요청 파라미터
    /// @param result SyncSession 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result startSyncSession(Session& session,
                            const StartSessionParams& params,
                            SyncSessionResult& result);

    // ── 인증 ────────────────────────────────────────

    /// @brief 바이트 자격 증명으로 Authority 인증 수행
    /// @param session 활성 세션 객체
    /// @param authorityUid 인증할 Authority UID
    /// @param credential 자격 증명 (바이트 배열)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result authenticate(Session& session,
                        uint64_t authorityUid,
                        const Bytes& credential,
                        RawResult& result);

    /// @brief 문자열 패스워드로 Authority 인증 수행
    /// @param session 활성 세션 객체
    /// @param authorityUid 인증할 Authority UID
    /// @param password 패스워드 문자열
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result authenticate(Session& session,
                        uint64_t authorityUid,
                        const std::string& password,
                        RawResult& result);

    // ── 테이블 Get/Set (범용) ──────────────────────────

    /// @brief 테이블에서 지정된 컬럼 범위의 값을 읽기
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param startCol 시작 컬럼 번호
    /// @param endCol 종료 컬럼 번호
    /// @param result 테이블 읽기 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableGet(Session& session,
                    uint64_t objectUid,
                    uint32_t startCol, uint32_t endCol,
                    TableResult& result);

    /// @brief 테이블에서 모든 컬럼의 값을 읽기
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param result 테이블 읽기 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableGetAll(Session& session,
                       uint64_t objectUid,
                       TableResult& result);

    /// @brief 테이블에 여러 컬럼 값을 설정 (토큰 기반)
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param columns 설정할 컬럼 ID와 토큰 값의 쌍 목록
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableSet(Session& session,
                    uint64_t objectUid,
                    const std::vector<std::pair<uint32_t, Token>>& columns,
                    RawResult& result);

    /// @brief 테이블의 단일 컬럼에 uint 값 설정
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param column 대상 컬럼 번호
    /// @param value 설정할 uint64 값
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableSetUint(Session& session,
                        uint64_t objectUid,
                        uint32_t column, uint64_t value,
                        RawResult& result);

    /// @brief 테이블의 단일 컬럼에 bool 값 설정
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param column 대상 컬럼 번호
    /// @param value 설정할 bool 값
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableSetBool(Session& session,
                        uint64_t objectUid,
                        uint32_t column, bool value,
                        RawResult& result);

    /// @brief 테이블의 단일 컬럼에 바이트 배열 값 설정
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param column 대상 컬럼 번호
    /// @param value 설정할 바이트 배열
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableSetBytes(Session& session,
                         uint64_t objectUid,
                         uint32_t column, const Bytes& value,
                         RawResult& result);

    // ── C_PIN 연산 ──────────────────────────────────

    /// @brief C_PIN 테이블에서 PIN 값 읽기
    /// @param session 활성 세션 객체
    /// @param cpinUid C_PIN 객체 UID
    /// @param pin 읽어온 PIN 값이 저장될 버퍼
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getCPin(Session& session,
                   uint64_t cpinUid,
                   Bytes& pin,
                   RawResult& result);

    /// @brief C_PIN 테이블에 새 PIN 설정 (바이트 배열)
    /// @param session 활성 세션 객체
    /// @param cpinUid C_PIN 객체 UID
    /// @param newPin 설정할 새 PIN (바이트 배열)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setCPin(Session& session,
                   uint64_t cpinUid,
                   const Bytes& newPin,
                   RawResult& result);

    /// @brief C_PIN 테이블에 새 패스워드 설정 (문자열)
    /// @param session 활성 세션 객체
    /// @param cpinUid C_PIN 객체 UID
    /// @param newPassword 설정할 새 패스워드 문자열
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setCPin(Session& session,
                   uint64_t cpinUid,
                   const std::string& newPassword,
                   RawResult& result);

    // ── MBR 연산 ────────────────────────────────────

    /// @brief MBR 섀도잉 활성화/비활성화 설정
    /// @param session 활성 세션 객체
    /// @param enable 활성화 여부 (true=활성화, false=비활성화)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setMbrEnable(Session& session, bool enable, RawResult& result);

    /// @brief MBR Done 플래그 설정
    /// @param session 활성 세션 객체
    /// @param done Done 플래그 값 (true=완료, false=미완료)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setMbrDone(Session& session, bool done, RawResult& result);

    /// @brief MBR 테이블에 데이터 쓰기
    /// @param session 활성 세션 객체
    /// @param offset 쓰기 시작 오프셋 (바이트)
    /// @param data 쓸 데이터
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result writeMbrData(Session& session,
                        uint32_t offset, const Bytes& data,
                        RawResult& result);

    /// @brief MBR 테이블에서 데이터 읽기
    /// @param session 활성 세션 객체
    /// @param offset 읽기 시작 오프셋 (바이트)
    /// @param length 읽을 길이 (바이트)
    /// @param data 읽어온 데이터가 저장될 버퍼
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result readMbrData(Session& session,
                       uint32_t offset, uint32_t length,
                       Bytes& data, RawResult& result);

    /// @brief MBR Control 테이블의 NSID를 1로 설정 (일반적인 평가 단축 경로)
    /// @param session 활성 세션 객체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setMbrControlNsidOne(Session& session, RawResult& result);

    // ── 잠금 범위 연산 ──────────────────────────────

    /// @brief 잠금 범위의 시작/길이 및 잠금 활성화 설정
    /// @param session 활성 세션 객체
    /// @param rangeId 잠금 범위 ID
    /// @param rangeStart 범위 시작 LBA
    /// @param rangeLength 범위 길이 (섹터 수)
    /// @param readLockEnabled 읽기 잠금 활성화 여부
    /// @param writeLockEnabled 쓰기 잠금 활성화 여부
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setRange(Session& session,
                    uint32_t rangeId,
                    uint64_t rangeStart,
                    uint64_t rangeLength,
                    bool readLockEnabled,
                    bool writeLockEnabled,
                    RawResult& result);

    /// @brief 잠금 범위의 읽기/쓰기 잠금 상태 설정
    /// @param session 활성 세션 객체
    /// @param rangeId 잠금 범위 ID
    /// @param readLocked 읽기 잠금 여부
    /// @param writeLocked 쓰기 잠금 여부
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setRangeLock(Session& session,
                        uint32_t rangeId,
                        bool readLocked,
                        bool writeLocked,
                        RawResult& result);

    /// @brief 잠금 범위 정보 조회
    /// @param session 활성 세션 객체
    /// @param rangeId 조회할 잠금 범위 ID
    /// @param info 잠금 범위 정보가 저장될 구조체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getRangeInfo(Session& session,
                        uint32_t rangeId,
                        LockingRangeInfo& info,
                        RawResult& result);

    // ── Authority / ACE 연산 ────────────────────────

    /// @brief Authority 활성화/비활성화 설정
    /// @param session 활성 세션 객체
    /// @param authorityUid Authority UID
    /// @param enabled 활성화 여부 (true=활성화, false=비활성화)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setAuthorityEnabled(Session& session,
                               uint64_t authorityUid,
                               bool enabled,
                               RawResult& result);

    /// @brief ACE에 Authority 추가
    /// @param session 활성 세션 객체
    /// @param aceUid 대상 ACE UID
    /// @param authorityUid 추가할 Authority UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result addAuthorityToAce(Session& session,
                             uint64_t aceUid,
                             uint64_t authorityUid,
                             RawResult& result);

    /// @brief ACE 정보 조회
    /// @param session 활성 세션 객체
    /// @param aceUid 조회할 ACE UID
    /// @param info ACE 정보가 저장될 구조체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getAceInfo(Session& session,
                      uint64_t aceUid,
                      AceInfo& info,
                      RawResult& result);

    // ── SP 수명 주기 ────────────────────────────────

    /// @brief SP 활성화
    /// @param session 활성 세션 객체
    /// @param spUid 활성화할 SP UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result activate(Session& session, uint64_t spUid, RawResult& result);

    /// @brief SP Revert (SP를 공장 초기 상태로 복원)
    /// @param session 활성 세션 객체
    /// @param spUid Revert할 SP UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result revertSP(Session& session, uint64_t spUid, RawResult& result);

    // ── 암호화 / 키 연산 ────────────────────────────

    /// @brief 지정된 객체에 대해 새 암호화 키 생성
    /// @param session 활성 세션 객체
    /// @param objectUid 키를 생성할 대상 객체 UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result genKey(Session& session, uint64_t objectUid, RawResult& result);

    /// @brief TPer에서 난수 데이터 획득
    /// @param session 활성 세션 객체
    /// @param count 요청할 난수 바이트 수
    /// @param randomData 생성된 난수 데이터가 저장될 버퍼
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getRandom(Session& session, uint32_t count,
                     Bytes& randomData, RawResult& result);

    /// @brief 지정된 객체에 대해 암호화 소거 수행
    /// @param session 활성 세션 객체
    /// @param objectUid 소거할 대상 객체 UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result erase(Session& session, uint64_t objectUid, RawResult& result);

    // ── 원시 메서드 전송 ────────────────────────────

    /// @brief 원시 토큰으로 메서드 전송
    /// @param session 활성 세션 객체
    /// @param methodTokens 메서드 호출을 구성하는 원시 토큰 바이트
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result sendRawMethod(Session& session,
                         const Bytes& methodTokens,
                         RawResult& result);

    /// @brief 원시 ComPacket 데이터 전송 및 응답 수신
    /// @param session 활성 세션 객체
    /// @param comPacketData 전송할 원시 ComPacket 데이터
    /// @param rawResponse 원시 응답이 저장될 버퍼
    /// @return 성공 또는 오류 코드
    Result sendRawComPacket(Session& session,
                            const Bytes& comPacketData,
                            Bytes& rawResponse);

    /// @brief 메서드 호출 토큰 구성 (정적 유틸리티)
    /// @param invokingUid 호출 대상 객체 UID
    /// @param methodUid 메서드 UID
    /// @param paramTokens 메서드 파라미터 토큰 (기본값: 빈 바이트)
    /// @return 구성된 메서드 호출 토큰 바이트
    static Bytes buildMethodCall(uint64_t invokingUid,
                                 uint64_t methodUid,
                                 const Bytes& paramTokens = {});

    /// @brief ifRecv with polling (LAW 14) — retries until ComPacket.length > 0
    static Result pollRecv(std::shared_ptr<ITransport> transport,
                           uint8_t protocolId, uint16_t comId,
                           Bytes& outBuffer, size_t maxSize,
                           int maxAttempts = 20);

    /// @brief 세션 정보를 사용하여 ComPacket 구성 (정적 유틸리티)
    /// @param session 세션 객체
    /// @param tokens 포함할 토큰 바이트
    /// @return 구성된 ComPacket 바이트
    static Bytes buildComPacket(Session& session, const Bytes& tokens);

    // ══════════════════════════════════════════════════
    //  TC Library 유틸리티 함수
    // ══════════════════════════════════════════════════

    /// @brief Discovery를 파싱하여 드라이브 기능 요약 정보 반환 (getTcgOption 대응)
    /// @param transport 전송 인터페이스
    /// @param option TCG 옵션 정보가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getTcgOption(std::shared_ptr<ITransport> transport,
                        TcgOption& option);

    /// @brief Discovery에서 기능 존재 플래그 조회 (GetClass0SecurityStatus 대응)
    /// @param transport 전송 인터페이스
    /// @param status 보안 상태 정보가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getSecurityStatus(std::shared_ptr<ITransport> transport,
                             SecurityStatus& status);

    /// @brief 특정 기능 코드에 대한 상세 정보 조회 (GetSecurityFeatureType 대응)
    /// @param transport 전송 인터페이스
    /// @param featureCode 조회할 기능 코드
    /// @param info 보안 기능 정보가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getSecurityFeature(std::shared_ptr<ITransport> transport,
                              uint16_t featureCode,
                              SecurityFeatureInfo& info);

    /// @brief 모든 보안 기능 정보 조회 (GetSecurityFeatureType 전체)
    /// @param transport 전송 인터페이스
    /// @param features 모든 기능 정보가 저장될 벡터
    /// @return 성공 또는 오류 코드
    Result getAllSecurityFeatures(std::shared_ptr<ITransport> transport,
                                  std::vector<SecurityFeatureInfo>& features);

    /// @brief 잠금 범위 정보 읽기 (활성 세션 필요) (GetLockingInfo 대응)
    /// @param session 활성 세션 객체
    /// @param rangeId 조회할 잠금 범위 ID
    /// @param info 잠금 정보가 저장될 구조체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getLockingInfo(Session& session,
                         uint32_t rangeId,
                         LockingInfo& info,
                         RawResult& result);

    /// @brief 모든 잠금 범위 정보 읽기 (GetLockingInfo 전체)
    /// @param session 활성 세션 객체
    /// @param ranges 잠금 범위 정보가 저장될 벡터
    /// @param maxRanges 최대 조회할 범위 수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getAllLockingInfo(Session& session,
                            std::vector<LockingInfo>& ranges,
                            uint32_t maxRanges,
                            RawResult& result);

    /// @brief DataStore 테이블 속성 읽기 (GetByteTableInfo 대응)
    /// @param session 활성 세션 객체
    /// @param info 바이트 테이블 정보가 저장될 구조체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getByteTableInfo(Session& session,
                            ByteTableInfo& info,
                            RawResult& result);

    /// @brief DataStore 테이블에 지정된 오프셋부터 바이트 쓰기 (TcgWrite 대응)
    /// @param session 활성 세션 객체
    /// @param tableUid 대상 테이블 UID
    /// @param offset 쓰기 시작 오프셋
    /// @param data 쓸 데이터
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tcgWrite(Session& session,
                    uint64_t tableUid,
                    uint32_t offset,
                    const Bytes& data,
                    RawResult& result);

    /// @brief DataStore 테이블에서 지정된 오프셋부터 바이트 읽기 (TcgRead 대응)
    /// @param session 활성 세션 객체
    /// @param tableUid 대상 테이블 UID
    /// @param offset 읽기 시작 오프셋
    /// @param length 읽을 길이 (바이트)
    /// @param result 데이터 연산 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tcgRead(Session& session,
                   uint64_t tableUid,
                   uint32_t offset,
                   uint32_t length,
                   DataOpResult& result);

    /// @brief 데이터 쓰기 후 다시 읽어 비교 수행 (TcgCompare 대응)
    /// @param session 활성 세션 객체
    /// @param tableUid 대상 테이블 UID
    /// @param offset 비교 시작 오프셋
    /// @param expected 비교 기대 데이터
    /// @param result 데이터 연산 결과가 저장될 구조체 (compareMatch 포함)
    /// @return 성공 또는 오류 코드
    Result tcgCompare(Session& session,
                      uint64_t tableUid,
                      uint32_t offset,
                      const Bytes& expected,
                      DataOpResult& result);

    /// @brief 기본 DataStore 테이블에 데이터 쓰기
    /// @param session 활성 세션 객체
    /// @param offset 쓰기 시작 오프셋
    /// @param data 쓸 데이터
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tcgWriteDataStore(Session& session,
                             uint32_t offset,
                             const Bytes& data,
                             RawResult& result);

    /// @brief 기본 DataStore 테이블에서 데이터 읽기
    /// @param session 활성 세션 객체
    /// @param offset 읽기 시작 오프셋
    /// @param length 읽을 길이 (바이트)
    /// @param result 데이터 연산 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tcgReadDataStore(Session& session,
                            uint32_t offset,
                            uint32_t length,
                            DataOpResult& result);

    // ══════════════════════════════════════════════════
    //  테이블 열거
    // ══════════════════════════════════════════════════

    /// @brief Next 메서드 — 테이블의 행을 열거
    /// @param session 활성 세션 객체
    /// @param tableUid 대상 테이블 UID
    /// @param startRowUid 열거 시작 행 UID
    /// @param rows 열거된 행 UID가 저장될 벡터
    /// @param count 최대 반환 행 수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableNext(Session& session,
                     uint64_t tableUid,
                     uint64_t startRowUid,
                     std::vector<Uid>& rows,
                     uint32_t count,
                     RawResult& result);

    /// @brief 단일 컬럼 값 읽기 (편의 함수)
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param column 대상 컬럼 번호
    /// @param value 읽어온 토큰 값이 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableGetColumn(Session& session,
                          uint64_t objectUid,
                          uint32_t column,
                          Token& value,
                          RawResult& result);

    // ══════════════════════════════════════════════════
    //  사용자 / Authority 관리
    // ══════════════════════════════════════════════════

    /// @brief 사용자 Authority 활성화 (예: Locking SP의 User1)
    /// @param session 활성 세션 객체
    /// @param userId 사용자 번호 (1, 2, 3...)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result enableUser(Session& session,
                      uint32_t userId,
                      RawResult& result);

    /// @brief 사용자 Authority 비활성화
    /// @param session 활성 세션 객체
    /// @param userId 사용자 번호
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result disableUser(Session& session,
                       uint32_t userId,
                       RawResult& result);

    /// @brief 사용자 패스워드 설정 (User1..N, 바이트 배열)
    /// @param session 활성 세션 객체
    /// @param userId 사용자 번호
    /// @param newPin 새 PIN (바이트 배열)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setUserPassword(Session& session,
                           uint32_t userId,
                           const Bytes& newPin,
                           RawResult& result);

    /// @brief 사용자 패스워드 설정 (User1..N, 문자열)
    /// @param session 활성 세션 객체
    /// @param userId 사용자 번호
    /// @param newPassword 새 패스워드 문자열
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setUserPassword(Session& session,
                           uint32_t userId,
                           const std::string& newPassword,
                           RawResult& result);

    /// @brief 사용자 활성화 상태 확인
    /// @param session 활성 세션 객체
    /// @param userId 사용자 번호
    /// @param enabled 활성화 상태가 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result isUserEnabled(Session& session,
                         uint32_t userId,
                         bool& enabled,
                         RawResult& result);

    /// @brief Locking SP의 Admin1 패스워드 설정 (바이트 배열)
    /// @param session 활성 세션 객체
    /// @param newPin 새 PIN (바이트 배열)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setAdmin1Password(Session& session,
                             const Bytes& newPin,
                             RawResult& result);

    /// @brief Locking SP의 Admin1 패스워드 설정 (문자열)
    /// @param session 활성 세션 객체
    /// @param newPassword 새 패스워드 문자열
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setAdmin1Password(Session& session,
                             const std::string& newPassword,
                             RawResult& result);

    /// @brief 사용자를 잠금 범위에 할당 (ACE 조작)
    /// @param session 활성 세션 객체
    /// @param userId 사용자 번호
    /// @param rangeId 잠금 범위 ID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result assignUserToRange(Session& session,
                             uint32_t userId,
                             uint32_t rangeId,
                             RawResult& result);

    // ══════════════════════════════════════════════════
    //  SP 수명 주기 (확장)
    // ══════════════════════════════════════════════════

    /// @brief SP 수명 주기 상태 조회 (Manufactured=0, Manufactured-Inactive=8, Manufactured-Disabled=9)
    /// @param session 활성 세션 객체
    /// @param spUid 조회할 SP UID
    /// @param lifecycle 수명 주기 값이 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getSpLifecycle(Session& session,
                          uint64_t spUid,
                          uint8_t& lifecycle,
                          RawResult& result);

    /// @brief PSID Revert (PSID Authority를 통한 Admin SP 복원)
    /// @param session 활성 세션 객체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result psidRevert(Session& session, RawResult& result);

    // ══════════════════════════════════════════════════
    //  MBR 확장
    // ══════════════════════════════════════════════════

    /// @brief MBR 상태 조회 (Enable + Done 플래그)
    /// @param session 활성 세션 객체
    /// @param mbrEnabled MBR 활성화 상태가 저장될 변수
    /// @param mbrDone MBR Done 상태가 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getMbrStatus(Session& session,
                        bool& mbrEnabled,
                        bool& mbrDone,
                        RawResult& result);

    // ══════════════════════════════════════════════════
    //  잠금 범위 확장
    // ══════════════════════════════════════════════════

    /// @brief 잠금 범위에 대한 LockOnReset 설정
    /// @param session 활성 세션 객체
    /// @param rangeId 잠금 범위 ID
    /// @param lockOnReset 리셋 시 잠금 여부
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setLockOnReset(Session& session,
                          uint32_t rangeId,
                          bool lockOnReset,
                          RawResult& result);

    /// @brief 잠금 범위 암호화 소거 (새 키 생성)
    /// @param session 활성 세션 객체
    /// @param rangeId 소거할 잠금 범위 ID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result cryptoErase(Session& session,
                       uint32_t rangeId,
                       RawResult& result);

    // ══════════════════════════════════════════════════
    //  Enterprise SSC 전용
    // ══════════════════════════════════════════════════

    /// @brief Enterprise 밴드 구성 (시작, 길이, 잠금 활성화)
    /// @param session 활성 세션 객체
    /// @param bandId 밴드 ID
    /// @param bandStart 밴드 시작 LBA
    /// @param bandLength 밴드 길이 (섹터 수)
    /// @param readLockEnabled 읽기 잠금 활성화 여부
    /// @param writeLockEnabled 쓰기 잠금 활성화 여부
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result configureBand(Session& session,
                         uint32_t bandId,
                         uint64_t bandStart,
                         uint64_t bandLength,
                         bool readLockEnabled,
                         bool writeLockEnabled,
                         RawResult& result);

    /// @brief Enterprise 밴드 잠금
    /// @param session 활성 세션 객체
    /// @param bandId 잠글 밴드 ID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result lockBand(Session& session, uint32_t bandId, RawResult& result);

    /// @brief Enterprise 밴드 잠금 해제
    /// @param session 활성 세션 객체
    /// @param bandId 잠금 해제할 밴드 ID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result unlockBand(Session& session, uint32_t bandId, RawResult& result);

    /// @brief Enterprise 밴드 정보 조회
    /// @param session 활성 세션 객체
    /// @param bandId 조회할 밴드 ID
    /// @param info 잠금 정보가 저장될 구조체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getBandInfo(Session& session,
                       uint32_t bandId,
                       LockingInfo& info,
                       RawResult& result);

    /// @brief BandMaster 패스워드 설정
    /// @param session 활성 세션 객체
    /// @param bandId 대상 밴드 ID
    /// @param newPin 새 PIN (바이트 배열)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setBandMasterPassword(Session& session,
                                 uint32_t bandId,
                                 const Bytes& newPin,
                                 RawResult& result);

    /// @brief EraseMaster 패스워드 설정
    /// @param session 활성 세션 객체
    /// @param newPin 새 PIN (바이트 배열)
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setEraseMasterPassword(Session& session,
                                  const Bytes& newPin,
                                  RawResult& result);

    /// @brief Enterprise 밴드 소거
    /// @param session 활성 세션 객체
    /// @param bandId 소거할 밴드 ID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result eraseBand(Session& session,
                     uint32_t bandId,
                     RawResult& result);

    // ══════════════════════════════════════════════════
    //  원시 전송 접근
    // ══════════════════════════════════════════════════

    /// @brief 원시 IF-SEND 수행 (전송 수준, 세션 불필요)
    /// @param transport 전송 인터페이스
    /// @param protocolId 보안 프로토콜 ID
    /// @param comId ComID
    /// @param data 전송할 데이터
    /// @return 성공 또는 오류 코드
    Result rawIfSend(std::shared_ptr<ITransport> transport,
                     uint8_t protocolId,
                     uint16_t comId,
                     const Bytes& data);

    /// @brief 원시 IF-RECV 수행 (전송 수준, 세션 불필요)
    /// @param transport 전송 인터페이스
    /// @param protocolId 보안 프로토콜 ID
    /// @param comId ComID
    /// @param data 수신 데이터가 저장될 버퍼
    /// @param maxSize 최대 수신 크기 (기본값: 65536)
    /// @return 성공 또는 오류 코드
    Result rawIfRecv(std::shared_ptr<ITransport> transport,
                     uint8_t protocolId,
                     uint16_t comId,
                     Bytes& data,
                     size_t maxSize = 65536);

    // ══════════════════════════════════════════════════
    //  세션 상태 및 제어
    // ══════════════════════════════════════════════════

    /// @brief 세션 상태 정보 구조체
    struct SessionInfo {
        bool     active          = false;  ///< 세션 활성화 여부
        uint32_t hostSessionNumber = 0;    ///< 호스트 세션 번호
        uint32_t tperSessionNumber = 0;    ///< TPer 세션 번호
        uint32_t maxComPacketSize  = 0;    ///< 최대 ComPacket 크기
        uint32_t timeoutMs         = 0;    ///< 타임아웃 (밀리초)
        uint32_t seqNumber         = 0;    ///< 현재 시퀀스 번호
    };

    /// @brief 세션 상태 조회
    /// @param session 조회할 세션 객체
    /// @return 세션 상태 정보
    static SessionInfo getSessionInfo(const Session& session);

    /// @brief 세션 타임아웃 설정
    /// @param session 대상 세션 객체
    /// @param ms 타임아웃 값 (밀리초)
    static void setSessionTimeout(Session& session, uint32_t ms);

    /// @brief 최대 ComPacket 크기 설정
    /// @param session 대상 세션 객체
    /// @param size 최대 ComPacket 크기 (바이트)
    static void setSessionMaxComPacket(Session& session, uint32_t size);

    // ══════════════════════════════════════════════════
    //  ComID 관리 (프로토콜 리셋 등)
    // ══════════════════════════════════════════════════

    /// @brief Security Protocol 0x02를 통한 스택 리셋 수행
    /// @param transport 전송 인터페이스
    /// @param comId 리셋할 ComID
    /// @return 성공 또는 오류 코드
    Result stackReset(std::shared_ptr<ITransport> transport,
                      uint16_t comId);

    /// @brief ComID 활성 상태 확인 (Security Protocol 0x02, ComID 관리)
    /// @param transport 전송 인터페이스
    /// @param comId 확인할 ComID
    /// @param active 활성 상태가 저장될 변수
    /// @return 성공 또는 오류 코드
    Result verifyComId(std::shared_ptr<ITransport> transport,
                       uint16_t comId,
                       bool& active);

    // ══════════════════════════════════════════════════
    //  패스워드 / 해싱 유틸리티
    // ══════════════════════════════════════════════════

    /// @brief 패스워드를 바이트 배열로 해싱 (PBKDF2 구성 시 PBKDF2 사용, 아니면 원시)
    /// @param password 해싱할 패스워드 문자열
    /// @return 해싱된 바이트 배열
    static Bytes hashPassword(const std::string& password);

    /// @brief 명시적 솔트와 반복 횟수로 PBKDF2 패스워드 해싱
    /// @param password 해싱할 패스워드 문자열
    /// @param salt 솔트 바이트 배열
    /// @param iterations PBKDF2 반복 횟수
    /// @return 해싱된 바이트 배열
    static Bytes hashPasswordPbkdf2(const std::string& password,
                                     const Bytes& salt,
                                     uint32_t iterations);

    /// @brief C_PIN의 TryLimit / 남은 시도 횟수 조회
    /// @param session 활성 세션 객체
    /// @param cpinUid C_PIN 객체 UID
    /// @param remaining 남은 시도 횟수가 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getCPinTriesRemaining(Session& session,
                                 uint64_t cpinUid,
                                 uint32_t& remaining,
                                 RawResult& result);

    // ══════════════════════════════════════════════════
    //  테이블 행 관리 (CreateRow / DeleteRow)
    // ══════════════════════════════════════════════════

    /// @brief 테이블에 새 행 생성 (CreateRow)
    /// @param session 활성 세션 객체
    /// @param tableUid 대상 테이블 UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableCreateRow(Session& session,
                          uint64_t tableUid,
                          RawResult& result);

    /// @brief 테이블에서 행 삭제 (DeleteRow)
    /// @param session 활성 세션 객체
    /// @param rowUid 삭제할 행 UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableDeleteRow(Session& session,
                          uint64_t rowUid,
                          RawResult& result);

    // ══════════════════════════════════════════════════
    //  접근 제어 (GetACL / Assign / Remove)
    // ══════════════════════════════════════════════════

    /// @brief 객체+메서드 조합에 대한 ACL 정보 구조체
    struct AclInfo {
        std::vector<Uid> aceList;  ///< ACE 목록
        RawResult raw;             ///< 원시 결과 데이터
    };

    /// @brief 특정 호출 UID + 메서드 UID에 대한 접근 제어 읽기 (GetACL)
    /// @param session 활성 세션 객체
    /// @param invokingUid 호출 대상 UID
    /// @param methodUid 메서드 UID
    /// @param info ACL 정보가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getAcl(Session& session,
                  uint64_t invokingUid,
                  uint64_t methodUid,
                  AclInfo& info);

    /// @brief 테이블 행에 Authority 할당 (DataStore 등에 사용)
    /// @param session 활성 세션 객체
    /// @param tableUid 대상 테이블 UID
    /// @param rowUid 대상 행 UID
    /// @param authorityUid 할당할 Authority UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableAssign(Session& session,
                       uint64_t tableUid,
                       uint64_t rowUid,
                       uint64_t authorityUid,
                       RawResult& result);

    /// @brief 테이블 행에서 Authority 제거
    /// @param session 활성 세션 객체
    /// @param tableUid 대상 테이블 UID
    /// @param rowUid 대상 행 UID
    /// @param authorityUid 제거할 Authority UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableRemove(Session& session,
                       uint64_t tableUid,
                       uint64_t rowUid,
                       uint64_t authorityUid,
                       RawResult& result);

    // ══════════════════════════════════════════════════
    //  편의용 단일 타입 컬럼 읽기
    // ══════════════════════════════════════════════════

    /// @brief 단일 uint 컬럼 값 읽기
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param column 대상 컬럼 번호
    /// @param value 읽어온 uint64 값이 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableGetUint(Session& session,
                        uint64_t objectUid,
                        uint32_t column,
                        uint64_t& value,
                        RawResult& result);

    /// @brief 단일 바이트 배열 컬럼 값 읽기
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param column 대상 컬럼 번호
    /// @param value 읽어온 바이트 배열이 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableGetBytes(Session& session,
                         uint64_t objectUid,
                         uint32_t column,
                         Bytes& value,
                         RawResult& result);

    /// @brief 단일 bool 컬럼 값 읽기
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param column 대상 컬럼 번호
    /// @param value 읽어온 bool 값이 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableGetBool(Session& session,
                        uint64_t objectUid,
                        uint32_t column,
                        bool& value,
                        RawResult& result);

    // ══════════════════════════════════════════════════
    //  다중 컬럼 설정 (ColumnValues 맵)
    // ══════════════════════════════════════════════════

    /// @brief 한 번의 호출로 여러 uint 컬럼 값 설정
    /// @param session 활성 세션 객체
    /// @param objectUid 대상 객체 UID
    /// @param columns 설정할 컬럼 번호와 uint64 값의 쌍 목록
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tableSetMultiUint(Session& session,
                             uint64_t objectUid,
                             const std::vector<std::pair<uint32_t, uint64_t>>& columns,
                             RawResult& result);

    // ══════════════════════════════════════════════════
    //  Revert (객체 수준, RevertSP와 구별)
    // ══════════════════════════════════════════════════

    /// @brief 객체에 대한 Revert 메서드 수행 (SP 수준 Revert가 아님)
    /// @param session 활성 세션 객체
    /// @param objectUid Revert할 대상 객체 UID
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result revert(Session& session, uint64_t objectUid, RawResult& result);

    // ══════════════════════════════════════════════════
    //  클록
    // ══════════════════════════════════════════════════

    /// @brief TPer 클록 값 읽기 (GetClock)
    /// @param session 활성 세션 객체
    /// @param clockValue 읽어온 클록 값이 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getClock(Session& session, uint64_t& clockValue, RawResult& result);

    // ══════════════════════════════════════════════════
    //  Authority 검증
    // ══════════════════════════════════════════════════

    /// @brief 자격 증명 유효성 검증 (StartSession + Auth -> 종료, 바이트 배열)
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param spUid 대상 SP UID
    /// @param authorityUid 검증할 Authority UID
    /// @param credential 자격 증명 (바이트 배열)
    /// @return 성공 또는 오류 코드
    Result verifyAuthority(std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           uint64_t spUid,
                           uint64_t authorityUid,
                           const Bytes& credential);

    /// @brief 자격 증명 유효성 검증 (StartSession + Auth -> 종료, 문자열)
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param spUid 대상 SP UID
    /// @param authorityUid 검증할 Authority UID
    /// @param password 패스워드 문자열
    /// @return 성공 또는 오류 코드
    Result verifyAuthority(std::shared_ptr<ITransport> transport,
                           uint16_t comId,
                           uint64_t spUid,
                           uint64_t authorityUid,
                           const std::string& password);

    // ══════════════════════════════════════════════════
    //  테이블 번호를 지정한 DataStore
    // ══════════════════════════════════════════════════

    /// @brief 번호가 지정된 DataStore 테이블에 데이터 쓰기 (테이블 0, 1, 2...)
    /// @param session 활성 세션 객체
    /// @param tableNumber DataStore 테이블 번호
    /// @param offset 쓰기 시작 오프셋
    /// @param data 쓸 데이터
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tcgWriteDataStoreN(Session& session,
                              uint32_t tableNumber,
                              uint32_t offset,
                              const Bytes& data,
                              RawResult& result);

    /// @brief 번호가 지정된 DataStore 테이블에서 데이터 읽기
    /// @param session 활성 세션 객체
    /// @param tableNumber DataStore 테이블 번호
    /// @param offset 읽기 시작 오프셋
    /// @param length 읽을 길이 (바이트)
    /// @param result 데이터 연산 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result tcgReadDataStoreN(Session& session,
                             uint32_t tableNumber,
                             uint32_t offset,
                             uint32_t length,
                             DataOpResult& result);

    // ══════════════════════════════════════════════════
    //  Enterprise 밴드 확장
    // ══════════════════════════════════════════════════

    /// @brief Enterprise 밴드에 대한 LockOnReset 설정
    /// @param session 활성 세션 객체
    /// @param bandId 밴드 ID
    /// @param lockOnReset 리셋 시 잠금 여부
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result setBandLockOnReset(Session& session,
                              uint32_t bandId,
                              bool lockOnReset,
                              RawResult& result);

    /// @brief 모든 밴드 소거 (Enterprise EraseMaster 사용)
    /// @param session 활성 세션 객체
    /// @param maxBands 최대 밴드 수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result eraseAllBands(Session& session,
                         uint32_t maxBands,
                         RawResult& result);

    // ══════════════════════════════════════════════════
    //  활성 키 / 키 관리
    // ══════════════════════════════════════════════════

    /// @brief 잠금 범위의 활성 키 UID 조회
    /// @param session 활성 세션 객체
    /// @param rangeId 잠금 범위 ID
    /// @param keyUid 활성 키 UID가 저장될 변수
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result getActiveKey(Session& session,
                        uint32_t rangeId,
                        Uid& keyUid,
                        RawResult& result);

    // ══════════════════════════════════════════════════
    //  Discovery 네임스페이스 (파싱된 구조체)
    // ══════════════════════════════════════════════════

    /// @brief 전체 파싱된 DiscoveryInfo 구조체를 반환하는 Discovery0
    /// @param transport 전송 인터페이스
    /// @param info Discovery 결과가 저장될 구조체
    /// @param result 원시 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    Result discovery0Parsed(std::shared_ptr<ITransport> transport,
                            DiscoveryInfo& info,
                            RawResult& result);

    // ══════════════════════════════════════════════════
    //  NVMe 디바이스 접근 (DI 전송 경유)
    // ══════════════════════════════════════════════════

    /// @brief 전송에서 INvmeDevice 추출 (NVMe DI가 아닌 경우 nullptr 반환)
    /// @param transport 전송 인터페이스
    /// @return INvmeDevice 포인터 또는 nullptr
    static INvmeDevice* getNvmeDevice(std::shared_ptr<ITransport> transport);

    /// @brief NVMe Identify Controller 수행 (INvmeDevice 경유 편의 함수)
    /// @param transport 전송 인터페이스
    /// @param cns CNS (Controller or Namespace Structure) 값
    /// @param nsid 네임스페이스 ID
    /// @param data Identify 데이터가 저장될 버퍼
    /// @return 성공 또는 오류 코드
    static Result nvmeIdentify(std::shared_ptr<ITransport> transport,
                               uint8_t cns, uint32_t nsid, Bytes& data);

    /// @brief NVMe Get Log Page 수행
    /// @param transport 전송 인터페이스
    /// @param logId 로그 페이지 ID
    /// @param nsid 네임스페이스 ID
    /// @param data 로그 데이터가 저장될 버퍼
    /// @param dataLen 요청할 데이터 길이
    /// @return 성공 또는 오류 코드
    static Result nvmeGetLogPage(std::shared_ptr<ITransport> transport,
                                 uint8_t logId, uint32_t nsid,
                                 Bytes& data, uint32_t dataLen);

    /// @brief NVMe Get Feature 수행
    /// @param transport 전송 인터페이스
    /// @param featureId Feature ID
    /// @param nsid 네임스페이스 ID
    /// @param cdw0 Completion 큐 DWORD 0이 저장될 변수
    /// @param data Feature 데이터가 저장될 버퍼
    /// @return 성공 또는 오류 코드
    static Result nvmeGetFeature(std::shared_ptr<ITransport> transport,
                                 uint8_t featureId, uint32_t nsid,
                                 uint32_t& cdw0, Bytes& data);

    /// @brief NVMe Set Feature 수행
    /// @param transport 전송 인터페이스
    /// @param featureId Feature ID
    /// @param nsid 네임스페이스 ID
    /// @param cdw11 Command DWORD 11 값
    /// @param data Feature 데이터 (기본값: 빈 바이트)
    /// @return 성공 또는 오류 코드
    static Result nvmeSetFeature(std::shared_ptr<ITransport> transport,
                                 uint8_t featureId, uint32_t nsid,
                                 uint32_t cdw11, const Bytes& data = {});

    /// @brief NVMe Format NVM 수행
    /// @param transport 전송 인터페이스
    /// @param nsid 네임스페이스 ID
    /// @param lbaf LBA Format 인덱스
    /// @param ses Secure Erase Setting (기본값: 0)
    /// @param pi Protection Information (기본값: 0)
    /// @return 성공 또는 오류 코드
    static Result nvmeFormat(std::shared_ptr<ITransport> transport,
                             uint32_t nsid, uint8_t lbaf,
                             uint8_t ses = 0, uint8_t pi = 0);

    /// @brief 임의의 NVMe Admin 명령 전송
    /// @param transport 전송 인터페이스
    /// @param cmd NVMe Admin 명령 구조체
    /// @param cpl NVMe Completion 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    static Result nvmeAdminCmd(std::shared_ptr<ITransport> transport,
                               NvmeAdminCmd& cmd, NvmeCompletion& cpl);

    /// @brief 임의의 NVMe IO 명령 전송
    /// @param transport 전송 인터페이스
    /// @param cmd NVMe IO 명령 구조체
    /// @param cpl NVMe Completion 결과가 저장될 구조체
    /// @return 성공 또는 오류 코드
    static Result nvmeIoCmd(std::shared_ptr<ITransport> transport,
                            NvmeIoCmd& cmd, NvmeCompletion& cpl);

    // ══════════════════════════════════════════════════
    //  RawResult 생략 가능한 편의 오버로드
    //  (RawResult가 필요 없는 일반적인 사용 패턴용)
    // ══════════════════════════════════════════════════

    Result authenticate(Session& session, uint64_t authorityUid, const Bytes& credential);
    Result authenticate(Session& session, uint64_t authorityUid, const std::string& password);

    Result getCPin(Session& session, uint64_t cpinUid, Bytes& pin);
    Result setCPin(Session& session, uint64_t cpinUid, const Bytes& newPin);
    Result setCPin(Session& session, uint64_t cpinUid, const std::string& newPassword);

    Result setRange(Session& session, uint32_t rangeId, uint64_t rangeStart,
                    uint64_t rangeLength, bool readLockEnabled, bool writeLockEnabled);
    Result setRangeLock(Session& session, uint32_t rangeId, bool readLocked, bool writeLocked);
    Result getRangeInfo(Session& session, uint32_t rangeId, LockingRangeInfo& info);

    Result activate(Session& session, uint64_t spUid);
    Result revertSP(Session& session, uint64_t spUid);
    Result psidRevert(Session& session);

    Result setMbrEnable(Session& session, bool enable);
    Result setMbrDone(Session& session, bool done);
    Result writeMbrData(Session& session, uint32_t offset, const Bytes& data);
    Result readMbrData(Session& session, uint32_t offset, uint32_t length, Bytes& data);
    Result getMbrStatus(Session& session, bool& mbrEnabled, bool& mbrDone);
    Result setMbrControlNsidOne(Session& session);

    Result enableUser(Session& session, uint32_t userId);
    Result setUserPassword(Session& session, uint32_t userId, const Bytes& newPin);
    Result setUserPassword(Session& session, uint32_t userId, const std::string& newPassword);
    Result isUserEnabled(Session& session, uint32_t userId, bool& enabled);
    Result setAdmin1Password(Session& session, const Bytes& newPin);
    Result setAdmin1Password(Session& session, const std::string& newPassword);
    Result assignUserToRange(Session& session, uint32_t userId, uint32_t rangeId);

    Result setAuthorityEnabled(Session& session, uint64_t authorityUid, bool enabled);
    Result addAuthorityToAce(Session& session, uint64_t aceUid, uint64_t authorityUid);

    Result getLockingInfo(Session& session, uint32_t rangeId, LockingInfo& info);
    Result getSpLifecycle(Session& session, uint64_t spUid, uint8_t& lifecycle);
    Result getActiveKey(Session& session, uint32_t rangeId, Uid& keyUid);
    Result cryptoErase(Session& session, uint32_t rangeId);
    Result genKey(Session& session, uint64_t objectUid);
    Result setLockOnReset(Session& session, uint32_t rangeId, bool lockOnReset);

    Result configureBand(Session& session, uint32_t bandId, uint64_t bandStart,
                         uint64_t bandLength, bool readLockEnabled, bool writeLockEnabled);
    Result lockBand(Session& session, uint32_t bandId);
    Result unlockBand(Session& session, uint32_t bandId);
    Result getBandInfo(Session& session, uint32_t bandId, LockingInfo& info);
    Result setBandMasterPassword(Session& session, uint32_t bandId, const Bytes& newPin);
    Result setEraseMasterPassword(Session& session, const Bytes& newPin);
    Result eraseBand(Session& session, uint32_t bandId);
    Result eraseAllBands(Session& session, uint32_t maxBands);
    Result setBandLockOnReset(Session& session, uint32_t bandId, bool lockOnReset);

    Result getByteTableInfo(Session& session, ByteTableInfo& info);
    Result tcgWriteDataStore(Session& session, uint32_t offset, const Bytes& data);
    Result tcgWriteDataStoreN(Session& session, uint32_t tableNumber, uint32_t offset, const Bytes& data);

    Result getAllLockingInfo(Session& session, std::vector<LockingInfo>& ranges, uint32_t maxRanges);
    Result getAceInfo(Session& session, uint64_t aceUid, AceInfo& info);
    Result getRandom(Session& session, uint32_t count, Bytes& randomData);
    Result getClock(Session& session, uint64_t& clockValue);
    Result tableSetBool(Session& session, uint64_t objectUid, uint32_t column, bool value);
    Result tableGetUint(Session& session, uint64_t objectUid, uint32_t column, uint64_t& value);
    Result getCPinTriesRemaining(Session& session, uint64_t cpinUid, uint32_t& remaining);
};

// ════════════════════════════════════════════════════════
//  편의 기능: 일반적인 평가 테스트 시퀀스
// ════════════════════════════════════════════════════════

namespace sequence {

    /// @brief 각 단계의 중간 결과를 전달받는 옵저버 콜백 타입.
    ///
    /// 전체 소유권 획득 시퀀스: Discovery -> Properties -> StartSession(Admin,SID,MSID)
    ///                        -> C_PIN(SID) 설정 -> CloseSession
    /// 각 단계 후 옵저버가 호출되며, 중간 결과를 확인할 수 있습니다.
    /// @return true이면 계속 진행, false이면 시퀀스 중단
    using StepObserver = std::function<bool(const std::string& stepName,
                                            const RawResult& result)>;

    /// @brief 단계별 소유권 획득 시퀀스 수행
    ///
    /// Discovery -> Properties -> StartSession -> C_PIN(SID) 설정 -> CloseSession
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param newSidPassword 설정할 새 SID 패스워드
    /// @param observer 각 단계의 중간 결과를 전달받는 옵저버 (nullptr 허용)
    /// @return 성공 또는 오류 코드
    Result takeOwnershipStepByStep(
        std::shared_ptr<ITransport> transport,
        uint16_t comId,
        const std::string& newSidPassword,
        StepObserver observer = nullptr);

    /// @brief 단계별 전체 Opal 설정 시퀀스 수행
    ///
    /// 소유권 획득 -> 활성화 -> Admin1 설정 -> User1 활성화
    /// -> 범위 구성 -> 글로벌 잠금 활성화
    /// @param transport 전송 인터페이스
    /// @param comId 사용할 ComID
    /// @param sidPassword SID 패스워드
    /// @param admin1Password Admin1 패스워드
    /// @param user1Password User1 패스워드
    /// @param observer 각 단계의 중간 결과를 전달받는 옵저버 (nullptr 허용)
    /// @return 성공 또는 오류 코드
    Result fullOpalSetupStepByStep(
        std::shared_ptr<ITransport> transport,
        uint16_t comId,
        const std::string& sidPassword,
        const std::string& admin1Password,
        const std::string& user1Password,
        StepObserver observer = nullptr);

} // namespace sequence

} // namespace eval
} // namespace libsed
