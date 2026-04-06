#pragma once

/// @file sim_transport.h
/// @brief 소프트웨어 SED 시뮬레이터 Transport — 하드웨어 없이 TCG 프로토콜 검증
///
/// ITransport를 구현하는 완전한 TPer 시뮬레이터:
///   - Discovery (Feature Descriptors 생성)
///   - StackReset / VerifyComId
///   - Properties Exchange
///   - StartSession / SyncSession / CloseSession
///   - Get / Set (C_PIN, Locking, MBR Control, Authority, SP, DataStore)
///   - Authenticate
///   - Activate / RevertSP / PsidRevert
///   - GenKey / CryptoErase
///
/// 사용법:
/// @code
///   auto sim = std::make_shared<SimTransport>();
///   SedDrive drive(sim);
///   drive.query();
///   drive.takeOwnership("my_password");
/// @endcode

#include "i_transport.h"
#include "../core/uid.h"
#include "../core/endian.h"
#include "../codec/token_encoder.h"
#include "../codec/token_decoder.h"
#include "../packet/packet_builder.h"
#include "../method/method_uids.h"

#include <map>
#include <set>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>
#include <functional>

namespace libsed {

/// @brief 소프트웨어 SED 시뮬레이터 설정
struct SimConfig {
    SscType sscType         = SscType::Opal20;
    uint16_t baseComId      = 0x0001;
    uint16_t numComIds      = 1;
    uint32_t maxComPacketSize = 2048;
    uint32_t maxPacketSize  = 2028;
    uint32_t maxIndTokenSize = 2016;
    uint32_t maxRanges      = 8;
    uint32_t maxUsers       = 4;
    uint32_t dataStoreSize  = 65536;  // 64KB
    uint32_t mbrSize        = 131072; // 128KB
    Bytes    msid;                    // 공장 MSID (비어있으면 자동 생성)
    Bytes    psid;                    // PSID (비어있으면 자동 생성)
    uint32_t pinTryLimit    = 5;
    uint32_t maxBands       = 4;     // Enterprise: 최대 Band 수
    uint32_t numDataStoreTables = 2; // DataStore 테이블 수
};

/// @brief 소프트웨어 SED 시뮬레이터 Transport
class SimTransport : public ITransport {
public:
    /// 기본 설정으로 생성
    SimTransport();

    /// 커스텀 설정으로 생성
    explicit SimTransport(const SimConfig& config);

    ~SimTransport() override = default;

    // ── ITransport 구현 ──
    Result ifSend(uint8_t protocolId, uint16_t comId, ByteSpan payload) override;
    Result ifRecv(uint8_t protocolId, uint16_t comId,
                  MutableByteSpan buffer, size_t& bytesReceived) override;

    TransportType type() const override { return TransportType::NVMe; }
    std::string devicePath() const override { return "/dev/sim_sed"; }
    bool isOpen() const override { return true; }
    void close() override {}

    // ── 시뮬레이터 제어 ──

    /// 공장 초기 상태로 리셋 (모든 상태 초기화)
    void factoryReset();

    /// 현재 설정 접근
    const SimConfig& config() const { return config_; }

    /// MSID 값 접근 (테스트에서 검증용)
    const Bytes& msid() const { return msid_; }

private:
    // ── 내부 상태 ──

    /// SP 수명 주기 상태
    enum class SpLifecycle : uint8_t {
        Manufactured         = 0,   // Active
        ManufacturedInactive = 8,
        ManufacturedDisabled = 9,
    };

    /// 세션 상태
    struct SessionState {
        uint32_t tsn = 0;
        uint32_t hsn = 0;
        uint64_t spUid = 0;
        bool     write = false;
        uint64_t authUid = 0;       // 인증된 Authority (0=Anybody)
        bool     authenticated = false;
    };

    /// Locking Range 상태
    struct RangeState {
        uint64_t rangeStart = 0;
        uint64_t rangeLength = 0;
        bool readLockEnabled = false;
        bool writeLockEnabled = false;
        bool readLocked = false;
        bool writeLocked = false;
        bool lockOnReset = false;
        uint64_t activeKey = 0;
    };

    /// Authority 상태
    struct AuthState {
        bool enabled = false;
        Bytes pin;
        uint32_t triesRemaining = 5;
    };

    // ── 프로토콜 처리 ──

    /// Protocol 0x01 (세션 프로토콜) 요청 처리
    void handleSessionProtocol(uint16_t comId, ByteSpan payload);

    /// Protocol 0x02 (ComID 관리) 요청 처리
    void handleComIdManagement(uint16_t comId, ByteSpan payload);

    /// Discovery 응답 생성
    Bytes buildDiscoveryResponse();

    /// SM 메서드 처리 (Properties, StartSession, CloseSession)
    Bytes handleSmMethod(uint16_t comId, const std::vector<Token>& tokens);

    /// In-session 메서드 처리 (Get, Set, Authenticate, Activate, Revert 등)
    Bytes handleSessionMethod(uint16_t comId, uint32_t tsn, uint32_t hsn,
                               const std::vector<Token>& tokens);

    // ── 개별 메서드 핸들러 ──
    Bytes handleProperties(const std::vector<Token>& tokens);
    Bytes handleStartSession(const std::vector<Token>& tokens);
    Bytes buildSmSyncError(uint8_t statusCode);
    Bytes handleCloseSession(uint32_t tsn, uint32_t hsn);
    Bytes handleGet(uint64_t objectUid, const std::vector<Token>& params,
                     const SessionState& session);
    Bytes handleSet(uint64_t objectUid, const std::vector<Token>& params,
                     const SessionState& session);
    Bytes handleAuthenticate(const std::vector<Token>& params, SessionState& session);
    Bytes handleActivate(uint64_t objectUid, const SessionState& session);
    Bytes handleRevertSP(uint64_t objectUid, SessionState& session);
    Bytes handleGenKey(uint64_t objectUid, const SessionState& session);
    Bytes handleErase(uint64_t objectUid, const SessionState& session);
    Bytes handleRandom(const std::vector<Token>& params, const SessionState& session);
    Bytes handleGetACL(uint64_t objectUid, uint64_t methodUid,
                        const SessionState& session);

    // ── 응답 빌더 헬퍼 ──

    /// 성공 응답 토큰 (결과 없음)
    Bytes buildSuccessResponse();

    /// 에러 응답 토큰
    Bytes buildErrorResponse(uint8_t statusCode);

    /// Get 응답 — uint 컬럼들
    Bytes buildGetUintResponse(const std::vector<std::pair<uint32_t, uint64_t>>& cols);

    /// Get 응답 — bytes 컬럼들
    Bytes buildGetBytesResponse(const std::vector<std::pair<uint32_t, Bytes>>& cols);

    /// Get 응답 — mixed
    Bytes buildGetMixedResponse(
        const std::vector<std::pair<uint32_t, uint64_t>>& uintCols,
        const std::vector<std::pair<uint32_t, Bytes>>& bytesCols);

    /// SM 응답을 ComPacket으로 래핑
    Bytes wrapSmPacket(uint16_t comId, const Bytes& tokenPayload);

    /// In-session 응답을 ComPacket으로 래핑
    Bytes wrapSessionPacket(uint16_t comId, uint32_t tsn, uint32_t hsn,
                              const Bytes& tokenPayload);

    // ── 권한 검사 ──
    bool isAuthorizedForGet(const SessionState& session, uint64_t objectUid);
    bool isAuthorizedForSet(const SessionState& session, uint64_t objectUid);
    bool isAuthorizedForActivate(const SessionState& session);

    // ── UID 판별 헬퍼 ──
    bool isCpinUid(uint64_t uid) const;
    bool isLockingRangeUid(uint64_t uid) const;
    uint32_t lockingRangeIndex(uint64_t uid) const;
    bool isAuthorityUid(uint64_t uid) const;
    bool isDataStoreUid(uint64_t uid) const;
    bool isAceUid(uint64_t uid) const;
    uint32_t aceRangeIndex(uint64_t aceUid) const;
    uint32_t dataStoreTableNum(uint64_t uid) const;
    Bytes& getDataStoreRef(uint64_t uid);

    // ── 상태 ──
    SimConfig config_;
    Bytes msid_;                                      // 공장 MSID
    Bytes pendingResponse_;                            // ifRecv에서 반환할 응답
    bool responseReady_ = false;

    // SP 상태
    SpLifecycle adminSpLifecycle_ = SpLifecycle::Manufactured;
    SpLifecycle lockingSpLifecycle_ = SpLifecycle::ManufacturedInactive;

    // 세션
    uint32_t nextTsn_ = 1;
    std::map<uint32_t, SessionState> sessions_;        // TSN → session

    // C_PIN 테이블 (UID → AuthState)
    std::unordered_map<uint64_t, AuthState> cpins_;

    // Locking Range 상태 (rangeId → RangeState)
    std::map<uint32_t, RangeState> ranges_;

    // Authority 활성 상태 (UID → enabled)
    std::unordered_map<uint64_t, bool> authorities_;

    // ACE: Authority → 허용된 Range 목록 (User별 Range 격리)
    // key = Authority UID, value = 허용된 rangeId 집합
    std::unordered_map<uint64_t, std::set<uint32_t>> aceRangeAccess_;

    // MBR 상태
    bool mbrEnabled_ = false;
    bool mbrDone_ = false;
    Bytes mbrData_;

    // PSID (물리적 보안 ID)
    Bytes psid_;

    // DataStore (멀티 테이블): tableNumber(0-based) → data
    std::map<uint32_t, Bytes> dataStores_;

    // ComID 상태
    enum class ComIdState { Idle, Associated };
    ComIdState comIdState_ = ComIdState::Idle;

    // 키 카운터 (GenKey 시 증가)
    uint64_t keyCounter_ = 0x1000;

    mutable std::recursive_mutex mutex_;
};

} // namespace libsed
