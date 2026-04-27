#pragma once

#include "../core/types.h"
#include "../core/error.h"
#include "../transport/i_transport.h"
#include "../packet/packet_builder.h"
#include "../method/method_result.h"
#include <memory>

namespace libsed {

/// @brief 하나의 Security Provider와의 TCG SED 세션을 나타냄
class Session {
public:
    /// @brief 세션 상태
    enum class State {
        Idle,       ///< 시작되지 않은 초기 상태
        Starting,   ///< StartSession 전송됨, SyncSession 대기 중
        Active,     ///< 세션 활성화됨, 메서드 전송 가능
        Closing,    ///< CloseSession 전송됨
        Closed,     ///< 세션 종료됨
    };

    /// @brief 세션 객체 생성
    /// @param transport  사용할 전송 인터페이스 (공유 포인터)
    /// @param comId      통신에 사용할 ComID
    Session(std::shared_ptr<ITransport> transport, uint16_t comId);
    ~Session();

    // Prevent copy
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Allow move
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;

    // ── Session lifecycle ────────────────────────────

    /// @brief 지정된 SP와 세션 시작
    /// @param spUid          대상 Security Provider의 UID
    /// @param write          쓰기 세션 여부 (true이면 읽기/쓰기, false이면 읽기 전용)
    /// @param hostAuthority  호스트 인증 기관 UID (선택 사항)
    /// @param hostChallenge  호스트 챌린지 (비밀번호/크리덴셜, 선택 사항)
    /// @return 세션 시작 결과
    Result startSession(const Uid& spUid, bool write,
                        const Uid& hostAuthority = Uid(),
                        const Bytes& hostChallenge = {});

    /// @brief 세션 종료
    /// @return 세션 종료 결과
    Result closeSession();

    /// @brief 메서드 호출 전송 및 결과 수신
    /// @param methodTokens  인코딩된 메서드 호출 토큰
    /// @param result         메서드 실행 결과 (출력)
    /// @return 전송/수신 결과
    Result sendMethod(const Bytes& methodTokens, MethodResult& result);

    /// @brief 메서드 프레이밍 없이 raw 토큰 payload를 ComPacket으로 보내고 응답 payload 수신.
    ///
    /// StartTransaction / EndTransaction / EndOfSession 처럼 CALL…EOD 구조를
    /// 가지지 않는 primitive token 전송용. 응답은 method result로 파싱하지 않고
    /// 그대로 반환하므로 호출자가 직접 해석한다.
    ///
    /// @param tokens      보낼 token payload
    /// @param respTokens  TPer가 돌려준 token payload (출력, 있을 수 있음)
    /// @return 전송/수신 결과 (transport 레벨 에러)
    Result sendTokenPayload(const Bytes& tokens, Bytes& respTokens);

    // ── Session state ────────────────────────────────

    /// @brief 현재 세션 상태 반환
    /// @return 세션 상태 열거값
    State state() const { return state_; }

    /// @brief 세션 활성화 여부 확인
    /// @return 세션이 Active 상태이면 true
    bool isActive() const { return state_ == State::Active; }

    /// @brief TPer 세션 번호 반환
    /// @return TPer가 할당한 세션 번호 (TSN)
    uint32_t tperSessionNumber() const { return tsn_; }

    /// @brief 호스트 세션 번호 반환
    /// @return 호스트가 할당한 세션 번호 (HSN)
    uint32_t hostSessionNumber() const { return hsn_; }

    // ── Low-level send/recv ──────────────────────────

    /// @brief 저수준 ComPacket 데이터 전송
    /// @param comPacketData  전송할 ComPacket 원시 데이터
    /// @return 전송 결과
    Result sendRaw(const Bytes& comPacketData);

    /// @brief 저수준 ComPacket 데이터 수신
    /// @param comPacketData  수신된 ComPacket 원시 데이터 (출력)
    /// @param timeoutMs      수신 타임아웃 (밀리초, 기본값: 5000)
    /// @return 수신 결과
    Result recvRaw(Bytes& comPacketData, uint32_t timeoutMs = 5000);

    // ── Configuration ────────────────────────────────

    /// @brief 최대 ComPacket 크기 설정
    /// @param size  최대 ComPacket 크기 (바이트)
    void setMaxComPacketSize(uint32_t size) { maxComPacketSize_ = size; }

    /// @brief 현재 최대 ComPacket 크기 반환
    /// @return 최대 ComPacket 크기 (바이트)
    uint32_t maxComPacketSize() const { return maxComPacketSize_; }

    /// @brief 명령 타임아웃 설정
    /// @param ms  타임아웃 값 (밀리초)
    void setTimeout(uint32_t ms) { timeoutMs_ = ms; }

    /// @brief StartSession 응답 후 첫 in-session 호출 전 대기 시간(ms).
    ///
    /// 일부 TPer는 SyncSession 응답을 보낸 직후 잠시 동안 in-session 호출을
    /// 처리할 준비가 되어 있지 않아 0x0F(TPER_MALFUNCTION)으로 응답한다.
    /// 50~100ms 정도의 대기로 회피 가능. 기본값은 0.
    void setPostStartDelay(uint32_t ms) { postStartDelayMs_ = ms; }

    /// @brief 이 세션의 SSC 타입 설정 — Get/Set/Authenticate UID 선택에 사용됨.
    ///
    /// Opal/Pyrite(기본) 세션은 GET=0x16/SET=0x17/AUTHENTICATE=0x1C를 쓰고,
    /// Enterprise 세션은 EGET=0x06/ESET=0x07/EAUTHENTICATE=0x0C를 쓴다.
    /// Enterprise SP에 세션을 열 때는 반드시 이 값을 SscType::Enterprise 로
    /// 설정해야 EvalApi가 올바른 메서드 UID로 토큰을 빌드한다.
    void setSscType(SscType ssc) { sscType_ = ssc; }

    /// @brief 이 세션의 SSC 타입 반환 (기본: Opal20)
    SscType sscType() const { return sscType_; }

private:
    /// @brief ComPacket 전송 후 응답 수신 (재시도 처리 포함)
    Result sendRecv(const Bytes& sendData, Bytes& recvTokens);

    /// @brief 호스트 세션 번호 반환 (sedutil 호환: 항상 105)
    static uint32_t nextHostSessionNumber();

    std::shared_ptr<ITransport> transport_;
    PacketBuilder packetBuilder_;
    State state_ = State::Idle;
    uint16_t comId_ = 0;
    uint32_t tsn_ = 0;  // TPer session number
    uint32_t hsn_ = 0;  // Host session number
    uint32_t maxComPacketSize_ = 2048;
    uint32_t timeoutMs_ = 30000;
    uint32_t postStartDelayMs_ = 0;  // post-StartSession quiesce delay
    SscType sscType_ = SscType::Opal20;  // Default; call setSscType() for Enterprise
    static inline uint32_t sessionCounter_ = 105;  // sedutil hardcodes HSN=105
};

} // namespace libsed
