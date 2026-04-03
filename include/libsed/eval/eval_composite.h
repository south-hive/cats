#pragma once

/// @file eval_composite.h
/// @brief EvalApi 기반 복합(Composite) 유틸리티 함수.
///
/// EvalApi는 의도적으로 모든 프로토콜 단계를 독립 함수로 노출합니다(atomic).
/// 이 파일은 평가 TC 작성 시 **반복되는 다단계 시퀀스**를 한 줄 호출로
/// 제공하여 보일러플레이트를 제거합니다.
///
/// 설계 원칙:
///   - EvalApi의 atomic 메서드만 조합 (내부 상태 없음)
///   - 각 단계의 성공/실패를 StepLog에 기록 (디버그 용이)
///   - 세션을 함수 내부에서 열고 닫음 (호출자가 세션 관리 불필요)
///   - 실패 시 cleanup 보장 (세션 누수 방지)
///
/// 기존 코드의 sed_macro_util에 해당하며, 다음을 대체합니다:
///   - TcgMacroGetMsidCPin  → getMsid()
///   - TcgMacroRevert       → revertToFactory()
///   - TcgMacroPsidInjectionVerify → psidRevertAndVerify()
///
/// 사용 예:
/// @code
///   using namespace libsed::eval::composite;
///
///   // MSID 읽기 (세션 자동 관리)
///   Bytes msid;
///   auto r = getMsid(api, transport, comId, msid);
///
///   // 인증된 세션에서 콜백 실행
///   r = withSession(api, transport, comId, uid::SP_LOCKING, true,
///                   uid::AUTH_ADMIN1, admin1Cred,
///                   [&](Session& s) {
///                       return api.setRange(s, 1, 0, 2048, true, true, raw);
///                   });
///
///   // 팩토리 리셋
///   r = revertToFactory(api, transport, comId, sidCred);
/// @endcode

#include "eval_api.h"
#include "../security/hash_password.h"
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace libsed {
namespace eval {
namespace composite {

// ════════════════════════════════════════════════════════
//  결과 / 로그 구조체
// ════════════════════════════════════════════════════════

/// @brief 복합 연산의 개별 단계 기록
struct StepEntry {
    std::string name;               ///< 단계 이름
    Result      result;             ///< 단계 결과
    RawResult   raw;                ///< 원시 페이로드 (디버그용)
};

/// @brief 복합 연산 전체 결과
struct CompositeResult {
    Result                  overall;    ///< 최종 결과 (마지막 실패 또는 Success)
    std::vector<StepEntry>  steps;      ///< 단계별 로그

    /// @brief 전체 성공 여부
    bool ok() const { return overall.ok(); }

    /// @brief 실패 여부
    bool failed() const { return overall.failed(); }

    /// @brief 실패 메시지
    std::string message() const { return overall.message(); }

    /// @brief 성공한 단계 수
    uint32_t passCount() const {
        uint32_t n = 0;
        for (auto& s : steps) if (s.result.ok()) n++;
        return n;
    }

    /// @brief 실패한 단계 수
    uint32_t failCount() const {
        uint32_t n = 0;
        for (auto& s : steps) if (s.result.failed()) n++;
        return n;
    }
};

// ════════════════════════════════════════════════════════
//  1. getMsid — MSID PIN 읽기
// ════════════════════════════════════════════════════════

/// @brief 익명 AdminSP 세션으로 MSID C_PIN 값을 읽고 세션을 닫음.
///
/// 내부 시퀀스:
///   1. StartSession(AdminSP, Anybody, ReadOnly)
///   2. Get C_PIN_MSID → msid에 저장
///   3. CloseSession
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param msid      [out] 읽어온 MSID 바이트
/// @return 복합 결과 (단계별 로그 포함)
CompositeResult getMsid(EvalApi& api,
                        std::shared_ptr<ITransport> transport,
                        uint16_t comId,
                        Bytes& msid);

// ════════════════════════════════════════════════════════
//  2. takeOwnership — 소유권 확보
// ════════════════════════════════════════════════════════

/// @brief MSID 읽기 → SID 인증 → SID PIN 변경 → 세션 종료.
///
/// 내부 시퀀스:
///   1. getMsid()
///   2. StartSession(AdminSP, SID, MSID, Write)
///   3. SetCPin(C_PIN_SID, newSidPin)
///   4. CloseSession
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param newSidPw  설정할 새 SID 패스워드 문자열
/// @return 복합 결과
CompositeResult takeOwnership(EvalApi& api,
                              std::shared_ptr<ITransport> transport,
                              uint16_t comId,
                              const std::string& newSidPw);

// ════════════════════════════════════════════════════════
//  3. revertToFactory — 팩토리 초기화
// ════════════════════════════════════════════════════════

/// @brief SID 인증으로 RevertSP(AdminSP) 수행. 실패 시 PSID로 fallback.
///
/// 내부 시퀀스:
///   1. StartSession(AdminSP, SID, sidCred, Write)
///   2. RevertSP(AdminSP)
///   3. (세션은 TPer가 자동 종료)
///   4. SID 실패 시 → PSID 인증 → psidRevert
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param sidPw     SID 패스워드 문자열
/// @param psidPw    PSID 패스워드 문자열 (SID 실패 시 fallback, 빈 문자열이면 PSID 미시도)
/// @return 복합 결과
CompositeResult revertToFactory(EvalApi& api,
                                std::shared_ptr<ITransport> transport,
                                uint16_t comId,
                                const std::string& sidPw,
                                const std::string& psidPw = "");

// ════════════════════════════════════════════════════════
//  4. activateAndSetup — 활성화 + 사용자 설정
// ════════════════════════════════════════════════════════

/// @brief Locking SP 활성화 → Admin1/User1 비밀번호 설정 → ACE 구성.
///
/// 내부 시퀀스:
///   1. SID 인증 → AdminSP 세션
///   2. Activate(SP_LOCKING) (Manufactured-Inactive인 경우만)
///   3. CloseSession
///   4. Admin1 인증 → LockingSP 세션 (MSID로 시도, 실패 시 admin1Pw로)
///   5. SetAdmin1Password
///   6. EnableUser(1)
///   7. SetCPin(C_PIN_USER1, user1Pw)
///   8. AddAuthorityToAce(Range1 RdLock/WrLock, User1)
///   9. CloseSession
///
/// @param api        EvalApi 인스턴스
/// @param transport  전송 인터페이스
/// @param comId      사용할 ComID
/// @param sidPw      SID 패스워드
/// @param admin1Pw   Admin1 패스워드
/// @param user1Pw    User1 패스워드
/// @return 복합 결과
CompositeResult activateAndSetup(EvalApi& api,
                                 std::shared_ptr<ITransport> transport,
                                 uint16_t comId,
                                 const std::string& sidPw,
                                 const std::string& admin1Pw,
                                 const std::string& user1Pw);

// ════════════════════════════════════════════════════════
//  5. withSession — 인증된 세션 RAII 패턴
// ════════════════════════════════════════════════════════

/// @brief 세션을 열고 콜백을 실행한 후 세션을 닫는 RAII 래퍼.
///
/// 콜백 내에서 오류가 발생해도 세션은 반드시 닫힙니다.
/// RevertSP처럼 TPer가 세션을 닫는 경우에도 안전하게 처리합니다.
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param spUid     대상 SP UID
/// @param write     쓰기 세션 여부
/// @param authUid   Authority UID
/// @param credential 자격 증명 (바이트)
/// @param fn        세션에서 실행할 콜백 (Session& 받음)
/// @return 콜백의 반환값 (세션 열기 실패 시 해당 오류 코드)
Result withSession(EvalApi& api,
                   std::shared_ptr<ITransport> transport,
                   uint16_t comId,
                   uint64_t spUid,
                   bool write,
                   uint64_t authUid,
                   const Bytes& credential,
                   std::function<Result(Session&)> fn);

/// @brief 문자열 패스워드 버전
Result withSession(EvalApi& api,
                   std::shared_ptr<ITransport> transport,
                   uint16_t comId,
                   uint64_t spUid,
                   bool write,
                   uint64_t authUid,
                   const std::string& password,
                   std::function<Result(Session&)> fn);

/// @brief 익명 읽기 전용 세션 버전
Result withAnonymousSession(EvalApi& api,
                            std::shared_ptr<ITransport> transport,
                            uint16_t comId,
                            uint64_t spUid,
                            std::function<Result(Session&)> fn);

// ════════════════════════════════════════════════════════
//  6. psidRevertAndVerify — PSID 리셋 후 상태 검증
// ════════════════════════════════════════════════════════

/// @brief PSID 인증으로 Revert 후 MSID==SID 상태를 검증.
///
/// 내부 시퀀스:
///   1. StartSession(AdminSP, PSID, psidCred, Write)
///   2. PsidRevert
///   3. (세션 자동 종료)
///   4. getMsid() — Revert 후 MSID 읽기
///   5. verifyAuthority(AdminSP, SID, msid) — SID==MSID 확인
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param psidPw    PSID 패스워드 문자열
/// @return 복합 결과
CompositeResult psidRevertAndVerify(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    const std::string& psidPw);

// ════════════════════════════════════════════════════════
//  7. configureRangeAndLock — 범위 구성 + 잠금
// ════════════════════════════════════════════════════════

/// @brief Admin1 세션으로 Locking Range 구성 후 잠금/잠금해제 확인.
///
/// 내부 시퀀스:
///   1. Admin1 인증 → LockingSP 세션
///   2. SetRange(rangeId, start, len, RLE, WLE)
///   3. SetRangeLock(rangeId, true, true) — 잠금
///   4. SetRangeLock(rangeId, false, false) — 잠금 해제
///   5. GetLockingInfo(rangeId) — 검증
///   6. CloseSession
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param admin1Pw  Admin1 패스워드
/// @param rangeId   잠금 범위 ID
/// @param start     범위 시작 LBA
/// @param length    범위 길이 (섹터)
/// @return 복합 결과
CompositeResult configureRangeAndLock(EvalApi& api,
                                      std::shared_ptr<ITransport> transport,
                                      uint16_t comId,
                                      const std::string& admin1Pw,
                                      uint32_t rangeId,
                                      uint64_t start,
                                      uint64_t length);

// ════════════════════════════════════════════════════════
//  8. mbrWriteAndVerify — MBR 쓰기 + 읽기 비교
// ════════════════════════════════════════════════════════

/// @brief MBR 활성화 → 데이터 쓰기 → 읽기 비교 → MBRDone 설정.
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param admin1Pw  Admin1 패스워드
/// @param data      쓸 MBR 데이터
/// @return 복합 결과
CompositeResult mbrWriteAndVerify(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& admin1Pw,
                                   const Bytes& data);

// ════════════════════════════════════════════════════════
//  9. dataStoreRoundTrip — DataStore 쓰기/읽기/비교
// ════════════════════════════════════════════════════════

/// @brief DataStore에 데이터 쓰기 → 읽기 → 비교 수행.
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param admin1Pw  Admin1 패스워드
/// @param offset    DataStore 오프셋
/// @param data      쓸 데이터
/// @return 복합 결과
CompositeResult dataStoreRoundTrip(EvalApi& api,
                                    std::shared_ptr<ITransport> transport,
                                    uint16_t comId,
                                    const std::string& admin1Pw,
                                    uint32_t offset,
                                    const Bytes& data);

// ════════════════════════════════════════════════════════
//  10. blockSidAndVerify — NVMe Block SID 설정/검증
// ════════════════════════════════════════════════════════

/// @brief NVMe Block SID Feature 설정 → SID 인증 차단 확인 → 해제.
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param sidPw     SID 패스워드 (차단 확인용)
/// @return 복합 결과
CompositeResult blockSidAndVerify(EvalApi& api,
                                   std::shared_ptr<ITransport> transport,
                                   uint16_t comId,
                                   const std::string& sidPw);

// ════════════════════════════════════════════════════════
//  11. cryptoEraseAndVerify — 암호화 소거 + 키 변경 확인
// ════════════════════════════════════════════════════════

/// @brief Range의 ActiveKey를 읽고 CryptoErase 후 키 변경을 확인.
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param admin1Pw  Admin1 패스워드
/// @param rangeId   소거할 잠금 범위 ID
/// @return 복합 결과 (steps[2]에 키 변경 여부 포함)
CompositeResult cryptoEraseAndVerify(EvalApi& api,
                                      std::shared_ptr<ITransport> transport,
                                      uint16_t comId,
                                      const std::string& admin1Pw,
                                      uint32_t rangeId);

// ═════════════════════════════════���══════════════════════
//  12. revertLockingSP — Locking SP만 Revert
// ════════════════════════════════════════════════════════

/// @brief Admin1 인증으로 Locking SP만 Revert.
///
/// RevertSP(SP_LOCKING) 후 TPer가 세션을 자동 종료합니다.
///
/// @param api       EvalApi 인스턴스
/// @param transport 전송 인터페이스
/// @param comId     사용할 ComID
/// @param admin1Pw  Admin1 패스워드
/// @return 복합 결과
CompositeResult revertLockingSP(EvalApi& api,
                                std::shared_ptr<ITransport> transport,
                                uint16_t comId,
                                const std::string& admin1Pw);

} // namespace composite
} // namespace eval
} // namespace libsed
