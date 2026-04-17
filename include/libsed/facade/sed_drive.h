#pragma once

/// @file sed_drive.h
/// @brief TC 개발자용 SED 드라이브 facade — 가장 간단한 SED 제어 인터페이스.
///
/// 사용법:
/// @code
///   #include <cats.h>
///
///   SedDrive drive("/dev/nvme0");
///   drive.query();
///   printf("SSC: %s\n", drive.sscName());
///
///   auto session = drive.login(SP_ADMIN, "password", AUTH_SID);
///   session.setPin(CPIN_SID, "new_password");
/// @endcode

#include "../core/types.h"
#include "../core/error.h"
#include "../core/uid.h"
#include "../codec/token_list.h"
#include "../transport/i_transport.h"
#include "../transport/transport_factory.h"
#include "../discovery/discovery.h"
#include "../eval/eval_api.h"
#include "../session/session.h"
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <functional>

namespace libsed {

class SedSession;  // forward

// ═══════════════════════════════════════════════════════
//  SedDrive — 1 device = 1 instance
// ═══════════════════════════════════════════════════════

class SedDrive {
public:
    // ── 생성 ──

    /// 디바이스 경로로 생성 (NVMe/ATA/SCSI 자동 감지)
    explicit SedDrive(const std::string& devicePath);

    /// 디바이스 경로 + 명시적 ComID (multi-PF 지원)
    SedDrive(const std::string& devicePath, uint16_t comId);

    /// 기존 transport로 생성 (테스트/시뮬레이터용)
    explicit SedDrive(std::shared_ptr<ITransport> transport);

    /// transport + 명시적 ComID
    SedDrive(std::shared_ptr<ITransport> transport, uint16_t comId);

    ~SedDrive();

    // Move only
    SedDrive(SedDrive&&) noexcept;
    SedDrive& operator=(SedDrive&&) noexcept;
    SedDrive(const SedDrive&) = delete;
    SedDrive& operator=(const SedDrive&) = delete;

    // ── Query (Discovery + Properties + MSID) ──

    /// 드라이브 조회 — Discovery, Properties, MSID를 한 번에 수행
    Result query();

    /// SSC 타입
    SscType sscType() const;
    const char* sscName() const;

    /// Discovery 정보
    const DiscoveryInfo& info() const;

    /// MSID (query() 후 사용 가능, 읽기 제한 시 empty)
    const Bytes& msid() const;
    std::string msidString() const;

    /// 사용 중인 ComID
    uint16_t comId() const;

    /// ComID 변경 (multi-PF 전환)
    void setComId(uint16_t comId);

    /// 사용 가능한 ComID 개수 (Discovery에서 획득)
    uint16_t numComIds() const;

    /// Properties 교환 결과
    uint32_t maxComPacketSize() const;

    // ── 디버그 ──

    /// 패킷 dump 활성화 (stderr). verbosity: 1=decoded, 2=decoded+hex
    void enableDump(std::ostream& os = std::cerr, int verbosity = 1);

    /// 커맨드 로그 파일 활성화
    void enableLog(const std::string& logDir = ".");

    /// dump + log 동시 활성화. verbosity: 1=decoded, 2=decoded+hex
    void enableDumpAndLog(const std::string& logDir = ".", std::ostream& os = std::cerr,
                          int verbosity = 1);

    // ── 세션 (Multi-Session 지원) ──

    /// 인증 세션 열기 — RAII, 소멸 시 자동 종료
    /// @param spUid      SP UID (uid::SP_ADMIN, uid::SP_LOCKING 등)
    /// @param password   인증 비밀번호
    /// @param authUid    Authority UID (uid::AUTH_SID, uid::AUTH_ADMIN1 등)
    /// @param write      쓰기 세션 여부 (기본: true)
    SedSession login(Uid spUid, const std::string& password, Uid authUid,
                     bool write = true);

    /// 인증 세션 (Bytes credential)
    SedSession login(Uid spUid, const Bytes& credential, Uid authUid,
                     bool write = true);

    /// 익명 읽기 세션 열기
    SedSession loginAnonymous(Uid spUid);

    // ── 편의 메서드 (내부적으로 세션 열고 닫음) ──

    /// MSID 읽기 (익명 세션)
    Result readMsid(Bytes& msid);

    /// 소유권 획득: MSID로 AdminSP 인증 → SID PIN 변경
    Result takeOwnership(const std::string& newSidPassword);

    /// Locking SP 활성화
    Result activateLocking(const std::string& sidPassword);

    /// Locking Range 설정
    Result configureRange(uint32_t rangeId,
                          uint64_t rangeStart, uint64_t rangeLength,
                          const std::string& admin1Password);

    /// Range 잠금
    Result lockRange(uint32_t rangeId, const std::string& password,
                     uint32_t authId = 1);

    /// Range 잠금 해제
    Result unlockRange(uint32_t rangeId, const std::string& password,
                       uint32_t authId = 1);

    /// SID로 공장 초기화
    Result revert(const std::string& sidPassword);

    /// PSID로 공장 초기화 (SID 비밀번호 분실 시)
    Result psidRevert(const std::string& psid);

    /// Crypto Erase
    Result cryptoErase(uint32_t rangeId, const std::string& admin1Password);

    // ── User 관리 ──

    /// User 활성화 + 비밀번호 설정 + Range 할당 (한 번에)
    Result setupUser(uint32_t userId, const std::string& userPassword,
                     uint32_t rangeId, const std::string& admin1Password);

    // ── MBR ──

    /// MBR 활성화/비활성화
    Result setMbrEnable(bool enable, const std::string& admin1Password);

    /// MBR Done 설정
    Result setMbrDone(bool done, const std::string& admin1Password);

    // ── Enterprise Band 전용 ──

    /// Band 설정 (Enterprise SSC)
    Result configureBand(uint32_t bandId,
                         uint64_t bandStart, uint64_t bandLength,
                         const std::string& bandMasterPassword);

    /// Band 잠금 (Enterprise)
    Result lockBand(uint32_t bandId, const std::string& bandMasterPassword);

    /// Band 잠금 해제 (Enterprise)
    Result unlockBand(uint32_t bandId, const std::string& bandMasterPassword);

    // ── 고급 접근 (파워 유저용) ──

    /// EvalApi 직접 접근
    eval::EvalApi& api();

    /// Transport 직접 접근
    std::shared_ptr<ITransport> transport();

    /// Discovery 파서 직접 접근
    const Discovery& discovery() const;

    /// 세션 내에서 콜백 실행 (withSession 패턴)
    Result withSession(Uid spUid, const std::string& password, Uid authUid,
                       std::function<Result(Session&)> fn);

    /// 익명 세션 내에서 콜백 실행
    Result withAnonymousSession(Uid spUid,
                                std::function<Result(Session&)> fn);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};


// ═══════════════════════════════════════════════════════
//  SedSession — RAII 세션 래퍼
// ═══════════════════════════════════════════════════════

/// 세션 RAII 래퍼. 소멸 시 자동으로 세션을 닫는다.
/// move 가능, copy 불가. 여러 세션을 동시에 열 수 있다 (multi-session).
///
/// @code
///   auto s = drive.login(uid::SP_ADMIN, "pw", uid::AUTH_SID);
///   if (!s.ok()) { /* 세션 열기 실패 */ }
///   s.setPin(uid::CPIN_SID, "new_pw");
/// @endcode
class SedSession {
public:
    ~SedSession();

    // Move only
    SedSession(SedSession&&) noexcept;
    SedSession& operator=(SedSession&&) noexcept;
    SedSession(const SedSession&) = delete;
    SedSession& operator=(const SedSession&) = delete;

    /// 세션 열기 성공 여부
    bool ok() const;
    bool failed() const;
    Result openResult() const;

    /// 세션 활성 여부
    bool isActive() const;

    /// 세션 닫기 (소멸자에서 자동 호출)
    void close();

    // ── PIN 읽기/쓰기 ──

    /// C_PIN 테이블에서 PIN 읽기
    Result getPin(Uid cpinUid, Bytes& pin);

    /// C_PIN 테이블에 PIN 쓰기
    Result setPin(Uid cpinUid, const std::string& newPin);
    Result setPin(Uid cpinUid, const Bytes& newPin);

    // ── Locking Range ──

    /// Range 설정 (start, length, lock enable)
    Result setRange(uint32_t rangeId,
                    uint64_t rangeStart, uint64_t rangeLength,
                    bool readLockEnabled = true, bool writeLockEnabled = true);

    /// Range 잠금
    Result lockRange(uint32_t rangeId);

    /// Range 잠금 해제
    Result unlockRange(uint32_t rangeId);

    /// Range 정보 조회
    Result getRangeInfo(uint32_t rangeId, LockingRangeInfo& info);

    // ── SP 관리 ──

    /// SP 활성화
    Result activate(Uid spUid);

    /// SP Revert
    Result revertSP(Uid spUid);

    // ── User 관리 ──

    /// User 활성화
    Result enableUser(uint32_t userId);

    /// User 비밀번호 설정
    Result setUserPassword(uint32_t userId, const std::string& password);

    /// User를 Range에 할당
    Result assignUserToRange(uint32_t userId, uint32_t rangeId);

    // ── MBR ──

    Result setMbrEnable(bool enable);
    Result setMbrDone(bool done);
    Result writeMbr(uint64_t offset, const Bytes& data);
    Result readMbr(uint64_t offset, uint32_t length, Bytes& data);

    // ── Key / Erase ──

    Result genKey(Uid objectUid);
    Result cryptoErase(uint32_t rangeId);

    // ── Enterprise Band ──

    Result configureBand(uint32_t bandId,
                         uint64_t bandStart, uint64_t bandLength,
                         bool readLockEnabled = true, bool writeLockEnabled = true);
    Result lockBand(uint32_t bandId);
    Result unlockBand(uint32_t bandId);

    // ── DataStore ──

    Result writeDataStore(uint64_t offset, const Bytes& data);
    Result readDataStore(uint64_t offset, uint32_t length, Bytes& data);

    // ── Generic Table Access ──

    Result tableGet(Uid objectUid, uint32_t startCol, uint32_t endCol,
                    eval::TableResult& result);
    Result tableSet(Uid objectUid, const TokenList& values);

    // ── 고급 접근 ──

    /// 내부 Session 객체 직접 접근
    Session& raw();
    const Session& raw() const;

    /// EvalApi 접근
    eval::EvalApi& api();

private:
    friend class SedDrive;
    SedSession();  // failed session
    SedSession(std::unique_ptr<Session> session, eval::EvalApi& api,
               Result openResult);

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace libsed
