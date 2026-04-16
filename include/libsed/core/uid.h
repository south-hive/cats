#pragma once

#include "types.h"

namespace libsed {
namespace uid {

// ══════════════════════════════════════════════════════
//  세션 매니저 UID
//  TCG 세션 관리에 사용되는 기본 UID
// ══════════════════════════════════════════════════════
inline constexpr uint64_t SMUID          = 0x00000000000000FF;  ///< Session Manager UID (세션 매니저 호출 대상)
inline constexpr uint64_t THIS_SP        = 0x0000000000000001;  ///< 현재 SP를 지칭하는 특수 UID
inline constexpr uint64_t UID_HEXFF      = 0xFFFFFFFFFFFFFFFF;  ///< Null/sentinel UID — "no authority" (인증 없음 표시)

// ══════════════════════════════════════════════════════
//  보안 제공자(Security Provider) UID
//  각 SP는 독립적인 보안 도메인을 나타낸다
// ══════════════════════════════════════════════════════
inline constexpr uint64_t SP_ADMIN       = 0x0000020500000001;  ///< Admin SP — 드라이브 관리 및 초기 설정용 SP
inline constexpr uint64_t SP_LOCKING     = 0x0000020500000002;  ///< Locking SP — 데이터 잠금/암호화 관리용 SP (Opal)
inline constexpr uint64_t SP_ENTERPRISE  = 0x0000020500010001;  ///< Enterprise SP — 데이터센터용 잠금 관리 SP (Enterprise SSC)

// ══════════════════════════════════════════════════════
//  Authority(권한 주체) UID
//  인증 및 권한 부여에 사용되는 Authority 객체
// ══════════════════════════════════════════════════════
inline constexpr uint64_t AUTH_ANYBODY   = 0x0000000900000001;  ///< Anybody Authority — 인증 없이 접근 가능한 공개 권한
inline constexpr uint64_t AUTH_ADMINS    = 0x0000000900000002;  ///< Admins Authority — 관리자 그룹 권한
inline constexpr uint64_t AUTH_MAKERS    = 0x0000000900000003;  ///< Makers Authority — 제조사 권한 (공장 초기화 등)
inline constexpr uint64_t AUTH_SID       = 0x0000000900000006;  ///< SID (Security Identifier) — 드라이브 소유자 최상위 권한
inline constexpr uint64_t AUTH_PSID      = 0x000000090001FF01;  ///< PSID (Physical Security ID) — 물리적 리셋용 권한 (라벨에 인쇄)
inline constexpr uint64_t AUTH_MSID      = 0x0000000900008402;  ///< MSID (Manufactured SID) — 제조 시 설정된 기본 비밀번호 권한

/// @name Admin SP 관리자 Authority
/// @brief Admin SP 내에서 세부 관리 권한을 가진 Admin Authority (1~4)
/// @{
inline constexpr uint64_t AUTH_ADMIN1    = 0x0000000900010001;  ///< Admin1 Authority — Admin SP 관리자 1
inline constexpr uint64_t AUTH_ADMIN2    = 0x0000000900010002;  ///< Admin2 Authority — Admin SP 관리자 2
inline constexpr uint64_t AUTH_ADMIN3    = 0x0000000900010003;  ///< Admin3 Authority — Admin SP 관리자 3
inline constexpr uint64_t AUTH_ADMIN4    = 0x0000000900010004;  ///< Admin4 Authority — Admin SP 관리자 4
/// @}

/// @name Locking SP 사용자 Authority
/// @brief Locking SP에서 잠금 범위 접근 제어에 사용되는 User Authority (1~9)
/// @{
inline constexpr uint64_t AUTH_USER1     = 0x0000000900030001;  ///< User1 Authority — Locking SP 사용자 1
inline constexpr uint64_t AUTH_USER2     = 0x0000000900030002;  ///< User2 Authority — Locking SP 사용자 2
inline constexpr uint64_t AUTH_USER3     = 0x0000000900030003;  ///< User3 Authority — Locking SP 사용자 3
inline constexpr uint64_t AUTH_USER4     = 0x0000000900030004;  ///< User4 Authority — Locking SP 사용자 4
inline constexpr uint64_t AUTH_USER5     = 0x0000000900030005;  ///< User5 Authority — Locking SP 사용자 5
inline constexpr uint64_t AUTH_USER6     = 0x0000000900030006;  ///< User6 Authority — Locking SP 사용자 6
inline constexpr uint64_t AUTH_USER7     = 0x0000000900030007;  ///< User7 Authority — Locking SP 사용자 7
inline constexpr uint64_t AUTH_USER8     = 0x0000000900030008;  ///< User8 Authority — Locking SP 사용자 8
inline constexpr uint64_t AUTH_USER9     = 0x0000000900030009;  ///< User9 Authority — Locking SP 사용자 9
/// @}

/// @name Enterprise SSC Authority
/// @brief Enterprise SSC 전용 Authority (EraseMaster, BandMaster)
/// @{
inline constexpr uint64_t AUTH_ERASEMASTER    = 0x0000000900008401;  ///< EraseMaster Authority — Enterprise SSC에서 밴드 초기화(Erase) 권한
inline constexpr uint64_t AUTH_BANDMASTER0    = 0x0000000900008001;  ///< BandMaster0 Authority — Enterprise SSC Band 0 관리 권한
inline constexpr uint64_t AUTH_BANDMASTER1    = 0x0000000900008002;  ///< BandMaster1 Authority — Enterprise SSC Band 1 관리 권한
inline constexpr uint64_t AUTH_BANDMASTER2    = 0x0000000900008003;  ///< BandMaster2 Authority — Enterprise SSC Band 2 관리 권한
/// @}

// ══════════════════════════════════════════════════════
//  테이블 UID
//  TCG 데이터 저장소의 각 테이블을 식별하는 UID
// ══════════════════════════════════════════════════════
inline constexpr uint64_t TABLE_SP       = 0x0000020500000000;  ///< SP 테이블 — Security Provider 목록 및 속성
inline constexpr uint64_t TABLE_LOCKING  = 0x0000080200000000;  ///< Locking 테이블 — 잠금 범위 구성 및 상태
inline constexpr uint64_t TABLE_MBRCTRL  = 0x0000080300000000;  ///< MBR Control 테이블 — MBR 섀도잉 제어
inline constexpr uint64_t TABLE_MBR      = 0x0000080400000000;  ///< MBR 테이블 — 섀도 MBR 데이터 저장
inline constexpr uint64_t TABLE_ACE      = 0x0000000800000000;  ///< ACE 테이블 — 접근 제어 요소 (Access Control Element)
inline constexpr uint64_t TABLE_AUTHORITY = 0x0000000900000000; ///< Authority 테이블 — Authority 객체 목록 및 속성
inline constexpr uint64_t TABLE_CPIN     = 0x0000000B00000000;  ///< C_PIN 테이블 — Authority별 PIN(비밀번호) 저장
inline constexpr uint64_t TABLE_DATASTORE = 0x0000100100000000; ///< DataStore 테이블 — 범용 데이터 저장 영역

/// @name Locking 테이블 행 UID
/// @brief Locking 테이블의 특정 행(잠금 범위)을 가리키는 UID
/// @{
inline constexpr uint64_t LOCKING_GLOBALRANGE   = 0x0000080200000001;  ///< Global Locking Range — 전체 디스크에 적용되는 기본 잠금 범위
inline constexpr uint64_t LOCKING_RANGE1        = 0x0000080200000002;  ///< Locking Range 1 — 사용자 정의 잠금 범위 1
inline constexpr uint64_t LOCKING_RANGE2        = 0x0000080200000003;  ///< Locking Range 2 — 사용자 정의 잠금 범위 2
/// @}

/// @name C_PIN 테이블 행 UID
/// @brief C_PIN 테이블에서 각 Authority의 비밀번호 행을 가리키는 UID
/// @{
inline constexpr uint64_t CPIN_SID       = 0x0000000B00000001;  ///< SID의 C_PIN 행 — SID Authority의 비밀번호
inline constexpr uint64_t CPIN_MSID      = 0x0000000B00008402;  ///< MSID의 C_PIN 행 — 제조 시 설정된 기본 비밀번호 (읽기 전용)
inline constexpr uint64_t CPIN_ADMIN1    = 0x0000000B00010001;  ///< Admin1의 C_PIN 행 — Admin1 Authority의 비밀번호
inline constexpr uint64_t CPIN_USER1     = 0x0000000B00030001;  ///< User1의 C_PIN 행 — User1 Authority의 비밀번호
inline constexpr uint64_t CPIN_USER2     = 0x0000000B00030002;  ///< User2의 C_PIN 행 — User2 Authority의 비밀번호
/// @}

/// @name MBR Control 테이블 행 UID
/// @{
inline constexpr uint64_t MBRCTRL_SET    = 0x0000080300000001;  ///< MBR Control 설정 행 — MBR Enable/Done 플래그 제어
/// @}

/// @name ACE(Access Control Element) 테이블 행 UID
/// @brief 잠금 범위의 읽기/쓰기 잠금 상태 변경 권한을 정의하는 ACE 행
/// @{
inline constexpr uint64_t ACE_LOCKING_RANGE_SET_RDLOCKED  = 0x000000080003E001;  ///< Locking Range 읽기 잠금 설정 ACE
inline constexpr uint64_t ACE_LOCKING_RANGE_SET_WRLOCKED  = 0x000000080003E801;  ///< Locking Range 쓰기 잠금 설정 ACE
inline constexpr uint64_t ACE_LOCKING_GLOBALRANGE_SET_RDLOCKED = 0x000000080003E000;  ///< Global Range 읽기 잠금 설정 ACE
inline constexpr uint64_t ACE_LOCKING_GLOBALRANGE_SET_WRLOCKED = 0x000000080003E800;  ///< Global Range 쓰기 잠금 설정 ACE
/// @}

/// @name K_AES(AES 암호화 키) 테이블 UID
/// @brief 잠금 범위별 AES 암호화 키를 관리하는 테이블 및 행 UID
/// @{
inline constexpr uint64_t TABLE_K_AES           = 0x0000080500000000;  ///< K_AES 테이블 — 암호화 키 저장 테이블
inline constexpr uint64_t K_AES_GLOBALRANGE     = 0x0000080500000001;  ///< Global Range의 AES 키 행
/// @}

/// @name Enterprise SSC Band 테이블 UID
/// @brief Enterprise SSC의 Band(잠금 영역) 관련 테이블 UID
/// @{
inline constexpr uint64_t TABLE_BAND            = 0x0000080200000000;  ///< Band 테이블 — Enterprise SSC 밴드 구성 (Locking 테이블과 동일)
inline constexpr uint64_t BAND_MASTER_TABLE     = 0x0000000900008000;  ///< BandMaster 테이블 — BandMaster Authority 기본 주소
/// @}

/// @name Enterprise C_PIN 테이블 행 UID
/// @brief Enterprise SSC 전용 Authority의 비밀번호 행
/// @{
inline constexpr uint64_t CPIN_BANDMASTER0      = 0x0000000B00008001;  ///< BandMaster0의 C_PIN 행 — BandMaster0 비밀번호
inline constexpr uint64_t CPIN_ERASEMASTER      = 0x0000000B00008401;  ///< EraseMaster의 C_PIN 행 — EraseMaster 비밀번호
/// @}

/// @name DataStore 테이블 행 UID
/// @{
inline constexpr uint64_t DATASTORE_TABLE_0     = 0x0000100100000000;  ///< DataStore 테이블 0 — 기본 데이터 저장 영역
/// @}

// ══════════════════════════════════════════════════════
//  열 번호 상수
//  각 테이블의 열(Column)을 식별하는 정수 상수
// ══════════════════════════════════════════════════════
namespace col {
    /// @name C_PIN 테이블 열
    /// @{
    inline constexpr uint32_t PIN            = 3;   ///< PIN 값 (비밀번호 바이트 배열)
    inline constexpr uint32_t PIN_TRIES_REMAINING = 4;  ///< PIN 남은 시도 횟수 (잠금까지 남은 인증 시도)
    inline constexpr uint32_t PIN_CHARSETS   = 5;   ///< PIN 허용 문자셋 (비밀번호에 허용되는 문자 집합)
    /// @}

    /// @name Locking 테이블 열
    /// @{
    inline constexpr uint32_t RANGE_START    = 3;   ///< 잠금 범위 시작 LBA
    inline constexpr uint32_t RANGE_LENGTH   = 4;   ///< 잠금 범위 길이 (LBA 단위)
    inline constexpr uint32_t READ_LOCK_EN   = 5;   ///< 읽기 잠금 활성화 여부 (bool)
    inline constexpr uint32_t WRITE_LOCK_EN  = 6;   ///< 쓰기 잠금 활성화 여부 (bool)
    inline constexpr uint32_t READ_LOCKED    = 7;   ///< 현재 읽기 잠금 상태 (bool)
    inline constexpr uint32_t WRITE_LOCKED   = 8;   ///< 현재 쓰기 잠금 상태 (bool)
    inline constexpr uint32_t LOCK_ON_RESET  = 9;   ///< 리셋 시 자동 잠금 설정 (리셋 유형 목록)
    inline constexpr uint32_t ACTIVE_KEY     = 10;  ///< 활성 암호화 키 참조 (K_AES 테이블 UID)
    /// @}

    /// @name MBR Control 테이블 열
    /// @{
    inline constexpr uint32_t MBR_ENABLE     = 1;   ///< MBR 섀도잉 활성화 여부 (bool)
    inline constexpr uint32_t MBR_DONE       = 2;   ///< MBR Done 플래그 — true이면 실제 MBR을 노출
    /// @}

    /// @name Authority 테이블 열
    /// @{
    inline constexpr uint32_t AUTH_ENABLED   = 5;   ///< Authority 활성화 여부 (bool)
    inline constexpr uint32_t AUTH_COMMON_NAME = 1;  ///< Authority 공통 이름 (문자열)
    inline constexpr uint32_t AUTH_IS_CLASS  = 4;   ///< 클래스 Authority 여부 (bool, 그룹 vs 개별)
    /// @}

    /// @name SP 테이블 열
    /// @{
    inline constexpr uint32_t LIFECYCLE      = 6;   ///< SP 수명 주기 상태 (Manufactured/ManufacturedInactive 등)
    /// @}

    /// @name DataStore/ByteTable 테이블 열
    /// @{
    inline constexpr uint32_t MAX_SIZE       = 3;   ///< 최대 저장 가능 크기 (바이트)
    inline constexpr uint32_t USED_SIZE      = 4;   ///< 현재 사용 중인 크기 (바이트)
    /// @}

    /// @name K_AES 테이블 열
    /// @{
    inline constexpr uint32_t KEY_MODE       = 5;   ///< 키 암호화 모드 (AES-128/AES-256 등)
    /// @}

    /// @name ACE 테이블 열
    /// @{
    inline constexpr uint32_t ACE_BOOLEAN_EXPR = 3;  ///< ACE 부울 표현식 — 접근 허용 조건 (Authority 조합)
    inline constexpr uint32_t ACE_COLUMNS    = 4;   ///< ACE 열 목록 — 이 ACE가 보호하는 열 목록
    /// @}
}

// ══════════════════════════════════════════════════════
//  헬퍼 함수: 인덱스 기반 Authority/C_PIN/Range UID 생성
//  기본 UID에 인덱스를 더하여 동적으로 UID를 생성한다
// ══════════════════════════════════════════════════════

/// @brief Locking SP의 User Authority UID를 인덱스로 생성한다
/// @param userIndex 사용자 인덱스 (1~9, User1~User9에 대응)
/// @return 해당 User Authority의 Uid 객체
inline Uid makeUserUid(uint32_t userIndex) {
    return Uid(0x0000000900030000ULL + userIndex);
}

/// @brief Admin SP의 Admin Authority UID를 인덱스로 생성한다
/// @param adminIndex 관리자 인덱스 (1~4, Admin1~Admin4에 대응)
/// @return 해당 Admin Authority의 Uid 객체
inline Uid makeAdminUid(uint32_t adminIndex) {
    return Uid(0x0000000900010000ULL + adminIndex);
}

/// @brief Enterprise SSC의 BandMaster Authority UID를 인덱스로 생성한다
/// @param bandIndex 밴드 인덱스 (0부터 시작, BandMaster0~에 대응)
/// @return 해당 BandMaster Authority의 Uid 객체
inline Uid makeBandMasterUid(uint32_t bandIndex) {
    return Uid(0x0000000900008000ULL + bandIndex);
}

/// @brief User Authority에 대응하는 C_PIN 테이블 행 UID를 생성한다
/// @param userIndex 사용자 인덱스 (1~9)
/// @return 해당 User의 C_PIN 행 Uid 객체
inline Uid makeCpinUserUid(uint32_t userIndex) {
    return Uid(0x0000000B00030000ULL + userIndex);
}

/// @brief Admin Authority에 대응하는 C_PIN 테이블 행 UID를 생성한다
/// @param adminIndex 관리자 인덱스 (1~4)
/// @return 해당 Admin의 C_PIN 행 Uid 객체
inline Uid makeCpinAdminUid(uint32_t adminIndex) {
    return Uid(0x0000000B00010000ULL + adminIndex);
}

/// @brief BandMaster Authority에 대응하는 C_PIN 테이블 행 UID를 생성한다
/// @param bandIndex 밴드 인덱스 (0부터 시작)
/// @return 해당 BandMaster의 C_PIN 행 Uid 객체
inline Uid makeCpinBandMasterUid(uint32_t bandIndex) {
    return Uid(0x0000000B00008000ULL + bandIndex);
}

/// @brief Locking 테이블의 잠금 범위 행 UID를 생성한다
/// @param rangeIndex 범위 인덱스 (0=GlobalRange, 1~N=사용자 정의 범위)
/// @return 해당 Locking Range의 Uid 객체
inline Uid makeLockingRangeUid(uint32_t rangeIndex) {
    // GlobalRange=0x01, Range1=0x02, Range2=0x03, ...
    return Uid(0x0000080200000001ULL + rangeIndex);
}

/// @brief 잠금 범위의 읽기 잠금 설정 ACE UID를 생성한다
/// @param rangeIndex 범위 인덱스 (0=GlobalRange, 1~N=사용자 정의 범위)
/// @return 해당 범위의 ReadLocked 설정 ACE Uid 객체
inline Uid makeAceLockingRangeSetRdLocked(uint32_t rangeIndex) {
    // sedutil: ACE_Locking_Range_Set_RdLocked = 00 00 00 08 00 03 E0 01 (Range 1)
    // Global: 00 00 00 08 00 03 E0 00
    return Uid(0x000000080003E000ULL + rangeIndex);
}

/// @brief 잠금 범위의 쓰기 잠금 설정 ACE UID를 생성한다
/// @param rangeIndex 범위 인덱스 (0=GlobalRange, 1~N=사용자 정의 범위)
/// @return 해당 범위의 WriteLocked 설정 ACE Uid 객체
inline Uid makeAceLockingRangeSetWrLocked(uint32_t rangeIndex) {
    // sedutil: ACE_Locking_Range_Set_WrLocked = 00 00 00 08 00 03 E8 01 (Range 1)
    // Global: 00 00 00 08 00 03 E8 00
    return Uid(0x000000080003E800ULL + rangeIndex);
}

/// @brief 잠금 범위의 AES 암호화 키 행 UID를 생성한다
/// @param rangeIndex 범위 인덱스 (0=GlobalRange, 1~N=사용자 정의 범위)
/// @return 해당 범위의 K_AES 행 Uid 객체
inline Uid makeKAesUid(uint32_t rangeIndex) {
    // K_AES: GlobalRange=0x01, Range1=0x02, ...
    return Uid(0x0000080500000001ULL + rangeIndex);
}

} // namespace uid
} // namespace libsed
