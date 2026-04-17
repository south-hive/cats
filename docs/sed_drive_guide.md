# TC 개발자 가이드

cats 라이브러리를 사용한 SED(Self-Encrypting Drive) 제어 가이드입니다.

---

## 1. 시작하기

### 헤더 하나만 include

```cpp
#include <cats.h>
using namespace libsed;
```

이것만으로 SedDrive, SedSession, 모든 UID 상수, Result 등을 사용할 수 있습니다.

### 빌드

```bash
cmake -B build -DLIBSED_BUILD_EXAMPLES=ON
cmake --build build
```

### 최소 코드

```cpp
#include <cats.h>
using namespace libsed;

int main() {
    SedDrive drive("/dev/nvme0");
    auto r = drive.query();
    if (r.failed()) return 1;

    printf("SSC: %s\n", drive.sscName());
    printf("MSID: %s\n", drive.msidString().c_str());
    return 0;
}
```

---

## 2. SedDrive — 핵심 클래스

`SedDrive`는 **1개 디바이스 = 1개 인스턴스** 원칙입니다.

### 생성

```cpp
// 자동 감지 (NVMe/ATA/SCSI)
SedDrive drive("/dev/nvme0");

// 특정 ComID 지정 (Multi-PF)
SedDrive drive("/dev/nvme0", 0x0002);
```

### 조회 (query)

`query()`는 다음을 한 번에 수행합니다:
1. Level 0 Discovery — SSC 타입, ComID, 기능 확인
2. StackReset — ComID 상태 초기화
3. Properties Exchange — TPer 속성 교환
4. MSID 읽기 — 공장 초기 비밀번호 (읽기 제한 시 빈 값)

```cpp
auto r = drive.query();
if (r.failed()) {
    printf("실패: %s\n", r.message().c_str());
    return 1;
}

// 조회 결과
drive.sscType()          // SscType::Opal20, Enterprise, Pyrite 등
drive.sscName()          // "Opal 2.0", "Enterprise", ...
drive.comId()            // 0x0001
drive.numComIds()        // Multi-PF 개수
drive.maxComPacketSize() // TPer 최대 패킷 크기
drive.msid()             // Bytes (바이트 배열)
drive.msidString()       // 문자열
drive.info()             // DiscoveryInfo 구조체
```

### 디버그 / 로깅

libsed 로그는 두 종류로 분리돼 있다:

1. **흐름(Flow) 로그** — `LIBSED_INFO/DEBUG/WARN/ERROR`가 내보내는 "라이브러리가
   지금 뭘 하고 있는가" 메시지. 기본 sink는 `StderrSink` (항상 화면). TC 플랫폼의
   로거로 흘리려면 `Logger::setSink()`. 화면+파일 동시에 쓰려면
   `installDefaultFlowLog("path")` 한 줄.
2. **패킷(Packet) 로그** — IF-SEND/IF-RECV 바이트를 Rosetta Stone 형태로 decoded
   해서 보여주고 파일에는 raw hex까지 같이 기록. `enableDump/enableLog`가 이걸
   제어한다.

```cpp
// 패킷 로그
drive.enableDump();                            // decoded → stderr
drive.enableLog("./logs");                     // 파일 (자동명: <exe>_<ts>.sed.log)
drive.enableLogFile("/tmp/run42.sed.log");     // 파일 (경로 직접 지정)
drive.enableDumpAndLog();                      // stderr + 자동명 파일
drive.enableDumpAndLogFile("/tmp/run42.sed.log"); // stderr + 지정 파일

// 흐름 로그
libsed::installDefaultFlowLog("/tmp/flow.log");   // 화면 + 파일
libsed::Logger::setSink(myPlatformSink);          // TC 플랫폼 로거로 교체
```

`enableLogFile`로 찍는 파일엔 verbosity와 상관없이 **decoded + raw hex가 항상** 들어간다 — 아카이브용이기 때문. 콘솔 스트림만 `--dump2` / `verbosity=2`로 raw hex를 켠다.

**중요**: `enableDump()` / `enableLog*()`는 `query()` 전에 호출하세요. query 과정도 덤프됩니다.

---

## 3. 에러 처리

모든 메서드는 `Result`를 반환합니다.

```cpp
Result r = drive.takeOwnership("password");

if (r.ok())     printf("성공\n");
if (r.failed()) printf("실패: %s\n", r.message().c_str());

// if문에서 직접 사용 가능
if (auto r = drive.query(); r.failed()) {
    return 1;
}
```

주요 에러 코드:

| 코드 | 의미 |
|------|------|
| `TransportOpenFailed` | 디바이스를 열 수 없음 (경로 확인, 권한 확인) |
| `DiscoveryFailed` | TCG SED가 아님 |
| `MethodNotAuthorized` | 비밀번호 틀림 |
| `AuthLockedOut` | 인증 시도 초과 (드라이브 잠김) |
| `MethodInvalidParam` | 파라미터 오류 |
| `SessionNotStarted` | 세션이 없는 상태에서 작업 시도 |

---

## 4. 편의 메서드 (세션 자동 관리)

세션을 직접 열 필요 없이 한 줄로 작업할 수 있습니다.

### 소유권 확보

```cpp
// MSID 읽기 → SID 인증 → SID PIN 변경 (내부 자동)
drive.takeOwnership("new_sid_password");
```

### Locking SP 활성화

```cpp
drive.activateLocking("sid_password");
```

### Range 설정 + 잠금/해제

```cpp
// Range 1: 0~1M sectors, Lock 활성화
drive.configureRange(1, 0, 1048576, "admin1_pw");

// 잠금 (User1 인증)
drive.lockRange(1, "user1_pw", 1);

// 해제
drive.unlockRange(1, "user1_pw", 1);
```

### User 설정

```cpp
// User1 활성화 + 비밀번호 설정 + Range 1 할당 (한 번에)
drive.setupUser(1, "user1_pw", 1, "admin1_pw");
```

### 공장 초기화

```cpp
drive.revert("sid_password");           // SID 비밀번호를 아는 경우
drive.psidRevert("PSID_FROM_LABEL");    // 비밀번호 분실 시 (드라이브 라벨 참조)
```

### Crypto Erase

```cpp
drive.cryptoErase(1, "admin1_pw");  // Range 1의 암호화 키 폐기
```

### MBR 설정

```cpp
drive.setMbrEnable(true, "admin1_pw");
drive.setMbrDone(true, "admin1_pw");
```

---

## 5. SedSession — 직접 세션 제어

더 세밀한 제어가 필요하면 세션을 직접 열 수 있습니다.

### 세션 열기

```cpp
// 인증 세션 (쓰기)
auto session = drive.login(
    uid::SP_ADMIN,     // SP UID
    "password",              // 비밀번호
    uid::AUTH_SID      // Authority UID
);

if (session.failed()) {
    printf("로그인 실패: %s\n", session.openResult().message().c_str());
    return 1;
}

// 익명 세션 (읽기 전용)
auto session = drive.loginAnonymous(uid::SP_ADMIN);
```

### 세션 내 작업

```cpp
// PIN 읽기/쓰기
Bytes pin;
session.getPin(uid::CPIN_MSID, pin);
session.setPin(uid::CPIN_SID, "new_password");

// Range 제어
session.setRange(1, 0, 1048576);     // Range 설정
session.lockRange(1);                 // 잠금
session.unlockRange(1);               // 해제

LockingRangeInfo info;
session.getRangeInfo(1, info);        // 정보 조회

// SP 관리
session.activate(uid::SP_LOCKING);
session.revertSP(uid::SP_ADMIN);

// User 관리
session.enableUser(1);
session.setUserPassword(1, "user1_pw");
session.assignUserToRange(1, 1);

// MBR
session.setMbrEnable(true);
session.setMbrDone(true);
session.writeMbr(0, data);
session.readMbr(0, 512, data);

// DataStore
session.writeDataStore(0, data);
session.readDataStore(0, 1024, data);

// Crypto
session.genKey(uid::makeKAesUid(1));
session.cryptoErase(1);
```

### 세션 닫기

```cpp
session.close();  // 명시적 닫기
// 또는 소멸자가 자동으로 닫음 (RAII)
```

### Multi-Session

여러 세션을 동시에 열 수 있습니다:

```cpp
auto s1 = drive.login(uid::SP_ADMIN, "sid_pw", uid::AUTH_SID);
auto s2 = drive.login(uid::SP_LOCKING, "admin1_pw", uid::AUTH_ADMIN1);

// s1, s2 독립적으로 사용
s1.setPin(uid::CPIN_SID, "new_pw");
s2.lockRange(1);
// 소멸자가 각각 자동 닫기
```

---

## 6. Multi-PF (Physical Function)

NVMe 드라이브가 여러 PF를 가진 경우, 각 PF는 별도의 ComID를 사용합니다.

```cpp
// Discovery에서 ComID 범위 확인
drive.query();
printf("Base: 0x%04X, 개수: %d\n", drive.comId(), drive.numComIds());

// 특정 PF 선택
drive.setComId(0x0002);  // PF1

// 또는 생성 시 지정
SedDrive pf1("/dev/nvme0", 0x0002);
```

---

## 7. Enterprise SSC (Band)

Enterprise SSC 드라이브는 Locking Range 대신 Band를 사용합니다.
BandMaster/EraseMaster 인증 체계를 따릅니다.

```cpp
// Band 설정
drive.configureBand(0, 0, 1048576, "bandmaster0_pw");

// Band 잠금/해제
drive.lockBand(0, "bandmaster0_pw");
drive.unlockBand(0, "bandmaster0_pw");

// 세션에서 직접
auto s = drive.login(uid::SP_LOCKING, "bm0_pw", uid::makeBandMasterUid(0));
s.configureBand(0, 0, 1048576);
s.lockBand(0);
s.unlockBand(0);
```

---

## 8. 파워 유저: 내부 API 접근

SedDrive/SedSession에 없는 기능이 필요하면, 내부 API에 직접 접근할 수 있습니다.

```cpp
// EvalApi 직접 사용
auto& api = drive.api();
auto transport = drive.transport();

// 세션 내부의 Session 객체
auto s = drive.login(...);
Session& rawSession = s.raw();

// withSession 패턴
drive.withSession(uid::SP_ADMIN, "pw", uid::AUTH_SID,
    [](Session& s) -> Result {
        // 여기서 EvalApi를 직접 호출
        return Result::success();
    });
```

---

## 9. 주요 UID 상수

코드에서 자주 쓰는 UID들:

### SP (Security Provider)

| 상수 | 설명 |
|------|------|
| `uid::SP_ADMIN` | AdminSP — 소유권, SP 활성화, Revert |
| `uid::SP_LOCKING` | LockingSP — Range 설정, 잠금/해제, User 관리 |

### Authority (인증 주체)

| 상수 | 설명 |
|------|------|
| `uid::AUTH_SID` | SID — AdminSP 관리자 |
| `uid::AUTH_PSID` | PSID — 물리 라벨 비밀번호 |
| `uid::AUTH_ADMIN1` | Admin1 — LockingSP 관리자 |
| `uid::makeUserUid(n)` | User N — LockingSP 사용자 |
| `uid::makeBandMasterUid(n)` | BandMaster N — Enterprise Band 관리자 |

### C_PIN (비밀번호 테이블)

| 상수 | 설명 |
|------|------|
| `uid::CPIN_SID` | SID 비밀번호 |
| `uid::CPIN_MSID` | MSID (공장 초기 비밀번호, 읽기 전용) |
| `uid::CPIN_ADMIN1` | Admin1 비밀번호 |

### Locking Range

| 상수 | 설명 |
|------|------|
| `uid::LOCKING_GLOBALRANGE` | Global Range (Range 0) |
| `uid::LOCKING_RANGE1` | Range 1 |
| `uid::makeLockingRangeUid(n)` | Range N (동적 생성) |

---

## 10. 전체 플로우 요약

### Opal 드라이브 설정 (공장 초기 → 잠금 가능)

```
query() → takeOwnership() → activateLocking() →
configureRange() → setupUser() → lockRange()
```

### 일상적인 잠금/해제

```
query() → lockRange() / unlockRange()
```

### 공장 초기화

```
query() → revert() 또는 psidRevert()
```

---

## 11. 예제 파일

| 파일 | 내용 |
|------|------|
| `examples/facade/01_query.cpp` | 드라이브 조회 |
| `examples/facade/02_take_ownership.cpp` | 소유권 확보 |
| `examples/facade/03_opal_full_setup.cpp` | Opal 전체 설정 |
| `examples/facade/04_multi_session.cpp` | 다중 세션 |
| `examples/facade/05_multi_pf.cpp` | Multi-PF |
| `examples/facade/06_enterprise_band.cpp` | Enterprise Band |
| `examples/facade/07_revert.cpp` | 공장 초기화 |

---

## 12. 문제 해결

### "Transport open failed"
- 디바이스 경로 확인 (`/dev/nvme0`, `/dev/sda`)
- root 권한 필요: `sudo ./program /dev/nvme0`

### "Discovery failed"
- TCG SED를 지원하지 않는 드라이브
- `--dump`로 Discovery 응답 확인

### "Method not authorized"
- 비밀번호 틀림
- 또는 해당 Authority로는 이 작업을 할 수 없음

### "Authority locked out"
- 비밀번호를 너무 많이 틀림
- Power cycle (전원 재투입) 후 재시도
- 최악의 경우 PSID Revert 필요

### "SP frozen"
- OS가 TCG freeze lock을 보냈음
- BIOS/UEFI에서 TCG freeze 비활성화
- 또는 OS 부팅 전 (PBA 단계에서) 작업 수행

### 디버그 방법
```cpp
drive.enableDump();  // 모든 패킷을 hex dump로 확인
drive.enableLog();   // 로그 파일에 기록
```
