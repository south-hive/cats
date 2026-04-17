# TC 레시피 모음 (Cookbook)

복사-붙여넣기로 바로 쓸 수 있는 코드 레시피 모음입니다.
모든 레시���는 `#include <cats.h>`와 `using namespace libsed;`를 가정합니다.

---

## 레시피 1: 드라이브 정보 확인

```cpp
SedDrive drive("/dev/nvme0");
if (drive.query().failed()) return 1;

printf("SSC: %s\n", drive.sscName());
printf("ComID: 0x%04X\n", drive.comId());
printf("Locked: %s\n", drive.info().locked ? "YES" : "NO");
printf("MSID: %s\n", drive.msidString().c_str());
```

---

## 레시피 2: 소유권 확보 (공�� 초기 상태)

```cpp
SedDrive drive("/dev/nvme0");
drive.query();
auto r = drive.takeOwnership("my_sid_password");
if (r.failed()) printf("실패: %s\n", r.message().c_str());
```

---

## 레시피 3: Opal 전체 설정 (한 번에)

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

drive.takeOwnership("sid_pw");
drive.activateLocking("sid_pw");
drive.configureRange(1, 0, 1048576, "admin1_pw");
drive.setupUser(1, "user1_pw", 1, "admin1_pw");
```

---

## 레시피 4: Range 잠금/해제

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

// 잠금 (authId: 1=Admin1, 또는 User 번호)
drive.lockRange(1, "user1_pw", 1);

// 해제
drive.unlockRange(1, "user1_pw", 1);
```

---

## 레시피 5: Range 상태 확인

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

auto s = drive.login(uid::SP_LOCKING, "admin1_pw", uid::AUTH_ADMIN1);
LockingRangeInfo info;
s.getRangeInfo(1, info);

printf("Range 1: start=%lu, len=%lu\n", info.rangeStart, info.rangeLength);
printf("  ReadLocked=%d, WriteLocked=%d\n", info.readLocked, info.writeLocked);
```

---

## 레시피 6: MSID 직접 읽기

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

// 방법 1: query() 후 캐시된 값
printf("MSID: %s\n", drive.msidString().c_str());

// 방법 2: 직접 읽기
Bytes msid;
drive.readMsid(msid);
```

---

## 레시피 7: 비밀번호 변경

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

// SID 비밀번호 변경
auto s = drive.login(uid::SP_ADMIN, "old_pw", uid::AUTH_SID);
s.setPin(uid::CPIN_SID, "new_pw");

// Admin1 비밀번호 변경 (LockingSP)
auto s2 = drive.login(uid::SP_LOCKING, "old_admin1", uid::AUTH_ADMIN1);
s2.setPin(uid::CPIN_ADMIN1, "new_admin1");
```

---

## 레시피 8: User 추가

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

// User 2를 Range 1에 할당
drive.setupUser(2, "user2_pw", 1, "admin1_pw");
```

---

## 레시피 9: Crypto Erase (암호화 키 폐기)

```cpp
SedDrive drive("/dev/nvme0");
drive.query();
drive.cryptoErase(1, "admin1_pw");
// Range 1의 데이터는 이제 복구 불가
```

---

## 레시피 10: MBR (Shadow MBR)

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

// MBR 활성화
drive.setMbrEnable(true, "admin1_pw");

// PBA 이미지 쓰기
auto s = drive.login(uid::SP_LOCKING, "admin1_pw", uid::AUTH_ADMIN1);
Bytes pbaImage = /* PBA 이미지 데이터 */;
s.writeMbr(0, pbaImage);
s.setMbrDone(true);  // 부팅 시 원래 디스크로 전환
```

---

## 레시피 11: DataStore 읽기/쓰기

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

auto s = drive.login(uid::SP_LOCKING, "admin1_pw", uid::AUTH_ADMIN1);

// 쓰기
Bytes data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
s.writeDataStore(0, data);

// 읽기
Bytes readBack;
s.readDataStore(0, 5, readBack);
```

---

## 레시피 12: 공장 초기화

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

// 방법 1: SID 비밀번호를 아는 경우
drive.revert("sid_pw");

// 방법 2: 비밀번호 분실 (드라이브 라벨의 PSID 사용)
drive.psidRevert("PSID_FROM_LABEL");
```

---

## 레시피 13: Multi-PF (여러 ComID)

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

printf("ComIDs: %d개 (0x%04X부터)\n", drive.numComIds(), drive.comId());

// PF1으로 전환
drive.setComId(drive.comId() + 1);

// 또는 생성 시 지정
SedDrive pf1("/dev/nvme0", 0x0002);
```

---

## 레시피 14: 패킷 디버그

```cpp
SedDrive drive("/dev/nvme0");
drive.enableDump();                              // stderr에 decoded 패킷
drive.enableLogFile("/tmp/run42.sed.log");       // 파일에 decoded + raw hex
drive.query();                                    // Discovery/Properties가 둘 다에 출력
```

CLI로 동일하게: `./my_tool /dev/nvme0 --dump --logfile /tmp/run42.sed.log`.
`--logfile`이 없으면 `--log`가 자동 파일명(`<exe>_<timestamp>.sed.log`)을 만든다.
라이브러리 내부 흐름 로그(`LIBSED_INFO` 등)까지 파일로 남기려면
`--flow-log PATH` 또는 `libsed::installDefaultFlowLog(path)`.

---

## 레시피 15: Enterprise Band

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

if (drive.sscType() == SscType::Enterprise) {
    drive.configureBand(0, 0, 1048576, "bm0_pw");
    drive.lockBand(0, "bm0_pw");
    drive.unlockBand(0, "bm0_pw");
}
```

---

## 레시피 16: withSession 패턴

```cpp
SedDrive drive("/dev/nvme0");
drive.query();

// 세션을 열고 작업 후 자동 닫기
auto r = drive.withSession(
    uid::SP_LOCKING, "admin1_pw", uid::AUTH_ADMIN1,
    [](Session& s) -> Result {
        // 여기서 EvalApi 직접 사용 가능
        return Result::success();
    });
```

---

## 레시피 17: 에러 처리 패턴

```cpp
SedDrive drive("/dev/nvme0");

// 패턴 1: 간단한 확인
if (drive.query().failed()) return 1;

// 패�� 2: 메시지 출력
auto r = drive.takeOwnership("pw");
if (r.failed()) {
    printf("실패: %s\n", r.message().c_str());
    return 1;
}

// 패턴 3: 에러 코드별 분기
if (r.code() == ErrorCode::MethodNotAuthorized) {
    printf("비밀번호 틀림\n");
} else if (r.code() == ErrorCode::AuthLockedOut) {
    printf("잠김 — power cycle 필요\n");
}
```
