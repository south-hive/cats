# TCG SED 스펙 강의

> **대상**: SED를 처음 접하는 개발자
> **목표**: 스펙 개념을 이해한 뒤 예제를 실행하며 체득
> **방식**: 각 챕터 읽기 → 해당 예제 실행 → 다음 챕터

---

## Chapter 0: SED란 무엇인가?

### 자기 암호화 드라이브 (Self-Encrypting Drive)

SED는 드라이브 내부에 AES 암호화 엔진이 내장된 저장장치입니다.

```
Host ──write──▶ [AES Engine] ──encrypted──▶ NAND/Platter
Host ◀──read─── [AES Engine] ◀──encrypted── NAND/Platter
```

핵심 특징:
- **항상 암호화**: 데이터가 미디어에 기록되는 순간부터 암호화됨
- **성능 영향 없음**: 하드웨어 AES 엔진이 처리하므로 소프트웨어 암호화와 달리 속도 저하 없음
- **키는 드라이브 내부**: AES 키가 드라이브 밖으로 나가지 않음
- **즉시 삭제**: 키를 바꾸면 이전 데이터는 순식간에 복구 불가능

### TCG (Trusted Computing Group)

SED를 제어하는 프로토콜 표준을 만든 단체입니다. 주요 스펙:

| 스펙 | 역할 |
|------|------|
| **TCG Core Spec** | 프로토콜 기본 구조 (패킷, 세션, 메서드 호출) |
| **Opal SSC 2.0** | 클라이언트 SSD/HDD용 (노트북, 데스크탑) |
| **Enterprise SSC** | 서버/데이터센터 SSD용 |
| **Pyrite SSC** | 암호화 없는 접근제어 전용 |

대부분의 NVMe SSD는 **Opal 2.0**을 지원합니다.

### 통신 방식

Host와 드라이브(TPer)는 NVMe/ATA/SCSI의 보안 명령으로 통신합니다:

```
Host                          TPer (드라이브)
  │                              │
  │── Security Send (IF-SEND) ──▶│   요청 전송
  │                              │
  │◀── Security Recv (IF-RECV) ──│   응답 수신
  │                              │
```

| 전송 방식 | Send 명령 | Receive 명령 |
|-----------|-----------|-------------|
| NVMe | Security Send (0x81) | Security Receive (0x82) |
| SCSI | Security Protocol Out (0xB5) | Security Protocol In (0xA2) |
| ATA | Trusted Send (0x5E) | Trusted Receive (0x5C) |

libsed의 `ITransport` 인터페이스가 이 차이를 추상화합니다.

---

## Chapter 1: Discovery — 드라이브가 뭘 할 수 있는지 물어보기

> 실습: `./01_hello_discovery /dev/nvme0`

### Level 0 Discovery

TCG SED 통신의 첫 단계입니다. 세션 없이, 인증 없이 실행할 수 있습니다.

```
Host ── IF-SEND(proto=0x01, comId=0x0001) ──▶ TPer
     ◀── IF-RECV(proto=0x01, comId=0x0001) ──
```

응답은 **ComPacket이 아닙니다** (이것 때문에 많은 버그가 발생합니다). 고유한 48바이트 헤더 + Feature Descriptor 목록입니다.

### Feature Descriptors

Discovery 응답에는 드라이브가 지원하는 기능이 Feature Descriptor로 나열됩니다:

| Feature Code | 이름 | 의미 |
|-------------|------|------|
| 0x0001 | **TPer** | 기본 TPer 기능 (ComID 관리, 스트리밍 지원 여부) |
| 0x0003 | **Locking** | 잠금 기능 지원 (암호화 가능 여부) |
| 0x0203 | **Opal v2** | Opal SSC 2.0 지원 (BaseComID, NumComIDs 포함) |
| 0x0100 | **Enterprise** | Enterprise SSC 지원 |
| 0x0201 | **Opal v1** | Opal SSC 1.0 |
| 0x0002 | **Geometry** | 논리/물리 블록 크기, 정렬 |

가장 중요한 정보:
- **BaseComID**: 이후 모든 통신에 사용할 ComID (보통 0x07FE)
- **SSC 타입**: Opal인지 Enterprise인지 — 이후 프로토콜 흐름이 달라짐
- **Locking 상태**: 잠금 기능이 활성화되어 있는지

### Discovery가 중요한 이유

1. ComID를 모르면 다음 단계(Properties, Session)를 진행할 수 없음
2. SSC 타입에 따라 사용할 API가 다름
3. Locking 상태로 현재 드라이브 설정 상태를 파악

```cpp
// libsed 코드
EvalApi api;
DiscoveryInfo info;
api.discovery0(transport, info);
// info.baseComId, info.primarySsc, info.lockingEnabled 등
```

---

## Chapter 2: Properties Exchange — 서로의 한계를 알려주기

> 실습: `./02_properties /dev/nvme0`

### 왜 필요한가?

Host와 TPer는 처리할 수 있는 패킷 크기가 다릅니다. 통신 전에 서로의 한계를 교환해야 합니다.

```
Host ──▶ "내 MaxComPacketSize는 65536이야"
     ◀── "내 MaxComPacketSize는 2048이야"
     
결과: 둘 다 2048 이하로 패킷을 보내야 함
```

### 교환되는 속성들

| 속성 | 의미 | 일반적인 값 |
|------|------|------------|
| MaxComPacketSize | 최대 ComPacket 크기 | 2048~65536 |
| MaxPacketSize | 최대 Packet 크기 | 2028~65516 |
| MaxIndTokenSize | 단일 토큰 최대 크기 | 1992~65480 |
| MaxAggTokenSize | 토큰 합계 최대 크기 | 1992~65480 |
| MaxMethods | 한 패킷 안 최대 메서드 수 | 1 |
| MaxSubpackets | 한 패킷 안 최대 SubPacket 수 | 1 |

### 프로토콜

Properties Exchange는 **Session Manager(SM)** 메서드입니다. 세션 없이 호출합니다.

```
Host ──▶ SM::Properties (method UID 0xFF01)
         { "MaxComPacketSize"=65536, "MaxPacketSize"=65516, ... }
     ◀── { TPerProperties: {...}, HostProperties: {...} }
```

TPer는 Host가 보낸 값을 자신의 한계에 맞게 조정해서 돌려보냅니다.

```cpp
PropertiesResult props;
api.exchangeProperties(transport, comId, props);
// props.tperMaxComPacketSize — 이 값 이하로 패킷을 만들어야 함
```

---

## Chapter 3: Session — 대화의 시작과 끝

> 실습: `./03_sessions /dev/nvme0`

### 세션이란?

TCG에서 모든 명령(Discovery, Properties 제외)은 세션 안에서 실행됩니다. 세션은 Host와 TPer 사이의 대화입니다.

```
Host ──▶ StartSession (SM method 0xFF02)
     ◀── SyncSession  (SM method 0xFF03)   ← TPer가 TSN 할당
     
  [ 세션 안에서 명령 실행 ]
     
Host ──▶ CloseSession (SM method 0xFF06)
```

### TSN과 HSN

| 식별자 | 누가 지정 | 역할 |
|--------|----------|------|
| **HSN** (Host Session Number) | Host | Host가 정하는 세션 번호 (보통 1) |
| **TSN** (TPer Session Number) | TPer | TPer가 할당하는 세션 번호 (고유) |

모든 패킷 헤더에 TSN/HSN 쌍이 들어갑니다. 이걸로 어떤 세션의 패킷인지 구분합니다.

### 익명 세션 vs 인증 세션

```
익명 세션 (Read-Only):
  StartSession(SP=Admin, write=false)
  → 읽기만 가능 (MSID 읽기 등)

인증 세션 (Read-Write):  
  StartSession(SP=Admin, write=true, auth=SID, challenge=password)
  → 읽기 + 쓰기 가능 (비밀번호 변경, 설정 변경 등)
```

### Security Provider (SP)

세션은 특정 SP에 대해 열립니다. SP는 드라이브의 "관리 도메인"입니다.

| SP | 역할 | 주요 작업 |
|----|------|----------|
| **Admin SP** | 드라이브 전체 관리 | SID 비밀번호, Locking SP 활성화, Revert |
| **Locking SP** | 잠금/암호화 관리 | 범위 설정, 잠금/해제, 사용자 관리 |

```
Admin SP  ─── 소유권, 활성화, 초기화
Locking SP ── 범위 잠금, 사용자, MBR, DataStore
```

```cpp
// 익명 세션
Session session(transport, comId);
api.startSession(session, uid::SP_ADMIN, false, ssr);

// 인증 세션
api.startSessionWithAuth(session, uid::SP_ADMIN, true,
                          uid::AUTH_SID, passwordBytes, ssr);
```

---

## Chapter 4: 자격증명 — MSID, SID, PSID

> 실습: `./04_read_msid /dev/nvme0`

### 세 가지 중요한 비밀번호

| 자격증명 | 저장 위치 | 변경 가능 | 용도 |
|----------|----------|----------|------|
| **MSID** | C_PIN_MSID | 불가 | 공장 출하 비밀번호. 드라이브 라벨에 인쇄됨 |
| **SID** | C_PIN_SID | 가능 | 관리자 비밀번호. 초기에는 MSID와 동일 |
| **PSID** | C_PIN_PSID | 불가 | 비상 복구용. 드라이브 라벨에 인쇄됨 |

### 공장 출하 상태

```
                  공장 출하
                  ────────
SID password  ==  MSID  (누구나 읽을 수 있음)
Locking SP    ==  Manufactured-Inactive (비활성)
Locking Ranges == 없음
Users          == 비활성
```

### C_PIN 테이블

비밀번호는 C_PIN 테이블에 저장됩니다. 각 행이 하나의 자격증명입니다.

```
C_PIN 테이블 (Admin SP):
┌──────────────┬───────────┬────────────┐
│ UID          │ Column 3  │ 의미       │
│              │ (PIN)     │            │
├──────────────┼───────────┼────────────┤
│ C_PIN_MSID   │ "abc..."  │ 공장 비밀번호 │
│ C_PIN_SID    │ "abc..."  │ 관리자 비번  │
│ C_PIN_PSID   │ "xyz..."  │ 비상 복구용  │
└──────────────┴───────────┴────────────┘
```

MSID는 익명 세션으로 읽을 수 있습니다 (보안 취약점이 아니라 설계 의도):

```cpp
// 익명 세션으로 MSID 읽기
api.startSession(session, uid::SP_ADMIN, false, ssr);
api.getCPin(session, uid::CPIN_MSID, msid);
api.closeSession(session);
```

---

## Chapter 5: 소유권 확보 — Take Ownership

> 실습: `./05_take_ownership /dev/nvme0 --force`

### 왜 소유권을 확보해야 하는가?

공장 출하 상태에서 SID == MSID입니다. MSID는 드라이브 라벨에 인쇄되어 있으므로, 누구나 관리자로 로그인할 수 있습니다. 소유권 확보 = SID 비밀번호를 아는 사람만 변경.

### 프로토콜 흐름

```
1. 익명 세션 → MSID 읽기
2. MSID로 SID 인증 세션 열기 (write=true)
3. Set(C_PIN_SID, column=PIN, "새 비밀번호")
4. 세션 닫기

결과: SID ≠ MSID → 비밀번호를 아는 사람만 관리 가능
```

### 소유권 확보 후 상태

```
                  소유권 확보 후
                  ──────────────
SID password  ==  "MySecret" (MSID와 다름)
MSID          ==  변경 없음 (영구 고정)
Locking SP    ==  아직 Manufactured-Inactive
```

소유권을 확보했다고 암호화가 시작되는 것은 아닙니다. 다음 단계(Locking SP 활성화)가 필요합니다.

---

## Chapter 6: Locking SP 활성화

> 실습: `./06_activate_locking /dev/nvme0 --force`

### Manufactured-Inactive → Active

Locking SP는 공장 출하 시 비활성 상태입니다. 활성화해야 잠금 기능을 사용할 수 있습니다.

```
Admin SP에서 SID 인증 ──▶ Activate(Locking SP)
```

### 활성화 후 변화

| 항목 | 활성화 전 | 활성화 후 |
|------|----------|----------|
| Locking SP | Manufactured-Inactive | Active |
| Global Range | 없음 | Range 0 (전체 디스크) |
| Admin1 | 존재하나 비번 없음 | 비밀번호 설정 가능 |
| User1-User8 | 비활성 | 활성화 가능 |
| C_PIN (Locking SP) | 비어있음 | Admin1 비번 설정 가능 |

### Admin1 비밀번호

Locking SP 활성화 후, Locking SP의 관리자(Admin1)에 비밀번호를 설정해야 합니다. Admin1은 Locking SP 안에서의 관리자이며, SID(Admin SP 관리자)와는 다릅니다.

```
Admin SP의 SID  ── 드라이브 전체 관리 (활성화, 초기화)
Locking SP의 Admin1 ── 잠금 관리 (범위, 사용자, MBR)
```

```cpp
// 활성화 (Admin SP에서)
composite::withSession(api, transport, comId,
    uid::SP_ADMIN, true, uid::AUTH_SID, sidPw,
    [&](Session& s) { return api.activate(s, uid::SP_LOCKING); });

// Admin1 비밀번호 설정 (Locking SP에서)
composite::withSession(api, transport, comId,
    uid::SP_LOCKING, true, uid::AUTH_ADMIN1, Bytes{},
    [&](Session& s) { return api.setAdmin1Password(s, "Admin1Pw"); });
```

---

## Chapter 7: Locking Range — 암호화 범위 설정

> 실습: `./07_locking_ranges /dev/nvme0`

### Locking Range란?

디스크의 특정 LBA 영역을 독립적으로 잠글 수 있는 단위입니다.

```
LBA 공간:
┌───────────────────────────────────────────────┐
│              Range 0 (Global)                 │
│  전체 디스크. 다른 Range가 없으면 이것이 전부  │
├───────────┬───────────────┬───────────────────┤
│  Range 1  │   Range 2     │   (나머지=Range 0) │
│  LBA 0-1K │   LBA 1K-10K  │                   │
└───────────┴───────────────┴───────────────────┘
```

### Range 속성

| 속성 | 의미 |
|------|------|
| RangeStart | 시작 LBA |
| RangeLength | LBA 개수 |
| ReadLockEnabled (RLE) | 읽기 잠금 활성화 여부 |
| WriteLockEnabled (WLE) | 쓰기 잠금 활성화 여부 |
| ReadLocked | 현재 읽기 잠금 상태 |
| WriteLocked | 현재 쓰기 잠금 상태 |
| ActiveKey | 이 범위의 AES 암호화 키 UID |

### 잠금의 의미

```
ReadLocked=true:  읽기 시도 → 드라이브가 에러 반환 (I/O error)
WriteLocked=true: 쓰기 시도 → 드라이브가 에러 반환 (I/O error)
```

운영체제가 해당 LBA를 접근하려 하면 드라이브가 명령을 거부합니다. 부팅도 불가능해집니다 (→ MBR Shadow로 해결).

### 설정 흐름

```
1. setRange(rangeId, startLBA, length, RLE=true, WLE=true)
2. lockRange(rangeId, readLock=true, writeLock=true)  ← 잠금
3. unlockRange(rangeId)                                ← 해제
```

---

## Chapter 8: 사용자 관리

> 실습: `./08_user_management /dev/nvme0`

### 권한 구조

```
Locking SP 내부:
┌────────────────────────────────────┐
│  Admin1 ── 모든 범위 관리           │
│  User1  ── Range 1 잠금/해제 권한   │
│  User2  ── Range 2 잠금/해제 권한   │
│  ...                               │
│  User8  ── Range 8 잠금/해제 권한   │
└────────────────────────────────────┘
```

### User 활성화 흐름

User는 기본적으로 비활성 상태입니다:

```
1. Admin1 인증 세션에서:
   enableUser(User1)                    ← 활성화
   setUserPassword(User1, "password")   ← 비밀번호 설정

2. ACE(Access Control Entry) 설정:
   assignRangeAce(rangeId=1, User1)     ← Range 1 잠금/해제 권한 부여
```

### ACE (Access Control Entry)

ACE는 "누가 무엇을 할 수 있는지" 정의합니다. Range별로 잠금/해제 권한을 부여합니다.

```
ACE_Locking_Range1_Set_RdLocked:
  → User1이 Range 1의 ReadLocked를 변경할 수 있음

ACE_Locking_Range1_Set_WrLocked:
  → User1이 Range 1의 WriteLocked를 변경할 수 있음
```

사용자가 자기 범위를 잠금/해제할 수 있게 하려면, 해당 ACE에 User UID를 설정해야 합니다.

---

## Chapter 9: Shadow MBR — 잠긴 디스크에서 부팅하기

> 실습: `./09_mbr_shadow /dev/nvme0`

### 문제

Range 0를 잠그면 OS가 부팅할 수 없습니다. MBR/GPT가 Range 0 안에 있기 때문입니다.

### 해결: Shadow MBR

드라이브가 "가짜 MBR"을 보여줍니다:

```
전원 ON, MBRDone=false:
  Host가 LBA 0 읽기 → Shadow MBR 반환 (PBA 이미지)
  
PBA가 비밀번호를 받아서 MBRDone=true 설정 + Range 해제:
  Host가 LBA 0 읽기 → 실제 디스크 데이터 반환 (잠금 해제됨)
```

### PBA (Pre-Boot Authentication)

Shadow MBR 영역에 쓰는 작은 OS 이미지입니다:

```
┌──────────────────────────┐
│  Shadow MBR (PBA 이미지)  │ ← 전원 켜면 이것이 보임
│  - 비밀번호 입력 화면     │
│  - TCG 통신으로 잠금 해제 │
│  - MBRDone=true 설정     │
│  - 리부트                │
└──────────────────────────┘
         ↓ 리부트 후
┌──────────────────────────┐
│  실제 OS (Windows 등)    │ ← 잠금 해제된 실제 데이터
└──────────────────────────┘
```

### MBR 제어 플래그

| 플래그 | 의미 |
|--------|------|
| MBREnabled | Shadow MBR 기능 활성화 여부 |
| MBRDone | false: Shadow MBR 표시 / true: 실제 데이터 표시 |

MBRDone은 전원 리셋(Power Cycle)마다 false로 돌아갑니다.

---

## Chapter 10: DataStore — 드라이브 내 영구 저장소

> 실습: `./10_datastore /dev/nvme0`

### DataStore란?

Locking SP가 관리하는 ByteTable입니다. 일반 I/O와 별도로, 소량의 데이터를 드라이브 내부에 영구 저장할 수 있습니다.

용도:
- PBA 설정 정보 저장
- 키 관리 메타데이터
- 드라이브 상태 태그

### 읽기/쓰기

```cpp
// 쓰기
api.writeDataStore(session, tableNumber=0, offset=0, data);

// 읽기
Bytes readBack;
api.readDataStore(session, tableNumber=0, offset=0, length, readBack);
```

크기는 Discovery에서 확인할 수 있습니다 (보통 수 KB ~ 수 MB).

---

## Chapter 11: Crypto Erase — 즉시 데이터 파기

> 실습: `./11_crypto_erase /dev/nvme0 --force`

### 원리

모든 데이터는 AES 키(K_AES)로 암호화되어 저장됩니다. **GenKey**를 호출하면 새로운 랜덤 키가 생성되고, 이전 키는 파기됩니다.

```
GenKey 전:
  데이터 ──[K_AES_old]──▶ 암호문 (미디어)
  데이터 ◀──[K_AES_old]── 암호문 (읽기 가능)

GenKey 후:
  데이터 ◀──[K_AES_new]── 암호문 (복호화 실패 = 쓰레기)
  K_AES_old는 영구 삭제됨
```

### 특징

- **즉시 완료**: 키만 바꾸면 됨. 1TB든 100TB든 밀리초 단위
- **복구 불가**: 이전 키가 드라이브 밖으로 나간 적이 없으므로 절대 복구 불가
- **범위별 독립**: Range 1만 erase해도 Range 2는 영향 없음
- **설정 보존**: 범위 구성(start, length, RLE/WLE)은 유지됨

### Secure Erase와의 차이

| | Crypto Erase (GenKey) | Secure Erase |
|---|---|---|
| 속도 | 밀리초 | 수 시간 |
| 방식 | 키 교체 | 미디어 전체 덮어쓰기 |
| 범위 | 범위별 가능 | 드라이브 전체 |

---

## Chapter 12: Factory Reset — 공장 초기화

> 실습: `./12_factory_reset /dev/nvme0 --force`

### 두 가지 방법

#### 1. RevertSP (SID 비밀번호 필요)

```
SID 인증 세션 ──▶ RevertSP(Admin SP)
```

결과:
- SID 비밀번호 → MSID로 복원
- Locking SP → Manufactured-Inactive
- 모든 범위, 사용자, MBR, DataStore 삭제
- 모든 AES 키 재생성 (데이터 영구 손실)

#### 2. PSID Revert (비밀번호 분실 시)

```
PSID 인증 세션 ──▶ RevertSP(Admin SP)
```

PSID는 드라이브 라벨에 인쇄된 32자리 코드입니다. SID 비밀번호를 잊었을 때 사용하는 **비상 탈출구**입니다. 결과는 RevertSP와 동일합니다.

### 언제 사용하는가?

| 상황 | 방법 |
|------|------|
| 테스트 후 정리 | RevertSP (SID) |
| 비밀번호 분실 | PSID Revert |
| 드라이브 폐기/재사용 | RevertSP 또는 PSID Revert |
| 드라이브 판매 전 | RevertSP (모든 데이터 파기 보장) |

---

## Chapter 13: Enterprise SSC — 서버용 SED

> 실습: `./13_enterprise_bands /dev/nvme0` (Enterprise 드라이브 필요)

### Opal과의 차이

| | Opal 2.0 | Enterprise |
|---|---|---|
| 대상 | 클라이언트 (노트북, PC) | 서버, 데이터센터 |
| 잠금 단위 | Locking Range | Band |
| 관리자 | Admin1 + User1-8 | BandMaster0-15 + EraseMaster |
| SP 구조 | Admin SP + Locking SP | Admin SP + Locking SP (구조 다름) |
| MBR Shadow | 지원 | 미지원 (서버는 불필요) |

### Band와 BandMaster

Enterprise에서는 Range 대신 **Band**, User 대신 **BandMaster**를 사용합니다.

```
BandMaster0 ── Band 0 관리 (잠금/해제/설정)
BandMaster1 ── Band 1 관리
...
EraseMaster ── 모든 Band의 Crypto Erase 권한
```

각 BandMaster는 자기 Band만 관리할 수 있습니다. EraseMaster는 모든 Band를 erase할 수 있습니다.

---

## Chapter 14: 에러 처리

> 실습: `./14_error_handling /dev/nvme0`

### 에러 계층

TCG 프로토콜에는 여러 단계의 에러가 있습니다:

```
┌─────────────────────────────────────┐
│ Layer 4: Method Status              │ ← 메서드 실행 결과
│   NotAuthorized, InvalidParameter   │
├─────────────────────────────────────┤
│ Layer 3: Session Errors             │ ← 세션 상태 문제
│   SessionNotOpen, SessionTimeout    │
├─────────────────────────────────────┤
│ Layer 2: Protocol Errors            │ ← 패킷 파싱 실패
│   MalformedResponse, EmptyPayload   │
├─────────────────────────────────────┤
│ Layer 1: Transport Errors           │ ← IF-SEND/IF-RECV 실패
│   TransportSendFailed, Timeout      │
└─────────────────────────────────────┘
```

### Method Status 코드

TCG 메서드가 반환하는 상태 코드입니다:

| 코드 | 이름 | 의미 |
|------|------|------|
| 0x00 | Success | 성공 |
| 0x01 | NotAuthorized | 권한 없음 (비밀번호 틀림, 권한 부족) |
| 0x02 | Obsolete | 사용되지 않는 메서드 |
| 0x03 | SPBusy | SP가 다른 세션으로 바쁨 |
| 0x04 | SPFailed | SP 내부 오류 |
| 0x05 | SPDisabled | SP 비활성 (Locking SP 미활성화) |
| 0x06 | SPFrozen | SP 동결 (변경 불가) |
| 0x0C | InvalidParameter | 잘못된 파라미터 |
| 0x0F | UniquenessFailed | 중복 값 |
| 0x10 | TokenSyntaxError | 토큰 파싱 실패 |

가장 흔한 에러:
- **NotAuthorized**: 비밀번호 틀림 또는 write 세션이 아닌데 쓰기 시도
- **InvalidParameter**: Properties 인코딩 오류, 잘못된 UID
- **SPDisabled**: Locking SP를 활성화하지 않고 접근 시도

---

## Chapter 15: 와이어 포맷 — 패킷 구조

> 실습: `./15_wire_inspection /dev/nvme0`

### 패킷 레이어

```
┌──────────────────────────────────────────┐
│ ComPacket Header (20 bytes)              │
│   extendedComId(4) + outstandingData(4)  │
│   + minTransfer(4) + length(4)           │
├──────────────────────────────────────────┤
│ Packet Header (24 bytes)                 │
│   TSN(4) + HSN(4) + seqNumber(4)        │
│   + ackType(2) + ack(4) + length(4)     │
├──────────────────────────────────────────┤
│ SubPacket Header (12 bytes)              │
│   kind(6) + length(4)                   │
├──────────────────────────────────────────┤
│ Token Payload                            │
│   메서드 호출 또는 응답 데이터            │
└──────────────────────────────────────────┘
```

### 토큰 인코딩

TCG는 자체 바이너리 인코딩을 사용합니다:

| 토큰 | 바이트 | 의미 |
|------|--------|------|
| Tiny Atom | 0x00-0x3F | 0-63 정수 (1바이트) |
| Short Atom | 0x80-0xBF | 짧은 바이트 시퀀스/정수 |
| Medium Atom | 0xC0-0xDF | 중간 길이 |
| Long Atom | 0xE0-0xE3 | 긴 데이터 |
| STARTLIST | 0xF0 | `[` 시작 |
| ENDLIST | 0xF1 | `]` 끝 |
| STARTNAME | 0xF2 | `name=` 시작 |
| ENDNAME | 0xF3 | `name=` 끝 |
| CALL | 0xF8 | 메서드 호출 시작 |
| ENDOFDATA | 0xF9 | 데이터 끝 |
| ENDOFSESSION | 0xFA | 세션 종료 |
| METHODSTATUS | 0xF0..F1 | 메서드 결과 상태 리스트 |

### 메서드 호출 예시

Get(C_PIN_MSID) 호출의 토큰 구조:

```
F8                    CALL
  [8B InvokingUID]    C_PIN_MSID (0x00000009 00000001)
  [8B MethodUID]      Get        (0x00000006 00000001)
  F0                  STARTLIST (파라미터)
    F0 F2 03 00 F3    STARTLIST STARTNAME 3 TinyAtom(0) ENDNAME
       F2 04 00 F3    STARTNAME 4 TinyAtom(0) ENDNAME
    F1                ENDLIST
  F1                  ENDLIST
F9                    ENDOFDATA
F0 00 00 00 F1        METHODSTATUS [0, 0, 0]
```

`--dump` 옵션을 사용하면 실제 전송되는 바이트를 확인할 수 있습니다.

---

## Chapter 16-20: Expert 영역

### Chapter 16: EvalApi 수동 제어

> 실습: `./16_eval_step_by_step /dev/nvme0`

EvalApi는 모든 프로토콜 단계를 개별 함수로 노출합니다. `RawResult`를 통해 실제 전송/수신된 바이트를 검사할 수 있습니다. 다른 구현체(sedutil 등)와 바이트 단위 비교가 가능합니다.

### Chapter 17: Composite 패턴

> 실습: `./17_composite_patterns /dev/nvme0`

여러 EvalApi 호출을 묶는 편의 함수입니다. `CompositeResult`로 각 단계의 성공/실패를 개별 추적할 수 있습니다.

### Chapter 18: Fault Injection

> 실습: `./18_fault_injection /dev/nvme0`

`FaultBuilder`로 특정 시점에 결함을 주입합니다. 24개 주입 포인트 (BeforeIfSend, AfterIfRecv 등). 에러 복구 테스트에 필수적입니다.

### Chapter 19: 멀티 세션과 스레딩

> 실습: `./19_multi_session /dev/nvme0`

TPer는 제한된 수의 동시 세션을 지원합니다 (보통 1-4개). `SedContext`로 스레드별 상태를 관리합니다. EvalApi는 stateless이므로 스레드 안전합니다.

### Chapter 20: Custom Transport

> 실습: `./20_custom_transport /dev/nvme0`

`ITransport` 인터페이스를 직접 구현하여 로깅, 필터링, 시뮬레이션 등을 추가합니다. 데코레이터 패턴으로 기존 Transport를 감쌉니다.

---

## 부록: 용어 사전

| 용어 | 뜻 |
|------|-----|
| **TPer** | Trusted Peripheral — 드라이브 (TCG 프로토콜을 구현하는 장치) |
| **SP** | Security Provider — 관리 도메인 (Admin SP, Locking SP) |
| **SSC** | Security Subsystem Class — 프로토콜 변종 (Opal, Enterprise, Pyrite) |
| **ComID** | Communication ID — Discovery에서 얻는 통신 채널 식별자 |
| **TSN** | TPer Session Number — TPer가 할당하는 세션 번호 |
| **HSN** | Host Session Number — Host가 지정하는 세션 번호 |
| **MSID** | Manufacturer SID — 공장 출하 비밀번호 (변경 불가) |
| **SID** | Security ID — 관리자 비밀번호 (변경 가능) |
| **PSID** | Physical Security ID — 비상 복구용 (드라이브 라벨에 인쇄) |
| **MBR** | Master Boot Record — 부팅 영역 |
| **PBA** | Pre-Boot Authentication — 부팅 전 인증 이미지 |
| **RLE** | Read Lock Enabled — 읽기 잠금 활성화 |
| **WLE** | Write Lock Enabled — 쓰기 잠금 활성화 |
| **ACE** | Access Control Entry — 권한 정의 |
| **GenKey** | Generate Key — AES 키 재생성 (Crypto Erase) |
| **SM** | Session Manager — 세션 관리 메서드 (Properties, StartSession 등) |
| **K_AES** | AES Encryption Key — 범위별 암호화 키 |

---

## 부록: 전체 프로토콜 흐름 (Opal 2.0)

```
전원 ON
  │
  ▼
Discovery ──▶ BaseComID, SSC 확인
  │
  ▼
Properties Exchange ──▶ MaxComPacketSize 협상
  │
  ▼
Anonymous Session (Admin SP) ──▶ MSID 읽기
  │
  ▼
Authenticated Session (Admin SP, SID) ──▶ SID 비밀번호 변경
  │
  ▼
Authenticated Session (Admin SP, SID) ──▶ Locking SP 활성화
  │
  ▼
Authenticated Session (Locking SP, Admin1) ──▶ Admin1 비밀번호 설정
  │                                           ──▶ Range 설정
  │                                           ──▶ User 활성화
  │                                           ──▶ MBR Shadow 설정
  ▼
운용 중:
  User 인증 ──▶ Range 잠금/해제
  │
  ▼
폐기/초기화:
  SID 인증 ──▶ RevertSP (공장 초기화)
  또는
  PSID 인증 ──▶ PSID Revert (비상 복구)
```
