# TCG SED Examples Guide

20개 예제로 배우는 TCG SED 프로토콜 + libsed API 가이드.
초보(Discovery)부터 전문가(Fault Injection, Custom Transport)까지 단계별 학습 경로.

---

## 빌드

```bash
cmake -B build -DLIBSED_BUILD_EXAMPLES=ON
cmake --build build
```

실행 파일은 `build/examples/` 에 생성됩니다.

---

## 실행

```bash
# 기본 실행 (NVMe/ATA/SCSI 자동 감지)
./build/examples/01_hello_discovery /dev/nvme0

# 패킷 덤프 (IF-SEND/IF-RECV hex dump)
./build/examples/01_hello_discovery /dev/nvme0 --dump

# 명령 로그 파일 저장
./build/examples/01_hello_discovery /dev/nvme0 --log --logdir /tmp
```

---

## CLI 옵션

모든 예제에 공통으로 적용됩니다.

| 옵션 | 설명 |
|------|------|
| `<device>` | 디바이스 경로 (필수). 예: `/dev/nvme0`, `/dev/sda` |
| `--dump` | stderr에 IF-SEND/IF-RECV 패킷 hex dump 출력 |
| `--log` | 명령 로그를 파일로 저장 |
| `--logdir D` | 로그 파일 디렉토리 (기본: `.`) |
| `--force` | 파괴적 작업 시 확인 프롬프트 건너뛰기 |
| `--password PW` | 테스트 비밀번호 지정 (기본값 대신 사용) |
| `--help` | 도움말 출력 |

### 비밀번호 우선순위

1. `--password` CLI 플래그
2. `SED_PASSWORD` 환경변수
3. 예제별 기본값 (예: `TestSid05`)

```bash
# CLI로 비밀번호 지정
./build/examples/05_take_ownership /dev/nvme0 --password "MySecret" --force

# 환경변수로 지정
export SED_PASSWORD="MySecret"
./build/examples/05_take_ownership /dev/nvme0 --force
```

### 안전 잠금 (Safety Interlocks)

파괴적 예제(05, 11, 12)는 실행 전 확인 프롬프트가 표시됩니다:

```
WARNING: This will change the SID password on /dev/nvme0
Are you sure? [y/N]
```

`--force` 플래그로 건너뛸 수 있습니다. 자동화 스크립트에서 유용합니다.

---

## 학습 트랙

### Beginner (01-06): SED 기초

처음 SED를 접하는 개발자를 위한 트랙. Discovery부터 Ownership까지.

| # | 예제 | TCG 개념 | 배우는 것 |
|---|------|----------|-----------|
| 01 | `hello_discovery` | Level 0 Discovery | 드라이브가 지원하는 기능 확인 (SSC, Feature Descriptors) |
| 02 | `properties` | Properties Exchange | Host↔TPer 협상 (MaxComPacketSize 등) |
| 03 | `sessions` | Session Lifecycle | TSN/HSN, 익명 vs 인증 세션, 세션 열기/닫기 |
| 04 | `read_msid` | C_PIN Table, MSID | Admin SP에서 공장 출하 자격증명 읽기 |
| 05 | `take_ownership` | SID Password 변경 | MSID → 사용자 비밀번호로 변경 (드라이브 소유권 확보) |
| 06 | `activate_locking` | Locking SP 활성화 | Manufactured-Inactive → Active 전환 |

**순서**: 01 → 02 → 03 → 04 → 05 → 06 (순서대로 읽으세요)

### Core Opal (07-12): 실전 기능

암호화 범위, 사용자, MBR, DataStore, 초기화 등 실전 운용에 필요한 기능.

| # | 예제 | TCG 개념 | 배우는 것 |
|---|------|----------|-----------|
| 07 | `locking_ranges` | Locking Range 설정 | RLE/WLE, 범위 잠금/해제, 범위 정보 조회 |
| 08 | `user_management` | User 관리 | User1 활성화, 비밀번호 설정, ACE 권한 부여 |
| 09 | `mbr_shadow` | Shadow MBR | PBA 이미지 쓰기, MBRDone 플래그 제어 |
| 10 | `datastore` | DataStore (ByteTable) | 드라이브 내 영구 데이터 저장/읽기 |
| 11 | `crypto_erase` | GenKey (키 회전) | AES 키 재생성으로 즉시 데이터 파기 |
| 12 | `factory_reset` | RevertSP, PSID Revert | SID 리버트 + PSID 비상 복구 |

**전제조건**: 01-06 완료

### Enterprise (13): Enterprise SSC

Opal과 다른 Enterprise SSC 드라이브 전용 트랙.

| # | 예제 | TCG 개념 | 배우는 것 |
|---|------|----------|-----------|
| 13 | `enterprise_bands` | Band, BandMaster, EraseMaster | Enterprise 밴드 관리, 권한 체계 |

**전제조건**: 01-05 (Opal 06-08은 불필요)

### Expert (14-20): 심화/디버깅

프로토콜 내부, 와이어 포맷, 결함 주입, 멀티스레딩, 커스텀 전송 계층.

| # | 예제 | TCG 개념 | 배우는 것 |
|---|------|----------|-----------|
| 14 | `error_handling` | Method Status, Auth Failure | 에러 코드 계층 (Transport/Protocol/Session/Method) |
| 15 | `wire_inspection` | ComPacket/Packet/SubPacket | 와이어 포맷 구조, 토큰 인코딩 바이트 분석 |
| 16 | `eval_step_by_step` | EvalApi 수동 제어 | RawResult로 송수신 페이로드 검사, 테이블 직접 접근 |
| 17 | `composite_patterns` | EvalComposite | 다단계 작업 묶기, CompositeResult 스텝 로깅 |
| 18 | `fault_injection` | FaultBuilder, TestContext | 결함 주입 포인트 24개, 에러 시나리오 재현 |
| 19 | `multi_session` | 동시 세션, 스레딩 | SedContext, 멀티스레드 Discovery, 세션 격리 |
| 20 | `custom_transport` | ITransport 구현 | 데코레이터 패턴 (CountingTransport, FilteringTransport) |
| 21 | `transactions` | StartTransaction / Commit / Rollback | 명시적 경계, RawResult로 NVMe + TCG 상태 분리 검사 |

**전제조건**: 01-05 + 해당 예제의 Prerequisites 참조

---

## API 계층 가이드

예제에서 사용하는 세 가지 API 계층:

### SedDrive (Facade)

```cpp
SedDrive drive("/dev/nvme0");
drive.query();                           // Discovery
drive.takeOwnership("MyPassword");       // 한 줄로 소유권 확보
drive.revert("MyPassword");              // 한 줄로 초기화
```

가장 간단. 내부적으로 EvalApi를 호출. 예제 01, 03, 05, 08, 11, 12, 19에서 사용.

### EvalApi (Low-Level)

```cpp
EvalApi api;
Session session(transport, comId);
api.startSession(session, uid::SP_ADMIN, false, ssr);
api.getCPin(session, uid::CPIN_MSID, msid);
api.closeSession(session);
```

모든 프로토콜 단계를 개별 함수로 호출. `RawResult`로 송수신 바이트까지 검사 가능.
상태 없음(stateless) — 스레드 안전. 대부분의 예제에서 사용.

### EvalComposite (Multi-Step)

```cpp
auto cr = composite::takeOwnership(api, transport, comId, "Password");
// cr.steps[]로 각 단계 결과 확인
// cr.passCount(), cr.failCount()
```

여러 EvalApi 호출을 묶은 편의 함수. 스텝별 로깅 포함. 예제 06, 12, 17에서 사용.

---

## 예제별 주의사항

### 파괴적 예제 (주의 필요)

- **05_take_ownership**: SID 비밀번호를 변경합니다. 예제 끝에서 자동으로 MSID로 복원합니다.
- **11_crypto_erase**: AES 키를 재생성합니다. 암호화된 데이터가 영구 손실됩니다.
- **12_factory_reset**: 드라이브를 공장 초기 상태로 되돌립니다. 모든 설정과 데이터가 삭제됩니다.

이 예제들은 `--force` 없이 실행하면 확인 프롬프트가 표시됩니다.

### 드라이브 상태 요구사항

- **01-04**: 아무 상태에서나 실행 가능 (읽기 전용)
- **05-12**: 공장 초기 상태(SID == MSID)에서 시작해야 합니다. 각 예제는 끝에서 cleanup합니다.
- **13**: Enterprise SSC 드라이브 필요
- **14-20**: 대부분 아무 상태에서나 실행 가능

### SimTransport로 하드웨어 없이 테스트

```bash
# SimTransport 사용 (디바이스 없이)
./build/examples/01_hello_discovery sim:opal
```

SimTransport는 소프트웨어 SED 시뮬레이터입니다. Discovery, Properties, Session 등 기본 프로토콜을 시뮬레이션합니다.

---

## 추천 학습 순서

### SED를 처음 접하는 개발자

```
01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 12
```

Discovery부터 사용자 관리까지 배운 뒤, Factory Reset으로 마무리.

### 프로토콜 디버깅이 목적인 개발자

```
01 → 04 → 15 → 16 → 14 → 18
```

Discovery → MSID → 와이어 포맷 → EvalApi 수동 제어 → 에러 처리 → 결함 주입.

### 테스트 프레임워크를 만드는 개발자

```
01 → 16 → 17 → 18 → 19 → 20
```

EvalApi → Composite → Fault Injection → 멀티스레딩 → 커스텀 Transport.
