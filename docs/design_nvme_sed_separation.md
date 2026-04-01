# NVMe + SED 이중 평가를 위한 인터페이스 분리 설계

> **목적:** 기존 스파게티 코드에서 ITransport에 몰려있는 NVMe/SED API를 역할별로 분리하여,
> NVMe 평가와 SED 평가를 동시에 수행할 수 있는 깔끔한 구조를 제시한다.

---

## 1. 현재 문제 진단

### 1.1 스파게티의 근본 원인

기존 코드에서 Transport 하나에 모든 것을 넣으면 다음과 같이 된다:

```
ITransport (비대해진 인터페이스)
  ├── ifSend / ifRecv              ← TCG Security Protocol (SED용)
  ├── identify()                   ← NVMe Admin
  ├── getLogPage()                 ← NVMe Admin
  ├── getFeature() / setFeature()  ← NVMe Admin
  ├── formatNvm()                  ← NVMe Admin
  ├── sanitize()                   ← NVMe Admin
  ├── fwDownload() / fwCommit()    ← NVMe Admin
  ├── nsCreate/Delete/Attach()     ← NVMe Namespace Mgmt
  ├── adminCommand()               ← NVMe Generic Admin
  ├── ioCommand()                  ← NVMe I/O
  └── read() / write()             ← NVMe I/O (LBA)
```

**문제점:**

| 문제 | 설명 |
|------|------|
| **다형성 파괴** | ATA/SCSI Transport는 NVMe Admin 명령을 구현할 수 없어 빈 stub 또는 `NotSupported` 반환 필요 |
| **단일 책임 위반** | "TCG 프로토콜 전송"과 "NVMe 디바이스 제어"는 독립된 관심사 |
| **테스트 어려움** | SED 단위 테스트에 NVMe mock까지 구현해야 함 |
| **확장성 저하** | NVMe 명령 추가 시 모든 Transport 구현체 수정 필요 |
| **스레드 모델 혼란** | Session(SED)과 Admin Command(NVMe)의 동시성 요구사항이 다름 |

### 1.2 역할 분석: 무엇이 SED이고 무엇이 NVMe인가

```
┌──────────────────────────────────────────────────────────────┐
│                    NVMe Controller                           │
│                                                              │
│  ┌─────────────────────┐  ┌────────────────────────────────┐ │
│  │ Security Protocol    │  │ Admin Command Set              │ │
│  │ (opcode 0x81/0x82)  │  │ (Identify, GetLogPage,         │ │
│  │                     │  │  Format, Sanitize, FW, NS, ...) │ │
│  │  → TCG SED 전용     │  │  → NVMe 평가 전용              │ │
│  └─────────────────────┘  └────────────────────────────────┘ │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ I/O Command Set (Read/Write/Compare/...)                │ │
│  │  → 데이터 무결성 평가, LBA 접근                          │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

핵심 관찰: **NVMe 컨트롤러 하나에 서로 다른 3가지 명령 집합이 공존하며, 각각 독립적인 평가 대상이다.**

---

## 2. 제안 아키텍처: 3-레이어 인터페이스 분리

### 2.1 인터페이스 분류 원칙

| 레이어 | 인터페이스 | 책임 | 사용자 |
|--------|-----------|------|--------|
| **L1: SED Transport** | `ITransport` | TCG Security Protocol IF-SEND/IF-RECV만 | EvalApi, Session |
| **L2: NVMe Device** | `INvmeDevice` | NVMe Admin/IO 명령 전체 | NVMe 평가 코드 |
| **L3: Unified Context** | `SedContext` | L1 + L2를 묶어서 스레드별 컨텍스트 제공 | Worker, 테스트 시나리오 |

### 2.2 아키텍처 다이어그램

```
┌─ 평가 시나리오 (Worker) ────────────────────────────────────┐
│                                                              │
│   SED 평가                          NVMe 평가               │
│   ─────────                         ──────────              │
│   ctx.api().startSession(...)       ctx.nvme()->identify()  │
│   ctx.api().getLockingInfo(...)      ctx.nvme()->formatNvm() │
│   ctx.api().revertSP(...)           ctx.nvme()->getLogPage()│
│        │                                   │                │
│        ▼                                   ▼                │
│   ┌─────────┐                      ┌──────────────┐        │
│   │ EvalApi  │ (stateless)         │  INvmeDevice  │        │
│   └────┬────┘                      └──────┬───────┘        │
│        │                                   │                │
│        ▼                                   │                │
│   ┌─────────────┐    securitySend/Recv     │                │
│   │ ITransport  │◄────────────────────────┘                │
│   │ (ifSend/    │    (내부적으로 위임)                       │
│   │  ifRecv만)  │                                           │
│   └─────────────┘                                           │
│                                                              │
│   ┌─ SedContext ────────────────────────────────────────┐   │
│   │  transport_  : shared_ptr<ITransport>               │   │
│   │  nvmeDevice_ : shared_ptr<INvmeDevice>              │   │
│   │  api_        : EvalApi                              │   │
│   │  session_    : unique_ptr<Session>                  │   │
│   └─────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 핵심 설계 결정

#### (1) ITransport: SED 전용, 최소 인터페이스

```cpp
class ITransport {
public:
    virtual ~ITransport() = default;

    // TCG Core Spec: IF-SEND / IF-RECV 만 노출
    virtual Result ifSend(uint8_t protocolId, uint16_t comId,
                          ByteSpan payload) = 0;
    virtual Result ifRecv(uint8_t protocolId, uint16_t comId,
                          MutableByteSpan buffer, size_t& received) = 0;

    // Transport 메타데이터
    virtual TransportType type() const = 0;
    virtual std::string devicePath() const = 0;
    virtual bool isOpen() const = 0;
    virtual void close() = 0;
};
```

**여기에 NVMe 명령을 넣지 않는 이유:**
- ATA는 `TRUSTED SEND/RECEIVE` (CDB 0x5E/0x5C)
- SCSI는 `SECURITY PROTOCOL IN/OUT` (CDB 0xA2/0xB5)
- NVMe는 `Security Send/Receive` (opcode 0x81/0x82)
- 세 가지 모두 "Security Protocol + ComID + 페이로드" 추상화로 통일 가능
- NVMe Identify, Format 등은 ATA/SCSI에 대응물이 없거나 완전히 다른 형태

#### (2) INvmeDevice: NVMe 명령 전담

```cpp
class INvmeDevice {
public:
    virtual ~INvmeDevice() = default;

    // ── Security Protocol (Transport 내부에서 호출) ──
    virtual Result securitySend(uint8_t protocolId, uint16_t comId,
                                const uint8_t* data, uint32_t len) = 0;
    virtual Result securityRecv(uint8_t protocolId, uint16_t comId,
                                uint8_t* data, uint32_t len,
                                uint32_t& received) = 0;

    // ── Admin Commands ──
    virtual Result adminCommand(NvmeAdminCmd& cmd, NvmeCompletion& cpl) = 0;
    virtual Result identify(uint8_t cns, uint32_t nsid, Bytes& data) = 0;
    virtual Result getLogPage(uint8_t logId, uint32_t nsid,
                              Bytes& data, uint32_t dataLen) = 0;
    virtual Result getFeature(uint8_t fid, uint32_t nsid,
                              uint32_t& cdw0, Bytes& data) = 0;
    virtual Result setFeature(uint8_t fid, uint32_t nsid,
                              uint32_t cdw11, const Bytes& data = {}) = 0;
    virtual Result formatNvm(uint32_t nsid, uint8_t lbaf,
                             uint8_t ses = 0, uint8_t pi = 0) = 0;
    virtual Result sanitize(uint8_t action, uint32_t owPass = 0) = 0;
    virtual Result fwDownload(const Bytes& image, uint32_t offset) = 0;
    virtual Result fwCommit(uint8_t slot, uint8_t action) = 0;

    // ── Namespace Management ──
    virtual Result nsCreate(const Bytes& nsData, uint32_t& nsid) = 0;
    virtual Result nsDelete(uint32_t nsid) = 0;
    virtual Result nsAttach(uint32_t nsid, uint16_t ctrlId, bool attach) = 0;

    // ── I/O Commands ──
    virtual Result ioCommand(NvmeIoCmd& cmd, NvmeCompletion& cpl) = 0;

    // ── Device Info ──
    virtual std::string devicePath() const = 0;
    virtual bool isOpen() const = 0;
    virtual void close() = 0;
};
```

#### (3) NvmeTransport: 두 인터페이스의 브릿지

```cpp
class NvmeTransport : public ITransport {
public:
    // DI 생성 (권장): INvmeDevice를 주입받아 securitySend/Recv를 위임
    explicit NvmeTransport(std::shared_ptr<INvmeDevice> device);

    // ITransport 구현: Security Protocol만
    Result ifSend(...) override {
        return nvmeDevice_->securitySend(...);  // 위임
    }
    Result ifRecv(...) override {
        return nvmeDevice_->securityRecv(...);  // 위임
    }

    // NVMe 디바이스 접근자 (SedContext에서 사용)
    INvmeDevice* nvmeDevice() const;
    std::shared_ptr<INvmeDevice> nvmeDeviceShared() const;

private:
    std::shared_ptr<INvmeDevice> nvmeDevice_;
};
```

**핵심:** `NvmeTransport`는 `ITransport`만 구현하되, 내부에 `INvmeDevice`를 보유.
필요할 때 `nvmeDevice()`로 꺼내서 NVMe 명령 직접 실행 가능.

---

## 3. API 재분류 가이드

기존 스파게티 코드의 API를 아래 표에 따라 분류하면 된다.

### 3.1 ITransport에 남겨야 할 것 (SED 프로토콜)

| API | 역할 | 비고 |
|-----|------|------|
| `ifSend(protocolId, comId, payload)` | TCG IF-SEND | NVMe/ATA/SCSI 공통 |
| `ifRecv(protocolId, comId, buffer, received)` | TCG IF-RECV | NVMe/ATA/SCSI 공통 |
| `type()` | Transport 종류 | 열거형 반환 |
| `devicePath()` | 디바이스 경로 | 디버그/로깅용 |
| `isOpen()` / `close()` | 수명 관리 | |

**총 6개 메서드.** 이 이상 늘어나면 안 된다.

### 3.2 INvmeDevice로 옮겨야 할 것 (NVMe 명령)

| 카테고리 | API | NVMe Opcode |
|---------|-----|-------------|
| **필수 Admin** | `identify(cns, nsid)` | 0x06 |
| | `getLogPage(logId, nsid, len)` | 0x02 |
| | `getFeature(fid, nsid)` | 0x0A |
| | `setFeature(fid, nsid, cdw11)` | 0x09 |
| **디바이스 관리** | `formatNvm(nsid, lbaf, ses)` | 0x80 |
| | `sanitize(action, owPass)` | 0x84 |
| **펌웨어** | `fwDownload(image, offset)` | 0x11 |
| | `fwCommit(slot, action)` | 0x10 |
| **네임스페이스** | `nsCreate(data)` | 0x0D |
| | `nsDelete(nsid)` | 0x0D |
| | `nsAttach(nsid, ctrlId, attach)` | 0x15 |
| **Security** | `securitySend(protocolId, comId, data)` | 0x81 |
| | `securityRecv(protocolId, comId, data)` | 0x82 |
| **Generic** | `adminCommand(cmd, cpl)` | 임의 |
| | `ioCommand(cmd, cpl)` | 임의 |

### 3.3 EvalApi에 남겨야 할 것 vs 제거할 것

| 현재 EvalApi 메서드 | 분류 | 행선지 |
|--------------------|------|--------|
| `discovery0()`, `startSession()`, `closeSession()` | SED 프로토콜 | **EvalApi 유지** |
| `getLockingInfo()`, `setCPin()`, `revertSP()`, ... | SED 메서드 호출 | **EvalApi 유지** |
| `stackReset()`, `verifyComId()` | ComID 관리 (Protocol 0x02) | **EvalApi 유지** (Transport 경유) |
| `nvmeIdentify()`, `nvmeGetLogPage()`, ... | NVMe 편의 래퍼 | **제거 권장** (아래 참고) |
| `nvmeAdminCmd()`, `nvmeIoCmd()` | NVMe Generic | **제거 권장** |
| `getNvmeDevice()` | 유틸리티 | **유지** (브릿지 역할) |

**`EvalApi::nvmeXxx()` 편의 래퍼에 대해:**

현재 libsed에는 `nvmeIdentify()`, `nvmeFormat()` 등이 EvalApi static 메서드로 존재한다.
이들은 단순히 `getNvmeDevice()` + 위임이므로, 두 가지 선택지가 있다:

| 옵션 | 장점 | 단점 |
|------|------|------|
| **A: EvalApi에 유지** | 진입점이 하나 (EvalApi) | EvalApi 비대화, SED와 무관한 코드 혼재 |
| **B: 제거, ctx.nvme() 직접 사용** | 역할 분리 명확 | 호출부가 2개 (api + nvme) |

**권장: 옵션 B** — `ctx.nvme()->identify(...)` 직접 호출. EvalApi는 SED 전용으로 유지.

---

## 4. SedContext: 통합 사용 패턴

### 4.1 생성 패턴

```cpp
// 사용자의 NVMe 구현체 (libnvme 래핑)
auto nvmeDevice = std::make_shared<YourLibNvme>("/dev/nvme0n1");

// SedContext가 내부에서 NvmeTransport 생성
auto ctx = std::make_unique<SedContext>(nvmeDevice);
ctx->initialize();  // Discovery + Properties

// 이제 두 가지 모두 사용 가능:
// SED: ctx->api().xxx(ctx->transport(), ...)
// NVMe: ctx->nvme()->xxx(...)
```

### 4.2 평가 시나리오 예시

```cpp
// ── 시나리오: Format 후 SED 상태 복구 검증 ──

// 1. [SED] 현재 Locking 상태 확인
LockingInfo before;
ctx->api().getLockingInfo(ctx->session(), 0, before, raw);

// 2. [NVMe] Format 수행 (Crypto Erase)
ctx->nvme()->formatNvm(1, 0, /*ses=*/1);

// 3. [SED] Discovery 재수행 (Format이 SED 상태에 영향)
ctx->initialize();

// 4. [SED] Locking 상태 재확인
LockingInfo after;
ctx->api().getLockingInfo(ctx->session(), 0, after, raw);

// 5. [NVMe] SMART 로그로 Format 완료 확인
Bytes smart;
ctx->nvme()->getLogPage(0x02, 0xFFFFFFFF, smart, 512);
```

### 4.3 접근 경로 요약

```
ctx->api()          → EvalApi&        → SED 프로토콜 (120+ 메서드)
ctx->transport()    → ITransport*     → ifSend/ifRecv (내부용)
ctx->nvme()         → INvmeDevice*    → NVMe Admin/IO (15+ 메서드)
ctx->session()      → Session&        → 활성 TCG 세션
```

---

## 5. 스레드 모델

```
┌─ Thread 1 ──────────────────────┐  ┌─ Thread 2 ──────────────────────┐
│ SedContext ctx1(nvmeDevice1)     │  │ SedContext ctx2(nvmeDevice2)     │
│                                  │  │                                  │
│ ctx1.api()  → SED 평가           │  │ ctx2.api()  → SED 평가           │
│ ctx1.nvme() → NVMe 평가          │  │ ctx2.nvme() → NVMe 평가          │
│                                  │  │                                  │
│ Session은 ctx1 전용              │  │ Session은 ctx2 전용              │
└──────────────────────────────────┘  └──────────────────────────────────┘

안전 규칙:
 - EvalApi: stateless → 스레드 안전 (공유 가능)
 - Session: 스레드당 1개 → 공유 금지
 - INvmeDevice: 구현체에 mutex 필요 (또는 스레드당 1개)
 - SedContext: 스레드당 1개 → 공유 금지
```

---

## 6. 리팩토링 마이그레이션 가이드

### 6.1 단계별 진행

```
Phase 1: 인터페이스 분리 (비파괴적)
  ├── INvmeDevice 인터페이스 정의
  ├── ITransport에서 NVMe 메서드 식별 및 태그
  └── INvmeDevice 구현체 작성 (기존 코드를 래핑)

Phase 2: Transport 정리
  ├── NvmeTransport에 DI 생성자 추가
  ├── ITransport에서 NVMe 메서드를 deprecated 마킹
  └── 호출부를 ctx.nvme()->xxx()로 점진적 전환

Phase 3: EvalApi 정리
  ├── EvalApi::nvmeXxx() static 메서드 deprecated
  ├── 호출부를 ctx.nvme()->xxx() 직접 호출로 전환
  └── deprecated 메서드 제거

Phase 4: 검증
  ├── 기존 테스트 전체 통과 확인
  ├── NVMe + SED 이중 시나리오 테스트 추가
  └── Mock 분리 검증 (SED mock과 NVMe mock 독립)
```

### 6.2 기존 코드 매핑 체크리스트

기존 스파게티 코드를 리팩토링할 때, 각 API를 아래 기준으로 분류한다:

```
해당 API가 Security Protocol (IF-SEND/IF-RECV)을 사용하는가?
  ├── Yes → ITransport에 유지
  └── No
       ├── NVMe Admin/IO opcode를 사용하는가?
       │    ├── Yes → INvmeDevice로 이동
       │    └── No → 상위 레이어 (EvalApi 또는 비즈니스 로직)
       └── 여러 명령의 조합인가? (예: Format + Discovery 재수행)
            └── Yes → SedContext 또는 Worker 레벨 헬퍼
```

---

## 7. Mock/테스트 전략

인터페이스 분리의 가장 큰 이점: **SED 테스트에 NVMe mock이 필요 없다.**

```
[SED 단위 테스트]
  MockTransport : ITransport
    → ifSend/ifRecv만 mock
    → NVMe 관련 코드 zero

[NVMe 단위 테스트]
  MockNvmeDevice : INvmeDevice
    → identify, formatNvm 등만 mock
    → SED Session 관련 코드 zero

[통합 테스트]
  SimLibNvme : INvmeDevice  (시뮬레이션)
  NvmeTransport(simLibNvme)
  SedContext(simLibNvme)
    → SED + NVMe 모두 테스트
```

---

## 8. 요약: 분리 전후 비교

### Before (스파게티)

```
ITransport (30+ 메서드)
  ├── ifSend / ifRecv
  ├── identify / getLogPage / getFeature / setFeature
  ├── formatNvm / sanitize
  ├── fwDownload / fwCommit
  ├── nsCreate / nsDelete / nsAttach
  ├── adminCommand / ioCommand
  └── (ATA/SCSI는 절반이 NotSupported)
```

### After (분리됨)

```
ITransport (6 메서드)          INvmeDevice (15+ 메서드)
  ├── ifSend                    ├── securitySend/Recv
  ├── ifRecv                    ├── identify / getLogPage
  ├── type                      ├── getFeature / setFeature
  ├── devicePath                ├── formatNvm / sanitize
  ├── isOpen                    ├── fwDownload / fwCommit
  └── close                     ├── nsCreate/Delete/Attach
                                ├── adminCommand
                                └── ioCommand

SedContext (통합 접근점)
  ├── api()       → EvalApi (SED 전용, 120+ 메서드)
  ├── nvme()      → INvmeDevice* (NVMe 전용)
  ├── transport() → ITransport* (내부/고급 사용)
  └── session()   → Session& (TCG 세션)
```

| 지표 | Before | After |
|------|--------|-------|
| ITransport 메서드 수 | 30+ | 6 |
| ATA/SCSI stub 메서드 | 20+ (`NotSupported`) | 0 |
| SED 테스트에 NVMe mock 필요 | Yes | No |
| NVMe 명령 추가 시 수정 파일 | 모든 Transport | INvmeDevice 구현체만 |
| 역할 명확성 | 혼재 | 완전 분리 |
