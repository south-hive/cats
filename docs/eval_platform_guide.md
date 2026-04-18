# TCG SED Evaluation Library — Developer Guide

> **Version**: 1.0
> **Target**: TC Library 평가 플랫폼 개발자
> **Language**: C++17
> **Scope**: NVMe drives with TCG SED (Opal / Enterprise / Pyrite)


## 1. Overview

이 라이브러리는 TCG SED 지원 NVMe 드라이브 평가를 위한 flat, step-by-step C++17 API를 제공합니다.
기존 high-level API(OpalAdmin, OpalLocking 등)는 여러 프로토콜 단계를 하나로 묶어 편의성을 제공하지만,
평가 플랫폼에서는 각 단계를 독립적으로 실행하고 중간 상태를 검증해야 합니다.

### 핵심 설계 원칙

1. **Every step is callable** — Discovery, StartSession, SyncSession, Auth, Get/Set 등 모든 단계가 독립 함수
2. **Wire-level visibility** — 모든 결과에 `rawSendPayload`, `rawRecvPayload` 포함
3. **Explicit session** — 암묵적 open/close 없음, caller가 session lifecycle 제어
4. **DI-friendly** — libnvme를 Transport에 주입하여 TCG + NVMe 복합 테스트 지원
5. **Thread-safe design** — EvalApi는 stateless, 스레드당 Session으로 병렬 평가 가능


### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Your Evaluation Platform                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Thread 1     │  │ Thread 2     │  │ Thread N             │   │
│  │ EvalApi      │  │ EvalApi      │  │ EvalApi              │   │
│  │ Session A    │  │ Session B    │  │ Session C            │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────────┘   │
│         │                  │                  │                    │
│  ┌──────▼──────────────────▼──────────────────▼───────────────┐  │
│  │  eval_api.h — Flat EvalApi (120+ methods)                   │  │
│  │  Discovery | Session | Table | C_PIN | MBR | Locking        │  │
│  │  Authority | ACE | SP Lifecycle | Crypto | Enterprise       │  │
│  │  DataStore | TC Utils | NVMe Access | Raw Transport         │  │
│  ├─────────────────────────────────────────────────────────────┤  │
│  │  Session / PacketBuilder / MethodCall / TokenEncoder         │  │
│  ├─────────────────────────────────────────────────────────────┤  │
│  │  ITransport (abstract)                                      │  │
│  │  └── NvmeTransport                                          │  │
│  │      ├── Mode A: direct ioctl (legacy)                      │  │
│  │      └── Mode B: DI via INvmeDevice ← your libnvme          │  │
│  └───────────────────────────┬─────────────────────────────────┘  │
│                               │                                    │
│  ┌───────────────────────────▼─────────────────────────────────┐  │
│  │  INvmeDevice (your libnvme facade)                           │  │
│  │  securitySend/Recv | identify | getLogPage | formatNvm ...   │  │
│  └─────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Naming Convention

| 항목 | 규칙 | 예시 |
|---|---|---|
| Header files | `snake_case.h` | `eval_api.h`, `i_nvme_device.h` |
| Source files | `snake_case.cpp` | `eval_api.cpp` |
| Function names | `camelCase` | `startSession`, `getLockingInfo` |
| Class names | `PascalCase` | `EvalApi`, `NvmeTransport` |
| UID constants | namespace + PascalCase | `uid::SP_ADMIN`, `uid::AUTH_SID` |
| Column constants | `UPPER_SNAKE` | `uid::col::RANGE_START` |


## 2. Transport & NVMe DI Architecture

### 핵심 고민: TCG 평가 중 NVMe 동작을 어떻게 호출할 것인가?

TCG 평가 시 NVMe 기능(Identify, Format, SMART 등)도 같이 사용해야 할 때, 두 가지 접근이 가능합니다.

```
                ┌─────────────────────────────────────────────────────┐
                │             Your Evaluation Test Code                │
                │                                                     │
                │  TCG ops:     api.discovery0(transport, ...)        │
                │               api.startSession(session, ...)        │
                │                                                     │
                │  NVMe ops:    ??????????                            │
                └──────────────────┬──────────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼                              ▼
           Option A: Transport              Option B: INvmeDevice 직접
           api.rawIfSend(                   auto* nvme = EvalApi::
             transport,                       getNvmeDevice(transport);
             0x06, 0, identData)            nvme->identify(1, 0, data);
```

#### 비교

| 기준 | Option A: Transport 경유 | Option B: INvmeDevice 직접 |
|---|---|---|
| **TCG 동작** | `api.xxx(session, ...)` | `api.xxx(session, ...)` |
| **NVMe Security Send/Recv** | `api.rawIfSend(transport, 0x01, ...)` | 같음 (transport 내부 위임) |
| **NVMe Identify/Format** | ❌ 불가 (ITransport = Security 프로토콜 전용) | ✅ `nvme->identify(1, 0, data)` |
| **NVMe Admin 일반 커맨드** | ❌ ITransport에 없음 | ✅ `nvme->adminCommand(cmd, cpl)` |
| **NVMe IO 커맨드** | ❌ | ✅ `nvme->ioCommand(cmd, cpl)` |
| **코드 의존성** | ITransport만 | INvmeDevice 추가 |
| **테스트 격리** | TCG만 테스트 시 깔끔 | NVMe+TCG 복합 시 필수 |

#### 권장: DI + 직접 접근

```
┌──────────────────────────────────────────────────────────────┐
│  결론: INvmeDevice를 DI로 주입, 필요 시 직접 접근            │
│                                                               │
│  • TCG 동작     → 항상 EvalApi 통해 (transport 경유)         │
│  • NVMe Security→ EvalApi.rawIfSend/Recv 또는 자동           │
│  • NVMe Admin   → INvmeDevice 직접 접근                      │
│  • 복합 시나리오→ getNvmeDevice()로 꺼내서 사용              │
└──────────────────────────────────────────────────────────────┘
```

이유:
1. **ITransport는 Security Protocol 전용** — Identify, Format 등은 scope 밖
2. **Transport에 NVMe 전체를 넣으면** ATA/SCSI와의 polymorphism 깨짐
3. **DI된 INvmeDevice를 transport에서 꺼내면** 자연스럽게 양쪽 다 접근 가능
4. **Thread 관점**: NVMe device handle은 하나, transport와 INvmeDevice가 같은 handle 공유

### 구현 패턴

```cpp
// Step 1: libnvme를 INvmeDevice로 구현
class YourLibNvme : public libsed::INvmeDevice {
    Result securitySend(...) override { /* NVMe opcode 0x81 */ }
    Result securityRecv(...) override { /* NVMe opcode 0x82 */ }
    Result identify(...) override { /* NVMe opcode 0x06 */ }
    Result formatNvm(...) override { /* NVMe opcode 0x80 */ }
    // ...
};

// Step 2: DI
auto nvme = std::make_shared<YourLibNvme>("/dev/nvme0");
auto transport = std::make_shared<NvmeTransport>(nvme);

// Step 3: TCG 동작 — EvalApi 경유
EvalApi api;
api.discovery0(transport, info);    // → nvme.securityRecv()

// Step 4: NVMe 동작 — INvmeDevice 직접
INvmeDevice* dev = EvalApi::getNvmeDevice(transport);
dev->identify(1, 0, identData);
dev->getLogPage(0x02, 0xFFFFFFFF, smartData, 512);

// 또는 EvalApi convenience wrapper
EvalApi::nvmeIdentify(transport, 1, 0, identData);
EvalApi::nvmeFormat(transport, 1, 0);
```

### 복합 시나리오: NVMe Format → TCG 상태 확인

```cpp
auto* nvme = EvalApi::getNvmeDevice(transport);

// 1) NVMe: Format NVM (crypto erase)
nvme->formatNvm(1, 0, /*ses=*/2);

// 2) TCG: Discovery — Format 후 SED 상태 변경 확인
api.discovery0(transport, info);

// 3) TCG: MSID 읽기
Session session(transport, comId);
api.startSession(session, uid::SP_ADMIN, false, ssr);
api.getCPin(session, uid::CPIN_MSID, msid, raw);
api.closeSession(session);

// 4) NVMe: SMART log
Bytes smart;
nvme->getLogPage(0x02, 0xFFFFFFFF, smart, 512);
```


## 3. Quick Start

```cpp
#include <libsed/eval/eval_api.h>
#include <libsed/transport/transport_factory.h>
#include <libsed/sed_library.h>

using namespace libsed;
using namespace libsed::eval;

int main() {
    libsed::initialize();
    auto transport = TransportFactory::createNvme("/dev/nvme0");
    EvalApi api;

    TcgOption opt;
    api.getTcgOption(transport, opt);

    PropertiesResult props;
    api.exchangeProperties(transport, opt.baseComId, props);

    Session session(transport, opt.baseComId);
    session.setMaxComPacketSize(props.tperMaxComPacketSize);
    StartSessionResult ssr;
    api.startSession(session, uid::SP_ADMIN, false, ssr);

    Bytes msid;
    RawResult raw;
    api.getCPin(session, uid::CPIN_MSID, msid, raw);
    // raw.rawSendPayload — 전송된 bytes
    // raw.rawRecvPayload — 수신된 bytes

    api.closeSession(session);
    libsed::shutdown();
}
```


## 4. Session Management

### 4.1 StartSession / SyncSession 분리

```cpp
StartSessionParams params;
params.spUid = uid::SP_ADMIN;
params.write = true;
params.hostExchangeAuthority = uid::AUTH_SID;
params.hostChallenge = msidPin;
params.hostSessionId = 42;  // 수동 HSN

Bytes sentPayload;
api.sendStartSession(transport, comId, params, sentPayload);
// → fault injection point

SyncSessionResult syncResult;
api.recvSyncSession(transport, comId, syncResult);
// → SyncSession OPT: spChallenge, transTimeout, initialCredits, signedHash
```

### 4.2 Dual Session

```cpp
Session sessionA(transport, comId);
api.startSessionWithAuth(sessionA, uid::SP_ADMIN, true, uid::AUTH_SID, sidCred, ssrA);
Session sessionB(transport, comId);
api.startSessionWithAuth(sessionB, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Cred, ssrB);
// Both active — interleave operations
api.closeSession(sessionA);
api.closeSession(sessionB);
```


## 5. Multi-Threading

### 핵심 규칙

| 항목 | Thread-safe? | 설명 |
|---|---|---|
| `EvalApi` | ✅ | Stateless |
| `Session` | ❌ | **스레드당 하나** |
| `ITransport` | ⚠️ 조건부 | 드라이버 의존, serialize 권장 |
| `INvmeDevice` | ⚠️ 구현 의존 | 내부 mutex 필요 |

### 스레드당 Session

```cpp
void worker(std::shared_ptr<ITransport> tr, uint16_t comId, const Bytes& cred) {
    EvalApi api;
    Session session(tr, comId);
    StartSessionResult ssr;
    api.startSessionWithAuth(session, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, cred, ssr);
    // ... work ...
    api.closeSession(session);
}
```

### Session Pool

```cpp
class SessionPool {
    std::vector<std::unique_ptr<Session>> pool_;
    std::mutex mutex_;
public:
    std::unique_ptr<Session> acquire();
    void release(std::unique_ptr<Session>);
};
// 8 workers sharing 4 pre-opened sessions
```

### 동시 TCG + NVMe

```cpp
std::thread tcg([&]() { /* session per iteration */ });
std::thread nvme([&]() { /* nvme->getLogPage() loop */ });
```

See `examples/eval_multi_session.cpp` for 6 complete multi-thread scenarios.


## 6. TC Library Util 함수 매핑

| TC Library | EvalApi | 비고 |
|---|---|---|
| `getTcgOption` | `api.getTcgOption(transport, opt)` | SSC/ComID/Locking/MBR 요약 |
| `GetClass0SecurityStatus` | `api.getSecurityStatus(transport, status)` | Feature 존재 여부 |
| `GetSecurityFeatureType` | `api.getSecurityFeature(transport, code, info)` | 개별 feature 상세 |
| `GetLockingInfo` | `api.getLockingInfo(session, rangeId, info, raw)` | Range 정보 |
| `GetByteTableInfo` | `api.getByteTableInfo(session, info, raw)` | DataStore 크기 |
| `SetMBRControlTableNsidOne` | `api.setMbrControlNsidOne(session, raw)` | MBR Enable+Done |
| `TcgWrite` | `api.tcgWrite(session, tableUid, offset, data, raw)` | ByteTable 쓰기 |
| `TcgRead` | `api.tcgRead(session, tableUid, offset, len, result)` | ByteTable 읽기 |
| `TcgCompare` | `api.tcgCompare(session, tableUid, offset, expected, result)` | Write-Read-Compare |


## 7. Well-Known UIDs

```cpp
namespace libsed::uid {
    SP_ADMIN, SP_LOCKING, SP_ENTERPRISE
    AUTH_SID, AUTH_PSID, AUTH_MSID, AUTH_ADMIN1, AUTH_USER1
    AUTH_BANDMASTER0, AUTH_ERASEMASTER
    CPIN_SID, CPIN_MSID, CPIN_ADMIN1, CPIN_USER1, CPIN_ERASEMASTER
    TABLE_LOCKING, TABLE_MBRCTRL, TABLE_MBR, TABLE_ACE
    TABLE_AUTHORITY, TABLE_CPIN, TABLE_DATASTORE, TABLE_K_AES
    LOCKING_GLOBALRANGE, LOCKING_RANGE1, LOCKING_RANGE2

    // Helpers
    makeUserUid(n), makeAdminUid(n), makeBandMasterUid(n)
    makeCpinUserUid(n), makeCpinAdminUid(n), makeCpinBandMasterUid(n)
    makeLockingRangeUid(n), makeKAesUid(n)
    makeAceLockingRangeSetRdLocked(n), makeAceLockingRangeSetWrLocked(n)

    namespace col {
        PIN, PIN_TRIES_REMAINING, RANGE_START, RANGE_LENGTH
        READ_LOCK_EN, WRITE_LOCK_EN, READ_LOCKED, WRITE_LOCKED
        LOCK_ON_RESET, ACTIVE_KEY, MBR_ENABLE, MBR_DONE
        AUTH_ENABLED, LIFECYCLE, ACE_BOOLEAN_EXPR, MAX_SIZE, USED_SIZE
    }
}
```


## 8. Debug & Fault Injection

```cpp
auto& tc = TestContext::instance();
tc.enable();
TestSession ts("my_test");

ts.fault(FaultBuilder("corrupt_sync")
    .at(FaultPoint::AfterIfRecv)
    .corrupt(8, 0xFF).once());

api.startSession(session, uid::SP_ADMIN, false, ssr);  // fault fires
for (auto& ev : ts.trace()) std::cout << ev.tag << ": " << ev.detail << "\n";

tc.disable();
```

24 fault points, 동작: corrupt, drop, delay, duplicate, truncate, inject


## 8.5. 플랫폼 로거 통합 (Flow Log)

libsed 내부 로그는 `LIBSED_INFO / LIBSED_DEBUG / LIBSED_WARN / LIBSED_ERROR`
매크로 하나의 경로를 탄다. TC 플랫폼 로거로 이 스트림을 흡수하려면 `ILogSink`를
구현하고 `Logger::setSink()` 한 번만 호출하면 된다 — 라이브러리 전역에서 자동 반영.

```cpp
class MyPlatformSink : public libsed::ILogSink {
public:
    void log(libsed::LogLevel lv, const char* file, int line,
             const std::string& msg) override {
        platform_log(static_cast<int>(lv), file, line, msg.c_str());
    }
};

// 부팅 시 한 번
libsed::Logger::setSink(std::make_shared<MyPlatformSink>());
```

플랫폼 싱크를 안 연결한 상태에서도 기본 `StderrSink`가 항상 화면에 찍는다.
추가로 화면 + 파일 동시 출력이 필요하면 `FileSink` + `TeeSink` 직접 합성하거나
편의 헬퍼 한 줄:

```cpp
libsed::installDefaultFlowLog("/var/log/tc/libsed.log");   // screen + file tee
```

Flow 로그는 레벨 필터링(`Logger::setLevel`)과 thread-safe 배달 모두 라이브러리가
이미 책임진다. 플랫폼 쪽은 최종 포맷만 신경 쓰면 된다.

CLI 실험용: `--flow-log PATH` 플래그로 같은 screen+file 세팅을 부팅 인자로 가능.


## 8.6. Transactions (명시적 boundary)

`EvalApi`는 TCG transaction을 4개 primitive로 노출한다. 묵시적 auto-apply
없음 — TC 시나리오가 start / commit / rollback을 직접 호출해야 한다. 이
설계는 의도적이다. 시나리오가 각 경계마다 NVMe 수준 에러와 TCG 수준
에러를 독립적으로 관찰/결정해야 하기 때문.

```cpp
RawResult txStart, setRaw1, setRaw2, txEnd;

api.startTransaction(session, txStart);
if (txStart.transportError != ErrorCode::Success) {
    // NVMe/ATA/SCSI ioctl 자체가 실패. 트랜잭션 못 연다.
    return;
}
if (!txStart.methodResult.isSuccess()) {
    // TPer가 transaction 시작을 거부 (0x0F TPer_Malfunction,
    // 0x10 TRANSACTION_FAILURE 등). 드라이브 미지원 가능.
    return;
}

api.setRange(session, 1, 0, 0x1000, true, true, setRaw1);
api.setRange(session, 2, 0x1000, 0x1000, true, true, setRaw2);

bool allOk = setRaw1.ok() && setRaw1.methodResult.isSuccess()
          && setRaw2.ok() && setRaw2.methodResult.isSuccess();

if (allOk) api.commitTransaction(session, txEnd);
else       api.rollbackTransaction(session, txEnd);
```

네 개 API 모두 `RawResult&`를 받는다:
- `transportError` — NVMe/ATA/SCSI layer 결과
- `methodResult.status()` — TCG method status byte
- `rawSendPayload` / `rawRecvPayload` — 와이어 바이트 (scenario 재현용)

와이어 포맷은 `rosetta_stone.md §14` 참조. 예제는
`examples/21_transactions.cpp`.

**벤더 편차 경고**: 실제 Opal 드라이브의 transaction 지원은 고르지 않다.
다수 벤더가 `0x0F TPer_Malfunction` 또는 `0x10 TRANSACTION_FAILURE`를
반환한다. TC 시나리오는 이 응답을 에러가 아닌 "드라이브 특성"으로 캡처해야
한다 — libsed는 자동 해석하지 않고 원본을 그대로 돌려준다.


## 9. Examples

### 평가 API 예제

| File | Description |
|---|---|
| `eval_step_by_step.cpp` | 기본 프로토콜 단계별 실행 |
| `eval_tc_utils.cpp` | TC Library util 전체 데모 |
| `eval_full_demo.cpp` | 120+ API 전체 데모 |
| `eval_multi_session.cpp` | Multi-thread 6개 시나리오 |
| `eval_worker_pattern.cpp` | Worker pool 패턴 |
| `eval_fault_injection.cpp` | Debug layer + fault injection |
| `eval_reset_scenarios.cpp` | Reset/Power-cycle 시나리오 |

### 고수준 API 예제

| File | Description |
|---|---|
| `opal_setup.cpp` | Opal 초기 설정 (고수준 OpalDevice API) |
| `lock_unlock.cpp` | Range 잠금/해제 (고수준 API) |
| `enterprise_band.cpp` | Enterprise Band 관리 (고수준 API) |
| `discovery.cpp` | 디바이스 탐색 및 정보 출력 |

### Application Note 예제

TCG Storage Application Note 문서에 기반한 전체 워크플로우 예제입니다.
모든 Application Note는 EvalApi (단계별 플랫 API)를 사용하며, 각 단계마다
결과 확인과 오류 처리를 포함합니다.

| File | Description | TCG Reference |
|---|---|---|
| `appnote_opal.cpp` | Opal SSC 전체 라이프사이클 (AppNote 3-13) | TCG Storage Application Note: Opal SSC |
| `appnote_enterprise.cpp` | Enterprise SSC Band 관리 8개 시나리오 | TCG Storage Application Note: Enterprise SSC |
| `appnote_mbr.cpp` | Shadow MBR 심층 — PBA 쓰기/부팅 사이클/다중 사용자 | TCG Storage Application Note: Shadow MBR |
| `appnote_psid.cpp` | PSID Revert 비상 복구 및 상태 확인 | TCG Storage Application Note: PSID |
| `appnote_datastore.cpp` | DataStore(ByteTable) 쓰기/읽기/비교/청크 처리 | TCG Storage Feature Set: DataStore Tables |
| `appnote_block_sid.cpp` | NVMe Block SID Feature 설정/확인/해제 | TCG Storage Feature Set: Block SID Authentication |
| `appnote_ns_locking.cpp` | Namespace별 잠금 범위 구성 및 NVMe Identify 매핑 | TCG Storage Feature Set: Configurable Namespace Locking |

#### Opal Application Note 상세 (appnote_opal.cpp)

| 함수 | AppNote 섹션 | 시나리오 |
|---|---|---|
| `appnote3_takeOwnership` | 3 | 소유권 확보 — MSID 읽기 → SID 비밀번호 설정 |
| `appnote4_activateLockingSP` | 4 | Locking SP 활성화 |
| `appnote5_configureLockingRange` | 5 | 잠금 범위 구성 (RangeStart/Length/RLE/WLE) |
| `appnote6_setUserPassword` | 6 | 사용자 비밀번호 설정 (C_PIN_User1) |
| `appnote7_enableUserInAce` | 7 | ACE에서 사용자 권한 활성화 |
| `appnote8_lockRange` | 8 | 범위 잠금 (ReadLocked/WriteLocked) |
| `appnote9_unlockRange` | 9 | 범위 잠금 해제 |
| `appnote10_mbrShadow` | 10 | MBR 섀도잉 (PBA 이미지 쓰기/MBRDone) |
| `appnote11_cryptoErase` | 11 | 암호화 소거 (ActiveKey 재생성) |
| `appnote12_revertLockingSP` | 12 | Locking SP 복원 |
| `appnote13_revertTPer` | 13 | TPer 복원 / PSID Revert |


## 10. Building Your Platform

### INvmeDevice 구현 최소 템플릿

```cpp
class YourLibNvme : public libsed::INvmeDevice {
public:
    explicit YourLibNvme(const std::string& path);
    Result securitySend(uint8_t proto, uint16_t comId,
                        const uint8_t* data, uint32_t len) override;
    Result securityRecv(uint8_t proto, uint16_t comId,
                        uint8_t* data, uint32_t len, uint32_t& received) override;
    Result adminCommand(NvmeAdminCmd& cmd, NvmeCompletion& cpl) override;
    Result ioCommand(NvmeIoCmd& cmd, NvmeCompletion& cpl) override;
    Result identify(uint8_t cns, uint32_t nsid, Bytes& data) override;
    Result getLogPage(uint8_t logId, uint32_t nsid, Bytes& data, uint32_t len) override;
    Result getFeature(uint8_t fid, uint32_t nsid, uint32_t& cdw0, Bytes& data) override;
    Result setFeature(uint8_t fid, uint32_t nsid, uint32_t cdw11, const Bytes& data) override;
    Result formatNvm(uint32_t nsid, uint8_t lbaf, uint8_t ses, uint8_t pi) override;
    Result sanitize(uint8_t action, uint32_t owPass) override;
    Result fwDownload(const Bytes& fw, uint32_t offset) override;
    Result fwCommit(uint8_t slot, uint8_t action) override;
    Result nsCreate(const Bytes& data, uint32_t& nsid) override;
    Result nsDelete(uint32_t nsid) override;
    Result nsAttach(uint32_t nsid, uint16_t cid, bool attach) override;
    std::string devicePath() const override;
    bool isOpen() const override;
    void close() override;
    int fd() const override;
};
```

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.14)
project(your_eval CXX)
set(CMAKE_CXX_STANDARD 17)
add_subdirectory(lib/tcg-sed-lib)
find_package(Threads REQUIRED)
add_executable(eval_main src/eval_main.cpp src/your_libnvme.cpp)
target_link_libraries(eval_main PRIVATE tcgsed Threads::Threads)
```


## 11. SedContext & Worker 통합 패턴

### Worker가 갖는 인스턴스

```
┌─ NVMeThread ──────────────────────────────────────────────────┐
│  owns: libnvme (shared_ptr<INvmeDevice>)  ← 스레드당 1개     │
│  owns: SedContext (libnvme DI'd)          ← 스레드당 1개     │
│                                                                │
│  SedContext 내부:                                              │
│    transport_ (NvmeTransport, libnvme 주입됨)                 │
│    api_       (EvalApi, stateless)                             │
│    session_   (Session, 현재 활성 세션)                       │
│    tcgOption_ (cached Discovery)                              │
│    properties_(cached Properties)                              │
│    comId_     (cached ComID)                                  │
│                                                                │
│  ┌─ Worker A ──────────────────────────────────────────────┐  │
│  │  receives: INvmeDevice& libnvme  (NVMe ops)             │  │
│  │  receives: SedContext&  ctx      (TCG ops)               │  │
│  │                                                          │  │
│  │  NVMe:  libnvme.identify(1, 0, data);                   │  │
│  │  TCG:   ctx.api().getLockingInfo(ctx.session(), ...);    │  │
│  │  Both:  libnvme = ctx.nvme()도 가능                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌─ Worker B ──────────────────────────────────────────────┐  │
│  │  same libnvme&, same ctx& (순차 실행이므로 안전)          │  │
│  │  Worker B가 openSession 하면 A의 session은 이미 닫힘     │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### 의존성 방향

```
Your Platform (위)
    │
    ├── NVMeThread
    │     ├── libnvme (shared_ptr<INvmeDevice>)
    │     └── SedContext ← libnvme DI
    │           ├── NvmeTransport ← libnvme DI
    │           ├── EvalApi
    │           └── Session
    │
    ├── Worker (abstract)
    │     └── execute(INvmeDevice&, SedContext&)
    │
    └── ConcreteWorker : Worker
          └── 위에서 아래로만 의존
                                    
TCG SED Library (아래)
    ├── eval_api.h / sed_context.h
    ├── ITransport / NvmeTransport
    ├── INvmeDevice (interface)
    └── Session / Discovery / ...
```

**핵심**: 의존성은 항상 위(Platform) → 아래(Library). Library는 Platform을 모름.

### SedContext API

```cpp
// 생성 (NVMeThread에서)
auto libnvme = std::make_shared<YourLibNvme>("/dev/nvme0");
SedContext ctx(libnvme);

// 초기화 (Discovery + Properties 캐싱)
ctx.initialize();

// Worker에서 사용
ctx.api()          // → EvalApi&
ctx.transport()    // → shared_ptr<ITransport>
ctx.nvme()         // → INvmeDevice*
ctx.comId()        // → uint16_t (cached)
ctx.tcgOption()    // → const TcgOption& (cached)

// 세션 관리
ctx.openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, "password");
ctx.session()      // → Session& (현재 활성)
ctx.hasSession()   // → bool
ctx.closeSession();

// 편의 함수
ctx.readMsid(msid);                      // 임시 세션 열고 MSID 읽기
ctx.takeOwnership("new_sid_password");    // MSID → SID 설정

// 독립 세션 (dual-SP 테스트)
auto extraSession = ctx.createAndOpenSession(
    uid::SP_ADMIN, uid::AUTH_SID, sidCred);
```

### Worker 구현 예시

```cpp
class MyTcgTestWorker : public Worker {
    std::string admin1Pw_;
public:
    explicit MyTcgTestWorker(std::string pw) : admin1Pw_(std::move(pw)) {}
    std::string name() const override { return "MyTcgTest"; }

    Result execute(INvmeDevice& libnvme, SedContext& ctx) override {
        // NVMe: SMART 확인
        Bytes smart;
        libnvme.getLogPage(0x02, 0xFFFFFFFF, smart, 512);

        // TCG: 세션 열기
        auto r = ctx.openSession(uid::SP_LOCKING, uid::AUTH_ADMIN1, admin1Pw_);
        if (r.failed()) return r;

        // TCG: 평가 동작
        RawResult raw;
        LockingInfo li;
        ctx.api().getLockingInfo(ctx.session(), 0, li, raw);

        // 검증
        assert(li.readLockEnabled == true);

        // TCG: 세션 닫기
        ctx.closeSession();
        return ErrorCode::Success;
    }
};
```
