# TCG SED Test Scenarios (TCG SED 테스트 시나리오)

> **Version**: 1.0 | **Date**: 2026-04-06 | **Library**: CATS (libsed)

## 목적

이 문서는 세 가지 목적으로 작성되었습니다:

1. **CATS 라이브러리 검증** — EvalApi, SedDrive, EvalComposite의 모든 기능이 올바르게 동작하는지 확인
2. **SED 디바이스 적합성 테스트** — TCG Opal/Enterprise/Pyrite 스펙에 따른 디바이스 동작 검증
3. **TC 개발자 교육** — 실제 개발 시 흔한 실수, 프로토콜 gotcha, 와이어 레벨 이해를 돕는 교육 자료

## 문서 구조

| Level | 이름 | 시나리오 수 | 설명 |
|-------|------|------------|------|
| **L1** | 단위 기능 검증 | 20 | 개별 API 메서드 1개 호출 + 기대 결과 |
| **L2** | 표준 시퀀스 검증 | 15 | TCG Application Note 기반 멀티 스텝 흐름 |
| **L3** | 기능 간 연동 검증 | 20 | 여러 기능 결합, 8~20 steps |
| **L4** | 오류/네거티브 검증 | 22 | 에러 핸들링, 경계 조건, 권한 위반 |
| **L5** | 고급 시나리오 | 20 | 멀티 세션, Fault injection, Recovery, Stress |
| **L6** | SSC별 특화 검증 | 5 | Opal/Enterprise/Pyrite 행동 차이 |
| | **합계** | **102** | |

## ID 체계

```
TS-LX-NNN
│  │  └── 일련번호
│  └──── 서브카테고리 (A, B, C, D, E)
└────── Level (1~6)
```

## 시나리오 읽는 법

각 시나리오는 다음 필드를 포함합니다:
- **Category**: 검증 분류
- **Purpose**: 무엇을 검증하는가
- **API Layer**: `EvalApi` / `EvalComposite` / `SedDrive` / `SedSession`
- **SSC**: `Opal 2.0` / `Enterprise` / `Pyrite` / `All`
- **Transport**: `MockTransport` / `SimTransport` / `Real Device`
- **Steps**: 번호, 동작, API 호출, 기대 결과
- **Code Example**: 핵심 API 호출 스니펫
- **Educational Notes**: 교육 포인트 (Common Mistake, TCG Spec Reference)

## 환경 요구사항

```bash
# 빌드
cmake -B build -DLIBSED_BUILD_TESTS=ON -DLIBSED_BUILD_EXAMPLES=ON
cmake --build build

# L1~L4: MockTransport (하드웨어 불필요)
# L5~L6: SimTransport 또는 실제 SED 디바이스
```

---

# Level 1: 단위 기능 검증 (Basic Function Tests)

> 개별 EvalApi 메서드를 독립적으로 호출하여 기본 동작을 확인합니다.
> MockTransport에 응답을 큐잉하고 send/recv 페이로드를 검증합니다.

---

## TS-1A-001: Discovery0 기본 파싱

**Category**: L1 — Discovery | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: Level 0 Discovery 응답을 올바르게 파싱하여 DiscoveryInfo 구조체의 모든 필드(SSC 타입, ComID, feature 플래그)를 추출하는지 검증.

#### Prerequisites
- MockTransport에 유효한 Opal 2.0 Discovery 응답 큐잉

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Discovery0 수행 | `api.discovery0(transport, info)` | `Result::Success` |
| 2 | SSC 타입 확인 | `info.primarySsc` | `SscType::Opal20` |
| 3 | ComID 확인 | `info.baseComId` | `!= 0` (e.g., 0x0001) |
| 4 | Locking 기능 확인 | `info.lockingPresent` | `true` |
| 5 | MBR 기능 확인 | `info.mbrEnabled` | Discovery 데이터에 따름 |

#### Code Example
```cpp
EvalApi api;
auto mock = std::make_shared<MockTransport>();
mock->queueDiscoveryResponse(SscType::Opal20);

DiscoveryInfo info;
auto r = api.discovery0(mock, info);
EXPECT_OK(r);
EXPECT_EQ(info.primarySsc, SscType::Opal20);
EXPECT_NE(info.baseComId, 0);
EXPECT_TRUE(info.lockingPresent);
```

#### Educational Notes
- **TCG Spec Reference**: TCG Core Spec 3.3.6 "Level 0 Discovery"
- **Wire-Level**: Discovery는 Security Protocol 0x01, ComID 0x0001로 전송됨. 응답은 48바이트 헤더 + Feature Descriptor 배열.

---

## TS-1A-002: Discovery0 Raw 바이트 반환

**Category**: L1 — Discovery | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `discovery0Raw()`가 Discovery 응답을 파싱하지 않고 원시 바이트 그대로 반환하는지 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Raw Discovery 수행 | `api.discovery0Raw(transport, rawResponse)` | `Result::Success` |
| 2 | 응답 크기 확인 | `rawResponse.size()` | `> 48` (최소 헤더 크기) |
| 3 | 헤더 시그니처 확인 | `rawResponse[0..3]` | Discovery 헤더의 총 길이 필드 |

#### Code Example
```cpp
Bytes rawResponse;
auto r = api.discovery0Raw(mock, rawResponse);
EXPECT_OK(r);
EXPECT_GT(rawResponse.size(), 48u);
```

---

## TS-1A-003: Discovery0 Custom — 잘못된 Protocol ID로 네거티브 테스트

**Category**: L1 — Discovery | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `discovery0Custom()`으로 비표준 protocolId/comId를 사용했을 때 동작 확인. 네거티브 테스트 기반.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 잘못된 프로토콜로 Discovery | `api.discovery0Custom(transport, 0xFF, 0xFFFF, raw)` | 에러 또는 빈 응답 |
| 2 | 올바른 프로토콜로 Discovery | `api.discovery0Custom(transport, 0x01, 0x0001, raw)` | `Result::Success` |

#### Educational Notes
- **Common Mistake**: Discovery는 반드시 Protocol 0x01, ComID 0x0001을 사용해야 합니다. 다른 값은 TPer가 무시하거나 에러를 반환합니다.

---

## TS-1B-001: Properties Exchange 기본

**Category**: L1 — Properties | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: Properties 교환 후 TPer의 MaxComPacketSize, MaxPacketSize 등을 올바르게 파싱하는지 검증.

#### Prerequisites
- MockTransport에 유효한 Properties 응답 큐잉 (TPerProperties + HostProperties echo)

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Properties 교환 | `api.exchangeProperties(transport, comId, result)` | `Result::Success` |
| 2 | MaxComPacketSize 확인 | `result.tperMaxComPacketSize` | `> 0` (일반적으로 2048+) |
| 3 | MaxPacketSize 확인 | `result.tperMaxPacketSize` | `> 0` |
| 4 | MaxIndTokenSize 확인 | `result.tperMaxIndTokenSize` | `> 0` |
| 5 | Raw 페이로드 존재 확인 | `result.raw.rawSendPayload.size()` | `> 0` |

#### Code Example
```cpp
PropertiesResult result;
auto r = api.exchangeProperties(transport, comId, result);
EXPECT_OK(r);
EXPECT_GT(result.tperMaxComPacketSize, 0u);
EXPECT_GT(result.raw.rawSendPayload.size(), 0u);
```

#### Educational Notes
- **Wire-Level**: Properties는 StackReset(Protocol 0x02) 후에 수행해야 합니다. `exchangeProperties()`는 내부적으로 StackReset을 먼저 호출합니다 (Hammurabi Law 7).
- **Common Mistake**: "MaxSubpackets"의 'p'는 소문자. "MaxSubPackets"로 보내면 일부 TPer가 0x0C(Invalid Parameter) 반환 (Hammurabi Law 6).

---

## TS-1B-002: Properties Custom 값 전송

**Category**: L1 — Properties | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `exchangePropertiesCustom()`으로 커스텀 호스트 값을 전송했을 때 페이로드에 해당 값이 포함되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 커스텀 Properties 교환 | `api.exchangePropertiesCustom(transport, comId, 4096, 4080, 4064, result)` | `Result::Success` |
| 2 | 전송 페이로드에 4096 포함 확인 | `result.raw.rawSendPayload` 검사 | 4096 (0x1000) 값이 인코딩됨 |

---

## TS-1C-001: 익명 세션 열기

**Category**: L1 — Session | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: 인증 없이 읽기 전용 AdminSP 세션을 열고 TSN/HSN이 할당되는지 확인.

#### Prerequisites
- MockTransport에 유효한 SyncSession 응답 큐잉

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 익명 세션 시작 | `api.startSession(session, uid::SP_ADMIN, false, result)` | `Result::Success` |
| 2 | TSN 확인 | `result.tperSessionNumber` | `> 0` |
| 3 | HSN 확인 | `result.hostSessionNumber` | `> 0` |
| 4 | 세션 활성 확인 | `session.isActive()` | `true` |

#### Code Example
```cpp
Session session(transport, comId);
StartSessionResult result;
auto r = api.startSession(session, uid::SP_ADMIN, false, result);
EXPECT_OK(r);
EXPECT_GT(result.tperSessionNumber, 0u);
```

#### Educational Notes
- **TCG Spec Reference**: TCG Core Spec Table 225 "StartSession Method"
- **Wire-Level**: 익명 세션은 HostChallenge, HostExchangeAuthority 필드를 생략합니다. TSN=0, HSN=0인 SM 패킷으로 전송됩니다.

---

## TS-1C-002: 인증 세션 열기

**Category**: L1 — Session | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: SID 자격 증명으로 쓰기 세션을 열고 SyncSession의 모든 필드가 파싱되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | SID 인증 세션 시작 | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, uid::AUTH_SID, credential, result)` | `Result::Success` |
| 2 | TSN/HSN 확인 | `result.tperSessionNumber`, `result.hostSessionNumber` | 둘 다 `> 0` |
| 3 | SP 세션 타임아웃 확인 | `result.spSessionTimeout` | TPer 기본값 (0 = 무제한 또는 양수) |

---

## TS-1C-003: 세션 종료

**Category**: L1 — Session | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `closeSession()` 호출 후 세션이 비활성화되고 CloseSession 토큰(0xFA)이 전송되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSession(...)` | `Result::Success` |
| 2 | 세션 종료 | `api.closeSession(session)` | `Result::Success` |
| 3 | 비활성 확인 | `session.isActive()` | `false` |
| 4 | 전송 페이로드 확인 | `sendHistory` 마지막 항목 | 0xFA 토큰 포함 |

#### Educational Notes
- **Wire-Level**: CloseSession은 특수합니다. CALL/EOD 래퍼 없이 0xFA 토큰만 전송합니다 (Hammurabi Law 11).
- **Common Mistake**: CloseSession을 일반 메서드 호출처럼 buildSmCall()로 래핑하면 안 됩니다.

---

## TS-1C-004: StartSession/SyncSession 분리 호출

**Category**: L1 — Session | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `sendStartSession()` + `recvSyncSession()`을 분리 호출하여 중간 상태를 검사할 수 있는지 확인. 평가 시나리오에서 fault injection 지점 제공.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | StartSession만 전송 | `api.sendStartSession(transport, comId, params, rawSent)` | `Result::Success` |
| 2 | 전송 페이로드 검사 | `rawSent` | StartSession 토큰 포함 |
| 3 | ↑ 여기서 fault injection 가능 | — | — |
| 4 | SyncSession 수신 | `api.recvSyncSession(transport, comId, syncResult)` | `Result::Success` |
| 5 | TSN 확인 | `syncResult.tperSessionNumber` | `> 0` |
| 6 | SP Challenge 존재 여부 | `syncResult.spChallenge` | 빈 바이트 또는 TPer 제공 값 |

#### Code Example
```cpp
StartSessionParams params;
params.spUid = uid::SP_ADMIN;
params.write = true;
params.hostChallenge = credential;
params.hostExchangeAuthority = uid::AUTH_SID;

Bytes rawSent;
api.sendStartSession(transport, comId, params, rawSent);
// ← fault injection 가능 지점
SyncSessionResult syncResult;
api.recvSyncSession(transport, comId, syncResult);
```

#### Educational Notes
- **교육 포인트**: 분리된 REQ/OPT 호출은 평가 시나리오의 핵심입니다. SyncSession 수신 전에 패킷을 변조하거나, 의도적으로 응답을 지연시키는 테스트가 가능합니다.

---

## TS-1D-001: C_PIN MSID 읽기

**Category**: L1 — C_PIN | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: 익명 세션에서 CPIN_MSID의 PIN 값을 읽을 수 있는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 익명 AdminSP 세션 시작 | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | Success |
| 2 | MSID 읽기 | `api.getCPin(session, uid::CPIN_MSID, pin, raw)` | Success |
| 3 | PIN 값 확인 | `pin.size()` | `> 0` (일반적으로 20~32 바이트) |
| 4 | 세션 종료 | `api.closeSession(session)` | Success |

---

## TS-1D-002: C_PIN SID 설정 (Bytes)

**Category**: L1 — C_PIN | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `setCPin()`으로 SID PIN을 바이트 배열로 설정하고, Set 메서드가 올바르게 인코딩되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | SID 인증 세션 시작 | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, uid::AUTH_SID, msid, ssr)` | Success |
| 2 | SID PIN 설정 | `api.setCPin(session, uid::CPIN_SID, newPin, raw)` | Success |
| 3 | 전송 페이로드 검증 | `raw.rawSendPayload` | Set 메서드 + Where절(빈) + Values절(PIN) |
| 4 | 세션 종료 | `api.closeSession(session)` | Success |

#### Educational Notes
- **Common Mistake**: Set 메서드에는 빈 Where 절이 반드시 포함되어야 합니다: `STARTNAME 0 STARTLIST ENDLIST ENDNAME`. 이를 생략하면 sedutil과 5바이트 차이가 납니다 (Hammurabi Law 3).

---

## TS-1D-003: C_PIN SID 설정 (String)

**Category**: L1 — C_PIN | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: 문자열 오버로드 `setCPin(session, uid, "password")`가 동일하게 동작하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | SID 인증 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | 문자열로 PIN 설정 | `api.setCPin(session, uid::CPIN_SID, "new_password", raw)` | Success |
| 3 | 바이트 버전과 페이로드 비교 | `raw.rawSendPayload` | 문자열 UTF-8 바이트가 PIN 값으로 인코딩 |

---

## TS-1E-001: Table Get 컬럼 범위 읽기

**Category**: L1 — Table | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `tableGet()`으로 특정 컬럼 범위(예: 3~5)를 읽고 TableResult에 올바른 컬럼 ID와 값이 반환되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(session, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, cred, ssr)` | Success |
| 2 | Locking Range 1 컬럼 3~7 읽기 | `api.tableGet(session, uid::LOCKING_RANGE1, 3, 7, tableResult)` | Success |
| 3 | 반환 컬럼 수 확인 | `tableResult.columns.size()` | 5 (col 3,4,5,6,7) |
| 4 | 각 컬럼 ID 확인 | `tableResult.columns[i].first` | 3, 4, 5, 6, 7 |

---

## TS-1E-002: Table SetMultiUint

**Category**: L1 — Table | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `tableSetMultiUint()`으로 여러 uint 컬럼을 한 번에 설정하는 인코딩 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | 다중 컬럼 설정 | `api.tableSetMultiUint(session, uid::LOCKING_RANGE1, {{3, 0}, {4, 2048}}, raw)` | Success |
| 3 | 페이로드에 두 값 포함 확인 | `raw.rawSendPayload` | 0, 2048이 power-of-2 인코딩 |

#### Educational Notes
- **Common Mistake**: 정수 인코딩은 반드시 power-of-2 바이트 폭(1,2,4,8)만 사용해야 합니다. 값 0x100000은 4바이트(0x84)로 인코딩, 절대 3바이트(0x83) 아님 (Hammurabi Law 2).

---

## TS-1E-003: Table GetAll

**Category**: L1 — Table | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: `tableGetAll()`이 객체의 모든 컬럼을 반환하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | 전체 컬럼 읽기 | `api.tableGetAll(session, uid::LOCKING_RANGE1, tableResult)` | Success |
| 3 | 컬럼 수 확인 | `tableResult.columns.size()` | 잠금 범위의 전체 컬럼 수 (보통 10+) |

---

## TS-1F-001: Locking Range 설정

**Category**: L1 — Range | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: MockTransport

**Purpose**: `setRange()`로 Range의 시작/길이/RLE/WLE를 설정하는 인코딩 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | Range 1 설정 | `api.setRange(session, 1, 0, 2048, true, true, raw)` | Success |
| 3 | 페이로드 확인 | `raw.rawSendPayload` | Set 메서드 + Where(빈) + Values(start=0, len=2048, RLE=1, WLE=1) |

---

## TS-1F-002: Range Lock/Unlock 상태 설정

**Category**: L1 — Range | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: MockTransport

**Purpose**: `setRangeLock()`으로 ReadLocked/WriteLocked 플래그를 설정하는 인코딩 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | Range 잠금 | `api.setRangeLock(session, 1, true, true, raw)` | Success |
| 3 | Range 잠금 해제 | `api.setRangeLock(session, 1, false, false, raw)` | Success |

---

## TS-1F-003: Range 정보 조회

**Category**: L1 — Range | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: MockTransport

**Purpose**: `getRangeInfo()`가 LockingRangeInfo 구조체의 모든 필드를 채우는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | Range 정보 조회 | `api.getRangeInfo(session, 1, info, raw)` | Success |
| 3 | 필드 확인 | `info.rangeStart, info.rangeLength, info.readLocked, info.writeLocked` | 설정한 값과 일치 |

---

## TS-1G-001: 인증 (Bytes 자격 증명)

**Category**: L1 — Auth | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: 활성 세션에서 `authenticate()`로 추가 인증을 수행하고 성공하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 익명 세션 시작 | `api.startSession(session, uid::SP_LOCKING, false, ssr)` | Success |
| 2 | Admin1 인증 | `api.authenticate(session, uid::AUTH_ADMIN1, credential, raw)` | Success |
| 3 | 인증 후 쓰기 가능 확인 | `api.setRange(...)` | Success |

---

## TS-1G-002: 인증 (String 패스워드)

**Category**: L1 — Auth | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: 문자열 오버로드 `authenticate(session, uid, "password")`가 동일하게 동작하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSession(...)` | Success |
| 2 | 문자열 인증 | `api.authenticate(session, uid::AUTH_ADMIN1, "password", raw)` | Success |

---

# Level 2: 표준 시퀀스 검증 (Standard Sequence Tests)

> TCG Application Note에 정의된 표준 프로토콜 흐름을 처음부터 끝까지 실행합니다.
> 각 시퀀스는 실제 디바이스에서 수행되는 완전한 작업 단위입니다.

---

## TS-2A-001: Query Flow — sedutil --query 동등 흐름

**Category**: L2 — Query | **API Layer**: EvalApi + EvalComposite | **SSC**: All | **Transport**: MockTransport / Real

**Purpose**: Discovery → Properties → 익명 세션 → MSID 읽기 → 세션 종료의 전체 조회 흐름 검증. sedutil의 `--query` 동작과 동일.

**Cross-Reference**: `examples/eval/query_flow.cpp`, `examples/facade/01_query.cpp`

#### Prerequisites
- 디바이스가 공장 초기 상태 (MSID == SID)

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Level 0 Discovery | `api.discovery0(transport, info)` | Success, SSC 타입 감지 |
| 2 | ComID 획득 | `info.baseComId` | `!= 0` |
| 3 | Properties 교환 | `api.exchangeProperties(transport, comId, props)` | Success, MaxComPacketSize > 0 |
| 4 | 익명 세션 시작 | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | Success, TSN 할당 |
| 5 | MSID 읽기 | `api.getCPin(session, uid::CPIN_MSID, msid)` | Success, msid.size() > 0 |
| 6 | 세션 종료 | `api.closeSession(session)` | Success |

#### Code Example
```cpp
// Composite 버전 (한 줄)
Bytes msid;
auto r = composite::getMsid(api, transport, comId, msid);
EXPECT_OK(r.overall);
EXPECT_FALSE(msid.empty());

// 또는 SedDrive facade
SedDrive drive(transport);
drive.query();
printf("SSC: %s, MSID: %s\n", drive.sscName(), drive.msidString().c_str());
```

#### Cleanup
- 없음 (읽기 전용)

#### Educational Notes
- **교육 포인트**: 이것이 SED 작업의 시작점입니다. 모든 다른 시나리오는 Query Flow가 성공한 후에 수행됩니다.
- **Wire-Level**: Discovery는 TSN=0/HSN=0으로 전송 (세션 외부). Properties도 SM 수준이므로 TSN=0/HSN=0. StartSession 응답(SyncSession)에서 TPer가 TSN을 할당합니다.

---

## TS-2A-002: Take Ownership — 소유권 획득 (AppNote 3)

**Category**: L2 — Ownership | **API Layer**: EvalComposite | **SSC**: All | **Transport**: MockTransport / Real

**Purpose**: MSID를 읽어 SID 인증 → SID PIN 변경으로 디바이스 소유권을 확보하는 표준 흐름.

**Cross-Reference**: `examples/facade/02_take_ownership.cpp`, `examples/appnote/appnote_opal.cpp`

#### Prerequisites
- 디바이스가 공장 초기 상태 (MSID == SID)

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | MSID 읽기 | `composite::getMsid(api, transport, comId, msid)` | Success |
| 2 | SID 인증 세션 시작 (MSID 사용) | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, uid::AUTH_SID, msid, ssr)` | Success |
| 3 | SID PIN 변경 | `api.setCPin(session, uid::CPIN_SID, newSidPassword, raw)` | Success |
| 4 | 세션 종료 | `api.closeSession(session)` | Success |
| 5 | 검증: 새 비밀번호로 인증 | `api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, newSidPassword)` | Success |
| 6 | 검증: MSID로 인증 실패 | `api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, msid)` | AuthFailed |

#### Cleanup
- `composite::revertToFactory(api, transport, comId, newSidPassword)` 로 공장 초기화

#### Educational Notes
- **Common Mistake**: MSID는 제조 시 설정된 값으로, 공장 초기 상태에서 SID의 PIN과 동일합니다. Take Ownership 후에는 SID PIN만 변경되고 MSID는 변하지 않습니다.
- **TCG Spec Reference**: TCG Storage Application Note (AN) — Section 3

---

## TS-2A-003: Activate Locking SP (AppNote 4)

**Category**: L2 — SP Lifecycle | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: Locking SP를 Manufactured-Inactive에서 Active로 전환.

#### Prerequisites
- Take Ownership 완료 (SID 비밀번호 알고 있음)

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | SID 세션 시작 (AdminSP, RW) | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, uid::AUTH_SID, sidPw, ssr)` | Success |
| 2 | SP Lifecycle 확인 | `api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle, raw)` | lifecycle == 8 (Manufactured-Inactive) |
| 3 | Locking SP 활성화 | `api.activate(session, uid::SP_LOCKING, raw)` | Success |
| 4 | 활성화 확인 | `api.getSpLifecycle(session, uid::SP_LOCKING, lifecycle, raw)` | lifecycle == 0 (Manufactured = Active) |
| 5 | 세션 종료 | `api.closeSession(session)` | Success |

#### Cleanup
- `api.revertSP(session, uid::SP_ADMIN)` 후 `composite::revertToFactory()`

#### Educational Notes
- **Common Mistake**: Locking SP 활성화 후 Admin1의 초기 비밀번호는 MSID입니다. 대부분의 개발자가 빈 문자열을 기대합니다.
- **TCG Spec Reference**: TCG Core Spec — SP Lifecycle states

---

## TS-2A-004: Configure Locking Range (AppNote 5)

**Category**: L2 — Range | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: Locking Range 1의 시작/길이/잠금 활성화를 설정하고 검증.

#### Prerequisites
- Locking SP 활성화 완료, Admin1 비밀번호 설정 완료

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 (LockingSP) | `api.startSessionWithAuth(session, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw, ssr)` | Success |
| 2 | Range 1 설정 | `api.setRange(session, 1, 0, 1048576, true, true, raw)` | Success |
| 3 | Range 정보 검증 | `api.getRangeInfo(session, 1, info, raw)` | start=0, length=1048576, RLE=true, WLE=true |
| 4 | 세션 종료 | `api.closeSession(session)` | Success |

#### Code Example
```cpp
// Composite 버전
auto r = composite::configureRangeAndLock(api, transport, comId, admin1Pw, 1, 0, 1048576);
EXPECT_OK(r.overall);
// steps: SetRange → Lock → Unlock → Verify
```

---

## TS-2A-005: Lock / Unlock Range (AppNote 8)

**Category**: L2 — Range Lock | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: Range를 잠그고 해제하는 전체 사이클을 검증.

#### Prerequisites
- Range 1이 설정됨 (RLE=true, WLE=true), Admin1 비밀번호 설정 완료

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | Range 1 잠금 | `api.setRangeLock(session, 1, true, true, raw)` | Success |
| 3 | 잠금 확인 | `api.getRangeInfo(session, 1, info, raw)` | readLocked=true, writeLocked=true |
| 4 | Range 1 잠금 해제 | `api.setRangeLock(session, 1, false, false, raw)` | Success |
| 5 | 잠금 해제 확인 | `api.getRangeInfo(session, 1, info, raw)` | readLocked=false, writeLocked=false |
| 6 | 세션 종료 | `api.closeSession(session)` | Success |

---

## TS-2A-006: User Enable + ACE Setup (AppNote 6-7)

**Category**: L2 — User Management | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: User1을 활성화하고 비밀번호를 설정한 후 Range1에 대한 ACE를 구성하여 User1이 잠금/해제할 수 있도록 함.

#### Prerequisites
- Locking SP 활성화, Admin1 비밀번호 설정, Range 1 구성 완료

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(session, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw, ssr)` | Success |
| 2 | User1 활성화 | `api.enableUser(session, 1, raw)` | Success |
| 3 | User1 비밀번호 설정 | `api.setUserPassword(session, 1, "user1_pw", raw)` | Success |
| 4 | User1을 Range1에 할당 | `api.assignUserToRange(session, 1, 1, raw)` | Success |
| 5 | 세션 종료 | `api.closeSession(session)` | Success |
| 6 | User1 세션 시작 | `api.startSessionWithAuth(session2, uid::SP_LOCKING, true, uid::AUTH_USER1, "user1_pw", ssr)` | Success |
| 7 | User1이 Range1 잠금 | `api.setRangeLock(session2, 1, true, true, raw)` | Success |
| 8 | User1이 Range1 잠금 해제 | `api.setRangeLock(session2, 1, false, false, raw)` | Success |
| 9 | 세션 종료 | `api.closeSession(session2)` | Success |

#### Educational Notes
- **Common Mistake**: User를 활성화하고 비밀번호를 설정해도 ACE에 추가하지 않으면 MethodNotAuthorized 에러가 발생합니다. `assignUserToRange()`가 내부적으로 ACE Set을 수행합니다.
- **TCG Spec Reference**: TCG Application Note — Section 6-7 (User Management)

---

## TS-2A-007: MBR Shadow Write / Read (AppNote 9)

**Category**: L2 — MBR | **API Layer**: EvalComposite | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: MBR 섀도잉 활성화 → 데이터 쓰기 → 읽기 비교 → MBRDone 설정의 전체 흐름.

#### Prerequisites
- Locking SP 활성화, Admin1 비밀번호 설정 완료

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | MBR 활성화 | `api.setMbrEnable(session, true, raw)` | Success |
| 3 | MBR 데이터 쓰기 | `api.writeMbrData(session, 0, pbaData, raw)` | Success |
| 4 | MBR 데이터 읽기 | `api.readMbrData(session, 0, pbaData.size(), readBack, raw)` | Success |
| 5 | 데이터 비교 | `pbaData == readBack` | true |
| 6 | MBRDone 설정 | `api.setMbrDone(session, true, raw)` | Success |
| 7 | MBR 상태 확인 | `api.getMbrStatus(session, enabled, done, raw)` | enabled=true, done=true |
| 8 | 세션 종료 | `api.closeSession(session)` | Success |

#### Code Example
```cpp
// Composite 버전
Bytes pba = {0x55, 0xAA, /* PBA image... */};
auto r = composite::mbrWriteAndVerify(api, transport, comId, admin1Pw, pba);
EXPECT_OK(r.overall);
```

---

## TS-2A-008: Crypto Erase (AppNote 10)

**Category**: L2 — Crypto | **API Layer**: EvalComposite | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: Range의 ActiveKey를 읽고 CryptoErase 후 키가 변경되었는지 확인.

#### Prerequisites
- Range 1 구성 완료

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | ActiveKey 읽기 (변경 전) | `api.getActiveKey(session, 1, keyBefore, raw)` | Success |
| 3 | Crypto Erase 수행 | `api.cryptoErase(session, 1, raw)` | Success |
| 4 | ActiveKey 읽기 (변경 후) | `api.getActiveKey(session, 1, keyAfter, raw)` | Success |
| 5 | 키 변경 확인 | `keyBefore != keyAfter` | true |
| 6 | 세션 종료 | `api.closeSession(session)` | Success |

#### Educational Notes
- **교육 포인트**: CryptoErase는 실제 디스크 데이터를 지우는 것이 아니라 암호화 키를 새로 생성하여 이전 데이터를 복호화 불가능하게 만듭니다. Range 설정(start, length)은 유지됩니다.

---

## TS-2A-009: Revert to Factory (AppNote 13)

**Category**: L2 — Revert | **API Layer**: EvalComposite | **SSC**: All | **Transport**: MockTransport / Real

**Purpose**: SID 인증으로 AdminSP를 공장 초기화. 실패 시 PSID fallback.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | SID 인증 세션 시작 | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, uid::AUTH_SID, sidPw, ssr)` | Success |
| 2 | RevertSP(AdminSP) | `api.revertSP(session, uid::SP_ADMIN, raw)` | Success |
| 3 | 세션 자동 종료 확인 | — | TPer가 세션을 자동 종료 |
| 4 | 공장 상태 확인: MSID 읽기 | `composite::getMsid(api, transport, comId, msid)` | Success |
| 5 | MSID로 SID 인증 | `api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, msid)` | Success (MSID == SID) |

#### Educational Notes
- **Common Mistake**: RevertSP 후 세션은 TPer에 의해 자동 종료됩니다. `closeSession()`을 별도로 호출하면 에러가 날 수 있습니다. `withSession` RAII 패턴은 이를 안전하게 처리합니다.

---

## TS-2A-010: PSID Revert

**Category**: L2 — Revert | **API Layer**: EvalComposite | **SSC**: All | **Transport**: MockTransport / Real

**Purpose**: PSID(물리적 보안 ID)로 공장 초기화 후 MSID == SID 상태 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | PSID 세션 시작 | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, uid::AUTH_PSID, psidBytes, ssr)` | Success |
| 2 | PSID Revert | `api.psidRevert(session, raw)` | Success |
| 3 | 세션 자동 종료 | — | TPer 자동 종료 |
| 4 | MSID == SID 확인 | `api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, msid)` | Success |

#### Code Example
```cpp
auto r = composite::psidRevertAndVerify(api, transport, comId, psidString);
EXPECT_OK(r.overall);
```

#### Educational Notes
- **교육 포인트**: PSID는 드라이브 라벨에 인쇄된 32자리 문자열입니다. SID 비밀번호를 분실했을 때 유일한 복구 수단입니다.

---

## TS-2A-011: DataStore Round Trip

**Category**: L2 — DataStore | **API Layer**: EvalComposite | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: DataStore 테이블에 데이터를 쓰고 읽어서 비교하는 전체 흐름.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | ByteTable 정보 조회 | `api.getByteTableInfo(session, info, raw)` | maxSize > 0 |
| 3 | 데이터 쓰기 | `api.tcgWriteDataStore(session, 0, testData, raw)` | Success |
| 4 | 데이터 읽기 | `api.tcgReadDataStore(session, 0, testData.size(), readResult)` | Success |
| 5 | 데이터 비교 | `readResult.data == testData` | true |
| 6 | 세션 종료 | `api.closeSession(session)` | Success |

---

## TS-2A-012: NVMe Block SID Feature

**Category**: L2 — NVMe | **API Layer**: EvalComposite | **SSC**: All | **Transport**: Real (NVMe only)

**Purpose**: NVMe Block SID Feature를 설정하여 SID 인증을 차단하고, 해제 후 복구되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Block SID 활성화 | `EvalApi::nvmeSetFeature(transport, 0x17, 0, 1)` | Success |
| 2 | SID 인증 시도 | `api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, sidPw)` | AuthFailed (차단됨) |
| 3 | Block SID 해제 | `EvalApi::nvmeSetFeature(transport, 0x17, 0, 0)` | Success |
| 4 | SID 인증 재시도 | `api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, sidPw)` | Success |

---

## TS-2A-013: Stack Reset 후 세션 복구

**Category**: L2 — ComID | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport / Real

**Purpose**: StackReset이 ComID 상태를 초기화하고 새 세션이 정상 열리는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | Success |
| 2 | ComID 활성 확인 | `api.verifyComId(transport, comId, active)` | active = true (세션으로 occupied) |
| 3 | Stack Reset | `api.stackReset(transport, comId)` | Success |
| 4 | 기존 세션 무효화 확인 | 기존 session으로 작업 시도 | 에러 (세션 무효) |
| 5 | 새 세션 시작 | `api.startSession(session2, uid::SP_ADMIN, false, ssr)` | Success |

---

## TS-2A-014: Enterprise Band Setup

**Category**: L2 — Enterprise | **API Layer**: EvalApi | **SSC**: Enterprise | **Transport**: MockTransport / Real

**Purpose**: Enterprise SSC의 Band 설정, 잠금, 해제 전체 흐름.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | BandMaster0 세션 시작 | `api.startSessionWithAuth(session, uid::SP_ENTERPRISE, true, uid::AUTH_BANDMASTER0, bm0Pw, ssr)` | Success |
| 2 | Band 1 구성 | `api.configureBand(session, 1, 0, 1048576, true, true, raw)` | Success |
| 3 | Band 1 잠금 | `api.lockBand(session, 1, raw)` | Success |
| 4 | Band 정보 확인 | `api.getBandInfo(session, 1, info, raw)` | readLocked=true, writeLocked=true |
| 5 | Band 1 해제 | `api.unlockBand(session, 1, raw)` | Success |
| 6 | 세션 종료 | `api.closeSession(session)` | Success |

---

## TS-2A-015: Revert Locking SP Only

**Category**: L2 — Revert | **API Layer**: EvalComposite | **SSC**: Opal 2.0 | **Transport**: MockTransport / Real

**Purpose**: Admin1 인증으로 Locking SP만 Revert하고, AdminSP는 유지되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 (LockingSP) | `api.startSessionWithAuth(session, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, admin1Pw, ssr)` | Success |
| 2 | RevertSP(LockingSP) | `api.revertSP(session, uid::SP_LOCKING, raw)` | Success |
| 3 | 세션 자동 종료 | — | TPer 자동 종료 |
| 4 | AdminSP SID 인증 확인 | `api.verifyAuthority(transport, comId, uid::SP_ADMIN, uid::AUTH_SID, sidPw)` | Success (AdminSP 유지) |
| 5 | Locking SP lifecycle 확인 | SP_LOCKING lifecycle | Manufactured-Inactive (재활성화 필요) |

---

# Level 3: 기능 간 연동 검증 (Cross-Feature Tests)

> 여러 기능을 결합한 복합 시나리오입니다. 실제 제품 개발 시 마주치는
> 통합 문제, 순서 의존성, 상태 전이를 검증합니다.
> 각 시나리오에는 TC 개발자가 흔히 빠지는 함정(gotcha)이 포함되어 있습니다.

---

## TS-3A-001: Full Opal Lifecycle — 전체 수명 주기

**Category**: L3 — Lifecycle | **API Layer**: EvalApi + EvalComposite | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 공장 상태 → 소유권 → 활성화 → Range 설정 → User 설정 → MBR → Lock/Unlock → Revert까지 전체 Opal 수명 주기를 한 번에 검증.

**Cross-Reference**: `examples/appnote/appnote_opal.cpp`, `examples/facade/03_opal_full_setup.cpp`

#### Prerequisites
- 디바이스가 공장 초기 상태

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Query Flow | `drive.query()` | SSC=Opal20, MSID 획득 |
| 2 | Take Ownership | `drive.takeOwnership("my_sid_pw")` | Success |
| 3 | Activate Locking SP | `drive.activateLocking("my_sid_pw")` | Success |
| 4 | Configure Range 1 | `drive.configureRange(1, 0, 1048576, "admin1_pw")` | Success |
| 5 | Setup User 1 | `drive.setupUser(1, "user1_pw", 1, "admin1_pw")` | Success |
| 6 | MBR Enable | `drive.setMbrEnable(true, "admin1_pw")` | Success |
| 7 | MBR Write | `session.writeMbr(0, pbaData)` | Success |
| 8 | MBR Done | `drive.setMbrDone(true, "admin1_pw")` | Success |
| 9 | User1 Lock Range | `drive.lockRange(1, "user1_pw")` | Success |
| 10 | Verify Locked | `session.getRangeInfo(1, info)` | readLocked=true, writeLocked=true |
| 11 | User1 Unlock Range | `drive.unlockRange(1, "user1_pw")` | Success |
| 12 | Verify Unlocked | `session.getRangeInfo(1, info)` | readLocked=false, writeLocked=false |
| 13 | Crypto Erase | `drive.cryptoErase(1, "admin1_pw")` | Success |
| 14 | Revert | `drive.revert("my_sid_pw")` | Success |
| 15 | 공장 상태 확인 | `drive.query()` | MSID == SID |

#### Educational Notes
- **Gotcha**: Revert 후 Admin1 비밀번호는 MSID로 복원됩니다 (빈 문자열이 아님!). 많은 개발자가 이 점을 놓칩니다.
- **순서 의존성**: 반드시 Ownership → Activate → Configure → User Setup 순서. Activate 전에 Range 설정하면 MethodSpDisabled.

---

## TS-3A-002: Multi-User Range Isolation — 다중 사용자 범위 격리

**Category**: L3 — User/ACE | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 3명의 사용자를 각각 다른 Range에 할당하고, 자신의 Range만 제어할 수 있는지 확인.

#### Prerequisites
- Locking SP 활성화, Admin1 비밀번호 설정 완료

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | Range 1 설정 (0~1M) | `api.setRange(session, 1, 0, 1048576, true, true)` | Success |
| 3 | Range 2 설정 (1M~2M) | `api.setRange(session, 2, 1048576, 1048576, true, true)` | Success |
| 4 | User1 활성화 + 비밀번호 + Range1 할당 | `enableUser(1)` + `setUserPassword(1)` + `assignUserToRange(1, 1)` | Success |
| 5 | User2 활성화 + 비밀번호 + Range2 할당 | `enableUser(2)` + `setUserPassword(2)` + `assignUserToRange(2, 2)` | Success |
| 6 | Admin1 세션 종료 | `api.closeSession(session)` | Success |
| 7 | User1 세션 → Range1 잠금 | `startSession(User1)` → `setRangeLock(1, true, true)` | Success |
| 8 | User1 → Range2 잠금 시도 | `setRangeLock(2, true, true)` | **MethodNotAuthorized** |
| 9 | User1 세션 종료 | `api.closeSession(...)` | Success |
| 10 | User2 세션 → Range2 잠금 | `startSession(User2)` → `setRangeLock(2, true, true)` | Success |
| 11 | User2 → Range1 잠금 시도 | `setRangeLock(1, true, true)` | **MethodNotAuthorized** |
| 12 | User2 세션 종료 | `api.closeSession(...)` | Success |

#### Educational Notes
- **Gotcha**: `assignUserToRange()`는 ACE_Locking_Range1_Set_RdLocked와 ACE_Locking_Range1_Set_WrLocked 양쪽에 Authority를 추가합니다. 수동으로 ACE를 설정할 때는 두 ACE 모두에 추가해야 합니다.
- **Common Mistake**: User를 활성화하고 비밀번호를 설정했지만 ACE에 추가하지 않는 경우 — 인증은 성공하지만 모든 잠금 작업이 MethodNotAuthorized.

---

## TS-3A-003: MBR + Locking Interaction — MBR과 잠금의 상호작용

**Category**: L3 — MBR/Locking | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: MBR 섀도잉과 Locking이 독립적으로 동작하는지 확인하고, MBRDone 플래그가 부트 동작에 미치는 영향을 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 2 | MBR Enable | `api.setMbrEnable(session, true)` | Success |
| 3 | MBR Done = false | `api.setMbrDone(session, false)` | Success |
| 4 | MBR 데이터 쓰기 (PBA) | `api.writeMbrData(session, 0, pba)` | Success |
| 5 | Range 1 설정 | `api.setRange(session, 1, 0, 1048576, true, true)` | Success |
| 6 | Range 1 잠금 | `api.setRangeLock(session, 1, true, true)` | Success |
| 7 | MBR 상태 확인 | `api.getMbrStatus(session, en, done)` | enabled=true, done=false |
| 8 | MBR Done = true (PBA 인증 후) | `api.setMbrDone(session, true)` | Success |
| 9 | Range 잠금 해제 | `api.setRangeLock(session, 1, false, false)` | Success |
| 10 | 세션 종료 | `api.closeSession(session)` | Success |

#### Educational Notes
- **교육 포인트**: MBRDone=false 상태에서 디스크 읽기 요청이 오면 실제 디스크 대신 MBR 섀도 영역을 반환합니다 (PBA 이미지). MBRDone=true로 설정하면 정상 디스크 접근으로 전환됩니다. 이것이 Pre-Boot Authentication의 핵심 메커니즘입니다.
- **Gotcha**: MBR Enable과 Locking은 독립적입니다. MBR을 활성화하지 않고 Range만 잠글 수 있고, 그 반대도 가능합니다.

---

## TS-3A-004: DataStore + User Access Control

**Category**: L3 — DataStore/ACE | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: DataStore에 대한 접근 제어를 검증. Admin1만 쓰기 가능하고 User1이 읽기만 가능한지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 → 데이터 쓰기 | `api.tcgWriteDataStore(session, 0, testData)` | Success |
| 2 | Admin1 세션 → 데이터 읽기 확인 | `api.tcgReadDataStore(session, 0, len, result)` | Success, data match |
| 3 | Admin1 세션 종료 | close | Success |
| 4 | User1 세션 시작 | `startSessionWithAuth(uid::SP_LOCKING, User1)` | Success |
| 5 | User1 → DataStore 읽기 시도 | `api.tcgReadDataStore(session, 0, len, result)` | MethodNotAuthorized (기본 ACE에 User1 없음) |
| 6 | User1 세션 종료 | close | Success |
| 7 | Admin1 세션 → User1을 DataStore ACE에 추가 | `api.addAuthorityToAce(session, dataStoreReadAce, uid::AUTH_USER1)` | Success |
| 8 | User1 세션 → DataStore 읽기 재시도 | `api.tcgReadDataStore(session, 0, len, result)` | **Success** (ACE 추가됨) |

---

## TS-3A-005: Crypto Erase + Range Reconfigure

**Category**: L3 — CryptoErase/Range | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: CryptoErase 후에 Range 설정이 유지되는지 확인하고, Range를 재구성하여 정상 동작하는지 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Range 1 설정 (0~1M) | `api.setRange(session, 1, 0, 1048576, true, true)` | Success |
| 2 | ActiveKey 기록 (before) | `api.getActiveKey(session, 1, keyBefore)` | Success |
| 3 | Crypto Erase | `api.cryptoErase(session, 1)` | Success |
| 4 | ActiveKey 기록 (after) | `api.getActiveKey(session, 1, keyAfter)` | keyAfter != keyBefore |
| 5 | Range 정보 확인 | `api.getRangeInfo(session, 1, info)` | start=0, length=1048576 (유지) |
| 6 | Range 재구성 (1M~2M) | `api.setRange(session, 1, 1048576, 1048576, true, true)` | Success |
| 7 | Lock/Unlock 사이클 | lock → verify → unlock → verify | Success |

#### Educational Notes
- **교육 포인트**: CryptoErase는 데이터만 파괴 (키 교체). Range 설정, User/ACE 구성은 모두 유지됩니다. Revert와 혼동하지 마세요.

---

## TS-3A-006: Password Rotation Under Active Session

**Category**: L3 — C_PIN/Session | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: 활성 세션 중에 비밀번호를 변경했을 때 현재 세션은 유지되고, 새 세션부터 새 비밀번호가 적용되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 (old_pw) | `api.startSessionWithAuth(...)` | Success |
| 2 | Admin1 비밀번호 변경 | `api.setAdmin1Password(session, "new_pw")` | Success |
| 3 | 현재 세션에서 작업 계속 | `api.getRangeInfo(session, 1, info)` | **Success** (세션 유지) |
| 4 | 세션 종료 | `api.closeSession(session)` | Success |
| 5 | 새 세션: old_pw로 시도 | `api.startSessionWithAuth(..., "old_pw", ...)` | **AuthFailed** |
| 6 | 새 세션: new_pw로 시도 | `api.startSessionWithAuth(..., "new_pw", ...)` | **Success** |

#### Educational Notes
- **Gotcha**: 비밀번호 변경은 즉시 적용되지만 현재 세션에는 영향을 주지 않습니다. 현재 세션은 이미 인증된 상태이므로 종료 시까지 유효합니다.

---

## TS-3A-007: Multi-Range + Global Range 상호작용

**Category**: L3 — Range | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: Global Range와 개별 Range의 잠금이 독립적으로 동작하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Range 1 설정 (0~1M) | `api.setRange(session, 1, 0, 1048576, true, true)` | Success |
| 2 | Range 2 설정 (1M~2M) | `api.setRange(session, 2, 1048576, 1048576, true, true)` | Success |
| 3 | Range 1만 잠금 | `api.setRangeLock(session, 1, true, true)` | Success |
| 4 | Range 2 상태 확인 | `api.getRangeInfo(session, 2, info)` | readLocked=false, writeLocked=false |
| 5 | Global Range 잠금 | `api.setRangeLock(session, 0, true, true)` | Success |
| 6 | Global Range 잠금 해제 | `api.setRangeLock(session, 0, false, false)` | Success |
| 7 | Range 1 여전히 잠금 상태 | `api.getRangeInfo(session, 1, info)` | readLocked=true (개별 잠금 유지) |

#### Educational Notes
- **교육 포인트**: Global Range(Range 0)는 개별 Range에 포함되지 않는 LBA 영역을 커버합니다. 개별 Range의 Lock/Unlock과 Global Range는 **독립적**입니다.

---

## TS-3A-008: LockOnReset + Power Cycle

**Category**: L3 — LockOnReset | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: LockOnReset 설정 후 StackReset(power cycle 시뮬레이션)을 수행하여 Range가 자동 잠금되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Range 1 설정 + RLE/WLE 활성화 | `api.setRange(session, 1, 0, 1M, true, true)` | Success |
| 2 | LockOnReset 활성화 | `api.setLockOnReset(session, 1, true)` | Success |
| 3 | Range 1 잠금 해제 | `api.setRangeLock(session, 1, false, false)` | Success |
| 4 | 잠금 해제 확인 | `api.getRangeInfo(session, 1, info)` | readLocked=false |
| 5 | 세션 종료 | `api.closeSession(session)` | Success |
| 6 | **Power Cycle 시뮬레이션** | `api.stackReset(transport, comId)` | Success |
| 7 | 새 세션 시작 | `api.startSessionWithAuth(...)` | Success |
| 8 | Range 1 자동 잠금 확인 | `api.getRangeInfo(session, 1, info)` | **readLocked=true, writeLocked=true** |

#### Educational Notes
- **교육 포인트**: LockOnReset은 "secure by default" 메커니즘입니다. 전원 차단이나 리셋 후 Range가 자동으로 잠기므로, 인증 없이는 디스크 데이터에 접근할 수 없습니다.
- **Gotcha**: StackReset은 완전한 power cycle과 다릅니다. 실제 디바이스에서는 NVMe Controller Reset 또는 전원 재투입이 필요할 수 있습니다.

---

## TS-3A-009: User Disable While Session Active

**Category**: L3 — User/Session | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: User1 세션이 활성인 상태에서 Admin1이 User1을 비활성화했을 때의 동작 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1: User1 활성화 + 비밀번호 설정 | enableUser + setUserPassword | Success |
| 2 | User1 세션 시작 | `startSessionWithAuth(User1)` | Success |
| 3 | Admin1 세션 시작 (별도) | `startSessionWithAuth(Admin1)` | Success |
| 4 | Admin1: User1 비활성화 | `api.disableUser(adminSession, 1)` | Success |
| 5 | User1: 작업 시도 | `api.setRangeLock(user1Session, 1, true, true)` | Success 또는 에러 (TPer 구현에 따라 다름) |
| 6 | User1 세션 종료 | close | Success |
| 7 | User1 재접속 시도 | `startSessionWithAuth(User1)` | **AuthFailed** (비활성화됨) |

#### Educational Notes
- **교육 포인트**: 이미 인증된 세션은 Authority 상태 변경에 영향을 받지 않을 수 있습니다 (TPer 구현 의존). 그러나 새 세션은 반드시 실패합니다.

---

## TS-3A-010: GenKey + GetActiveKey + CryptoErase Chain

**Category**: L3 — Key Management | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 키 관리의 전체 체인을 검증: 원래 키 → GenKey로 새 키 → CryptoErase로 또 다른 키.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `startSessionWithAuth(Admin1)` | Success |
| 2 | ActiveKey 읽기 (K1) | `api.getActiveKey(session, 1, k1)` | Success |
| 3 | GenKey 수행 | `api.genKey(session, uid::makeKAesUid(1))` | Success |
| 4 | ActiveKey 읽기 (K2) | `api.getActiveKey(session, 1, k2)` | k2 != k1 |
| 5 | CryptoErase 수행 | `api.cryptoErase(session, 1)` | Success |
| 6 | ActiveKey 읽기 (K3) | `api.getActiveKey(session, 1, k3)` | k3 != k2 |
| 7 | 세 키 모두 다른지 확인 | k1 != k2, k2 != k3, k1 != k3 | true |

---

## TS-3B-001: SedDrive Facade Full Lifecycle

**Category**: L3 — Facade | **API Layer**: SedDrive + SedSession | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: SedDrive facade API만으로 전체 Opal 수명 주기를 실행하여 facade의 완성도를 검증.

**Cross-Reference**: `examples/facade/03_opal_full_setup.cpp`

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 드라이브 생성 | `SedDrive drive("/dev/nvme0")` | 성공 |
| 2 | 조회 | `drive.query()` | Success, sscType()==Opal20 |
| 3 | 소유권 | `drive.takeOwnership("sid_pw")` | Success |
| 4 | 활성화 | `drive.activateLocking("sid_pw")` | Success |
| 5 | Range 설정 | `drive.configureRange(1, 0, 1M, "admin1_pw")` | Success |
| 6 | User 설정 | `drive.setupUser(1, "user1_pw", 1, "admin1_pw")` | Success |
| 7 | 잠금 | `drive.lockRange(1, "user1_pw")` | Success |
| 8 | 잠금 해제 | `drive.unlockRange(1, "user1_pw")` | Success |
| 9 | MBR 활성화 | `drive.setMbrEnable(true, "admin1_pw")` | Success |
| 10 | MBR Done | `drive.setMbrDone(true, "admin1_pw")` | Success |
| 11 | Crypto Erase | `drive.cryptoErase(1, "admin1_pw")` | Success |
| 12 | Revert | `drive.revert("sid_pw")` | Success |

---

## TS-3B-002: SedSession Multi-Session 동시 접근

**Category**: L3 — Multi-Session | **API Layer**: SedDrive + SedSession | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: SedDrive에서 여러 SedSession을 동시에 열고 독립적으로 작업할 수 있는지 확인. RAII 자동 정리 검증.

**Cross-Reference**: `examples/facade/04_multi_session.cpp`

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | AdminSP/SID 세션 | `auto s1 = drive.login(uid::SP_ADMIN, "sid_pw", uid::AUTH_SID)` | s1.ok() == true |
| 2 | LockingSP/Admin1 세션 | `auto s2 = drive.login(uid::SP_LOCKING, "admin1_pw", uid::AUTH_ADMIN1)` | s2.ok() == true |
| 3 | s1에서 AdminSP 작업 | `s1.getPin(uid::CPIN_MSID, pin)` | Success |
| 4 | s2에서 LockingSP 작업 | `s2.setRange(1, 0, 1M)` | Success |
| 5 | s1 수동 종료 | `s1.close()` | Success |
| 6 | s2는 여전히 활성 | `s2.isActive()` | true |
| 7 | 스코프 벗어남 → s2 자동 종료 | `~SedSession()` | 세션 자동 종료 |

---

## TS-3B-003: withSession Callback Pattern

**Category**: L3 — Composite Pattern | **API Layer**: EvalComposite | **SSC**: All | **Transport**: Real

**Purpose**: `withSession()` RAII 패턴이 성공/실패 모두에서 세션을 안전하게 정리하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 성공 콜백 | `withSession(api, transport, comId, SP_ADMIN, true, AUTH_SID, pw, [](Session& s) { return Result::success(); })` | Success, 세션 자동 종료 |
| 2 | 실패 콜백 | `withSession(api, transport, comId, SP_ADMIN, true, AUTH_SID, pw, [](Session& s) { return Result(ErrorCode::MethodFailed); })` | MethodFailed 반환, 세션 자동 종료 |
| 3 | 예외 안전성 | 콜백에서 예외 throw | 세션 여전히 종료됨 (RAII) |

---

## TS-3B-004: TableNext + TableGet 열거

**Category**: L3 — Table | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: `tableNext()`로 Locking 테이블의 모든 행을 열거하고, 각 행에 대해 `tableGetAll()`로 전체 데이터를 읽는 패턴 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `startSessionWithAuth(Admin1)` | Success |
| 2 | Locking 테이블 행 열거 | `api.tableNext(session, uid::TABLE_LOCKING, 0, rows, 20, raw)` | Success, rows.size() > 0 |
| 3 | 각 행 읽기 | for each row: `api.tableGetAll(session, row, result)` | Success |
| 4 | Global Range 존재 확인 | rows에 LOCKING_GLOBALRANGE 포함 | true |
| 5 | Range 1 존재 확인 | rows에 LOCKING_RANGE1 포함 | true (활성화된 경우) |

---

## TS-3B-005: Authority Status + C_PIN TryLimit

**Category**: L3 — Auth/C_PIN | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: C_PIN의 TryLimit 메커니즘을 검증. 잘못된 비밀번호로 인증을 반복하면 남은 시도 횟수가 감소하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `startSessionWithAuth(Admin1)` | Success |
| 2 | User1 활성화 | `api.enableUser(session, 1)` | Success |
| 3 | User1 활성 확인 | `api.isUserEnabled(session, 1, enabled)` | enabled = true |
| 4 | C_PIN_USER1 남은 시도 확인 | `api.getCPinTriesRemaining(session, uid::CPIN_USER1, remaining)` | remaining = 초기값 (예: 5) |
| 5 | Admin1 세션 종료 | close | Success |
| 6 | User1 잘못된 비밀번호로 인증 시도 | `api.verifyAuthority(transport, comId, SP_LOCKING, AUTH_USER1, "wrong")` | AuthFailed |
| 7 | 남은 시도 재확인 | `getCPinTriesRemaining(uid::CPIN_USER1, remaining)` | remaining = 초기값 - 1 |

---

## TS-3B-006: Composite StepLog 검사

**Category**: L3 — Debug | **API Layer**: EvalComposite | **SSC**: All | **Transport**: MockTransport

**Purpose**: CompositeResult의 steps 벡터를 검사하여 각 단계의 이름, 결과, raw 페이로드가 올바른지 확인. 디버깅 패턴 교육.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | activateAndSetup 실행 | `composite::activateAndSetup(api, transport, comId, sidPw, admin1Pw, user1Pw)` | CompositeResult 반환 |
| 2 | steps 수 확인 | `result.steps.size()` | 9 (시퀀스 단계 수) |
| 3 | 각 step name 확인 | `result.steps[0].name` | "getMsid", "StartSession", ... |
| 4 | passCount 확인 | `result.passCount()` | 전체 성공 시 == steps.size() |
| 5 | raw 페이로드 존재 확인 | `result.steps[i].raw.rawSendPayload.size()` | > 0 |

#### Educational Notes
- **교육 포인트**: CompositeResult는 복합 연산의 디버깅에 핵심입니다. 어느 단계에서 실패했는지, 실제로 어떤 바이트가 전송/수신되었는지를 단계별로 추적할 수 있습니다.

---

## TS-3B-007: DataStore Multi-Table Round Trip

**Category**: L3 — DataStore | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 여러 DataStore 테이블(0, 1)에 독립적으로 데이터를 쓰고 읽어 테이블 간 격리를 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Table 0에 데이터 A 쓰기 | `api.tcgWriteDataStoreN(session, 0, 0, dataA)` | Success |
| 2 | Table 1에 데이터 B 쓰기 | `api.tcgWriteDataStoreN(session, 1, 0, dataB)` | Success |
| 3 | Table 0에서 읽기 | `api.tcgReadDataStoreN(session, 0, 0, len, result)` | result.data == dataA |
| 4 | Table 1에서 읽기 | `api.tcgReadDataStoreN(session, 1, 0, len, result)` | result.data == dataB |

---

## TS-3B-008: MBR Multi-User Access

**Category**: L3 — MBR/ACE | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: MBR 데이터에 대한 다중 사용자 접근 제어 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1: MBR 활성화 + PBA 쓰기 | setMbrEnable(true) + writeMbrData() | Success |
| 2 | Admin1: User1 활성화 | enableUser(1) + setUserPassword(1) | Success |
| 3 | Admin1: User2 활성화 | enableUser(2) + setUserPassword(2) | Success |
| 4 | User1 세션: MBR 읽기 | `api.readMbrData(session, 0, len, data)` | Success 또는 MethodNotAuthorized (ACE 의존) |
| 5 | User2 세션: MBR 읽기 | `api.readMbrData(session, 0, len, data)` | Success 또는 MethodNotAuthorized |
| 6 | Admin1: MBR Done 설정 | `api.setMbrDone(session, true)` | Success |

---

## TS-3B-009: Session + Discovery Re-query

**Category**: L3 — Discovery/Session | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: 세션 열기/닫기 후 Discovery 재수행 시 값이 일관되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 첫 Discovery | `api.discovery0(transport, info1)` | Success |
| 2 | Properties 교환 | `api.exchangeProperties(transport, comId, props1)` | Success |
| 3 | 세션 열기/닫기 | startSession → closeSession | Success |
| 4 | 두 번째 Discovery | `api.discovery0(transport, info2)` | Success |
| 5 | Properties 재교환 | `api.exchangeProperties(transport, comId, props2)` | Success |
| 6 | 값 비교 | info1.baseComId == info2.baseComId, props1.tperMaxComPacketSize == props2.tperMaxComPacketSize | true |

---

## TS-3B-010: Enterprise Band Setup + EraseMaster

**Category**: L3 — Enterprise | **API Layer**: EvalApi | **SSC**: Enterprise | **Transport**: Real

**Purpose**: Enterprise SSC에서 Band 설정, BandMaster/EraseMaster 비밀번호 설정, Band Erase의 전체 흐름.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | BandMaster0 세션 시작 | `startSessionWithAuth(SP_ENTERPRISE, AUTH_BANDMASTER0)` | Success |
| 2 | Band 1 구성 | `api.configureBand(session, 1, 0, 1M, true, true)` | Success |
| 3 | BandMaster1 비밀번호 설정 | `api.setBandMasterPassword(session, 1, newBm1Pin)` | Success |
| 4 | Band 1 잠금 | `api.lockBand(session, 1)` | Success |
| 5 | 세션 종료 | close | Success |
| 6 | EraseMaster 세션 시작 | `startSessionWithAuth(SP_ENTERPRISE, AUTH_ERASEMASTER)` | Success |
| 7 | EraseMaster 비밀번호 변경 | `api.setEraseMasterPassword(session, newEmPin)` | Success |
| 8 | Band 1 소거 | `api.eraseBand(session, 1)` | Success |
| 9 | 세션 종료 | close | Success |

---

# Level 4: 오류/네거티브 검증 (Error & Negative Tests)

> 에러 핸들링, 잘못된 입력, 경계 조건, 권한 위반을 검증합니다.
> 각 시나리오는 특정 ErrorCode 반환을 기대합니다.

---

## TS-4A-001: 잘못된 비밀번호로 인증

**Category**: L4 — Auth Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: 올바른 Authority에 잘못된 자격 증명을 제공했을 때 AuthFailed가 반환되고 세션이 열리지 않는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 잘못된 비밀번호로 SID 인증 | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, uid::AUTH_SID, wrongPw, ssr)` | **AuthFailed (600)** |
| 2 | 세션 상태 확인 | `session.isActive()` | false |

---

## TS-4A-002: 존재하지 않는 Authority UID

**Category**: L4 — Auth Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: 존재하지 않는 Authority UID로 세션을 열 때 적절한 에러가 반환되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 가짜 Authority로 세션 시작 | `api.startSessionWithAuth(session, uid::SP_ADMIN, true, 0xDEADBEEF, cred, ssr)` | **MethodNotAuthorized (401)** 또는 **AuthFailed (600)** |

---

## TS-4A-003: 비활성 User로 인증

**Category**: L4 — Auth Error | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 비활성화된 User로 세션을 열 때 AuthFailed가 반환되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | User1이 비활성 상태인지 확인 | `api.isUserEnabled(session, 1, enabled)` | enabled = false |
| 2 | User1으로 세션 시작 시도 | `api.startSessionWithAuth(..., uid::AUTH_USER1, ...)` | **AuthFailed (600)** |

---

## TS-4A-004: 존재하지 않는 SP로 세션

**Category**: L4 — Session Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 가짜 SP로 세션 시작 | `api.startSession(session, 0xDEADBEEF, false, ssr)` | **MethodSpFailed (404)** |

---

## TS-4A-005: 이중 세션 열기

**Category**: L4 — Session Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: 이미 활성인 Session 객체에 다시 startSession을 호출했을 때 SessionAlreadyActive 에러 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 첫 번째 세션 시작 | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | Success |
| 2 | 두 번째 세션 시작 (같은 객체) | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | **SessionAlreadyActive (301)** |

---

## TS-4A-006: 세션 종료 후 메서드 호출

**Category**: L4 — Session Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSession(...)` | Success |
| 2 | 세션 종료 | `api.closeSession(session)` | Success |
| 3 | 종료된 세션에서 작업 | `api.tableGet(session, uid::LOCKING_RANGE1, 3, 7, result)` | **SessionNotStarted (300)** |

---

## TS-4A-007: 읽기 전용 세션에서 쓰기 시도

**Category**: L4 — Auth Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 읽기 전용 세션 시작 | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | Success (write=false) |
| 2 | PIN 변경 시도 | `api.setCPin(session, uid::CPIN_SID, newPin, raw)` | **MethodNotAuthorized (401)** |

---

## TS-4A-008: 비활성 Locking SP에서 Range 설정 시도

**Category**: L4 — SP Error | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: Locking SP가 Manufactured-Inactive 상태에서 Range 설정을 시도했을 때 에러 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Locking SP 세션 시작 시도 | `api.startSessionWithAuth(session, uid::SP_LOCKING, true, uid::AUTH_ADMIN1, cred, ssr)` | **MethodSpDisabled (405)** 또는 AuthFailed |

#### Educational Notes
- **교육 포인트**: Locking SP는 Activate 전에는 Manufactured-Inactive 상태입니다. 이 상태에서는 세션을 열 수 없거나 매우 제한된 작업만 가능합니다.

---

## TS-4A-009: 이미 활성인 SP 재활성화

**Category**: L4 — SP Error | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Locking SP 활성화 (첫 번째) | `api.activate(session, uid::SP_LOCKING)` | Success |
| 2 | Locking SP 재활성화 (두 번째) | `api.activate(session, uid::SP_LOCKING)` | **MethodFailed (463)** 또는 Success (TPer 구현 의존) |

---

## TS-4A-010: 인증 없이 Revert 시도

**Category**: L4 — Auth Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 익명 세션 시작 | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | Success |
| 2 | RevertSP 시도 | `api.revertSP(session, uid::SP_ADMIN, raw)` | **MethodNotAuthorized (401)** |

---

## TS-4B-001: 잘못된 ComID로 Discovery

**Category**: L4 — Transport Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 잘못된 ComID로 Discovery | `api.discovery0Custom(transport, 0x01, 0xFFFF, raw)` | 에러 또는 빈 응답 |

---

## TS-4B-002: 손상된 응답 처리

**Category**: L4 — Protocol Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: MockTransport에 손상된 바이트를 큐잉하고 exchangeProperties 호출 시 MalformedResponse가 반환되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 손상된 응답 큐잉 | `mock->queueRecvData({0xFF, 0xFE, 0xFD, 0xFC})` | — |
| 2 | StackReset 응답 큐잉 | `mock->queueRecvData({})` | — |
| 3 | Properties 교환 | `api.exchangeProperties(transport, comId, result)` | **MalformedResponse (207)** 또는 **InvalidPacket (201)** |

---

## TS-4B-003: 빈 응답 처리

**Category**: L4 — Protocol Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 빈 응답 큐잉 | `mock->queueRecvData({})` | — |
| 2 | Discovery 수행 | `api.discovery0(transport, info)` | **BufferTooSmall (204)** 또는 에러 |

---

## TS-4B-004: 트렁케이트된 패킷 응답

**Category**: L4 — Protocol Error | **API Layer**: EvalApi | **SSC**: All | **Transport**: MockTransport

**Purpose**: 유효한 ComPacket 헤더이지만 바디가 잘린 응답을 처리할 때 적절한 에러 반환 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 트렁케이트된 패킷 큐잉 | 20바이트 ComPacket 헤더만 큐잉 (바디 없음) | — |
| 2 | StartSession 시도 | `api.startSession(...)` | **InvalidPacket (201)** |

---

## TS-4B-005: 빈 문자열 비밀번호

**Category**: L4 — Boundary | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 빈 문자열로 PIN 설정 | `api.setCPin(session, uid::CPIN_SID, "", raw)` | Success 또는 에러 (TPer 의존) |
| 2 | 빈 문자열로 인증 | `api.verifyAuthority(transport, comId, SP_ADMIN, AUTH_SID, "")` | 결과 확인 |

#### Educational Notes
- **교육 포인트**: 일부 TPer는 빈 PIN을 허용하고 다른 TPer는 거부합니다. 디바이스 검증 시 이 동작을 문서화해야 합니다.

---

## TS-4B-006: 최대 길이 비밀번호

**Category**: L4 — Boundary | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 32바이트 PIN 설정 | `api.setCPin(session, uid::CPIN_SID, pin32, raw)` | Success (일반적으로 허용) |
| 2 | 33바이트 PIN 설정 | `api.setCPin(session, uid::CPIN_SID, pin33, raw)` | Success 또는 **MethodInvalidParam (412)** |
| 3 | 256바이트 PIN 설정 | `api.setCPin(session, uid::CPIN_SID, pin256, raw)` | 동작 확인 (TPer limit 테스트) |

---

## TS-4C-001: Range 길이 UINT64_MAX

**Category**: L4 — Boundary | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 초대형 Range 설정 | `api.setRange(session, 1, 0, UINT64_MAX, true, true)` | **MethodInvalidParam (412)** |

---

## TS-4C-002: 겹치는 Range 설정

**Category**: L4 — Boundary | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Range 1 설정 (0~1000) | `api.setRange(session, 1, 0, 1000, true, true)` | Success |
| 2 | Range 2 설정 (500~1000, 겹침) | `api.setRange(session, 2, 500, 1000, true, true)` | **MethodInvalidParam (412)** 또는 TPer 의존 |

#### Educational Notes
- **교육 포인트**: Range 겹침 처리는 TPer 구현마다 다릅니다. 일부는 거부하고, 일부는 허용합니다. 디바이스 검증 시 반드시 테스트하세요.

---

## TS-4C-003: 범위 외 Range ID

**Category**: L4 — Boundary | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 큰 Range ID | `api.setRange(session, 999, 0, 1000, true, true)` | **MethodInvalidParam (412)** |

---

## TS-4C-004: DataStore 용량 초과 쓰기

**Category**: L4 — Boundary | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | ByteTable 정보 조회 | `api.getByteTableInfo(session, info)` | maxSize 확인 |
| 2 | maxSize 위치에 쓰기 시도 | `api.tcgWriteDataStore(session, info.maxSize, data)` | **MethodInvalidParam (412)** |

---

## TS-4C-005: MBR 테이블 용량 초과 쓰기

**Category**: L4 — Boundary | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | MBR 활성화 | `api.setMbrEnable(session, true)` | Success |
| 2 | 대용량 MBR 데이터 쓰기 | `api.writeMbrData(session, 0, hugeData)` | **MethodInvalidParam (412)** 또는 부분 성공 |

---

## TS-4D-001: User1이 Admin1 작업 수행 시도 (권한 분리)

**Category**: L4 — Access Control | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 일반 User가 관리자 전용 작업을 수행할 때 MethodNotAuthorized가 반환되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | User1 세션 시작 | `startSessionWithAuth(SP_LOCKING, AUTH_USER1)` | Success |
| 2 | User 활성화 시도 | `api.enableUser(session, 2)` | **MethodNotAuthorized (401)** |
| 3 | Range 설정 시도 | `api.setRange(session, 1, 0, 1000, true, true)` | **MethodNotAuthorized (401)** |
| 4 | MBR Enable 시도 | `api.setMbrEnable(session, true)` | **MethodNotAuthorized (401)** |
| 5 | Admin1 비밀번호 변경 시도 | `api.setAdmin1Password(session, "hacked")` | **MethodNotAuthorized (401)** |

#### Educational Notes
- **교육 포인트**: 이 테스트는 TCG의 권한 분리 모델을 검증합니다. User는 자신에게 ACE로 할당된 Range의 Lock/Unlock만 가능하고, 관리 작업은 Admin만 수행할 수 있습니다.

---

# Level 5: 고급 시나리오 (Advanced Scenarios)

> 복합 멀티 세션, Fault injection, Recovery, Stress 테스트.
> 실제 제품 환경에서 발생할 수 있는 고급 상황을 시뮬레이션합니다.

---

## TS-5A-001: 4-Session Aging Cycle — 에이징 테스트

**Category**: L5 — Aging/Stress | **API Layer**: EvalApi + EvalComposite | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 4개의 독립 세션을 번갈아 사용하며 비밀번호 변경, Range 재구성, Lock/Unlock을 반복하는 에이징 테스트. N 사이클 반복 후 모든 상태가 일관되는지 확인.

**Cross-Reference**: `examples/facade/08_aging_4session.cpp`

#### Prerequisites
- 공장 초기 상태에서 시작

#### Setup Phase (1회)

| # | Action | Expected Result |
|---|--------|-----------------|
| 1 | takeOwnership("sid_pw") | Success |
| 2 | activateLocking("sid_pw") | Success |
| 3 | setRange(1, 0, 1M) + setRange(2, 1M, 1M) | Success |
| 4 | setupUser(1, "user1_pw", 1) + setupUser(2, "user2_pw", 2) | Success |

#### Per-Cycle Steps (N회 반복)

| # | Session | Action | Expected Result |
|---|---------|--------|-----------------|
| 1 | S1: AdminSP/SID | SID 비밀번호 변경: "sid_pw_v{N}" | Success |
| 2 | S1 종료 | — | — |
| 3 | S2: LockingSP/Admin1 | Admin1 비밀번호 변경 | Success |
| 4 | S2 | Range 1 재구성 (크기 변경) | Success |
| 5 | S2 | MBR Enable + Write 512B + MBR Done | Success |
| 6 | S2 | DataStore Write 256B | Success |
| 7 | S2 종료 | — | — |
| 8 | S3: LockingSP/User1 | Range 1 Lock | Success |
| 9 | S3 | Range 1 Unlock | Success |
| 10 | S3 종료 | — | — |
| 11 | S4: LockingSP/User2 | Range 2 Lock | Success |
| 12 | S4 | Range 2 Unlock | Success |
| 13 | S4 종료 | — | — |

#### Verification (매 사이클 후)

| # | Check | Expected |
|---|-------|----------|
| 1 | SID 인증 (최신 비밀번호) | Success |
| 2 | Admin1 인증 (최신 비밀번호) | Success |
| 3 | Range 1, 2 상태 | 설정한 값과 일치 |
| 4 | DataStore 읽기 | 마지막 쓴 데이터와 일치 |

#### Teardown
- `revertToFactory(sidPw_latest, psidPw)` | 공장 초기화

#### Educational Notes
- **교육 포인트**: 에이징 테스트는 TPer의 상태 머신 안정성을 검증합니다. 세션을 빈번하게 열고 닫으면서 상태가 누수되지 않는지 확인합니다.

---

## TS-5A-002: Full Lifecycle Aging — 전체 수명 주기 반복

**Category**: L5 — Lifecycle Stress | **API Layer**: EvalComposite + SedDrive | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 공장→소유권→활성화→설정→잠금→해제→MBR→DataStore→CryptoErase→Revert 전체 주기를 3회 반복하여 반복 안정성 확인.

#### Per-Cycle Steps (~40 steps)

| # | Phase | Actions | Expected |
|---|-------|---------|----------|
| 1 | 공장 상태 확인 | query(), MSID==SID 검증 | Success |
| 2 | 소유권 + 활성화 | takeOwnership → activateLocking | Success |
| 3 | Range 1~4 설정 | 4개 Range 각각 configureRange | Success |
| 4 | User 1~4 설정 | 4명 각각 enableUser + setPassword + assignToRange | Success |
| 5 | 전체 잠금 | 4 Range 모두 Lock (각 User) | Success |
| 6 | 전체 해제 | 4 Range 모두 Unlock | Success |
| 7 | MBR | Enable → Write → Read/Compare → Done | Success |
| 8 | DataStore | Write → Read → Compare | Success |
| 9 | CryptoErase Range 1 | cryptoErase(1) + key 변경 확인 | Key changed |
| 10 | Revert LockingSP | revertLockingSP(admin1Pw) | Success, AdminSP 유지 |
| 11 | AdminSP Revert | revertToFactory(sidPw) | Success |
| 12 | 공장 상태 재확인 | query(), MSID==SID | Success |

반복: 3회

---

## TS-5A-003: Password Brute-Force Lockout & Recovery

**Category**: L5 — Security | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: C_PIN TryLimit 메커니즘 검증. 잘못된 비밀번호를 TryLimit 횟수만큼 시도하여 AuthLockedOut을 유발하고, PSID Revert로 복구.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 소유권 획득 + User1 설정 | takeOwnership, activate, setupUser(1) | Success |
| 2 | C_PIN TryLimit 확인 | `api.getCPinTriesRemaining(session, uid::CPIN_USER1, remaining)` | remaining = N (예: 5) |
| 3~7 | 잘못된 비밀번호로 인증 (N회) | `api.verifyAuthority(..., AUTH_USER1, "wrong")` × N | AuthFailed × (N-1), 마지막에 **AuthLockedOut (601)** |
| 8 | 올바른 비밀번호로 인증 시도 | `api.verifyAuthority(..., AUTH_USER1, correctPw)` | **AuthLockedOut (601)** (잠김) |
| 9 | PSID Revert로 복구 | `composite::psidRevertAndVerify(api, transport, comId, psidPw)` | Success |
| 10 | 공장 상태 확인 | MSID == SID | true |

#### Educational Notes
- **교육 포인트**: AuthLockedOut 상태에서는 올바른 비밀번호를 입력해도 인증이 거부됩니다. PSID Revert가 유일한 복구 수단입니다. 이것이 물리적 보안의 핵심 — PSID는 드라이브 라벨에 인쇄되어 있으므로 물리적 접근이 필요합니다.

---

## TS-5B-001: Fault Injection — Send 실패 복구

**Category**: L5 — Fault Injection | **API Layer**: EvalApi + Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: FaultBuilder로 3번째 IF-SEND에서 TransportSendFailed를 발생시키고, 복합 연산이 적절히 실패한 후 재시도로 복구되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | TestContext 활성화 | `TestContext::instance().enable()` | — |
| 2 | Fault 장착 | `FaultBuilder("fail_3rd").at(BeforeIfSend).returnError(TransportSendFailed).times(1).arm()` | ruleId 반환 |
| 3 | takeOwnership 실행 | `composite::takeOwnership(api, transport, comId, "new_pw")` | **실패** (3번째 Send에서) |
| 4 | CompositeResult 검사 | `result.failCount()` | 1 (실패한 단계) |
| 5 | 세션 정리 확인 | 세션 누수 없음 | — |
| 6 | Fault 해제 | `TestContext::instance().disarmFault(ruleId)` | — |
| 7 | 재시도 | `composite::takeOwnership(api, transport, comId, "new_pw")` | **Success** |

#### Code Example
```cpp
auto& tc = TestContext::instance();
tc.enable();

auto ruleId = FaultBuilder("fail_3rd")
    .at(FaultPoint::BeforeIfSend)
    .returnError(ErrorCode::TransportSendFailed)
    .times(1)
    .arm();

auto r = composite::takeOwnership(api, transport, comId, "new_pw");
EXPECT_TRUE(r.failed());

tc.disarmFault(ruleId);

r = composite::takeOwnership(api, transport, comId, "new_pw");
EXPECT_OK(r.overall);
```

---

## TS-5B-002: Fault Injection — SyncSession 응답 손상

**Category**: L5 — Fault Injection | **API Layer**: EvalApi + Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: SyncSession 응답의 4번째 바이트를 XOR 0xFF로 손상시켜 SessionSyncFailed 에러가 발생하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Fault 장착 | `FaultBuilder("corrupt_sync").at(AfterIfRecv).corrupt(4, 0xFF).once().arm()` | — |
| 2 | startSession 시도 | `api.startSession(session, uid::SP_ADMIN, false, ssr)` | **MalformedResponse (207)** 또는 **SessionSyncFailed (303)** |
| 3 | 세션 상태 확인 | `session.isActive()` | false (깨끗한 상태) |
| 4 | Fault 해제 후 재시도 | `disarmFault()` → `startSession(...)` | **Success** |

---

## TS-5B-003: Fault Injection — CloseSession 패킷 Drop

**Category**: L5 — Fault Injection | **API Layer**: EvalApi + Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: CloseSession 전송을 Drop하면 TPer가 세션을 유지하는 상황 시뮬레이션. StackReset으로 복구.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `api.startSession(...)` | Success |
| 2 | 작업 수행 | `api.getCPin(session, uid::CPIN_MSID, pin)` | Success |
| 3 | Fault 장착 (CloseSession Drop) | `FaultBuilder("drop_close").at(BeforeIfSend).drop().once().arm()` | — |
| 4 | 세션 종료 시도 | `api.closeSession(session)` | 로컬에서는 종료되지만 TPer에서는 세션 유지 |
| 5 | 새 세션 시작 시도 | `api.startSession(...)` | **MethodSpBusy (403)** 또는 성공 (ComID 충돌) |
| 6 | StackReset으로 복구 | `api.stackReset(transport, comId)` | Success |
| 7 | 새 세션 시작 | `api.startSession(...)` | **Success** |

---

## TS-5B-004: Fault Injection — 응답 지연 + 타임아웃

**Category**: L5 — Fault Injection | **API Layer**: EvalApi + Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: 응답을 5초 지연시키고 세션 타임아웃을 2초로 설정하여 TransportTimeout 에러 확인. 이후 타임아웃을 늘려 성공.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Fault 장착 (5s 지연) | `FaultBuilder("slow").at(AfterIfRecv).delay(5000).once().arm()` | — |
| 2 | 세션 타임아웃 2s 설정 | `EvalApi::setSessionTimeout(session, 2000)` | — |
| 3 | 작업 시도 | `api.exchangeProperties(...)` | **TransportTimeout (104)** |
| 4 | Fault 해제 | disarmFault | — |
| 5 | 타임아웃 10s로 증가 후 재시도 | `setSessionTimeout(10000)` → `exchangeProperties(...)` | **Success** |

---

## TS-5B-005: Fault Injection — 페이로드 교체 (MITM 시뮬레이션)

**Category**: L5 — Security | **API Layer**: EvalApi + Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: 응답 페이로드를 가짜 MSID로 교체하여 중간자 공격을 시뮬레이션. 라이브러리가 교체된 데이터를 그대로 반환하는지 확인 (전송 계층 보안의 중요성 교육).

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 가짜 MSID 응답 구성 | Properties + SyncSession + Get(CPIN_MSID) 응답을 조작 | — |
| 2 | Fault 장착 (Replace) | `FaultBuilder("mitm").at(AfterIfRecv).replaceWith(fakeResponse).once().arm()` | — |
| 3 | MSID 읽기 | `composite::getMsid(api, transport, comId, msid)` | Success, 하지만 msid == fake_msid |
| 4 | 가짜 MSID 확인 | `msid == fakeValue` | true (전송 계층에서 교체됨) |

#### Educational Notes
- **교육 포인트**: TCG 프로토콜 자체에는 전송 계층 무결성 검증이 없습니다. MITM 방어는 TCG의 TLS Session 또는 외부 보안 채널에 의존합니다. 이 테스트는 왜 보안 전송이 중요한지를 보여줍니다.

---

## TS-5B-006: Fault Injection — 콜백 기반 선택적 Fault

**Category**: L5 — Fault Injection | **API Layer**: EvalApi + Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: 콜백으로 페이로드를 검사하여 특정 메서드(Get on CPIN)만 실패시키고 나머지는 통과시키는 정밀 fault injection.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 콜백 Fault 장착 | `FaultBuilder("selective").at(BeforeIfSend).callback([](Bytes& payload) { /* CPIN Get인지 확인 */ }).arm()` | — |
| 2 | Properties 교환 | `api.exchangeProperties(...)` | **Success** (콜백이 통과) |
| 3 | StartSession | `api.startSession(...)` | **Success** |
| 4 | Get CPIN_MSID | `api.getCPin(session, uid::CPIN_MSID, pin)` | **TransportSendFailed** (콜백이 차단) |
| 5 | CloseSession | `api.closeSession(session)` | **Success** |

---

## TS-5C-001: Workaround — RetryOnSpBusy

**Category**: L5 — Workaround | **API Layer**: Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: `wa.retry_on_sp_busy` 워크어라운드 활성화 시 SpBusy 에러를 자동 재시도하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 워크어라운드 활성화 | `TestContext::instance().activateWorkaround(workaround::kRetryOnSpBusy)` | — |
| 2 | SpBusy 1회 발생 Fault | `FaultBuilder("busy").at(AfterIfRecv).returnError(MethodSpBusy).once().arm()` | — |
| 3 | 작업 수행 | `api.startSession(...)` | **Success** (자동 재시도) |
| 4 | 카운터 확인 | `TestContext::instance().getCounter("retry_count")` | 1 |

---

## TS-5C-002: Trace Event 분석

**Category**: L5 — Debug | **API Layer**: Debug | **SSC**: All | **Transport**: MockTransport

**Purpose**: TraceObserver를 등록하고 전체 소유권 시퀀스를 수행하여 기록된 TraceEvent들이 올바른 순서와 내용을 가지는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | TestContext 활성화 | `tc.enable()` | — |
| 2 | TraceObserver 등록 | `tc.addTraceObserver([](const TraceEvent& e) { events.push_back(e); })` | — |
| 3 | takeOwnership 실행 | `composite::takeOwnership(...)` | Success |
| 4 | TraceEvent 수 확인 | `events.size()` | > 0 |
| 5 | 첫 이벤트 확인 | `events[0].point` | BeforeIfSend 또는 BeforeDiscovery |
| 6 | 이벤트 순서 검증 | Send → Recv 교대 | 올바른 순서 |
| 7 | 각 이벤트의 snapshot 확인 | `event.snapshot.size()` | > 0 (페이로드 캡처) |

---

## TS-5D-001: Concurrent Session Contention — 동시 세션 경쟁

**Category**: L5 — Concurrency | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 두 스레드가 각각 독립 Session 객체를 사용하여 같은 Range에 Lock/Unlock을 동시에 수행할 때 데이터 손상 없이 처리되는지 확인.

#### Steps

| # | Action | Expected Result |
|---|--------|-----------------|
| 1 | Thread A: Admin1 세션 시작 | Success |
| 2 | Thread B: User1 세션 시작 | Success |
| 3 | Thread A: setRange(1, 0, 1M) | Success |
| 4 | Thread B: setRangeLock(1, true, true) | Success 또는 MethodSpBusy (동시 접근) |
| 5 | Thread A: setRangeLock(1, false, false) | Success 또는 MethodSpBusy |
| 6 | 10회 반복 | 에러 없이 완료 또는 SpBusy로 안전하게 실패 |
| 7 | 양쪽 세션 종료 | Success |

#### Educational Notes
- **교육 포인트**: EvalApi는 stateless이므로 스레드 안전하지만, Session은 스레드당 하나를 사용해야 합니다. 같은 TPer에 여러 세션이 동시 접근하면 SpBusy가 발생할 수 있습니다.

---

## TS-5D-002: Rapid Session Open/Close Storm

**Category**: L5 — Stress | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: 세션을 100회 빠르게 열고 닫아 TSN 누수, 세션 슬롯 고갈이 없는지 확인.

#### Steps

| # | Action | Expected Result |
|---|--------|-----------------|
| 1~100 | `startSession()` → `closeSession()` 반복 | 모두 Success |
| 101 | 최종 세션 시작 | Success (누수 없음) |

---

## TS-5D-003: Large DataStore Transfer — 대용량 데이터 전송

**Category**: L5 — Stress | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: DataStore 전체 용량을 청크 단위로 쓰고 읽어 데이터 무결성 확인. MaxComPacketSize 제한에 따른 청크 전략 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | ByteTable 정보 조회 | `api.getByteTableInfo(session, info)` | maxSize > 0 |
| 2 | 청크 크기 계산 | `chunkSize = min(maxSize, props.tperMaxIndTokenSize - overhead)` | — |
| 3 | 전체 데이터 생성 | `data = generatePattern(info.maxSize)` | — |
| 4~N | 청크별 쓰기 | `api.tcgWriteDataStore(session, offset, chunk)` × ceil(maxSize/chunkSize) | 각 Success |
| N+1~2N | 청크별 읽기 | `api.tcgReadDataStore(session, offset, chunkSize, result)` × ceil(maxSize/chunkSize) | 각 Success |
| 2N+1 | 전체 데이터 비교 | 읽은 데이터 == 원본 데이터 | true |

#### Educational Notes
- **교육 포인트**: DataStore의 한 번 전송 가능한 최대 크기는 MaxIndTokenSize에 의해 제한됩니다. 대용량 데이터는 반드시 청크 단위로 분할하여 전송해야 합니다.

---

## TS-5D-004: MBR Large Write Stress

**Category**: L5 — Stress | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: MBR 테이블 전체 용량을 쓰고 읽어 무결성 확인.

#### Steps

| # | Action | Expected Result |
|---|--------|-----------------|
| 1 | MBR Enable | Success |
| 2 | 전체 MBR 크기 결정 (TPer Discovery) | 보통 128MB |
| 3 | 패턴 데이터 청크 쓰기 (offset 0~max) | 각 Success |
| 4 | 전체 읽기 + 비교 | 데이터 일치 |
| 5 | 다른 패턴으로 재쓰기 | 각 Success |
| 6 | 재읽기 + 비교 | 데이터 일치 |

---

## TS-5E-001: Revert Race Condition — Revert 경쟁 조건

**Category**: L5 — Race Condition | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: Admin1 세션이 활성인 상태에서 별도 SID 세션으로 AdminSP Revert를 수행할 때 Admin1 세션의 동작 확인.

#### Steps

| # | Action | Expected Result |
|---|--------|-----------------|
| 1 | Admin1 세션 시작 (LockingSP) | Success |
| 2 | SID 세션 시작 (AdminSP) | Success |
| 3 | SID 세션: RevertSP(AdminSP) | Success, 세션 자동 종료 |
| 4 | Admin1 세션: 작업 시도 | **에러** (세션 무효화) — SessionClosed 또는 TransportRecvFailed |
| 5 | StackReset | Success |
| 6 | 새 세션 시작 | Success (공장 상태) |

---

## TS-5E-002: Ownership Transfer Simulation — 소유권 이전

**Category**: L5 — Lifecycle | **API Layer**: EvalComposite + SedDrive | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 원래 소유자가 모든 것을 구성한 뒤 SID 비밀번호를 변경하여 새 소유자에게 이전하는 시나리오.

#### Steps

| # | Phase | Action | Expected |
|---|-------|--------|----------|
| 1 | 원래 소유자 | takeOwnership("owner_A_pw") | Success |
| 2 | 원래 소유자 | activateLocking + configureRange + setupUser | Success |
| 3 | 원래 소유자 | lockRange(1) | Success |
| 4 | **소유권 이전** | SID 비밀번호 변경: "owner_A_pw" → "owner_B_pw" | Success |
| 5 | **소유권 이전** | Admin1 비밀번호 변경: "admin1_A" → "admin1_B" | Success |
| 6 | **소유권 이전** | User1 비밀번호 변경: "user1_A" → "user1_B" | Success |
| 7 | 새 소유자 | SID 인증 ("owner_B_pw") | Success |
| 8 | 새 소유자 | Admin1 인증 ("admin1_B") | Success |
| 9 | 새 소유자 | User1으로 Range1 해제 ("user1_B") | Success |
| 10 | 새 소유자 | Revert + 재구성 | Success |

---

## TS-5E-003: ComID State Verification

**Category**: L5 — ComID | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: `verifyComId()`로 ComID 상태를 추적하여 세션 중/후의 ComID 상태 변화를 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 초기 상태 | `api.verifyComId(transport, comId, active)` | active = false (idle) |
| 2 | Properties 교환 | `api.exchangeProperties(...)` | Success |
| 3 | 세션 중 상태 | `api.verifyComId(transport, comId, active)` | active = true (occupied) |
| 4 | 세션 종료 후 | `api.closeSession(...)` | — |
| 5 | 상태 확인 | `api.verifyComId(transport, comId, active)` | active = false 또는 TPer 의존 |
| 6 | StackReset 후 | `api.stackReset(...)` + `verifyComId(...)` | active = false (확실히 idle) |

---

## TS-5E-004: Clock Reading and Timing

**Category**: L5 — TPer Feature | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: TPer 클록 값이 단조 증가하는지 확인하고, 작업 간 시간 차이가 합리적인지 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `startSessionWithAuth(...)` | Success |
| 2 | 클록 읽기 (T1) | `api.getClock(session, clock1)` | Success |
| 3 | 작업 수행 | setRange, setRangeLock 등 | Success |
| 4 | 클록 읽기 (T2) | `api.getClock(session, clock2)` | Success |
| 5 | 단조 증가 확인 | `clock2 >= clock1` | true |

---

## TS-5F-001: getRandom 엔트로피 검증

**Category**: L5 — Crypto | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: TPer의 난수 생성기가 반복되지 않는 데이터를 생성하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `startSessionWithAuth(...)` | Success |
| 2 | 난수 32바이트 생성 (R1) | `api.getRandom(session, 32, r1)` | Success, r1.size()==32 |
| 3 | 난수 32바이트 생성 (R2) | `api.getRandom(session, 32, r2)` | Success, r2.size()==32 |
| 4 | R1 != R2 확인 | `r1 != r2` | true (극히 낮은 확률로 같을 수 있음) |
| 5 | 100회 반복 중복 없음 확인 | 100개 난수 모두 고유 | true |

---

## TS-5F-002: GetACL 접근 제어 감사

**Category**: L5 — Access Control | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: `getAcl()`로 특정 객체+메서드 조합에 대한 ACL 정보를 조회하여 접근 제어 감사 패턴 검증.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Admin1 세션 시작 | `startSessionWithAuth(Admin1)` | Success |
| 2 | Locking Range1 Set에 대한 ACL 조회 | `api.getAcl(session, uid::LOCKING_RANGE1, uid::method::SET, aclInfo)` | Success |
| 3 | ACE 목록 확인 | `aclInfo.aceList` | ACE_Locking_Range1_Set 포함 |
| 4 | ACE 상세 조회 | `api.getAceInfo(session, aceUid, aceInfo)` | authorities 목록 확인 |

---

## TS-5F-003: TableCreateRow / TableDeleteRow

**Category**: L5 — Table Management | **API Layer**: EvalApi | **SSC**: Opal 2.0 | **Transport**: Real

**Purpose**: 테이블 행 생성/삭제 메서드의 동작 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | 세션 시작 | `startSessionWithAuth(Admin1)` | Success |
| 2 | 행 생성 | `api.tableCreateRow(session, tableUid, raw)` | Success 또는 MethodNotAuthorized (테이블에 따라) |
| 3 | 행 삭제 | `api.tableDeleteRow(session, rowUid, raw)` | Success 또는 MethodNotAuthorized |

---

# Level 6: SSC별 특화 검증 (SSC-Specific Tests)

> Opal, Enterprise, Pyrite SSC 간의 행동 차이를 검증합니다.
> 같은 논리적 작업이 각 SSC에서 어떻게 다르게 구현되는지를 교육합니다.

---

## TS-6A-001: Opal vs Enterprise Authority 모델 비교

**Category**: L6 — Cross-SSC | **API Layer**: EvalApi | **SSC**: Opal + Enterprise | **Transport**: Real

**Purpose**: 같은 논리적 작업(Range/Band 잠금)을 Opal과 Enterprise에서 각각 수행하여 Authority 모델 차이를 교육.

#### Opal 방식

| # | Action | API Call |
|---|--------|---------|
| 1 | SID → AdminSP 세션 | startSessionWithAuth(SP_ADMIN, AUTH_SID) |
| 2 | Activate Locking SP | activate(SP_LOCKING) |
| 3 | Admin1 → LockingSP 세션 | startSessionWithAuth(SP_LOCKING, AUTH_ADMIN1) |
| 4 | setRange(1, ...) | setRange() |
| 5 | User1 활성화 + ACE | enableUser + assignUserToRange |
| 6 | User1 → Lock | setRangeLock(1, true, true) |

#### Enterprise 방식

| # | Action | API Call |
|---|--------|---------|
| 1 | BandMaster0 → EnterpriseSP 세션 | startSessionWithAuth(SP_ENTERPRISE, AUTH_BANDMASTER0) |
| 2 | configureBand(1, ...) | configureBand() |
| 3 | setBandMasterPassword(1, ...) | setBandMasterPassword() |
| 4 | BandMaster1 → Lock | lockBand(1) |

#### Educational Notes
- **핵심 차이**: Opal은 SID → Admin1 → User 3계층. Enterprise는 BandMaster (per-band) + EraseMaster 2계층.
- **Opal**: ACE 기반 fine-grained access control. 하나의 User가 여러 Range 가능.
- **Enterprise**: BandMaster는 자기 Band만 관리. EraseMaster만 모든 Band를 소거 가능.

---

## TS-6A-002: Enterprise EraseMaster 전체 소거

**Category**: L6 — Enterprise | **API Layer**: EvalApi | **SSC**: Enterprise | **Transport**: Real

**Purpose**: EraseMaster가 모든 Band를 한 번에 소거하고, 소거 후 Band가 잠금 해제되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Band 1, 2, 3 구성 | configureBand × 3 | Success |
| 2 | 각 Band 잠금 | lockBand × 3 | Success |
| 3 | EraseMaster 세션 시작 | startSessionWithAuth(AUTH_ERASEMASTER) | Success |
| 4 | 전체 소거 | `api.eraseAllBands(session, 3)` | Success |
| 5 | Band 상태 확인 | getBandInfo × 3 | 잠금 해제됨 |

---

## TS-6A-003: Enterprise BandMaster 독립성

**Category**: L6 — Enterprise | **API Layer**: EvalApi | **SSC**: Enterprise | **Transport**: Real

**Purpose**: 각 BandMaster가 자기 Band만 관리할 수 있고, 다른 Band에 접근하면 에러가 발생하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | BandMaster0: Band 1 잠금 | lockBand(1) (BM0 세션) | **MethodNotAuthorized** (BM0은 Band 0 전용) |
| 2 | BandMaster1: Band 1 잠금 | lockBand(1) (BM1 세션) | **Success** |
| 3 | BandMaster1: Band 2 잠금 시도 | lockBand(2) (BM1 세션) | **MethodNotAuthorized** |
| 4 | BandMaster2: Band 2 잠금 | lockBand(2) (BM2 세션) | **Success** |

---

## TS-6A-004: Pyrite 제한 기능 확인

**Category**: L6 — Pyrite | **API Layer**: EvalApi | **SSC**: Pyrite | **Transport**: Real

**Purpose**: Pyrite SSC에서 지원되지 않는 기능(MBR, CryptoErase)을 호출했을 때 적절한 에러가 반환되는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | Discovery | `api.discovery0(transport, info)` | primarySsc = Pyrite |
| 2 | Locking Range 설정 | `api.setRange(session, 1, ...)` | Success (잠금은 지원) |
| 3 | MBR Enable 시도 | `api.setMbrEnable(session, true)` | **FeatureNotFound (503)** 또는 **MethodFailed** |
| 4 | CryptoErase 시도 | `api.cryptoErase(session, 1)` | **FeatureNotFound (503)** 또는 **MethodFailed** |

#### Educational Notes
- **교육 포인트**: Pyrite는 "접근 제어는 되지만 암호화는 안 되는" SSC입니다. Range Lock/Unlock은 지원하지만, MBR 섀도잉과 Crypto Erase는 지원하지 않습니다. DataStore 지원 여부도 TPer 구현에 따라 다릅니다.

---

## TS-6A-005: SSC 감지 및 기능 게이팅

**Category**: L6 — Cross-SSC | **API Layer**: EvalApi | **SSC**: All | **Transport**: Real

**Purpose**: `getTcgOption()`, `getSecurityStatus()`, `getAllSecurityFeatures()`로 디바이스의 SSC와 지원 기능을 정확히 감지하는지 확인.

#### Steps

| # | Action | API Call | Expected Result |
|---|--------|---------|-----------------|
| 1 | TcgOption 조회 | `api.getTcgOption(transport, option)` | sscType, baseComId, lockingSupported 등 |
| 2 | SecurityStatus 조회 | `api.getSecurityStatus(transport, status)` | opalV2Present, enterprisePresent 등 boolean |
| 3 | 전체 Feature 조회 | `api.getAllSecurityFeatures(transport, features)` | Feature 코드별 상세 정보 |
| 4 | SSC별 기능 매핑 | Opal → MBR+DataStore+ACE, Enterprise → Band+EraseMaster, Pyrite → 제한된 Locking | 일치 |
| 5 | 기능 없는 SSC에서 해당 작업 시도 | (Level 6의 다른 시나리오에서 검증) | 적절한 에러 |

#### Code Example
```cpp
TcgOption option;
api.getTcgOption(transport, option);

switch (option.sscType) {
    case SscType::Opal20:
        // MBR, DataStore, ACE, CryptoErase 모두 가능
        break;
    case SscType::Enterprise:
        // Band, BandMaster, EraseMaster 사용
        break;
    case SscType::Pyrite10:
    case SscType::Pyrite20:
        // 제한된 Locking만 가능
        break;
}
```

---

# Appendix A: 시나리오 요약표

| ID | 이름 | Level | SSC | API Layer |
|----|------|-------|-----|-----------|
| TS-1A-001 | Discovery0 기본 | L1 | All | EvalApi |
| TS-1A-002 | Discovery0 Raw | L1 | All | EvalApi |
| TS-1A-003 | Discovery0 Custom | L1 | All | EvalApi |
| TS-1B-001 | Properties Exchange | L1 | All | EvalApi |
| TS-1B-002 | Properties Custom | L1 | All | EvalApi |
| TS-1C-001 | 익명 세션 열기 | L1 | All | EvalApi |
| TS-1C-002 | 인증 세션 열기 | L1 | All | EvalApi |
| TS-1C-003 | 세션 종료 | L1 | All | EvalApi |
| TS-1C-004 | StartSession/SyncSession 분리 | L1 | All | EvalApi |
| TS-1D-001 | C_PIN MSID 읽기 | L1 | All | EvalApi |
| TS-1D-002 | C_PIN SID 설정 (Bytes) | L1 | All | EvalApi |
| TS-1D-003 | C_PIN SID 설정 (String) | L1 | All | EvalApi |
| TS-1E-001 | Table Get 컬럼 범위 | L1 | All | EvalApi |
| TS-1E-002 | Table SetMultiUint | L1 | All | EvalApi |
| TS-1E-003 | Table GetAll | L1 | All | EvalApi |
| TS-1F-001 | Range 설정 | L1 | Opal | EvalApi |
| TS-1F-002 | Range Lock/Unlock | L1 | Opal | EvalApi |
| TS-1F-003 | Range 정보 조회 | L1 | Opal | EvalApi |
| TS-1G-001 | 인증 (Bytes) | L1 | All | EvalApi |
| TS-1G-002 | 인증 (String) | L1 | All | EvalApi |
| TS-2A-001 | Query Flow | L2 | All | EvalApi+Composite |
| TS-2A-002 | Take Ownership | L2 | All | EvalComposite |
| TS-2A-003 | Activate Locking SP | L2 | Opal | EvalApi |
| TS-2A-004 | Configure Range | L2 | Opal | EvalApi+Composite |
| TS-2A-005 | Lock/Unlock Range | L2 | Opal | EvalApi |
| TS-2A-006 | User + ACE Setup | L2 | Opal | EvalApi |
| TS-2A-007 | MBR Shadow Write | L2 | Opal | EvalComposite |
| TS-2A-008 | Crypto Erase | L2 | Opal | EvalComposite |
| TS-2A-009 | Revert to Factory | L2 | All | EvalComposite |
| TS-2A-010 | PSID Revert | L2 | All | EvalComposite |
| TS-2A-011 | DataStore Round Trip | L2 | Opal | EvalComposite |
| TS-2A-012 | Block SID Feature | L2 | All | EvalApi+NVMe |
| TS-2A-013 | Stack Reset | L2 | All | EvalApi |
| TS-2A-014 | Enterprise Band Setup | L2 | Enterprise | EvalApi |
| TS-2A-015 | Revert Locking SP | L2 | Opal | EvalComposite |
| TS-3A-001 | Full Opal Lifecycle | L3 | Opal | SedDrive |
| TS-3A-002 | Multi-User Range Isolation | L3 | Opal | EvalApi |
| TS-3A-003 | MBR + Locking Interaction | L3 | Opal | EvalApi |
| TS-3A-004 | DataStore + User ACE | L3 | Opal | EvalApi |
| TS-3A-005 | CryptoErase + Reconfigure | L3 | Opal | EvalApi |
| TS-3A-006 | Password Rotation | L3 | All | EvalApi |
| TS-3A-007 | Multi-Range + Global | L3 | Opal | EvalApi |
| TS-3A-008 | LockOnReset + Power Cycle | L3 | Opal | EvalApi |
| TS-3A-009 | User Disable Mid-Session | L3 | Opal | EvalApi |
| TS-3A-010 | GenKey + ActiveKey Chain | L3 | Opal | EvalApi |
| TS-3B-001 | SedDrive Facade Lifecycle | L3 | Opal | SedDrive |
| TS-3B-002 | SedSession Multi-Session | L3 | Opal | SedDrive |
| TS-3B-003 | withSession Callback | L3 | All | EvalComposite |
| TS-3B-004 | TableNext + TableGet | L3 | Opal | EvalApi |
| TS-3B-005 | Authority + TryLimit | L3 | All | EvalApi |
| TS-3B-006 | Composite StepLog | L3 | All | EvalComposite |
| TS-3B-007 | DataStore Multi-Table | L3 | Opal | EvalApi |
| TS-3B-008 | MBR Multi-User | L3 | Opal | EvalApi |
| TS-3B-009 | Discovery Re-query | L3 | All | EvalApi |
| TS-3B-010 | Enterprise Band + Erase | L3 | Enterprise | EvalApi |
| TS-4A-001 | 잘못된 비밀번호 | L4 | All | EvalApi |
| TS-4A-002 | 존재하지 않는 Authority | L4 | All | EvalApi |
| TS-4A-003 | 비활성 User 인증 | L4 | Opal | EvalApi |
| TS-4A-004 | 존재하지 않는 SP | L4 | All | EvalApi |
| TS-4A-005 | 이중 세션 열기 | L4 | All | EvalApi |
| TS-4A-006 | 세션 종료 후 메서드 | L4 | All | EvalApi |
| TS-4A-007 | 읽기 전용 쓰기 시도 | L4 | All | EvalApi |
| TS-4A-008 | 비활성 SP Range 설정 | L4 | Opal | EvalApi |
| TS-4A-009 | SP 재활성화 | L4 | Opal | EvalApi |
| TS-4A-010 | 인증 없이 Revert | L4 | All | EvalApi |
| TS-4B-001 | 잘못된 ComID Discovery | L4 | All | EvalApi |
| TS-4B-002 | 손상된 응답 | L4 | All | EvalApi |
| TS-4B-003 | 빈 응답 | L4 | All | EvalApi |
| TS-4B-004 | 트렁케이트 패킷 | L4 | All | EvalApi |
| TS-4B-005 | 빈 문자열 비밀번호 | L4 | All | EvalApi |
| TS-4B-006 | 최대 길이 비밀번호 | L4 | All | EvalApi |
| TS-4C-001 | Range UINT64_MAX | L4 | Opal | EvalApi |
| TS-4C-002 | 겹치는 Range | L4 | Opal | EvalApi |
| TS-4C-003 | 범위 외 Range ID | L4 | Opal | EvalApi |
| TS-4C-004 | DataStore 용량 초과 | L4 | Opal | EvalApi |
| TS-4C-005 | MBR 용량 초과 | L4 | Opal | EvalApi |
| TS-4D-001 | User 권한 분리 | L4 | Opal | EvalApi |
| TS-5A-001 | 4-Session Aging | L5 | Opal | EvalApi |
| TS-5A-002 | Full Lifecycle Aging | L5 | Opal | EvalComposite |
| TS-5A-003 | Brute-Force Lockout | L5 | All | EvalApi |
| TS-5B-001 | Fault: Send 실패 | L5 | All | Debug |
| TS-5B-002 | Fault: SyncSession 손상 | L5 | All | Debug |
| TS-5B-003 | Fault: CloseSession Drop | L5 | All | Debug |
| TS-5B-004 | Fault: 응답 지연 | L5 | All | Debug |
| TS-5B-005 | Fault: MITM 시뮬레이션 | L5 | All | Debug |
| TS-5B-006 | Fault: 선택적 콜백 | L5 | All | Debug |
| TS-5C-001 | Workaround: SpBusy 재시도 | L5 | All | Debug |
| TS-5C-002 | Trace Event 분석 | L5 | All | Debug |
| TS-5D-001 | Concurrent Session | L5 | Opal | EvalApi |
| TS-5D-002 | Session Open/Close Storm | L5 | All | EvalApi |
| TS-5D-003 | Large DataStore Transfer | L5 | Opal | EvalApi |
| TS-5D-004 | MBR Large Write | L5 | Opal | EvalApi |
| TS-5E-001 | Revert Race Condition | L5 | Opal | EvalApi |
| TS-5E-002 | Ownership Transfer | L5 | Opal | EvalComposite |
| TS-5E-003 | ComID State Verification | L5 | All | EvalApi |
| TS-5E-004 | Clock Timing | L5 | All | EvalApi |
| TS-5F-001 | getRandom 엔트로피 | L5 | All | EvalApi |
| TS-5F-002 | GetACL 감사 | L5 | Opal | EvalApi |
| TS-5F-003 | CreateRow/DeleteRow | L5 | Opal | EvalApi |
| TS-6A-001 | Opal vs Enterprise | L6 | Both | EvalApi |
| TS-6A-002 | Enterprise EraseMaster | L6 | Enterprise | EvalApi |
| TS-6A-003 | BandMaster 독립성 | L6 | Enterprise | EvalApi |
| TS-6A-004 | Pyrite 제한 기능 | L6 | Pyrite | EvalApi |
| TS-6A-005 | SSC 감지 + 게이팅 | L6 | All | EvalApi |

---

# Appendix B: 참조 파일

| 파일 | 용도 |
|------|------|
| `include/libsed/eval/eval_api.h` | EvalApi 160+ 메서드 정의 |
| `include/libsed/eval/eval_composite.h` | 12개 Composite 함수 |
| `include/libsed/facade/sed_drive.h` | SedDrive + SedSession facade |
| `include/libsed/debug/fault_builder.h` | FaultBuilder 플루언트 API |
| `include/libsed/debug/test_context.h` | TestContext 싱글톤 |
| `include/libsed/core/uid.h` | UID 상수 |
| `include/libsed/core/error.h` | ErrorCode 정의 |
| `include/libsed/eval/eval_types.h` | Result 구조체 |
| `docs/hammurabi_code.md` | 15 인코딩 불변법칙 |
| `docs/rosetta_stone.md` | 바이트 인코딩 참조 |
| `tests/integration/ioctl_validator.cpp` | 5개 시퀀스 바이트 비교 |
| `examples/appnote/appnote_opal.cpp` | Opal 전체 수명 주기 예제 |
| `examples/facade/08_aging_4session.cpp` | 에이징 테스트 예제 |
