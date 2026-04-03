# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**libsed** — A C++17 library for TCG SED (Self-Encrypting Drive) evaluation and control. Provides a flat, step-by-step API (`EvalApi`) with 120+ methods for testing individual TCG protocol steps in isolation, enabling fault injection, wire-level payload inspection, and multi-threaded evaluation scenarios. Supports Opal 2.0, Enterprise, and Pyrite SSCs over NVMe/ATA/SCSI transports.

## Build Commands

```bash
# Configure and build
cmake -B build -DLIBSED_BUILD_TESTS=ON -DLIBSED_BUILD_EXAMPLES=ON -DLIBSED_BUILD_TOOLS=ON
cmake --build build

# Run all tests
cd build && ctest

# Run test binary directly
./build/libsed_tests
```

### CMake Options

- `-DLIBSED_BUILD_TESTS=ON|OFF` — Unit tests (default: ON)
- `-DLIBSED_BUILD_EXAMPLES=ON|OFF` — Example programs (default: ON)
- `-DLIBSED_BUILD_TOOLS=ON|OFF` — CLI tools (default: ON)
- `-DLIBSED_BUILD_SHARED=ON|OFF` — Shared vs static library (default: OFF/static)

### Dependencies

- No external dependencies for the core library (C++17 standard library only)
- Google Test (optional, auto-detected) — falls back to standalone test runner in `tests/test_main.cpp`
- pthreads on Linux for multi-threaded examples

## Architecture

```
EvalApi (stateless, 120+ step-by-step methods)
  ├── Session (per-thread, manages TSN/HSN/sequence)
  ├── PacketBuilder / MethodCall / TokenEncoder
  └── ITransport (abstract)
      ├── NvmeTransport (Mode A: direct ioctl, Mode B: DI via INvmeDevice)
      ├── AtaTransport
      └── ScsiTransport
```

### Two API Layers

1. **EvalApi** (`include/libsed/eval/eval_api.h`, ~960 lines) — Low-level flat API. Every protocol step is an independent function. All results include `rawSendPayload`/`rawRecvPayload` for wire-level inspection. This is the primary API for evaluation platforms.

2. **Eval Composite** (`include/libsed/eval/eval_composite.h`) — Multi-step convenience functions built on EvalApi. Bundles common TC sequences (getMsid, takeOwnership, revertToFactory, withSession RAII, etc.) into single calls with step-by-step logging via `CompositeResult`. Replaces the old `sed_macro_util` pattern.

3. **SSC High-Level APIs** (`include/libsed/ssc/`) — Convenience wrappers (`OpalAdmin`, `OpalLocking`, `EnterpriseDevice`, etc.) that bundle multiple protocol steps. Used for simple operations where step-by-step control isn't needed.

### Key Modules

| Module | Headers | Purpose |
|--------|---------|---------|
| `eval/` | `eval_api.h`, `eval_composite.h`, `sed_context.h` | Core evaluation API, composite utilities, and per-thread context |
| `transport/` | `i_transport.h`, `i_nvme_device.h`, `nvme_transport.h` | Transport abstraction and NVMe DI |
| `session/` | `session.h` | Session lifecycle (explicit open/close) |
| `codec/` | `token*.h` | TCG token encoding/decoding |
| `packet/` | `packet_builder.h`, `com_packet.h` | ComPacket construction/parsing |
| `discovery/` | `discovery.h`, feature descriptors | Level 0 Discovery and feature parsing |
| `debug/` | `fault_builder.h`, `test_context.h`, `command_logger.h`, `logging_transport.h` | Fault injection (24 points), command history logging |
| `core/` | `types.h`, `error.h`, `uid.h` | Fundamental types, error codes, 150+ well-known UIDs |

### NVMe Dependency Injection

The recommended pattern injects an `INvmeDevice` implementation into `NvmeTransport`, enabling both TCG operations (via `EvalApi`) and NVMe admin commands (via `INvmeDevice` directly). Use `EvalApi::getNvmeDevice(transport)` to extract the injected device.

### Threading Model

- `EvalApi` is stateless and thread-safe
- `Session` is **not** thread-safe — use one per thread
- `SedContext` bundles transport + EvalApi + Session + cached discovery for per-thread use

## Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Headers/sources | `snake_case` | `eval_api.h` |
| Functions | `camelCase` | `startSession()`, `getLockingInfo()` |
| Classes | `PascalCase` | `EvalApi`, `NvmeTransport` |
| UID constants | namespace + `UPPER_SNAKE` | `uid::SP_ADMIN`, `uid::AUTH_SID` |
| Column constants | `UPPER_SNAKE` | `uid::col::RANGE_START` |
| Enums | `PascalCase` values | `SscType::Opal20`, `MethodStatus::Success` |

## Key Types

- `Bytes` = `std::vector<uint8_t>`
- `ByteSpan` / `MutableByteSpan` — non-owning views
- `Uid` — 8-byte UID with uint64_t conversion
- `Result` — error code enum (ranges: Transport 100-199, Protocol 200-299, Session 300-399, Method 400-499, Discovery 500-599, Auth 600-699)

## Testing

8 unit test files in `tests/unit/` covering: token codec, packet building, discovery parsing, password hashing, endian conversion, session management, method calls, and debug/fault injection. Mock transport in `tests/mock/mock_transport.cpp` enables testing without hardware.

## Application Note Examples

TCG Storage Application Note documents mapped to EvalApi calls in `examples/`:

| File | Content |
|------|---------|
| `appnote_opal.cpp` | Opal SSC full lifecycle (AppNote 3-13): Take Ownership → Activate → Configure Range → User/ACE → Lock/Unlock → MBR → Crypto Erase → Revert |
| `appnote_enterprise.cpp` | Enterprise SSC: Band config, lock/unlock, BandMaster/EraseMaster passwords, erase, LockOnReset |
| `appnote_mbr.cpp` | Shadow MBR deep dive: PBA write, boot cycle simulation, multi-user access, enable/disable |
| `appnote_psid.cpp` | PSID Revert: locked-out recovery, post-revert state verification, MSID check |
| `appnote_datastore.cpp` | DataStore (ByteTable): info query, write-read-compare, multi-table, chunked large data |
| `appnote_block_sid.cpp` | NVMe Block SID Feature: set/verify/clear, power cycle behavior |
| `appnote_ns_locking.cpp` | Configurable Namespace Locking: per-NS range config, NVMe Identify mapping |

## Developer Guide

Comprehensive documentation in `docs/developer_guide.md` (in Korean) covers architecture, NVMe DI patterns, session management, multi-threading rules, TC Library util mapping, fault injection, the SedContext/Worker integration pattern, and a full application note example catalog.

---

## Current Debug Status (2026-04-03)

### Problem: Properties 메서드만 0x0C (InvalidParameter) 반환

**증상**: `sedutil-cli --query`는 정상 동작하지만, libsed의 Properties exchange만 status 0x0C를 반환. Discovery, StackReset, StartSession(AdminSP), MSID Read, CloseSession은 모두 정상.

### 이미 수정 완료된 버그들

1. **SedErrorCategory::message()** — 모든 ErrorCode에 대해 메시지 추가 (이전에 "Unknown error")
2. **MethodResult CALL header skip** — SM 메서드 응답(SyncSession, Properties, CloseSession)에 CALL 헤더가 포함되는데 이를 스킵하지 않아 MalformedResponse 발생 → 수정
3. **StartSession named param index** — HostExchangeAuthority=3, HostSigningAuthority=4 (TCG Core Spec Table 225). 1,2로 잘못 변경되었다가 복구
4. **Properties 토큰 인코딩** — `STARTNAME "HostProperties" STARTLIST { pairs } ENDLIST ENDNAME` 래퍼 추가 (이전에 bare list)
5. **ComPacket 최소 크기** — 512 → 2048 바이트 (sedutil IO_BUFFER_LENGTH). 일부 TPer는 작은 패킷 거부
6. **"MaxSubPackets" → "MaxSubpackets"** — 대소문자 구분 (lowercase 'p'). 1바이트 차이
7. **Properties 응답 파서 순서** — TPer가 TPerProperties를 먼저, HostProperties를 나중에 보냄. 이름 문자열 체크로 순서 무관하게 파싱하도록 수정 (`src/eval/eval_api.cpp:124-153`)
8. **Method 에러 로깅** — method_result.cpp에서 메서드 이름+상태 표시 (예: "Properties returned status: 0x0C (Invalid Parameter)")

### 현재 의심 원인

- `props_diff` 도구로 비교 시 libsed와 sedutil의 send 패킷이 **IDENTICAL** → 패킷 내용 차이 아님
- 둘 다 동일하게 St=12 반환 → TPer 상태 문제 가능성 (power cycle 필요?)
- 또는 NVMe ioctl 레벨 차이 가능성

### 진단 도구

- `tools/props_diff.cpp` — 실제 디바이스에서 libsed vs sedutil 방식 패킷 비교
- `examples/eval_props_diag.cpp` — Properties만 10개 시나리오로 격리 진단
- `examples/eval_sedutil_query.cpp` — sedutil --query 동일 플로우 + Feature Descriptor 출력 + `--sedutil-first` 옵션

### 다음 작업: SED 소프트웨어 시뮬레이터

하드웨어 없이 테스트하기 위해 `ITransport`를 구현하는 소프트웨어 SED 시뮬레이터 제작 예정. 현재 `tests/mock/mock_transport.h`는 단순 큐 기반이라 TCG 프로토콜을 시뮬레이션하지 않음.

시뮬레이터가 처리해야 할 것:
- **Discovery** (Protocol 0x01, ComID 0x0001): Feature Descriptor 응답 생성 (TPer, Locking, Geometry, Opal v2)
- **StackReset** (Protocol 0x02, ComID): ComID 상태 초기화
- **Properties** (SM method 0xFF01): TPerProperties + HostProperties echo 응답
- **StartSession/SyncSession** (SM method 0xFF02/0xFF03): TSN 할당, 세션 상태 관리
- **Get** (method 0x06): C_PIN_MSID 등 테이블 읽기
- **CloseSession** (SM method 0xFF06): 세션 정리

패킷 구조: `ComPacket(20B) + Packet(24B) + SubPacket(12B) + TokenPayload`

구현 위치: `src/transport/sim_transport.cpp` + `include/libsed/transport/sim_transport.h`
또는 `tests/mock/` 아래에 `sed_simulator.cpp`로.

### 핵심 참조 파일

| 파일 | 역할 |
|------|------|
| `src/eval/eval_api.cpp` | Properties exchange 구현 (line 62-161) |
| `src/method/param_encoder.cpp` | encodeProperties() (line 51-83), encodeStartSession() |
| `src/method/method_call.cpp` | buildSmCall() — SM 메서드 토큰 생성 |
| `src/method/method_result.cpp` | 응답 파싱, CALL header skip, status 추출 |
| `src/packet/packet_builder.cpp` | ComPacket 생성 (2048B 패딩), 응답 파싱 |
| `src/session/session.cpp` | sendMethod() — 패킷 전송/수신 + MethodResult 파싱 |
| `include/libsed/transport/i_transport.h` | ITransport 인터페이스 (ifSend/ifRecv) |
| `tests/mock/mock_transport.h` | 현재 단순 mock (큐 기반) |
| `include/libsed/method/method_uids.h` | SM_PROPERTIES=0xFF01, SM_START_SESSION=0xFF02 등 |
| `include/libsed/core/uid.h` | SMUID, SP_ADMIN, CPIN_MSID 등 UID 상수 |
