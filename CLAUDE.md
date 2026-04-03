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

2. **SSC High-Level APIs** (`include/libsed/ssc/`) — Convenience wrappers (`OpalAdmin`, `OpalLocking`, `EnterpriseDevice`, etc.) that bundle multiple protocol steps. Used for simple operations where step-by-step control isn't needed.

### Key Modules

| Module | Headers | Purpose |
|--------|---------|---------|
| `eval/` | `eval_api.h`, `sed_context.h` | Core evaluation API and per-thread context |
| `transport/` | `i_transport.h`, `i_nvme_device.h`, `nvme_transport.h` | Transport abstraction and NVMe DI |
| `session/` | `session.h` | Session lifecycle (explicit open/close) |
| `codec/` | `token*.h` | TCG token encoding/decoding |
| `packet/` | `packet_builder.h`, `com_packet.h` | ComPacket construction/parsing |
| `discovery/` | `discovery.h`, feature descriptors | Level 0 Discovery and feature parsing |
| `debug/` | `fault_builder.h`, `test_context.h` | Fault injection (24 injection points) |
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
