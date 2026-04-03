# GEMINI.md - libsed (TCG SED Evaluation Library)

This document provides foundational mandates and expert guidance for working on the **libsed** project. These instructions take precedence over general defaults.

## 1. Core Mandates

### 1.1 Architecture & Design
- **Flat API Principle**: Maintain the `EvalApi` as a stateless, "flat" API where every protocol step is an independent function. Do not introduce hidden state or implicit session management in `EvalApi`.
- **Wire-Level Visibility**: Every `EvalApi` method MUST return or update a `RawResult` structure containing `rawSendPayload` and `rawRecvPayload` for wire-level inspection.
- **Explicit Sessions**: Sessions must be explicitly opened, managed, and closed by the caller. Never implement RAII-based automatic session closing in core library classes unless specifically requested as a high-level utility (e.g., in `EvalComposite`).
- **NVMe Dependency Injection**: Follow the `INvmeDevice` injection pattern. `NvmeTransport` MUST NOT implement NVMe Admin commands directly; instead, it delegates to an injected `INvmeDevice`. Users should extract the device via `EvalApi::getNvmeDevice(transport)` for non-TCG operations.
- **Thread Safety**: `EvalApi` is stateless and thread-safe. `Session` is NOT thread-safe; maintain a strict "one session per thread" model.

### 1.2 Coding Standards
- **Naming Conventions**:
    - **Files**: `snake_case.h` / `snake_case.cpp`.
    - **Classes/Structs**: `PascalCase` (e.g., `EvalApi`, `NvmeTransport`).
    - **Functions/Methods**: `camelCase` (e.g., `startSession`, `getLockingInfo`).
    - **UID Constants**: Namespace `libsed::uid` + `UPPER_SNAKE` (e.g., `uid::SP_ADMIN`).
    - **Column Constants**: Namespace `libsed::uid::col` + `UPPER_SNAKE` (e.g., `uid::col::RANGE_START`).
- **Types**:
    - Use `Bytes` for `std::vector<uint8_t>`.
    - Use `ByteSpan` (const) or `MutableByteSpan` for non-owning views.
    - Use `Result` and `ErrorCode` for error handling. Avoid exceptions.
- **C++ Version**: C++17. Prefer `std::optional`, `std::variant`, and `std::string_view` where appropriate.

### 1.3 Error Handling & Logging
- **Error Codes**: Adhere to established ranges (Transport 100-199, Protocol 200-299, Session 300-399, Method 400-499).
- **Logging**: Use the internal logging system (`core/log.h`). For `EvalApi` results, always ensure the `method_result.cpp` logic logs the method name and status on failure.

## 2. Testing & Validation

### 2.1 Unit Testing
- All new features MUST include unit tests in `tests/unit/`.
- Use `tests/mock/mock_transport.h` for protocol-level testing without hardware.
- Follow the existing test pattern: `test_token_codec.cpp`, `test_packet.cpp`, etc.

### 2.2 Fault Injection
- When modifying protocol logic, verify that existing fault points (`debug/fault_builder.h`) still function correctly.
- If adding new protocol steps, consider adding new `FaultPoint` locations (up to 24 points are currently supported).

### 2.3 Application Notes
- `examples/appnote_*.cpp` are the "Source of Truth" for how the library should be used for specific TCG scenarios. Always update or add an app-note example when implementing major feature sets.

## 3. Implementation Workflow

### 3.1 Research & Strategy
- Before implementing a TCG feature, identify the corresponding section in the **TCG Core Specification** or **SSC Specification** (Opal/Enterprise/Pyrite).
- Map specification steps directly to `EvalApi` methods.

### 3.2 NVMe IOCTLs
- When working on `NvmeTransport`, ensure compatibility with both direct `ioctl` (Mode A) and `INvmeDevice` (Mode B).
- Maintain 2048-byte buffer alignments for `ComPacket` to ensure compatibility with all TPers.

### 3.3 Debugging "Invalid Parameter" (0x0C)
- When encountering `0x0C` status from a TPer:
    1. Check `ComPacket` padding (must be 2048 bytes).
    2. Verify `MaxSubpackets` vs `MaxSubPackets` casing (TCG is case-sensitive).
    3. Use `tools/props_diff.cpp` to compare payloads with known-good implementations (e.g., `sedutil`).

## 4. Key Symbols Reference
- `libsed::eval::EvalApi`: The primary entry point for evaluation.
- `libsed::Session`: Manages TSN, HSN, and sequence numbers.
- `libsed::ITransport`: Abstract interface for `ifSend`/`ifRecv`.
- `libsed::uid`: Namespace containing all well-known TCG UIDs.
- `libsed::ErrorCode`: Enum for detailed failure analysis.
