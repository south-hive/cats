# Gemini Fix Report - TCG SED Properties & Session Issues (2026-04-03)

This report documents the fixes implemented to resolve the `0x0C (Invalid Parameter)` status returned by TPers during Properties exchange and Session start.

## 1. Properties Exchange Fix

### Problem
TPers were returning `0x0C (Invalid Parameter)` during the `Properties` method call.
The encoded payload had two main issues:
1. **Incorrect Nesting**: Each property (e.g., `MaxComPacketSize`) was being enclosed in its own `STARTNAME`/`ENDNAME` pair.
2. **Naming Typo**: The property `MaxSubpackets` was using an uppercase 'P' (`MaxSubPackets`), which TCG protocol considers a different name.

### Solution
- **Flattened Encoding**: Properties are now encoded as simple `String-Uint` pairs directly within the `HostProperties` list.
- **Unified Naming**: Standardized all property names to lowercase `p` in `MaxSubpackets`.
- **Decoder Robustness**: Updated `ParamDecoder::decodeProperties` to correctly parse these simple pairs and properly exit the list loop.

**Modified Files:**
- `src/method/param_encoder.cpp`: Fixed `encodeProperties`.
- `src/method/param_decoder.cpp`: Fixed `decodeProperties`.
- `src/eval/eval_api.cpp`: Updated `exchangePropertiesCustom` to populate missing fields.

## 2. StartSession Parameter Fix

### Problem
TPers were intermittently rejecting `StartSession` calls, especially when credentials (host challenge) were provided.

### Solution
- **Correct Indexing**: According to **TCG Core Specification Table 225**, the `HostChallenge` parameter is a named parameter with index **5**. The code was incorrectly using index **0** (which is `HostSessionID`).
- **Additional Indexing**: Corrected `HostExchangeCert` index to **6** (previously 2) in the manual `sendStartSession` implementation.

**Modified Files:**
- `src/method/param_encoder.cpp`: Fixed `encodeStartSession`.
- `src/eval/eval_api.cpp`: Fixed `sendStartSession`.

## 3. Library Standards & GEMINI.md

Created `GEMINI.md` to serve as a persistent "Source of Truth" for any Gemini agent interacting with this codebase. It includes mandates for the **Flat API Principle**, **Wire-Level Visibility**, and specific **NVMe Dependency Injection** patterns.

---
*End of Report*
