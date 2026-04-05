# Work History

## Session 2026-04-05 (2) — Full Hammurabi Audit + 4 fixes

### What was done

**Full library audit against Hammurabi Code and Rosetta Stone — 15 laws checked across all encoding, transport, and API layers.**

**1. Fix: encodeInt() missing power-of-2 rounding (LAW 2)**
- `src/codec/token_encoder.cpp` — added `if (nBytes == 3) nBytes = 4` rounding to match encodeUint()
- Latent bug — currently unused but would break hardware if `namedInt()` ever called

**2. Fix: Transport bytesReceived returns padded size (LAW 8)**
- `src/transport/nvme_transport.cpp` — parse ComPacket.length (offset 16-19) for actual size
- `src/transport/scsi_transport.cpp` — same fix
- `src/transport/ata_transport.cpp` — same fix
- Previously returned 2048 (padded) even for empty responses, breaking Session::sendRecv() polling

**3. Fix: Missing ifRecv polling (LAW 14)**
- Added `EvalApi::pollRecv()` helper — retries up to 20 times checking ComPacket.length > 0
- `discovery0Raw()` — single-shot → pollRecv
- `discovery0Custom()` — single-shot → pollRecv
- `verifyComId()` — already wrapped in stackReset polling loop, left as-is

**4. Cleanup: Removed unused ParamEncoder methods**
- Removed `encodeLockingRangeSet`, `encodePinSet`, `encodeMbrControl`, `encodeAuthorityEnable`, `encodeSetValues`
- These were never called — all Set operations use `MethodCall::buildSet()` instead

### Known issues flagged but NOT fixed (needs hardware validation)

- `tcgWrite()`/`writeMbrData()` — uses offset-based Where clause (different from standard Set). May be correct for ByteTable ops. Needs sedutil comparison test.
- `assignUserToRange()` — duplicate UID encoding in ACE BooleanExpr. May need half-UID pairs per TCG spec.

### Files modified

```
src/codec/token_encoder.cpp          — encodeInt power-of-2 rounding
src/transport/nvme_transport.cpp     — bytesReceived from ComPacket header
src/transport/scsi_transport.cpp     — same
src/transport/ata_transport.cpp      — same
src/eval/eval_api.cpp                — pollRecv helper + discovery polling
include/libsed/eval/eval_api.h       — pollRecv declaration
src/method/param_encoder.cpp         — removed 5 unused methods
include/libsed/method/param_encoder.h — removed declarations
```

### Current state

- `ctest` — 2/2 PASS
- `ioctl_validator` — 17/17 PASS
- All examples build clean
- **Still needs real NVMe hardware validation**

---

## Session 2026-04-05 — ioctl_validator expansion + 3 bug fixes + Hammurabi Code

### What was done

**1. Ran ioctl_validator (5 tests) — all PASS**
- Confirmed Properties, StartSession (unauth/auth), Get CPIN_MSID, CloseSession all byte-identical to sedutil.

**2. Added 6 new tests → found Bug: Missing Where clause in Set**
- Added tests for: Set C_PIN, Set Locking Range, Authenticate, Activate, RevertSP, Erase
- Tests 6,7 (both Set operations) FAILED — missing `STARTNAME 0 STARTLIST ENDLIST ENDNAME` (empty Where)
- **Fixed** in `src/method/method_call.cpp:buildSet()` and `src/method/param_encoder.cpp:encodeSetValues()`
- All 11 tests PASS after fix

**3. Restructured tests into 5 TCG sequences (17 total steps)**
- User pointed out tests must follow real protocol sequences, not isolated commands
- Reorganized into: A=Query, B=TakeOwnership, C=Activate, D=Configure+Lock, E=PSID Revert
- Each sequence uses correct TSN progression (TSN_A=1, TSN_B=2, etc.)
- Found Bug: Integer encoding width — 1048576 encoded as 3 bytes, sedutil uses 4
- **Fixed** in `src/codec/token_encoder.cpp:encodeUint()` — round up to power-of-2 (1,2,4,8)
- All 17 tests PASS

**4. Fixed Properties failing on real NVMe**
- User reported Properties command fails intermittently, sedutil works fine
- Root cause: `exchangePropertiesCustom()` didn't call `stackReset()` first
- ComID could be in Associated state from previous session
- **Fixed** in `src/eval/eval_api.cpp` — added `stackReset()` call inside `exchangePropertiesCustom()`

**5. Simplified includes — expanded `sed_library.h`**
- User said too many diverse include statements for TC developers
- Expanded `include/libsed/sed_library.h` to include eval, transport, security, session, discovery
- Simplified all 19 example files: most now just `#include <libsed/sed_library.h>`
- Only debug/low-level protocol headers remain as extra includes

**6. Created Hammurabi Code + Rosetta Stone**
- User requested permanent rules to prevent repetitive mistakes
- `docs/hammurabi_code.md` — 15 immutable laws from every bug
- `docs/rosetta_stone.md` — byte-exact encoding reference for all TCG commands

### Files modified

```
src/method/method_call.cpp          — Added empty Where clause to buildSet()
src/method/param_encoder.cpp        — Added empty Where clause to encodeSetValues()
src/codec/token_encoder.cpp         — Integer encoding rounded to power-of-2 widths
src/eval/eval_api.cpp               — Added stackReset() inside exchangePropertiesCustom()
include/libsed/sed_library.h        — Expanded to master convenience header
tools/ioctl_validator.cpp           — Rewritten: 5 sequences, 17 tests, proper TSN/HSN
examples/*.cpp (19 files)           — Simplified includes to use sed_library.h
```

### Current state

- `ctest` — 2/2 PASS (libsed_tests + ioctl_validator)
- `ioctl_validator` — 17/17 PASS across 5 sequences
- All examples build clean, no warnings
- **NOT YET VALIDATED on real NVMe hardware** — this is the critical next step

### What needs to happen next

1. **Real hardware validation** — run the full appnote sequences on actual NVMe SED
   - Start with `eval_sedutil_query` (Query flow — safest, read-only)
   - Then `eval_basic_check` (Properties + session)
   - Compare pass rate against sedutil on same device
2. **Test coverage gaps** — ioctl_validator covers 17 command patterns but ~100+ EvalApi methods exist untested
3. **Enterprise SSC** — no ioctl_validator tests for Enterprise-specific commands yet
4. **Response parsing** — ioctl_validator tests encoding only, not response parsing correctness

### Bugs fixed this session (3 total)

| Bug | File | Root cause |
|-----|------|------------|
| Set missing Where clause | method_call.cpp, param_encoder.cpp | Empty Where `STARTNAME 0 [] ENDNAME` not emitted |
| Integer 3-byte encoding | token_encoder.cpp | 0x100000 encoded as 0x83 not 0x84 |
| Properties fails on NVMe | eval_api.cpp | No StackReset before Properties exchange |
