# Code of Hammurabi — libsed Immutable Laws

These laws are written in the blood of 17+ bugs that caused real hardware failures.
Every law has a specific bug that created it. Violate none.

---

## LAW 1: sedutil is the Constitution

**sedutil works on real hardware. libsed must produce byte-identical packets.**

If libsed and sedutil differ by even 1 byte, libsed is wrong. Period.
The ioctl_validator (17 tests, 5 sequences) is the supreme court.

**Before committing ANY change to these files, run `./build/ioctl_validator`:**
- `src/method/param_encoder.cpp`
- `src/method/method_call.cpp`
- `src/codec/token_encoder.cpp`
- `src/packet/packet_builder.cpp`
- `src/eval/eval_api.cpp` (Properties/session sections)

**Why:** AI-suggested "spec fixes" broke encoding twice. ioctl_validator caught it.

---

## LAW 2: Integer encoding uses power-of-2 widths ONLY

Encode unsigned integers as: tiny (0-63), 1-byte, 2-byte, 4-byte, or 8-byte.
**Never** use 3, 5, 6, or 7-byte integers even though TCG spec allows it.

```
value < 64      → tiny atom (1 byte total)
value < 0x100   → 0x81 + 1 byte
value < 0x10000 → 0x82 + 2 bytes
value < 0x100000000 → 0x84 + 4 bytes
else            → 0x88 + 8 bytes
```

**Why:** 1048576 (0x100000) was encoded as 3 bytes (0x83). sedutil uses 4 bytes (0x84). Real TPers may reject non-power-of-2 widths.

---

## LAW 3: Object.Set has NO Where clause; only Byte-Table writes do

**Object.Set** (CPIN_SID, LockingRange row, MBRControl row, ACE, Authority,
…): the InvokingUID identifies the row directly. Per TCG Core Spec §5.3.3,
the encoding is `[ Values : list_of_named_values ]` — **no Where**:

```
STARTLIST
  STARTNAME 1 STARTLIST  values  ENDLIST ENDNAME    ← only Values
ENDLIST
```

**Byte-Table writes** (raw MBR area, DataStore offset write): the table
holds a flat byte array; Where carries the offset:

```
STARTLIST
  STARTNAME 0 [offset]                   ENDNAME    ← Where = byte offset
  STARTNAME 1 [bytes]                    ENDNAME    ← Values = bytes
ENDLIST
```

`MethodCall::buildSet()` is for Object.Set only and does NOT emit Where.
Byte-table writers (`EvalApi::writeMbrData`, DataStore writes) build their
tokens manually with the offset Where.

**Why:** This rule was originally LAW 3 in the OPPOSITE direction
("MUST include empty Where") — that was wrong. The wrong rule survived
because:
  - `e41c77d` (2026-04-17 15:32) correctly removed the empty Where
    citing TCG Core Spec §5.3.3.
  - `deac2e6` (2026-04-17 20:21, 5 hours later) wrongly re-added it
    based on `sed_compare`'s hand-rolled DtaCommand reference (which
    had the same misreading as cats — false-positive PASS).
  - User-captured `sedutil-cli` hex dump on hardware 2026-04-27 finally
    showed the truth: no Where for `CPIN_SID.Set` (74 B vs 69 B
    subpacket length, exactly the 5-byte empty-Where overhead).

This is the **second** instance of the same hand-rolled-reference trap;
the first was CellBlock (LAW 16). See LAW 17 — `golden_validator` with
real-hardware fixtures is the only sound validation; spec-text reading
+ hand-rolled reference is not.

---

## LAW 4: Properties encoding structure is sacred

```
STARTNAME "HostProperties"
  STARTLIST
    STARTNAME "MaxComPacketSize" 2048 ENDNAME
    STARTNAME "MaxPacketSize" 2028 ENDNAME
    STARTNAME "MaxIndTokenSize" 1992 ENDNAME
    STARTNAME "MaxPackets" 1 ENDNAME
    STARTNAME "MaxSubpackets" 1 ENDNAME     ← lowercase 'p'!
    STARTNAME "MaxMethods" 1 ENDNAME
  ENDLIST
ENDNAME
```

Each property pair MUST be wrapped in STARTNAME/ENDNAME.
The outer "HostProperties" wrapper is REQUIRED.

**Why:** AI removed the inner STARTNAME/ENDNAME wrapping → 12 bytes missing → InvalidParameter (0x0C).

---

## LAW 5: String case is sacred — "MaxSubpackets" not "MaxSubPackets"

TCG wire protocol is **case-sensitive**. One wrong letter = InvalidParameter.

- Wire string: `"MaxSubpackets"` (lowercase 'p')
- C++ field: `maxSubPackets` (camelCase, irrelevant)

**Why:** Single byte difference (0x70 vs 0x50) caused Properties to fail on real hardware.

---

## LAW 6: StartSession named parameter indices are 0, 3, 4

```
Positional params (always present):
  [0] HostSessionID (uint)
  [1] SP UID
  [2] Write (bool)

Named params (optional, indices are FIXED):
  0 = HostChallenge (credential bytes)
  3 = HostExchangeAuthority (authority UID)
  4 = HostSigningAuthority (authority UID)
```

**NOT 5. NOT 1. NOT 2.** Indices 1 and 2 are HostExchangeCert and HostSigningCert (never used by sedutil).

**Why:** AI changed index 0→5. Different commit changed 3→1, 4→2. Both broke authentication. This bug was fixed THREE times.

---

## LAW 7: StackReset before Properties — always

`exchangeProperties()` must call `stackReset()` internally before sending the Properties packet. The ComID may be in Associated state from a previous session.

**Why:** Properties fails intermittently on real NVMe without StackReset. sedutil always resets first. User reported "fails many time with property command" while sedutil works consistently.

---

## LAW 8: ComPacket minimum 2048 bytes

All ComPackets must be padded to at least 2048 bytes. If larger than 2048, pad to next 512-byte boundary.

**Why:** Some TPers reject packets smaller than 2048. sedutil uses MIN_BUFFER_LENGTH=2048.

---

## LAW 9: SM responses contain CALL header — skip it

Session Manager method responses (Properties, SyncSession, CloseSession) include:
```
CALL(0xF8) + InvokingUID + MethodUID + result_list + EOD + status_list
```

The parser MUST skip the 3-token CALL header before reading the result list.
Regular method responses do NOT have this header.

**Why:** Parser tried to interpret CALL token (0xF8) as data → MalformedResponse on every SM method.

---

## LAW 10: Response parsing must be order-independent

Never assume fields arrive in a specific order. Use name-based matching.

Properties response may return TPerProperties first or HostProperties first — depends on TPer firmware.

**Why:** Properties parser assumed TPerProperties came first. Different TPer sent HostProperties first → wrong values extracted.

---

## LAW 11: CloseSession is special — EndOfSession ONLY

CloseSession sends just the `0xFA` (EndOfSession) token. No CALL. No EndOfData. No status list.

**Why:** It's the only command with this format. Adding CALL/EOD would break the session teardown.

---

## LAW 12: UIDs are always 8-byte byte strings

Every UID is encoded as: `0xA8` + 8 big-endian bytes (9 bytes total).
Never use shorter encoding even for small UIDs like SMUID (0xFF).

**Why:** sedutil convention. TCG spec requires fixed 8-byte UID encoding.

---

## LAW 13: Never trust AI spec interpretation without byte validation

When any AI suggests a "spec fix":
1. Run ioctl_validator BEFORE and AFTER
2. If any test goes from PASS to FAIL, **revert immediately**
3. The AI is wrong until byte-identical output proves otherwise

**Why:** Past AI review — 2 of 3 suggested "fixes" were catastrophically wrong. Both survived code review but failed byte comparison.

**Recent example (2026-04-26):** `d94a674` "Fix MethodCall::buildGet — drop
extra list wrap around CellBlock" was wrong. AI inferred from `sed_compare`'s
hand-rolled `DtaCommand` reference that sedutil emits CellBlock named pairs
flat (no inner list). Real `sedutil-cli` running on hardware was wrapping
the inner list all along (verified by user-captured hex dump showing
`f0 f0 f2 03 03 f3 f2 04 03 f3 f1 f1` — two STARTLIST). Reverted in
`71a6818` after ~9 days. `sed_compare` and `ioctl_validator` PASSed
throughout because both shared the wrong reference. This is exactly the
class of bug that LAW 17 (golden_validator > sed_compare) addresses.

---

## LAW 14: ifRecv must poll until ComPacket.length > 0

After ifSend, the TPer may not have the response ready. ifRecv must loop:
1. Call ifRecv
2. Parse ComPacket header
3. If ComPacket.length == 0 → sleep 10ms → retry (up to 20 times)
4. If ComPacket.length > 0 → response is ready

**Why:** Single-shot ifRecv returns empty response on fast hosts. sedutil has this polling loop.

---

## LAW 15: This is a library for TC developers — be simple

`sed_library.h` is the single include for all common use cases. TC developers should write:
```cpp
#include <libsed/sed_library.h>
```
Not 5-10 scattered includes. Only add extra includes for debug/low-level protocol work.

**Why:** User said "many diversed include statements are not recommended." The library exists to make TC developers' lives easier.

---

## LAW 16: CellBlock named pairs MUST be wrapped in inner STARTLIST/ENDLIST

`Get [ Cellblock : cell_block ]` per TCG Core Spec — `cell_block` is itself
a list type, so it MUST be wrapped in its own STARTLIST/ENDLIST inside the
method's parameter list. The outer list is the args wrapper; the inner list
is the CellBlock object itself.

```
Wire form (CPIN_MSID Get):
  F8                          CALL
  A8 [obj_uid]                InvokingUID
  A8 [GET method]             MethodUID
  F0                          STARTLIST   ← outer args
    F0                        STARTLIST   ← inner CellBlock
      F2 03 03 F3             startColumn (key=3) = 3
      F2 04 03 F3             endColumn   (key=4) = 3
    F1                        ENDLIST     ← close inner CellBlock
  F1                          ENDLIST     ← close outer args
  F9 F0 00 00 00 F1           EOD + status
```

**Wrong (without inner list):**
```
F0    F2 03 03 F3 F2 04 03 F3    F1   ← cats produced this until 71a6818
```

CellBlock key numbers per TCG Core Spec Table 32: 1=startRow, 2=endRow,
3=startColumn, 4=endColumn.

**Why:** 0x0F (TPER_MALFUNCTION) on real hardware. Strict firmwares parse
the tokens but reject the call when the cellblock arg shape does not match
the method signature. Verified by user-captured `sedutil-cli` hex dump
2026-04-26; the vendored `DtaCommand` reference was missing the wrap and
fooled `sed_compare`/`ioctl_validator` into matching libsed's identical
mistake. Cf. LAW 13 recent example, LAW 17.

---

## LAW 17: golden_validator with hardware fixtures > sed_compare with hand-rolled refs

`sed_compare`'s `DtaCommand` reference is **NOT** ground truth. Two
implementations sharing the same TCG misreading produce matching but wrong
bytes — `sed_compare` passes, real hardware rejects. The same applies to
the hand-rolled `ioctl_validator` references.

**Authority order (encoding correctness):**

```
1. golden_validator with .bin fixtures captured from real hardware
2. sed_compare / ioctl_validator (sanity check only)
```

When adding new commands:
- `sed_compare` PASS = **encoding looks consistent with our own assumptions**
- `golden_validator` PASS = **encoding is what real hardware actually accepts**

Both matter, but only golden_validator is decisive. A level-3 PASS by
itself is not evidence of correctness.

**Process for new operation:**
1. Implement encoding from spec.
2. Add hand-rolled reference to `sed_compare` / `ioctl_validator` (level 3).
3. Capture sedutil bytes on real hardware → `tests/fixtures/golden/*.bin`.
4. Add `golden_validator` builder for the operation (level 1).
5. Only call the encoding "validated" when both pass.

**Why:** CellBlock bug (LAW 16) survived 100% of `sed_compare` runs for ~9
days because the test ran a wrong vs wrong comparison. `golden_validator`
infrastructure (`tests/integration/golden_validator.cpp`,
`tests/fixtures/golden/`) was added to break this circular validation. See
also rosetta_stone.md §15 (Validation Hierarchy).

---

## LAW 18: SyncSession TSN must be ≠ 0 — defensive check

`Session::startSession()` MUST reject SyncSession responses where TSN=0.

```
TSN = 0  →  Session Manager (reserved); not a valid session number
TSN ≥ 1  →  Real session, TPer-assigned
```

A real, healthy SyncSession success response always returns TSN ≥ 1. TSN=0
in a "success" SyncSession means either:
- response was malformed and our parser silently mis-extracted, OR
- TPer is in a bad state and reported success with a sentinel value.

In either case, treating TSN=0 as a real session would send all subsequent
in-session packets to the SM, producing 0x0F (TPER_MALFUNCTION) on the
first Get/Set.

**Implementation:** `src/session/session.cpp` — after `decodeSyncSession`,
check `tsn_ != 0`; if zero, log error and return
`ErrorCode::MalformedResponse`, leave session state Idle.

**Why:** Defensive against silent corruption. Documented and enforced as
part of the 0x0F investigation (`b75ea17`).

---

## LAW 19: exchangeProperties() before any session — always

Every code path that opens a session MUST call `exchangeProperties()`
between `discovery0()` and the first `StartSession`. Properties exchange
is not a stylistic convention; some firmwares reject auth or in-session
calls entirely if Properties was never exchanged.

`exchangeProperties()` internally also runs `stackReset()` to push the
ComID into Issued(idle) state — this is a required precondition.

**Canonical pattern:**
```cpp
DiscoveryInfo info;
api.discovery0(transport, info);

PropertiesResult props;
api.exchangeProperties(transport, info.baseComId, props);

Session s(transport, info.baseComId);
s.setMaxComPacketSize(props.tperMaxComPacketSize);   // also required
api.startSession(s, uid::SP_ADMIN, false, ssr);
```

**Why:** `examples/05_take_ownership.cpp` originally only called
`api.discovery0()` and went straight to `api.startSession()`. On real
hardware this returned `NOT_AUTHORIZED` on the second StartSession (the one
with SID + MSID). Adding the Properties call fixed it (`7880bee`). The
SedDrive facade and `eval_composite::fullOpalSetupStepByStep()` already do
this internally; only the step-by-step example flows had the gap.

---

## LAW 20: Match sedutil's session-lifecycle exactly — no extra resets

When a libsed flow is a deliberate mirror of a sedutil-cli operation
(e.g., `examples/22_sedutil_initial_setup.cpp` = `sedutil-cli --initialSetup`),
do **not** add reset/cleanup steps that sedutil itself doesn't perform.

Specifically:
- `stackReset()` runs **once per device-open** (inside
  `exchangeProperties()`). Not between sub-ops, even when each sub-op
  cleanly closes its session.
- `exchangeProperties()` runs **once per device-open**. Not between sub-ops.

If a session-level error happens between sub-ops, the right answer is to
diagnose it, not to paper over it with an extra StackReset.

**Why:** Adding inter-op StackReset breaks the "byte-identical to sedutil"
guarantee that the example was created to demonstrate. It also masks the
real failure mode — the user/maintainer is led to believe extra resets are
"required", when the actual bug is elsewhere (encoding, timing, auth, …).
Concrete: `b75ea17` added `betweenSessions(stackReset)` to example 22 in
response to a 0x0F that turned out to be the CellBlock encoding bug
(LAW 16). The reset additions did not help and were reverted in `22f7b10`.
