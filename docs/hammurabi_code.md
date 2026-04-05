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

## LAW 3: Set method MUST include empty Where clause

Every Set operation must encode:
```
STARTNAME 0 STARTLIST ENDLIST ENDNAME    ← Where (empty, but REQUIRED)
STARTNAME 1 STARTLIST values ENDLIST ENDNAME  ← Values
```

**Never** emit Values without Where, even though Where is empty.

**Why:** Missing Where clause caused 5-byte mismatch with sedutil in ALL Set operations (setCPin, setRange, setMbrEnable, etc.)

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
