# Rosetta Stone — TCG Packet Encoding Reference

This document maps TCG spec → sedutil wire format → libsed code for every command type.
When in doubt, the **wire bytes captured from sedutil-cli running on real
hardware** are the truth — not hand-rolled `DtaCommand` references in
`sed_compare` / `ioctl_validator`. See §15 (Validation Hierarchy) for the
authority order. CellBlock encoding (§4d) was wrong in this doc and in the
hand-rolled references for ~9 days because both shared the same misreading;
real hardware capture finally caught it (2026-04-26).

---

## 1. PACKET STRUCTURE (56-byte header)

```
Offset  Size  Field                    Notes
──────  ────  ─────────────────────    ──────────────────────────────
 0-3     4    ComPacket.reserved       Always 0x00000000
 4-5     2    ComPacket.comId          0x0001 (big-endian)
 6-7     2    ComPacket.comIdExt       0x0000
 8-11    4    ComPacket.outstanding    0x00000000
12-15    4    ComPacket.minTransfer    0x00000000
16-19    4    ComPacket.length         = everything after this field
20-23    4    Packet.TSN               0 for SM, TPer-assigned for session
24-27    4    Packet.HSN               0 for SM, 105 for session (sedutil)
28-31    4    Packet.seqNumber         0x00000000
32-33    2    Packet.reserved          0x0000
34-35    2    Packet.ackType           0x0000
36-39    4    Packet.acknowledgement   0x00000000
40-43    4    Packet.length            = SubPacketHeader + SubPacketData (padded)
44-49    6    SubPacket.reserved       0x000000000000
50-51    2    SubPacket.kind           0x0000
52-55    4    SubPacket.length         = token payload length (unpadded)
56+      -    Token payload            4-byte aligned after tokens
```

Minimum ComPacket: 2048 bytes (pad with zeros).
If > 2048: pad to next 512-byte boundary.

---

## 2. TOKEN TYPE BYTE MAP

```
Byte Range   Type              Example
──────────   ────              ───────
0x00-0x3F    Tiny uint         0x03 = uint 3, 0x00 = uint 0
0x40-0x7F    Tiny signed int   0x41 = int +1, 0x7F = int -1
0x80-0x9F    Short atom (int)  0x81 = 1-byte uint, 0x84 = 4-byte uint
0xA0-0xBF    Short atom (byte) 0xA8 = 8-byte bytestring (UID)
0xC0-0xDF    Medium atom       0xD0|hi = medium byte, 0xC0|hi = medium int
0xE0-0xEF    Long atom         0xE0 = long int, 0xE4 = long byte
0xF0         STARTLIST
0xF1         ENDLIST
0xF2         STARTNAME
0xF3         ENDNAME
0xF8         CALL
0xF9         ENDOFDATA (EOD)
0xFA         ENDOFSESSION
0xFB         STARTTRANSACTION  (sedutil: STARTTRANSACTON — typo in source)
0xFC         ENDTRANSACTION    (sedutil: ENDTRANSACTON — typo in source)
0xFF         EMPTY
```

---

## 3. UINT ENCODING TABLE (power-of-2 widths ONLY)

```
Value Range          Header  Data Bytes  Total   Example (value=2048)
───────────────────  ──────  ──────────  ─────   ────────────────────
0 - 63               none    0           1       0x08 (value 8)
64 - 255             0x81    1           2       0x81 0xC8 (value 200)
256 - 65535          0x82    2           3       0x82 0x08 0x00 (value 2048)
65536 - 4294967295   0x84    4           5       0x84 0x00 0x10 0x00 0x00 (1048576)
> 4294967295         0x88    8           9       (rare, 64-bit values)
```

NEVER use 0x83 (3-byte) or 0x85-0x87 (5-7 byte). Round up.

---

## 4. COMMAND TEMPLATES

### 4a. Properties (SM, TSN=0/HSN=0)

```
F8                              CALL
A8 00 00 00 00 00 00 00 FF      SMUID
A8 00 00 00 00 00 00 FF 01      SM_PROPERTIES
F0                              STARTLIST
  F2                            STARTNAME
  00                            numeric tiny-atom 0  ← key for HostProperties
  F0                            STARTLIST
    F2 B0"MaxComPacketSize" 82 08 00 F3    prop(2048)
    F2 AE"MaxPacketSize"    82 07 EC F3    prop(2028)
    F2 AF"MaxIndTokenSize"  82 07 C8 F3    prop(1992)
    F2 AA"MaxPackets"       01 F3          prop(1)
    F2 AD"MaxSubpackets"    01 F3          prop(1)  ← lowercase 'p'!
    F2 AA"MaxMethods"       01 F3          prop(1)
  F1                            ENDLIST
  F3                            ENDNAME
F1                              ENDLIST
F9                              EOD
F0 00 00 00 F1                  status [0,0,0]
```

**Key is numeric `0` (tiny atom), NOT the string "HostProperties".** This
doc previously showed `AE "HostProperties"` — wrong. Confirmed by
`src/method/param_encoder.cpp:56-60` and sedutil hex dump. The property
*names* inside the inner list ARE strings (`"MaxComPacketSize"`, etc.) — only
the outer wrapper key is numeric.

### 4b. StartSession Unauthenticated (SM, TSN=0/HSN=0)

```
F8                              CALL
A8 [SMUID]                      SMUID
A8 [SM_START_SESSION]           method
F0                              STARTLIST
  82 00 69                      HSN=105
  A8 [SP_ADMIN]                 SP UID
  00                            Write=false (read-only for anonymous sessions)
F1                              ENDLIST
F9 F0 00 00 00 F1               EOD + status
```

### 4c. StartSession Authenticated (SM, TSN=0/HSN=0)

```
F8                              CALL
A8 [SMUID]                      SMUID
A8 [SM_START_SESSION]           method
F0                              STARTLIST
  82 00 69                      HSN=105
  A8 [SP_ADMIN]                 SP UID
  01                            Write=true
  F2 00 D0 20 [32B cred] F3    HostChallenge (index=0) — libsed: SHA-256, 32B
                               — sedutil:  PBKDF2-HMAC-SHA1, 20B → D0 14 [20B]
  F2 03 A8 [AUTH_SID] F3        HostExchangeAuthority (index=3)
F1                              ENDLIST
F9 F0 00 00 00 F1               EOD + status
```

Named param indices: **0=Challenge, 3=ExchangeAuth, 4=SigningAuth**

### 4d. Get with CellBlock (in-session, TSN=N/HSN=105)

CellBlock is its own list type per TCG Core Spec, so it MUST be wrapped in
an **inner STARTLIST/ENDLIST** inside the method's parameter list. The outer
list is the method args wrapper; the inner list is the CellBlock object.

```
F8                              CALL
A8 [object_uid]                 e.g., CPIN_MSID
A8 [GET method]                 0x0000000600000016
F0                              STARTLIST (method params, outer)
  F0                            STARTLIST (CellBlock, inner)
    F2 03 03 F3                 startColumn(key=3) = 3 (PIN)
    F2 04 03 F3                 endColumn(key=4)   = 3 (PIN)
  F1                            ENDLIST (CellBlock, inner)
F1                              ENDLIST (method params, outer)
F9 F0 00 00 00 F1               EOD + status
```

CellBlock key numbers per TCG Core Spec Table 32: 1=startRow, 2=endRow,
3=startColumn, 4=endColumn. NOT 0/1.

**Verified against real-hardware sedutil-cli hex dump** — NOT against
`sed_compare`'s `DtaCommand` reference. From 2026-04-08 to 2026-04-26 this
section incorrectly showed a flat (single-list) form, matching the
hand-rolled reference but disagreeing with what real sedutil-cli actually
sends to drives. Real-hardware capture (cats=35B vs sedutil=37B, diff = inner
`f0`/`f1` pair) corrected this. See LAW 16, LAW 17 in `hammurabi_code.md`.

### 4e. Object.Set with Values (in-session, TSN=N/HSN=105)

For `ObjectUID.Set [ Values : list ]` — the object position is identified by
the InvokingUID itself, so **no Where**.

```
F8                              CALL
A8 [object_uid]                 e.g., CPIN_SID, LOCKING_GLOBALRANGE, MBRCTRL_SET
A8 [SET method]                 0x0000000600000017
F0                              STARTLIST
  F2 01                         Values (key = uint 1)
    F0                          STARTLIST
      F2 03 A8 [pin_bytes] F3   PIN column(3) = bytes
    F1                          ENDLIST
  F3                            ENDNAME
F1                              ENDLIST
F9 F0 00 00 00 F1               EOD + status
```

**No empty Where.** This doc previously showed `F2 00 F0 F1 F3` (empty
Where) before the Values pair — that was wrong, and matched libsed's wrong
encoding for ~9 days (2026-04-17 to 2026-04-27). User-captured sedutil
hex dump on real hardware showed cats=74B vs sedutil=69B subpacket — the
5-byte difference was exactly the empty-Where overhead. See LAW 3 in
`hammurabi_code.md`.

For **Byte-Table writes** (DataStore, raw MBR shadow), Where IS used and
carries the byte offset — see §4e' below.

### 4e'. Byte-Table.Set with Where (DataStore / raw MBR write)

```
F8                              CALL
A8 [byte_table_uid]             e.g., TABLE_MBR, DATASTORE_TABLE_0
A8 [SET method]                 0x0000000600000017
F0                              STARTLIST
  F2 00 [offset]              F3   Where (key=0) = uint byte offset
  F2 01 [byte_data]           F3   Values (key=1) = bytes
F1                              ENDLIST
F9 F0 00 00 00 F1               EOD + status
```

In libsed: `EvalApi::writeMbrData(offset, data)` and DataStore writes
build these tokens manually (NOT through `MethodCall::buildSet`, which
is for object set only).

### 4f. Activate / RevertSP / Erase / GenKey (empty params)

```
F8                              CALL
A8 [object_uid]                 e.g., SP_LOCKING
A8 [method_uid]                 e.g., ACTIVATE
F0 F1                           STARTLIST ENDLIST (empty)
F9 F0 00 00 00 F1               EOD + status
```

### 4g. CloseSession (SPECIAL — no CALL/EOD)

```
FA                              EndOfSession (ONLY THIS)
```

No CALL. No EOD. No status list. Just 0xFA.

---

## 5. SESSION NUMBER RULES

```
Packet Type          TSN       HSN       Built With
─────────────────    ────      ────      ──────────────────────
Properties           0         0         buildSessionManagerPacket()
StartSession         0         0         buildSessionManagerPacket()
Get/Set/Auth/etc.    N (1+)    105       buildComPacket()
CloseSession         N         105       buildComPacket()
```

- TSN=0, HSN=0 for ALL session manager packets
- TSN assigned by TPer in SyncSession response (1, 2, 3...)
- HSN=105 (sedutil hardcoded constant)
- After CloseSession, that TSN is dead — next session gets new TSN

---

## 6. PROTOCOL FLOW (sedutil --query)

```
Step  Protocol  Command                          TSN/HSN
────  ────────  ───────────────────────────────  ────────
 1    0x01      Discovery (ifRecv only)           N/A
 2    0x02      StackReset (ifSend+ifRecv poll)   N/A
 3    0x01      Properties (SM)                   0/0
 4    0x01      StartSession(AdminSP,RO) (SM)     0/0
 5    0x01      Get(CPIN_MSID) (in-session)       1/105
 6    0x01      CloseSession (in-session)          1/105
```

StackReset ALWAYS precedes Properties. This is not optional.

---

## 7. KEY UIDs (hex, 8-byte big-endian)

```
Name              Value                   Usage
────────────────  ──────────────────────  ───────────────
SMUID             0x00000000000000FF      Session Manager invocations
THIS_SP           0x0000000000000001      Authenticate invocation target
SP_ADMIN          0x0000020500000001      Admin SP
SP_LOCKING        0x0000020500000002      Locking SP (Opal)
SP_ENTERPRISE     0x0000020500010001      Enterprise Locking SP
AUTH_SID          0x0000000900000006      SID Authority
AUTH_PSID         0x000000090001FF01      PSID Authority
AUTH_ADMIN1       0x0000000900010001      Admin1 Authority
AUTH_USER1        0x0000000900030001      User1 Authority
AUTH_BANDMASTER0  0x0000000900008001      Enterprise BandMaster0
AUTH_ERASEMASTER  0x0000000900008401      Enterprise EraseMaster
CPIN_SID          0x0000000B00000001      SID password row
CPIN_MSID         0x0000000B00008402      MSID password row
CPIN_ADMIN1       0x0000000B00010001      Admin1 password row
LOCKING_GLOBAL    0x0000080200000001      Global Locking Range
LOCKING_RANGE1    0x0000080200030001      Locking Range 1
MBRCTRL_SET       0x0000080300000001      MBR Control row
TABLE_MBR         0x0000080400000000      Shadow MBR table (write target)
UID_HEXFF         0xFFFFFFFFFFFFFFFF      Null/sentinel — "no authority"
```

---

## 8. METHOD UIDs (hex, 8-byte big-endian)

```
Name              Value                   Type
────────────────  ──────────────────────  ──────
SM_PROPERTIES     0x000000000000FF01      SM method
SM_START_SESSION  0x000000000000FF02      SM method
SM_SYNC_SESSION   0x000000000000FF03      SM method (response only)
SM_CLOSE_SESSION  0x000000000000FF06      SM method (spec only — NOT sent by sedutil;
                                          CloseSession = bare 0xFA token, no method call)
GET               0x0000000600000016      Object method  (Opal 2.0)
SET               0x0000000600000017      Object method  (Opal 2.0)
EGET              0x0000000600000006      Object method  (Enterprise)
ESET              0x0000000600000007      Object method  (Enterprise)
NEXT              0x0000000600000008      Object method
EAUTHENTICATE     0x000000060000000C      Object method  (Enterprise)
AUTHENTICATE      0x000000060000001C      Object method  (Opal 2.0)
GENKEY            0x0000000600000010      Object method
ACTIVATE          0x0000000600000203      Object method
REVERTSP          0x0000000600000011      Object method
ERASE             0x0000000600000803      Object method
REVERT            0x0000000600000202      Object method
RANDOM            0x0000000600000601      Object method
```

---

## 9. COLUMN NUMBERS (Locking Table)

```
Column  Name              Type     Notes
──────  ────────────────  ───────  ──────────────────
3       RANGE_START       uint64   Starting LBA
4       RANGE_LENGTH      uint64   Length in LBAs
5       READ_LOCK_EN      bool     Enable read locking
6       WRITE_LOCK_EN     bool     Enable write locking
7       READ_LOCKED       bool     Current read lock state
8       WRITE_LOCKED      bool     Current write lock state
9       LOCK_ON_RESET     list     Reset types that trigger lock
10      ACTIVE_KEY        uid      K_AES reference
```

C_PIN Table: column 3 = PIN (bytes)
MBR Control: column 1 = MBR_ENABLE, column 2 = MBR_DONE
Authority: column 5 = AUTH_ENABLED

---

## 10. PASSWORD HASHING

```
Tool        Algorithm         Salt                      Iter    Output   Wire
──────────  ────────────────  ────────────────────────  ──────  ───────  ──────────────────
sedutil     PBKDF2-HMAC-SHA1  drive serial / MSID       75000   20 B     D0 14 [20 bytes]
libsed      SHA-256           (none)                    —       32 B     D0 20 [32 bytes]
```

### ⚠ Cross-tool incompatibility — read carefully

The drive accepts any byte sequence ≥ 20 bytes as a PIN, but it stores
exactly what you Set. Auth must send exactly the same bytes. Therefore:

- **libsed-Set drive + sedutil-Auth (same password)** → MISMATCH → AUTH_FAIL
- **sedutil-Set drive + libsed-Auth (same password)** → MISMATCH → AUTH_FAIL
- After `TryLimit` failures (typically 5) the SID authority locks. Recovery
  requires **PSID Revert**, which **destroys all data and crypto keys**.

Pinned divergence test: `tests/unit/test_hash.cpp::
SedutilDivergence_Sha256VsPbkdf2Sha256`.

### Safe usage

- Use **libsed throughout the drive's lifecycle** — Set, Auth, and Revert
  via libsed only. Self-consistent.
- Or use **sedutil-cli throughout** — likewise consistent.
- **Do not mix tools on the same drive.** If you must, pre-compute a
  sedutil-compatible PIN (PBKDF2-HMAC-SHA1, drive-serial salt, 75000 iter,
  20 B) and pass it via `setCPin(Bytes)` / `startSessionWithAuth(Bytes)`.
  libsed exposes `pbkdf2Sha256` as a building block but **does not yet
  ship PBKDF2-HMAC-SHA1**; cross-tool users must implement that themselves
  or vendor it.

### Implementation notes

- `HashPassword::passwordToBytes(string)` always returns plain SHA-256.
  All `string`-overload entry points (`setCPin`, `startSessionWithAuth`,
  `takeOwnership`, etc.) flow through this function.
- `Bytes`-overload entry points pass the bytes through verbatim — use
  these for sedutil-compatible PINs or for raw MSID flows.
- MSID is read from the drive (factory-set). For `cats`-only lifecycle,
  the raw MSID bytes can be passed verbatim. For `sedutil`-style
  authentication on the same drive, MSID must also be hashed via
  `sedutilHash(msid_string, drive_serial)` because sedutil's
  `DtaSession::start` runs the credential through PBKDF2 unconditionally.
- See LAW 21 in `hammurabi_code.md` for the full risk model and
  recovery considerations.

### sedutil-compatible API (opt-in, since 2026-04-28)

For users who must mix tools or want byte-identical wire output to
sedutil-cli, libsed now ships building blocks (does not change the
default):

```
HashPassword::sha1 / hmacSha1 / pbkdf2Sha1     — primitives
HashPassword::sedutilHash(pw, drive_serial,
                          iter=75000,
                          keyLen=32)            — DTA-fork-compatible
EvalApi::getNvmeSerial(transport, &serial)      — extract 20B salt
```

Usage pattern:
```cpp
Bytes serial;  api.getNvmeSerial(transport, serial);            // 20 B
Bytes pin = HashPassword::sedutilHash("MyPW", serial);          // 32 B
api.setCPin(session, CPIN_SID, pin, raw);                       // Bytes overload
api.startSessionWithAuth(s, SP_ADMIN, true,
                         AUTH_SID, pin, ssr);                    // Bytes overload
```

`examples/23_sedutil_compat_setup.cpp` is the full reference flow.

This path is **opt-in only**. Calling the `string` overloads still
produces SHA-256, unchanged from prior behavior. Default switch is
**not safe** — would lock every libsed-set drive.

---

## 11. DISCOVERY RESPONSE FORMAT

Discovery (Protocol 0x01, ComID 0x0001) is **NOT** a ComPacket. Raw binary format:

```
Offset  Size  Field                    Notes
──────  ────  ─────────────────────    ──────────────────────────────
 0-3     4    headerLength             BE uint32, length of data after this field
 4-5     2    majorVersion             BE uint16
 6-7     2    minorVersion             BE uint16
 8-47    40   Reserved                 Zero-filled
48+      -    Feature Descriptors      Repeating, variable-length
```

### Feature Descriptor (repeating)

```
Offset  Size  Field                    Notes
──────  ────  ─────────────────────    ──────────────────────────────
 0-1     2    featureCode              BE uint16 (0x0001=TPer, 0x0002=Locking, etc.)
 2       1    version + flags          Upper nibble = version
 3       1    dataLength               uint8, length of feature-specific data
 4+      N    featureData              Feature-specific payload
```

Feature codes: `0x0001`=TPer, `0x0002`=Locking, `0x0003`=Geometry,
`0x0100`=Enterprise, `0x0200`=Opal v1, `0x0203`=Opal v2,
`0x0302`=Pyrite v1, `0x0303`=Pyrite v2

---

## 12. SM RESPONSE FORMAT

Session Manager responses (Properties, SyncSession) include a CALL header (LAW 9):

```
F8                              CALL
A8 [SMUID]                      InvokingUID
A8 [SM_METHOD_UID]              MethodUID
F0                              STARTLIST
  ... result tokens ...
F1                              ENDLIST
F9                              EOD
F0 status 00 00 F1              Status list [status, reserved, reserved]
```

Regular method responses (Get, Set, etc.) do NOT have the CALL header.

### Status List

```
F0                              STARTLIST
  status_code                   uint (0x00=Success, 0x01=NotAuthorized, etc.)
  00                            reserved
  00                            reserved
F1                              ENDLIST
```

### Status Codes

```
Code  Name                 Meaning
────  ───────────────────  ──────────────────────────
0x00  Success              Method completed successfully
0x01  NotAuthorized        Auth state disallows operation
0x03  SpBusy               SP processing another session
0x04  SpFailed             SP internal error
0x05  SpDisabled           SP is disabled
0x06  SpFrozen             SP frozen (reset required)
0x07  NoSessionsAvailable  No available session slots
0x08  UniquenessConflict   Uniqueness constraint violation
0x09  InsufficientSpace    Storage space exhausted
0x0A  InsufficientRows     Table has insufficient rows
0x0C  InvalidParameter     Invalid method parameter(s)
0x0F  TPerMalfunction      TPer hardware/firmware failure
0x10  TransactionFailure   Transaction processing failed
0x11  ResponseOverflow     Response exceeds buffer size
0x12  AuthorityLockedOut   Authority locked (too many attempts)
0x3F  Fail                 Generic failure (unclassified)
```

### Properties Response

```
CALL + SMUID + SM_PROPERTIES + STARTLIST
  STARTNAME "TPerProperties" STARTLIST
    STARTNAME "MaxComPacketSize" value ENDNAME
    STARTNAME "MaxResponseComPacketSize" value ENDNAME
    STARTNAME "MaxPacketSize" value ENDNAME
    STARTNAME "MaxIndTokenSize" value ENDNAME
    STARTNAME "MaxPackets" value ENDNAME
    STARTNAME "MaxSubpackets" value ENDNAME
    STARTNAME "MaxMethods" value ENDNAME
  ENDLIST ENDNAME
  STARTNAME "HostProperties" STARTLIST
    ... echoed host values ...
  ENDLIST ENDNAME
ENDLIST + EOD + status
```

Order of TPerProperties / HostProperties may vary (LAW 10).

### SyncSession Response

```
CALL + SMUID + SM_SYNC_SESSION + STARTLIST
  hsn                           uint (echoed HostSessionNumber)
  tsn                           uint (TPer-assigned session number)
  [optional named params]       SPChallenge(0), TransTimeout(4), etc.
ENDLIST + EOD + status
```

---

## 13. ENTERPRISE SSC METHOD UIDs

Enterprise SSC uses different method UIDs from Opal:

```
Operation      Opal UID                  Enterprise UID
───────────    ────────────────────────  ────────────────────────
Get            0x0000000600000016 (GET)  0x0000000600000006 (EGET)
Set            0x0000000600000017 (SET)  0x0000000600000007 (ESET)
Authenticate   0x000000060000001C        0x000000060000000C (EAUTHENTICATE)
```

Note: EAUTHENTICATE (0x0C) and DELETE_ROW (0x0C) share the same UID.
Context-dependent: EAUTHENTICATE targets THIS_SP, DELETE_ROW targets table UIDs.

---

## 14. TRANSACTIONS

TCG Core Spec §3.2.1.3. Group multiple method calls into an atomic batch
on the TPer. Host drives the lifecycle explicitly: open the group, run
methods, then either commit or abort. Each boundary travels as its own
ComPacket so an ioctl error on one step is visible independently of the
method-level status.

### Wire tokens

```
0xFB                                  StartTransaction (single byte)

0xFC  <status>                        EndTransaction
                                        status = 0x00 → commit
                                        status = 0x01 → abort / rollback
                                      status is encoded as a tiny atom
                                      (the same raw byte works at this range).
```

### Packet layout

Each boundary is its own ComPacket within an active session. Method calls
in between use the normal `CALL ... EOD status` framing:

```
ComPacket { Packet(TSN,HSN) { SubPacket { FB } } }                    -- Start
ComPacket { Packet(TSN,HSN) { SubPacket { F8 … F9 F0 00 00 00 F1 } } } -- method
ComPacket { Packet(TSN,HSN) { SubPacket { F8 … F9 F0 00 00 00 F1 } } } -- method
ComPacket { Packet(TSN,HSN) { SubPacket { FC 00 } } }                 -- Commit
```

### TPer response

Varies by drive. Common outcomes:
- Empty response (status list absent) — success.
- Method-status list with `St=0x00` — success.
- `St=0x10 TRANSACTION_FAILURE` — TPer aborted the group itself.
- `St=0x0F TPer_Malfunction` — drive does not implement transactions.

libsed does NOT auto-commit or auto-rollback. The host code checks each
`RawResult` and decides. See `examples/21_transactions.cpp` for the pattern.

---

## 15. VALIDATION HIERARCHY (encoding correctness)

When a discrepancy arises about how a TCG message is encoded, treat sources
in **strict authority order**:

```
1. (truth)    sedutil-cli running on real hardware
              └ captured via `sedutil-cli -vvvvv` hex dumps
              └ stored as .bin fixtures, validated by `golden_validator`

2. (sanity)   sedutil source code
              └ vendored at `third_party/sedutil/` (DtaCommand.cpp / .h only)
              └ helpful, but represents lower-level building blocks; the
                higher-level DtaSession/DtaDevOpal logic that wraps them
                is NOT vendored here

3. (suspect)  hand-rolled DtaCommand replicas in our test code
              └ `tools/sed_compare/*.cpp` — written by humans/AI from spec
              └ `tests/integration/ioctl_validator.cpp` — same
              └ can drift from real sedutil if the author misreads the spec
              └ and matches libsed's identical misreading → false PASS

4. (last)     spec text reading alone
              └ TCG Core Spec / Opal SSC PDFs
              └ humans and AIs misread regularly; never trust without
                level 1 or 2 verification
```

### Why this order matters

`sed_compare` and `ioctl_validator` compare libsed's output to a hand-rolled
reference (level 3). If the test author misread the spec the same way libsed
did, both produce identical-but-wrong bytes → the test passes forever while
real drives reject the packet on every run.

This is not hypothetical. Real example: the CellBlock inner-list wrap
(§4d) was removed from libsed in `d94a674` and from the rosetta_stone in
the same commit, both based on level-3 reasoning. `sed_compare` and
`ioctl_validator` both passed for ~9 days. Real-hardware capture from a user
(level 1) finally exposed the divergence (`71a6818`).

### Decision rule

- New encoding under development:
  - Level 3 PASS = **encoding is consistent with our own assumptions**
  - Level 1 PASS = **encoding is what real hardware accepts**
- Both levels matter, but only level 1 is decisive.
- A level-3 pass by itself is **not** evidence of correctness.
- See `tests/fixtures/golden/README.md` for capture procedure.

### Adding a new operation to libsed

1. Implement encoding (best-effort from spec).
2. Write level-3 reference in `sed_compare` / `ioctl_validator` (sanity
   check; commit when matches).
3. Capture sedutil's actual bytes on real hardware (level 1 fixture).
4. Add `golden_validator` builder + fixture entry.
5. Only when **all three** pass is the encoding considered validated.

If level 3 passes but level 1 fails, libsed AND the level-3 reference are
both wrong — fix both.
