# Rosetta Stone — TCG Packet Encoding Reference

This document maps TCG spec → sedutil wire format → libsed code for every command type.
When in doubt, the sedutil wire bytes are the truth.

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
  AE "HostProperties"           string (14 bytes)
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

### 4b. StartSession Unauthenticated (SM, TSN=0/HSN=0)

```
F8                              CALL
A8 [SMUID]                      SMUID
A8 [SM_START_SESSION]           method
F0                              STARTLIST
  82 00 69                      HSN=105
  A8 [SP_ADMIN]                 SP UID
  01                            Write=true  (sedutil hardcodes UINT_01 always)
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

```
F8                              CALL
A8 [object_uid]                 e.g., CPIN_MSID
A8 [GET method]                 0x0000000600000016
F0                              STARTLIST
  F0                            STARTLIST (CellBlock)
    F2 00 03 F3                 startColumn=3 (PIN)
    F2 01 03 F3                 endColumn=3
  F1                            ENDLIST (CellBlock)
F1                              ENDLIST
F9 F0 00 00 00 F1               EOD + status
```

### 4e. Set with Values (in-session, TSN=N/HSN=105)

```
F8                              CALL
A8 [object_uid]                 e.g., CPIN_SID
A8 [SET method]                 0x0000000600000017
F0                              STARTLIST
  F2 00 F0 F1                  Where (EMPTY, NO EndName — sedutil format)
  F2 01                         Values (index=1)
    F0                          STARTLIST
      F2 03 A8 [pin_bytes] F3  PIN column(3) = bytes
    F1                          ENDLIST
  F3                            ENDNAME
F1                              ENDLIST
F9 F0 00 00 00 F1               EOD + status
```

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
sedutil     PBKDF2-HMAC-SHA1  20-byte drive serial num  75000   20 B     D0 14 [20 bytes]
libsed      SHA-256           (none)                    —       32 B     D0 20 [32 bytes]
```

Both encodings are accepted by Opal 2.0 drives.
NEVER use raw ASCII password bytes — most drives require ≥ 20-byte PINs.
Always call `HashPassword::passwordToBytes()` in libsed code.
