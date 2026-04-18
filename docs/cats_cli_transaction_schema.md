# `cats-cli eval transaction <script.json>` Schema v1

TC 평가 시나리오에서 **한 세션 안의 다수 연산을 스크립트 하나로 실행**하기 위한 JSON 스키마. 각 단계는 개별 `ComPacket`으로 전송되고 결과는 JSON 배열로 반환된다 (기본 stdout, `--json` 지정 시 machine-readable).

## 1. 전체 구조

```jsonc
{
  "version":  1,                              // 필수. 현재 유일 값.
  "session": {                                // 세션 설정
    "sp":        "Admin" | "Locking" | "Enterprise",
    "authority": "SID" | "Admin1" | "User1" | "BandMaster0" | "EraseMaster" | "PSID" | "Anybody",
    "write":     true | false,                // 선택, 기본 true
    "pw":        "literal-password"           // 선택 — 다음 중 하나만:
    "pw_env":    "TC_PW",                     //   환경변수 이름
    "pw_file":   "/path/to/pw.txt"            //   파일 경로 (첫 줄, 개행 제거)
  },
  "ops": [
    { "op": "start_transaction" },
    { "op": "set", "object": "LockingRange1",
      "values": { "RangeStart": 4096, "RangeLength": 8192,
                  "ReadLockEnabled": true, "WriteLockEnabled": true } },
    { "op": "get", "object": "LockingRange1",
      "columns": [0, 10] },
    { "op": "genkey", "object": "LockingRange1" },
    { "op": "authenticate", "authority": "User1", "pw_env": "USER_PW" },
    { "op": "erase", "object": "LockingRange1" },
    { "op": "commit" }                         // 또는 "rollback"
  ],
  "on_error": "rollback" | "continue" | "abort"  // 선택, 기본 "rollback"
}
```

## 2. Session 해석

- **`sp`** → 내부적으로 `uid::SP_ADMIN` / `uid::SP_LOCKING` / `uid::SP_ENTERPRISE` 매핑
- **`authority`** → `uid::AUTH_SID` / `AUTH_ADMIN1` / `AUTH_USER1` 등. `"Anybody"` 는 익명 세션 (write=false 강제)
- **비밀번호**: `pw` / `pw_env` / `pw_file` 중 **정확히 하나**. 둘 이상이면 parse error
- `authority == "Anybody"` 인 경우 비밀번호 필드 금지

## 3. 지원 op

| op | 필수 필드 | 선택 필드 | 의미 |
|----|----------|----------|------|
| `start_transaction` | (없음) | — | StartTransaction 토큰 전송 |
| `commit`            | (없음) | — | EndTransaction(commit=true) 전송 |
| `rollback`          | (없음) | — | EndTransaction(commit=false) 전송 |
| `get`               | `object` | `columns: [start,end]` | 테이블 Get. columns 없으면 전체 |
| `set`               | `object`, `values: {...}` | — | 테이블 Set. values는 column 이름 → 값 |
| `genkey`            | `object` | — | GenKey (crypto erase) |
| `erase`             | `object` | — | Erase method (Enterprise용) |
| `authenticate`      | `authority` | `pw` / `pw_env` / `pw_file` | 세션 내 재인증 |
| `sleep`             | `ms: N` | — | N 밀리초 대기 (타이밍 민감 시나리오용) |

### 3.1 object 이름 해석

**named** (자주 쓰는 것 — 내부에서 UID로 매핑):
- `"LockingRange0"` (Global), `"LockingRange1"`, …
- `"C_PIN_SID"`, `"C_PIN_MSID"`, `"C_PIN_Admin1"`, `"C_PIN_User1"`
- `"MBRControl"`, `"MBR"`, `"DataStore"`

**raw UID** (hex literal):
- `"0x0000000B00000001"` (U64 hex, 8 바이트 UID)

알 수 없는 이름 → parse error.

### 3.2 values 필드 해석

set의 `values` 객체 키는 TCG Opal column 이름:

| 이름 | col # | 타입 |
|------|-------|------|
| `RangeStart`         | 3 | uint64 |
| `RangeLength`        | 4 | uint64 |
| `ReadLockEnabled`    | 5 | bool   |
| `WriteLockEnabled`   | 6 | bool   |
| `ReadLocked`         | 7 | bool   |
| `WriteLocked`        | 8 | bool   |
| `LockOnReset`        | 9 | uint   |
| `PIN`                | 3 | bytes (hex string) |
| `Enabled`            | 5 | bool   |
| `Enable` (MBRCtrl)   | 1 | bool   |
| `Done`   (MBRCtrl)   | 2 | bool   |

알 수 없는 이름 → parse error. (동생아, 원칙: 추측하지 말고 거절하자.)

## 4. 실행 결과 (JSON 출력)

`cats-cli --json eval transaction script.json` stdout 형식:

```jsonc
{
  "command": "eval transaction",
  "exit_code": 0,
  "steps": [
    { "step": 1, "op": "start_transaction",
      "transport_ok": true,
      "tcg_status": 0,
      "tcg_status_name": "Success",
      "elapsed_ms": 2,
      "send_hex": "FB",
      "recv_hex": "..." },
    { "step": 2, "op": "set", "object": "LockingRange1",
      "transport_ok": true, "tcg_status": 0, "tcg_status_name": "Success",
      "elapsed_ms": 5, "send_hex": "...", "recv_hex": "..." },
    ...
  ],
  "on_error": "rollback",
  "terminated_by": "commit"   // "commit" | "rollback" | "abort" | "continue"
}
```

실행 도중 에러가 발생하고 `on_error: "rollback"` 이면 자동으로 rollback op를 추가 실행한 뒤 `terminated_by: "rollback"` 으로 표시.
`"continue"` 는 에러 무시하고 다음 op 진행. `"abort"` 는 즉시 중단 (commit/rollback 안 함 — 세션 닫히면 TPer가 자동 rollback 함).

## 5. Non-JSON 출력 (기본값, verbosity=info)

사람 읽기 좋은 형식:

```
[1/7] start_transaction ...................... OK   (2ms, St=0x00)
[2/7] set LockingRange1 ....................... OK   (5ms, St=0x00)
[3/7] get LockingRange1 cols 0-10 ............. OK   (3ms, St=0x00)
  col[3]=4096 col[4]=8192 col[5]=1 col[6]=1 ...
[4/7] genkey LockingRange1 .................... OK   (8ms, St=0x00)
[5/7] authenticate User1 ...................... OK   (2ms, St=0x00)
[6/7] erase LockingRange1 ..................... FAIL (12ms, St=0x10 TRANSACTION_FAILURE)
[7/7] rollback (on_error) ..................... OK   (1ms, St=0x00)
Summary: 6/7 ok, terminated_by=rollback
```

## 6. 제약 사항 (v1)

- 중첩 transaction 미지원 (start_transaction 한 번만, commit/rollback 한 번만)
- authenticate op는 **세션 내 재인증**. SP 변경은 세션을 닫고 새 스크립트로.
- `values` 의 bytes 필드는 `"PIN": "0x1234ABCD..."` hex 문자열. 원시 UTF-8 문자열은 미지원 (혼동 방지)
- `sleep` 외에는 동기 실행. 동시성 op 없음.
- v1에서 부분 rollback (savepoint) 없음. 전체 rollback만.

## 7. 예시 스크립트

### 7.1 Admin1 로그인 후 Range1 설정 + 커밋

```json
{
  "version": 1,
  "session": { "sp": "Locking", "authority": "Admin1", "pw_env": "ADMIN1_PW" },
  "ops": [
    { "op": "start_transaction" },
    { "op": "set", "object": "LockingRange1",
      "values": { "RangeStart": 0, "RangeLength": 1024000,
                  "ReadLockEnabled": true, "WriteLockEnabled": true } },
    { "op": "commit" }
  ],
  "on_error": "rollback"
}
```

### 7.2 읽기 전용: Global range 상태 조회

```json
{
  "version": 1,
  "session": { "sp": "Locking", "authority": "Admin1", "pw_env": "ADMIN1_PW", "write": false },
  "ops": [
    { "op": "get", "object": "LockingRange0", "columns": [0, 10] }
  ]
}
```

### 7.3 Drive 탐색 (익명)

```json
{
  "version": 1,
  "session": { "sp": "Admin", "authority": "Anybody" },
  "ops": [
    { "op": "get", "object": "C_PIN_MSID", "columns": [3, 3] }
  ]
}
```
