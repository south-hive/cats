# cats-cli 사용자 가이드

cats-cli는 libsed(`cats`) 위에 얹은 **평가/디버깅 전용 커맨드라인 도구**다. `sedutil-cli`가 production 잠금/해제에 집중한다면, cats-cli는 NVMe/SED 펌웨어 개발자·QA·보안 평가자를 위한 **프로토콜 아날라이저 + 결함 주입 + 스크립트 실행** 플랫폼을 지향한다.

## 빠른 시작

```bash
# 빌드
cmake -B build -DLIBSED_BUILD_TOOLS=ON
cmake --build build
./build/tools/cats-cli --help

# 실기
./build/tools/cats-cli -d /dev/nvme0 drive discover

# 시뮬레이터로 로직/스크립트 검증 (하드웨어 불필요)
./build/tools/cats-cli --sim drive discover
```

## 명령 트리

```
cats-cli
├── drive
│   ├── discover          # Discovery + summary
│   ├── msid              # Read MSID
│   ├── revert --sp ...   # Factory reset (DESTRUCTIVE, --force)
│   └── psid-revert       # PSID-based reset (DESTRUCTIVE, --force)
├── range
│   ├── list              # Enumerate ranges
│   ├── setup             # Configure start/length (DESTRUCTIVE, --force)
│   ├── lock --read --write   # Set lock state
│   └── erase             # Crypto-erase (DESTRUCTIVE, --force)
├── band                  # Enterprise SSC
│   └── list
├── user
│   ├── list              # Admin1-4 + User1-8 + enabled state
│   ├── enable            # Enable user authority
│   ├── assign            # Assign user to range ACL
│   └── set-pw            # Set user password
├── mbr
│   ├── status            # Shadow enabled/done/supported
│   ├── enable --state    # On/off (DESTRUCTIVE, --force)
│   ├── done --state      # On/off (after PBA handoff)
│   └── write --file      # PBA image write (DESTRUCTIVE, --force)
└── eval                  # Evaluator-only
    ├── tx-start          # StartTransaction (session closes on exit)
    ├── table-get         # Read table columns
    ├── raw-method        # Send arbitrary method (DESTRUCTIVE, --force)
    └── transaction       # Run JSON script in one session
```

## 전역 옵션

| 옵션 | 의미 |
|------|------|
| `-d, --device PATH` | Target device (e.g. `/dev/nvme0`). `--sim` 이 아니면 필수 |
| `--sim` | 내부 `SimTransport`에 라우팅 (하드웨어 없이 로직 검증) |
| `-v, --verbosity N` | 0=quiet, 1=info (기본), 2=debug, 3=trace (패킷 덤프) |
| `--log-file PATH` | flow log (LIBSED_INFO 등)를 stderr + 파일로 동시 기록 |
| `--json` | stdout JSON 출력 (discover / msid / range list / user list / mbr status / eval transaction) |
| `--repeat N` | 서브커맨드를 N회 반복 (aging/stress) |
| `--repeat-delay MS` | 반복 사이 대기 (ms) |
| `--force` | Destructive 명령 필수. 없으면 `EC_USAGE(=1)`로 거부 |

## Password 입력 (4가지 경로 중 하나)

CI/자동화에서는 `ps(1)` 노출을 피하기 위해 literal 사용 금지 권장.

| 플래그 | 용도 |
|--------|------|
| `-p, --password STR` | 리터럴 (평가 세션에만, ps에 보임) |
| `--pw-env VAR` | 환경변수에서 읽기. CI에 맞음 |
| `--pw-file PATH` | 파일 첫 줄에서 읽기 (chmod 0600 권장) |
| `--pw-stdin` | stdin 첫 줄에서 읽기 (pipe 친화) |

둘 이상 지정하면 `EC_USAGE` 반환. `user set-pw`의 **새 사용자 비밀번호**는 `--new-pw` / `--new-pw-env` / `--new-pw-file`로 따로 전달.

## Exit Code 스키마

| Code | 의미 |
|------|------|
| 0 | 성공 |
| 1 | `EC_USAGE` — CLI parse 에러, missing required, pw 경로 충돌, hex 파싱 실패 등 |
| 2 | `EC_TRANSPORT` — NVMe/ATA/SCSI ioctl 실패 |
| 3 | `EC_TCG_METHOD` — TCG 메서드 status ≠ 0 (세부는 stderr 및 JSON 응답) |
| 4 | `EC_AUTH` — `MethodStatus::NotAuthorized` |
| 5 | `EC_NOT_SUPPORTED` — 드라이브가 기능 미지원 (SSC 불일치, feature 없음 등) |

## JSON 출력 스키마

`--json` 지정 시 stdout에 `{"command": "...", ...}` 형식. 주요 명령 스키마:

### drive discover
```json
{
  "command": "drive discover",
  "ssc": "Opal 2.0",
  "com_id": 1,
  "num_com_ids": 1,
  "max_compacket": 2048,
  "locking_present": true,
  "locking_enabled": false,
  "locked": false,
  "mbr_supported": true,
  "mbr_enabled": false,
  "mbr_done": false
}
```

### drive msid
```json
{
  "command": "drive msid",
  "msid_hex": "66b35c...",
  "length": 32,
  "msid_ascii": "..."   // printable-ASCII일 때만
}
```

### range list
```json
{
  "command": "range list",
  "ranges": [
    { "id": 0, "start": 0, "length": 0,
      "read_lock_enabled": false, "write_lock_enabled": false,
      "read_locked": false, "write_locked": false, "active_key": 0 },
    ...
  ]
}
```

### user list
```json
{
  "command": "user list",
  "authorities": [
    { "kind": "Admin", "id": 1, "uid": 2594073385625419777, "enabled": true },
    ...
  ]
}
```

### mbr status
```json
{
  "command": "mbr status",
  "supported": true,
  "enabled": false,
  "done": false
}
```

### eval transaction (상세는 `docs/cats_cli_transaction_schema.md`)
```json
{
  "command": "eval transaction",
  "ok": true,
  "terminated_by": "commit",
  "on_error": "rollback",
  "script": "...",
  "steps": [
    { "step": 1, "op": "start_transaction",
      "transport_ok": true, "tcg_status": 0, "tcg_status_name": "Success",
      "elapsed_ms": 2 },
    ...
  ]
}
```

## 파괴 가능 명령 일관 규칙

모든 destructive 명령은 `--force` 없으면 `EC_USAGE(1)`로 거부한다. 이는 규칙으로 강제됨 (`requireForce()` 헬퍼 공통 적용). 현재 대상:

- `drive revert` (AdminSP 또는 LockingSP)
- `drive psid-revert`
- `range setup` / `range erase`
- `mbr enable` / `mbr write`
- `eval raw-method` (fuzzing — brick 가능성)

## `eval transaction` — JSON 스크립트 실행

한 세션 안에서 다수 연산을 스크립트로. 전체 스키마는 [`cats_cli_transaction_schema.md`](cats_cli_transaction_schema.md).

예시:
```bash
export TC_PW="$(cat /secure/admin1.pw)"
cats-cli -d /dev/nvme0 --pw-env TC_PW --json \
    eval transaction --script my_scenario.json
```

`tests/fixtures/tx_sample_read.json`: 익명 MSID 조회 (가장 단순한 샘플)
`tests/fixtures/tx_sample_txn.json`: start → set → get → commit
`tests/fixtures/tx_sample_genkey.json`: range key rotation

## 실기 MoT (Moment of Truth) 주의

- **MBR shadow 상태 조회**: `mbr status`는 Discovery LockingFeature 플래그에서 읽는다. MBRControl 테이블에서 직접 읽는 경로는 LockingSP/Admin1 인증이 필요하므로 anonymous 호출 시 실패한다. cats-cli는 Discovery 경로를 쓰므로 인증 불필요.
- **`drive revert --sp admin`**: 공장 드라이브에서는 SID == MSID이므로 `--password`에 **MSID 바이트**를 주어야 한다. Ownership 후에는 사용자가 설정한 SID 비밀번호.
- **`eval transaction`의 commit/rollback**: 실제 Opal 드라이브의 트랜잭션 지원은 편차가 크다. `St=0x10 (TRANSACTION_FAILURE)` 또는 `St=0x0F (TPer_Malfunction)` 반환하는 드라이브 있음. JSON 출력의 `tcg_status_name`에 그대로 노출되니 자동화에서 판별 가능.
- **`band list`**: `BandMaster0` 권한으로 열리므로 Band0 정보만 정확히 보인다. 다른 Band는 각자의 BandMaster 자격증명이 필요 (library 제약).

## Logging / Trace

```bash
# 패킷 구조 트리까지
cats-cli -v 3 --sim drive discover

# flow log를 stderr + /var/log/tc.log로
cats-cli --log-file /var/log/tc.log drive discover

# --json + --pw-env + --log-file 조합이 CI 친화적
TC_PW=... cats-cli --sim --pw-env TC_PW --json \
                   --log-file /tmp/run.log drive discover
```

## 자동화 레시피

### 드라이브 식별
```bash
SSC=$(cats-cli -d /dev/nvme0 --json drive discover | jq -r '.ssc')
echo "SSC: $SSC"
```

### 조건부 provisioning
```bash
if cats-cli -d /dev/nvme0 --json drive discover \
     | jq -e '.locking_enabled == false' >/dev/null; then
  cats-cli -d /dev/nvme0 --pw-env ADMIN_PW --force drive revert --sp admin
  cats-cli -d /dev/nvme0 --pw-env ADMIN_PW --force \
           range setup --id 1 --start 0 --len 1024000
fi
```

### Aging / stress
```bash
cats-cli -d /dev/nvme0 --pw-env ADMIN_PW --repeat 1000 --repeat-delay 50 \
         drive discover
```

## 관련 문서

- `docs/sed_drive_guide.md` — `SedDrive` facade 사용법 (코드 레벨)
- `docs/eval_platform_guide.md` — `EvalApi` 저수준 API
- `docs/rosetta_stone.md` — TCG 와이어 포맷 레퍼런스
- `docs/cats_cli_transaction_schema.md` — `eval transaction` JSON 스키마
- `docs/internal/cats_cli_review.md` — 구현 리뷰 (기여자용)
