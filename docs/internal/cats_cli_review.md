---
name: cats-cli 초기 구현 리뷰 및 보완 기록
description: 원 저작자에게 전달할 피드백 — 검토한 버그, 적용한 수정, 남은 작업과 권고 사항. 2026-04-18 기준 cats-cli MVP 복구 세션 기록.
type: project
---

# cats-cli 초기 구현 리뷰 & 보완 기록

**대상 파일**: `tools/cats-cli/main.cpp` (초기 ~256 lines), `CMakeLists.txt`의 cats-cli 섹션
**기준 문서**: `/home/cromshield/.gemini/tmp/cats/.../plans/cats-cli-design.md` (§1~§12)
**기준 플랜**: `/home/cromshield/.claude/plans/keen-dazzling-platypus.md`
**리뷰 일자**: 2026-04-18
**리뷰/보완 수행자**: Claude (review + baseline repair)

---

## 1. 이 문서의 목적

원 저작자의 cats-cli 초기 구현을 받아 검토했고, **빌드 가능한 baseline 복구**를 위한 최소 보완을 수행했다. 원 저작자가 이어 작업할 때 중복 삽질하지 않도록:

1. 어떤 버그가 있었는지 (정확히 무엇이 틀렸는지)
2. 어떻게 고쳤는지 (간단한 변경은 내가 수행)
3. 무엇이 남았는지 (Phase 1~4 설계에 비춰)
4. 권고하는 진행 순서

를 정리한다. 톤은 개선 방향 공유. 모든 지적은 **디자인 문서 §1~§12와 플랜을 비추어서 객관화**했다.

---

## 2. 검토 요약 (심각도 순)

| 심각도 | 항목 | 위치 |
|-------|------|------|
| 🔴 블로커 | 존재하지 않는 API 7곳 사용 → 컴파일 자체 실패 | main.cpp 여러 곳 |
| 🔴 원칙 위반 | `FetchContent(URL https://...)` — 폐쇄망 빌드 불가 | CMakeLists.txt |
| 🔴 설계 위반 | Phase 0(facade gap) 건너뜀 → CLI가 EvalApi 직접 호출 | main.cpp 전반 |
| 🟡 보안 | `raw-method`에 brick-risk 게이트 없음 | eval raw-method |
| 🟡 안전성 | hex 파서: 홀수 길이 UB, 공백/0x 접두사 미지원 | raw-method 파싱 |
| 🟡 사용성 | exit code 모두 0 고정 → CI/스크립트 구분 불가 | main() |
| 🟡 명세 미반영 | 로깅 매핑(§8.2) 없음, password 다각화(§8.1) 없음, JSON(§9.6) 없음 | 전역 |
| 🟡 범위 누락 | design doc §3의 명령 대부분 미구현 (drive revert/psid, range setup/lock/erase, band*, user*, mbr*) | 서브커맨드 트리 |
| 🟢 구조 좋음 | `<Resource> <Action>` 서브커맨드 배치 | CLI11 setup |
| 🟢 좋음 | `PacketDissector` (trace verbosity에서 토큰 덤프) — 설계 의도 반영 | dumpToken/dumpPayload |

---

## 3. 존재하지 않는 API (컴파일 실패 원인)

실제 libsed 헤더에 없는 심볼 7곳을 사용 중이었다. 이건 헤더를 열어보지 않고 "있을 법한" 이름으로 호출한 결과로 보인다. 향후 IDE 자동완성이나 `grep` 한 번으로 거를 수 있음.

| 잘못 쓴 심볼 | 실제 API | 비고 |
|------------|---------|-----|
| `Logger::enableDump(bool)` | 없음. 패킷 덤프는 `LoggingTransport::wrapDump(inner, os, verbosity)` 또는 `SedDrive::enableDump(os, v)` | 패킷 덤프는 **Logger가 아니라 Transport 데코레이터** |
| `Logger::enableLog(bool)` | 없음. `SedDrive::enableLog(logDir)` 또는 `enableLogFile(path)` | 동일 구조 |
| `Logger::setLogFile(string)` | 없음. 플로우 로그는 `libsed::installDefaultFlowLog(path)` | Logger 자체는 sink 주입 방식 |
| `DiscoveryInfo::opal2` | `primarySsc == SscType::Opal20` | bool 플래그 없음, `SscType` enum 사용 |
| `DiscoveryInfo::enterprise` | `primarySsc == SscType::Enterprise` | 동일 |
| `LockingInfo::start` | `rangeStart` | 필드명 불일치 |
| `LockingInfo::length` | `rangeLength` | 필드명 불일치 |

**권고**: `include/libsed/core/types.h`, `include/libsed/core/log.h`, `include/libsed/eval/eval_types.h` 세 파일은 CLI 기능 구현 전에 한 번씩 눈으로 훑는 것을 추천. `grep -n '^struct\|^class\|^enum' include/libsed/...` 으로 구조체·enum 목록을 먼저 만들어두면 좋다.

보완 조치로 위 7개를 **정확한 API로 전부 교체**. 추가로 `MethodResult::status()`는 `uint8_t`가 아니라 `MethodStatus` enum이라서 `mapTcgStatusToExit`의 시그니처도 바꿨다.

---

## 4. 폐쇄망 원칙 위반 — FetchContent

```cmake
# 원본 (CMakeLists.txt)
include(FetchContent)
FetchContent_Declare(
    cli11
    URL https://github.com/CLIUtils/CLI11/releases/download/v2.3.2/CLI11.hpp
    ...
)
```

이 도구는 폐쇄망 환경에서 돌아가야 한다 (사내용 라이브러리, design doc §8.8 + 기존 `libsed` 프로젝트의 명시적 제약). GitHub release URL을 빌드 시 호출하면:
- 빌드 서버에 인터넷이 없거나 프록시가 있으면 **즉시 실패**
- CI 재현성도 낮아짐 (업스트림 릴리즈 삭제/이동 리스크)

**보완 조치**:
1. 현재 dev box의 `build/_deps/cli11-src/CLI11.hpp`에서 파일 추출 (v2.3.2)
2. `third_party/CLI11/CLI11.hpp` 로 git-tracked 벤더링
3. CMakeLists.txt에서 `FetchContent` 블록 제거, `target_include_directories(cats-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/CLI11)` 로 교체

향후 `nlohmann/json` 도입 시(§9.6 JSON 출력) 동일 패턴 — **반드시 벤더링, FetchContent 금지**.

---

## 5. 설계 원칙 위반 — CLI가 EvalApi 직접 호출

Design doc §5.2:
> 내부 로직은 전적으로 `libsed` (cats)의 `SedDrive` 및 `EvalApi` 계층을 활용하여 구현. CLI 자체에 비즈니스 로직을 두지 않음.

원 구현의 `range list` 콜백 (발췌):

```cpp
// 이게 CLI 한 콜백에 들어있었음 — 모든 콜백이 이 6줄을 반복
DiscoveryInfo info;
ctx->api.discovery0(ctx->transport, info);
Session session(ctx->transport, info.baseComId);
StartSessionResult ssr;
ctx->api.startSessionWithAuth(session, uid::SP_LOCKING, false,
                               uid::AUTH_ADMIN1, ctx->getPwBytes(), ssr);
std::vector<LockingInfo> ranges;
auto r = ctx->api.getAllLockingInfo(session, ranges, 8);
...
ctx->api.closeSession(session);
```

이건 CLI가 **세션 수명 주기 + 인증 라우팅 + enumeration**을 다 짊어진 형태다. 설계 상으로는 `SedDrive::enumerateRanges(const std::string& admin1Pw, std::vector<LockingRangeInfo>&)` 한 줄이어야 한다.

**Phase 0 (plan §Phase 0)이 선행조건이었던 이유**. 원 구현은 이 단계를 건너뛰어서 CLI가 자체 로직을 짊어진다. 새 명령(`user list`, `band list`, `mbr status` 등) 추가할수록 이 패턴이 누적되어 유지보수 비용이 폭증한다.

**보완 조치 (이번 세션)**:
- Phase 0 자체를 수행하는 건 범위 초과라 보류
- 대신 `SessionScope` RAII 헬퍼를 추가하여 최소한 CLI 내부의 반복 보일러플레이트(6줄→2줄)만 제거
  ```cpp
  SessionScope s(ctx, info.baseComId);
  if (auto r = s.openWithAuth(uid::SP_LOCKING, false,
                               uid::AUTH_ADMIN1, ctx.pwBytes()); r.failed())
      return reportResult(ctx, "startSession", r);
  // 사용… scope 종료 시 자동 closeSession
  ```
- **원 저작자가 이어갈 때 반드시 Phase 0부터**: `SedDrive::enumerateRanges/enumerateAuthorities/enumerateBands/getMbrStatus/revertLockingSP` 6개 메서드를 facade에 먼저 추가 → CLI 콜백은 한 줄로 축소

---

## 6. 보안 / 안전성 결함

### 6.1 `raw-method` brick 방지 게이트 없음

Design doc §8.4:
> **Brick 방지 게이트:** 두 모드 모두 `--i-know-this-can-brick-the-drive` 플래그 또는 `--force` 없으면 거부.

원 구현은 `--force` 체크 없이 바로 임의 tokens을 전송. fuzzing 도구인데 보호막이 없어서 평가 장비 손실 가능.

**보완 조치**:
- `--force` 플래그 전역 추가
- `cmd::eval_raw_method`에 명시적 거부 블록:
  ```cpp
  if (!ctx.force) {
      std::cerr << "error: 'eval raw-method' can brick the drive. "
                   "Re-run with --force if you understand the risk.\n";
      return EC_USAGE;
  }
  ```
- 동작 확인: `exit=1` (EC_USAGE) 반환, 메시지 출력됨

### 6.2 Hex 파서 취약성

원 구현:
```cpp
for (size_t i = 0; i < hexPayload.length(); i += 2) {
    payload.push_back(static_cast<uint8_t>(
        std::stoul(hexPayload.substr(i, 2), nullptr, 16)));
}
```

문제:
- 홀수 길이 입력 시 마지막 반복이 `substr(i, 2)`로 1글자만 잘라내 `std::stoul`에 넘김 → 파싱 성공, 결과 바이트가 의도와 달라짐 (silent corruption)
- `0x`, `0X` 접두사 미지원
- 공백/탭 섞인 입력 거부 (CLI에서 "DEAD BEEF" 같은 자연스러운 형식 못 씀)
- `std::stoul` 실패 시 예외 미처리

**보완 조치** — `parseHexString(in, out, err)` 헬퍼 추가:
- 공백 스킵
- `0x`/`0X` 접두사 스트립
- 홀수 길이 → `EC_USAGE` + 명확한 에러 메시지
- 비-hex 문자 → 마찬가지
- 동작 확인: `--payload "0xABC"` → `hex string must have an even number of nibbles` + `exit=1`

### 6.3 Password 입력 경로 (미보완)

Design doc §8.1 — `-p` 한 경로만으로는 `ps(1)`에서 비밀번호가 보여서 평가 환경에서도 부적절. `--pw-env VAR`, `--pw-file PATH`, `--pw-stdin`, TTY 프롬프트 경로가 필요.

**보완 안 함** (범위 초과). 원 저작자가 이어서 해야 할 일로 표시. `-p` 플래그의 `help`에 "visible in 'ps'; prefer env/file in CI" 경고 추가해둠.

---

## 7. Exit Code 스키마

Design doc §8.3 요구 사항을 반영했다:

| Code | 의미 |
|------|------|
| 0 | 성공 |
| 1 | CLI / parse error (EC_USAGE) |
| 2 | Transport / NVMe ioctl error (EC_TRANSPORT) |
| 3 | TCG method status != 0 (EC_TCG_METHOD) |
| 4 | Authentication failed — `MethodStatus::NotAuthorized` (EC_AUTH) |
| 5 | Drive does not support feature (EC_NOT_SUPPORTED, 현재 미사용) |

원 구현은 모든 경로가 `return 0`. CLI11 콜백이 `void` 반환이므로 **공용 `int finalExit` 변수**를 main 지역에 두고 각 콜백이 여기에 써두는 패턴으로 해결. main 말미에 `return finalExit;`.

`reportRaw` 가 transport/method 상태를 보고 자동으로 EC_AUTH / EC_TCG_METHOD / EC_TRANSPORT로 매핑한다.

---

## 8. 로깅 매핑 (Design Doc §8.2)

원 구현은 verbosity를 0/1/2/3 숫자로만 받고 실제 libsed 로거와 연동 없음. 설계 문서의 매핑 표를 구현:

| CLI `-v` | libsed `Logger::setLevel` | 패킷 경로 | 플로우 로그 파일 |
|----------|---------------------------|----------|-----------------|
| 0 quiet | `Error` | off | off (`--log-file` 없으면) |
| 1 info | `Info` | off | 〃 |
| 2 debug | `Debug` | off (명시적 요청 시만) | 〃 |
| 3 trace | `Trace` | `LoggingTransport::wrapDump(stderr, v=2)` | 〃 |

`--log-file PATH`가 주어지면 verbosity와 무관하게 `installDefaultFlowLog(path)` 호출 → screen + file 동시 출력.

향후 `-v trace` 가 너무 크다면 `--packet-log FILE` 옵션을 분리하여 파일로만 패킷 아카이브 가능하게 할 것. 설계 문서 §8.2 후반부에 이미 명시됨.

---

## 9. 적용된 세션 헬퍼

원 구현의 반복되는 세션 개폐 6줄 블록을 제거하기 위해 `SessionScope` RAII 도입:

```cpp
class SessionScope {
public:
    SessionScope(Context& ctx, uint16_t comId);
    ~SessionScope();                          // 자동 closeSession

    Result openAnonymous(uint64_t spUid, bool write);
    Result openWithAuth(uint64_t spUid, bool write,
                        uint64_t authUid, const Bytes& credential);

    Session& raw();
    // copy 금지, move 금지 (명시적)
};
```

- 콜백 중간에 early return 해도 소멸자에서 자동으로 세션 닫힘
- open 실패 시 `open_ = false` → 소멸자가 두 번 닫지 않음
- CLI 콜백 한 개가 4~5줄로 축소

**원 저작자가 추가 명령 구현할 때 이 패턴 계속 쓰면 됨.** Phase 0이 완료되어 facade 메서드가 늘어나면 `SessionScope`는 점점 덜 쓰이게 되고 facade 한 줄 호출로 대체되는 방향.

---

## 10. 빌드 / 테스트 결과 (보완 후)

```
$ cmake --build build
[ 71%] Built target cats-cli
... (no errors, no warnings)

$ ./build/tools/cats-cli --help                       # OK
$ ./build/tools/cats-cli drive --help                 # OK
$ ./build/tools/cats-cli eval --help                  # OK

$ ./build/tools/cats-cli -d /dev/nvme0 eval raw-method \
      --invoke 0x101 --method 0x102
error: 'eval raw-method' can brick the drive. Re-run with --force if you understand the risk.
# exit=1  ✓ brick 게이트 작동

$ ./build/tools/cats-cli -d /dev/nvme0 --force eval raw-method \
      --invoke 0x101 --method 0x102 --payload "0xABC"
error: --payload: hex string must have an even number of nibbles
# exit=1  ✓ hex 파서 에러 보고

$ cd build && ctest
100% tests passed, 0 tests failed out of 5
# ✓ 기존 테스트 회귀 없음 (libsed_tests, sed_compare 68/68, ioctl_validator 17/17,
#   scenario_tests 104/104, golden_validator)
```

---

## 11. 남은 작업 (Phase별)

플랜의 Phase 0~4 기준으로 현재 상태와 남은 작업을 정리.

### Phase 0 (필수 선행): libsed facade gap 6개
**상태**: 미수행. 보완 세션에서는 `SessionScope`로 우회.
**남은 항목**:
- `SedDrive::enumerateRanges(std::vector<LockingRangeInfo>&)`
- `SedDrive::enumerateAuthorities(AuthoritySummary&)`
- `SedDrive::enumerateBands(std::vector<BandInfo>&)` (Enterprise)
- `SedSession::setRangeLockState(rangeId, rl, wl)` (read/write 개별)
- `SedDrive::getMbrStatus(MbrStatus&)`
- `SedDrive::revertLockingSP(const std::string& pw)`

**추정**: 반나절.

### Phase 1: 기본 Resource 명령 (~5일)
**상태**: 일부만 (discover, msid, range list).
**남은 항목**:
- `drive revert --sp {admin|locking}`, `drive psid-revert`
- `range setup`, `range lock --read --write`, `range erase`
- `band list/setup/erase` (Enterprise)
- `user list/enable/set-pw/assign`
- `mbr status/enable/write`
- Password 다각화 (§8.1): `--pw-env`, `--pw-file`, `--pw-stdin`, TTY 프롬프트
- `--json` 출력 스키마 (§9.6) — 전 명령 적용

### Phase 2: `eval` 명령 확장 (~5일)
**상태**: tx-start(한계 있음), table-get(단일 컬럼), raw-method(게이트 추가됨).
**남은 항목**:
- `eval raw-tokens` — params만이 아닌 전체 token payload (§8.4 모드 2)
- `eval transaction <script.json>` — JSON script runner (§8.5 스키마 그대로)
- `eval fault-list` / `eval fault-inject` — FaultBuilder 24개 지점 노출 (§8.6)
- `eval table-get --col <s>:<e>` 범위 지원
- 전역 플래그: `--repeat N`, `--repeat-delay`, `--dry-run` (SimTransport 라우팅)

### Phase 3: 차별화 명령 (~5일)
**상태**: 전부 미구현.
**남은 항목**:
- `session run <script>` / `session repl` (세션 유지 — `tx-start` 문제의 근본 해결)
- `compare --cmd <sedutil-cmd>` (`tools/sed_compare` CLI 승격)
- `drive snapshot` / `restore`
- `--timing` (CommandLogger `elapsedMs` 노출)
- `eval golden record` / `compare` (`golden_validator` CLI 승격)

### Phase 4: 벤더링 / 문서 / 리그레션 (~3일)
**상태**: CLI11 벤더링 완료. 나머지 미수행.
**남은 항목**:
- `third_party/json/json.hpp` (nlohmann/json) 벤더링
- `docs/cats_cli_guide.md` (사용자 가이드)
- `CHANGELOG.md` 항목 추가
- `tests/integration/cats_cli_smoke.sh` — SimTransport smoke test, ctest 등록
- CMake 옵션 `LIBSED_BUILD_CLI` 분리

---

## 12. 권고 (원 저작자에게)

가장 도움 될 순서로:

1. **헤더부터 훑기**: `include/libsed/core/types.h`, `core/log.h`, `eval/eval_types.h` 세 파일을 코드 쓰기 전에 1회 통독. 이번 빌드 실패 7건은 전부 헤더를 안 본 결과.
2. **Phase 0 우선 완수**: 플랜에 명시된 facade 6개 메서드부터 추가. 이게 없으면 CLI 코드가 점점 더 EvalApi를 직접 호출하는 방향으로 굳어진다.
3. **폐쇄망 제약 항상 상기**: 새 외부 라이브러리 필요할 때 **무조건 `third_party/` 벤더링**. `FetchContent`·`ExternalProject_Add`·`pkg_check_modules` 모두 네트워크 전제라면 금지.
4. **MVP 기준 명확히**: 지금 구현은 "무엇이 MVP인가"가 모호한 상태. 제안: "Phase 1 + `--json` + exit code" 까지를 MVP로 선언하고 그 지점을 태깅. 나머지(Phase 2~3)는 평가 플랫폼 정체성 확보 후속 작업으로.
5. **각 subcommand에 smoke test 동반**: `SimTransport`로 라우팅 가능한 smoke 스크립트(`--dry-run`)가 있으면 명령 추가 시 회귀 검출이 빠르다. ctest에 등록.
6. **commit 단위**: 이번에 수정한 내용은 한 commit이 아니라 최소 3~4개로 쪼갤 수 있음 (api-rename / fetchcontent-remove / session-scope / brick-gate / hex-parser / exit-codes). 원 저작자가 리뷰하며 받아들이기 쉽게 쪼개어 반영 권장.

---

## 13. 참고 파일

- 수정된 파일:
  - `tools/cats-cli/main.cpp` — 재작성 (API 교정 + SessionScope + brick gate + hex parser + exit codes + 로깅 매핑)
  - `CMakeLists.txt` — cats-cli 섹션 (FetchContent 제거, `third_party/CLI11` 참조)
  - `third_party/CLI11/CLI11.hpp` — 신규 (v2.3.2 single-header 벤더링)
- 변경되지 않은 파일 (확인용):
  - `include/libsed/*` — libsed 본체는 그대로
  - 다른 모든 examples / tools — 회귀 없음 (ctest 5/5 유지)

---

## 14. 피드백 제출 시 한 줄 요약

> 초기 구현을 검토했고 빌드 실패 원인(API 7건 + 네트워크 의존) 및 최소 안전성 문제를 수정해 baseline을 돌려놓았습니다. 구조적 개선(Phase 0 facade gap, 남은 subcommand, JSON/password/session 명세)은 이 문서 §11 순서대로 이어서 진행하시면 됩니다. 세부는 docs/internal/cats_cli_review.md 참조.
