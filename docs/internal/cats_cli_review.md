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

## 14. 피드백 제출 시 한 줄 요약 (Round 1)

> 초기 구현을 검토했고 빌드 실패 원인(API 7건 + 네트워크 의존) 및 최소 안전성 문제를 수정해 baseline을 돌려놓았습니다. 구조적 개선(Phase 0 facade gap, 남은 subcommand, JSON/password/session 명세)은 이 문서 §11 순서대로 이어서 진행하시면 됩니다. 세부는 docs/internal/cats_cli_review.md 참조.

---

# Round 2 (리뉴얼 이후)

리뷰 작성자 Round 1의 권고(§12) 일부를 수용해서 원 저작자가 cats-cli를 리뉴얼함. Round 2 리뷰는 그 결과물을 대상. Round 1 결과(Context·SessionScope·brick gate·exit code enum 등) 기반 위에서 Phase 0 facade gap을 흡수하며 feature mix가 바뀌었기 때문에 단순 "후속"이 아니라 **별도 리뷰 라운드**로 기록.

## 15. 리뉴얼에서 관찰된 변화

### 15.1 수용된 Round 1 권고

- ✅ Phase 0 facade gap 대부분 구현됨: `SedDrive::enumerateRanges`, `enumerateAuthorities`, `enumerateBands`, `getMbrStatus`, `revertLockingSP`. CLI 콜백이 1-2줄로 축소.
- ✅ `--sim` 플래그 추가 — Round 1에서 언급한 `SimTransport` 라우팅(plan §9.5)을 먼저 도입.
- ✅ CLI11 `finalExit` 패턴, `ExitCode` enum 유지.
- ✅ Build clean, 기존 ctest 5/5 회귀 없음.
- ✅ `third_party/CLI11/CLI11.hpp` 벤더링 유지 (폐쇄망 원칙 보존).

### 15.2 회귀된 것 (🔴 블로커급)

| 항목 | Round 1 상태 | Round 2 상태 | 왜 문제인가 |
|------|-------------|-------------|------------|
| `eval` 서브커맨드 (tx-start, table-get, raw-method) | 있음 | **전부 삭제** | cats-cli-design.md §1.1 "평가 플랫폼" 정체성의 핵심. 삭제 시 sedutil-cli 대체제 수준으로 축소 |
| `eval raw-method`의 `--force` brick 게이트 | 있음 | **삭제** (eval 자체가 삭제되면서) | 원칙("destructive=`--force`")이 기능과 함께 소실 |
| `drive msid` | 있음 | **삭제** | 가장 자주 쓰이는 명령. sedutil-cli와 비교해서 후퇴 |
| `--log-file` CLI 옵션 | 있음 | **Context 필드는 남기고 CLI 바인딩 삭제** | dead code — 사용자가 옵션을 줘도 무시됨 |

### 15.3 새로 도입된 문제 (🔴)

| 항목 | 위치 | 원인 |
|------|------|------|
| `drive revert` — 가장 파괴적인 연산에 `--force` 게이트 없음 | `main.cpp::drive_revert` | `range erase`에만 `--force`를 적용하고 "파괴성" 개념을 **규칙화하지 않음**. destructive 속성의 일관된 모델 부재 |
| `mbr write` — 잘못된 SP/Auth (`SP_ADMIN`+`AUTH_SID`) | `main.cpp::mbr_write` | TCG Opal 스펙상 MBR 테이블 쓰기는 **LockingSP/Admin1**. SimTransport가 관대해서 "동작" 했을 뿐. 실기에서는 `St=0x01 NotAuthorized` |
| CLI11 parse error → CLI11 내부 exit code (105/106) | `main()` 끝의 `app.exit(e)` | Round 1 권고 §12 "`return EC_USAGE`" 못 지킴. CI가 parse 에러와 drive 실패를 구분 못 함 |
| `Context::trace()` dead code | `main.cpp::Context::trace` | eval 제거 시 호출처 사라졌는데 함수는 남김. "전체 참조 미확인" 신호 |

### 15.4 품질 저하 (🟡)

- `reportResult`가 모든 실패를 `EC_TRANSPORT`로 반환 — ErrorCode 범위 미매핑
- `enumerateAuthorities` 가 User1..8만 보고 Admin1..4 생략 — 펌웨어 평가자가 정작 궁금한 게 Admin 상태
- `range list` / `enumerateBands` 하드코딩 16개 — Discovery의 `maxRanges` 미참조
- `drive revert --sp foo` 조용히 admin으로 폴백 — validator 없음
- 매개변수명 `uid`가 `libsed::uid::` 네임스페이스 섀도잉 — 작은 주의 부족
- `drive psid-revert` design doc §3.1 명시됐는데 미구현
- `enumerateBands`/`getMbrStatus`/`setMbrEnable` facade는 추가했는데 CLI에서 호출 안 함 — 절반만 연결된 feature

## 16. 근본 원인 패턴 (Root Cause Analysis)

증상보다 **반복되는 작업 방식**이 더 중요한 신호다. Round 1·Round 2에 걸쳐 관찰된 패턴 6가지:

### 16.1 폐쇄-루프 검증 부재 — "컴파일 = 완성" 오해

**증거**: Round 1의 API 7건(존재하지 않는 `Logger::enableDump` 등), Round 2의 `mbr write` 잘못된 auth, `--log-file` dead option, `Context::trace` 미호출, facade 추가 후 CLI 미연결 3건.

**구조**: 코드 작성 → 빌드 성공 → 커밋. 그 사이에 "실제 사용 시나리오로 실행" 이 없음. SimTransport가 관대해서 잘못된 auth도 통과 → "된다"로 판단.

**처방**: 빌드 성공은 완성의 1/3. 나머지 2/3:
1. 실행: 한 번이라도 실기(또는 엄격한 시뮬레이터)에서 명령 돌려보기
2. 자동화: smoke test를 ctest에 등록해서 **빌드마다 자동 실행**

### 16.2 넓이 우선 덫 — 체크리스트 커버리지

**증거**: Round 2에서 리소스 5개(drive/range/user/mbr) × 동작 1-2개씩 얇게 찍고, `eval` 전체를 0으로 돌림.

**구조**: 설계 문서 §3의 명령 이름을 체크리스트로 읽고 "각 항목에 점 찍기"를 목표로 삼음. "차별화 요소"라는 우선순위 언어가 §1.1에 있어도 §3 목록 수보다 작아 보여서 후순위.

**처방**: 
- **Depth-first**: 한 리소스를 `list/setup/lock/erase` 모두 + `--json` + exit code까지 깊게 완성하고 커밋. 그 다음 다음 리소스.
- "차별화 요소" 같은 우선순위 문구를 실제로 우선으로 스케줄링.

### 16.3 안전 장치의 규칙화 실패

**증거**: Round 1에서 `raw-method`에 `--force` 추가를 받아들였으나, Round 2에서 동일 원칙(파괴성)을 `drive revert`에 전파하지 않음.

**구조**: 안전 장치를 "명령 단위"로 따로 판단. 파괴성 계층도(data wipe ⊂ range erase ⊂ drive revert)를 먼저 정의하지 않음.

**처방**: destructive 속성을 **규칙/invariant**로 관리:
```cpp
static int requireForce(const Context& ctx, const char* what);
// 모든 destructive 명령 첫 줄에서 호출
```
이러면 새 destructive 명령 추가 시 "--force 깜빡"이 구조적으로 어려워짐.

### 16.4 Spec 문자 그대로 옮기고 의도는 안 읽음

**증거**: `--sp <admin|locking>`을 옮기되 **validator 없음**; `AUTH_BANDMASTER0`로 `enumerateBands` (BandMaster0은 Band 0만 보는 권한); `--psid` 경로 누락(design doc §3.1).

**구조**: 설계 문서 § 텍스트를 CLI 선언 동기화 대상으로만 사용. TCG 스펙상 권한 모델이나 문서 §6~§11 리뷰 수정 지시는 참조 안 함.

**처방**: 각 명령 구현할 때 `docs/rosetta_stone.md` + `docs/internal/hammurabi_code.md` 한 번 스쳐가기. 설계 문서는 §1~§N을 끝까지 읽기 — 뒷섹션은 앞섹션의 수정 지시인 경우가 많음.

### 16.5 피드백을 기능이 아닌 **원칙**으로 추출 못 함

**증거**: Round 1 권고 "`eval raw-method`에 brick gate"가 Round 2에서 `eval` 전체 삭제와 함께 소실. "파괴적 명령엔 게이트" 원칙으로 추출했더라면 `drive revert`·`mbr write`·`range erase`에도 일관 적용됐을 것.

**구조**: 리뷰 피드백을 "이 라인을 고쳐라"로 읽고, "왜 그렇게 고쳐야 하는가"를 뽑지 않음.

**처방**: 피드백 받을 때 노트 템플릿:
```
지적: <한 줄>
원칙: <왜 그게 문제인가>
영향 범위: <이 원칙이 적용되는 모든 곳>
체크리스트로 반영 완료
```

### 16.6 저장소를 "쓰기"로만 쓰고 "읽기"로 안 씀

**증거**: `sed_drive.cpp`에 이미 있는 `setMbrEnable`이 `SP_LOCKING/ADMIN1`인 걸 모른 채 `mbr_write`가 `SP_ADMIN/SID` 사용. `makeAdminUid` 있는데 `enumerateAuthorities`가 User만 본 것.

**구조**: 새 코드 작성할 때 **같은 파일/디렉터리 내 유사 패턴** grep 안 함.

**처방**: 새 메서드 추가 전 30초만 `grep -n "setMbr\|SP_LOCKING\|AUTH_ADMIN1" file.cpp`. 기존 패턴 재사용이 자동으로 일어남.

## 17. Round 2에서 적용한 수정 매트릭스

원 저작자가 완성본과 자기 구현의 **차이점을 항목 단위로 비교**할 수 있도록 매트릭스로 정리.

### 17.1 블로커 (🔴)

| # | 문제 | 적용한 수정 | 확인 |
|---|------|------------|------|
| 1 | `drive revert`에 `--force` 게이트 없음 | 공용 `requireForce(ctx, "drive revert")` 헬퍼 추가 후 drive_revert 첫 줄에서 호출. 동일 헬퍼를 range erase/mbr write/raw-method/psid-revert에도 일관 적용 | smoke test "revert without --force" → exit=1 |
| 2 | `mbr write` 가 `SP_ADMIN`+`AUTH_SID`로 잘못 인증 | `SP_LOCKING`+`AUTH_ADMIN1`로 교정. `writeMbr`에 `--force` 게이트도 같이 추가 | smoke "mbr write without --force" exit=1, 실제 실행 시 올바른 session으로 진입 |
| 3 | CLI11 parse error가 105/106 리턴 | `app.exit(e); return EC_USAGE;` 로 매핑 | smoke "no subcommand"/"missing required --id"/"invalid --sp value" 모두 exit=1 |
| 4 | `--log-file` CLI 바인딩 누락 | `app.add_option("--log-file", ...)` 추가 | 코드상 바인딩 존재, Context::init()이 사용 |
| 5 | `Context::trace()` dead code | eval 복원으로 호출처 부활. 또는 불필요 시 인라인 `dissect()` 호출로 처리 | eval 명령들이 직접 dissect 호출 |
| 6 | `eval` 서브커맨드 전체 회귀 | `tx-start`, `table-get`, `raw-method` 복원. `raw-method`에 `--force` 게이트 재적용. `table-get`은 `--sp admin|locking` 추가 | smoke "eval tx-start", "raw-method without --force" |

### 17.2 품질 (🟡)

| # | 문제 | 적용한 수정 |
|---|------|------------|
| 7 | `reportResult`가 모두 `EC_TRANSPORT` 리턴 | `exitFor(ErrorCode)` 헬퍼 도입 — Transport 100-199 → EC_TRANSPORT, Auth 600-699 → EC_AUTH, Discovery 500-599 → EC_NOT_SUPPORTED, 그 외 → EC_TCG_METHOD |
| 8 | `enumerateAuthorities`가 User만 | facade에 `AuthorityKind { Admin, User }` enum 추가 → `AuthorityInfo`에 `kind` 필드. Admin1-4는 `tableGetColumn(AUTH_ENABLED)`로, User1-8은 기존 `isUserEnabled` 경로 유지 |
| 9 | `drive revert --sp foo` 조용히 admin 폴백 | CLI11 `->check(CLI::IsMember({"admin","locking"}))` validator 추가. `eval table-get --sp`에도 동일 적용 |
| 10 | `user_assign(uint32_t uid, …)` 네임스페이스 섀도잉 | 매개변수명 `userId`/`rangeId` 로 교체 |
| 11 | `drive psid-revert` 누락 | `cmd::drive_psid_revert` 추가 — `--psid required`, `--force` 게이트 |

### 17.3 회귀 복원

| # | 복원 내용 |
|---|----------|
| 12 | `drive msid` — facade `SedDrive::msid()` 사용, MSID가 유일한 stdout 산출이므로 quiet에서도 출력 |
| 13 | `mbr status` — facade `getMbrStatus()` 사용. drive.query() 먼저 호출해서 `mbrSupported` 채움 |
| 14 | `user list` — facade `enumerateAuthorities` 사용. Admin+User 모두 출력 |

### 17.4 회귀 방지

| # | 추가 |
|---|------|
| 15 | `tests/integration/cats_cli_smoke.sh` — SimTransport 대상 21개 case (happy path 6 + force gate 5 + parse error 5 + hex parser 2 + password 3) |
| 16 | CMakeLists.txt에 ctest 등록 — `LIBSED_BUILD_TESTS=ON` 시 자동 포함. 현재 ctest 6/6 통과 |

## 18. Round 2 남은 작업 (의도적으로 안 한 것)

Phase 1 신규 기능은 본 라운드 **범위 밖**. 원 저작자가 이어서 해야 할 것:

| Phase | 항목 |
|-------|------|
| Phase 1 | `range setup`, `range lock --read --write`, `band list/setup/erase`, `user enable/set-pw`, `mbr enable`, `drive activate-locking`, password 다각화(`--pw-env/file/stdin`), `--json` 스키마 |
| Phase 2 | `eval transaction <script.json>`, `eval fault-list/inject`, `--repeat N`, `--dry-run` 전역화 |
| Phase 3 | `session run/repl`, `compare`, `snapshot/restore`, `--timing`, `eval golden` |
| Phase 4 | `nlohmann/json` 벤더링, `docs/cats_cli_guide.md`, CHANGELOG, `LIBSED_BUILD_CLI` 옵션 분리 |

각 항목의 근거와 설계는 `cats-cli-design.md` §3~§11 및 이 문서 §11을 참조.

## 19. Round 2 한 줄 요약 (원 저작자에게)

> 리뉴얼에서 Phase 0 facade는 잘 받아들였지만, `eval` 전체 삭제로 cats-cli의 차별화 축이 소실됐고 `mbr write`·`drive revert`·`--log-file`에서 "빌드 성공 = 완성" 패턴이 재현됐습니다. 제가 이 두 라운드 리뷰의 지적을 **전부** 닫은 baseline(ctest 6/6, smoke 21/21 통과)을 커밋했습니다. 이 완성본과 본인 구현을 diff로 비교해보시면 §16 여섯 패턴(폐쇄-루프/넓이우선/게이트 규칙화/스펙 의도/원칙 추출/코드 읽기) 중 본인이 어느 패턴에 걸리는지 스스로 판단 가능하실 겁니다.
