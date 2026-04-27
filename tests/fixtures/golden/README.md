# Golden Packet Fixtures

실 SED 하드웨어에서 sedutil-cli 가 송신한 packet 의 byte-level capture.
libsed 의 packet encoding **ground truth** 검증용.

## 왜 필요한가

`sed_compare` 는 hand-rolled `DtaCommand` reference 와 cats 출력을 byte 비교한다.
테스트 작성자가 sedutil 인코딩을 잘못 알고 있으면 **잘못된 cats vs 잘못된 reference**
가 매칭되어 영원히 pass — 실제로 CellBlock 누락 버그가 그렇게 sed_compare 모든
시퀀스에서 매번 PASS 였음에도 실 하드웨어에서는 0x0F (TPER_MALFUNCTION).

`golden_validator` 는 이 circular validation 을 깨고, **TPer 가 실제로 받아들인
바이트** 와 직접 비교한다.

## 테스트 분담

| 테스트              | 비교 대상              | 잡는 버그                  |
|--------------------|------------------------|--------------------------|
| `sed_compare`       | hand-rolled DtaCommand  | spec 해석 sanity check    |
| `ioctl_validator`   | hand-rolled DtaCommand  | 단위 테스트 (mock 환경)   |
| **`golden_validator`** | **실 sedutil capture**  | **encoding logic 정확성**  |

`golden_validator` 가 fail 하면 그게 진짜 버그. `sed_compare` 만 fail 하면 reference
가 잘못됐을 수도 있으니 함께 점검.

## Diff 모드

| 모드       | 비교 범위                | 용도                              |
|-----------|-------------------------|----------------------------------|
| `Full`     | 전체 패킷 (헤더+payload) | TSN=0/HSN=0 SM 패킷 (StartSession, Properties) |
| `TokensOnly` | offset 56+ token payload | in-session 패킷 (Get/Set/Activate/CloseSession). TSN 가변이라 헤더 무시. |

## Capture 절차

### A 시퀀스 (`--query`) — 가장 간단
```bash
sudo ./scripts/capture_golden.sh /dev/nvme0 tests/fixtures/golden/
```
A1~A4 가 자동 추출됨.

### B-E 시퀀스 (`--initialSetup`) — 다세션
**드라이브가 factory 상태일 때만** 캡쳐 가능. 사전:
```bash
# 캡쳐 전 드라이브가 factory 상태인지 확인
sudo sedutil-cli --query /dev/nvme0 | grep -i ownership
# 만약 ownership 가 yes 면 PSID Revert 로 reset
sudo sedutil-cli --PSIDrevert <PSID> /dev/nvme0
```

캡쳐:
```bash
sudo sedutil-cli -vvvvv --initialSetup TestPW123 /dev/nvme0 2>&1 | tee setup.log

# 추출 (B/C/D/E 시퀀스는 별도 추출 스크립트 필요 — TODO 참조)
```

캡쳐된 MSID 와 newPw 를 골든 비교에 그대로 박기 위해 hex 로 추출:
```bash
# 예: MSID 가 "MSID0123456789ABCDEF0123456789AB" 면
export LIBSED_GOLDEN_MSID_HEX=4D5349443031323334353637383941...
export LIBSED_GOLDEN_NEWPW_HEX=$(printf 'TestPW123' | xxd -p)
./build/tests/golden_validator
```

## File Format

- 각 `.bin` 은 **2048-byte** raw ioctl buffer (sedutil `MIN_BUFFER_LENGTH`)
- 레이아웃: `ComPacket(20B) + Packet(24B) + SubPacket(12B) + TokenPayload + 0x00 padding`
- 모든 multi-byte 헤더 필드 big-endian (TCG Core Spec)

## 명명 규칙

```
{시퀀스}{단계}_{op}.bin

A = --query Flow
B = takeOwnership session 2 (SID + MSID)
C = activateLockingSP
D = configureLockingRange + setLockingRange (Global)
E = setMBREnable(0)
```

## 새 fixture 추가

1. 위 절차로 캡쳐
2. `manifest.json` 에 entry 추가
3. `.bin` commit
4. `golden_validator` 가 자동 pickup

## 검증 실행

```bash
cmake --build build && ./build/tests/golden_validator
# fixture 있는 항목은 PASS, 없는 항목은 SKIP
```

## TODO

- `capture_golden.sh` 에 `--initialSetup` 모드 추가 (현재는 `--query` 만)
- B-E fixture 캡쳐 (실 하드웨어 필요)
- F-G 시퀀스 추가 (revert 등)
