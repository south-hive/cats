# TC 라이브러리 누락 API / 개선 필요 사항

> 이 문서는 현재 libsed 라이브러리에서 TC 개발자가 필요로 할 수 있지만
> 아직 구현되지 않은 API와 개선이 필요한 영역을 정리합니다.

## 1. Power Reset 시뮬레이션 API

**현재 상태:** Transport close/reopen으로 수동 시뮬레이션만 가능
**필요 기능:**
- `EvalApi::simulatePowerCycle(transport)` — Transport를 닫고 재오픈하는 헬퍼
- `SedContext::reconnect()` — 전원 사이클 후 자동 재연결 + Discovery 갱신
- 전원 사이클 전후 상태 비교 유틸리티

**우선순위:** 높음
**관련 시나리오:** Power Cycle 후 LockOnReset 검증, Controller Reset 복구

---

## 2. NSSR (Non-Synchronous Session Reset) 전용 API

**현재 상태:** `stackReset()` 메서드 있으나 세션 상태 자동 정리 없음
**필요 기능:**
- `Session::forceReset()` — 세션 내부 상태를 Idle로 강제 전환
- `SedContext::resetAndRecover()` — StackReset + Discovery + 새 세션 자동 열기
- 세션 유효성 확인: `Session::isStale()` — 외부 리셋 감지

**우선순위:** 높음
**관련 시나리오:** NSSR 시뮬레이션, Controller Reset 복구

---

## 3. Controller Reset 시뮬레이션

**현재 상태:** FaultPoint에 Controller Reset 전용 포인트 없음
**필요 기능:**
- `FaultPoint::ControllerReset` — Controller Reset 발생 시점 시뮬레이션
- `FaultAction::ResetTransport` — Transport를 리셋하는 Fault 동작
- NVMe Controller Reset (CC.EN=0→1) 시뮬레이션 API

**우선순위:** 중간
**관련 시나리오:** Controller Reset 후 세션 복구

---

## 4. Revert 결과 검증 Helper

**현재 상태:** `revertSP()`, `psidRevert()` 실행 후 결과 수동 검증 필요
**필요 기능:**
- `EvalApi::verifyRevertState()` — Revert 후 예상 초기 상태와 비교
- 자동 검증 항목: SID==MSID, Locking SP 비활성화, Range 초기화, MBR 초기화
- Revert 전 상태 스냅샷 생성 유틸리티

**우선순위:** 중간
**관련 시나리오:** RevertTPer, PSID Revert 후 상태 검증

---

## 5. Session 상태 자동 검증

**현재 상태:** Session::state()로 수동 확인만 가능
**필요 기능:**
- `Session::isStale()` — 외부 요인(리셋, 타임아웃)으로 세션이 무효화되었는지 확인
- `Session::wasResetExternally()` — 외부 리셋 감지
- `Session::heartbeat()` — 세션 유효성 주기적 확인 (Properties 교환 등)
- 세션 만료 시 자동 콜백/이벤트

**우선순위:** 높음
**관련 시나리오:** 모든 리셋/타임아웃 시나리오

---

## 6. Device State Snapshot/Restore

**현재 상태:** 테스트 전후 상태 비교 수동 구현 필요
**필요 기능:**
- `DeviceSnapshot` 구조체 — Discovery, Locking Ranges, MBR, Authority 상태 캡처
- `EvalApi::takeSnapshot(session)` → `DeviceSnapshot`
- `EvalApi::compareSnapshots(before, after)` → 변경 목록
- JSON/바이너리 직렬화 지원

**우선순위:** 중간
**관련 시나리오:** 모든 시나리오의 전후 상태 비교

---

## 7. Retry Policy 설정 API

**현재 상태:** `workaround::kRetryOnSpBusy` 플래그만 있고 세부 설정 불가
**필요 기능:**
- `RetryPolicy` 구조체 — maxRetries, backoffMs, retryableErrors 설정
- `Session::setRetryPolicy(policy)` — 세션별 재시도 정책
- `SedContext::setDefaultRetryPolicy(policy)` — 기본 재시도 정책
- 재시도 횟수/결과 통계 조회
- 지수 백오프(exponential backoff) 지원

**우선순위:** 높음
**관련 시나리오:** SP_BUSY 복구, Timeout 시나리오

---

## 8. Sanitize 진행률 조회 API

**현재 상태:** `INvmeDevice::sanitize()` 실행만 가능, 진행률 확인 불가
**필요 기능:**
- `EvalApi::getSanitizeProgress(transport)` — NVMe Sanitize Log (Log ID 0x81) 파싱
- `SanitizeStatus` 구조체 — progress %, status, estimated completion time
- 비동기 폴링 지원 (진행률 콜백)

**우선순위:** 낮음
**관련 시나리오:** NVMe Sanitize 후 TCG 상태 확인

---

## 9. Namespace 관리 후 TCG 상태 검증 Helper

**현재 상태:** NVMe NS 생성/삭제 API는 있으나 TCG 상태 자동 확인 없음
**필요 기능:**
- `EvalApi::verifyNsidMapping()` — Namespace 변경 후 TCG Locking 상태 검증
- NS 생성/삭제/연결 전후 자동 Discovery 비교
- 다중 Namespace 환경에서의 Range-to-NS 매핑 확인

**우선순위:** 낮음
**관련 시나리오:** Namespace 관리 + TCG 복합 테스트

---

## 10. Enterprise Band ↔ Opal Range 전환 테스트 Helper

**현재 상태:** Enterprise/Opal 각각의 API는 있으나 전환 테스트 유틸리티 없음
**필요 기능:**
- `EvalApi::compareBandAndRange()` — Enterprise Band와 Opal Range 설정 비교
- SSC 전환 시나리오 헬퍼 (Enterprise → Opal 또는 반대)
- Band/Range 매핑 테이블 생성 유틸리티

**우선순위:** 낮음
**관련 시나리오:** SSC 전환 테스트

---

## 11. 비동기 작업 지원

**현재 상태:** 모든 API가 동기(blocking) 방식
**필요 기능:**
- `std::future<Result>` 기반 비동기 API
- 작업 취소(cancellation) 토큰 지원
- 비동기 Discovery, 비동기 세션 열기

**우선순위:** 낮음

---

## 12. 배치(Batch) 작업 API

**현재 상태:** 모든 작업이 개별 호출
**필요 기능:**
- `BatchBuilder` — 여러 Set 작업을 하나의 ComPacket으로 묶기
- 트랜잭션 롤백 지원 (부분 실패 시)
- 배치 작업 결과 일괄 검증

**우선순위:** 낮음

---

## 요약

| # | 항목 | 우선순위 | 난이도 |
|---|------|---------|--------|
| 1 | Power Reset 시뮬레이션 API | 높음 | 중간 |
| 2 | NSSR 전용 API | 높음 | 중간 |
| 3 | Controller Reset 시뮬레이션 | 중간 | 높음 |
| 4 | Revert 결과 검증 Helper | 중간 | 낮음 |
| 5 | Session 상태 자동 검증 | 높음 | 중간 |
| 6 | Device State Snapshot/Restore | 중간 | 중간 |
| 7 | Retry Policy 설정 API | 높음 | 낮음 |
| 8 | Sanitize 진행률 조회 | 낮음 | 낮음 |
| 9 | Namespace-TCG 검증 Helper | 낮음 | 중간 |
| 10 | Enterprise↔Opal 전환 Helper | 낮음 | 중간 |
| 11 | 비동기 작업 지원 | 낮음 | 높음 |
| 12 | 배치 작업 API | 낮음 | 높음 |
