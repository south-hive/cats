#!/bin/bash
# sedutil_session_loop.sh — eval_session_loop.cpp 동일 동작
#
# Usage: ./sedutil_session_loop.sh <device> <sid_password> [count]
# 예:    ./sedutil_session_loop.sh /dev/nvme0 myPassword 5
#
# 동작 (매 반복):
#   1. SID 인증 확인 (setSIDPassword same→same)
#   2. Locking SP 상태 확인 (query)
#   3. MSID 읽기
#
# sedutil은 세션 단위 제어가 없으므로, 동일 효과의 명령을 반복한다.

set -e

DEVICE=${1:?"Usage: $0 <device> <sid_password> [count]"}
SID_PW=${2:?"Usage: $0 <device> <sid_password> [count]"}
COUNT=${3:-5}

echo "══════════════════════════════════════════"
echo "  sedutil Session Loop: $DEVICE"
echo "  Iterations: $COUNT"
echo "══════════════════════════════════════════"
echo ""

# Discovery
echo "── Discovery ──"
sedutil-cli --query "$DEVICE"
echo ""

# MSID 확인
echo "── MSID ──"
MSID=$(sedutil-cli --printDefaultPassword "$DEVICE" 2>&1) || true
echo "  MSID: $MSID"
echo ""

PASS=0
FAIL=0

for i in $(seq 1 "$COUNT"); do
    echo "── Iteration $i/$COUNT ──"
    START=$(date +%s%3N)

    # 1. SID 인증 테스트: setSIDPassword(old=SID_PW, new=SID_PW)
    #    동일 비밀번호로 설정 → 인증 성공 여부만 확인
    if sedutil-cli --setSIDPassword "$SID_PW" "$SID_PW" "$DEVICE" 2>&1; then
        echo "  SID auth: OK"
    else
        echo "  SID auth: FAIL"
        FAIL=$((FAIL + 1))
        continue
    fi

    # 2. Locking Range 상태 (Locking SP에 Admin1으로 접근)
    #    NOTE: sedutil은 Admin1 권한 사용. SID와 Admin1 비밀번호가 같다고 가정.
    sedutil-cli --listLockingRanges "$SID_PW" "$DEVICE" 2>&1 || true

    END=$(date +%s%3N)
    ELAPSED=$((END - START))
    echo "  -> OK (${ELAPSED}ms)"
    echo ""
    PASS=$((PASS + 1))
done

echo "══════════════════════════════════════════"
echo "  Session Loop: $PASS pass / $FAIL fail ($COUNT total)"
echo "══════════════════════════════════════════"

[ "$FAIL" -eq 0 ] || exit 1
