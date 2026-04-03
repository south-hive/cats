#!/bin/bash
# sedutil_basic_check.sh — eval_basic_check.cpp 동일 동작
#
# Usage: ./sedutil_basic_check.sh <device>
# 예:    ./sedutil_basic_check.sh /dev/nvme0
#
# 동작:
#   1. Level 0 Discovery (--scan / --query)
#   2. Anonymous AdminSP session → MSID 읽기 (--printDefaultPassword)

set -e

DEVICE=${1:?"Usage: $0 <device>"}

echo "══════════════════════════════════════════"
echo "  sedutil Basic Check: $DEVICE"
echo "══════════════════════════════════════════"
echo ""

# Step 1: Discovery + 기본 정보
echo "── Step 1: Discovery & Query ──"
sedutil-cli --query "$DEVICE"
echo ""

# Step 2: MSID 읽기 (anonymous session)
echo "── Step 2: Read MSID ──"
MSID=$(sedutil-cli --printDefaultPassword "$DEVICE" 2>&1) || true
echo "  MSID: $MSID"
echo ""

echo "══════════════════════════════════════════"
echo "  Basic Check: DONE"
echo "══════════════════════════════════════════"
