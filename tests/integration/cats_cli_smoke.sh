#!/bin/bash
# cats-cli smoke test — runs every subcommand against SimTransport and checks
# exit-code expectations. Catches regressions like "force gate missing",
# "parse error returns CLI11 code instead of EC_USAGE", "MBR auth mismatch".
#
# Keep this FAST and INDEPENDENT of real hardware. Anything requiring
# actual drive semantics belongs in tests/scenarios/ instead.

set -u

CLI="${1:-./build/tools/cats-cli}"
if [[ ! -x "$CLI" ]]; then
    echo "error: cats-cli binary not found at $CLI"
    exit 127
fi

FAIL=0
PASS=0

# expect_exit <expected_code> <label> <cmd...>
expect_exit() {
    local want="$1"; shift
    local label="$1"; shift
    "$@" >/dev/null 2>&1
    local got=$?
    if [[ "$got" == "$want" ]]; then
        echo "  OK   $label (exit=$got)"
        PASS=$((PASS+1))
    else
        echo "  FAIL $label (exit=$got, want=$want)"
        FAIL=$((FAIL+1))
    fi
}

echo "== cats-cli smoke =="

# ── Happy paths (SimTransport-backed) ──
expect_exit 0 "drive discover"        "$CLI" --sim drive discover
expect_exit 0 "drive msid"            "$CLI" --sim drive msid
expect_exit 0 "mbr status"            "$CLI" --sim mbr status
expect_exit 0 "eval tx-start"         "$CLI" --sim eval tx-start

# range list / user list may return EC_TCG_METHOD(3) from SimTransport when
# the row doesn't exist — we just need "not a crash/parse error".
"$CLI" --sim -p pw range list >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" ]]; then echo "  OK   range list (exit=$ec)"; PASS=$((PASS+1)); \
    else echo "  FAIL range list (exit=$ec)"; FAIL=$((FAIL+1)); fi

"$CLI" --sim -p pw user list >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" ]]; then echo "  OK   user list (exit=$ec)"; PASS=$((PASS+1)); \
    else echo "  FAIL user list (exit=$ec)"; FAIL=$((FAIL+1)); fi

# ── Force gates (destructive operations) ──
expect_exit 1 "revert without --force"      "$CLI" --sim -p pw drive revert --sp admin
expect_exit 1 "range erase without --force" "$CLI" --sim -p pw range erase --id 1
expect_exit 1 "mbr write without --force"   "$CLI" --sim -p pw mbr write --file /dev/null
expect_exit 1 "raw-method without --force"  "$CLI" --sim eval raw-method --invoke 0x1 --method 0x2
expect_exit 1 "psid-revert without --force" "$CLI" --sim drive psid-revert --psid PSID123
expect_exit 1 "range setup without --force" "$CLI" --sim -p pw range setup --id 1 --start 0 --len 1000

# ── Author-added commands also register and route ──
#    SimTransport can return EC_TCG_METHOD(3) for operations it doesn't
#    fully model; we accept {0,3} and only fail on parse / crash codes.
"$CLI" --sim -p pw band list >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" ]]; then echo "  OK   band list (exit=$ec)"; PASS=$((PASS+1)); \
    else echo "  FAIL band list (exit=$ec)"; FAIL=$((FAIL+1)); fi

"$CLI" --sim -p pw eval table-get --table 0x0000000B00008402 --col 3 >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" ]]; then echo "  OK   eval table-get (exit=$ec)"; PASS=$((PASS+1)); \
    else echo "  FAIL eval table-get (exit=$ec)"; FAIL=$((FAIL+1)); fi

# ── Usage / parse errors must return EC_USAGE=1 (not CLI11's 105/106) ──
expect_exit 1 "no subcommand"                "$CLI"
expect_exit 1 "missing required --id"        "$CLI" --sim -p pw user assign
expect_exit 1 "invalid --sp value"           "$CLI" --sim -p pw --force drive revert --sp bogus
expect_exit 1 "missing --psid"               "$CLI" --sim --force drive psid-revert
expect_exit 1 "no device and no --sim"       "$CLI" drive discover

# ── Raw-method hex parser ──
expect_exit 1 "raw-method odd-hex"           "$CLI" --sim --force eval raw-method \
    --invoke 0x1 --method 0x2 --payload "0xABC"
expect_exit 1 "raw-method non-hex"           "$CLI" --sim --force eval raw-method \
    --invoke 0x1 --method 0x2 --payload "ZZ"

# ── Password input required where design mandates ──
expect_exit 1 "range list without password"  "$CLI" --sim range list
expect_exit 1 "user list without password"   "$CLI" --sim user list
expect_exit 1 "revert without password"      "$CLI" --sim --force drive revert --sp admin

echo "=="
echo "  pass=$PASS fail=$FAIL"
exit $((FAIL > 0 ? 1 : 0))
