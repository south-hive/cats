#!/bin/bash
# cats-cli smoke test — runs every subcommand against SimTransport and checks
# exit-code expectations. Catches regressions like "force gate missing",
# "parse error returns CLI11 code instead of EC_USAGE", "MBR auth mismatch".
#
# Keep this FAST and INDEPENDENT of real hardware. Anything requiring
# actual drive semantics belongs in tests/scenarios/ instead.

set -u

# Resolve paths against the script's own location so ctest (cwd=build/) and
# hand-invocation (cwd=repo root) both find the fixtures.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures"

CLI="${1:-$REPO_ROOT/build/tools/cats-cli}"
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

# ── JSON output ──
"$CLI" --sim --json drive discover 2>/dev/null | grep -q '"command"' && {
    echo "  OK   drive discover --json has 'command' key"; PASS=$((PASS+1));
} || { echo "  FAIL drive discover --json missing 'command'"; FAIL=$((FAIL+1)); }

"$CLI" --sim --json drive msid 2>/dev/null | grep -q '"msid_hex"' && {
    echo "  OK   drive msid --json has 'msid_hex'"; PASS=$((PASS+1));
} || { echo "  FAIL drive msid --json missing 'msid_hex'"; FAIL=$((FAIL+1)); }

"$CLI" --sim --json mbr status 2>/dev/null | grep -q '"supported"' && {
    echo "  OK   mbr status --json has 'supported'"; PASS=$((PASS+1));
} || { echo "  FAIL mbr status --json missing 'supported'"; FAIL=$((FAIL+1)); }

# ── Password input paths ──
echo "test_pw" > /tmp/cats_smoke_pw.txt
expect_exit 0 "pw-file routes correctly (drive discover needs no pw)"  \
    "$CLI" --sim --pw-file /tmp/cats_smoke_pw.txt drive discover

TC_CATS_SMOKE_PW=envpw "$CLI" --sim --pw-env TC_CATS_SMOKE_PW drive discover >/dev/null 2>&1
if [[ $? == 0 ]]; then echo "  OK   pw-env routes"; PASS=$((PASS+1)); \
    else echo "  FAIL pw-env"; FAIL=$((FAIL+1)); fi

expect_exit 1 "two pw sources rejected" \
    "$CLI" --sim -p pw --pw-env TC_CATS_SMOKE_PW drive discover
expect_exit 1 "pw-env unset var rejected" \
    "$CLI" --sim --pw-env UNSET_VAR_XYZABC drive discover

rm -f /tmp/cats_smoke_pw.txt

# ── eval transaction runner ──
expect_exit 0 "eval transaction anonymous read" \
    "$CLI" --sim eval transaction --script "$FIXTURES/tx_sample_read.json"
expect_exit 1 "eval transaction missing script" \
    "$CLI" --sim eval transaction

# ── --repeat N ──
OUT=$("$CLI" --sim --repeat 3 drive discover 2>/dev/null | grep -c "SSC")
if [[ "$OUT" == "3" ]]; then echo "  OK   --repeat 3 runs command thrice"; PASS=$((PASS+1)); \
    else echo "  FAIL --repeat 3 (got $OUT executions)"; FAIL=$((FAIL+1)); fi

# ── New subcommands parse/register ──
"$CLI" --sim -p pw range lock --id 1 --read on --write off >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" || "$ec" == "4" ]]; then
    echo "  OK   range lock parses (exit=$ec)"; PASS=$((PASS+1));
else echo "  FAIL range lock (exit=$ec)"; FAIL=$((FAIL+1)); fi

"$CLI" --sim -p pw user enable --id 1 >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" || "$ec" == "4" ]]; then
    echo "  OK   user enable parses (exit=$ec)"; PASS=$((PASS+1));
else echo "  FAIL user enable (exit=$ec)"; FAIL=$((FAIL+1)); fi

"$CLI" --sim -p pw user set-pw --id 1 --new-pw newpw >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" || "$ec" == "4" ]]; then
    echo "  OK   user set-pw parses (exit=$ec)"; PASS=$((PASS+1));
else echo "  FAIL user set-pw (exit=$ec)"; FAIL=$((FAIL+1)); fi

expect_exit 1 "mbr enable without --force"   "$CLI" --sim -p pw mbr enable --state on
"$CLI" --sim -p pw mbr done --state on >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" || "$ec" == "4" ]]; then
    echo "  OK   mbr done parses (exit=$ec)"; PASS=$((PASS+1));
else echo "  FAIL mbr done (exit=$ec)"; FAIL=$((FAIL+1)); fi

# ── Password input required where design mandates ──
expect_exit 1 "range list without password"  "$CLI" --sim range list
expect_exit 1 "user list without password"   "$CLI" --sim user list
expect_exit 1 "revert without password"      "$CLI" --sim --force drive revert --sp admin

# ── band setup / erase force gates ──
expect_exit 1 "band setup without --force"   "$CLI" --sim -p pw band setup --id 0 --start 0 --len 1024
expect_exit 1 "band erase without --force"   "$CLI" --sim -p pw band erase --id 0

"$CLI" --sim -p pw --force band setup --id 0 --start 0 --len 1024 >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" || "$ec" == "4" ]]; then
    echo "  OK   band setup parses (exit=$ec)"; PASS=$((PASS+1));
else echo "  FAIL band setup (exit=$ec)"; FAIL=$((FAIL+1)); fi

"$CLI" --sim -p pw --force band erase --id 0 >/dev/null 2>&1; ec=$?
if [[ "$ec" == "0" || "$ec" == "3" || "$ec" == "4" ]]; then
    echo "  OK   band erase parses (exit=$ec)"; PASS=$((PASS+1));
else echo "  FAIL band erase (exit=$ec)"; FAIL=$((FAIL+1)); fi

# ── eval fault-list (read-only, no device) ──
expect_exit 0 "eval fault-list"              "$CLI" eval fault-list
OUT=$("$CLI" eval fault-list 2>/dev/null | wc -l)
if [[ "$OUT" -ge "10" ]]; then echo "  OK   eval fault-list non-empty ($OUT lines)"; PASS=$((PASS+1)); \
    else echo "  FAIL eval fault-list only $OUT lines"; FAIL=$((FAIL+1)); fi

"$CLI" --json eval fault-list 2>/dev/null | grep -q '"points"' && {
    echo "  OK   eval fault-list --json has 'points' array"; PASS=$((PASS+1));
} || { echo "  FAIL eval fault-list --json missing 'points'"; FAIL=$((FAIL+1)); }

echo "=="
echo "  pass=$PASS fail=$FAIL"
exit $((FAIL > 0 ? 1 : 0))
