#!/bin/bash
# capture_golden.sh — Capture golden packet fixtures from real hardware.
#
# Runs sedutil-cli -vvvvv --query on the specified device, parses the
# "Sent Command Buffer:" hex dumps, and saves each as a 2048-byte .bin file.
#
# Usage:
#   sudo ./scripts/capture_golden.sh <device> [output_dir]
#
# Example:
#   sudo ./scripts/capture_golden.sh /dev/nvme0 tests/fixtures/golden/
#
# Prerequisites:
#   - sedutil-cli in PATH (or specify SEDUTIL_CLI env var)
#   - xxd (usually in vim package)
#   - Root/sudo for NVMe ioctl access

set -euo pipefail

DEVICE="${1:?Usage: $0 <device> [output_dir]}"
OUTDIR="${2:-tests/fixtures/golden}"
SEDUTIL="${SEDUTIL_CLI:-sedutil-cli}"

# Verify prerequisites
command -v "$SEDUTIL" >/dev/null 2>&1 || { echo "ERROR: $SEDUTIL not found"; exit 1; }
command -v xxd >/dev/null 2>&1 || { echo "ERROR: xxd not found (install vim)"; exit 1; }
[ -b "$DEVICE" ] || { echo "ERROR: $DEVICE is not a block device"; exit 1; }

mkdir -p "$OUTDIR"

echo "Capturing golden packets from $DEVICE"
echo "Output: $OUTDIR"
echo ""

# Run sedutil-cli with max verbosity and capture stderr+stdout
TMPLOG=$(mktemp)
trap 'rm -f "$TMPLOG"' EXIT

"$SEDUTIL" -vvvvv --query "$DEVICE" > "$TMPLOG" 2>&1 || true

echo "sedutil-cli output captured ($(wc -l < "$TMPLOG") lines)"
echo ""

# Parse "Sent Command Buffer:" blocks
# Each block starts with "Sent Command Buffer:" and contains hex lines like:
#   0000  00000000 10040000 00000000 00000000
#   0010  000000b0 ...
#
# We extract these blocks sequentially. The --query flow produces 4 send packets:
#   1. Properties
#   2. StartSession (anonymous to AdminSP)
#   3. Get (C_PIN_MSID)
#   4. CloseSession

NAMES=("A1_properties" "A2_start_session" "A3_get_msid" "A4_close_session")
DESCS=("Properties" "StartSession(anon)" "Get(MSID)" "CloseSession")

# Extract hex blocks after "Sent Command Buffer:"
PACKET_NUM=0
IN_BLOCK=0
HEXDATA=""

while IFS= read -r line; do
    if [[ "$line" == *"Sent Command Buffer:"* ]]; then
        # Save previous block if any
        if [ -n "$HEXDATA" ] && [ $PACKET_NUM -lt ${#NAMES[@]} ]; then
            BINFILE="$OUTDIR/${NAMES[$PACKET_NUM]}.bin"
            echo "$HEXDATA" | xxd -r -p > "$BINFILE"
            # Pad to 2048 bytes
            FSIZE=$(stat -f%z "$BINFILE" 2>/dev/null || stat -c%s "$BINFILE" 2>/dev/null)
            if [ "$FSIZE" -lt 2048 ]; then
                dd if=/dev/zero bs=1 count=$((2048 - FSIZE)) >> "$BINFILE" 2>/dev/null
            fi
            echo "  [${NAMES[$PACKET_NUM]}] ${DESCS[$PACKET_NUM]} → $BINFILE ($(stat -f%z "$BINFILE" 2>/dev/null || stat -c%s "$BINFILE" 2>/dev/null) bytes)"
            PACKET_NUM=$((PACKET_NUM + 1))
        fi
        IN_BLOCK=1
        HEXDATA=""
        continue
    fi

    if [ $IN_BLOCK -eq 1 ]; then
        # Hex lines start with 4-digit offset: "0000  ..."
        if [[ "$line" =~ ^[0-9a-fA-F]{4}\  ]]; then
            # Strip offset prefix, remove spaces, keep hex digits only
            HEX=$(echo "$line" | sed 's/^[0-9a-fA-F]*  //' | tr -d ' \t')
            HEXDATA="${HEXDATA}${HEX}"
        else
            # Non-hex line ends the block
            IN_BLOCK=0
        fi
    fi
done < "$TMPLOG"

# Save last block
if [ -n "$HEXDATA" ] && [ $PACKET_NUM -lt ${#NAMES[@]} ]; then
    BINFILE="$OUTDIR/${NAMES[$PACKET_NUM]}.bin"
    echo "$HEXDATA" | xxd -r -p > "$BINFILE"
    FSIZE=$(stat -f%z "$BINFILE" 2>/dev/null || stat -c%s "$BINFILE" 2>/dev/null)
    if [ "$FSIZE" -lt 2048 ]; then
        dd if=/dev/zero bs=1 count=$((2048 - FSIZE)) >> "$BINFILE" 2>/dev/null
    fi
    echo "  [${NAMES[$PACKET_NUM]}] ${DESCS[$PACKET_NUM]} → $BINFILE ($(stat -f%z "$BINFILE" 2>/dev/null || stat -c%s "$BINFILE" 2>/dev/null) bytes)"
    PACKET_NUM=$((PACKET_NUM + 1))
fi

echo ""
echo "Captured $PACKET_NUM / ${#NAMES[@]} packets"

if [ $PACKET_NUM -eq 0 ]; then
    echo ""
    echo "WARNING: No packets captured. Check:"
    echo "  1. sedutil-cli version supports -vvvvv verbosity"
    echo "  2. Device $DEVICE is a TCG SED"
    echo "  3. Running as root/sudo"
    echo ""
    echo "Raw log saved at: $TMPLOG"
    trap - EXIT  # Don't delete log on failure
    exit 1
fi

# Update manifest.json capture metadata
MANIFEST="$OUTDIR/manifest.json"
if [ -f "$MANIFEST" ]; then
    SEDVER=$("$SEDUTIL" --version 2>&1 | head -1 || echo "unknown")
    TODAY=$(date +%Y-%m-%d)
    # Simple sed-based update (no jq dependency)
    sed -i "s/\"capture_date\": null/\"capture_date\": \"$TODAY\"/" "$MANIFEST"
    sed -i "s/\"device\": null/\"device\": \"$DEVICE\"/" "$MANIFEST"
    sed -i "s/\"sedutil_version\": null/\"sedutil_version\": \"$SEDVER\"/" "$MANIFEST"
    echo "Updated $MANIFEST with capture metadata"
fi

echo ""
echo "Next steps:"
echo "  git add $OUTDIR/*.bin"
echo "  cmake --build build && ./build/tests/golden_validator"
