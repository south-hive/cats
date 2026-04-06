# Golden Packet Fixtures

Binary packet fixtures captured from real SED hardware via `sedutil-cli -vvvvv`.
These serve as **ground truth** for validating libsed packet encoding.

## Why

libsed and its reference implementation (DtaCommand) share the same TCG spec
interpretation. If both misread the spec identically, they produce matching
but *wrong* packets. Golden fixtures break this circular validation by
comparing against actual packets that a real TPer accepted.

## Capture Procedure

```bash
# 1. Run sedutil-cli with max verbosity on a real device
sudo sedutil-cli -vvvvv --query /dev/nvme0 2>&1 | tee sedutil_query.log

# 2. Extract packets using the capture script
sudo ./scripts/capture_golden.sh /dev/nvme0 tests/fixtures/golden/
```

## File Format

- Each `.bin` file is a **2048-byte** raw ioctl buffer (sedutil `MIN_BUFFER_LENGTH`)
- Layout: `ComPacket(20B) + Packet(24B) + SubPacket(12B) + TokenPayload + zero-padding`
- Big-endian for all multi-byte header fields (TCG Core Spec)

## Naming Convention

```
{Sequence}{Step}_{method}.bin

A = Query Flow (--query)
B = Take Ownership (AppNote 3)
C = Activate Locking SP (AppNote 4)
D = Configure + Lock Range (AppNote 5, 8)
E = PSID Revert (AppNote 13)
```

## Adding New Fixtures

1. Capture from real hardware using `scripts/capture_golden.sh`
2. Add entry to `manifest.json`
3. Commit the `.bin` file
4. `golden_validator` will automatically pick up new fixtures

## Validation

```bash
cmake --build build && ./build/tests/golden_validator
# PASS for fixtures present, SKIP for missing ones
```
