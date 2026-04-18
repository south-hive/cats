# libsed (cats)

A C++17 library for **TCG SED (Self-Encrypting Drive)** evaluation and
control. Provides a flat, step-by-step `EvalApi` with 120+ methods for
testing individual TCG protocol steps in isolation, plus a high-level
`SedDrive` facade for everyday application code. Supports Opal 2.0,
Enterprise, and Pyrite SSCs over NVMe, ATA, and SCSI transports.

```cpp
#include <cats.h>
using namespace libsed;

int main() {
    SedDrive drive("/dev/nvme0");
    if (drive.query().failed()) return 1;

    printf("SSC: %s  ComID: 0x%04X\n", drive.sscName(), drive.comId());

    if (drive.takeOwnership("my-password").ok()) {
        drive.activateLocking("my-password");
    }
}
```

## Highlights

- **Two API layers.** `SedDrive` for quick application code; `EvalApi`
  when you need byte-level control, fault injection, or multi-threaded
  evaluation.
- **`cats-cli` evaluation CLI** — `<Resource> <Action>` subcommand tree
  (`drive discover/msid/revert`, `range list/setup/lock/erase`, `user
  list/enable/assign/set-pw`, `mbr status/enable/write`, `eval tx-start/
  table-get/raw-method/transaction`) with `--json` output, `--pw-env /
  file / stdin` password paths, `--sim` routing, `--force` on every
  destructive op, `--repeat N` for aging, and a JSON script runner for
  multi-op scenarios. Targets firmware engineers / QA / security
  evaluators. See [`docs/cats_cli_guide.md`](docs/cats_cli_guide.md).
- **Byte-identical to sedutil-cli.** The `sed_compare` tool proves 68/68
  packets byte-identical against sedutil-cli for 17 commands across
  Tier 1 (ownership/revert), Tier 2 (locking/users), and Tier 3 (MBR/
  DataStore/rekey).
- **Transport-agnostic.** `NvmeTransport`, `AtaTransport`, `ScsiTransport`,
  plus `SimTransport` for hardware-free testing.
- **104 scenario tests + 39-case cats-cli smoke** covering L1 unit → L6
  SSC-specific behavior, and 17 wire-level `ioctl_validator` tests
  pinning sedutil compatibility.
- **21 example programs** that form a beginner-to-expert learning path
  paired chapter-by-chapter with a TCG SED protocol primer.

## Requirements

- C++17 compiler (g++ 9+, clang 10+)
- CMake 3.20+
- Linux (primary), no external dependencies for the core library
- Optional: Google Test (auto-detected; the repo includes a standalone
  runner if GTest isn't present)

## Build

```bash
cmake -B build -DLIBSED_BUILD_TESTS=ON \
               -DLIBSED_BUILD_EXAMPLES=ON \
               -DLIBSED_BUILD_TOOLS=ON
cmake --build build

# Run all tests
cd build && ctest
```

### CMake options

| Option | Default | Description |
|--------|---------|-------------|
| `LIBSED_BUILD_TESTS` | ON | Unit + scenario + integration tests |
| `LIBSED_BUILD_EXAMPLES` | ON | 20 example programs in `examples/` |
| `LIBSED_BUILD_TOOLS` | ON | CLI tools (`cats-cli`, `sed_discover`, `sed_manage`, `token_dump`, `sed_compare`) |
| `LIBSED_BUILD_SHARED` | OFF | Shared (ON) vs static (OFF) library |

## Install

```bash
cmake --install build --prefix /usr/local
```

Then in a downstream project:

```cmake
find_package(libsed REQUIRED)
target_link_libraries(your_app PRIVATE libsed::libsed)
```

## Repository layout

```
include/libsed/      Public headers
  cats.h             Single include (recommended)
  sed_library.h      Module bundle
  eval/              EvalApi (low-level step-by-step)
  facade/            SedDrive (high-level)
  transport/         ITransport + NVMe/ATA/SCSI/SimTransport
  codec/ packet/     TCG token + packet encoding
  ssc/               Opal / Enterprise / Pyrite convenience layers
src/                 Implementation
examples/            01-20 progressive learning examples
tools/               cats-cli, sed_discover, sed_manage, token_dump, sed_compare
tests/               Unit, scenario, integration, mock/simulator transports
docs/                Documentation — start at docs/README.md
third_party/sedutil/ Subset of sedutil-cli sources used by sed_compare
                     and ioctl_validator for wire-level comparison
```

## Documentation

Start at **[`docs/README.md`](docs/README.md)** — it routes readers by
audience:

- **TC application developer** → [`docs/sed_drive_guide.md`](docs/sed_drive_guide.md)
  + [`docs/cookbook.md`](docs/cookbook.md)
- **SED newcomer** → [`docs/tcg_sed_primer.md`](docs/tcg_sed_primer.md)
  (15-chapter protocol tutorial paired with examples 01-20)
- **Evaluation platform engineer** → [`docs/eval_platform_guide.md`](docs/eval_platform_guide.md)
  + [`docs/rosetta_stone.md`](docs/rosetta_stone.md)

## Testing

```bash
cd build
ctest                    # All registered test suites
./tools/sed_compare      # Byte-identity proof against sedutil-cli
./tests/ioctl_validator  # 17-test sedutil wire-format conformance
./tests/scenario_tests   # 104 protocol scenarios on MockTransport + SimTransport
```

## License

Proprietary — internal use only. See [`LICENSE`](LICENSE). External
distribution, publication, or third-party disclosure is not permitted
without prior written consent from the copyright holder.

## Status

Version 0.1.0 — early development. See [`CHANGELOG.md`](CHANGELOG.md) for
release history and [`docs/internal/future_api_ideas.md`](docs/internal/future_api_ideas.md)
for planned work.
