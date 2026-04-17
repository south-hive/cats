# Changelog

All notable changes to libsed (cats) will be documented here. This file is
the public-facing release log — the contributor-facing session-by-session
log lives at [`docs/internal/work_history.md`](docs/internal/work_history.md).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `tools/sed_compare/` — byte-for-byte packet comparison against sedutil-cli
  for 13 commands (Tier 1: query, initialSetup, setSIDPassword, revertTPer,
  revertLockingSP, PSIDrevert; Tier 2: activateLockingSP, setLockingRange,
  enable/disableLockingRange, setupLockingRange, enableUser, setPassword,
  listLockingRanges). 56/56 packets byte-identical on the current main.
- `docs/README.md` — audience-based documentation navigation map.
- Top-level `README.md` and this `CHANGELOG.md`.

### Changed
- Reorganized `docs/` for distribution:
  - `tc_dev_guide.md` → `sed_drive_guide.md` (SedDrive facade users)
  - `developer_guide.md` → `eval_platform_guide.md` (EvalApi evaluation platform)
  - `tcg_sed_lecture.md` → `tcg_sed_primer.md`
  - `examples_guide.md` → `examples.md`
  - `tc_cookbook.md` → `cookbook.md`
- Moved contributor-only docs to `docs/internal/`:
  - `hammurabi_code.md` (immutable encoding rules from past bugs)
  - `work_history.md` (session changelog)
  - `architecture_rationale.md` (transport layer split)
  - `future_api_ideas.md` (planned API enhancements; was top-level `tc_todo.md`)
- `SedDrive::login(const std::string&)` now SHA-256-hashes the password
  host-side, matching the drive's stored hash. `takeOwnership` logs in with
  raw MSID bytes (MSID is already a drive credential, not a user password).
- Anonymous / read-only `StartSession` callers (`getMsid`, `loginAnonymous`,
  `readMsid`, etc.) now send `Write=false`. Authenticated sessions keep
  `Write=true` to match sedutil behavior.
- Rosetta Stone gained §11 (Discovery format), §12 (SM response format),
  §13 (Enterprise method UIDs).
- Consolidated unit-test entrypoints in `tests/test_main.cpp` — dropped the
  ad-hoc minitest framework in favor of per-file `run_*_tests()` functions.

### Fixed
- `MethodCall::buildGet` was wrapping the CellBlock in an extra
  `STARTLIST/ENDLIST` that real Opal drives reject with status 0x0C.
  CellBlock named pairs now go directly into the method parameter list,
  matching sedutil. Confirmed by byte-identity against 13 sedutil-cli
  commands.
- `tests/integration/ioctl_validator.cpp` had the same double-wrap in its
  sedutil reference, so the two buggy encodings agreed with each other.
  Both corrected.
- `Set` method now emits the mandatory empty `Where` clause with the
  closing `ENDNAME`, and all integer tokens use power-of-2 widths
  (no 3-byte/5-byte encodings) to satisfy strict drives.
- `Properties` token wrapping, `StartSession` named-param indices
  (0=HostChallenge, 3=ExchangeAuth, 4=SigningAuth), `MaxSubpackets`
  spelling, and `ComPacket` minimum size (2048 B) all brought in line with
  sedutil so the same drives that accept sedutil also accept libsed.

## [0.1.0] — initial development

Initial `EvalApi` / `SedDrive` design, Opal 2.0 / Enterprise / Pyrite
support, MockTransport + SimTransport for hardware-free testing, 20-example
learning path, 104-scenario test catalog, 17-test `ioctl_validator` wire
conformance suite.
