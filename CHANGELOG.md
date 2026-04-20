# Changelog

All notable changes to libsed (cats) will be documented here. This file is
the public-facing release log — the contributor-facing session-by-session
log lives at [`docs/internal/work_history.md`](docs/internal/work_history.md).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **`tools/cats-cli/`** — TCG SED evaluation & debugging CLI, ship-ready.
  Subcommand tree: `drive discover|msid|revert|psid-revert`,
  `range list|setup|lock|erase`, `band list`, `user list|enable|assign|set-pw`,
  `mbr status|enable|done|write`, `eval tx-start|table-get|raw-method|transaction`.
  All destructive ops gated by `--force` via a common helper. Exit-code
  schema 0–5 (EC_USAGE / EC_TRANSPORT / EC_TCG_METHOD / EC_AUTH / EC_NOT_SUPPORTED).
  Closed-network: CLI11 2.3.2 + nlohmann/json 3.11.3 vendored at
  `third_party/`.
- **`eval transaction <script.json>`** — JSON script runner executing
  multiple ops inside one session (start_transaction / set / get / genkey
  / erase / authenticate / sleep / commit / rollback). Spec at
  `docs/cats_cli_transaction_schema.md`.
- **`--json` output** — machine-readable JSON on stdout for `drive
  discover`, `drive msid`, `range list`, `user list`, `mbr status`, and
  `eval transaction`. Unified `{"command": ..., ...}` envelope.
- **Password input diversification** — `--pw-env VAR`, `--pw-file PATH`,
  `--pw-stdin` in addition to `-p/--password`. Only one of the four may
  be given; violation → EC_USAGE. Prevents literal-password leakage via
  `ps(1)` in CI.
- **`--repeat N` / `--repeat-delay MS`** — re-run a subcommand for
  aging/stress; last failing exit is preserved.
- **`SedDrive::enumerateRanges / enumerateAuthorities / enumerateBands /
  getMbrStatus / revertLockingSP / runRawMethod / getTableColumn`** —
  Phase 0 facade gap closed so the CLI stays thin (no TCG logic in
  callbacks). `SedDrive::AuthorityKind` enum + `AuthorityInfo` now
  carries Admin1-4 alongside User1-8.
- **`docs/cats_cli_guide.md`**, **`docs/cats_cli_transaction_schema.md`** —
  user-facing documentation.
- **`tests/integration/cats_cli_smoke.sh`** — 46-case SimTransport smoke
  (registered in CTest as `cats_cli_smoke`).
- **`band setup --id --start --len` / `band erase --id`** — Enterprise
  SSC band lifecycle on the CLI. Both gated by `--force`. Builds on
  `SedDrive::eraseBand()` (new) and existing `configureBand()`.
- **`eval fault-list`** — read-only enumeration of `FaultBuilder`'s 20
  fault points (text or `--json`). Input catalog for upcoming
  `eval fault-inject`.
- **`tests/unit/test_cats_cli_transaction.cpp`** — 17 parser tests
  (3 positive + 14 negative). Covers paths the smoke shell can't:
  unknown SP/Authority/Object/Column, two password sources, `Anybody`
  with credential, empty `pw_env`, bad `on_error`, malformed JSON.

### Changed
- `SedDrive::configureBand / lockBand / unlockBand` now route via
  `SP_ENTERPRISE` (was `SP_LOCKING`). Aligned with `enumerateBands`.
  SimTransport hid this discrepancy; real Enterprise drives would
  reject the wrong SP UID.
- `cats-cli` is now an installed target (`make install` / `cmake
  --install`). Lands in `${CMAKE_INSTALL_BINDIR}/cats-cli`.
- `DiscoveryInfo` gains `mbrSupported` (LockingFeature flag 0x40) so
  `cats-cli mbr status` can report "supported" without opening a session
  that real drives may refuse to anonymous readers.
- `TokenEncoder::endTransaction(bool commit)` now emits the spec-
  required status byte (`0xFC 0x00` commit / `0xFC 0x01` abort).
  Default argument keeps existing callers at commit.

### Deprecated / Removed
- None.

### Added (earlier pre-Unreleased items)
- `tools/sed_compare/` — byte-for-byte packet comparison against sedutil-cli
  for 17 commands across Tier 1 (ownership/revert), Tier 2 (locking/users),
  and Tier 3 (MBR/DataStore/rekey). 68/68 packets byte-identical on the
  current main; registered in CTest so drift fails the suite.
- `docs/README.md` — audience-based documentation navigation map.
- Top-level `README.md` and this `CHANGELOG.md`.
- Enterprise SSC EGET/ESET/EAUTHENTICATE routing: `Session::setSscType()`
  + method-UID parameterized `MethodCall::build*` + `method::getUidFor /
  setUidFor / authenticateUidFor` helpers. `EnterpriseSession` facade
  tags its sessions automatically.
- **Logging — pluggable flow log with screen + file mirror.**
  `libsed::FileSink` and `libsed::TeeSink` in `core/log.h`, plus a one-call
  helper `libsed::installDefaultFlowLog(path)` that installs a
  `Stderr + File` tee as the global `Logger` sink. TC platforms can still
  replace the sink entirely with `Logger::setSink(theirSink)` as before.
- **Logging — packet log with explicit filename.**
  `SedDrive::enableLogFile(path)` / `enableDumpAndLogFile(path, ...)`,
  `LoggingTransport::wrapToFile(inner, path)`, and
  `LoggerConfig::filePath` expose the previously unreachable explicit-path
  constructor of `CommandLogger`. CLI: `--logfile PATH` (implies `--log`,
  overrides auto-naming) and `--flow-log PATH` (mirrors library flow log
  to both stderr and the given file).
- **Transactions — explicit Start / Commit / Rollback / End primitives.**
  New `EvalApi::startTransaction`, `endTransaction(commit)`,
  `commitTransaction`, `rollbackTransaction` — each returns `RawResult`
  so TC scenarios can observe transport-level (NVMe/ATA/SCSI) and TCG
  method-status errors independently at every boundary. No implicit
  wrapping or auto-commit; the host composes the lifecycle itself and
  inspects results. Backed by `TokenEncoder::endTransaction(bool commit)`
  which emits the spec-required `0xFC <0x00|0x01>` pair, and by a new
  public `Session::sendTokenPayload` primitive. See
  `examples/21_transactions.cpp` and `docs/rosetta_stone.md §14`.

### Changed
- `CommandLogger` file output now always includes the raw hex block under
  each decoded line regardless of `verbosity` — the file is the archive.
  Stream output still respects `verbosity` (0=decoded, 2=decoded+hex), so
  `--dump` / `--dump2` console behavior is unchanged.
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
