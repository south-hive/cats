# libsed (cats) Documentation

libsed is a C++17 library for TCG SED (Self-Encrypting Drive) evaluation and
control. This folder contains everything you need to learn the library and
the underlying TCG protocol.

---

## Pick your path

Different documents target different readers. Start here:

### I'm a TC application developer — I just want to unlock a drive

You need the high-level facade (`SedDrive`, `SedSession`).

1. [`sed_drive_guide.md`](sed_drive_guide.md) — Quick start with `SedDrive`.
2. [`cookbook.md`](cookbook.md) — Copy-paste recipes for the 11 most common
   tasks (discovery, take ownership, range lock, MBR, DataStore, etc.).
3. [`examples.md`](examples.md) — 20 progressive example programs.
4. If you hit an error code or an auth failure, jump to
   [`examples.md`](examples.md) example 14 (Error Handling).

### I'm new to TCG SED — I need to understand the protocol first

Start from zero. SED, Opal, ComIDs, Sessions — what do any of those mean?

1. [`tcg_sed_primer.md`](tcg_sed_primer.md) — 15-chapter tutorial on the TCG
   SED specification. Each chapter points at a runnable example.
2. [`examples.md`](examples.md) — Run examples 01-06 alongside chapters 1-6
   of the primer.
3. When you want the wire-level truth, open
   [`rosetta_stone.md`](rosetta_stone.md).

### I'm building an evaluation platform — I need wire-level control

You need the low-level `EvalApi` with byte-level inspection and fault
injection.

1. [`eval_platform_guide.md`](eval_platform_guide.md) — Architecture,
   multi-threading rules, NVMe DI pattern, SedContext, fault injection.
2. [`examples.md`](examples.md) — Focus on examples 15 (wire inspection),
   16 (step-by-step EvalApi), 17 (composite patterns), 18 (fault
   injection), 19 (multi-session), 20 (custom transport).
3. [`rosetta_stone.md`](rosetta_stone.md) — Byte-exact encoding for every
   TCG command type.
4. [`test_scenarios.md`](test_scenarios.md) — 104-scenario test catalog
   spanning Levels 1–6 (L1=unit, L5=stress, L6=SSC-specific).

### I'm evaluating / debugging a drive from the shell

[`cats_cli_guide.md`](cats_cli_guide.md) — the `cats-cli` tool with
`<Resource> <Action>` subcommand tree, `--json` output, `--pw-env/file/
stdin` password paths, `--sim` for hardware-free logic checks, `--force`
gating on every destructive op, and `eval transaction <script.json>`
for multi-op scenarios. The evaluator-facing counterpart to `sedutil-cli`.

Transaction script schema: [`cats_cli_transaction_schema.md`](cats_cli_transaction_schema.md).

### I'm verifying compatibility or tracing a wire bug

The tools in [`../tools/`](../tools/) have the byte-level answers.

- `tools/cats-cli/` — full evaluation CLI (see `cats_cli_guide.md`).
- `tools/sed_compare/` — byte-for-byte proof against `sedutil-cli` for
  13 commands (Tier 1+2). Run `./build/tools/sed_compare`.
- `tools/token_dump.cpp` — decode a hex stream into TCG tokens.
- `tools/sed_discover.cpp` — quick one-shot discovery CLI.
- `tools/sed_manage.cpp` — production-style admin CLI (ownership, lock,
  revert, user management).

### I'm contributing to libsed

See [`internal/`](internal/) — those files are for contributors, not library
users.

- [`internal/hammurabi_code.md`](internal/hammurabi_code.md) — 15 immutable
  laws derived from past bugs. Violate none.
- [`internal/architecture_rationale.md`](internal/architecture_rationale.md) —
  Why the transport layer is split between `ITransport` and `INvmeDevice`.
- [`internal/work_history.md`](internal/work_history.md) — Session-by-session
  changelog.

---

## Document map

| Document | Audience | Purpose |
|----------|----------|---------|
| [`sed_drive_guide.md`](sed_drive_guide.md) | TC app developer | Quick start using the `SedDrive` facade |
| [`cookbook.md`](cookbook.md) | TC app developer | 11 copy-paste recipes |
| [`examples.md`](examples.md) | Any reader | Guide to the 20 example programs |
| [`tcg_sed_primer.md`](tcg_sed_primer.md) | SED newcomer | 15-chapter TCG protocol tutorial |
| [`eval_platform_guide.md`](eval_platform_guide.md) | Evaluation engineer | `EvalApi`, threading, NVMe DI, fault injection |
| [`rosetta_stone.md`](rosetta_stone.md) | Wire-level debugger | Byte-exact encoding reference |
| [`test_scenarios.md`](test_scenarios.md) | QA / TC evaluator | 104-scenario test catalog |
| [`internal/hammurabi_code.md`](internal/hammurabi_code.md) | Contributor | Immutable encoding rules from past bugs |
| [`internal/architecture_rationale.md`](internal/architecture_rationale.md) | Contributor | Why transport is split `ITransport` + `INvmeDevice` |
| [`internal/work_history.md`](internal/work_history.md) | Contributor | Session log |

---

## Reading order for self-study

If you're going end-to-end on your own:

1. `tcg_sed_primer.md` chapters 0-3 + run examples 01-04.
2. `sed_drive_guide.md` + run examples 05-08.
3. `cookbook.md` — try the recipes that match your goal.
4. `tcg_sed_primer.md` chapters 4-15 + run examples 09-14.
5. `eval_platform_guide.md` + examples 15-20 — only if you need wire-level
   control.
6. `rosetta_stone.md` — consult when a packet doesn't look right.

The `examples.md` guide also ties every chapter to a runnable program, so
you can flip between "why" (primer) and "how" (example) chapter by chapter.
