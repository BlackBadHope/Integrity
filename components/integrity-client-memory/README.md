# integrity-client-memory

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

The client side of Integrity memory: lifecycle hooks, MCP brokers and profile generators that
connect Codex, Claude Code and Antigravity to an Integrity memory server, plus the
`integrity-doctor` diagnostic. Use it on the machine where the agent runs.

## Status

- Version `1.13.1`, stable. It ships with the Guardian 7.0.0 source release (tag `v7.0.1`) and
  targets the memory MCP facade API 2.11.0.
- Python 3.11 or newer.
- Depends on `integrity-guardian>=7.0.0,<8` and `integrity-action-log>=2.10.0,<3`.
  Extras: `native` (`websockets>=13,<16`) and `dev` (`pytest>=8.2,<10`).
- Optional, and off until you configure it. Importing the package starts no process, opens no
  database and connects to no host. Nothing is installed into a client until you copy a
  generated profile into place.

## What it does

**Hook and broker resources.** The package ships the scripts that a client runs: admission
hooks, turn brokers and turn-envelope helpers for Windows, Windows remote, Linux, Claude
Code, Claude Code Native and Antigravity, plus scope-capture wrappers (`scope.sh`,
`scope.ps1`) and a generation launcher. `integrity-client-memory --list` prints their names.
`integrity-client-memory` starts one of them in a fresh Python (or `pwsh` for `.ps1`) process,
after it has read a valid configuration file.

**Native profiles.** `integrity-native-profile` builds a complete, isolated profile for one
vendor (`codex`, `claude` or `antigravity`) in a new output directory: MCP registration, hook
files and a `profile.json` with source pins. It never edits active client settings. It prints
where the generated hook file is and its scope (project folder for Codex and Claude, user
plugin for Antigravity). `python -m integrity_client_memory.native_runtime --profile
profile.json verify|probe|mcp|hook` runs a generated profile: `verify` checks source and
configuration bytes, `probe` imports the real entry points without calling a model. See the
[native onboarding guide](../../docs/native-onboarding.md) and
[Linux native clients](../../docs/linux-native-clients.md).

**Turn-close guard** (`turn_guard.py`, shared by the hooks):

- A top-level `Stop` after a turn that changed state (file edits, any shell tool, MCP tools
  that write, `integrity_append_event`) without an observed `integrity_turn_memory_close`
  returns a block decision once per turn. After that one block, or under
  `stop_hook_active`, the turn ends and the gap is recorded. Notifications and
  `SubagentStop` are exempt.
- Modes are `block`, `advise` and `off`. Precedence: `INTEGRITY_TURN_CLOSE_ENFORCEMENT`, then
  `turn-guard.json`, then the launcher default (`block` for processes started by
  `integrity-client-memory`), then `advise`. Invalid values fall back to `advise`.
- An optional admission-first gate (`--admission-first block`) denies other tools until the
  turn's admission call was attempted. It opens after two denials, and when the broker or
  the last probe failed. `ToolSearch` and Integrity tools are always allowed.
- After two owner turns without admission, the prompt hook shows one notice:
  `INTEGRITY ADMISSION SKIPPED` (memory answered in this session),
  `INTEGRITY MEMORY UNREACHABLE` (a broker start failed, or a fresh probe was refused twice),
  or `INTEGRITY ADMISSION NOT CALLED` (otherwise). A probe timeout counts as inconclusive,
  not as unreachable.
- A diagnostic log, `turn-guard-log.jsonl`, keeps the last 500 turns without prompt text.

**`integrity-doctor`** is read-only. It lists Integrity hooks by vendor and scope and the MCP
registrations, starts each referenced transport once for `initialize` and `tools/list`, makes
one read-only `integrity_turn_memory_coverage` call, and summarizes the turn log. It exits 1
when it has findings. See [hooks troubleshooting](../../docs/hooks-troubleshooting.md).

**Profile compilers.**

- `python -m integrity_client_memory.profile --tools-json TOOLS.json --output NEW_DIR`
  validates a `tools/list` catalogue from your server (descriptions, schemas and annotations
  must be present, plus the admission and lifecycle tools), writes it with its SHA-256 and the
  source pins, and leaves identity, upstream and project scope unset. It refuses an existing
  directory. The bundled catalogue `data/tools-current.json` is the memory API 2.11.0 surface.
- `python -m integrity_client_memory.broker_bundle --output NEW_DIR --bindings-json B.json
  --upstream-json U.json --tools-json T.json` compiles an isolated Windows Codex broker
  profile with `run-native-profile.py`. The optional `--deployment-root`, `--state-root`
  and `--envelope-root` are described in [docs/COHORT_ROOTS.md](docs/COHORT_ROOTS.md).
- `generation_navigation.render_config()` is a pure function that adds a generation
  navigation field to a caller-owned config. It performs no I/O.

**Recovery modules.** `recovery_client.py`, `operation_ledger.py` and `broker_adapter.py`
retain an already admitted request so the broker can deliver it again after a transport
fault. A lost response stays unknown; a missing local record is not proof that the server did
not commit.

**Claude hook patch series.** [hook-series/claude-windows/](hook-series/claude-windows/README.md)
holds a second Claude Code hook lineage as a base file, 23 strict patches, a builder and
the full build. The package does not install it, and no launcher profile uses it.
`tests/test_claude_hook_series.py` rebuilds it and compares every step sha and the result
with `built/`.

## Install

Install from source together with Guardian and the Action Log; see
[docs/INSTALL.md](../../docs/INSTALL.md) and [BOOTSTRAP.md](../../BOOTSTRAP.md):

```bash
python -m pip install . ./components/integrity-action-log ./components/integrity-client-memory
```

## Use

```bash
integrity-client-memory --list
integrity-client-memory --config /abs/path/config.json --preflight
integrity-client-memory --config /abs/path/config.json ENTRYPOINT [ARGS...]

integrity-native-profile --vendor codex --upstream-json U.json --bindings-json B.json \
  --output NEW_DIR [--tools-json T.json] [--turn-guard block|advise|off] \
  [--admission-first block|off]

integrity-doctor [--project DIR] [--transport FILE] [--state-root DIR] [--last N] \
  [--no-probe] [--no-coverage] [--json]
```

`--preflight` checks only the configuration header and reports
`runtime_bindings_verified: false`. `integrity-native-profile` prints JSON that includes
`"live_acceptance": "NOT_RUN"`; its `--admission-first` default is `block` for `claude` and
`off` for `codex` and `antigravity`. The launcher and the profile generator exit 2 on a
rejected input. Scope wrappers
need the harness named explicitly: `scope.sh EVENT codex` or
`scope.ps1 -Event EVENT -Harness claude`.

## Configuration

The launcher reads one JSON file, given by `--config` or `INTEGRITY_CLIENT_MEMORY_CONFIG`. It
must be an absolute regular file of at most 1 MiB. Start from
[configuration.example.json](configuration.example.json), which is disabled on purpose.
[CONFIGURATION-VALUES.json](CONFIGURATION-VALUES.json) lists which source locations need a
value. There are no defaults.

| Field | Required value |
| --- | --- |
| `schema` | `integrity/component-config/v1` |
| `component` | `integrity-client-memory` |
| `configured` | `true` |
| `guardian_version` | `6.1.0` (the value the code checks; see Limits) |
| `memory_api_version` | `2.11.0` |
| `values` | Your paths, commands and pins |

Environment variables read by the code:

| Variable | Purpose |
| --- | --- |
| `INTEGRITY_CLIENT_MEMORY_CONFIG` | Path of the configuration file |
| `INTEGRITY_TURN_CLOSE_ENFORCEMENT` | Turn-close guard mode: `block`, `advise` or `off` |
| `INTEGRITY_TURN_GUARD_CONFIG` | Path of `turn-guard.json`; its folder also holds the turn log |
| `INTEGRITY_TURN_GUARD_DEFAULT` | Launcher default mode; set to `block` by `integrity-client-memory` |
| `INTEGRITY_ADMISSION_FIRST` | Admission-first gate: `block` or `off` |
| `INTEGRITY_DOCTOR_HOME`, `CODEX_HOME` | Where `integrity-doctor` looks for client settings |

Optional, Claude standalone hook (`resources/claude/admission.py`) only: set
`values.event_summary_keywords_line` to an object such as
`{"label": "Keywords:", "min_items": 5, "max_items": 8}` to have the hook check that every
event summary ends with a keywords line. Add `"script": "cyrillic"` (or `"latin"`) and
`"min_script_share": 0.5` to require that share of items to contain letters of that script.
The check is advisory: an append is never refused. A missing or malformed line gives the
model a warning, and counts go to `keywords-line-health.json` next to the hook state. Without
this value, or with an invalid one, the check is off. The other hooks do not read it.

Keep credentials in your own credential store, not in the configuration file.

## What is verified

- Public CI runs the tests in `tests/` on Ubuntu and Windows with Python 3.11 and 3.12. They
  use synthetic state, fake IPC and stand-in peers; none calls a vendor or a model. They cover:
  - configuration admission, preflight without a process, and the resource catalogue;
  - the turn-close guard, status notices, admission-first gate and `integrity-doctor`;
  - the opt-in keywords-line advisory of the Claude standalone hook;
  - Native profile generation and real entry-point imports, owner policy and receipts;
  - broker turn registration, transport startup gate, recovery bundle and operation ledger;
  - Linux user-custody Native heads (Linux only) and Linux lifecycle regressions;
  - Windows weekly profiles, scope wrappers and replay of observed hook payloads;
  - UTF-8 BOM input, response size limits and frozen source integrity.
- Some tests run on one platform only and skip on the other. The reviewed skips are listed in
  [expected test skips](../../docs/expected-test-skips.md).
- An informational macOS job also runs these tests, with known failures.

For use in real clients, see
[What is verified](../../docs/STATUS.md#windows-desktop-claude-code-codex-antigravity).

## What is not verified

- The tests do not install hooks into a real client or call a model. A new installation
  needs its own lifecycle check.
- `--preflight` does not check runtime bindings.
- Live acceptance with a model on a fresh install is not published for any vendor.
- The hook patch series in `hook-series/claude-windows/` was not installed or run in its
  published form; its README lists what was changed against the installed bytes.

## Limits

- Hooks are project-scoped unless you merge them into user settings by hand.
- The Linux user-custody guard only advises.
- The configuration check expects `guardian_version` `6.1.0` in the file header, although
  the package requires Guardian 7.0.0 or newer. Use the value the code checks.
- Native Claude Code profiles on Windows need an enrolled session; see the
  [native onboarding guide](../../docs/native-onboarding.md).
- No memory data, keys, enrollments or deployment pins are included.

## License

Business Source License 1.1 from v7.0.0-beta.4 (earlier releases Apache-2.0); see
[LICENSE](LICENSE) and [NOTICE](NOTICE). No user memory, event corpus, enrollment, private
keys, service configuration, retained session state or live deployment pins are included.

Per-version changes are in the project [CHANGELOG.md](../../CHANGELOG.md).
