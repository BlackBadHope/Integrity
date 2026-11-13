# Claude hook patch series (Windows workstation lineage)

This folder publishes the Claude Code Integrity hook that runs on one Windows workstation as a
base file plus a strict patch series. It is a separate lineage from
`src/integrity_client_memory/resources/claude/admission.py`; the two are not merged here, and
nothing in this folder is installed by the package or by a launcher profile.

| Path | What it is |
| --- | --- |
| `base/integrity-client-admission.py` | the admission hook before the first step |
| `base/integrity_turn_guard.py` | the vendored turn-close guard before its first step |
| `patches/A01..A20-*.diff` | 20 steps of the admission hook, in order |
| `patches/T01..T03-*.diff` | 3 steps of the turn guard, in order |
| `SERIES.json` | order, a neutral label per step, `pre_sha256`/`post_sha256` of every step, CRLF flag, line counts |
| `build_hook.py` | the strict builder |
| `built/` | the full build, committed so the hook can be read without building |
| `make_series.py` | the one-time extraction tool that produced `base/`, `patches/` and `SERIES.json` |
| `helpers/` | two delegation helpers of the same installation that the repository does not ship otherwise |

## Build and verify

```text
python build_hook.py --out <empty folder>
python build_hook.py --out <folder> --upto A08
python build_hook.py --out <folder> --compare-live --live <installed hook folder>
```

- Every diff is applied strictly: exact context, no fuzz, no offset search. A context line that
  does not match stops the build.
- After every step the result (LF, or CRLF where `SERIES.json` records `"crlf": true`) must have
  the recorded `post_sha256`; the base must have the recorded `base_sha256`.
- There is no default output folder and no default installed folder. `--upto` refuses `built/` and
  the `--live` folder as output and adds a `.upto-<TAG>` suffix to its files.
- `--compare-live` reads the installed files read-only and exits 1 when they differ.

The hook and the turn guard are never run by the build or by the tests.

## Line endings

The series depends on exact bytes: the base files and several steps are LF, the last admission
steps and `built/integrity-client-admission.py` are CRLF. `.gitattributes` marks
`components/integrity-client-memory/hook-series/**` as `-text`, so Git stores and checks out
these bytes unchanged on every platform.

## What differs from the installed bytes

The installed files carry private marks of one installation. The same literal substitution was
applied to `base/`, every patch and the built files; afterwards the series was rebuilt and every
sha in `SERIES.json` was recomputed. Each replacement stays inside one line, so the line count of
every file and the added/removed counts of every step are unchanged. Replaced:

- the home path of the account (now `~`) and one `ProgramData` path (now `%ProgramData%`);
- the workstation name, including the MCP server label (now `integrity-local-memory`);
- three session ids in the session-pinned branches of `main()` (now invented
  `00000000-0000-4000-8000-...` ids; those branches are therefore never taken, and their paths are
  placeholders that are not expanded);
- two pinned sha256 values of installed files in those branches (now `000...1` and `000...2`);
- owner quotes, decision numbers, review references, private dates and timestamps in comments,
  docstrings and hook messages (neutral wording in the same language; Russian text was not
  translated).

`built/integrity-client-admission.py` differs from the installed file in 33 lines and
`built/integrity_turn_guard.py` in 5 lines; `base/integrity-client-admission.py` differs from the
installed base in 12 lines. `SERIES.json` holds neutral step labels instead of private paths, event
numbers and dates; two patch file names were neutralised (`A19-keywords-line.diff`,
`T01-tg-to-ISS-011.diff`). One reverted step that was never part of the series is not published.

`build_hook.py` changed against the installed builder: no default installed folder,
`--compare-live` needs `--live DIR`, `--out` is required, and the base sha check raises like the step
check. The strict applier and the per-step sha check are unchanged.

## Not published here

- The installation's generated broker shim (`integrity-client-turn-broker.py`): it pins
  machine-specific dispatcher generations. The shipped brokers are
  `src/integrity_client_memory/resources/windows/integrity-client-turn-broker.py` and
  `src/integrity_client_memory/resources/claude-native/integrity-client-turn-broker.py`.
- The installation's `integrity_scope_synapse.py`: it is
  `src/integrity_client_memory/resources/common/integrity_scope_synapse.py` plus one
  session-pinned branch and one `fsync` after a write.
- The hook's sibling module `integrity_client_turn_envelope.py` is not part of the series; the
  shipped one is `src/integrity_client_memory/resources/common/integrity_client_turn_envelope.py`.
- The installation's update and drift route: it needs the installation's file manifest and
  writes into the installed folder.

## Verified and not verified

Verified by `tests/test_claude_hook_series.py`: a full build in a temporary folder reproduces every
recorded step sha and equals `built/` byte for byte; a changed added line, context line or base
byte is refused; `--upto` never writes into `built/` or the `--live` folder; `--compare-live`
needs `--live`; both built files compile.

Not verified: the published build was not installed or run; the behaviour of the session-pinned
branches with their placeholder paths; `make_series.py` was not rerun in its published form; the
helpers in `helpers/` are published as installed and are not tested here. `base/integrity_turn_guard.py`
keeps the `Apache-2.0` SPDX line of the vendored beta.3 file it was taken from.
