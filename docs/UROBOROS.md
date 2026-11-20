# Uroboros: procedural memory

[Documentation](README.md) · [Project README](../README.md)

Uroboros lets an agent reuse a path that already worked instead of
rediscovering it. A completed, verified piece of work becomes a **route**. When
a later agent starts a turn whose intent matches that route, Integrity offers
it in the admission capsule. A route is guidance to check against current
state. It is never permission to act.

## What ships

| Piece | Status | Where |
|---|---|---|
| Known routes at admission | **in source, unreleased** (Action Log) | `uroboros_routes.py`; Action Log `/api/mind` |
| Route record format `uroboros-route/v1` | **in source, unreleased** | this page |
| Signed route-memory protocol (Toolzs a1–a14) | alpha library with public tests, no caller yet | `src/integrity_guardian/uroboros_toolzs_*`, `tests/test_uroboros_toolzs_*` |
| Route record validation, secret guard, `draft`/`validate` CLI | **in source, unreleased** | `python -m integrity_guardian.uroboros_routes` |
| Route checks (`uroboros-route-check/v1`) and repair by new version | **in source, unreleased** | `check` CLI; retrieval |
| Example route catalogue and contribution rules | **in source** | [`examples/uroboros-routes`](../examples/uroboros-routes/README.md) |
| Event triggers (`uroboros-event-trigger/v1`) and the runbook dispatcher, off by default | **in source, unreleased** (alpha, CI) | `integrity-guards runbooks`; [`examples/runbook-triggers`](../examples/runbook-triggers/README.md) |
| Signed, cursor-pinned Toolzs library for external contributions | roadmap | — |

### Known routes at admission

On every `/api/mind` projection, the Action Log does the following:

1. It derives search terms from the owner's prompt with the same
   wrapper-stripping as auxiliary recall. Harness metadata such as
   `<system-reminder>` blocks, bus notices and attachment carriers is not used
   for search.
2. It selects at most three routes from the admitted Seed snapshot.
3. When the capsule door is `admitted`, it adds them to the capsule's
   `learned_hints`.

Each hint ends with the one call that returns the whole route, for example
`steps: read_events after_id=8818`. The capsule text also carries a
`KNOWN ROUTES` block, right after the lead, with up to three runnable steps
per route.

Every client therefore gets the routes with no client change: Claude, Codex,
Windows, Linux and cloud seats all read the same capsule. A closed door
(undeclared or expired session) projects the routes for custody but never
speaks them.

The hint line looks like this:

```text
ROUTE #8706 verified gpon-migration-vlan v3 2026-11-01: Move a subscriber to GPON… [re-check; not authority]
```

The structured projection is `known_routes` in the Mind response. It is
covered by the projection digest. It has the protocol
`integrity-guardian/uroboros-known-routes/v1`, `authority: "none"` and
`production_authority: false`.

## Where routes come from

**Explicit routes.** An agent appends an ordinary Seed event (for example
with `integrity_append_event`) whose details carry `uroboros_route`:

```json
{
  "uroboros_route": {
    "format": "uroboros-route/v1",
    "route_id": "gpon-migration-vlan",
    "version": 3,
    "status": "verified",
    "title": "Move a subscriber to GPON: current VLAN, PON, uplink, ONU profile, free IP",
    "triggers": ["gpon", "onu", "vlan", "subscriber"],
    "preconditions": ["subscriber identity binding is known"],
    "steps": ["read current VLAN/IP", "verify VLAN on the PON", "verify uplink tagging"],
    "postchecks": ["ONU online, DHCP lease in the expected VLAN"],
    "rollback": "read-only route; apply steps need their own owner GO",
    "verified_at": "2026-11-01T00:00:00Z",
    "provenance_event_ids": [7881]
  }
}
```

Field rules:

- **`status`** is one of `candidate`, `verified`, `stale` or `superseded`.
- **Versions.** A newer `version` of the same `route_id` replaces the older
  one. History is append-only and nothing is edited.
- **`superseded`** routes are never offered.
- **`stale`** routes are offered with a *verify first* label.

**Route bundles.** One event may carry `uroboros_routes`: a list of up to 32
records in the same format. This lets a runbook catalogue be registered in a
single append. Each route keeps its own `route_id` and version.

**Observed routes.** No migration is needed: each Seed already holds routes.
Any agent-log close with `truth_status: verified` and `result: done` counts as
an observed route, and so does any event tagged `uroboros-route`. The route
carries the event's commands, verification and rollback fields. These routes
rank below explicitly verified ones.

## Recording a route

At the end of a turn whose work is reusable, draft the route and append it as
an ordinary Seed event:

```bash
python -m integrity_guardian.uroboros_routes draft   --route-id gpon-migration-vlan --version 3 --status verified   --title "Move a subscriber to GPON: current VLAN, PON, uplink, ONU profile"   --trigger gpon --trigger onu --trigger vlan   --step "read current VLAN/IP" --step "verify VLAN on the PON"   --rollback "read-only route" --provenance 7881
```

The command prints `{"uroboros_route": {...}}` for the event's details.
`validate FILE` checks a record, a list or a details object before an append.

Both commands reject malformed records. They also reject secret-like text:
passwords, tokens, API keys and private keys. A route should name the secret
store, not carry a secret. The error names only the field, never the value.

Retrieval applies the same guard. A route with secret-like text is never
offered, and the projection counts it in `rejected_secret_like`.

**Choosing a status:**
- `candidate`: done once, not yet re-checked.
- `verified`: worked and was checked against state.
- `stale`: known to be out of date.
- `superseded`: replaced by a newer version.

A new `version` of the same `route_id` replaces the old one.

## Checking and repairing a route

A route can go stale. Check it read-only against the current state, then
record the result:

```bash
python -m integrity_guardian.uroboros_routes check   --route-id gpon-migration-vlan --version 3 --result fail   --note "uplink no longer carries the VLAN"
```

Append the printed `{"uroboros_route_check": ...}` as event details. Retrieval
uses the newest check for that route and version:

- **`pass`** turns a `candidate` or `stale` route into `verified` and sets the
  verification date.
- **`fail`** marks the route `stale`. Its hint says
  `check failed <date>: repair, then new version`.

**Repair** means appending the corrected route as the next `version`. It
supersedes the old one, and the failed check no longer applies.

## Event-triggered turns

An infrastructure event can start a turn that follows a compiled route. The
runbook dispatcher in [`integrity-guards`](../components/integrity-guards/README.md#event-driven-runbooks)
does this. It is off by default: nothing runs until you create an instance
and set `"enabled": true` in its configuration.

A **trigger** (`uroboros-event-trigger/v1`) names:

- a source: a log file (`file`), `journald` (Linux), a `syslog` datagram on a
  loopback UDP port, a `webhook` on a loopback HTTP port, or a `timer`;
- a regular expression, `match`;
- the `route_id` of a compiled route (`uroboros-compiled-route/v1`, unchanged);
- how the route parameters come from the named groups of the match (`params`;
  by default each parameter takes the group of the same name);
- a dedup key with a suppression window, and an hourly limit;
- the adapter that runs the turn: `route` (the compiled route itself, no
  model), `claude-p` (headless `claude -p`), `codex-exec` (`codex exec`), or
  your own argv.

On every match the dispatcher, in this order:

1. checks each extracted value with the **same full-match regex** as the
   route's `params`, and rejects the event if one does not match;
2. asks the kill switch (`integrity-killswitch`) for the adapter's vendor
   (`service` for the `route` adapter). Without the kill switch package
   nothing runs, unless the configuration says it is not required;
3. applies the dedup window, the trigger's hourly limit, the global hourly
   limit and the number of turns running at once;
4. runs only `safety: read` routes. A `safety: write` route becomes a
   **proposal**: an event and an optional notification with the command that
   an operator would run with a GO. The dispatcher never passes `--apply` and
   never sets `INTEGRITY_ROUTE_WRITE_GO`.

Every decision goes to a hash-chained journal in the instance folder. A
noisy source does not grow it line by line: `rejected`, `blocked`, `busy`,
`suppressed` and `rate-limited` events are folded to one record per trigger,
kind and reason in each `limits.noise_window_s` (60 s by default); the next
record carries the folded count in `repeats_before`. Turns,
proposals and rejections can also go to an event sink: a
[local memory](LOCAL_MEMORY.md) instance (one signed, closed turn per
record) or a command that reads the record as JSON. `runbooks report` sums
turns, wall time and the model cost that the client printed.

A model turn runs as an ordinary headless client in the folder you configure,
so it goes through that client's own hooks: Integrity admission, the guards
and the known routes at admission. Its prompt carries the route id, the
one-call command and the trigger's terms, so admission matches the route.
An adapter whose argv would skip the client's permissions or hooks is
refused, in any spelling (`--flag=value`, `-c key=value`, JSON settings,
`yolo` as a value). A command adapter cannot use the `service` switch. Every
word of every argv element is read, including a command string given to
`sh -c`, `cmd /c` or `pwsh -Command`; when a word is a known agent client
(`claude`, `codex`, ... from the kill switch's vendor markers) the adapter's
vendor must be that client's, and an argv that names clients of two vendors
is refused, so an adapter cannot borrow another vendor's switch. This check
is static and the best it can be from the configuration alone: a script that
starts a model itself is not visible to it. The real barrier is the kill
switch with its process-ancestry check in the client's own hooks. A webhook
without `listen.webhook_token_env` accepts a post from any local process;
`runbooks doctor` warns about it.

What is verified: the dispatcher's tests run in public CI on Linux and
Windows with a stub adapter and invented routes. No real model, log daemon
or production host took part. See [What is verified](STATUS.md#event-driven-runbooks).

## Integrity uses its own routes

The steps that turn a change to this repository into a review package are
compiled routes too. They live in [`.integrity/routes/`](../.integrity/routes),
one `<route_id>.json` per route, next to a runbook configuration
[`.integrity/runbooks.json`](../.integrity/runbooks.json) that is off
(`"enabled": false`) and points `compiled_routes` at that folder. Run them from
the repository root:

```bash
export INTEGRITY_COMPILED_ROUTES=.integrity/routes
integrity-guards uroboros run integrity-dev.ci-checks
integrity-guards uroboros run integrity-dev.ci-build work=../ci-work
integrity-guards uroboros run integrity-dev.ci-tests work=../ci-work
integrity-guards uroboros run integrity-dev.package-diff base=main out=../change.diff
```

| Route | Safety | What it does |
|---|---|---|
| `integrity-dev.manifest-refresh` | write | `update_manifest.py --root .`: bytes, mode and sha256 of every listed file |
| `integrity-dev.manifest-add` | write | the same with `--add` or `--add-generated` for one new file |
| `integrity-dev.catalog-write` | write | `component_catalog.py --root . --write`, then the check without `--write` |
| `integrity-dev.ci-checks` | read | the public-surface job's checks: manifest and privacy boundary, catalog, canonical sources, export hygiene, `ruff` 0.16.3 on `src` |
| `integrity-dev.ci-build` | read: does not change the working tree; writes only into a new folder outside it | build, verify and co-install every distribution in `work` (outside the tree), the kill switch alone, the installed `guardian` profile |
| `integrity-dev.ci-tests` | read | the root and component suites against that installation, and `runbooks validate` of this configuration |
| `integrity-dev.package-diff` | read: does not change the working tree; writes only into a new file outside it | a plain `git diff --binary base..HEAD` in `out` (outside the tree), its sha256, size and file count, and `git apply --check` of it on `base` in a temporary index |

The rules they keep:

- No route pushes, opens a pull request or merges; those words are not in any
  argv. Publishing stays a person's step.
- The write routes change only the working tree. Without `--apply` they print
  their plan; with it they need `INTEGRITY_ROUTE_WRITE_GO` to name the route,
  and they first store the old file in git's object store (`git hash-object -w`),
  printing its blob id for a restore with `git cat-file -p`.
- The read routes run in a clean clone: a precondition requires
  `git status --porcelain --untracked-files=all` to be empty, and the last
  step requires it again, so a check that leaves a file behind fails.
- `ci-checks` also refuses ignored files (`git status --ignored`): the
  public-surface check counts every file on disk, so the `*.egg-info` and
  `build/` of an earlier build fail it. Run it first on a fresh clone; the
  route never cleans the tree itself.
- `ci-build` and `ci-tests` refuse to start when `PYTHONPATH` is set: with it
  pointing at a source tree, the `*.egg-info` a build leaves there makes pip
  skip those wheels, and the tests would then check the source instead of the
  installed package.
- Parameters are full-match regular expressions: `work` and `out` are one
  name under `../`, `base` cannot start with `-`, and no value may hold `..`.
  The `manifest-add` path cannot start with `.git/` (in any letter case) and
  a precondition refuses a path git ignores (`route_tools.py not-ignored`), so
  build output and git's own files never enter the public manifest.
  Every path in a route is relative to the repository; no route names a host.
- A compiled route runs argv lists without a shell, so
  [`.github/scripts/route_tools.py`](../.github/scripts/route_tools.py) does
  the few shell jobs they need: check that a path is absent or not ignored, run python or a
  console script of the `work` virtual environment with the CI test
  environment and an expanded glob, hash a diff, and check that it applies.

`runbooks explain` shows what a request line would do; a read route is a
`turn`, a write route a `proposal`:

```bash
integrity-guards runbooks explain integrity-dev.package-request \
  --line "package base=main out=../change.diff" --file .integrity/runbooks.json
integrity-guards runbooks explain integrity-dev.manifest-add-request \
  --line "manifest add tests/test_example.py" --file .integrity/runbooks.json
```

The mirror is not the whole CI: the bus hub, HumanX and core-instance jobs
need Linux accounts or `sudo`, the UI models need Node, and the macOS job
needs macOS, so they stay in CI only. On the machine where it was timed the
build step took about 212 s of its 300 s limit.

What is verified, on the [STATUS](STATUS.md) scale:

| Part | Status |
|---|---|
| Every route validates, is named by its id, has no publishing word, absolute path or host; parameters refuse escapes; write routes only plan without `--apply`; `runbooks validate` and `explain` see every route; `package-diff` runs on a fresh clone and its sha256 matches | **CI** (`tests/test_integrity_dev_routes.py` in the root suite) |
| `ci-checks`, `ci-build`, `ci-tests` end to end on a clean clone; `manifest-add` and `catalog-write` applied to build the change that added them | **once** (one Windows workstation) |
| The dispatcher serving `.integrity/runbooks.json` | **not verified**: it is off, and nobody ran `runbooks serve` with it |

## Matching and ranking

- **Term matching.** Terms match by substring against four fields: triggers
  (weight 4), title (3), scope/subsystem (2) and steps (1). Long words are
  lightly stemmed, so inflected languages still match.
- **Threshold.**
  - An explicit route needs at least two matched terms and a minimum score.
  - An observed route needs three matched terms and a higher score.
  - Numbers alone never count as a match.
  - Unrelated prompts and harness messages therefore get no routes.
- **Score adjustments.** Status and a declared rollback raise the score. Age
  lowers it gently.
- **Exclusions.** Routes whose event is named in a later
  `supersedes_event_ids` are dropped.
- **Determinism.** The result is deterministic for the same snapshot and
  clock.

## Glossary

| Term | Meaning |
|---|---|
| **Uroboros** | Umbrella name for procedural memory: routes, runbooks, macros, verification. |
| **Route** | A reusable path to a result with provenance and a status. It is guidance only. |
| **Runbook** | Instructions for an AI turn: trigger, context to gather, decisions, allowed actions, checks. |
| **Macro** | A prepared call of an existing function. Its target and secrets are owned by the executor. |
| **Toolzs** | The signed, cursor-pinned route-memory protocol (alpha) for tool and UI routes. |
| **Route stamp** | The `route_digest` stored on each Seed append. It is internal binding, not procedural memory. |

## Authority

- Routes never grant execution, production or route authority.
- A route may be wrong, stale or written by an untrusted agent. Read its
  provenance and check current state before acting.
- Production changes still need the target's own owner approval.
- A trigger match is never a GO: the dispatcher turns a write route into a
  proposal and leaves the decision to the operator.
- No route enters a Stable Toolzs library without a security review.
