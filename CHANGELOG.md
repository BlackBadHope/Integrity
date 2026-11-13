# Changelog

All notable public changes are recorded here.

## Unreleased

Changes on `main` after 7.0.1. Nothing here is tagged, and the distribution
versions are unchanged unless an entry says otherwise.

### A core instance on one Linux account

- **`guardian-core-instance`**: a new command in `integrity-guardian`
  (`integrity_guardian.core_instance`), Linux only. `init` creates one private
  folder with an Action Log database, a Seed catalog, native trust with file
  keys, the custody ledger and Turn Memory; `serve` is the Guardian Memory MCP
  server for it; `server-json` prints the server description for
  `integrity-remote core init`; `doctor` checks the instance read-only;
  `uninstall` removes it. No root, sudo, systemd or network listener.
- Each `serve` process runs the Action Log service on a loopback port with a
  token of its own and imports new events into the catalog before every
  request, so sessions of one instance see each other's writes.
- It needs `integrity-action-log` 2.11.0 installed and refuses another
  version. On Windows and macOS it refuses and points to the local memory
  profile.
- A session reads the catalog cursor from the catalog, under the lock, before
  it imports, so it does not import again what another session of the same
  instance imported. An `init` that fails part-way removes what it wrote.
- `tests/test_core_instance.py` runs in CI on Ubuntu: two sessions in a row,
  two at once, one through an OpenSSH forced command, an import that another
  session made first, and an `init` stopped part-way. `docs/CORE_INSTANCE.md`
  lists what is not verified: a real agent client, two separate hosts, the
  hardened release mode, an upgrade over an existing instance.

### The demo is a run of real agents

- The demo at the top of the README is now three agents on one task and one
  local memory: A writes, B writes, and C reads from memory what B wrote, who
  B says it is, what B claimed and how B's turn ended. A second run shows B
  stopping early: C sees a claim that was never released and a turn with no
  closing receipt.
- The agents are processes of the user's own agent client. `demo/README.md`
  has the commands and `demo/prompts` the prompts. `demo/recorded` holds the
  records of two runs on Windows, with agents A and C in Claude Code and
  agent B in Codex CLI; the pictures are drawn from them.
- `demo/run.py` no longer plays agents. It prints the records, draws the
  pictures and builds a record from a user's own run: from the output of
  `claude -p --output-format stream-json` or of `codex exec --json`, with one
  client name or one for each agent.
- The four-scene script that the demo replaces is now a separate example,
  [`examples/scripted-scenes`](examples/scripted-scenes/README.md): record,
  recall, a one-use owner grant, and a missing close in the doctor. It says
  that a script plays the agents, and it draws no picture.
  `tests/test_example_scripted_scenes.py` runs it.
- `tests/test_demo.py` replays the recorded tool calls against a new instance
  without a model and fails when this code answers differently, when a
  published prompt differs from the one that was run, or when the pictures
  differ from the records.
- The README quick start begins with `guardian-local-memory init` and the
  three prompts. The two exercises that need no agent client follow it.
- Not run: Antigravity, a real client on Linux, a killed agent process, and
  Codex with its block in a config file.

### Local memory on one machine

- **`guardian-local-memory`**: a new command in `integrity-guardian`
  (`integrity_guardian.local_memory`). `init` creates a private instance and
  prints the MCP block for Claude Code, Codex or Antigravity; `serve` is the
  MCP server the client starts; `doctor` checks the instance read-only;
  `uninstall` removes it. Windows and Linux.
- The server joins three existing stores - Seed catalog, Turn Memory, work
  claims - and offers eleven tools, among them `lm_work_claim`,
  `lm_work_release`, `lm_work_claims` and `lm_turn_receipt_by_event`, which
  finds the signed turn and its closing receipt from one event.
- The tool names start with `lm_` and differ from the tool names of the core.
  A Native lifecycle hook recognises the core's tools by name; a test checks
  that no name of this server is one of them.
- The Codex block from `init` carries `default_tools_approval_mode =
  "approve"`: without it a non-interactive `codex exec` refuses the tools.
- Events carry `declared_agent`, `declared_client` and `declared_machine`.
  These are declared by the writer and not verified.
- This is not the core write path: no Action Log, no custody ledger, no
  admission of actions. [docs/LOCAL_MEMORY.md](docs/LOCAL_MEMORY.md) lists
  the limits.
- `WorkClaimRegistry.claim` takes an optional `reference`, stored in the
  claim's log event and so covered by the hash chain. Existing callers are
  unchanged.
- The memory facade (`memory_synapse_mcp.py`) is not changed.

### The kill switch installs, checks and removes on its own

- `integrity-killswitch doctor`: a read-only self-check. It creates no state
  file, writes no log line and opens no connection; it exits 1 when a check
  fails.
- `integrity-killswitch uninstall [--yes]`: lists, then removes, the state and
  log files the switch wrote for this user. When the stored state blocks
  something, removal is operator-only, like `on` and `resume`.
- The component README now gives the install commands without the rest of
  Integrity. CI installs the wheel alone into an empty environment on Ubuntu
  and Windows and runs install, `doctor`, `off`, `check`, `uninstall` and
  `pip uninstall`.
- The version stays 0.1.0a1. No release carries the wheel yet.

### Core fixes carried over from an installed release

A running core release carried fixes that had not reached this repository.
They are now in `src/integrity_guardian`:

- **Custody verification is anchored** and runs before the custody lock, so the
  lock is held only for the append. Architecture admission and the event-append
  grant and outcome sections use the same pass. A scheduled full verification
  runs off the hot path; admission is blocked when it is stale or missing.
- **Replay pool adoption**: an existing replay pool is adopted instead of
  rebuilt, and verified ledger row facts are reused.
- **Seed catalog**: a read-only open that tolerates a quiescent WAL, and a
  rewritten single-verifier lock. A race test with real processes
  (`tests/test_seed_catalog_single_verifier_race.py`) runs on Linux only.
- **Seed event pages are byte-budgeted**, with a summary-only form for an
  oversized event. Replay retention is 3 hours. Start-up no longer runs a full
  Seed verification; a verified-namespace gate runs before the first Turn
  Memory use and fails closed.
- **Owner-rule selector** in the admission capsule (`owner_rules.py`), opt-in
  and off by default.

### Client memory

- **Opt-in keywords-line advisory** in the Claude standalone hook
  (`resources/claude/admission.py`). With `values.event_summary_keywords_line`
  configured, the hook checks that an event summary ends with a keywords line.
  It warns and counts; it never refuses an append. Off by default; the other
  hooks do not read the value.
- A test now checks that the shipped tools catalogue lists every tool of the
  facade's current profile.
- **Claude hook patch series**
  (`components/integrity-client-memory/hook-series/claude-windows/`): a second
  Claude Code hook lineage, the one that runs on a Windows workstation,
  published as a base file plus 23 strict patches (20 for the admission hook,
  3 for the turn guard), the builder and the full build. A test rebuilds the
  series in a temporary folder, checks every recorded step sha and compares
  the result with `built/` byte for byte. Private marks of the installation
  were replaced, so the build differs from the installed bytes in 33 + 5
  lines. The published build was not installed or run. It is not part of any
  launcher profile, and the two Claude hooks are not merged.
- **Antigravity gate v2 (uncovered turn).** With the admission-first gate on,
  a turn whose admission failed, or whose turn-memory registration could not
  be opened, can no longer change state: state-changing tools and
  `call_mcp_tool` to other servers are denied; reads and Integrity calls stay
  open. Before the broker verifies an admission, other MCP servers now wait too.
- **Antigravity: automatic model selection.** A `modelName` of `auto` or empty
  is treated as `gemini-default` (vendor Google) instead of failing the
  PreInvocation hook.
- **Antigravity: the `<USER_REQUEST>` wrapper** is stripped from the prompt
  that admission binds; the turn fingerprint still uses the full text.
- **Antigravity: a new invocation after Stop** for the same owner message
  resumes that turn; a turn that never attempted admission gets a fresh
  turn_ref.
- **Antigravity: superseded registration.** When a new owner turn replaces a
  turn whose registration is still open, the broker records a `notify`-stage
  gap for the old registration before opening the new one (best effort).
- **Antigravity broker:** at most four conversation workers (least recently
  used one is shut down), and `not` is removed from model-facing tool schemas,
  which Antigravity does not accept; the server still validates the full schema.
  These six Antigravity changes are covered by tests with a fake upstream
  (`tests/test_antigravity_gate.py`, `tests/test_antigravity_gate_v2.py`);
  the published form was not run inside a live Antigravity session.

### Agent bus 1.1.0

`integrity-llm-bus` moves from 1.0.0 to 1.1.0 and now matches the bus scripts
of an installed deployment:

- **Hub**: a unix-socket daemon with a fixed JSON protocol, per-key rights,
  rate and seat limits, an owner gate, a hash-chained request journal, a
  replica change log, a migration tool and a route-catalog export
  (`resources/core/`), with example systemd units and an SSH gateway.
- **Hub client**: writes go to the hub over SSH and the local database becomes
  a guarded read-only replica. Enabled only by `<state>/CORE.json`.
- **Owner layer**: a message sent as `owner` must carry a valid owner
  signature; no key replaces it.
- **Agent mesh**, **human room** rules, a SQLite registry, automatic
  registration of harness sessions, ChatGPT registration, maintenance flag,
  attachments and reachability.
- Registration refuses the reserved `human-*` and `room-*` prefixes.
- Test only: the test of concurrent registration failed once in CI on Windows
  because one of four processes gave up waiting for the registry lock, which
  `autoreg.py ensure` does by design after 250 ms. The test now repeats such a
  process until its identity is registered and still requires one entry for
  each identity; a new test holds the lock and checks that the command reports
  `registry busy` and writes nothing.

The component README lists what was run and what was not; the hub's socket
handler, the systemd sandbox and multi-host operation are not verified.

### New components

- **`integrity-killswitch` 0.1.0a1**: a cooperative per-vendor and global
  switch for agent access on one workstation, with an audit log, a loopback
  dashboard and an optional sync to a bus host. It does not terminate
  processes; see its README for what it does not do.
- **`integrity-guards` 0.1.0a1**: hook-side guards for coding agents - a
  remote-change lock guard, a rule guard with a device command registry, a
  rules drift check, compiled routes and a repeat hook. Host tables, device
  registries and routes are yours to write; the examples are invented.
- **`integrity-humanx` 0.1.0a1**: a room for a human operator - a small web
  page, room agents of four vendors woken over the bus and held read-only by
  hooks, a read-only gateway, and ring and storm screens rendered without a
  model. Every site value comes from a configuration file. It is a port of a
  working pilot; the ported form has had no live run, and its README lists
  the defects carried over.

### Linux core deployment scripts

`deploy/linux-core/` holds the scripts that serve the memory core over an
OpenSSH forced command: the transport (`run-mcp`, `run-mcp-child`,
`verify-release`, `transport-supervisor.py`), the facade release entry points,
the passive Action Log witness with its sudoers template, and three host
wrappers. Deployment-specific values are `@PLACEHOLDER@` tokens that must be
filled before release digests are computed;
[deploy/linux-core/README.md](deploy/linux-core/README.md) lists them and
states what is verified.

- **The Action Log token is no longer on a command line.**
  `host/integrity-memory-mcp` used to pass the token as an argument of `env`,
  where any local user could read it from the process list. A clean child
  shell now reads the token file and exports the variable.

### Examples and the arbiter role

- **`examples/owner-rules-starter`**: 20 generic owner rules in the
  `owner-rule/v1` format, in English and Russian, each with a reason and a
  way to follow it. It is an example to copy and edit. A test loads the pack
  and checks that eight requests select the expected rule.
- **`examples/memory-carryover-tasks`**: six small two-session coding tasks
  with reference solutions and tests. It is an example of how such a set is
  built; it has no harness and no measurements.
- **`tools/lab`**: operator tools for an isolated two-VM lab, published as a
  worked example. Every value that describes one particular lab (paths, VM
  names and UUIDs, guest addresses, build pins) is read from a `lab.json`
  that you write from `lab.example.json`. The published form was checked
  statically only: no VM, guest or network call was made with it.
- **[The arbiter role](docs/ARBITER-ROLE.md)**: a page on the coordinating
  agent of the agent mesh. It separates what `mesh_store.py` enforces from
  what is a working convention.
- **Tests for the owner-answer rule of the agent mesh.** The rule was already
  in `mesh_store.py` and had no test here. A node blocked on a decision opens
  only on the owner's approval of exactly that decision; 29 cases now cover
  it, including `rebuild`.

### A demo at the top of the README

Replaced by "The demo is a run of real agents" above; kept as the record of
what was on `main` before.

- **`demo/run.py`** runs four scenes on one machine with synthetic data, no
  network and no account: an agent records a decision and closes its turn with
  a signed receipt; a second agent in a new process recalls the decision with
  its origin; an action backed only by memory is refused, a one-use owner grant
  passes once and its repeat is refused; a turn left open shows up in
  `integrity-doctor` as a signed gap. No model runs: the script plays both
  agents, and the stores, receipts and checks are this repository's code.
- The README opens with an animated picture of that run, in light and dark
  variants, drawn by the same script (`--svg`). `tests/test_demo.py` runs the
  scenes in CI and fails when the committed pictures differ from the run.
- The README section "The demo, step by step" names the code behind each
  scene and what the demo does not show: Seed events are not signed (the
  signature is on the turn close receipt), scene 2 is a recall and not the
  admission context of a hooked client, and scene 4 reads the turn store
  through a one-tool stand-in server.
- The README carries a dated block of figures from one real deployment
  (13 Nov 2026): events in the Seed, agent turns registered, closed and still
  open, and the clients whose agents have written to it. It is a measurement
  of our own deployment and cannot be checked from this repository.

### Documentation

- **The documentation set was reworked for the current functionality.** The
  README was rewritten around what Integrity does today, with generated
  diagrams in light and dark variants (`docs/assets/build_assets.py`). New
  pages: a documentation map ([docs/README.md](docs/README.md)), what is
  verified ([docs/STATUS.md](docs/STATUS.md)) and an install guide
  ([docs/INSTALL.md](docs/INSTALL.md)). The roadmap and the architecture
  page were brought up to date, every page got a navigation line, and test
  counts and skip reasons now come from a CI run.
- Corrected: Seed events are not signed. The Ledger, turn receipts, grants
  and cloud journals are.
- A personal device nickname was replaced by a generic description in the
  README, one embedded client comment and one test docstring. The affected
  client resource pins were refreshed.

## 7.0.1 -- 2026-11-06

Tagged as the GitHub release `v7.0.1` (client-memory 1.13.1). See
[RELEASE_NOTES.md](RELEASE_NOTES.md).

### Smaller memory responses for models

- **Append receipts** reach the model as a compact `/append-receipt`: outcome,
  `event_id`, `event_uid`, `request_sha256`, automatic-retry flag, witness
  status and the digest and size of the full receipt, at most 1 KB. This
  applies in the Windows and Linux Codex brokers, the Claude Native broker and
  the Antigravity broker, after each broker has observed the full result. Other
  results, and a receipt that would not fit, pass through unchanged.
- **Antigravity admissions** reach the model as a projection of at most 8 KB:
  ids, capsule text, recalled memory (summaries shortened to 400 characters),
  invariants, delivery health, snapshot, receipts, and the digest of the full
  document in place of the static blocks. The registration block keeps only
  the registration id and the close requirement. The broker validates the full
  admission and registration first.
### Claude Code standalone hook takes the broker's registration hand-off

- The standalone hook (`claude/admission.py`) now asks for and accepts the same
  one-use registration hand-off as the Native hooks: consent for each intent,
  then exact turn envelope, generation, intent and open arguments, and a receipt
  id that is its content digest. Without a valid hand-off it opens the
  registration itself, as before. The broker side for this hook is the one
  registered by hand; a broker that writes the public hand-off saves the cold
  open on every turn.

- **Claude Code Native admissions** are now file-backed like the Codex ones:
  the broker stores the full admission in the private admission-artifact store
  and gives the model a wrapper of at most 8 KB (ids, status, door, snapshot,
  delivery health, capsule text, capabilities digest). The Native hook resolves
  the wrapper to the full document before its usual validation.
- On the disposable Memory stand (Linux Native profiles, CI), a new test
  measures what the model sees per turn: admission at most 8 KB, append at most
  1 KB.
- Codex admissions were already file-backed and at most 8 KB.
- `RELEASE_NOTES.md` now carries the clean-machine results for 7.0.0, which the
  7.0.0 tag still marked as pending.

## 7.0.0 -- 2026-11-06

The first stable release in this repository, tagged as the GitHub release
`v7.0.0` (client-memory 1.13.0, Action Log 2.11.0). See
[RELEASE_NOTES.md](RELEASE_NOTES.md). Everything below is new since
`v7.0.0-beta.4`.

### README: every claim checked against evidence

- Claims that were not proven are narrowed or moved to a new "Known
  limitations" section, and known Antigravity limits are listed.
- The admission-first gate is described as on by default for Claude Code
  profiles on Linux; the Claude Code Native route on Windows has no gate.
- Security reports go through an issue titled "Security contact" until private
  vulnerability reporting is enabled.

### Admission-first gate: Claude Code Native on Linux now blocks

- A clean Debian VM showed that the gate let a tool run before admission in a
  Linux Claude Code Native profile, although `turn-guard.json` said `block`.
  The Native hook never marked the turn as an owner turn, and the gate only
  acts in owner turns. Each new intent is now marked by its prompt, with the
  same signal as the Claude Code standalone hook (`turn_guard.prompt_turn_kind`):
  an owner prompt is an owner turn, and a prompt that starts with a harness tag
  (a task notification, a peer message) is a notification turn, which the gate
  leaves alone. This covers the Native hook (Claude Code on Linux, Codex), the
  Linux hook and the Windows seats hook; the gate is opt-in on the last two and
  for Codex.
- The gate's message now reaches the model in Native profiles. The Native
  runner captured the hook's stderr and dropped it, so the model saw only "No
  stderr output" for a blocked tool. A blocking hook's reason (exit code 2) is
  now passed through; other stderr stays private.
- `integrity-doctor` labels the broker's protocol version as such
  ("broker protocol 1.6.0"), so it is not read as the package version.
- `docs/linux-native-clients.md` now creates `~/.config/integrity/clients`
  before the profile build, which needs an existing parent directory.

### Versions

- client-memory 1.13.0 (the broker-side turn registration below).
- Action Log 2.11.0, for the known-routes work that shipped in beta.4.

### Client hooks: the broker opens the turn registration right after admission

- **Faster turns.** The model's broker now opens the turn registration over
  its already admitted connection, before it returns the admission. The
  owning hook no longer starts a separate client for that, so it skips the
  launcher checks, the new SSH session and the cold server start. In the
  owner's Windows deployment of the same change (a Claude Code hook
  generation outside this repository), the median admission went from 45 s
  to 15 s and the turn close from 2.25 s to 0.7 s; the open itself took
  0.03–0.09 s. This build was not timed separately.
- **Same ownership rules.** The open goes through the broker's normal owning
  lifecycle path: the same identity checks, dispatch journal and
  unknown-outcome bookkeeping. The identity comes from the hook's private
  turn envelope and the owning state, never from the model. The broker opens
  only when the hook asked for it for this exact intent, and only on the warm
  connection, with a 4 s limit.
- **The hook checks the hand-off like its own open.** It accepts the receipt
  only for the exact turn, generation and open arguments, and only if the
  receipt id is the content digest. The file is removed whenever it is read.
  Without a valid hand-off the hook opens the registration itself, as before.
  If the broker's send has an unknown outcome, the Codex brokers' dispatch
  journal turns the hook's attempt into a recorded coverage gap rather than a
  second send. The server would replay an identical open anyway.
- **Warm-first lifecycle for Claude Native.** Its lifecycle calls now use the
  admitted connection first and fall back to a new connection only when
  nothing was sent.
- Covered: Codex on Windows and Linux (owning hooks), Claude Native. The
  Windows remote broker and the seats hooks are unchanged.

## 7.0.0-beta.4 -- 2026-11-06

The first release in this repository, tagged as the GitHub pre-release
`v7.0.0-beta.4` (client-memory 1.12.0). See [RELEASE_NOTES.md](RELEASE_NOTES.md).
Everything below is new since `v7.0.0-beta.3`. Entries for 7.0.0-beta.3 and
earlier describe releases published under Apache-2.0 in a previous repository;
pull request numbers refer to it.

### License: Business Source License 1.1

- From version 7.0.0-beta.4 on, Integrity is licensed under the
  [Business Source License 1.1](LICENSE). The Change License is Apache-2.0,
  four years after each version is first published.
- Production use is free for individuals, academic and research use,
  non-profits, and organizations whose annual gross revenue, with all their
  Affiliates, is below USD 1,000,000. Non-production use is free for everyone.
  Other production use needs a [commercial license](COMMERCIAL.md).
- Contributions need a signed [CLA](CLA.md).

### README: claims narrowed to what is proven

- The opening, pillars and use cases say which clients were run live and which
  paths are tested only in CI (cloud journals, Android, cross-machine fences).
- Known routes at admission need an Action Log newer than beta.3.
- The quickstart has a copy-pasteable clone URL and an explicit activate step.

### CI: Python 3.11, macOS, measured skips

- The `verify` job runs on Python 3.11 and 3.12 on Ubuntu and Windows (#31).
- A new informational macOS job runs the core and client-memory suites. It has
  known failures where Linux `/proc` custody is required, so README now says
  macOS is not supported yet.
- Test reports are kept as `junit-*` artifacts. `docs/expected-test-skips.md`
  now gives counts measured in CI for every platform.
- README states that the skip guard covers client-memory only, and corrects
  the Windows CI row: Windows runs the full suite.

### Enforcement defaults and an honest per-client table

- Generated Claude Code profiles now turn the admission-first gate on by
  default (`admission_first: block` in `turn-guard.json`).
- Codex and Antigravity profiles keep it opt-in:
  - Codex has no live run of the gate yet.
  - On Antigravity, an enabled gate also auto-approves the standard tools of
    admitted turns.
- Choose the gate at build time with `integrity-native-profile --admission-first`.
- The README now has a per-client enforcement table. It covers which clients
  can block an unclosed turn, which only advise or record a gap (Linux Native,
  Antigravity, Claude Native on Windows), and where the gate applies.
- The opening claim now says "every admitted turn ends with a signed close or
  gap", not "every turn".

### Antigravity: admission-first gate and snapshot binding (from live use)

- **Admission-first gate.** `antigravity_hook.py` gates tools that are not
  Integrity calls with the same switch as the Claude gate: `--admission-first`
  at build, `admission_first` in `turn-guard.json`, or
  `INTEGRITY_ADMISSION_FIRST`. Default off.
  - Before admission, other tools and other MCP servers are denied, and the
    deny message names the exact admission call and `turn_ref`.
  - A turn whose previous turn stopped or closed is denied until the next
    `PreInvocation` stages a new reference.
  - The gate fails open when there is no hook state.
- **Explicit pass.** Antigravity treats an empty `PreToolUse` reply as a silent
  deny. Standard tools now get `{"decision": "allow"}`, and calls to other MCP
  servers keep `{}`. With the gate on, the generated `hooks.json` matcher lists
  the standard tools, so admitted turns auto-approve them. This is documented
  in the onboarding guide. With the gate off, the matcher stays
  `^call_mcp_tool$`.
- **Snapshot binding.** The Antigravity broker fills a missing `snapshot_id` for
  Seed read tools whose schema has one, from the turn's verified admission.
  Models omitted it, and calls failed with "snapshot_id does not match session
  admission". A supplied value is never overridden.
- The onboarding guide lists the known Antigravity limits: `Stop` does not
  block, Gemini Flash may ignore `call_mcp_tool`, and agentapi
  `new-conversation` creates owner turns.

### Native profiles accept JSON written by Windows PowerShell 5.1

- `integrity-native-profile` refused files with a UTF-8 byte-order mark
  ("Unexpected UTF-8 BOM"). Windows PowerShell 5.1, the default shell on
  Windows, writes one with `Set-Content -Encoding utf8`, and Notepad can too. A
  fresh install on Windows Server 2025 failed at this step.
- The installer, the tools-catalogue compiler and `integrity-doctor` now read
  user-supplied JSON and TOML as `utf-8-sig`. Before this, `integrity-doctor`
  silently skipped such a settings file and reported "no hooks found".
- The onboarding guide notes that `utf8NoBOM` exists only in PowerShell 7.

### Client hooks: admission-first gate (opt-in)

- **What it does.** In an owner turn, `PreToolUse` denies every tool except
  `ToolSearch` until the model has called
  `integrity_context_admission_current_turn`.
  - The deny message names that call with the current `turn_ref`, and nothing
    else.
  - Routes and context arrive with admission. In an A/B run, agents spent 3–4
    calls reading files before admission.
- **When the gate stays open.**
  - Off by default; turn it on with `turn-guard.json` `"admission_first": "block"`
    or `INTEGRITY_ADMISSION_FIRST=block`. `off` disables it.
  - Notification, peer-message and subagent turns are exempt, except a
    notification that continues an interrupted owner turn, which is gated like
    the owner turn.
  - Fail-open: the gate opens
    - after any admission attempt (even a failed one),
    - without an armed turn envelope,
    - after a broker start failure or a refused probe,
    - after two denials in a turn.
- All four hook variants get the gate (Claude, Windows native, Windows seats,
  Linux seats).

### Turn guard: findings from an independent live test (client-memory 1.11.2)

- **Interrupted turns.** A notification or a steering prompt that arrived
  before the owner turn stopped started a new generation and dropped the open
  registration from hook state: no close, no gap. The Claude hook now records a
  `reconciliation` gap for it first. A notification turn that continues the
  owner's work keeps the earlier state change and is no longer exempt.
- **More state changes are detected:**
  - messages to other sessions (`SendMessage`, `send_message`);
  - schedules (`CronCreate`, `ScheduleWakeup`, `RemoteTrigger`);
  - published pages (`Artifact*`), stopped tasks, worktrees;
  - session management (`delete_session`, `archive_session`, permission
    changes), `hand_off_to_session`, `sync_with_base_branch`;
  - MCP `share`, `batch` and `kill` tools, browser `computer` and `form_input`.

  Session titles and read calls stay exempt.
- **Honest wording.** When no admission was made, the guard no longer says
  "the coverage gap is recorded": there is no registration, so nothing is
  recorded on the server.
- **Visible blocks.** The turn log now marks a turn that was blocked once, so
  `integrity-doctor` no longer reports "0 blocked once". It also counts
  state-changing turns that were closed with `outcome=no-event`. Such a close
  is still accepted, because a shell call may only have read.
- The probe budget is 50 s. Live cold starts took 31-38 s.

### Uroboros: known routes at admission (Action Log)

- **Routes in the capsule.** Each Mind projection now carries `known_routes`
  (`integrity-guardian/uroboros-known-routes/v1`): up to three routes from
  the admitted Seed that match the owner's prompt. When the door is
  `admitted`, they also appear in the capsule's `learned_hints` as
  `ROUTE #id status …: title [… not authority]` (at most 200 characters). Every client receives them
  without a client change.
- **Two sources.**
  - Explicit `uroboros-route/v1` records in event details, versioned
    append-only; `superseded` routes are hidden, `stale` ones are labelled
    *verify first*.
  - Observed routes: verified, completed agent-log closes, or events tagged
    `uroboros-route`.
- **Search terms.** They come from the prompt with harness wrappers removed.
  The Action Log copy of `mind_retrieval` is synced with the canonical one,
  so `<system-reminder>` blocks no longer drive auxiliary recall.
- **Capsule text.** The adaptive capsule no longer cuts the rendered
  `context_text` inside the mandatory lead (door, moves, learned hints). When
  a shorter step would cut into it, the whole lead is used. On the live core
  the second `ROUTE` line used to be cut mid-word.
- **Toolzs tests are public.** The 17 test modules for the Toolzs protocol
  (a1–a14), the WinOPS reset schemas and the Adapter SDK moved from the
  private tree. They use the deployment profile's synthetic tenant. On
  Windows, tests that need POSIX file modes, symlinks or `/usr/bin/printf`
  are skipped.
- **Recording routes.**
  - `python -m integrity_guardian.uroboros_routes draft|validate` builds and
    checks `uroboros-route/v1` records.
  - Records with secret-like text are rejected at drafting and are never
    offered at retrieval (`rejected_secret_like`).
- **Route checks and repair.** `uroboros-route-check/v1` records a `pass`
  or `fail` check against current state (`... uroboros_routes check`).
  - The newest check for a route version sets `verified` or `stale`.
  - A stale hint asks for repair by a new version.
- **Example catalogue.** `examples/uroboros-routes` holds generic example
  routes and the rules for contributing routes.
- **Speed and precision (owner bar).** Changes after an A/B on a real task
  (checking a SIP phone):
  - every hint names the one call that returns the full route
    (`read_events after_id=N`);
  - the capsule text carries a `KNOWN ROUTES` block with the runnable steps;
  - observed routes need three matching terms;
  - numbers alone no longer count as a match;
  - peer-session message markup no longer drives search.
- **Authority.** Routes are hints only: `authority: "none"`,
  `production_authority: false`. See [docs/UROBOROS.md](docs/UROBOROS.md).

### Client hooks: no false "memory unreachable" (client-memory 1.11.1)

- `INTEGRITY MEMORY UNREACHABLE` needs real evidence: a broker start failure,
  or a hook probe, made for this notice, that the server refused twice. A
  probe timeout is inconclusive, because a cold broker start over SSH takes
  about 21 seconds, and the probe used to give up after 20. The probe now
  has a 40-second budget, covering the retry.
- A failed probe is shown once, in the turn it was made. Later turns never
  repeat a stale result, and the probe is not re-run within 10 minutes.
- No probe is run, and no notice shown, when the hook's own lifecycle call
  reached the server in the last 10 minutes; that counts as `ADMISSION SKIPPED`.
- Harness notification and peer-event turns get no notice and no probe again,
  as before 1.11.0.

## 7.0.0-beta.3 -- 2026-11-06

Public source beta, tagged as the GitHub pre-release `v7.0.0-beta.3`. Not a
stable or production release; the latest stable release is `v6.1.1`, which is
also the rollback point. See [RELEASE_NOTES.md](RELEASE_NOTES.md). Everything
below is new since `v7.0.0-beta.2`.

### Client hooks: enforce the turn close, honest status, `integrity-doctor` (client-memory 1.11.0)

- **Turn-close guard.** The `Stop` hook now blocks, once, a turn that changed
  state (edits, shell, MCP writes) without `integrity_turn_memory_close`, and
  tells the model the exact close (or admission) call. The next stop always
  ends the turn and records the coverage gap, so a turn cannot loop.
  Notification and peer-event turns and subagent stops are exempt; read-only
  turns are not blocked. Native profiles and the `integrity-seats` plugin
  default to `block`; other installs default to `advise`, which shows the
  missing close to the operator. Switch it with
  `INTEGRITY_TURN_CLOSE_ENFORCEMENT=block|advise|off` or `turn-guard.json`.
  Linux user-custody profiles only advise. Applies to the Claude standalone,
  `integrity-seats` (Windows, Linux) and Native cohort (Codex) hooks.
- **Status notices from evidence.** The "memory offline ... MCP server is most
  likely not connected ... reconnect" notice is replaced. `ADMISSION SKIPPED`
  is shown when the server answered in this session, `MEMORY UNREACHABLE` only
  after a failed hook probe or broker start, `ADMISSION NOT CALLED` otherwise.
- **`integrity-doctor`.** New read-only command: installed hooks by vendor and
  scope, MCP registrations, a server probe, server-side close coverage and the
  local admission/close rate of the last turns. It flags project-only hooks.
- **Scope in install output.** `integrity-native-profile` prints the generated
  hook file, its scope and how to apply it to every folder.
- Claude Desktop relayed messages and background-task banners are recognized as
  harness notifications at `UserPromptSubmit`.
- Docs: [hooks troubleshooting](docs/hooks-troubleshooting.md), README section
  "Hooks: where they apply and what they enforce".

## 7.0.0-beta.2 -- 2026-11-06

Public source beta, tagged as the GitHub pre-release `v7.0.0-beta.2`. Not a
stable or production release; the latest stable release is `v6.1.1`, which is
also the rollback point. See [RELEASE_NOTES.md](RELEASE_NOTES.md). Everything
below is new since `v7.0.0-beta.1`.

### Cross-machine memory

- New `integrity-remote` 0.1.0b1: OpenSSH forced-command releases, per-device
  `authorized_keys` lines, a hardened client transport and `check`. See the
  [two-machine quickstart](docs/CROSS_MACHINE_QUICKSTART.md). A required
  `Cross-machine SSH` CI job runs the real Memory MCP lifecycle over loopback
  `sshd`.
- Known limits: bus, hub and mesh are not carried across machines.

### Fixes from live multi-client operation

- Guardian: context replay garbage collection for the pooled catalog layout.
  Expired replays and pools that no replay references are removed under the
  maintenance lock after a grace period, together with their catalog-pool
  marker. Empty SQLite `-wal` files and small `-shm` files left by read-only
  openers are removed too; a non-empty WAL is refused as `pending WAL`. Before
  this, pooled replays were never pruned, the 4 GiB quota filled up, and
  admission reported `replay-storage-unavailable`.
- Guardian: writes from a model session whose turn was opened by a hook in its
  own server session. Codex hooks open the turn through their own broker, so the
  model session that holds the admission had no registration and every append
  was denied with `same-session write requires original registration`. Now the
  first write adopts the registration of exactly its own admitted intent
  (`intent:<turn_ref_digest>`, same prompt SHA-256, not terminal) through the
  same checks as an in-session open. A foreign intent or a closed turn is still
  refused.
- Client Memory: Codex 0.166 runs hooks without `CODEX_THREAD_ID`. Under Linux
  user custody the hook owner is now the proven caller descending from the live
  pinned Codex process, and lifecycle claims carry the thread they were issued
  for. When the variable is present it must still match.
- Client Memory: Android app sandboxes (for example proot) refuse hard links;
  the atomic file store falls back from `os.link` to `os.replace`.

### Guardian: deployment identity profile

- New `--deployment-profile` and `--expected-deployment-profile-digest` for
  `guardian-memory-synapse-mcp` and `guardian native-trust-bootstrap`. One
  owner-provisioned, digest-pinned JSON file supplies a deployment's tenant
  identifiers, Action Log protocol labels, schema constants, archive policy and
  a few deployment settings. Public defaults are unchanged and the public tree
  carries no deployment values. See [docs/DEPLOYMENT_PROFILE.md](docs/DEPLOYMENT_PROFILE.md).
- A server started without the profile its state was created under still
  refuses with `ledger identity does not match requested identity`; nothing is
  written.
- Performance: architecture ledger verification reuses checks for exact
  unchanged event bytes; full Seed catalog verification is memoized per
  content; the package digest is computed once for an immutable installed
  release.
- Context replay understands pooled catalog layouts (`replay_catalog_pool`).
  Retirement waits up to 5 seconds for a contended replay lock and reports a
  failure code instead of failing at once.

### Client Memory 1.10.0: Linux Claude Code Native profile

- `native_install --vendor claude` builds on Linux from the shared Native cohort
  with an explicit `claude_executable`. It writes `.mcp.json` and
  `.claude/settings.json` and is owner-only. One profile serves every session of
  that binary under the user. The Windows publisher route is unchanged.
- Claude Code delivers no turn ID, so the pinned hook runner mints one random
  turn ID per `UserPromptSubmit` under the live pinned `claude` ancestor and
  records the prompt SHA-256. Later events must come from the same process, and
  the transcript must be the session's own private `<session_id>.jsonl`.
- `Stop`/`SubagentStop` never block or add context for Claude, so the turn is
  not re-run. An unproven prompt still runs with a notice, but no turn reference
  is issued and Integrity Memory calls are refused.
- The broker declares the generated vendor (`native_agent_product`) in its
  reader session instead of always `codex`.
- Linux client-memory skips drop to 11, all with reviewed reasons. The lifecycle
  stand test runs for both Codex and Claude Code.

### Cloud agents: signed turn journals without local hooks

- New `integrity-cloud` 0.1.0b1 with the following parts:
  - per-task Ed25519 journal: `open`, `turn-open`, `event`, `turn-close`, `seal`;
  - offline `verify` and `import-plan`, whose drafts carry `trust = reported`;
  - read-only context capsules with privacy refusals;
  - an optional Codex hook adapter.
- `AGENTS.md`, the `integrity-cloud-journal` repository skill and
  `examples/cloud-agents/codex-cloud-setup.sh` prepare a Codex cloud environment.
  [docs/CLOUD_AGENTS.md](docs/CLOUD_AGENTS.md) records which Codex cloud
  capabilities are documented and which are not, the threat model, and the
  design-only append-only ingress.

### Client Memory: Linux Codex Native profile (user custody)

- `native_install` builds the Codex Native profile on Linux. It requires an
  explicit `codex_executable`, pins its resolved image and SHA-256, and writes
  the whole profile owner-only (`0700`/`0600`); `native_runtime` refuses a
  profile root that is not yours and `0700`, and runs every hook, broker and
  upstream under `umask 077`.
- New `linux_user_native`: the hook runner records the Native head that Codex
  delivered on stdin; `owning_native` (mode `user`) accepts it only while the
  caller descends from the same live pinned Codex process (PID, start time,
  UIDs, image hash). The system-custody mode is unchanged.
- The canonical broker's transport-start gate uses `flock` on owner-only slots
  on POSIX, and the envelope keeps the delivered-context descriptor as
  `private-utf8-base64/v1` inside the owner-only root on POSIX (DPAPI/CNG on
  Windows), so same-session recovery is available on Linux.
- About 50 Linux skips are gone: profile, server-version, receipts, recovery
  bundle, hook replay and non-retained predecessor tests now run on Linux. New
  Linux tests cover real `/proc` ancestry, custody refusals, the start gate,
  the POSIX scope wrapper, and a hook/admission/registration/gap lifecycle
  against a disposable real Memory stand. Linux CI fails on unreviewed skips.
- See `docs/linux-native-clients.md` for the trust model and limits.

### Client Memory: Claude Native custody reader

- Define the Claude Native envelope's own custody reader (`_checked_owning_bytes`),
  which `_claude_profile_reader` and `_native_owning_head` called without a
  definition. The real owning-head read raised `NameError` on the claude-native
  profile; tests had stubbed the head. The reader is the same double-stat,
  junction-rejecting read as the Windows Native envelope, with a regression test.
- Add a static name-closure guard over every shipped client-memory resource:
  `symtable` must resolve each module-level name a resource uses, with the
  bundle-injected broker names allow-listed and verified against `broker_bundle`.

## 7.0.0-beta.1 -- 2026-11-04

### Integrity Seats

Public source beta, tagged as the GitHub pre-release `v7.0.0-beta.1` on
2026-11-04 (commit `b036acb`). Not a stable or production release.

- Shared-core seats, namespace isolation, a seat-scoped bus, fenced mesh claims,
  one-time GO checks, host transports, and enrollment. Existing single-user and
  silo installs keep their isolation until an explicit migration.
- The workbench resolves a configured seat through SeatPolicyRouter and passes
  that SeatContext into seat tools. Notes are written before `stored` is true,
  mesh status reads the mesh, and bus posts forward the message body.
- Known limits: Mode B tunnels are unverified; cross-machine Live was not in
  this tag. Roll back to tag `v6.1.1` or commit
  `fbc111ef209ceb45a445d049974f928d262ae430`.

### Client Memory 1.9.4 / Guardian recovery source acceptance

- Compile one shared Windows recovery implementation for Native and preserved-root
  profiles, with the 1.9.3 45-second startup deadline and single-shot model admission
  policy retained for both Windows broker families. Pin all vendor launch files.
- Decode compact Native receipts before the existing validators and use a neutral
  navigation result when no authenticated current task selector is available.
- Bound private snapshot allocation on disk, retain active owners, and distinguish
  unavailable replay retention from a valid signed current registration. Preserve
  append commit proof if subsequent feedback fails; reconcile unknown operations
  through receipt-backed same-session recovery rather than blind retries.
- Source tests use synthetic fixtures. Deployment, live Native acceptance and model
  context delivery require their separate target receipts; package versions do not
  establish those results.

### Client Memory 1.9.3

- Apply the same 45-second startup and single-shot admission policy to the
  separate Claude Code Windows broker. Add delayed-response and deadline
  checks for both actual transport implementations and generated profiles.
- Clarify that later successful historical Claude lifecycle probes used the
  legacy store and synthetic intent IDs; they are not Native acceptance.

### Client Memory 1.9.2

- Compile the Windows Native broker with a bounded 45-second cold initialize
  allowance. A real upstream handshake took 20.666 seconds, exceeding the old
  20-second cutoff before admission could be sent. The owning admission still
  occurs once; startup failure no longer advises a second model invocation.
- Pin the emitted Codex, Claude and Antigravity hook/MCP/plugin configuration
  files. Refuse configuration drift before launching the Native runtime.
  Regenerate older profiles into new directories; retain their old runtime and
  settings for rollback.

## 6.1.1 -- 2026-10-17

- Fixed the clean bootstrap example to use an absolute private architecture
  directory outside the source checkout; added the PowerShell equivalent and
  an explicit database-path check.
- Updated the supported stable version in SECURITY.md.
- Advanced Guardian patch metadata to 6.1.1 and regenerated the exact SDK
  source binding. Adapter SDK 2.0.0rc3 and Claude executor 0.1.0rc3 carry the
  matching dependencies; historical receipt/profile pins are unchanged.

## 6.1.0 -- 2026-10-17

- Consolidated the canonical Guardian implementation and independently versioned
  optional distributions. Removed repeated runtime source trees while retaining
  distinct broker/plugin contracts and historical LTS profile metadata.
- Integrated snapshot-bound context delivery, bounded canonical event context,
  topic extraction, ranked recall, separate Native/legacy Turn Memory and
  explicitly gated lifecycle curation. Memory facade API is 2.11.0; the modern
  request-independent transport remains the default surface.
- Added source packages for Action Log, Memory Plane, client hooks/brokers,
  Home/Chronicle, Space, the guarded Claude executor, LLM Bus and Bridges.
  Installation starts no service and includes no user archive, active host
  binding, session, route catalogue, credential or runtime database.
- Added one component catalogue with dependency, namespace, license and version
  checks. Adapter SDK 2.0.0rc2 binds Guardian 6.1.0 and its exact package origin;
  optional distributions keep their own versions and platform boundaries.
- Preserved Apache-2.0 ownership notices and third-party license texts, including
  the Space UI bundle and Execution Bridge supporting code.
- Catalog verification now rejects disagreement between indexed event fields
  and canonical payloads before ranked recall. Archive provenance policy is an
  explicit immutable input rather than a pre-enrolled corpus. Full source and
  catalog verification remain required.
- Preserved public export/privacy, functional and package checks; extended the
  release gate to canonical source layout, modes, metadata and optional packages.
  Tests use synthetic data and do not imply live production or model-delivery
  acceptance.
- Fixed the minimal Seed runtime's Windows virtual-environment launch boundary
  without relaxing exact process or signed-receipt checks. Its runtime revision
  is 0.1.4; the source plugin has a separate version and explicit package allowlist.
  Public CI now exercises isolated co-installation on both Linux and Windows.
- Upgrade boundary: historical signed deployment receipts and their reviewed
  replay paths retain their original version pins. This release neither rewrites
  those receipts nor silently migrates or bootstraps Native lifecycle state.

### Earlier changes since 6.0.0

- Seed writes no longer change identifiers or accepted text silently.
  `event_uid` is stored exactly as sent (up to 200 characters of
  `[A-Za-z0-9._:@/+-]`) or refused before the write; the same `event_uid`
  with a different operation returns `409 event_uid_conflict` and leaves the
  stored event unchanged. Operations are compared after normalization and
  redaction: actor, session_id, level, action, summary and tags exactly,
  `details` as a JSON object (key order ignored, `1` and `1.0` differ), and
  the fact time only when the client's `ts_utc` is accepted, to the stored
  second. Acceptance is judged against the stored first write's
  `created_utc`, not the retry's arrival, so an identical retry gets the same
  answer whenever it arrives. A `ts_utc` that was invalid or more than five
  minutes ahead of the first write is not part of the operation, so an
  identical retry returns the first event even after that time has passed. Requests that differ only inside redacted secret values
  cannot be told apart and are answered as duplicates. Over-limit `summary` (2000), `actor` (120),
  `session_id` (200) and `action` (160) are refused with `<field>_too_long`
  instead of being cut. Secret masking matches whole key segments, so keys
  such as `session_id`, `tokens_used` or `secretary` keep their values and
  types; every intentional change is listed in the reply's
  `transformations`. In text, `Authorization: <scheme> <credential>` (also
  `=` and `Proxy-Authorization`) keeps the scheme word and masks the whole
  credential: a token, or a comma-separated parameter list with quoted values
  such as Digest `username="...", response="..."`. A value without a scheme is
  masked as one token or one parameter list. A value whose end cannot be
  found (an unterminated quote, text glued to it, or an unparsed `name=`
  right after it) is refused with `400 authorization_value_unbounded`; the
  refusal does not repeat the value. `integrity_seed.py remember` prints these refusals.
- `guardian seed-sync` finds the source tail by event id, so backdated or
  near-future `ts_utc` values no longer stall or break a sync.
- A Seed catalog is bound to one runtime: the first sync records its
  `workspace_id`, later syncs refuse another source, and the catalog's first
  and last events are re-read from the source and compared before import.
  The sync report states which range was read and that earlier history is
  not proven unchanged; `seed-catalog-verify` states it checks the catalog
  only.
- Upgrade notes: events stored before this change keep their truncated or
  redacted values; nothing is restored, and an Authorization credential that
  the earlier filter left in place stays in those events, snapshots and
  exports; the same holds for Digest parameters after the first one. Retrying
  such an old operation now normalizes differently and returns
  `409 event_uid_conflict`; that is not a signal to resend it under a new
  `event_uid`. An `event_uid` longer than 160
  characters that was truncated before will not match its old row, so a
  retry stores a new event. Clients that relied on silent truncation, or on
  a reused `event_uid` returning the old event for a different operation,
  now receive an explicit error. Existing catalogs are bound on their next
  successful sync.
- Added `IntentCustody`: one-use reservation and consumption of signed
  ChangeIntents with replay rejection across processes and restarts.
- Added `WorkClaimRegistry`: local blast-radius claims with arrival-order
  waiting, fencing tokens, handoff, expiry and a shared hash-chained log.
- Added `SeedCatalog.find_events` for exact, index-backed event queries.
- Fixed a Ledger append race: the write lock is now taken before the source
  tip is read, so a concurrent writer gets a sequence mismatch.
- Documented the frozen `guardian-json-v1` digest frame and rejected digest
  domains that contain a backslash or control character. Digests are
  unchanged.
- Added `verify_trusted_signature`, which also checks the signature `key_id`.
- Added core protocol, custody, query and coordination tests, the
  architecture map and a manifest refresh script.
- Marked the package as Beta: local primitives are verified, distributed
  operation is not.

## 6.0.0 -- 2026-09-25

- First fresh-history public source release.
- Added Guardian Core, portable schemas, Seed memory protocol and portable
  plugin source.
- Added a closed export manifest and two-layer privacy verification.
- Added build/install/origin checks and the complete selected public test suite.
- Added public contribution, security, bootstrap and release documentation.

The release contains no customer data, private deployment overlays or
credentials. User-owned production deployments configure their own bindings
and authority.
