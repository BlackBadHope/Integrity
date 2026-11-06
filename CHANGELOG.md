# Changelog

All notable public changes are recorded here.

## Unreleased

### Client hooks: the broker opens the turn registration right after admission

- **Faster turns.** The model's broker now opens the turn registration over
  its already admitted connection, before it returns the admission. The
  owning hook no longer starts a separate client for that, so it skips the
  launcher checks, the new SSH session and the cold server start. On the
  owner's Windows machine the median admission went from 45 s to 15 s, and
  the turn close from 2.25 s to 0.7 s; the open itself takes 0.03–0.09 s.
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
