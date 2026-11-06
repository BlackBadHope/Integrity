# Integrity Seats 7.0.1

Integrity Guardian 7.0.0 with Integrity Seats, under the
[Business Source License 1.1](LICENSE). It is tagged as the GitHub release
`v7.0.1`; the first stable release in this repository was `v7.0.0`, and the
previous pre-release is `v7.0.0-beta.4`. Earlier versions were published under
Apache-2.0 in a previous repository, and pull request numbers before this
repository's #1 refer to it. A stable source release is not a production
deployment: no host is enrolled and no action authority is granted.

## New in 7.0.1

- **Smaller memory responses for models** (Client Memory 1.13.1). Every turn
  pays for what a memory tool returns, so the brokers now give the model only
  what it uses. Brokers and hooks still validate the full upstream results; only
  the model-facing copy is shorter.
  - **Append:** the model gets the outcome, `event_id`, `event_uid`,
    `request_sha256`, the witness status and a digest of the full receipt. In
    the Codex, Claude Native and Antigravity brokers a receipt of about 4.4 KB
    becomes about 0.5 KB, and one of 116 KB also stays under 1 KB. The owning
    hooks read the same fields as before.
  - **Admission through Antigravity:** the model gets the ids, the capsule text,
    the recalled memory (shortened), the delivery health, the snapshot and the
    digest of the static blocks, within 8 KB. On 50 recorded admissions of the
    owner's deployment this went from 22.7–24.6 KB to 4.2–5.6 KB.
  - **Admission through the Codex brokers** was already file-backed and at most
    8 KB. **Claude Code Native** admissions are not shortened yet, because its
    hook validates the admission from the tool response.

## New in 7.0.0

- **The broker opens the turn registration** (Client Memory 1.13.0; PR #1).
  The model's broker opens the registration over its admitted connection right
  after admission, through the same owning lifecycle checks and dispatch
  journal as before, and hands the receipt to the hook. The hook no longer
  starts a separate client for it. In the owner's Windows deployment of the
  same change (a Claude Code hook generation outside this repository), the
  median admission went from 45 s to 15 s and the turn close from 2.25 s to
  0.7 s; this build was not timed separately.
  This covers Codex on Windows and Linux and Claude Native; the Windows remote
  broker and the seats hooks are unchanged. Claude Native lifecycle calls now
  use the admitted connection first.
- **The admission-first gate blocks in Linux Claude Code Native profiles.**
  A clean-VM run of the release candidate showed a tool running before
  admission: the Native hook never marked owner turns. Fixed; the Linux guide
  also creates the profile's parent directory.
- **Every README claim checked against evidence.** Claims that were not
  proven are narrowed or moved to [Known limitations](README.md#known-limitations):
  the admission-first gate is on by default for Claude Code profiles on Linux,
  and the Claude Code Native route on Windows has no gate; Antigravity is in
  live tests, not daily use; the team quickstart is CI-tested with synthetic
  seats; known Antigravity limits are listed.
- **Action Log 2.11.0.** Version bump for the known-routes work that shipped in
  beta.4 (PR #53 of the previous repository).
- **Security reports.** Until private vulnerability reporting is enabled, open
  an issue titled "Security contact" with no details; see [SECURITY.md](SECURITY.md).

## Clean-machine acceptance

Run on the 7.0.0 release candidates on 06.11.2026 (fresh virtual machines;
the model in the hook run was scripted, not a live model):

- **Linux** (Debian 12, Python 3.11): install by the README PASS (first result
  in 21 s); read-only walkthrough PASS for all three clients; Claude Code
  2.1.318 with the Linux Native profile against a disposable Memory stand:
  admission → append → close PASS with a verified terminal receipt; the
  admission-first gate denies a tool before admission and its message reaches
  the model; a task-notification turn is not gated; `integrity-doctor` shows
  hooks, memory and 1/1 coverage.
- **Windows** (Server 2025, Windows PowerShell 5.1, Python 3.12): install by
  the README PASS (68 s); walkthrough PASS for all three clients; JSON written
  with a UTF-8 byte-order mark is accepted; Codex and Antigravity profiles
  build, and Codex `verify` and `probe` pass; the Claude Code Native profile is
  refused without an enrolled publisher, as documented. No hook run with a
  model was made on Windows.
- Not run: a live model on a fresh install (any vendor), live Codex.

7.0.1 was not re-run on clean machines; its change is limited to the
model-facing copy of memory responses and is covered by CI.

## New in 7.0.0-beta.4

**Known issue in beta.4, fixed in 7.0.0:** the admission-first gate was
inactive in the Native and seats hook profiles (Claude Code on Linux, Codex,
the `integrity-seats` plugin). Only the Claude Code standalone hook and
Antigravity enforced it.

- **License: Business Source License 1.1.** Production use is free for
  individuals, academic and research use, non-profits, and organizations whose
  group revenue is below USD 1M; everyone may evaluate, develop and test. Other
  production use needs a [commercial license](COMMERCIAL.md). Each version
  becomes Apache-2.0 four years after it is first published. Contributions need
  a signed [CLA](CLA.md).
- **Admission-first gate** (Client Memory 1.12.0; PRs #56, #60). In an owner
  turn, `PreToolUse` denies other tools until the model has called
  `integrity_context_admission_current_turn`, and the deny message names that
  call. Generated Claude Code profiles turn it on (`admission_first: block`).
  Codex and Antigravity keep it opt-in: Codex has no live run of the gate yet,
  and on Antigravity the gate also auto-approves standard tools in admitted
  turns. The gate fails open without hook state, after a failed broker start or
  after two denials. The README has a per-client enforcement table.
- **Antigravity from live use** (PR #59). Standard tools get an explicit
  `{"decision": "allow"}`, because Antigravity reads an empty reply as a silent
  deny. The broker fills a missing `snapshot_id` from the turn's verified
  admission and never overrides a supplied one.
- **Known routes at admission** (Uroboros, Action Log; PR #53). The capsule
  offers up to three matching runbook routes as hints, never as authority, for
  every client without a client change. The capsule no longer cuts its
  mandatory lead mid-word. The Toolzs protocol tests are public.
- **Turn guard fixes from an independent live test** (Client Memory 1.11.2;
  PR #54). An interrupted owner turn records a `reconciliation` gap instead of
  losing its registration. More tool calls count as state changes (messages to
  other sessions, schedules, published pages, session management, browser
  input). The probe budget is 50 seconds.
- **No false "memory unreachable"** (Client Memory 1.11.1; PR #52). The notice
  needs a failed broker start or a probe the server refused twice; a slow cold
  start is not a failure.
- **PowerShell 5.1 JSON** (PR #58). The installer, the tools-catalogue compiler
  and `integrity-doctor` accept JSON and TOML with a UTF-8 byte-order mark.
- **Honest CI and README** (PRs #51, #61, #62, #63). CI runs Python 3.11 and
  3.12 on Linux and Windows, plus an informational macOS job. Skip counts per
  platform are measured. README claims say what was run live and what is tested
  only in CI.

The full list is in [CHANGELOG.md](CHANGELOG.md). Pull request #57 (compiled
Uroboros routes) is not in this beta.

## New in 7.0.0-beta.3

- **Hooks enforce the turn close** (Client Memory 1.11.0). The `Stop` hook
  blocks, once, a turn that changed state without `integrity_turn_memory_close`
  and names the exact call; the next stop records a coverage gap instead of
  looping. Native profiles and the `integrity-seats` plugin default to `block`,
  other installs to `advise`; `INTEGRITY_TURN_CLOSE_ENFORCEMENT` switches it.
- **Honest status notices.** `ADMISSION SKIPPED` (the server answered, the model
  did not call it), `MEMORY UNREACHABLE` (a probe or broker start failed) and
  `ADMISSION NOT CALLED` replace the old "memory offline" guess.
- **`integrity-doctor`**, a read-only check of installed hooks, their scope, MCP
  registrations, a server probe and recent close coverage. See
  [docs/hooks-troubleshooting.md](docs/hooks-troubleshooting.md).

## New in 7.0.0-beta.2

- **Cross-machine memory.** New `integrity-remote` 0.1.0b1 connects client
  machines to one core over an OpenSSH forced command. See
  [docs/CROSS_MACHINE_QUICKSTART.md](docs/CROSS_MACHINE_QUICKSTART.md).
- **Linux native clients.** Codex and Claude Code Native profiles build on
  Linux under user custody (`docs/linux-native-clients.md`). Client Memory is
  1.10.0.
- **Cloud agents.** New `integrity-cloud` 0.1.0b1: agents that cannot run local
  hooks keep a signed turn journal in their sandbox, and the host verifies it
  before importing it as reported evidence. See [docs/CLOUD_AGENTS.md](docs/CLOUD_AGENTS.md)
  and `examples/cloud-agents/`.
- **Deployment identity profile.** One digest-pinned JSON file supplies a
  deployment's identifiers; public defaults are unchanged. See
  [docs/DEPLOYMENT_PROFILE.md](docs/DEPLOYMENT_PROFILE.md).
- **Fixes from live operation with several clients:**
  - context replay garbage collection for pooled catalogs, so the replay quota
    no longer fills up;
  - a model session can write when a hook opened its turn in a separate server
    session (the Codex hook layout);
  - Codex hooks without `CODEX_THREAD_ID`, and Android sandboxes that refuse
    hard links;
  - the Claude Native custody reader.
- Every skipped test has a documented reason in
  [docs/expected-test-skips.md](docs/expected-test-skips.md).

The full list is in [CHANGELOG.md](CHANGELOG.md).

## Included from 7.0.0-beta.1

- Seat-scoped hub tools: `seat_whoami`, `seat_append_note`, `mesh_status`, and
  `bus_post_message`. Identity comes from the server seat. Arguments that name
  `seat_id`, `host_id`, or a URL are rejected.
- Profiles `web-seat`, `workstation-agent`, and `core-operator`.
- Upstream ids come from a fixed allowlist. `example-memory` maps to
  `https://example.invalid/integrity-seats`. A raw URL is rejected. Memory
  owned by another seat is marked `trust=untrusted_peer_memory`.
- Shared-core seats, namespace checks, a seat-scoped bus, fenced mesh claims,
  one-time GO checks, host transports, and enrollment. An existing single-user
  or silo tree stays as it is until `integrity-seats migrate from-single-host`.
- Team docs: `docs/QUICKSTART_TEAM.md`, `docs/HOWTO_OPENAI_TUNNEL_SEATS.md`,
  `docs/MIGRATION_INTEGRITY_SEATS.md`, and `examples/two-seat/README.md`.
  Placeholders are `<CORE_HOST>`, `<YOUR_SEAT_ID>`, and `example.invalid`.
- Adapter SDK, client memory, memory plane, and space dependency bounds accept
  Guardian 7.0.0. Component config files still declare `guardian_version`
  `6.1.0` because that is the configuration contract those loaders check.

Existing search and fetch handlers are unchanged.

## Known limitations

- Mode B (a personal tunnel plus `X-Integrity-Seat-Token`) is optional and
  unverified against current OpenAI tunnel rules. Mode A remains the documented
  team path. This repository does not ship a tunnel client or a live address.
- Cross-machine memory uses `integrity-remote`: an OpenSSH forced command, one
  key per device, a pinned host key and immutable releases, with no new
  listener. Its two-machine test runs the real Memory MCP server through a
  loopback `sshd` with a synthetic producer, so it does not replace a live
  Codex/Claude/Antigravity owner acceptance. See
  [docs/CROSS_MACHINE_QUICKSTART.md](docs/CROSS_MACHINE_QUICKSTART.md). The
  bus, seats hub and mesh remain local-process and loopback tests, not a claim
  that two production machines coordinate.
- No production readiness claim. The public suite does not enroll a host, grant
  action authority, or certify a deployment.
- macOS is not supported yet. Its CI job is informational and shows known
  failures in Linux `/proc` custody (Toolzs authority ledger, Seed runtime
  recovery).
- Codex and Antigravity have no live acceptance of the admission-first gate.
- Installed packages report version 7.0.0.

## Install

Follow the [public beta quickstart](README.md#public-beta-quickstart) and
[team quickstart](docs/QUICKSTART_TEAM.md) from a clean virtualenv. Confirm
`guardian version --all` and the read-only MCP walkthrough before creating
seats.

## Rollback

The previous release in this repository is `v7.0.0`
(`git checkout v7.0.0`). Keep your existing install, and a copy of any
seat registry or Action Log you created, until the new install passes your
checks. This release does not migrate those files backward.
