# integrity-client-memory

## Status notices without false alarms (1.11.1)

`MEMORY UNREACHABLE` now needs a broker start failure, or a fresh probe, run
for this notice, that the server refused twice. A probe timeout (a cold broker
start took 31-38 s over SSH) is inconclusive and yields
`ADMISSION NOT CALLED`. A cached failure is never shown again. A recent
successful lifecycle call of the hook itself counts as an answer, so no probe
runs. Notification turns get no notice and no probe.

## Turn-close guard, status notices and `integrity-doctor` (1.11.0)

`turn_guard.py` holds the shared, stdlib-only decisions used by the Claude
standalone hook (`claude/admission`), the `integrity-seats` plugin hooks
(`windows/admission`, `linux/admission`) and the Native cohort hook
(`windows/native/integrity-client-admission.py`):

- **Stop guard.** A top-level `Stop` after a turn that attempted a state change
  (Edit/Write/NotebookEdit/apply_patch, any shell tool, MCP tools whose name
  says they write, `integrity_append_event`) and observed no
  `integrity_turn_memory_close` returns `{"decision": "block", "reason": ...}`
  once per turn generation. The reason names the `registration_id` to close, or
  the `turn_ref` to admit first. Under `stop_hook_active`, or after the one
  block, the turn ends and the existing gap recording runs. Harness
  notifications, peer events and `SubagentStop` are exempt. Linux user-custody
  profiles only advise.
- **Mode.** `INTEGRITY_TURN_CLOSE_ENFORCEMENT` (`block`/`advise`/`off`), then
  `turn-guard.json` (next to the hook state; Native profiles write it with
  `block`, `integrity-native-profile --turn-guard` changes it), then the
  launcher default (`block` for profiles started through `integrity-client-memory`),
  then `advise`.
- **Status notices.** After two owner turns without admission the
  `UserPromptSubmit` hook says `ADMISSION SKIPPED` when an Integrity tool or the
  hook's own read-only coverage call answered in this session, `MEMORY UNREACHABLE` only when the
  probe or the broker start failed, and `ADMISSION NOT CALLED` otherwise. The
  old "most likely not connected ... reconnect" guess is gone.
- **Local turn log.** `turn-guard-log.jsonl` (last 500 turns, diagnostic, no
  prompt text) feeds `integrity-doctor`.

`integrity-doctor` (also `python -m integrity_client_memory.doctor`) lists
Integrity hooks by vendor and scope, the MCP registrations, probes each
referenced transport (`initialize`, `tools/list`, read-only
`integrity_turn_memory_coverage`) and summarizes the turn log. See
[hooks troubleshooting](../../docs/hooks-troubleshooting.md).

`integrity-native-profile` now prints the generated hook file, its scope and
how to apply it to every folder.

## Canonical Windows recovery cohort (1.9.4)

The reviewed Windows broker resource is the sole implementation source.
`broker_adapter.py`, `recovery_client.py` and `operation_ledger.py` are its
shared recovery modules. `broker_bundle.render_windows_broker()` freezes their
exact source bytes and records their hashes; Native Codex compilation uses the
same renderer. It no longer chooses the older Native envelope without resume
methods. Hook version pairing, the complete tools contract, Native head checks,
protected state custody and signed registration joins remain required.

`python -m integrity_client_memory.broker_bundle --output NEW_DIRECTORY
--bindings-json OWNER_BINDINGS.json --upstream-json OWNER_UPSTREAM.json
--tools-json OWNER_TOOLS.json` compiles an isolated profile and its pinned local
runtime support. All three inputs belong to the installer; no installed broker,
historical deployment, maintainer identity or private baseline is read. The
declared Guardian and Action Log distribution dependencies remain prerequisites.
`run-native-profile.py --profile profile.json probe` checks local entrypoints
without starting upstream. Compilation changes no active configuration.

Only an authenticated successful current `open` explicitly reporting
`session_recovery.available=false` with reason `admission-not-retained` may
continue through the original broker path. Its signed registration, complete
current Native subject, prompt and admission must still match, on the same
transport. A corrupt, missing or superseded recovery descriptor is never this
opt-out. Lost responses preserve uncertainty and never trigger a cross-path
retry. The state directory comes from pinned owner configuration; an
environment value may agree with it but cannot redirect it.

Linux, Windows Remote, Claude and Antigravity retain their separate broker
families and platform guards. Source checks and fake routing fixtures do not
establish live Native or SSH acceptance. Published 1.9.1 artifacts and historical
deployment receipts remain unchanged.

Windows and Linux Codex hooks/brokers, Claude admission, Antigravity conversation-bound broker, and common opaque turn envelopes. Distribution revision is 1.9.4; admission hook revisions remain 1.8.0 / 1.8.0-linux.5 and broker wire families remain Windows 1.6.0, Linux 1.6.1-linux.7, Antigravity 1.4.1. They are distinct implementations, not version aliases. Native ownership adapters require fresh install-time bindings; absent adapters must fail closed, never fabricate session identity.

## Linux lifecycle repair

Slow Native ownership proofs execute outside the shared custody lock. One-use
consumption, claim expiry and final state comparisons remain under the lock.
The shared MCP process verifies the original private producer's exact Native
thread and turn without manufacturing a per-thread environment identity.
Runtime failures expose bounded static codes, message digests and safe frame
names, never arbitrary exception text or prompt content.

`generation_navigation.render_config()` is a pure helper for adding an inert
generation navigation field to a caller-owned config. Supply your own exact
preimage digest, generation, Python command and broker script. It preserves
unrelated bytes and rejects foreign drift. Applying the result and requesting
the normal MCP refresh remain separate owner actions; importing or calling the
renderer performs neither action.

## Installation and configuration

Install this distribution and its declared dependencies into your own environment.
Importing `integrity_client_memory` starts no process, opens no database and connects to no host.
`integrity-client-memory --list` lists preserved entrypoints without importing their resources.

Copy `configuration.example.json` outside the source installation, supply your own
values, then set `configured` to `true`. Templates are deliberately disabled.
`CONFIGURATION-VALUES.json` lists the source locations requiring paths, endpoints
or commands. Values have no maintainer defaults. Keep credentials in your own
credential store or environment, never in published configuration.

```text
integrity-client-memory --config /absolute/path/to/own-config.json --preflight
integrity-client-memory --config /absolute/path/to/own-config.json ENTRYPOINT [its arguments]
```

The launcher uses a fresh subprocess per profile so private top-level names cannot
collide with other installed components. It does not install hooks, register MCP,
mint identity, initialize databases, start background processes or contact services
until an explicit entrypoint is launched with owner configuration. A configured
entrypoint can have its documented service/database/network effects.

Configuration environment variable: `INTEGRITY_CLIENT_MEMORY_CONFIG`. Original script CLI arguments still
apply (e.g. a native profile's upstream TOML and tools contract). The public server
contract is Guardian 6.1.0 / memory MCP API 2.11.0. Profile revisions remain separate.

`SOURCE-MAP.json` preserves source coverage and copy hashes. Existing source tests
are in `legacy-tests`; datasets or deployment-specific fixtures are not synthesized.
These files provide source coverage, not proof of live multi-host acceptance.

## License

Business Source License 1.1 from v7.0.0-beta.4 (earlier releases Apache-2.0); see LICENSE and NOTICE. No user memory, event corpus, enrollment, private
keys, service configuration, retained session state or live deployment pins are included.

## Fresh catalogue and Native source pins

`python -m integrity_client_memory.profile --tools-json OWN_TOOLS.json --output NEW_DIRECTORY`
validates the actual owner-selected tools/list catalogue, preserves its schemas
and annotations and computes its exact digest. The sole bundled catalogue is the
current public memory API2.11 surface; older personalized copies are not retained.
The compiler emits source-derived Native pins and leaves identity, upstream,
project scope and Native owner bindings unset. It refuses an existing directory.

Linux Native custody requires an explicit native_owner_uid, native_daemon_directory,
native_home_parent and native_home_mode. The peer UID must equal both that chosen
owner and the actual process UID. A non-1000 owner is supported; any UID is not an
admission. No pre-enrolled Native subjects or room/session bindings are shipped.

Local runbook navigation defaults to paths:[]. Optional owner_local_catalogue
configuration names an absolute private file, its exact SHA256 and host_id.
POSIX private ownership or Windows SID-based ACL custody and digest/readback are
checked before the existing Navigator route/Native/closure validation. This is
navigation data and never grants target-action authority or executes a recipe.

The immutable-generation launcher is preserved at common/generation_launcher.
Cross-platform scope capture is preserved at common/integrity_scope_synapse,
with scope.ps1/scope.sh wrappers calling the installed public entrypoint. The
complete Linux scope profile additionally retains its sanitized, digest-bound
frozen modules. These are distinct profile implementations, not a live registration.

Preflight validates configuration header/version only; it reports runtime_bindings_verified:false. Complete owner bindings and an explicit entrypoint are still required before runtime use.

Scope wrapper setup must select its harness explicitly: `scope.sh EVENT codex` or `scope.sh EVENT claude`; PowerShell uses `scope.ps1 -Event EVENT -Harness codex` (or `claude`). Both forward --harness to the shared scope parser.

## Weekly Windows source profiles (2026-10-20)

Revision 1.8.2 adds two explicit source entrypoints. Existing Linux and default
Windows broker profiles retain their implementations. No hook or service is
installed, no host is enrolled and no saved state is migrated by this package.

- `windows/native_scope` ships the managed Windows Native/SCOPE selector and its
  protected adapter sources. Compaction reads one turn per page, at most 30 pages,
  retaining the 15-second observation deadline and rejecting truncated, duplicate
  or foreign evidence. Safe diagnostics preserve the last 8 failures and observed
  callbacks without raw errors or prompts. The publisher diagnostic session is
  disabled. The entrypoint rejects non-Windows execution.
- `windows-remote/integrity-client-turn-broker` preserves the separate remote
  Windows broker family 1.4.1. Nested upstream work shares one 180-second public
  request budget; cold initialization can use 45 seconds. An owner choosing this
  profile should allow at least 210 seconds at the outer MCP client boundary.

All source paths, pins and runtime bindings must be supplied in the owner
configuration. The generated profile includes hashes of the packaged Windows
Native sources; those hashes describe source bytes and grant no activation.
Live credentials, transport enrollment, machine settings and historical memory
records are deliberately absent. Local fake-IPC tests establish source behavior;
a new installation still needs its own lifecycle acceptance.

## Complete Native client profiles

`integrity-native-profile` generates private, source-pinned Codex, Claude CLI
and Antigravity MCP/hook registrations from an owner-selected server and real
Native bindings. See the [complete Native onboarding guide](../../docs/native-onboarding.md)
for installation, lifecycle behavior, paused-provider verification and rollback.
`native_runtime verify` checks exact source/configuration bytes; `probe` imports
the real entrypoints without calling a model. Both remain distinct from live
acceptance. The original header-only launcher preflight retains its original
meaning.
