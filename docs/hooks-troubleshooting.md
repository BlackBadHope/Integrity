# Integrity hooks: scope, enforcement and "memory offline"

Integrity memory reaches a model only through client hooks. This page explains
where the hooks apply, what they enforce, and what to do when a session says
memory is unavailable. Run `integrity-doctor` first: it answers most of the
questions below in one read-only pass.

```bash
integrity-doctor                      # hooks, MCP registrations, server probe, coverage
integrity-doctor --project ~/work/app # check another folder
integrity-doctor --no-probe --json    # no process started, machine-readable
```

`integrity-doctor` reads vendor settings files, starts the registered memory
transport once (`initialize`, `tools/list`, one read-only
`integrity_turn_memory_coverage` call) and reads the local turn log. It writes
nothing and appends no event. Exit code 1 means it has findings.

## Where the hooks apply

| Client | Generated file | Scope | Applies to every folder after |
| --- | --- | --- | --- |
| Claude Code | `claude-workspace/.claude/settings.json` | project | merging the hooks into `~/.claude/settings.json` and the MCP entry into `~/.claude.json` |
| Codex | `codex-workspace/.codex/hooks.json` | project (trusted folder) | merging into `$CODEX_HOME/hooks.json` and `$CODEX_HOME/config.toml` |
| Antigravity | `antigravity-plugin/hooks.json` | user (plugin) | copying to `~/.gemini/config/plugins/integrity-native/` and enabling it |

A project `.claude/settings.json` covers sessions whose project folder is that
folder only. Sessions started anywhere else run **without Integrity memory and
without any warning**. `integrity-native-profile` prints the generated path and
its scope; `integrity-doctor` reports `hooks are project-scoped only` when the
admission hook (`UserPromptSubmit`) exists only at project scope.

## The turn-close guard

Each owner turn should end with `integrity_turn_memory_close` (`events` for the
events appended in that turn, otherwise `no-event` with an honest reason). The
`Stop` hook checks this:

- A turn that changed state (file edits, shell commands, MCP tools whose name
  says they write, `integrity_append_event`) and was not closed is **blocked
  once**. The model gets the exact call to make: the `registration_id` to close,
  or the `turn_ref` to admit first if admission was skipped.
- The next stop is never blocked (the harness's `stop_hook_active` or the
  per-turn marker). The hook then records the coverage gap, as before, and says
  so to the operator. A turn cannot loop.
- A close counts only when its terminal receipt for the current registration
  came back. A close moved to the background stays pending until the hook's own
  lifecycle check sees the receipt.
- Read-only turns are not blocked; they may close with `no-event`. Code
  execution wrappers (`exec`, `functions.exec`) count as possible writes.
- Harness notifications, peer/cross-session events and subagent stops are exempt,
  except a notification that arrives before an owner turn stopped. That turn
  continues the owner's work and keeps its state change, and the Claude hook
  records a `reconciliation` gap for the registration it cuts off.
- `integrity-doctor` counts turns blocked once and state-changing turns closed
  with `no-event`; such a close is accepted because a shell call may only read.
- When nothing can be closed (admission failed or the `turn_ref` expired), the
  guard only reports.

Modes, in precedence order:

1. `INTEGRITY_TURN_CLOSE_ENFORCEMENT=block|advise|off` in the client's environment.
2. `turn-guard.json` next to the hook state (`{"enforce_turn_close": "off"}`).
   Native profiles write it with `block`; `integrity-native-profile --turn-guard advise`
   or `off` changes that at build time. The file is not pinned, so editing it is safe.
3. Profiles started through the `integrity-client-memory` launcher (the
   `integrity-seats` plugin) default to `block`.
4. Everything else, including older direct installs, defaults to `advise`: the
   missing close is shown to the operator at the end of the turn, nothing blocks.

On Linux user-custody profiles the guard only advises: the Native head is
published as completed before `Stop` runs, so a continued turn would have no owner.

## "Memory offline", "admission skipped" and friends

When the model does not call `integrity_context_admission_current_turn` for two
or more owner turns in a row, the `UserPromptSubmit` hook says why, from
evidence rather than a guess:

| Notice | Evidence | What to do |
| --- | --- | --- |
| `INTEGRITY ADMISSION SKIPPED` | An Integrity tool answered in this session, the hook's own lifecycle call reached the server in the last 10 minutes, or the hook's probe did | Nothing is broken. Do not reconnect or restart; the model must call admission. If it keeps skipping, enable the guard (`block`). |
| `INTEGRITY MEMORY UNREACHABLE` | The MCP broker recorded a startup failure, or the hook's probe, made for this notice, was refused twice. The probe is one read-only `integrity_turn_memory_coverage` call through the registered transport, so a local broker alone does not count. A timeout is never this evidence, because a cold broker start can take more than 30 s. A failed probe is shown only in the turn it was made, and a later real answer supersedes it | Run `/mcp` and reconnect the Integrity server, or restart the session. The notice quotes the failure. |
| `INTEGRITY ADMISSION NOT CALLED` | Neither of the above is known yet. This includes a probe that timed out or was refused only once, which the notice quotes | Check `/mcp`. If the Integrity server is listed as connected, just call the tool; reconnect only if it is missing or failed. |

The probe runs at most once every 10 minutes, only when the session has no
other evidence, and never in harness notification or peer-event turns. It has a
50-second budget, so it covers a cold broker start (31-38 s measured), and it retries once after
a refusal but not after a timeout. Turns without admission have no turn-memory registration, so
nothing from them is remembered.
