# Native lifecycle hooks on Linux

[Documentation](README.md) · [Project README](../README.md)

This page covers the **Linux user-custody** Native profiles for Codex and Claude
Code: hooks, one-use turn admission and Turn Memory lifecycle for a vendor CLI
that runs as your own user.
Read [Native memory with lifecycle hooks](native-onboarding.md) first. It
describes the owner-operated Memory instance, `upstream.json`, the instance
bindings, and the lifecycle itself; everything there applies here too.

| Client | Linux route | Status |
| --- | --- | --- |
| Codex CLI | user custody, pinned `codex` ancestor | this release |
| Claude Code CLI | user custody, pinned `claude` ancestor | this release |
| Antigravity | observed conversation boundary | unchanged |

## Trust model, plainly

On Windows the owning reader asks the Codex Desktop host. On Linux the generated
hook runner records the Native head that Codex delivered on the hook's stdin
(`session_id`, `turn_id`), and the local broker accepts that head only while it
still runs under the **same live Codex process**:

- same PID and kernel start time as recorded by the hook runner;
- every UID of that process equals yours;
- `/proc/<pid>/exe` resolves to the pinned `codex_executable`, and its SHA-256
  equals the pin taken when the profile was generated.

A process that is not a descendant of that Codex process, a reused PID, a
replaced or upgraded binary, or a different thread ID is refused before any
upstream request. The model never supplies a head.

Claude Code does not deliver a turn ID to hooks. On `UserPromptSubmit` the hook
runner, running under the live pinned `claude` process, mints one random turn ID
and records it with the prompt's SHA-256. This is the same role the delivery
publisher's ledger plays on Windows. Every later event of that session must
come from the same live Claude process, or it gets no turn. The session's
transcript must be its own `<session_id>.jsonl`, owned by you and not writable
by others. Claude persists the transcript asynchronously, so its content is not
a required join.

All profile, state, envelope and lock files are created owner-only: directories
`0700`, files `0600`, refusing symlinks and wider modes on read. Prompts and the
delivered-context descriptor are stored as `private-utf8-base64/v1` inside that
owner-only tree; they are **not encrypted at rest**. This is user custody: root
and any process running as your UID can read or replace them, much like data
protected by Windows DPAPI CurrentUser. For a host where the agent's own shell
must not be able to rewrite this evidence, use a system-custody deployment
(a root-owned reader factory and a Unix owner socket); this public profile does
not install one.

## 1. Install

Prerequisites on Debian/Ubuntu: `git`, `python3` (3.11+), `python3-venv`, and the
Codex CLI installed and signed in through its normal installer. Keep the virtual
environment and every generated profile outside the Git checkout.

```bash
python3 -m venv ~/.local/share/integrity/venv
~/.local/share/integrity/venv/bin/python -m pip install . ./components/integrity-action-log './components/integrity-client-memory[native]'
```

## 2. Pin the Codex executable

Hooks are started by the native Codex binary. Pin the file the kernel actually
runs for that process. A package-manager launcher (for example a Node.js
wrapper) is not that file. With Codex running in another terminal:

```bash
readlink -f "/proc/$(pgrep -n -x codex)/exe"
```

The result must be an absolute regular file that is not group- or
world-writable. Add it to the bindings from the onboarding guide:

```json
{
  "seed_namespace": "...",
  "namespace_fingerprint": "sha256:...",
  "architecture_checkpoint_id": "...",
  "codex_executable": "/absolute/path/to/the/native/codex"
}
```

Profiles without `codex_executable` are refused on Linux.

## 3. Generate, verify and probe

```bash
PY=~/.local/share/integrity/venv/bin/python
mkdir -p ~/.config/integrity/clients     # the parent must exist
OUT=~/.config/integrity/clients/codex-native   # must not exist yet
$PY -m integrity_client_memory.native_install --vendor codex \
  --upstream-json ~/.config/integrity/upstream.json --bindings-json ~/.config/integrity/bindings.json \
  --output "$OUT"
$PY -m integrity_client_memory.native_runtime --profile "$OUT/profile.json" verify
$PY -m integrity_client_memory.native_runtime --profile "$OUT/profile.json" probe
```

`verify` also refuses a profile root that is not owned by you with mode `0700`.
Neither command is a live acceptance.

## 4. Connect Codex

The output contains `codex-workspace/.codex/config.toml` (the `integrity_native`
MCP server) and `codex-workspace/.codex/hooks.json`. Every hook command is the
pinned interpreter running `integrity_client_memory.native_runtime ... hook
<Event>`, quoted for `/bin/sh`. Open that workspace with Codex first, review and
trust the exact hook definitions, then merge the single MCP entry and the hook
definitions into the layer you intend to use, preserving unrelated entries. Do
not run this profile alongside an older Integrity plugin for the same scope.

Expected first turn is the same as on Windows: `UserPromptSubmit` issues one
opaque `turn_ref`; the model calls `integrity_context_admission_current_turn`
once; the hook opens the signed registration; the turn ends with a terminal
receipt, or with a signed coverage gap when none was produced. A missing close
is never turned into an invented no-event.

## 5. Connect Claude Code

Pin the native `claude` executable the same way:

```bash
readlink -f "/proc/$(pgrep -n -x claude)/exe"
```

Add it as `claude_executable` to a copy of the common bindings. The Windows-only
publisher bindings (`claude_session_id`, owner file, ledger, transcript and
publisher) are not used on Linux: one profile serves every session of that
binary under your user. Generate the profile:

```bash
mkdir -p ~/.config/integrity/clients     # the parent must exist
OUT=~/.config/integrity/clients/claude-native   # must not exist yet
$PY -m integrity_client_memory.native_install --vendor claude \
  --upstream-json ~/.config/integrity/upstream.json --bindings-json ~/.config/integrity/claude-bindings.json \
  --output "$OUT"
$PY -m integrity_client_memory.native_runtime --profile "$OUT/profile.json" verify
$PY -m integrity_client_memory.native_runtime --profile "$OUT/profile.json" probe
```

The output contains `claude-workspace/.mcp.json` (the `integrity_native` server)
and `claude-workspace/.claude/settings.json` (the hooks). Try them in an
isolated session first:

```bash
cd "$OUT/claude-workspace" && claude
```

Approve the project MCP server when Claude asks, and check `/hooks` and `/mcp`.
Then merge the single MCP entry and the hook definitions into the settings
scope you intend to use, preserving unrelated entries.

Two Claude-specific guarantees are covered by tests:

- `Stop` and `SubagentStop` only inform (`systemMessage`). They never return a
  blocking decision or `additionalContext`, so Claude does not re-run the turn.
- When ownership cannot be shown for a prompt (no live pinned ancestor, a
  foreign or shared-writable transcript), the prompt still runs. Claude shows a
  notice, no `turn_ref` is issued, and every Integrity Memory call in that turn
  is refused. Unrelated tools are not blocked.

## Updating Codex, rollback and removal

- **Codex or Claude Code upgrade:** the binary hash changes, so heads are no
  longer published and admission fails closed. Generate a new profile into a
  new directory with the new `codex_executable` or `claude_executable`, review
  it, switch the hook/MCP entries, and keep the old directory until the new one
  is accepted.
- **Rollback:** restore the previous hook/MCP entries; the previous profile
  directory is untouched by a new generation.
- **Removal:** remove the hook and MCP entries, then delete the profile
  directory. It holds private prompts and state; delete it like any private file.

## Troubleshooting

| Broker or hook signal | Meaning |
| --- | --- |
| `Linux Codex requires codex_executable` / `Linux Claude Code requires claude_executable` | Add the binding (sections 2 and 5). |
| `Integrity Native ownership unavailable for this Claude turn (...)` | The prompt did not come from the pinned Claude process, or its transcript is not the session's own private file. |
| `Native profile root custody invalid` | The profile root is not yours or not `0700`. |
| `native producer observation unavailable` / `linux_native_vendor_ancestor_missing` | The caller is not running under the pinned Codex process, or Codex was upgraded. |
| `linux_native_executable_pin_changed` | The recorded head came from a different binary than the profile pin. |
| `linux_native_caller_mismatch` | `CODEX_THREAD_ID` names a different thread. |

CI runs the Linux suites on Ubuntu, including a lifecycle test where the test
process plays the Codex or Claude vendor against a disposable real Memory stand.
That is coverage, not a live Codex or Claude Code acceptance.
