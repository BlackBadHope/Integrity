# Local memory on one machine

[Documentation](README.md) · [Project README](../README.md) · [What is verified](STATUS.md)

This is install stage 1: memory for one user, on one computer, shared by the
agents that user already runs. It works on Windows and Linux. You bring the
agent client and its account; Integrity adds a memory server that the client
starts over MCP. No vendor key passes through Integrity.

## What it is and what it is not

Three stores sit in one private folder of your user account:

- a Seed catalog with the events your agents write;
- a Turn Memory store with a signed registration for every turn and a signed
  receipt that says how the turn ended;
- a work-claim log that records who claimed which task.

It is **not** the core write path that the [clean bootstrap](../BOOTSTRAP.md)
and the [cross-machine quickstart](CROSS_MACHINE_QUICKSTART.md) describe:

- **One machine.** Every agent must reach the same folder on this computer.
- **Names are declared, not verified.** An agent says who it is
  (`declared_agent`, `declared_client`, `declared_machine`). Nothing checks it.
- **Signatures show integrity, not identity.** The signing key lies beside
  the data. A valid signature means the record was written by this instance
  and not changed afterwards. Any process of your user can use the key.
- **Claims are not signed.** The claim log is a hash chain: a changed or
  removed entry breaks it, but no key stands behind an entry.
- **No Action Log, no custody ledger, no admission of actions, no production
  authority.** Memory here is context for an agent, never permission to act.

## Install

```bash
git clone https://github.com/BlackBadHope/Integrity.git
cd Integrity
python -m venv ../integrity-venv
```

Activate the environment (`. ../integrity-venv/bin/activate` on Linux,
`..\integrity-venv\Scripts\Activate.ps1` in Windows PowerShell), then:

```bash
python -m pip install .
guardian-local-memory init --client claude-code
```

`init` creates the instance and prints the MCP block for your client. The
block holds two paths from your machine: the Python of this environment and
the instance folder. `--client` accepts `claude-code`, `codex` and
`antigravity`. To print a block again:

```bash
guardian-local-memory config --client codex
```

The instance folder is `%LOCALAPPDATA%\integrity-local-memory` on Windows and
`$XDG_DATA_HOME/integrity-local-memory` (or
`~/.local/share/integrity-local-memory`) on Linux. `--home PATH` or
`INTEGRITY_LOCAL_MEMORY_HOME` selects another folder; it must be empty or
missing, and it must not be inside a clone. On Windows the folder is created
with access for your account only; on Linux with mode 0700.

### Where the block goes

| Client | Put the block here |
| --- | --- |
| Claude Code | `.mcp.json` in the folder where you start `claude`, or a file passed with `--mcp-config` |
| Codex | `.codex/config.toml` in a project you trust, or `~/.codex/config.toml` |
| Antigravity | `.agents/mcp_config.json` in the workspace |

Gemini CLI has no block here: it was not run.

The Codex block ends with `default_tools_approval_mode = "approve"`. With it
Codex calls the tools of this one server without asking you first. A
non-interactive `codex exec` cannot ask, and without the line it refuses
every tool of the server. Remove the line if you work interactively and want
to approve each call.

## Check

```bash
guardian-local-memory doctor
```

`doctor` only reads. It verifies the catalog, every turn signature and the
claim hash chain, and it counts the turns that have no closing receipt (a
warning, not a failure). It exits 1 when a check fails; `--json` prints the
report as JSON.

## How an agent uses it

The server offers eleven tools. Their names start with `lm_`, and none of them
is a tool name of the core. This is on purpose: a Native lifecycle hook
recognises the core's tools by name, and with the same names it would apply
the core's rules to calls of this server.

An agent that writes follows this order:

1. `lm_turn_open` - start a turn; returns a signed `registration_id`.
2. `lm_work_claim` - claim the task. `acquired` means the agent holds
   it; `waiting` means another agent holds it, and `blocked_by` names that
   claim.
3. `lm_append_event` - write a result under the open turn.
4. `lm_work_release` - release the claim and name the result event.
5. `lm_turn_close` - end the turn; returns a signed receipt that
   lists the events the turn wrote.

An agent that continues someone else's work reads first:

- `lm_seed_recall` with `task` returns every event of a task in the
  order written.
- `lm_turn_receipt_by_event` takes one `event_uid` and returns the
  event as written, the declared author, the signed turn it belongs to, how
  that turn ended (a signed receipt, a recorded gap, or never closed) and the
  claims of that turn.
- `lm_work_claims` returns the claim log and verifies its hash chain.
- `lm_turn_coverage` counts opened, closed and unclosed turns.
- `lm_turn_gap` records, signed, that a turn had no closing
  receipt when the agent looked. It does not close the turn.

`lm_capabilities` returns the limits listed above.

A turn that was closed cannot be written to again. An `event_uid` that already
exists is accepted only with identical content.

## Remove

```bash
guardian-local-memory uninstall          # says what would be removed
guardian-local-memory uninstall --yes    # removes the instance folder
python -m pip uninstall integrity-guardian
```

`uninstall --yes` deletes every event, receipt and claim of the instance. It
refuses a folder that is not a local memory instance. Remove the MCP block
from your client's configuration yourself.

## What is verified

- `tests/test_local_memory.py` runs in public CI on Ubuntu and Windows with
  Python 3.11 and 3.12. It drives the server through its MCP dispatcher: three
  agents on one task, the third reading what the second wrote, claimed and
  how it closed; the second breaking off without closing; refusals; two server
  processes on one folder over real stdio.
- CI also runs `init`, `doctor` and `uninstall` with the installed command on
  both systems.
- Once, on 13 Nov 2026: Claude Code 2.1.318 on Windows 11 ran against this
  server, installed as this page says. Three processes took the roles of
  three agents; a second run had the second agent stop early. The
  [demo](../demo/README.md) has the commands, the prompts and the records.

Not verified:

- Any client other than Claude Code. The blocks for Codex and Antigravity have
  the format of the [read-only example](../examples/local-memory/README.md),
  which lists what was run with each client there; they were not used with
  this server.
- A real agent client on Linux.
- Several agents writing at the same moment. The stores serialize writes, and
  the tests write from one process at a time.
- macOS. Gemini CLI.
