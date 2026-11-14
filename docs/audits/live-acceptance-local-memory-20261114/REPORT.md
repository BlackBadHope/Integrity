# Live acceptance: local memory with Claude Code on a fresh install, 14 Nov 2026

[Documentation](../../README.md) · [What is verified](../../STATUS.md) · [The demo](../../../demo/README.md)

**Scope.** One manual run of the [demo](../../../demo/README.md) with a real
model, on a fresh clone and a fresh install. It covers the local memory
profile (`guardian-local-memory`, install stage 1, one machine) with Claude
Code. It does not cover the core write path, Codex, Antigravity or Linux.
Mark: **once**.

## Setup

| Item | Value |
| --- | --- |
| Source | fresh clone of `main` at `194101d` |
| Install | new virtualenv outside the clone, `python -m pip install .` (17 s) |
| Package | `integrity-guardian 7.0.0` |
| Machine | Windows 11, Python 3.12.10 |
| Agent client | Claude Code 2.1.318, model Haiku, the user's own account |
| Commands | the three `claude -p --mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__integrity_local_memory` commands of the [Quick start](../../../README.md#quick-start), prompts `demo/prompts/agent-a.txt`, `agent-b.txt`, `agent-c.txt` |
| Duration | about 55 s for the three agents |

The client version and the model were reported by the person who ran it. They
are not in the records below.

## What the agents did

- A wrote `Result: 2` (event `client:demo-task-agent-a-result-001`, 09:16:27Z),
  with a claim of `task:demo-task` that got fence token 1, and closed its turn.
- B wrote `Result: X` (event `client:local-cbee7cd6a1424024b084b5c192c37e07`,
  09:16:45Z), claim with fence token 2, released, turn closed.
- C, asked to continue without asking B, answered from memory alone. Its
  four answers, quoted from its reply:
  1. A wrote `Result: 2`, then B wrote `Result: X`, with both event IDs and times.
  2. The last writer declared itself as `agent-b`, client `claude-code`,
     machine `local-machine`; C added that this identity is declared and not
     verified, and that the signatures show only that the records were not
     altered.
  3. B's claim was acquired with fence token 2 and released with its result
     event; A's claim, fence token 1, was released before it.
  4. B's turn closed with a signed receipt (both signatures valid) that lists
     one event, `event_id 3`; no gap was recorded.

## What the instance shows afterwards

`guardian-local-memory doctor` on the instance after the run, read only:

| Check | Result |
| --- | --- |
| events | ok: catalog verified, 3 events (the instance record and the two results) |
| turns | ok: 2 turns, 2 closed, 0 without a closing receipt; signatures valid |
| claims | ok: hash chain verified, 4 claim events (acquired 1, released 1, acquired 2, released 2) |
| doctor | PASS |

## Limits

- B also ran in Claude Code. A run with B in Codex CLI is the [recorded run of
  13 Nov 2026](../../../demo/README.md#the-records), made on the recording
  machine, not on a fresh install.
- C only read; it did not open a turn of its own, so the instance holds two
  turns, A and B.
- The run kept the agents' final replies, not the `--output-format stream-json`
  transcripts, so it cannot be replayed by `tests/test_demo.py` the way the two
  recorded runs are.
- One run, one machine. A model may take other steps than these.
