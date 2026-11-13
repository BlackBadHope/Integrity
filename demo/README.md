# Three agents, one task, one memory

[Project README](../README.md#the-demo-step-by-step) · [Local memory](../docs/LOCAL_MEMORY.md) · [What is verified](../docs/STATUS.md)

Agent A writes a result. Agent B writes another one for the same task. Agent C
has to continue and cannot ask B. This demo shows that C gets from memory:

1. what B wrote, word for word;
2. who B says it is (agent, client, machine) and when, and that nothing
   verified those names;
3. what B claimed and whether B released the claim;
4. how B's turn ended: a signed receipt that lists the event, a recorded gap,
   or no end at all.

The agents are yours. You run an agent client that you already have, with
your own account and model. Integrity adds one memory server on your machine;
the client starts it over MCP. No vendor key passes through Integrity, and
this folder holds no script that plays an agent.

## Run it

Install Guardian and create a memory instance as the
[quick start](../README.md#quick-start) shows:

```bash
python -m pip install .
guardian-local-memory init --client claude-code
```

`init` prints an MCP block. Make an empty working folder outside the clone
and save the block there as `.mcp.json`. The commands below are for Claude
Code and run in that folder; `../Integrity` is the path to your clone.

```bash
claude -p --mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__integrity_local_memory < ../Integrity/demo/prompts/agent-a.txt
claude -p --mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__integrity_local_memory < ../Integrity/demo/prompts/agent-b.txt
claude -p --mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__integrity_local_memory < ../Integrity/demo/prompts/agent-c.txt
```

In Windows PowerShell there is no `<`; pipe the prompt instead:

```powershell
Get-Content ..\Integrity\demo\prompts\agent-a.txt -Raw | claude -p --mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__integrity_local_memory
```

- `--mcp-config .mcp.json --strict-mcp-config` gives the agent this memory
  server and no other MCP server.
- `--allowedTools mcp__integrity_local_memory` lets it call the tools of this
  server without asking. It allows nothing else.

Each command is a separate process with no shared conversation. A and B
answer with the `event_uid` they wrote. C answers the four questions above.

For the second run, create another instance in another folder
(`guardian-local-memory init --home PATH --client claude-code`) and give B
[`agent-b-breaks-off.txt`](prompts/agent-b-breaks-off.txt) in place of
`agent-b.txt`. B then stops after writing. C reports a claim that was never
released and a turn that is still open.

Afterwards `guardian-local-memory doctor` verifies the catalog, the turn
signatures and the claim chain, and counts turns without a closing receipt.
`guardian-local-memory uninstall --yes` removes the instance.

## The prompts

| Agent | Prompt | What it asks |
| --- | --- | --- |
| A | [`prompts/agent-a.txt`](prompts/agent-a.txt) | open a turn, claim `demo-task`, write `Result: 2`, release, close |
| B | [`prompts/agent-b.txt`](prompts/agent-b.txt) | the same, with `Result: X` |
| B, second run | [`prompts/agent-b-breaks-off.txt`](prompts/agent-b-breaks-off.txt) | open a turn, claim, write `Result: X`, then stop: no release, no close |
| C | [`prompts/agent-c.txt`](prompts/agent-c.txt) | from memory only, answer the four questions; change nothing |

The prompts for A and B spell out the steps, so the demo does not depend on
how well a model plans. The prompt for C names no tool: C chooses what to
call. It ends with "Answer in English." so that the record reads the same
whatever language your client is set to.

## The records

[`recorded/closed.json`](recorded/closed.json) and
[`recorded/broken-off.json`](recorded/broken-off.json) hold two runs of
13 Nov 2026: Claude Code 2.1.318 on Windows 11, three processes each, model
`claude-sonnet-5-5`. A record keeps, for each agent, the prompt file with its
digest, every call to the memory server with its arguments and its full
result, and the agent's final answer. It keeps nothing else of the client's
output.

The recorded commands were the ones above with five more options:
`--model sonnet`, `--setting-sources project` (the run did not load the
user's own settings and hooks), `--no-session-persistence`, and
`--output-format stream-json --verbose` (the client prints its tool calls, so
a record can be built). They ran in Git Bash.

`python demo/run.py` prints the two records as four scenes; the pictures at
the top of the project README are drawn from them. To build a record from
your own run, keep the client output of each agent and pass the three files:

```bash
python demo/run.py record --client "Claude Code 2.1" --recorded 2026-11-13 --out my-run.json a.jsonl b.jsonl c.jsonl
```

## What was run, and what was not

Run:

- The two recorded runs.
- The same three commands from Windows PowerShell with the pipe form, without
  `--model` (the client's default model) and with `--setting-sources project`.
  A, B and C finished, C gave the four answers, and `doctor` passed.
- `tests/test_demo.py` in CI on Linux and Windows, without a model: it
  replays the recorded calls against a new instance and compares what C
  learns, checks that the published prompts are the ones that were run, and
  checks that the pictures are drawn from the records.

Not run:

- Any client other than Claude Code. The blocks for Codex and Antigravity
  were not used with this server; Gemini CLI has no block.
- A run on Linux or macOS with a real client. On Linux only the test without
  a model runs.
- Agents of two different vendors on one task.
- The commands exactly as printed above, without `--setting-sources project`.
- A killed agent process. In the second run B stops because its prompt says
  so.
- Two agents writing at the same moment.

A model may take other steps than the recorded ones. If C does not call
`integrity_turn_receipt_by_event`, `demo/run.py record` still writes the
record, and `demo/run.py` cannot draw scene 3 from it.

## What it does not prove

This is the [local memory profile](../docs/LOCAL_MEMORY.md): one machine, no
Action Log, no custody ledger, no admission of actions. Names are declared by
the writer. The signing key lies beside the data, so a signature shows that a
record was not changed, not who wrote it. Claims are not signed. Memory here
is context for an agent, never permission to act.
