# Example: two-session tasks that need memory

Six small coding tasks, `T1` to `T6`. Each one is given to an agent in two
separate sessions. The second session can only be done right if the agent
still knows what the first session decided.

This is an **example** of how such a task set is built. It is not a hidden
benchmark: the reference solutions and the tests are published here, so a
model may have seen them. No measurements are included.

## How a task works

| File | Who sees it | What it is |
|---|---|---|
| `README.md` | the agent | The task in one paragraph |
| `solution.py` | the agent | A stub with the public API |
| `_private/S1.txt` | the agent, session 1 | Part 1, plus facts and decisions needed later |
| `_private/S2.txt` | the agent, session 2 | Part 2; it refers to session 1 and does not repeat it |
| `_private/assessment.json` | the harness | Which facts exist only in session 1 |
| `_private/oracle.py` | the harness | A reference solution |
| `hidden_tests/test_solution.py` | the harness | The tests that decide success |

A harness copies the task folder for the agent without `_private` and
`hidden_tests` (`copy_exclusions` in `assessment.json`), sends `S1.txt`,
starts a new session, sends `S2.txt`, and then runs the tests against the
agent's `solution.py`.

| Task | What session 2 must remember |
|---|---|
| `T1` | An export format that was agreed in session 1 |
| `T2` | The root cause found in session 1 while investigating a fault |
| `T3` | A customer constraint told only in session 1 |
| `T4` | A decision that was cancelled in session 1 and must not come back |
| `T5` | A migration contract told only in session 1 |
| `T6` | Nothing: a control task, the whole contract is in its `README.md` |

`T6` shows how much of a result comes from the task itself and not from
memory.

The task texts are in Russian. The code needs Python 3.11 or newer and the
standard library only.

## Run the reference solutions

```bash
mkdir -p /tmp/t1
cp examples/memory-carryover-tasks/T1/_private/oracle.py /tmp/t1/solution.py
cp examples/memory-carryover-tasks/T1/hidden_tests/test_solution.py /tmp/t1/
cd /tmp/t1 && python -m unittest test_solution
```

## What is not here

- **A harness.** The steps above are a description; this folder has no runner
  that drives an agent through the two sessions.
- **Results.** Runs of real agents against these tasks are not published.

## Verified

`tests/test_example_memory_carryover_tasks.py` checks for every task that the
reference solution passes the tests, that the stub fails them, and that
`assessment.json` matches the folder.

## Not verified

- Whether a given agent passes these tasks with or without a memory server.
  That depends on the agent, the harness and the day; no claim is made here.
- Whether the six tasks separate "remembers" from "re-derives" well enough to
  rank memory systems. Six tasks are a demonstration, not a measurement.
