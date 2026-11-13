# Four scripted scenes: record, recall, one-use grant, missing close

[Project README](../../README.md) · [The demo with real agents](../../demo/README.md) · [What is verified](../../docs/STATUS.md)

A script plays two agents and an owner against the code of this repository.
It needs no agent client, no network, no account and no model. It writes to a
temporary directory and removes it.

This is **not** the demo at the top of the project README. In the demo, agent
clients of the user run and one of them reads from memory what another did.
Here nothing is an agent: `run.py` calls the stores and the checks directly
and prints what they answered. Use it to try two things the demo does not
show: the one-use owner grant and the report of `integrity-doctor`.

## Run it

After the [install](../../README.md#quick-start), from the clone:

```bash
python examples/scripted-scenes/run.py
```

It prints four scenes and exits with 0. If a scene does not behave as the
transcript says, it prints `scenes failed: ...` and exits with 1.

## The scenes

| Scene | What happens | The code that runs |
| --- | --- | --- |
| 1 Record | Agent A appends a decision and closes its turn. The close receipt names the event and is signed. | `SeedCatalog`, `TurnMemoryStore.close_turn`, `verify_turn_terminal_receipt` |
| 2 Recall | Agent B starts a new process and asks the memory server. It gets the event, who wrote it and when, and a recall receipt. | [`examples/local-memory/memory_server.py`](../local-memory/memory_server.py), `integrity_seed_recall` |
| 3 Grant | Agent B presents an intent it signed itself and is refused. The owner signs a one-use grant; it passes once; the repeat is refused. | `IntentCustody.reserve`, `IntentCustody.consume`, `verify_consumption_receipt` |
| 4 Close | Agent B stops without a close. The gap is recorded and signed, and `integrity-doctor` reports 1 of 2 turns closed. | `TurnMemoryStore.observe_gap`, `integrity_client_memory.doctor.probe` |

## What it is not

- No model runs and no agent client runs. The two agents and the owner are
  played by the script. The memory, the receipts and the checks are the code
  of this repository.
- Seed events are not signed, here or anywhere else. In scene 1 the signature
  is on the turn close receipt that names the event.
- Scene 2 is a recall through the read-only memory server of the
  [read-only walkthrough](../local-memory/README.md). The context that a
  hooked client receives at the start of a turn needs the memory core and is
  not shown.
- Scene 3 shows the custody store accepting and refusing signed intents. No
  file is changed: the observed change is given to the store by the script.
- In scene 4 the doctor reads the turn store through a stand-in server with
  one tool (`--serve-coverage` in the script). The full memory server serves
  turn coverage only with a signed write plane.
- The keys are derived from a public string. They protect nothing.

## Verified

`tests/test_example_scripted_scenes.py` runs the four scenes in CI on Linux
and Windows and checks the lines that carry a verdict: the signed close
receipt, the recalled event with its origin, refused / allowed / refused for
the grant, and the coverage line of the doctor.
