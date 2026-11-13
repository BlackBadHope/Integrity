# integrity-codex-persistent

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

An asyncio supervisor that attaches to one Codex app-server turn that a host has already
started and admitted. It watches the turn's events, enforces a deadline and a token budget,
checks owner controls, and sends `turn/interrupt` when the turn must stop. It is for host
developers who run Codex app-server turns with the `persistent` reasoning effort.

## Status

- Version `0.1.0rc3`, a release candidate.
- Python 3.11 or newer. No runtime dependencies.
- Optional and disabled by default: `Supervisor` refuses a `JobPolicy` with `enabled=False`.
- No console script and no command-line interface. It is a library only.

## What it does

The package has three modules.

**`policy.py`**

- `JobPolicy(model, role, enabled, finite_effort, supported_efforts)` turns on the
  `persistent` effort only for the `worker` role and only when the model lists `persistent`
  among its supported efforts. `overrides()` returns config values for the host to merge:
  model, effort, native multi-agent and goals off, `approval_policy` `never`, `sandbox_mode`
  `read-only`.
- `Binding(job_id, thread_id, turn_id, snapshot_id, control_generation)` names the exact turn.
- `Budget(deadline_epoch, max_tokens, used_tokens, thread_baseline_tokens, ...)` holds the
  mission deadline and token budget. Defaults: 10000 events, 0.25 s control poll, 2 s stop
  grace.
- `ControlView(generation, state, snapshot_id)` is what the host's control reader returns.
  `state` is `ACTIVE`, `PAUSED` or `STOPPED`.

**`connection.py`** — `JsonlConnection(reader, writer, max_frame_bytes=65536)` reads and writes
JSON-RPC lines on streams the host already owns. Frames are 1 KiB to 1 MiB; the
`StreamReader` limit must not exceed the frame bound. Duplicate keys, non-finite numbers and
envelopes that mix request, response and notification fields are rejected.

**`supervisor.py`** — `Supervisor(binding, budget, policy).run(connection, control)`:

- Requests an interrupt on deadline, token budget, owner `PAUSED` or `STOPPED`, a changed
  control generation or snapshot, an unavailable control reader, transport EOF or a protocol
  error.
- Sees only the bound thread and turn. A server request for another turn is not answered; it
  is a protocol error. Approval and elicitation requests for the bound turn are declined, and
  the turn is stopped for host action.
- Treats `turn/completed` with status `completed`, `interrupted` or `failed` as the end. A
  final answer item, plan, tool result or interrupt acknowledgment is not completion.
- Stops the turn for re-admission after context compaction, model rerouting or an unknown
  item type. Native subagent items also stop it and mark runtime reconciliation as required.
- Runs once per instance and returns a content-free `Observation`. `cleanup_required` stays
  true when no matching terminal event arrived. `usage_is_lower_bound` is always true;
  `independent_acceptance` and `replay_allowed` are always false.
- On task cancellation it tries one interrupt, keeps `last_observation` and re-raises.

## Install

Install from source as described in [BOOTSTRAP.md](../../BOOTSTRAP.md#install-functional-components):

```bash
python -m pip install ./components/integrity-codex-persistent
```

## Use

The host starts and initializes the app-server, starts and admits the turn, and supplies a
control reader. Then:

```python
from integrity_codex_persistent.connection import JsonlConnection
from integrity_codex_persistent.policy import Binding, Budget, JobPolicy
from integrity_codex_persistent.supervisor import Supervisor

policy = JobPolicy(model=model_id, enabled=True, supported_efforts=model_efforts)
supervisor = Supervisor(
    Binding(job_id, thread_id, turn_id, snapshot_id, control_generation),
    Budget(deadline_epoch=deadline, max_tokens=token_budget,
           used_tokens=used_so_far, thread_baseline_tokens=thread_usage),
    policy,
)
observation = await supervisor.run(JsonlConnection(reader, writer), read_owner_state)
record = observation.as_dict()   # store it in the host's own journal
```

`read_owner_state` is an async callable that returns a `ControlView` from the host's control
plane. It must not call a model and must not block.

## What is verified

- Public CI builds this distribution as a wheel, checks the wheel contents and installs it
  together with all other distributions (`pip check`) on Ubuntu and Windows with Python 3.11
  and 3.12.
- There are no behaviour tests: the component has no `tests/` folder, and no test elsewhere in
  the repository imports it.

## What is not verified

- Every behaviour described above is read from the source code only.
- Use against a real Codex app-server or a real account.
- Interrupt and cleanup races, and recovery after a crash.

## Limits

- It never starts, resumes or kills a process, never creates a thread or turn, and never runs
  a tool. Only `turn/interrupt` and refusal or error responses are sent.
- The token guard is based on usage notifications and can overshoot. It is not a spending cap.
- An interrupt acknowledgment does not prove that the turn or its children stopped. The host
  must clean up and reconcile.
- A read-only sandbox setting does not by itself restrict writes made through external MCP
  servers.
- Callbacks that block the event loop cannot be pre-empted; the host still needs its own
  process watchdog.

## License

Business Source License 1.1. See [LICENSE](LICENSE) and the project [NOTICE](../../NOTICE).
