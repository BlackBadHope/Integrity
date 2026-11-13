# integrity-resource-advisor

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

Deterministic, advice-only help for choosing a model, reasoning effort and speed for one
stage of a task, from calibration data, cost intervals and usage that the caller supplies.
It also contains small read-only tools that collect Codex usage and rate-limit data. It is for
operators and host developers; it never calls a provider and never changes a model setting.

## Status

- Version `0.1.0rc6`, a release candidate.
- Python 3.11 or newer. No runtime dependencies.
- Optional. Importing the package performs no I/O.
- `advise_from_guardian` and `verify_from_guardian` import
  `integrity_guardian.model_router` when called, so they need Guardian installed. Guardian is
  not a declared dependency; `advise` and `verify_advice` work without it.
- There is no HTTP listener, dashboard or daemon.

## What it does

`advise(...)` takes a `Stage`, `Candidate`s (configuration, token and cost intervals,
latency), `Calibration`s, a usage summary, a `Budget`, a `NativeView` of the native routing
decision and an `AdvisoryPolicy`. It returns a JSON-ready document with one status:

| Status | Meaning |
| --- | --- |
| `RETAIN` | Keep the current choice: not enough benefit, or no meaningful boundary. |
| `RECOMMEND` | A feasible, evidence-supported alternative. Not an observed switch. |
| `BASELINE_NEEDS_EVIDENCE` | A feasible baseline without a quality pass or a saving claim. |
| `NATIVE_BASELINE` | The mandatory native model and effort are kept. |
| `NATIVE_PENDING`, `NATIVE_BASELINE_UNAVAILABLE` | Native policy is pending, or its baseline does not fit the supplied resources. |
| `USAGE_UNKNOWN`, `RECONCILE_REQUIRED` | Usage is missing, or a sent operation has an unknown outcome. |
| `BUDGET_CONFLICT`, `NO_SUPPORTED_CHOICE` | Resources conflict, or no option is supported. |

Rules confirmed in the code and its demo:

- Quality qualification comes before cost. Sparse, stale, wrong-scope or synthetic evidence
  cannot justify a cheaper choice.
- Calibration is bound to the workload, including a four-part complexity assessment.
- Token counters are normalized so that cached input and reasoning output are not counted
  twice. Missing counters are unknown, not zero.
- Usage is summed over all leaf calls of the root task, including failed calls and children.
  Exact duplicates are merged; conflicting records are rejected.
- Costs use one explicit unit. There is no conversion between API charges and subscription
  quota.
- `verify_advice` recomputes the advice from fresh inputs and refuses it when the stored
  document differs, with exact type comparison.

`advise_from_guardian` recomputes the native route once from the full registry with
`integrity_guardian.model_router.route_model`, returns the native receipt unchanged and keeps
a mandatory native choice even when another candidate is cheaper.

Read-only Codex tools:

- `app_server_snapshot` (the `integrity-codex-read-snapshot` script) starts one
  `codex app-server` child over stdio with MCP servers, hooks, notify and analytics turned
  off for that child. It sends only `initialize`, paged `model/list` and
  `account/rateLimits/read`, and prints the model catalogue and rate limits. Missing limit
  values stay unknown.
- `rollout_usage` (the `integrity-codex-rollout-usage` script) reads one local Codex
  rollout file up to a byte boundary fixed before the read, checks that its
  `session_meta.id` matches `--thread-id`, and prints counters, completeness and a snapshot
  digest. With `--checkpoint` and `--pin` it continues from an
  earlier snapshot. It reads no other session.
- `codex` (the `integrity-codex-telemetry` script) projects a captured app-server
  notification stream (JSONL from a file or stdin) onto explicit thread baselines.

## Install

Install from source as described in [BOOTSTRAP.md](../../BOOTSTRAP.md#install-functional-components):

```bash
python -m pip install ./components/integrity-resource-advisor
```

Add `.` (Guardian) to the same command if you use `advise_from_guardian`.

## Use

```bash
integrity-resource-advisor --demo
integrity-codex-read-snapshot --codex /path/to/codex --timeout 30
integrity-codex-rollout-usage --rollout /path/to/rollout.jsonl --thread-id THREAD_ID \
  [--checkpoint previous.json --pin DIGEST]
integrity-codex-telemetry --bindings bindings.json [--events capture.jsonl]
integrity-codex-telemetry --checkpoint previous.json --pin DIGEST [--events capture.jsonl]
```

`--demo` prints synthetic scenarios only (`"synthetic": true`, `"measured_savings": null`).
Without `--demo`, `integrity-resource-advisor` prints its help. The telemetry and rollout
tools exit 2 on rejected input.

From Python:

```python
from integrity_resource_advisor import advise, verify_advice
from integrity_resource_advisor import advise_from_guardian, verify_from_guardian
```

The caller supplies every input. Nothing is discovered automatically.

## What is verified

- Public CI runs the tests in `tests/` on Ubuntu and Windows with Python 3.11 and 3.12. They
  cover:
  - every module imports without opening a socket or starting a process, and the package
    version is `0.1.0rc6`;
  - the synthetic demo runs without network or processes, reports no measured savings, and
    an unknown outcome yields `RECONCILE_REQUIRED`.
- `tests/run_suite.py` runs the same tests with `unittest`, from source or (with
  `--installed`) against the installed package.

## What is not verified

- The advice rules beyond the demo scenarios. No test checks the individual statuses.
- `advise_from_guardian` with real Guardian objects.
- `app_server_snapshot`, `rollout_usage` and `codex` against a real Codex binary or real
  rollout files.
- Any measured saving from following the advice.

## Limits

- Advice only. It is not an authorization, and it has no dispatch callback. Do not edit
  `selected_model` in the returned native receipt to apply advice.
- Default thresholds are adjustable parameters, not rules for every task.
- The caller's measurement sources are not authenticated.

## License

Business Source License 1.1. See [LICENSE](LICENSE) and the project [NOTICE](../../NOTICE).
