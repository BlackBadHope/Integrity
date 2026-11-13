# integrity-active-inquiry

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

An offline planner that picks the next useful question to settle one goal, for example "does
the deployed version match?", from a finite model that the developer supplies. It is meant for
developers who build read-only probing on top of the Guardian Synapse kernel.

## Status

- Version `0.1.0rc2`, a release candidate.
- Python 3.11 or newer. No runtime dependencies.
- Optional. Nothing else in the repository depends on it.
- The Synapse bridge functions expect a Guardian Synapse kernel object from the host. The
  package does not import Guardian and does not declare it as a dependency.

## What it does

You describe a `Goal` (subject, environment, revision, predicate, context digest, required
evidence basis and budgets), a table of possible worlds with the goal answer in each, and a set
of `Probe`s. Each probe predicts the token it would return in every world. `Inquiry.plan()`
then returns one versioned, hashed document with a status:

| Status | Meaning |
| --- | --- |
| `PROPOSED` | A probe is selected. Nothing is sent anywhere. |
| `WAITING` | A simulated attempt is open. |
| `ANSWERED_IN_MODEL` | All remaining worlds agree on the answer. This is an answer inside the model, not a confirmed real-world fact. |
| `EXTERNAL_EVIDENCE_REQUIRED` | The model has an answer, but the goal asked for `reported` or `witnessed` evidence. |
| `NEEDS_OBSERVATION` | Even all eligible probes together cannot separate the remaining answers. |
| `BUDGET_EXHAUSTED` | Eligible probes exist, but none fits the remaining budget. |
| `TASK_DENIED` | The task is not allowed. Human questions are refused too. |
| `*_NO_RETRY` | An unknown outcome, a model mismatch, an oversized response or the event limit stopped the session. |

Selection first excludes probes that are unavailable, denied, only proposed, already used or
that cannot change the goal answer. Among the rest it orders by safety rank, then by the worst
case number of remaining disagreeing worlds, then by gain per cost and a stable id. No
probabilities are estimated.

`begin_simulation()` and `receive_simulation()` reserve budget and record an in-memory attempt
bound to the exact session, probe, operation and contracts. `ack`, `ready` and `completed`
never narrow the answer; only a `synthetic-fact` token does. These are simulation methods, not
a dispatch path.

The bridge in `bridge.py` reads a host-supplied Synapse kernel:

- `capture_context(kernel, context)` reuses the native zero-hop route and its context digest.
- `select_from_synapse(inquiry, kernel, context)` keeps only probes whose edge is in
  `available_moves`, matches `explain_edge`, is read-only (`observe`, `analyze`, `plan`,
  `verify`) and has no production authority. It returns a view with `execution_authority`
  set to false.
- `begin_from_synapse(..., expected_view_digest=...)` refreshes that view and starts the
  simulation only if the view is unchanged.

Inert helper documents: `observation_request()`, `human_question()`, `human_report()`,
`recipe_candidate()`, `recipe_compatibility()` and `capsule()`. A compatible recipe only means
it may be planned again; it is not trusted or executable. A capsule that does not fit its byte
limit fails instead of being truncated.

Input limits enforced in code: at most 64 worlds and 32 probes; JSON input up to 256 KiB;
duplicate keys, non-finite numbers and unknown fields are rejected; 256 events per session.
`schemas/inquiry.schema.json` describes the input structure.

## Install

Install from source as described in [BOOTSTRAP.md](../../BOOTSTRAP.md#install-functional-components):

```bash
python -m pip install ./components/integrity-active-inquiry
```

## Use

The console script is `integrity-inquiry` (also `python -m integrity_active_inquiry`):

```bash
integrity-inquiry demo                  # six synthetic scenarios
integrity-inquiry fixture > inquiry.json   # a complete valid input document
integrity-inquiry plan < inquiry.json   # plan one input read from stdin
```

`demo` is the default command. Output is JSON on stdout. A rejected input prints
`Inquiry rejected: <type>` on stderr and exits 2. No command contacts a service, reads
credentials or starts a program.

## What is verified

- Public CI builds this distribution as a wheel, checks the wheel contents and installs it
  together with all other distributions (`pip check`) on Ubuntu and Windows with Python 3.11
  and 3.12.
- There are no behaviour tests: the component has no `tests/` folder, and no test elsewhere in
  the repository imports it.

## What is not verified

- Every behaviour described above is read from the source code only.
- Use with a real Guardian Synapse kernel.
- Any real probe, target or independent witness. None is implemented here.

## Limits

- Predictions come from the developer's model. They are not discovered facts, and a model
  can be incomplete.
- Budgets are in-memory reservations. They are not a running timeout or a transport limit,
  and nothing is refunded when a result is missing.
- There is no durable crash or replay record. A same-process caller can corrupt state.
- A digest proves a stable identity, not truth.
- No method dispatches anything or grants authority.

## License

Business Source License 1.1. See [LICENSE](LICENSE) and the project [NOTICE](../../NOTICE).
