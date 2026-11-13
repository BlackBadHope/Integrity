# integrity-agents-api

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

A client library for the OpenAI Agents API (`agents=v1`, beta) in which every HTTP request
must pass the Integrity Adapter SDK gate first. It is for host developers who want to run an
Agents API session under Integrity custody: request shape checks, a crash-safe local journal,
budget reservations and recovery of session history.

## Status

- Version `0.1.0rc2`, a release candidate.
- Python 3.11 or newer. No declared runtime dependencies.
- Optional. Disabled until a host builds the objects described below. The command-line tool
  is offline only.
- `GuardianGate` imports `integrity_adapter_sdk` at run time and calls `require_guardian()`.
  You must install `integrity-adapter-sdk` yourself; it pins `integrity-guardian==7.0.0`.
  Without it, the gate refuses with `exact_sdk_unavailable`.

## What it does

| Part | Module | Behaviour |
| --- | --- | --- |
| Session lifecycle | `lifecycle.Sessions` | `start`, `snapshot`, `message`, `cancel`, `delete`, `environment_state`. No model loop and no background thread. |
| Recovery | `Sessions.pages`, `Sessions.recover`, `lifecycle.reconcile` | Reads saved items and turns in pages of 100 and reconciles them with buffered stream events. |
| Function calls | `Sessions.execute_function`, `Sessions.submit_retained_result` | Runs only a call that the session currently lists in `required_actions`, checks its arguments against the declared schema, passes a second SDK gate, and stores the output before it is submitted. |
| Journal | `journal.Journal` | SQLite file. An operation is recorded as claimed before the call. A finished result is cached and returned again; an unknown outcome is never run again. At most 1024 operations. |
| Budget | `Journal` reservations, `contracts.aggregate_usage`, `Sessions.watchdog_tick` | Billable work needs a reservation. While usage is unknown, new billable work is refused. The watchdog only requests cancellation after a deadline. |
| Export | `contracts.ExportPolicy`, `contracts.context_capsule` | A request body is sent only if its SHA-256 is on the host's reviewed list and the host opted in to cloud retention. The capsule holds at most 32 extracts classified `synthetic`, `public` or `reviewed_project_extract`. |
| Session config | `contracts.compile_session` | Builds the Agents API request. No environment by default. Programmatic tool calling only for read-only tool sets. No subagents with functions or write tools. MCP tools only as admitted read-only HTTPS servers; stdio MCP is rejected. |
| Transport | `transport.OpenAIHTTP`, `transport.sse_events` | HTTPS to `api.openai.com` with an explicitly passed server key. Only documented session, item, turn, event and environment routes. One overall deadline per request, no retries. Bounded server-sent events. |
| Handoff | `Sessions.handoff_candidate` | Describes a handoff to another executor once the session is idle. Executes nothing. |
| Snapshot audit | `audit.audit_snapshot` | Hash-checks up to 32 supplied files and reports when the `pyproject.toml` version is missing from `README.md`. |

Messages are capped at 256 KiB. Duplicate JSON keys and non-finite numbers are rejected.

## Install

Install from source as described in [BOOTSTRAP.md](../../BOOTSTRAP.md#install-functional-components):

```bash
python -m pip install . ./components/integrity-adapter-sdk ./components/integrity-agents-api
```

The SDK and Guardian are needed only for the gated calls, not for the offline CLI.

## Use

The console script is `integrity-agents` (also `python -m integrity_agents_api`):

```bash
integrity-agents capabilities   # static description of the library, as JSON
integrity-agents demo           # audit of a built-in synthetic snapshot
```

Both commands are offline. They read no key, open no connection and create no session. The
demo reports a `version_not_documented` finding on purpose.

A host integration, in outline:

1. Build a capsule with `context_capsule` and a session config with `compile_session`.
2. Create a `Journal` with `Journal.create(path, identity, namespace, budget_microusd=...)`
   outside the agent workspace.
3. Create `OpenAIHTTP(server_key, namespace, export_policy, gate_factory)`. The factory must
   return a `GuardianGate` built from a genuine SDK envelope, verification context and
   `AdapterDispatchPermit` for the exact request.
4. Create `Sessions(transport, journal, configuration, catalog)` and call its methods.

## What is verified

- Public CI builds this distribution as a wheel, checks the wheel contents and installs it
  together with all other distributions (`pip check`) on Ubuntu and Windows with Python 3.11
  and 3.12.
- There are no behaviour tests: the component has no `tests/` folder, and no test elsewhere in
  the repository imports it.

## What is not verified

- Every behaviour described above is read from the source code only.
- Any request to the real Agents API, with a real key or a real SDK permit.
- Environments, MCP servers, programmatic tool calling and subagents in a live session.
- Whether the beta API still accepts the request shapes built here.

## Limits

- Local reservations limit new work started by this client. They do not meter or stop work
  inside the provider, and they are not a spending cap.
- `cancel` and the watchdog send a cancel request; they do not prove that work stopped.
- Journal file permissions are checked on POSIX only.
- Reconnecting or recovering a session does not restore lost side effects of an environment.
- The library creates no grant, key or permit, and never records task completion.

## License

Business Source License 1.1. See [LICENSE](LICENSE) and the project [NOTICE](../../NOTICE).
