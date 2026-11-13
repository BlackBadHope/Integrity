# integrity-claude-code

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

A Python library that runs one headless Claude Code CLI session (`claude -p`) on Windows under
Integrity custody. Every launch and every file tool call must pass the Integrity Adapter SDK
gate, and the run leaves only content-free records. It is for host developers who want a
governed Claude Code executor; it is not the hook that connects Claude Code to Integrity
memory (that is [`integrity-client-memory`](../integrity-client-memory/README.md)).

## Status

- Version `0.1.0rc3`, a release candidate.
- Python 3.11 or newer.
- Depends on `integrity-adapter-sdk==2.0.0rc3`, which pins `integrity-guardian==7.0.0`.
- Optional. Installing it starts no process and creates no ledger. Launching needs a policy,
  a verified activation artifact, an authentication preflight and SDK evidence that the host
  supplies; without them every launch is refused.
- The runtime (process, pipe and file handling) is Windows only. Parsers and policy checks
  are plain Python and import on any platform.
- The Claude Code CLI and its login are not included. The operator installs them.

## What it does

The capability statement (`capabilities.py`) lists the public entry points:

| Entry point | Behaviour |
| --- | --- |
| `launcher.ClaudeRun` | One governed run: durable claim, SDK launch permit, Job Object spawn, supervision, signed executor report, then the final ledger state. |
| `auth.preflight_auth` | Runs the pinned CLI with `auth status --json` and accepts only subscription login methods that the owner allowed. API-key, provider, helper and gateway methods are refused. |
| `activation.verify_activation` | Checks a retained activation artifact against the digest pinned in the policy. Default is deny. |
| `authority.SdkAuthority` | The only authority path: SDK envelope verification, durable attempt, one-use permit, then the effect. |
| `observer.observe_workspace`, `observer.evaluate` | Starts a separate read-only process that hashes the workspace files and repository HEAD. |
| `observer.terminal_receipt`, `observer.closure_handoff` | Prepare the host's terminal receipt and closure handoff. |
| `authority.recover_attempt` | Reopens an SDK attempt from trusted custody. |

Other behaviour confirmed in the source:

- The model gets four tools through an MCP relay inside the Job: `read_file`, `write_file`,
  `edit_file`, `list_dir`. There is no shell tool, no network tool and no subagents.
- The CLI argv is built from an immutable policy. The policy declares CLI version `2.1.281`
  and a digest of its `--help` text. This is a pinned interface, not a statement about the
  latest CLI.
- The run environment refuses variables that select API billing or another provider, or
  that look like credentials or proxies: names starting with `ANTHROPIC_`, `AWS_`, `AZURE_`
  or `CLAUDE_CODE_USE_`, names containing `KEY`, `TOKEN`, `SECRET` and similar, and a fixed
  list that includes `HTTP_PROXY` and `NODE_OPTIONS`. Flags such as
  `--dangerously-skip-permissions` are refused in the argv.
- `stream.ClaudeStream` parses `--output-format stream-json`. It requires the init event for
  the exact session, exactly one result event and nothing after it, and refuses blank,
  oversized, truncated, duplicate-key or non-UTF-8 lines. A successful result is recorded only
  as `reported_success`.
- `ledger.RunLedger` is a local SQLite cache: claim before effect, one live run per session,
  cached duplicates. An unknown or unverified-stop run keeps its session lease, so it is never
  retried or resumed from the ledger.
- File writes go through held Windows handles. A write is in place, not atomic: a failure in
  the middle is reported as unknown.

## Install

Install from source together with Guardian and the SDK, as in
[BOOTSTRAP.md](../../BOOTSTRAP.md#install-functional-components):

```bash
python -m pip install . ./components/integrity-adapter-sdk ./components/integrity-claude-code
python -m pip check
```

## Use

```bash
integrity-claude-code capabilities
```

`capabilities` is the only command (also `python -m integrity_claude_code capabilities`). It
prints the static capability statement as JSON and performs no probe. Any other argument prints
the usage line and exits 2. Everything else is the Python API above.

## What is verified

- Public CI runs the tests in `tests/` on Ubuntu and Windows with Python 3.11 and 3.12. They
  are pure protocol tests without the CLI, an account or an SDK grant. They cover:
  - the `capabilities` command, its version, and that it claims no production authority,
    no live activation and no canonical append;
  - refusal of duplicate JSON keys;
  - refusal of a stream event for the wrong session;
  - a successful result counted only as reported success, with the result text hashed and
    not echoed;
  - refusal of a second result event;
  - a truncated stream classified as a protocol violation, never as success.

## What is not verified

- No test launches Claude Code, signs an SDK envelope or activates a subscription.
- The Job Object launcher, named pipe, relay, coordinator, file sinks, observer and
  authentication preflight have no tests in this repository.
- Live end-to-end use with a real Claude Code CLI and account.

## Limits

- Windows only for the runtime.
- Job Objects bound the process tree. They do not restrict filesystem, registry or network
  access of the account that runs the CLI.
- The ledger directory's Windows access rights are not checked. Place it where the agent
  account cannot write.
- A provider result is a claim. Success needs independent observation and host authority.
- The package mints no authority, key or envelope.

## License

Business Source License 1.1 for Integrity source from v7.0.0-beta.4 (earlier releases
Apache-2.0); Anthropic CLI licensing is separate. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
