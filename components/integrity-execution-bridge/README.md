# integrity-execution-bridge

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

A small MCP server that lets a remote model, such as ChatGPT, read and edit files in one
prepared workspace and run exact commands through a Codex app-server, with every operation
passing the Integrity Adapter SDK gate. No second model is involved: the bridge only executes
what it is asked. It is for host developers who want to wire such a bridge themselves.

## Status

- Version `0.1.0rc5`, a release candidate.
- Python 3.11 or newer. Depends on `jsonschema>=4.19.2,<5`.
- Optional, and inactive until a host builds and serves it. Importing the package connects
  to nothing and runs nothing.
- `SDKInvoker` needs `integrity-adapter-sdk` at run time (it pins `integrity-guardian==7.0.0`);
  it is not a declared dependency.
- The workspace and the delivery cache work on POSIX only (they refuse with
  `workspace_platform_unproven` and `cache_platform_unproven` elsewhere). The bridge cannot
  run on Windows.
- No console script.

## What it does

Seven MCP tools, defined in `catalog.py` with closed input schemas:

| Tool | Behaviour |
| --- | --- |
| `bridge_info` | Component and catalogue identity. Starts nothing. |
| `workspace_read` | A UTF-8 slice of one file (up to 8192 characters), the full file SHA-256 and the next offset. |
| `workspace_replace` | Replaces exact text in an existing file only if the file hash and the match count are as expected. Writes a temporary file and renames it. |
| `command_start` | Starts one exact argv in the workspace with a deadline. Returns a job handle, not a result. |
| `command_read` | New merged stdout and stderr since a byte cursor, with truncation, gaps and exit status. |
| `command_write` | Sends literal stdin to an owned job. Needs its own operation id and SDK admission. |
| `command_stop` | Asks the backend to stop an owned job. An acknowledgment is not proof of exit. |

The parts a host composes:

- `workspace.Workspace(root)` opens the root with `O_NOFOLLOW` and walks paths by directory
  descriptors. It rejects `.git`, symlinks, hard links, special files and traversal.
- `executor.RpcChannel(stdout, stdin)` speaks to an already started Codex app-server.
  `CodexExecutor` sends only `initialize`, `command/exec`, `command/exec/write` and
  `command/exec/terminate`.
- `gateway.DeliveryCache(directory, namespace)` is a private SQLite cache of operation ids,
  hashes and delivery states (no code, commands or output). After a crash, unfinished records
  become unknown and keep later changes in that task blocked.
- `gateway.Bridge(cache, backend, invoker)` holds registered tasks. `register(task,
  workspace, control)` binds a `contracts.Task` to a workspace and a control reader that
  returns `contracts.Control` (`ACTIVE`, `PAUSED` or `STOPPED`). A watcher requests stops on
  pause, stop, a changed context or the deadline.
- `sdk_gate.SDKInvoker(evidence_factory)` verifies the SDK execution envelope for the exact
  operation descriptor and consumes a genuine `AdapterDispatchPermit` before the effect.
- `mcp.Dispatcher(bridge)` implements MCP `2025-11-25` as stateless JSON responses:
  `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
  `mcp.PrivateHTTPServer(dispatcher, tokens)` serves it on `127.0.0.1` only, with bearer
  tokens mapped to principals, Host and Origin checks, a 3-second input deadline and
  `/healthz` for process liveness.

Limits in code: 8 tasks per bridge, 128 jobs per task, 1024 operations per cache, 8 concurrent
work calls, 12 HTTP connections, 256 KiB RPC frames, 64 KiB output buffer, 16 KiB per output
read.

Source provenance of the design patterns is in [UPSTREAMS.json](UPSTREAMS.json) and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). No upstream code is bundled.

## Install

Install from source as described in [BOOTSTRAP.md](../../BOOTSTRAP.md#install-functional-components):

```bash
python -m pip install . ./components/integrity-adapter-sdk ./components/integrity-execution-bridge
```

## Use

A trusted host composes the parts. In outline:

```python
channel = RpcChannel(codex_stdout, codex_stdin)
channel.initialize()
backend = CodexExecutor(channel, sandbox_policy, environment=reviewed_overrides)
bridge = Bridge(DeliveryCache(cache_dir, namespace), backend, SDKInvoker(evidence_factory))
bridge.register(task, Workspace(worktree), read_owner_control)
server = PrivateHTTPServer(Dispatcher(bridge), principal_tokens)
```

The host starts the Codex app-server, provides the SDK evidence, serves the HTTP server
behind its own authenticated tunnel and shuts everything down.

## What is verified

- Public CI builds this distribution as a wheel, checks the wheel contents and installs it
  together with all other distributions (`pip check`) on Ubuntu and Windows with Python 3.11
  and 3.12.
- There are no behaviour tests: the component has no `tests/` folder, and no test elsewhere in
  the repository imports it.

## What is not verified

- Every behaviour described above is read from the source code only.
- Use with a real Codex app-server binary, a real SDK permit or a real ChatGPT connection.
- Process-tree cleanup after a stop, and behaviour after a crash.

## Limits

- POSIX only for the workspace and cache.
- The sandbox policy sent to Codex is a request, not proof of isolation. The host must check
  the real Codex executable, its effective policy and its environment.
- Hash checks assume no hostile writer with the same user id.
- The HTTP server is for a private integration, not an internet-facing service. Rate limiting
  belongs to the tunnel or proxy in front of it.
- A process exit is not proof of success, and the bridge never records a successful outcome
  on its own. It has no planner, no inference client and no automatic retry.

## License

Business Source License 1.1. See [LICENSE](LICENSE), the project [NOTICE](../../NOTICE) and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
