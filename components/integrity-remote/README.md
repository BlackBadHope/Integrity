# integrity-remote

Connects Integrity clients on one machine to a core on another over an OpenSSH
forced command. There is no new listener, every device has its own key, the
host key is pinned and releases are immutable. The step-by-step guide is
[docs/CROSS_MACHINE_QUICKSTART.md](../../docs/CROSS_MACHINE_QUICKSTART.md).

| Command | Machine | Effect |
| --- | --- | --- |
| `integrity-remote core init --root DIR --server-json FILE [--mode hardened --service-user NAME]` | core (Linux) | builds `DIR/releases/<digest>` and the private `DIR/run` |
| `integrity-remote core verify RELEASE` | core | re-runs the release's own custody and digest check |
| `integrity-remote authorize --release RELEASE --device-id ID --public-key FILE` | core | prints one `authorized_keys` line; writes nothing |
| `integrity-remote client-upstream --host H --user U --identity KEY --known-hosts FILE` | client | prints the hardened `ssh` command as `upstream.json`, Claude/Antigravity JSON or Codex TOML |
| `integrity-remote check UPSTREAM.json` | client | MCP `initialize` + `tools/list` through the real transport |

A release contains `run-mcp`, `verify-release`, `supervisor.py`, `server.json`,
`SHA256SUMS` and `artifact.sha256`:

- `run-mcp` discards the client's requested command and environment. It
  accepts only the `--device` value from the `authorized_keys` line.
- `verify-release` checks the digest-named directory, file modes, ownership,
  link counts and checksums before anything else runs.
- `supervisor.py` caps concurrent sessions. It gives the server a minimal
  environment and runs it in its own process group. When the session ends, it
  terminates that group and every descendant it adopted as a subreaper.

The server process inherits the SSH channel directly. The supervisor never
reads or rewrites MCP traffic.

Importing the package starts no process and reads no key. Standard library
only. The core side needs Linux and GNU coreutils. The client side needs any
OpenSSH client.
