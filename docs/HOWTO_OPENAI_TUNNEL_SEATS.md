# OpenAI tunnel seats

Each person uses their own OpenAI account and their own seat token. Integrity
does not pool quotas or store provider API keys.

Mode A is the primary path: an HTTPS OAuth 2.1 gateway on the shared core.
The core maps the verified `sub` to a seat. Mode B, a personal OpenAI
developer-plugin tunnel plus `X-Integrity-Seat-Token`, is optional and
experimental.

Whether a third party can connect through their own OpenAI developer-plugin
tunnel is an unverified assumption. Read the current OpenAI documentation
before relying on Mode B. This repository does not ship a tunnel client or a
live tunnel address.

Use placeholders only:

- core host: `<CORE_HOST>`
- seat id: `<YOUR_SEAT_ID>`
- token file: the path printed by `integrity-seats token issue`
- example URL host: `example.invalid`

Do not put a provider API key in the core config or in the seat registry.

## Codex

```toml
[mcp_servers.integrity-seats]
command = "python"
args = [
  "-m", "integrity_space.hub",
  "--config", "/absolute/path/space-config.json",
  "--hub-manifest", "/absolute/path/hub-manifest.json",
  "--hosts-config", "/absolute/path/hosts.json",
  "--seat-registry", "/absolute/path/seat-registry.sqlite3",
]

[mcp_servers.integrity-seats.env]
INTEGRITY_SEAT_TOKEN_FILE = "/absolute/path/seat.token"
```

`integrity_space.hub` requires `--config`, `--hub-manifest`, and a hosts
config (`--hosts-config`, or `INTEGRITY_HOSTS_FILE`). Without them the process
exits before it serves tools. `--seat-registry` (or `INTEGRITY_SEAT_REGISTRY`,
or a `seat_registry` path in the hosts file) is how the workbench resolves the
configured seat. The hosts file is the existing owner hosts document.

Point `INTEGRITY_SEAT_TOKEN_FILE` at a file mode `0600` that contains only that
seat's token. Install `integrity-space`, `integrity-home`, and, when mesh or
bus tools are used, `integrity-llm-bus`, from their `components/` directories.

## Claude Code

Register the Integrity Seats hook template under `plugins/integrity-seats`
and set `INTEGRITY_CLIENT_MEMORY_CONFIG` to your own config. The upstream MCP
command key is `upstream_mcp_command`. The older obfuscated key is still
accepted and warns.

## Allowlisted upstreams

Hub tools accept an upstream id from a fixed allowlist. A raw URL is rejected.
The public example id is `example-memory` (`https://example.invalid/integrity-seats`).
