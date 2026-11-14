# integrity-llm-bus

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

SQLite message queue for LLM agents, dynamic harness registry, bounded native steering, relay/outbox,
filesystem bridge, and (since 1.1.0) an optional hub daemon so several machines share one bus.
No queue, agents registry, webhook, native session identifier or historical message is included.
Built-in agent names identify harness roles, not enrolled sessions. Delivery receipts do not prove execution.

## Contents

| Part | Location | What it does |
| --- | --- | --- |
| Local bus | `resources/bus.py`, `local_cli.py`, `agent_registry.py`, `registry_db.py`, `autoreg.py`, `autoreg_hook.py` | queue, registry (JSON or SQLite), automatic registration of harness sessions, command line |
| Delivery | `relay.py`, `launcher.py`, `codex_steer*.py`, `bus_claude_hook.py`, `chatgpt_bus.py`, `file_bridge.py`, `archived_detect.py`, `reachability.py` | push to Codex / Grok, pull hooks for Claude, ChatGPT registration, file bridge, recipient reachability |
| Owner layer | `owner_verify.py`, `owner_layer.py` | messages sent as `owner` must carry a valid owner signature; no key replaces it |
| Agent mesh | `mesh_store.py`, `mesh_cli.py`, `mesh_validate.py`, `agent-bus-1.schema.json`, `agentbus_validate.py` | agent-mesh/1 projection and the agent-bus/1 body schema |
| Operations | `maintenance.py`, `bus_health.py`, `watch_bus.py`, `attach_cli.py`, `fix_registry_topics.py` | maintenance/freeze flag, health, live view, attachments, registry repair |
| Human room | `room_acl.py` | optional `human-*` operator address and `room-*` vendors with routing rules; enabled only by `<state>/room.json` |
| Hub client | `bus_remote.py`, `bus_replica_sync.py` | enabled only by `<state>/CORE.json`: writes go to the hub over SSH, the local database becomes a guarded read-only replica |
| Hub | `resources/core/` | unix-socket daemon with a fixed JSON protocol, per-key rights, rate and seat limits, owner gate, hash-chained request journal, replica change log, migration and route-catalog export |
| Examples | `examples/hub/`, `examples/client/` | systemd units, SSH gateway forced command and login shell, journal seal script, `core.json`, `principals.json`, `room.json`, client `CORE.json`, all with placeholders |

Without `CORE.json` and `room.json` the bus behaves as a single-machine bus (the `human-*` / `room-*`
prefixes are still reserved and cannot be self-registered).

## Configuration

Copy `configuration.example.json` outside the installation, fill every value you use and set
`configured` to `true`. There are no maintainer defaults. Point `INTEGRITY_LLM_BUS_CONFIG` at the file.

| Key | Used for |
| --- | --- |
| `state_directory` | bus state: database, registry, flags (all scripts) |
| `path_d4f3db5417f4` | root folder of the filesystem bridge |
| `path_dd2435d503a6` | working directory for processes started by the relay and launcher |
| `endpoint_173b0c3b2ac1` | allowed URL prefix of the Grok webhook (the URL itself comes from `GROKBOT_WEBHOOK_URL`) |
| `native_peer_port_49481` | loopback port of the native Codex peer used by the relay |
| `native_peer_host_id` | host id of that native peer (its key and link files live under `~/.codex/bridge-host/<id>/`) |
| `chatgpt_thread_id` | default thread UUID for `chatgpt_bus.py register` |
| `core_config` | hub only: path of `core.json` (environment `BUS_CORE_CONF` takes precedence) |
| `routes_seed`, `routes_module`, `routes_catalog`, `routes_source_label` | hub only: route-catalog export (environment `ROUTES_SEED`, `ROUTES_MODULE`, `ROUTES_OUT`, `ROUTES_SOURCE` take precedence) |

`CONFIGURATION-VALUES.json` lists every line that reads each key. Keep credentials (webhook key, agent
tokens, SSH keys) in your own credential store or environment, never in this configuration.

## Single machine

```text
integrity-llm-bus --list
integrity-llm-bus --config /absolute/path/own-config.json --preflight
integrity-llm-bus --config /absolute/path/own-config.json local_cli --help
```

The launcher starts each entrypoint in a fresh subprocess. Importing `integrity_llm_bus` starts no
process, opens no database and connects to no host. Preflight checks the configuration header only and
reports `runtime_bindings_verified: false`.

## Hub on a clean Linux machine

1. Install this distribution (and `cryptography`) for the system interpreter: the example units run
   `python3 -I`, which ignores `PYTHONPATH`.
2. Create a nologin bus account and group, and a separate SSH gateway account whose group may use the socket.
3. Write `core.json` from `examples/hub/core.example.json`, `principals.json` from
   `examples/hub/principals.example.json` (store only the sha256 of each client token), and set
   `core_config` and `state_directory` in the component configuration. `state_directory` must equal
   `state_dir` in `core.json`, because the bus library modules read it.
4. Move an existing bus database with `resources/core/migrate.py SRC_SQLITE DST_STATE_DIR` (refuses to
   overwrite, prints a per-table digest report, adds the body archive), or let the daemon create a new one.
5. Install `examples/hub/systemd/llm-bus-core.service` after replacing its `@NAME@` placeholders;
   optionally the journal seal and route export units and timers.
6. Install `examples/hub/bin/bus-gateway` as the forced command of each vendor key
   (`restrict,command="<path> <vendor-id>"`) and `bus-gw-shell` as the gateway account's login shell.
7. On each client, write `<state>/CORE.json` from `examples/client/CORE.example.json` (switch with
   `bus_remote.snapshot_and_guard`, then keep `bus_replica_sync.py` running).

`resources/core/bus_journal.py JOURNAL_DIR` verifies the journal chain. `bus_quota_report.py` summarises
journal usage per key and account.

`integrity-llm-bus-hub doctor --etc <configuration folder>` (Linux, as root) checks a hub made by
`integrity-llm-bus-hub install` and sends the running daemon one request without a key, which it must
refuse. Each run of doctor leaves one `denied` record with the reason `no key` in the request journal.
Run it by hand, not from a timer or a loop, so these records do not hide real refusals.

## Verified / not verified

Verified by public CI on Ubuntu and Windows with Python 3.11 and 3.12
(`python -B -m pytest --import-mode=importlib components/integrity-llm-bus/tests`):

- the 1.0.0 component tests;
- `tests/live/`: the bus script tests of the source tree, run against a synthetic configuration in a
  temporary folder (no real state, agent homes, webhook or network);
- `tests/core/`: the hub request path in-process (`execute`, key lookup, argument whitelist, strict JSON,
  read-only/revoked/unknown keys, op grants, key and account rate limits, seats, account labels, owner
  address rules and owner gate refusal, hub-key restrictions, room rules, journal chain and tamper
  detection, change log applied to a guarded replica, migration). `fcntl` is stubbed with a no-op lock
  on Windows and no socket server is started.

Not verified here:

- on Linux only these unit tests ran; the unix-socket handler (`SO_PEERCRED`), the systemd sandbox,
  `chattr` sealing, the SSH gateway and forced-command shell were not exercised;
- no multi-host operation (hub plus clients over SSH, replica sync stream) is claimed;
- the native Codex peer, Grok webhook, Claude/Codex/ChatGPT harnesses and Windows Hello signing were
  exercised only through mocks in the tests.

## License

Business Source License 1.1 from v7.0.0-beta.4 (earlier releases Apache-2.0); see LICENSE and NOTICE.
No user memory, event corpus, enrollment, private keys, service configuration, retained session state or
live deployment pins are included. `SOURCE-MAP.json` records the source and copy hashes of every resource;
modules merged from two source copies also record the second source hash.
