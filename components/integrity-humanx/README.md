# integrity-humanx

HumanX is a room for a human operator. The operator writes in a small web page. The page sends each
message over the LLM bus to one room vendor (claude, codex, gemini or grok). One vendor is the room
Arbiter. Each vendor runs read-only and is started by a waker only when a message arrives. Vendors read
production data only through a read-only gateway.

This is an alpha port (0.1.0a1) of a working pilot. Behaviour is kept as it was. Comments, logs, page texts
and prompts stay in the original language (mostly Russian). No room journal, topic list, ring map, host
table, grant, device transcript or credential is included.

## Contents

| Part | Location | What it does |
| --- | --- | --- |
| Wakers | `resources/client/room_claude_wake.py`, `room_codex_waker.py`, `room_gemini_waker.py`, `room_grok_waker.py` | poll the local bus replica for the room address, start the vendor agent once per message, ack, heartbeat |
| Supervisor | `resources/client/humanx_wakers_supervisor.py`, `humanx_wake_launch.py` | keeps one waker per vendor running, restarts with back-off, writes health alerts |
| Shared client code | `resources/client/humanx_delivery.py`, `humanx_context.py`, `humanx_topics.py`, `humanx_kparts.py`, `humanx_attach.py`, `humanx_maxreason.py` | delivery health, conversation context, shared topic list, service-note filter, attachments, Max Reasoning (several vendors answer together) |
| Quota readers | `resources/client/antigravity_quota.py`, `humanx_codexquota.py` | read vendor quota state for the vendor cards |
| Client hook | `resources/client/vendor_room_guard.py` | read-only guard for the Codex and Gemini rooms |
| Room template | `resources/room/room_tool.py`, `room_ro_guard.py`, `humanx_room_ro_mcp.py`, `codex-room-mcp.json` | copied into every `<pilot>/room-<vendor>/`: the only exit of an Arbiter (bus, gateway, host reads), the Claude hook, the Codex MCP server |
| Web | `resources/web/humanx_web.py`, `rings_screen.py`, `storm_screen.py` | chat page and API; ring and storm screens rendered from a fixed template without a model |
| Read-only gateway | `resources/ro/humanx_ro_gw.py`, `dlinkcli.py`, `humanx_ro_snapshot.py` | unix-socket gateway: SELECT-only SQL, whitelisted D-Link `show` commands, Integrity snapshot reads, storm log read |
| Examples | `examples/` | `room.json`, host table, ring map, web and gateway configuration, systemd units, vendor instruction files; all with invented values or placeholders |

## Configuration

Copy `configuration.example.json` outside the installation, fill every value the parts you run need, and
set `configured` to `true`. There are no defaults. Point `INTEGRITY_HUMANX_CONFIG` at the file.
`CONFIGURATION-VALUES.json` lists every line that reads each key.

| Key | Side | Used for |
| --- | --- | --- |
| `operator_id` | both | operator id: lower-case letters, digits and `-`. Bus addresses are `human-<operator_id>` and `room-<operator_id>-<vendor>` |
| `python` | client | interpreter that runs `room_tool.py` and the wakers' helper calls |
| `bus_replica` | client | local read-only replica of the bus database (`BUS_REPLICA` takes precedence) |
| `hosts_file` | client | JSON host table for `room_tool host` (see `examples/hosts.example.json`) |
| `host_ssh_key`, `ssh_config` | client | SSH key and SSH config used for host reads |
| `web_url` | client | room web base URL for attachments (`HUMANX_WEB` takes precedence) |
| `host_label` | client | label of the waker machine in Max Reasoning task files |
| `integrity_mcp_server` | client | MCP server name whose two turn tools the Claude room hook allows |
| `antigravity_wake_dir` | client | folder of the external `antigravity_wake` module (Gemini waker, sub-chats; `HUMANX_BUS_DIR` takes precedence) |
| `antigravity_steps_root`, `antigravity_language_server` | client | Antigravity step folder (Gemini guard) and language server binary (Gemini availability check) |
| `web_config` | server | JSON for the web: `bind`, `port`, `allow`, `socket`, `token_file` (see `examples/web-config.example.json`) |
| `web_state_dir` | server | web state: sent messages, replies, files (`STATE_DIRECTORY` takes precedence) |
| `ring_map_file` | server | ring map: `cores`, `not_polled`, `access_prefix`, `rings` (see `examples/ring-map.example.json`) |
| `ro_gateway_socket` | server | socket of the read-only gateway as seen by the web |
| `ro_gateway_config` | server | JSON for the gateway; every path, account, network and stop file (see `examples/ro-gateway-config.example.json`) |
| `integrity_action_log`, `ro_integrity_snapshot`, `ro_group` | server | snapshot job: source database, snapshot path, group that may read it |

Keep tokens, passwords and SSH keys in your own credential store. The configuration holds only paths to them.

## Setting up on a clean machine

Server (Linux):

1. Install this distribution for the interpreter the units use. The units run the `integrity-humanx` launcher;
   `--list` shows `humanx-web`, `humanx-ro-gateway` and `humanx-ro-snapshot`.
2. Create separate accounts for the web and the gateway, and the group that may use the gateway socket.
3. Write the web configuration, the gateway configuration and the ring map from `examples/`.
4. Install the example units after replacing their `<...>` placeholders. Limit the web to the `allow`
   addresses in the firewall and in `IPAddressAllow`.

Client (the machine that runs the vendors):

1. Install this distribution for the interpreter named in `python`. Agents run `python -I room_tool.py`,
   and `-I` ignores `PYTHONPATH`.
2. Make a pilot folder. Copy every file of `resources/client/` into it.
3. For each vendor, make `<pilot>/room-<vendor>/` with `work/` and `journal/`. Copy the room template
   (`resources/room/`) into it. Add `room.json` from `examples/room.example.json` and the vendor
   instruction file from `examples/room-instructions/` (renamed, with your own values in place of `<...>`).
4. Start `humanx_wakers_supervisor.py` from the pilot folder.

## How the room is enabled

The room exists only on a bus that has it enabled. In `integrity-llm-bus`, the installer writes
`<state>/room.json` with `{"human": "human-<operator_id>", "vendors": ["room-<operator_id>-claude", ...]}`
(`room_acl.py`). The bus then lets the operator write only to room vendors and the owner, and lets vendors
answer only the operator and the owner. The pilot used `humanx-<name>` for the operator address. This port
uses `human-<operator_id>`, so it matches `room_acl.py`.

## What it does not do

- It changes nothing on switches, hosts or databases. Changes go to the operator as text, or to the owner
  through `escalate`.
- It does not ship the external `antigravity_wake` module, the OCR script, the D-Link login profiles
  (`profiles.json`), the ring command reference (`shared/ring-commands.md`) or any grant list.
- It does not create accounts, keys, firewall rules or the bus room file for you.

## What is verified

On Windows 11 with Python 3.12 (`python -B -m pytest --import-mode=importlib components/integrity-humanx/tests`),
with a synthetic configuration in a temporary folder and no network:

- configuration contract, address helpers and launcher `--list` / `--preflight`;
- delivery health (back-off, crash loop, stuck and hung detection, healer policy), notice de-duplication,
  shared topic lock retry, using a stand-in `room_tool` written in the tests;
- `room_tool` reply, send and escalate checks, size and encoding guards, ring-change check, host-read
  limits, argument-file encodings, transport errors, journal hash chain and rotation;
- Codex MCP tool mapping and the Claude room hook decisions;
- web handlers in-process (allow list, CSRF header, stale page, send path, state API, escaped ring page,
  attachment types);
- ring and storm screens with an invented ring map, including the storm page-size limit;
- gateway caller checks, SQL and `show` whitelists, web screen rights and Integrity snapshot reads. The gateway
  is Linux-only; the tests use fake `pwd`/`grp` and a fake connection, and no socket server is started;
- `dlinkcli` whitelist and parsers on invented transcripts.

## What is not verified

- Nothing was run on Linux. The unix socket, `SO_PEERCRED`, systemd units and file ownership were not exercised.
- No live acceptance: no real bus, vendor agent, switch, database, SSH host or browser took part.
- The waker loops, the supervisor, Max Reasoning and the quota readers are not covered by the tests.

## Known problems carried over from the pilot

The port keeps the pilot's behaviour, including these defects:

- Both room hooks (`room_ro_guard.py` and `vendor_room_guard.py`) leave `ring_commands` out of the
  `room_tool` operations they allow, while the instruction examples tell the Arbiter to use it. An
  Arbiter behind either hook cannot read the ring command reference.
- `AGENTS.example.md` says in its safety section that ring and STP commands are not given to the
  operator; rule 5а of the same file says they are given as text. The rule is the newer one.
- The Codex MCP server (`humanx_room_ro_mcp.py`) keeps a request log, `mcp.log`, in the room folder.
  Treat the room folder as holding whatever the operator asked.
- Image text extraction calls `humanx_ocr.ps1`, which is not shipped; without it an image attachment
  is described by its dimensions and size only.
- The web accepts a state-changing request when it carries the `X-HumanX: 1` header. That is its only
  cross-site request check, so the address allow list is the real boundary.

## License

Business Source License 1.1; see LICENSE and NOTICE. `SOURCE-MAP.json` records the source and copy hashes
of every ported file.
