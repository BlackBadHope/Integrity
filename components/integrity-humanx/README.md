# integrity-humanx

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

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

Server (Linux), after the bus hub (`integrity-llm-bus-hub install`):

1. Install this distribution for the interpreter that will run the web and the gateway. The launcher
   `integrity-humanx --list` shows `humanx-web`, `humanx-ro-gateway` and `humanx-ro-snapshot`.
2. Write the web's bus key to a file of your own; the hub's keys file holds only its sha256, with the
   `human-<operator_id>` address and the room operations (`send`, `poll`, `get`, `ack`, `status`,
   `room-arbiter`, `room-arbiter-set`, `vendor-cards`, `status-batch`) and `"vendor": "human"`; the hub
   refuses every request of a key whose vendor it does not know, and its `install` refuses such an entry.
3. As root, run `integrity-humanx-server install`. It needs new folders and new names, and it names the
   hub's socket group, SSH gateway account and socket:

   ```bash
   integrity-humanx-server install --etc /etc/<humanx> --state /var/lib/<humanx> --runtime /run/<humanx> \
     --web-user <web account> --gateway-user <gateway account> --socket-group <gateway socket group> \
     --bus-group <hub socket group> --bus-gateway-user <hub SSH gateway account> --bus-socket <hub socket> \
     --web-key <key file> --operator-id <operator_id> --vendor claude --port 8890 --allow 127.0.0.1
   ```

   It creates the web account, the gateway account and the gateway socket group. It adds the web account
   to the hub's socket group and the hub's SSH gateway account to the gateway socket group. It writes the
   configuration (`configuration.json`, `web.json`, `gateway.json`, the key file readable by the web
   account only). It prints the commands that start the web and the gateway as their accounts.

   - It refuses an account, group or folder that already exists under a name it would create; it does not
     take over existing ones.
   - Before each step it writes the step to its record (`<etc>/humanx-server.json`). The record lists
     what install created and what was there before: the hub's socket group and SSH gateway account,
     whose only change is one group membership.
   - The key file must be a regular file (not a symbolic link), mode 600 or stricter, owned by root or by
     the user who runs `install` (through `sudo`). The copy is written to a temporary file that has mode
     400 and the web account as owner before any byte, then renamed.
   - The web listens on `--bind`, 127.0.0.1 by default. `0.0.0.0` or `::` are refused unless you add
     `--allow-any-address`.
   - The web answers only to a `Host` header naming its bind address, `127.0.0.1`, `localhost`, `[::1]`
     or a name given with `--web-host`, with its port or without; any other `Host` gets 421. A page whose
     name was pointed at the web's address (DNS rebinding) therefore cannot reach it through a browser on
     an allowed address.
4. Enable the room on the hub: `<hub state>/state/room.json` with `human`, `vendors` and `arbiters`
   (see below). `install` does not write it.
5. For SQL, switch reads, the storm reader, the snapshot job and the ring screens, add the files they need
   (`my.cnf`, `switch.cred`, `storm.key`, `storm.known_hosts`, the ring map) and their values in
   `gateway.json` and `configuration.json` yourself. Until then they refuse, and the ring and storm
   screens stay off (`web-rings.off`, `web-storm.off`).
6. `integrity-humanx-server doctor --etc /etc/<humanx>` only reads. It checks the hub's SSH gateway
   account is in the gateway socket group and names the web's address. An install that stopped half way
   is reported as `partial`. `uninstall --etc /etc/<humanx>` lists what it would remove; with `--yes` it
   removes what the record lists as created, newest first, and nothing else. It takes the hub's SSH gateway
   account out of the gateway socket group (`gpasswd --delete`) before it deletes the group. It refuses
   while a process of the web or gateway account runs, or while the configuration folder holds a file it
   did not write, and it removes nothing from a configuration folder without the record.
7. For a service, adapt the example units in `examples/`, replacing their `<...>` placeholders. Limit the
   web to the `allow` addresses in the firewall and in `IPAddressAllow`.

Client (the machine that runs the vendors):

1. Install this distribution for the interpreter named in `python`. Agents run `python -I room_tool.py`,
   and `-I` ignores `PYTHONPATH`.
2. Make a pilot folder. Copy every file of `resources/client/` into it.
3. For each vendor, make `<pilot>/room-<vendor>/` with `work/` and `journal/`. Copy the room template
   (`resources/room/`) into it. Add `room.json` from `examples/room.example.json` and the vendor
   instruction file from `examples/room-instructions/` (renamed, with your own values in place of `<...>`).
4. Start `humanx_wakers_supervisor.py` from the pilot folder.

## How the room is enabled

The room exists only on a bus that has it enabled: `<state>/room.json` in the bus state folder
(`room_acl.py`), with `{"human": "human-<operator_id>", "vendors": ["room-<operator_id>-claude", ...]}`. With
the hub, the folder is `<hub state>/state`; neither `integrity-llm-bus-hub` nor `integrity-humanx-server` writes
the file, so the operator writes it as the bus account. The web picks the room Arbiter from its `arbiters`
object, for example `{"claude": {"address": "room-<operator_id>-claude", "ro": "<how it is read-only>",
"ro_verified": true}}`; the hub refuses a candidate without `ro_verified`. The bus then lets the operator write only to room vendors and the owner, and lets vendors
answer only the operator and the owner. The pilot used `humanx-<name>` for the operator address. This port
uses `human-<operator_id>`, so it matches `room_acl.py`.

## What it does not do

- It changes nothing on switches, hosts or databases. Changes go to the operator as text, or to the owner
  through `escalate`.
- It does not ship the external `antigravity_wake` module, the OCR script, the D-Link login profiles
  (`profiles.json`), the ring command reference (`shared/ring-commands.md`) or any grant list.
- It does not create accounts, keys, firewall rules or the bus room file for you.

## What is verified

By public CI on Ubuntu and Windows with Python 3.11 and 3.12
(`python -B -m pytest --import-mode=importlib components/integrity-humanx/tests`), with a synthetic
configuration in a temporary folder and no network:

- configuration contract, address helpers and launcher `--list` / `--preflight`;
- delivery health (back-off, crash loop, stuck and hung detection, healer policy), notice de-duplication,
  shared topic lock retry, using a stand-in `room_tool` written in the tests;
- `room_tool` reply, send and escalate checks, size and encoding guards, ring-change check, host-read
  limits, argument-file encodings, transport errors, journal hash chain and rotation;
- Codex MCP tool mapping and the Claude room hook decisions;
- web handlers in-process (allow list, `Host` list, CSRF header, stale page, send path, state API, escaped
  ring page, attachment types);
- ring and storm screens with an invented ring map, including the storm page-size limit;
- gateway caller checks, SQL and `show` whitelists, web screen rights and Integrity snapshot reads. The gateway
  is Linux-only; the tests use fake `pwd`/`grp` and a fake connection, and no socket server is started;
- `dlinkcli` whitelist and parsers on invented transcripts;
- `integrity-humanx-server` argument checks (including the `--bind` default and `0.0.0.0`), the configuration
  it writes, its record handling, the key file checks (symbolic link, modes 644, 640, 604 and 620, owner;
  POSIX only) and `uninstall --yes` against invented accounts: it removes only what the record lists as
  created, takes the membership out before the group goes, and removes a partial install by its record;
- a refused SQL statement never starts the database client (the gateway reaches the database only through
  that client process).

By the public CI job `humanx server (ubuntu, real accounts)` (`.github/scripts/humanx_server_check.py`), on
Ubuntu with sudo inside the runner, with keys generated in the job and a synthetic Integrity snapshot:

- refused installs that create nothing: an existing account named like the web account (and `uninstall
  --yes` afterwards leaves that account alone), a key file given as a symbolic link, a key file with mode 644,
  and `--bind 0.0.0.0` without `--allow-any-address`;
- an install killed at the membership step and one killed while writing the key file (no rollback runs):
  `doctor` reports `partial`, `uninstall --yes` removes it by its record, and the hub's SSH gateway account
  keeps the groups it had before;
- `install` with real accounts and groups next to the installed bus hub, a refused second install, `doctor`
  (web on 127.0.0.1, the hub's SSH gateway account in the gateway socket group; a key file set to mode 644
  fails it);
- the gateway on its unix socket as its own account, with callers told apart by `SO_PEERCRED`. The hub's SSH
  gateway account reads the snapshot. Refused: a vendor outside the room, the web account, another account of
  the socket group, and `DROP TABLE` (the answer is the gateway policy's refusal, with none of the fields a
  run of the database client adds; no database server runs in the job). Accounts outside the socket group
  cannot connect. The gateway log holds request hashes and no request text;
- the web on 127.0.0.1 as its own account: the page (the key is not in it), a refusal from 127.0.0.2, a
  refusal without the `X-HumanX` header, 421 for a page and a send with a `Host` header not in its list,
  the page with `Host: localhost:<port>`, the state API;
- one question sent from the page through the real bus hub to the room vendor's address, read there with the
  vendor's key, and the vendor's answer shown under it on the page;
- `uninstall` refused while the web and the gateway run, and while an owner file is in the configuration folder;
  then `uninstall --yes`, `doctor` reporting `not-installed`, no accounts, groups or folders left, and the
  hub's SSH gateway account there with the groups it had before install.

## What is not verified

- systemd units, the firewall, and the SSH forced command in front of the bus gateway account were not
  exercised. The CI job calls the gateway from that account directly.
- SQL against a database server, switch reads, the storm reader, the snapshot job and the ring and storm
  screens were not run against a real service.
- No live acceptance: no vendor agent, switch, database, SSH host or browser took part. The vendor side in CI
  is a script holding the vendor's key, not an agent.
- The waker loops, the supervisor, Max Reasoning and the quota readers are not covered by the tests.
- A kill between creating the configuration folder and writing the record's first line leaves the folder
  without a record; `doctor` reports `broken` and `uninstall` removes nothing. Not tested.
- Two machines (web on one, hub on another) were not run.

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
