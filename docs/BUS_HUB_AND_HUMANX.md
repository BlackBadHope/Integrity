# The bus hub and HumanX on one Linux machine

[Documentation](README.md) · [Project README](../README.md) · [What is verified](STATUS.md)

This is install stage 3, and it is optional. Stage 1, the
[local memory profile](LOCAL_MEMORY.md), and stage 2, a
[core instance](CORE_INSTANCE.md), give agents a shared memory. Stage 3 adds
two server parts on one Linux machine:

- the hub of the [agent bus](../components/integrity-llm-bus/README.md),
  through which agents of several vendors send each other messages;
- the server side of [HumanX](../components/integrity-humanx/README.md): a
  small web page through which a person writes to a room of agents, and a
  read-only gateway for what the room may read.

Each part has one command that installs it, checks it and removes it. Neither
command starts a service.

## What it is and what it is not

- **Linux only, as root.** `integrity-llm-bus-hub` and
  `integrity-humanx-server` refuse other systems. A hub on Windows is not
  supported by design: the hub tells its callers apart by Linux accounts and
  groups and by the peer credentials of its Unix socket (`SO_PEERCRED`).
- **One machine.** The hub, its gateway account, the HumanX web and the
  HumanX gateway run on the same machine. Clients on other machines would
  reach the hub over SSH through the gateway account; that path is not
  verified.
- **No services.** Neither command installs a systemd unit, an SSH forced
  command, a firewall rule or a journal seal. `install` and `doctor` print
  the commands that start the daemon, the web and the gateway as their own
  accounts. Example units are in each component's `examples/` folder.
- **Your keys.** You generate every key and keep it. The hub's keys file holds
  only the sha256 of each key; `install` refuses an entry with a field named
  like a secret.
- **New names only.** Both commands refuse accounts, groups and folders that
  already exist under a name they would create, and do not take them over.

## The bus hub

1. Install `components/integrity-llm-bus` into an environment that root can
   run. The CI job uses a new virtual environment under `/opt` with this wheel
   alone. The example systemd units run the system `python3 -I`; the
   [bus README](../components/integrity-llm-bus/README.md#hub-on-a-clean-linux-machine)
   says what they need.
2. Write a keys file from `examples/hub/principals.example.json`, with the
   sha256 of each key in `key_sha256`. The vendor of each entry must be one of
   `antigravity`, `bus`, `claude`, `codex`, `grok` and `human`; the daemon
   refuses every other vendor, and `install` refuses such an entry.
3. Install:

   ```bash
   integrity-llm-bus-hub install --etc /etc/<bus> --state /var/lib/<bus> --runtime /run/<bus> \
     --bus-user <bus account> --gateway-user <gateway account> --socket-group <socket group> \
     --principals <keys file>
   ```

   It creates the bus account, the gateway account and the socket group, and
   the configuration, state and socket folders. If a step fails, it removes
   what it made.
4. Start the daemon with the command under `start` in the output.
5. Check it by hand:

   ```bash
   integrity-llm-bus-hub doctor --etc /etc/<bus>
   ```

   `doctor` reads accounts, owners and modes, the configuration, the keys, the
   journal chain and the installed files. It also sends the daemon one request
   without a key, which the daemon must refuse. The daemon writes that refusal
   to its journal, so each run of `doctor` leaves one `denied` record. Do not
   run it from a timer or a loop. While the daemon is stopped, the `daemon`
   check fails and says why.
6. Remove it:

   ```bash
   integrity-llm-bus-hub uninstall --etc /etc/<bus>        # lists, removes nothing
   integrity-llm-bus-hub uninstall --etc /etc/<bus> --yes  # removes what install created
   python -m pip uninstall integrity-llm-bus
   ```

   `uninstall --yes` refuses, before removing anything, while a process of the
   bus account or of the gateway account runs.

## The HumanX server side

Install it after the hub. The full option list is in the
[HumanX README](../components/integrity-humanx/README.md#setting-up-on-a-clean-machine).

1. Install `components/integrity-humanx` for the interpreter that will run
   the web and the gateway.
2. Generate the web's bus key and write it to a file of your own: a regular
   file, mode 600 or stricter, owned by root or by the user who runs
   `install`. Add its sha256 to the hub's keys file with the address
   `human-<operator_id>`, the room operations and the vendor `human`.
3. Install:

   ```bash
   integrity-humanx-server install --etc /etc/<humanx> --state /var/lib/<humanx> --runtime /run/<humanx> \
     --web-user <web account> --gateway-user <gateway account> --socket-group <gateway socket group> \
     --bus-group <hub socket group> --bus-gateway-user <hub gateway account> --bus-socket <hub socket> \
     --web-key <key file> --operator-id <operator_id> --vendor claude --port 8890 --allow 127.0.0.1
   ```

   It creates the web account, the gateway account and the gateway socket
   group, and gives the hub's gateway account one group membership. It writes
   each step to its record before the step. The web listens on 127.0.0.1
   unless `--bind` says otherwise.
4. Enable the room on the hub: `<hub state>/state/room.json`, from
   `examples/hub/room.example.json`. `install` does not write it.
5. Start the web and the gateway with the commands in the output.
6. Check and remove:

   ```bash
   integrity-humanx-server doctor --etc /etc/<humanx>
   integrity-humanx-server uninstall --etc /etc/<humanx>        # lists, removes nothing
   integrity-humanx-server uninstall --etc /etc/<humanx> --yes  # removes what the record lists
   ```

   `doctor` only reads, and reports an install that stopped half way as
   `partial`. `uninstall --yes` takes the hub's gateway account out of the
   gateway socket group before it deletes the group, and leaves the hub as it
   was.

SQL, switch reads and the ring and storm screens stay off until you add
their files yourself. The machine that runs the vendors (room folders and
wakers) is set up by hand, as the HumanX README describes.

## The kill switch on the agents' machine

The [kill switch](../components/integrity-killswitch/README.md) is not a
server part. It goes on the machine where the agents run, Windows or Linux,
and installs on its own, without the rest of Integrity: see
[Install it on its own](../components/integrity-killswitch/README.md#install-it-on-its-own),
`integrity-killswitch doctor` and `integrity-killswitch uninstall --yes`.
On Linux it reads the caller's process ancestry from `/proc`. It is
cooperative: it terminates nothing, and a process that changes its own name
(`prctl`) or command line is not caught.

## What CI runs

On Ubuntu, with sudo inside the runner only, and with keys generated in the
job and never printed:

- `bus hub (ubuntu, real accounts)`
  (`.github/scripts/bus_hub_accounts_check.py`): the bus wheel alone;
  `install`, a refused second install, and `doctor` before, during and after
  the daemon run; the daemon as the bus account; requests over its socket from
  the gateway account and from a second account of the socket group, with
  revoked, unknown and read-only keys refused, and a vendor named by an
  account other than the gateway refused; a connect from
  an account outside the group refused; the journal chain; `uninstall` refused
  while the daemon or a gateway process runs, then `uninstall --yes`,
  `doctor` reporting `not-installed`, and pip uninstall.
- `humanx server (ubuntu, real accounts)`
  (`.github/scripts/humanx_server_check.py`): HumanX installed next to that
  hub; refused and half-finished installs; the gateway on its socket as its
  own account; the web on 127.0.0.1; one question sent from the page through
  the hub to the room vendor's address and the answer shown under it;
  `uninstall --yes`, `doctor` reporting `not-installed`, and the hub's own
  `doctor` still passing.
- The kill switch wheel alone, on Ubuntu and Windows
  (`.github/scripts/killswitch_standalone_check.py`), and its process
  ancestry tests on invented `/proc` trees and on real processes the tests
  start.

The component READMEs list every case.

## What it does not prove

- No real agent client used the hub or HumanX. In CI the vendor side is a
  script that holds the vendor's key.
- systemd units, the SSH forced command in front of the gateway account, the
  journal seal, the firewall and HumanX SQL against a database server were not
  run.
- Two machines (clients reaching the hub over SSH, or the web on one machine
  and the hub on another) were not run.
- The kill switch was not run under a real agent on Linux.
- The hub on Windows: not supported by design.
